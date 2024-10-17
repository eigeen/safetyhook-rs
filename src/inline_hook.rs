use std::{
    ffi::c_void,
    ptr::{addr_of, addr_of_mut},
};

use better_default::Default;
use log::trace;
use zydis::VisibleOperands;

use crate::{
    allocator::{Allocation, Allocator, AllocatorError, SharedAllocator, VM},
    utility,
};

#[derive(Debug, thiserror::Error)]
pub enum InlineError {
    /// builder
    #[error("Inline hook builder error: {0}")]
    Builder(#[from] InlineBuilderError),
    #[error("Bad allocation: {0}")]
    BadAllocation(#[from] AllocatorError),
    #[error("No enough space")]
    NoEnoughSpace,
    #[error("Trampoline uninitialized")]
    TrampolineUninitialized,
    #[error("IP relative instruction out of range")]
    IpRelativeInstructionOutOfRange,

    #[error("Empty instruction")]
    EmptyInstruction,
    #[error("Zydis error: {0}")]
    Zydis(#[from] zydis::Status),
    #[error("Unsupported instruction in trampoline, ip = 0x{0:X}")]
    UnsupportedInstructionInTrampoline(usize),
}

#[derive(Debug, thiserror::Error)]
pub enum InlineBuilderError {
    #[error("address should not be null")]
    EmptyAddress,
}

#[allow(unused)]
#[repr(packed)]
#[derive(Clone, Copy, Default)]
struct JmpE9 {
    #[default(0xE9)]
    opcode: u8,
    pub(crate) offset: u32,
}

#[allow(unused)]
#[cfg(target_arch = "x86_64")]
#[repr(packed)]
#[derive(Clone, Copy, Default)]
struct JmpFF {
    #[default(0xFF)]
    opcode0: u8,
    #[default(0x25)]
    opcode1: u8,
    pub(crate) offset: u32,
}

#[cfg(target_arch = "x86_64")]
#[repr(packed)]
#[derive(Default)]
struct TrampolineEpilogueE9 {
    jmp_to_original: JmpE9,
    jmp_to_destination: JmpFF,
    destination_address: u64,
}

#[cfg(target_arch = "x86_64")]
#[repr(packed)]
#[derive(Default)]
struct TrampolineEpilogueFF {
    jmp_to_original: JmpFF,
    original_address: u64,
}

#[cfg(target_arch = "x86")]
#[repr(packed)]
#[derive(Default)]
struct TrampolineEpilogueE9 {
    jmp_to_original: JmpE9,
    jmp_to_destination: JmpE9,
}

unsafe fn make_jmp_ff(src: *const u8, dst: *const u8, data: *mut u8) -> JmpFF {
    let jmp_ff = JmpFF {
        offset: (data as usize - src as usize - size_of::<JmpFF>()) as u32,
        ..Default::default()
    };
    utility::store(data, dst);

    jmp_ff
}

unsafe fn emit_jmp_ff(
    src: *mut u8,
    dst: *const u8,
    data: *mut u8,
    size: Option<usize>,
) -> Result<(), InlineError> {
    const SIZE: usize = size_of::<JmpFF>();

    let size = size.unwrap_or(SIZE);
    if size < SIZE {
        return Err(InlineError::NoEnoughSpace);
    }
    if size > SIZE {
        unsafe {
            std::ptr::write_bytes(src, 0x90, size);
        }
    }

    utility::store(src, make_jmp_ff(src, dst, data));

    Ok(())
}

fn make_jmp_e9(src: *const u8, dst: *const u8) -> JmpE9 {
    JmpE9 {
        offset: ((dst as usize)
            .wrapping_sub(src as usize)
            .wrapping_sub(size_of::<JmpE9>())) as u32,
        ..Default::default()
    }
}

unsafe fn emit_jmp_e9(
    src: *mut u8,
    dst: *const u8,
    size: Option<usize>,
) -> Result<(), InlineError> {
    const SIZE: usize = size_of::<JmpE9>();

    let size = size.unwrap_or(SIZE);
    if size < SIZE {
        return Err(InlineError::NoEnoughSpace);
    }
    if size > SIZE {
        std::ptr::write_bytes(src, 0x90_u8, size);
    }

    utility::store(src, make_jmp_e9(src, dst));

    Ok(())
}

fn decode<O: zydis::Operands>(ip: &[u8]) -> Result<zydis::Instruction<O>, InlineError> {
    let decoder = if cfg!(target_arch = "x86_64") {
        zydis::Decoder::new64()
    } else {
        zydis::Decoder::new32()
    };

    let instruction = decoder
        .decode_first(ip)?
        .ok_or(InlineError::EmptyInstruction)?;

    Ok(instruction)
}

#[derive(Debug, Default)]
#[repr(i32)]
pub enum Flags {
    /// Default flags.
    #[default]
    Default = 0,
    /// Start the hook disabled.
    StartDisabled = 1 << 0,
}

pub struct InlineHookBuilder {
    target: *mut u8,
    destination: *const u8,
    enable_after_setup: bool,
    allocator: Option<SharedAllocator>,
}

impl Default for InlineHookBuilder {
    fn default() -> Self {
        Self {
            target: std::ptr::null_mut(),
            destination: std::ptr::null(),
            enable_after_setup: true,
            allocator: None,
        }
    }
}

impl InlineHookBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// **Required**
    ///
    /// Target address to hook.
    pub fn target(mut self, target: *mut c_void) -> Self {
        self.target = target as _;
        self
    }

    /// **Required**
    ///
    /// Destination address to jump to.
    pub fn destination(mut self, destination: *const c_void) -> Self {
        self.destination = destination as _;
        self
    }

    /// **Optional**: Default = true
    ///
    /// Enable immediately after setup.
    pub fn enable_after_setup(mut self, enable: bool) -> Self {
        self.enable_after_setup = enable;
        self
    }

    /// **Optional**: Default = global allocator
    ///
    /// Allocator to use.
    pub fn allocator(mut self, allocator: SharedAllocator) -> Self {
        self.allocator = Some(allocator);
        self
    }

    /// Create a inline hook.
    pub unsafe fn create(&self) -> Result<InlineHook, InlineError> {
        if self.target.is_null() || self.destination.is_null() {
            return Err(InlineBuilderError::EmptyAddress)?;
        }

        let flags = if self.enable_after_setup {
            Flags::Default
        } else {
            Flags::StartDisabled
        };

        if let Some(allocator) = self.allocator.clone() {
            InlineHook::new_with_allocator(allocator, self.target, self.destination, flags)
        } else {
            InlineHook::new(self.target, self.destination, flags)
        }
    }
}

/// Type of JMP opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JmpType {
    #[default]
    Unset,
    E9,
    FF,
}

pub struct InlineHook {
    target: *mut u8,
    destination: *const u8,
    trampoline: Option<Allocation>,
    original_bytes: Vec<u8>,
    trampoline_size: usize,
    enabled: bool,
    jmp_type: JmpType,
}

unsafe impl Send for InlineHook {}

impl Default for InlineHook {
    fn default() -> Self {
        Self {
            target: std::ptr::null_mut(),
            destination: std::ptr::null(),
            trampoline: None,
            original_bytes: Default::default(),
            trampoline_size: 0,
            enabled: false,
            jmp_type: Default::default(),
        }
    }
}

impl Drop for InlineHook {
    fn drop(&mut self) {
        let _ = self.disable();
    }
}

impl InlineHook {
    /// Create a inline hook.
    pub unsafe fn new(
        target: *mut u8,
        destination: *const u8,
        flags: Flags,
    ) -> Result<Self, InlineError> {
        let allocator = Allocator::global();

        Self::new_with_allocator(allocator, target, destination, flags)
    }

    /// Create a inline hook with a custom allocator.
    pub unsafe fn new_with_allocator(
        allocator: SharedAllocator,
        target: *mut u8,
        destination: *const u8,
        flags: Flags,
    ) -> Result<Self, InlineError> {
        let mut this = Self::default();

        this.target = target;
        this.destination = destination;

        trace!(
            "Setting up inline hook: target = {:p}, destination = {:p}",
            target,
            destination
        );

        this.setup(allocator)?;

        if (flags as i32 & Flags::StartDisabled as i32) == 0 {
            this.enable()?;
        }

        Ok(this)
    }

    /// Create a inline hook builder.
    pub fn builder() -> InlineHookBuilder {
        InlineHookBuilder::new()
    }

    /// Target address to hook.
    pub fn target(&self) -> *mut u8 {
        self.target
    }

    /// Target address to hook.
    pub fn target_address(&self) -> usize {
        self.target as usize
    }

    /// Destination address to jump to.
    pub fn destination(&self) -> *const u8 {
        self.destination
    }

    /// Destination address to jump to.
    pub fn destination_address(&self) -> usize {
        self.destination as usize
    }

    /// Trampoline allocation.
    pub fn trampoline(&self) -> Option<&Allocation> {
        self.trampoline.as_ref()
    }

    /// Is hook enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Original function address.
    ///
    /// You can use this address to call the original function.
    ///
    /// Example:
    ///
    /// ```
    /// // transmute ptr to function type.
    /// let original: FuncType = std::mem::transmute(hook.original());
    /// // call original function.
    /// original(arg1, arg2, arg3);
    /// ```
    pub fn original(&self) -> *const c_void {
        self.trampoline.as_ref().unwrap().data() as *const c_void
    }

    /// Original backuped bytes.
    pub fn original_bytes(&self) -> &[u8] {
        &self.original_bytes
    }

    /// Enable hook.
    pub fn enable(&mut self) -> Result<(), InlineError> {
        if self.enabled {
            return Ok(());
        }

        if self.trampoline.is_none() {
            return Err(InlineError::TrampolineUninitialized);
        }

        // jmp from original to trampoline.
        let mut error: Option<InlineError> = None;
        unsafe {
            VM::trap_threads(
                self.target,
                self.trampoline.as_ref().unwrap().data(),
                self.original_bytes.len(),
                Some(|| {
                    if self.jmp_type == JmpType::E9 {
                        let trampoline_epilogue: &mut TrampolineEpilogueE9 = std::mem::transmute(
                            self.trampoline.as_ref().unwrap().address() + self.trampoline_size
                                - size_of::<TrampolineEpilogueE9>(),
                        );

                        if let Err(e) = emit_jmp_e9(
                            self.target,
                            addr_of!(trampoline_epilogue.jmp_to_destination) as _,
                            Some(self.original_bytes.len()),
                        ) {
                            error = Some(e);
                        };
                    }

                    #[cfg(target_arch = "x86_64")]
                    if self.jmp_type == JmpType::FF {
                        if let Err(e) = emit_jmp_ff(
                            self.target,
                            self.destination,
                            self.target.add(size_of::<JmpFF>()),
                            Some(self.original_bytes.len()),
                        ) {
                            error = Some(e);
                        };
                    }
                }),
            );
        }

        if let Some(e) = error {
            return Err(e);
        }

        self.enabled = true;

        Ok(())
    }

    /// Disable hook.
    pub fn disable(&mut self) -> Result<(), InlineError> {
        if !self.enabled {
            return Ok(());
        }

        if self.trampoline.is_none() {
            return Err(InlineError::TrampolineUninitialized);
        }

        unsafe {
            VM::trap_threads(
                self.trampoline.as_ref().unwrap().data(),
                self.target,
                self.original_bytes.len(),
                Some(|| {
                    std::ptr::copy_nonoverlapping(
                        self.original_bytes.as_ptr(),
                        self.target,
                        self.original_bytes.len(),
                    );
                }),
            );
        }

        self.enabled = false;

        Ok(())
    }

    /// Initialize hook.
    #[allow(unused_assignments)]
    unsafe fn setup(&mut self, allocator: SharedAllocator) -> Result<(), InlineError> {
        let mut result: Result<(), InlineError> = Ok(());
        result = self.e9_hook(allocator.clone());
        #[cfg(target_arch = "x86_64")]
        if result.is_err() {
            result = self.ff_hook(allocator.clone());
        }

        result
    }

    /// Initialize E9 JMP hook.
    ///
    /// Availble if targe <=> destination < 2^31 (2GB).
    unsafe fn e9_hook(&mut self, allocator: SharedAllocator) -> Result<(), InlineError> {
        trace!("Setting up E9 hook");

        self.original_bytes.clear();
        self.trampoline_size = size_of::<TrampolineEpilogueE9>();

        let mut desired_addresses = vec![self.target];

        let mut ip = self.target;
        while ip < self.target.add(size_of::<JmpE9>()) {
            let buffer = unsafe { std::slice::from_raw_parts(ip, 20) };
            let ix = decode::<VisibleOperands>(buffer)?;

            self.trampoline_size += ix.length as usize;
            self.original_bytes
                .extend_from_slice(&buffer[..ix.length as usize]);

            let is_relative = (ix.attributes & zydis::InstructionAttributes::IS_RELATIVE)
                != zydis::InstructionAttributes::empty();

            if is_relative {
                if ix.raw.disp.size == 32 {
                    let target_address = ip
                        .add(ix.length as usize)
                        .offset(ix.raw.disp.value as isize);
                    desired_addresses.push(target_address);
                } else if ix.raw.imm[0].size == 32 {
                    let target_address = ip
                        .add(ix.length as usize)
                        .offset(ix.raw.imm[0].value as isize);
                    desired_addresses.push(target_address);
                } else if ix.meta.category == zydis::InstructionCategory::COND_BR
                    && ix.meta.branch_type == zydis::BranchType::SHORT
                {
                    let target_address = ip
                        .add(ix.length as usize)
                        .offset(ix.raw.imm[0].value as isize);
                    desired_addresses.push(target_address);
                    self.trampoline_size += 4; // near conditional branches are 4 bytes larger.
                } else if ix.meta.category == zydis::InstructionCategory::UNCOND_BR
                    && ix.meta.branch_type == zydis::BranchType::SHORT
                {
                    let target_address = ip
                        .add(ix.length as usize)
                        .offset(ix.raw.imm[0].value as isize);
                    desired_addresses.push(target_address);
                    self.trampoline_size += 3; // near unconditional branches are 3 bytes larger.
                } else {
                    return Err(InlineError::UnsupportedInstructionInTrampoline(ip as usize));
                }
            }

            ip = ip.add(ix.length as usize);
        }

        let trampoline_allocation = allocator.lock().unwrap().allocate_near(
            &desired_addresses,
            self.trampoline_size,
            None,
        )?;
        self.trampoline = Some(trampoline_allocation);
        let m_trampoline = self.trampoline.as_mut().unwrap();

        let mut ip = self.target;
        let mut tramp_ip = m_trampoline.data();
        while ip < self.target.add(self.original_bytes.len()) {
            let buffer = unsafe { std::slice::from_raw_parts(ip, 20) };
            let ix = match decode::<VisibleOperands>(buffer) {
                Ok(ix) => ix,
                Err(e) => {
                    self.trampoline = None;
                    return Err(e);
                }
            };

            let is_relative = (ix.attributes & zydis::InstructionAttributes::IS_RELATIVE)
                != zydis::InstructionAttributes::empty();

            if is_relative && ix.raw.disp.size == 32 {
                unsafe {
                    std::ptr::copy_nonoverlapping(ip, tramp_ip, ix.length as usize);
                };
                let target_address = ip
                    .add(ix.length as usize)
                    .offset(ix.raw.disp.value as isize);
                let new_disp = target_address as isize - (tramp_ip as isize + ix.length as isize);
                utility::store(tramp_ip.add(ix.raw.disp.offset as usize), new_disp as i32);
                tramp_ip = tramp_ip.add(ix.length as usize);
            } else if is_relative && ix.raw.imm[0].size == 32 {
                unsafe {
                    std::ptr::copy_nonoverlapping(ip, tramp_ip, ix.length as usize);
                };
                let target_address = ip
                    .add(ix.length as usize)
                    .offset(ix.raw.imm[0].value as isize);
                let new_disp = target_address as isize - (tramp_ip as isize + ix.length as isize);
                utility::store(tramp_ip.add(ix.raw.imm[0].offset as usize), new_disp as i32);
                tramp_ip = tramp_ip.add(ix.length as usize);
            } else if ix.meta.category == zydis::InstructionCategory::COND_BR
                && ix.meta.branch_type == zydis::BranchType::SHORT
            {
                let target_address = ip
                    .add(ix.length as usize)
                    .offset(ix.raw.imm[0].value as isize);
                let mut new_disp = target_address as isize - (tramp_ip as isize + 6);

                // Handle the case where the target is now in the trampoline.
                if target_address < self.target.add(self.original_bytes.len()) {
                    new_disp = ix.raw.imm[0].value as isize
                }

                unsafe {
                    tramp_ip.write(0x0F);
                    tramp_ip.add(1).write(0x10 + ix.opcode);
                    utility::store(tramp_ip.add(2), new_disp as i32);
                }
                tramp_ip = tramp_ip.add(6);
            } else if ix.meta.category == zydis::InstructionCategory::UNCOND_BR
                && ix.meta.branch_type == zydis::BranchType::SHORT
            {
                let target_address = ip
                    .add(ix.length as usize)
                    .offset(ix.raw.imm[0].value as isize);
                let mut new_disp = target_address as isize - (tramp_ip as isize + 5);

                // Handle the case where the target is now in the trampoline.
                if target_address < self.target.add(self.original_bytes.len()) {
                    new_disp = ix.raw.imm[0].value as isize
                }

                unsafe {
                    tramp_ip.write(0xE9);
                    utility::store(tramp_ip.add(1), new_disp as i32);
                }
                tramp_ip = tramp_ip.add(5);
            } else {
                unsafe {
                    std::ptr::copy_nonoverlapping(ip, tramp_ip, ix.length as usize);
                }
                tramp_ip = tramp_ip.add(ix.length as usize);
            }

            ip = ip.add(ix.length as usize);
        }

        let trampoline_epilogue: &mut TrampolineEpilogueE9 = std::mem::transmute(
            m_trampoline.address() + self.trampoline_size - size_of::<TrampolineEpilogueE9>(),
        );

        // jmp from trampoline to original.
        let src: *mut u8 = addr_of_mut!(trampoline_epilogue.jmp_to_original) as _;
        let dst: *mut u8 = self.target.add(self.original_bytes.len());

        trace!("jmp from trampoline to original: {:p} -> {:p}", src, dst);
        emit_jmp_e9(src, dst, None)?;

        // jmp from trampoline to destination.
        let src: *mut u8 = addr_of_mut!(trampoline_epilogue.jmp_to_destination) as _;
        let dst: *mut u8 = self.destination as _;

        trace!("jmp from trampoline to destination: {:p} -> {:p}", src, dst);
        if cfg!(target_arch = "x86_64") {
            let data: *mut u8 = addr_of_mut!(trampoline_epilogue.destination_address) as _;

            emit_jmp_ff(src, dst, data, None)?;
        } else {
            emit_jmp_e9(src, dst, None)?;
        }

        self.jmp_type = JmpType::E9;

        Ok(())
    }

    /// Initialize FF JMP hook.
    ///
    /// Available in x86_64.
    #[cfg(target_arch = "x86_64")]
    unsafe fn ff_hook(&mut self, allocator: SharedAllocator) -> Result<(), InlineError> {
        self.original_bytes.clear();
        self.trampoline_size = size_of::<TrampolineEpilogueFF>();

        let mut ip = self.target;
        while ip < self.target.add(size_of::<JmpFF>()) {
            let buffer = unsafe { std::slice::from_raw_parts(ip, 20) };
            let ix = decode::<VisibleOperands>(buffer)?;

            // We can't support any instruction that is IP relative here because
            // ff_hook should only be called if e9_hook failed indicating that
            // we're likely outside the +- 2GB range.
            if ix.attributes & zydis::InstructionAttributes::IS_RELATIVE
                != zydis::InstructionAttributes::empty()
            {
                return Err(InlineError::IpRelativeInstructionOutOfRange);
            }

            self.original_bytes
                .extend_from_slice(&buffer[..ix.length as usize]);
            self.trampoline_size += ix.length as usize;

            ip = ip.add(ix.length as usize);
        }

        let trampoline_allocation = allocator.lock().unwrap().allocate(self.trampoline_size)?;
        self.trampoline = Some(trampoline_allocation);

        std::ptr::copy_nonoverlapping(
            self.original_bytes.as_ptr(),
            self.trampoline.as_ref().unwrap().data(),
            self.original_bytes.len(),
        );

        let trampoline_epilogue_ptr: *mut TrampolineEpilogueFF =
            self.trampoline
                .as_ref()
                .unwrap()
                .data()
                .add(self.trampoline_size)
                .sub(size_of::<TrampolineEpilogueFF>()) as _;
        let trampoline_epilogue = &mut *(trampoline_epilogue_ptr);

        // jmp from trampoline to original.
        let src: *mut u8 = addr_of_mut!(trampoline_epilogue.jmp_to_original) as _;
        let dst: *const u8 = self.target.add(self.original_bytes.len());
        let data: *mut u8 = addr_of_mut!(trampoline_epilogue.original_address) as _;

        emit_jmp_ff(src, dst, data, None)?;

        self.jmp_type = JmpType::FF;

        Ok(())
    }
}
