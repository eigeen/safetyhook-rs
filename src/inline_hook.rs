use std::{
    ffi::c_void,
    ptr::{addr_of, addr_of_mut},
};

use better_default::Default;
use log::debug;
use zydis::VisibleOperands;

use crate::{
    allocator::{Allocation, Allocator, AllocatorError, SharedAllocator, VM},
    utility,
};

#[derive(Debug, thiserror::Error)]
pub enum InlineError {
    #[error("Bad allocation: {0}")]
    BadAllocation(#[from] AllocatorError),
    #[error("No enough space")]
    NoEnoughSpace,
    #[error("Trampoline uninitialized")]
    TrampolineUninitialized,
    #[error("InlineHook uninitialized")]
    Uninitialized,

    #[error("Empty instruction")]
    EmptyInstruction,
    #[error("Zydis error: {0}")]
    Zydis(#[from] zydis::Status),
    #[error("Unsupported instruction in trampoline, ip = 0x{0:X}")]
    UnsupportedInstructionInTrampoline(usize),
}

#[repr(packed)]
#[derive(Clone, Copy, Default)]
struct JmpE9 {
    #[default(0xE9)]
    opcode: u8,
    pub(crate) offset: u32,
}

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
    // lock
    enabled: bool,
    jmp_type: JmpType,
}

impl Default for InlineHook {
    fn default() -> Self {
        Self {
            target: std::ptr::null_mut(),
            destination: std::ptr::null_mut(),
            trampoline: None,
            original_bytes: Vec::new(),
            trampoline_size: 0,
            enabled: false,
            jmp_type: JmpType::Unset,
        }
    }
}

impl Drop for InlineHook {
    fn drop(&mut self) {
        unsafe {
            let _ = self.disable();
        }
    }
}

impl InlineHook {
    pub unsafe fn new(
        target: *mut u8,
        destination: *const u8,
        flags: Flags,
    ) -> Result<Self, InlineError> {
        let allocator = Allocator::global();

        Self::new_with_allocator(allocator, target, destination, flags)
    }

    pub unsafe fn new_with_allocator(
        allocator: SharedAllocator,
        target: *mut u8,
        destination: *const u8,
        flags: Flags,
    ) -> Result<Self, InlineError> {
        let mut this = Self::default();

        this.setup(allocator, target, destination)?;

        if (flags as i32 & Flags::StartDisabled as i32) == 0 {
            this.enable()?;
        }

        Ok(this)
    }

    pub fn target(&self) -> *mut u8 {
        self.target
    }

    pub fn target_address(&self) -> usize {
        self.target as usize
    }

    pub fn destination(&self) -> *const u8 {
        self.destination
    }

    pub fn destination_address(&self) -> usize {
        self.destination as usize
    }

    pub fn trampoline(&self) -> Option<&Allocation> {
        self.trampoline.as_ref()
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn original(&self) -> *const c_void {
        self.trampoline.as_ref().unwrap().data() as *const c_void
    }

    pub fn original_bytes(&self) -> &[u8] {
        &self.original_bytes
    }

    #[allow(unused_assignments)]
    pub unsafe fn setup(
        &mut self,
        allocator: SharedAllocator,
        target: *mut u8,
        destination: *const u8,
    ) -> Result<(), InlineError> {
        self.target = target;
        self.destination = destination;

        debug!(
            "Setting up hook: target = {:p}, destination = {:p}",
            target, destination
        );

        let mut result: Result<(), InlineError> = Ok(());
        result = self.e9_hook(allocator.clone());
        #[cfg(target_arch = "x86_64")]
        if result.is_err() {
            result = self.ff_hook(allocator.clone());
        }

        result
    }

    unsafe fn e9_hook(&mut self, allocator: SharedAllocator) -> Result<(), InlineError> {
        debug!("Setting up E9 hook");

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

        let trampoline_epilogue_ptr: *mut TrampolineEpilogueE9 =
            (m_trampoline.address() + self.trampoline_size - size_of::<TrampolineEpilogueE9>())
                as _;
        let trampoline_epilogue = trampoline_epilogue_ptr.as_mut().unwrap();

        // jmp from trampoline to original.
        let src: *mut u8 = addr_of_mut!(trampoline_epilogue.jmp_to_original) as _;
        let dst: *mut u8 = self.target.add(self.original_bytes.len());

        debug!("jmp from trampoline to original: {:p} -> {:p}", src, dst);
        emit_jmp_e9(src, dst, None)?;

        // jmp from trampoline to destination.
        let src: *mut u8 = addr_of_mut!(trampoline_epilogue.jmp_to_destination) as _;
        let dst: *mut u8 = self.destination as _;

        debug!("jmp from trampoline to destination: {:p} -> {:p}", src, dst);
        if cfg!(target_arch = "x86_64") {
            let data: *mut u8 = addr_of_mut!(trampoline_epilogue.destination_address) as _;

            emit_jmp_ff(src, dst, data, None)?;
        } else {
            emit_jmp_e9(src, dst, None)?;
        }

        self.jmp_type = JmpType::E9;

        Ok(())
    }

    pub fn ff_hook(&mut self, allocator: SharedAllocator) -> Result<(), InlineError> {
        unimplemented!()
    }

    pub unsafe fn enable(&mut self) -> Result<(), InlineError> {
        if self.enabled {
            return Ok(());
        }

        if self.trampoline.is_none() {
            return Err(InlineError::TrampolineUninitialized);
        }

        // jmp from original to trampoline.
        let mut error: Option<InlineError> = None;
        VM::trap_threads(
            self.target,
            self.trampoline.as_ref().unwrap().data(),
            self.original_bytes.len(),
            Some(|| {
                if self.jmp_type == JmpType::E9 {
                    let trampoline_epilogue_ptr: *mut TrampolineEpilogueE9 =
                        (self.trampoline.as_ref().unwrap().address() + self.trampoline_size
                            - size_of::<TrampolineEpilogueE9>()) as *mut _;
                    let trampoline_epilogue = trampoline_epilogue_ptr.as_ref().unwrap();

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

        if let Some(e) = error {
            return Err(e);
        }

        self.enabled = true;

        Ok(())
    }

    pub unsafe fn disable(&mut self) -> Result<(), InlineError> {
        if !self.enabled {
            return Ok(());
        }

        if self.trampoline.is_none() {
            return Err(InlineError::TrampolineUninitialized);
        }

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

        self.enabled = false;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use zydis::{Formatter, VisibleOperands};

    #[test]
    fn it_works() {
        let decoder = if cfg!(target_arch = "x86_64") {
            zydis::Decoder::new64()
        } else {
            zydis::Decoder::new32()
        };

        let buffer = [
            0xFF, 0x35, 0x79, 0x01, 0x00, 0x00, 0x54, 0x54, 0x55, 0x50, 0x53, 0x51, 0x52, 0x56,
            0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41,
            0x56, 0x41, 0x57, 0x9C, 0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00, 0xF3, 0x44, 0x0F,
            0x7F, 0xBC, 0x24, 0xF0, 0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x7F, 0xB4, 0x24, 0xE0,
            0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x7F, 0xAC, 0x24, 0xD0, 0x00, 0x00, 0x00, 0xF3,
            0x44, 0x0F, 0x7F, 0xA4, 0x24, 0xC0, 0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x7F, 0x9C,
            0x24, 0xB0, 0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x7F, 0x94, 0x24, 0xA0, 0x00, 0x00,
            0x00, 0xF3, 0x44, 0x0F, 0x7F, 0x8C, 0x24, 0x90, 0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F,
            0x7F, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x7F, 0x7C, 0x24, 0x70, 0xF3,
            0x0F, 0x7F, 0x74, 0x24, 0x60, 0xF3, 0x0F, 0x7F, 0x6C, 0x24, 0x50, 0xF3, 0x0F, 0x7F,
            0x64, 0x24, 0x40, 0xF3, 0x0F, 0x7F, 0x5C, 0x24, 0x30, 0xF3, 0x0F, 0x7F, 0x54, 0x24,
            0x20, 0xF3, 0x0F, 0x7F, 0x4C, 0x24, 0x10, 0xF3, 0x0F, 0x7F, 0x04, 0x24, 0x48, 0x8B,
            0x8C, 0x24, 0x80, 0x01, 0x00, 0x00, 0x48, 0x83, 0xC1, 0x10, 0x48, 0x89, 0x8C, 0x24,
            0x80, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x0C, 0x24, 0x48, 0x89, 0xE3, 0x48, 0x83, 0xEC,
            0x30, 0x48, 0x83, 0xE4, 0xF0, 0xFF, 0x15, 0xA8, 0x00, 0x00, 0x00, 0x48, 0x89, 0xDC,
            0xF3, 0x0F, 0x6F, 0x04, 0x24, 0xF3, 0x0F, 0x6F, 0x4C, 0x24, 0x10, 0xF3, 0x0F, 0x6F,
            0x54, 0x24, 0x20, 0xF3, 0x0F, 0x6F, 0x5C, 0x24, 0x30, 0xF3, 0x0F, 0x6F, 0x64, 0x24,
            0x40, 0xF3, 0x0F, 0x6F, 0x6C, 0x24, 0x50, 0xF3, 0x0F, 0x6F, 0x74, 0x24, 0x60, 0xF3,
            0x0F, 0x6F, 0x7C, 0x24, 0x70, 0xF3, 0x44, 0x0F, 0x6F, 0x84, 0x24, 0x80, 0x00, 0x00,
            0x00, 0xF3, 0x44, 0x0F, 0x6F, 0x8C, 0x24, 0x90, 0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F,
            0x6F, 0x94, 0x24, 0xA0, 0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x6F, 0x9C, 0x24, 0xB0,
            0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x6F, 0xA4, 0x24, 0xC0, 0x00, 0x00, 0x00, 0xF3,
            0x44, 0x0F, 0x6F, 0xAC, 0x24, 0xD0, 0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x6F, 0xB4,
            0x24, 0xE0, 0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x6F, 0xBC, 0x24, 0xF0, 0x00, 0x00,
            0x00, 0x48, 0x81, 0xC4, 0x00, 0x01, 0x00, 0x00, 0x9D, 0x41, 0x5F, 0x41, 0x5E, 0x41,
            0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5F, 0x5E, 0x5A,
            0x59, 0x5B, 0x58, 0x5D, 0x48, 0x8D, 0x64, 0x24, 0x08, 0x5C, 0xC3, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let fmt = Formatter::intel();
        let instructions = decoder.decode_all::<VisibleOperands>(&buffer, 0);
        for instruction in instructions {
            // println!("{:?}", instruction.unwrap());
            let (ip, _raw_bytes, insn) = instruction.unwrap();
            println!("0x{:08X} {}", ip, fmt.format(Some(ip), &insn).unwrap())
        }
    }
}
