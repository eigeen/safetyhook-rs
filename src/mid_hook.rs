use std::ffi::c_void;

use crate::{
    allocator::{Allocation, Allocator, AllocatorError, SharedAllocator},
    inline_hook::{self, InlineError, InlineHook},
    utility,
};

mod asm;

#[derive(Debug, thiserror::Error)]
pub enum MidError {
    /// builder
    #[error("Mid hook builder error: {0}")]
    Builder(#[from] MidBuilderError),
    #[error("Bad allocation: {0}")]
    BadAllocation(#[from] AllocatorError),
    #[error("Bad inline hook: {0}")]
    BadInlineHook(#[from] InlineError),
    #[error("Inline hook uninitialized")]
    InlineHookUninitialized,
}

#[derive(Debug, thiserror::Error)]
pub enum MidBuilderError {
    #[error("target should not be null")]
    EmptyTarget,
    #[error("destination should not be null")]
    EmptyDestination,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Flags {
    #[default]
    Default = 0,
    StartDisabled = 1,
}

pub struct MidHookBuilder {
    target: *mut u8,
    destination: Option<MidHookFn>,
    enable_after_setup: bool,
    allocator: Option<SharedAllocator>,
}

impl Default for MidHookBuilder {
    fn default() -> Self {
        Self {
            target: std::ptr::null_mut(),
            destination: None,
            allocator: None,
            enable_after_setup: true,
        }
    }
}

impl MidHookBuilder {
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
    pub fn destination(mut self, destination: MidHookFn) -> Self {
        self.destination = Some(destination);
        self
    }

    /// **Optional**: Default = true
    ///
    /// Enable immediately after setup.
    pub fn enable_after_setup(mut self, enable_after_setup: bool) -> Self {
        self.enable_after_setup = enable_after_setup;
        self
    }

    /// **Optional**: Default = global allocator
    ///
    /// Allocator to use.
    pub fn allocator(mut self, allocator: SharedAllocator) -> Self {
        self.allocator = Some(allocator);
        self
    }

    /// Create a mid hook.
    pub unsafe fn create(self) -> Result<MidHook, MidError> {
        if self.target.is_null() {
            return Err(MidBuilderError::EmptyTarget)?;
        }
        if self.destination.is_none() {
            return Err(MidBuilderError::EmptyDestination)?;
        }

        let flags = if self.enable_after_setup {
            Flags::Default
        } else {
            Flags::StartDisabled
        };

        if let Some(allocator) = self.allocator.clone() {
            MidHook::new_with_allocator(allocator, self.target, self.destination.unwrap(), flags)
        } else {
            MidHook::new(self.target, self.destination.unwrap(), flags)
        }
    }
}

pub struct MidHook {
    hook: Option<InlineHook>,
    target: *mut u8,
    stub: Allocation,
    destination: MidHookFn,
}

unsafe impl Send for MidHook {}

impl MidHook {
    /// Create a mid hook.
    pub unsafe fn new(
        target: *mut u8,
        destination: MidHookFn,
        flags: Flags,
    ) -> Result<Self, MidError> {
        Self::new_with_allocator(Allocator::global(), target, destination, flags)
    }

    /// Create a inline hook with a custom allocator.
    pub unsafe fn new_with_allocator(
        allocator: SharedAllocator,
        target: *mut u8,
        destination: MidHookFn,
        flags: Flags,
    ) -> Result<Self, MidError> {
        let mut this = Self {
            hook: None,
            target,
            stub: allocator.lock().unwrap().allocate(asm::ASM_DATA.len())?,
            destination,
        };

        this.setup(allocator)?;

        if flags != Flags::StartDisabled {
            this.enable()?;
        }

        Ok(this)
    }

    /// Create a mid hook builder.
    pub fn builder() -> MidHookBuilder {
        MidHookBuilder::new()
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
    pub fn destination(&self) -> MidHookFn {
        self.destination
    }

    /// Original backuped bytes.
    pub fn original_bytes(&self) -> &[u8] {
        self.hook.as_ref().unwrap().original_bytes()
    }

    /// Is hook enabled.
    pub fn enabled(&self) -> bool {
        self.hook.as_ref().unwrap().enabled()
    }

    /// Initialize hook.
    pub unsafe fn setup(&mut self, allocator: SharedAllocator) -> Result<(), MidError> {
        self.stub
            .data()
            .copy_from_nonoverlapping(asm::ASM_DATA.as_ptr(), asm::ASM_DATA.len());

        if cfg!(target_arch = "x86_64") {
            utility::store(
                self.stub.data().add(asm::ASM_DATA.len()).sub(16),
                self.destination,
            );
        } else {
            utility::store(
                self.stub.data().add(asm::ASM_DATA.len()).sub(8),
                self.destination,
            );

            // 32-bit has some relocations we need to fix up as well.
            utility::store(
                self.stub.data().add(0x02),
                self.stub.data().add(self.stub.size() - 4),
            );
            utility::store(
                self.stub.data().add(0x59),
                self.stub.data().add(self.stub.size() - 8),
            );
        }

        let hook = InlineHook::new_with_allocator(
            allocator,
            self.target,
            self.stub.data(),
            inline_hook::Flags::StartDisabled,
        )?;
        self.hook = Some(hook);

        let trampoline_data = self.hook.as_ref().unwrap().trampoline().unwrap().data();
        if cfg!(target_arch = "x86_64") {
            utility::store(
                self.stub.data().add(asm::ASM_DATA.len()).sub(8),
                trampoline_data,
            );
        } else {
            utility::store(
                self.stub.data().add(asm::ASM_DATA.len()).sub(4),
                trampoline_data,
            );
        }

        Ok(())
    }

    /// Enable hook.
    pub fn enable(&mut self) -> Result<(), MidError> {
        if self.hook.is_none() {
            return Err(MidError::InlineHookUninitialized);
        }

        Ok(self.hook.as_mut().unwrap().enable()?)
    }

    /// Disable hook.
    pub fn disable(&mut self) -> Result<(), MidError> {
        if self.hook.is_none() {
            return Err(MidError::InlineHookUninitialized);
        }

        Ok(self.hook.as_mut().unwrap().disable()?)
    }
}

/// Mid hook callback function.
pub type MidHookFn = unsafe extern "C" fn(&mut Context);

#[cfg(target_arch = "x86_64")]
pub type Context = Context64;
#[cfg(target_arch = "x86")]
pub type Context = Context32;

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Context64 {
    pub xmm0: Xmm,
    pub xmm1: Xmm,
    pub xmm2: Xmm,
    pub xmm3: Xmm,
    pub xmm4: Xmm,
    pub xmm5: Xmm,
    pub xmm6: Xmm,
    pub xmm7: Xmm,
    pub xmm8: Xmm,
    pub xmm9: Xmm,
    pub xmm10: Xmm,
    pub xmm11: Xmm,
    pub xmm12: Xmm,
    pub xmm13: Xmm,
    pub xmm14: Xmm,
    pub xmm15: Xmm,
    pub rflags: usize,
    pub r15: usize,
    pub r14: usize,
    pub r13: usize,
    pub r12: usize,
    pub r11: usize,
    pub r10: usize,
    pub r9: usize,
    pub r8: usize,
    pub rdi: usize,
    pub rsi: usize,
    pub rdx: usize,
    pub rcx: usize,
    pub rbx: usize,
    pub rax: usize,
    pub rbp: usize,
    pub rsp: usize,
    pub trampoline_rsp: usize,
    pub rip: usize,
}

#[cfg(target_arch = "x86")]
#[repr(C)]
pub struct Context32 {
    pub xmm0: Xmm,
    pub xmm1: Xmm,
    pub xmm2: Xmm,
    pub xmm3: Xmm,
    pub xmm4: Xmm,
    pub xmm5: Xmm,
    pub xmm6: Xmm,
    pub xmm7: Xmm,
    pub eflags: usize,
    pub edi: usize,
    pub esi: usize,
    pub edx: usize,
    pub ecx: usize,
    pub ebx: usize,
    pub eax: usize,
    pub ebp: usize,
    pub esp: usize,
    pub trampoline_esp: usize,
    pub eip: usize,
}

pub union Xmm {
    pub u8: [u8; 16],
    pub u16: [u16; 8],
    pub u32: [u32; 4],
    pub u64: [u64; 2],
    pub f32: [f32; 4],
    pub f64: [f64; 2],
}
