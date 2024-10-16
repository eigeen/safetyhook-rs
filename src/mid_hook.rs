use crate::{
    allocator::{Allocation, Allocator, AllocatorError, SharedAllocator},
    inline_hook::{self, InlineError, InlineHook},
    utility,
};

mod asm;

#[derive(Debug, thiserror::Error)]
pub enum MidError {
    #[error("Bad allocation: {0}")]
    BadAllocation(#[from] AllocatorError),
    #[error("Bad inline hook: {0}")]
    BadInlineHook(#[from] InlineError),
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Flags {
    #[default]
    Default = 0,
    StartDisabled = 1,
}

pub struct MidHook {
    hook: Option<InlineHook>,
    target: *mut u8,
    stub: Allocation,
    destination: MidHookFn,
}

impl MidHook {
    pub unsafe fn new(
        target: *mut u8,
        destination: MidHookFn,
        flags: Flags,
    ) -> Result<Self, MidError> {
        Self::new_with_allocator(Allocator::global(), target, destination, flags)
    }

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

    pub unsafe fn enable(&mut self) -> Result<(), MidError> {
        if self.hook.is_none() {
            return Err(MidError::BadInlineHook(InlineError::Uninitialized));
        }

        Ok(self.hook.as_mut().unwrap().enable()?)
    }

    pub unsafe fn disable(&mut self) -> Result<(), MidError> {
        if self.hook.is_none() {
            return Err(MidError::BadInlineHook(InlineError::Uninitialized));
        }

        Ok(self.hook.as_mut().unwrap().disable()?)
    }
}

pub type MidHookFn = extern "C" fn(*mut Context);

#[cfg(target_arch = "x86_64")]
pub type Context = Context64;
#[cfg(target_arch = "x86")]
pub type Context = Context32;

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
    u8: [u8; 16],
    u16: [u16; 8],
    u32: [u32; 4],
    u64: [u64; 2],
    f32: [f32; 4],
    f64: [f64; 2],
}
