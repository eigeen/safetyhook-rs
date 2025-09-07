#![allow(clippy::missing_safety_doc)]

mod allocator;
pub mod inline_hook;
pub mod mid_hook;
mod utility;

pub use inline_hook::InlineHook;
pub use mid_hook::MidHook;

use std::ffi::c_void;

/// Create a new inline hook, and enable after craetion.
///
/// It is a easy-to-use wrapper of [InlineHook::new] or [InlineHook::builder].
pub unsafe fn create_inline(
    target: *mut c_void,
    dest: *mut c_void,
) -> Result<InlineHook, inline_hook::InlineError> {
    unsafe { InlineHook::new(target as _, dest as _, inline_hook::Flags::Default) }
}

/// Create a new mid hook, and enable after craetion.
///
/// It is a easy-to-use wrapper of [MidHook::new] or [MidHook::builder].
pub unsafe fn create_mid(
    target: *mut c_void,
    dest: mid_hook::MidHookFn,
) -> Result<MidHook, mid_hook::MidError> {
    unsafe { MidHook::new(target as _, dest, mid_hook::Flags::Default) }
}
