#![allow(clippy::missing_safety_doc)]

mod allocator;
pub mod inline_hook;
pub mod mid_hook;
mod utility;

pub use inline_hook::InlineHook;
pub use mid_hook::MidHook;

use std::ffi::c_void;

/// Create a new inline hook, and enable after craetion.
pub unsafe fn create_inline(
    target: *const c_void,
    dest: *const c_void,
) -> Result<InlineHook, inline_hook::InlineError> {
    InlineHook::new(target as _, dest as _, inline_hook::Flags::Default)
}

/// Create a new mid hook, and enable after craetion.
pub unsafe fn create_mid(
    target: *const c_void,
    dest: mid_hook::MidHookFn,
) -> Result<MidHook, mid_hook::MidError> {
    MidHook::new(target as _, dest, mid_hook::Flags::Default)
}
