#[derive(Debug, thiserror::Error)]
pub enum OsError {
    #[error("Failed to allocate")]
    Allocate,
    #[error("Failed to protect")]
    Protect,
    #[error("Failed to query")]
    Query,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VmAccess {
    pub(crate) read: bool,
    pub(crate) write: bool,
    pub(crate) execute: bool,
}

impl VmAccess {
    pub const R: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    pub const RW: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    pub const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
    pub const RWX: Self = Self {
        read: true,
        write: true,
        execute: true,
    };
}

pub struct VmBasicInfo {
    pub(crate) address: *const u8,
    pub(crate) size: usize,
    pub(crate) access: VmAccess,
    pub(crate) is_free: bool,
}

impl Default for VmBasicInfo {
    fn default() -> Self {
        Self {
            address: std::ptr::null(),
            size: Default::default(),
            access: Default::default(),
            is_free: Default::default(),
        }
    }
}

pub struct SystemInfo {
    pub(crate) page_size: u32,
    pub(crate) allocation_granularity: u32,
    pub(crate) min_address: *const u8,
    pub(crate) max_address: *const u8,
}
