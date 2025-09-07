use std::sync::{Arc, Mutex, Weak};

pub type SharedAllocator = Arc<Mutex<Allocator>>;

static mut GLOBAL_ALLOCATOR: Option<SharedAllocator> = None;

type Result<T> = std::result::Result<T, AllocatorError>;

mod vm;
use vm::VmAccess;

#[cfg(target_os = "windows")]
mod vm_windows;
#[cfg(target_os = "windows")]
pub use vm_windows::VM;

use crate::utility;

#[derive(Debug, thiserror::Error)]
pub enum AllocatorError {
    #[error("VirtualAlloc failed")]
    BadVirtualAlloc,
    #[error("No memory in range")]
    NoMemoryInRange,
}

pub struct Allocation {
    allocator: SharedAllocator,
    address: *mut u8,
    size: usize,
}

impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.address.is_null() && self.size != 0 {
            self.allocator.lock().unwrap().free(self.address, self.size);
        }
    }
}

impl Allocation {
    pub fn new(allocator: SharedAllocator, address: *mut u8, size: usize) -> Self {
        Self {
            allocator,
            address,
            size,
        }
    }

    pub fn data(&self) -> *mut u8 {
        self.address
    }

    pub fn address(&self) -> usize {
        self.address as usize
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn is_null(&self) -> bool {
        self.address.is_null() || self.size == 0
    }
}

pub struct Memory {
    address: *mut u8,
    size: usize,
    freelist: Vec<FreeNode>,
}

impl Drop for Memory {
    fn drop(&mut self) {
        VM::free(self.address);
    }
}

#[derive(Clone)]
pub struct FreeNode {
    start: *mut u8,
    end: *mut u8,
}

#[derive(Default)]
struct AllocatorInner {
    memory: Vec<Memory>,
}

pub struct Allocator {
    inner: Mutex<AllocatorInner>,
    self_weak: Weak<Mutex<Self>>,
}

impl Allocator {
    #[allow(clippy::arc_with_non_send_sync)]
    pub fn new_shared() -> Arc<Mutex<Self>> {
        let this = Arc::new(Mutex::new(Self {
            inner: Default::default(),
            self_weak: Weak::new(),
        }));
        this.lock().unwrap().self_weak = Arc::downgrade(&this);

        this
    }

    pub fn global() -> SharedAllocator {
        unsafe {
            if let Some(ref allocator) = GLOBAL_ALLOCATOR {
                return allocator.clone();
            }

            let allocator = Allocator::new_shared();
            GLOBAL_ALLOCATOR = Some(allocator.clone());
            allocator
        }
    }

    pub fn allocate(&self, size: usize) -> Result<Allocation> {
        self.allocate_near(&[], size, None)
    }

    pub fn allocate_near(
        &self,
        desired_addresses: &[*mut u8],
        size: usize,
        max_distance: Option<usize>,
    ) -> Result<Allocation> {
        let mut inner = self.inner.lock().unwrap();

        // Align to 2 bytes to pass MFP virtual method check
        // See https://itanium-cxx-abi.github.io/cxx-abi/abi.html#member-function-pointers
        let size = utility::align_up(size, 2);

        // First search through our list of allocations for a free block that is large enough.
        let max_distance = max_distance.unwrap_or(usize::MAX);
        for allocation in inner.memory.iter_mut() {
            if allocation.size < size {
                continue;
            }

            for freenode in allocation.freelist.iter_mut() {
                // Enough room?
                if (freenode.end as usize - freenode.start as usize) < size {
                    continue;
                }

                let address = freenode.start;

                // Close enough?
                if !in_range(address, desired_addresses, max_distance) {
                    continue;
                }

                freenode.start = freenode.start.wrapping_byte_add(size);
            }
        }

        // If we didn't find a free block, we need to allocate a new one.
        let allocation_size =
            utility::align_up(size, VM::system_info().allocation_granularity as usize);
        let allocation_address =
            Self::allocate_nearby_memory(desired_addresses, allocation_size, max_distance)?;

        let memory = Memory {
            address: allocation_address,
            size: allocation_size,
            freelist: vec![FreeNode {
                start: allocation_address.wrapping_add(size),
                end: allocation_address.wrapping_add(allocation_size),
            }],
        };
        inner.memory.push(memory);

        Ok(Allocation {
            allocator: self.self_weak.upgrade().unwrap(),
            address: allocation_address,
            size,
        })
    }

    pub fn free(&self, address: *mut u8, size: usize) {
        let mut inner = self.inner.lock().unwrap();

        for allocation in inner.memory.iter_mut() {
            if allocation.address > address
                || allocation.address.wrapping_add(allocation.size) < address
            {
                continue;
            }

            // Find the right place for our new FreeNode.
            let index = allocation
                .freelist
                .iter()
                .position(|freenode| freenode.start > address)
                .unwrap_or(allocation.freelist.len());

            // Add new freenode.
            let new_freenode = FreeNode {
                start: address,
                end: address.wrapping_add(size),
            };

            allocation.freelist.insert(index, new_freenode);

            Self::combine_adjacent_freenodes(allocation);
            break;
        }
    }

    fn combine_adjacent_freenodes(memory: &mut Memory) {
        let mut i = 0;
        while i < memory.freelist.len() - 1 {
            let current = &memory.freelist[i];
            let next = &memory.freelist[i + 1];

            if current.end == next.start {
                memory.freelist[i].end = next.end;
                memory.freelist.remove(i + 1);
            } else {
                i += 1;
            }
        }
    }

    fn allocate_nearby_memory(
        desired_addresses: &[*mut u8],
        size: usize,
        max_distance: usize,
    ) -> Result<*mut u8> {
        if desired_addresses.is_empty() {
            if let Ok(result) = VM::alloc(std::ptr::null_mut(), size, VmAccess::RWX) {
                return Ok(result);
            }
            return Err(AllocatorError::BadVirtualAlloc);
        }

        let attempt_allocation = |p: *mut u8| -> Option<*mut u8> {
            if !in_range(p, desired_addresses, max_distance) {
                return None;
            }
            VM::alloc(p, size, VmAccess::RWX).ok()
        };

        let si = VM::system_info();
        let mut desired_address = desired_addresses[0];
        let mut search_start = si.min_address;
        let mut search_end = si.max_address;

        if (desired_address as usize - search_start as usize) > max_distance {
            search_start = unsafe { desired_address.offset(-(max_distance as isize)) };
        }

        if (search_end as usize - desired_address as usize) > max_distance {
            search_end = unsafe { desired_address.add(max_distance) };
        }

        search_start = search_start.max(si.min_address);
        search_end = search_end.min(si.max_address);
        desired_address =
            utility::align_up(desired_address as usize, si.allocation_granularity as usize)
                as *mut u8;

        // Search backwards from the desired_address.
        let mut p = desired_address;
        while p > search_start.cast_mut() && in_range(p, desired_addresses, max_distance) {
            let Ok(mbi) = VM::query(p) else {
                break;
            };

            if !mbi.is_free {
                p = utility::align_down(p as usize - 1, si.allocation_granularity as usize)
                    as *mut u8;
                continue;
            }

            if let Some(allocation_address) = attempt_allocation(p) {
                return Ok(allocation_address);
            }
            p = utility::align_down(p as usize - 1, si.allocation_granularity as usize) as *mut u8;
        }

        // Search forwards from the desired_address.
        let mut p = desired_address;
        while p < search_end.cast_mut() && in_range(p, desired_addresses, max_distance) {
            let Ok(mbi) = VM::query(p) else {
                break;
            };

            if !mbi.is_free {
                p = unsafe { p.add(mbi.size) };
                continue;
            }

            if let Some(allocation_address) = attempt_allocation(p) {
                return Ok(allocation_address);
            }
            p = unsafe { p.add(mbi.size) };
        }

        Err(AllocatorError::NoMemoryInRange)
    }
}

fn in_range(address: *const u8, desired_addresses: &[*mut u8], max_distance: usize) -> bool {
    desired_addresses.iter().all(|&desired_address| {
        let delta = if address > desired_address {
            (address as usize) - (desired_address as usize)
        } else {
            (desired_address as usize) - (address as usize)
        };
        delta <= max_distance
    })
}
