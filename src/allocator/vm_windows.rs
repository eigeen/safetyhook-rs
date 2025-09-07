use std::{
    collections::HashMap,
    ffi::c_void,
    sync::{
        atomic::{AtomicBool, Ordering},
        LazyLock, Mutex,
    },
};

use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{EXCEPTION_ACCESS_VIOLATION, FALSE},
        System::{
            Diagnostics::Debug::{
                AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, RtlPcToFileHeader,
                CONTEXT, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH,
                EXCEPTION_POINTERS, IMAGE_FILE_HEADER, IMAGE_SCN_MEM_EXECUTE,
                IMAGE_SECTION_CHARACTERISTICS, IMAGE_SECTION_HEADER,
            },
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::{
                IsBadReadPtr, IsBadWritePtr, VirtualAlloc, VirtualFree, VirtualProtect,
                VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_RELEASE,
                MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
                PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
            },
            SystemInformation::{GetSystemInfo, SYSTEM_INFO},
            SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE},
        },
    },
};

use crate::utility;

use super::vm::{OsError, SystemInfo, VmAccess, VmBasicInfo};

#[allow(non_camel_case_types)]
#[cfg(target_arch = "x86_64")]
type IMAGE_NT_HEADERS = windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
#[allow(non_camel_case_types)]
#[cfg(target_arch = "x86")]
type IMAGE_NT_HEADERS = windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;

pub struct VM;

impl VM {
    pub fn alloc(address: *const u8, size: usize, access: VmAccess) -> Result<*mut u8, OsError> {
        let protect = match access {
            VmAccess::R => PAGE_READONLY,
            VmAccess::RW => PAGE_READWRITE,
            VmAccess::RX => PAGE_EXECUTE_READ,
            VmAccess::RWX => PAGE_EXECUTE_READWRITE,
            _ => return Err(OsError::Allocate),
        };

        let result =
            unsafe { VirtualAlloc(Some(address as _), size, MEM_COMMIT | MEM_RESERVE, protect) };
        if result.is_null() {
            return Err(OsError::Allocate);
        }

        Ok(result as *mut u8)
    }

    pub fn free(address: *mut u8) {
        unsafe {
            let _ = VirtualFree(address as _, 0, MEM_RELEASE);
        }
    }

    pub fn protect(address: *mut u8, size: usize, protect: u32) -> Result<(), OsError> {
        let mut old_protect = PAGE_PROTECTION_FLAGS::default();

        unsafe {
            VirtualProtect(
                address as _,
                size,
                PAGE_PROTECTION_FLAGS(protect),
                &mut old_protect,
            )
            .map_err(|_| OsError::Protect)?;
        };

        Ok(())
    }

    pub fn query(address: *const u8) -> Result<VmBasicInfo, OsError> {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let result = unsafe {
            VirtualQuery(
                Some(address as _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if result == 0 {
            return Err(OsError::Query);
        }

        let access = VmAccess {
            read: (mbi.Protect
                & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))
                != PAGE_PROTECTION_FLAGS(0),
            write: (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))
                != PAGE_PROTECTION_FLAGS(0),
            execute: (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))
                != PAGE_PROTECTION_FLAGS(0),
        };

        Ok(VmBasicInfo {
            address: mbi.BaseAddress as *mut u8,
            size: mbi.RegionSize,
            access,
            is_free: mbi.State == MEM_FREE,
        })
    }

    pub fn is_readable(address: *const u8, size: usize) -> bool {
        unsafe { IsBadReadPtr(Some(address as _), size) == FALSE }
    }

    pub fn is_writable(address: *const u8, size: usize) -> bool {
        unsafe { IsBadWritePtr(Some(address as _), size) == FALSE }
    }

    pub fn is_executable(address: *const u8) -> bool {
        unsafe {
            let mut image_base = std::ptr::null_mut();

            let result = RtlPcToFileHeader(address as _, &mut image_base);
            if result.is_null() {
                return Self::query(address).unwrap_or_default().access.execute;
            }

            // Just check if the section is executable.
            let dos_hdr_ptr: *const IMAGE_DOS_HEADER = image_base as *const IMAGE_DOS_HEADER;
            let dos_hdr: &IMAGE_DOS_HEADER = &*dos_hdr_ptr;

            if dos_hdr.e_magic != IMAGE_DOS_SIGNATURE {
                return Self::query(address).unwrap_or_default().access.execute;
            }

            let nt_hdr_ptr = image_base.add(dos_hdr.e_lfanew as usize) as *const IMAGE_NT_HEADERS;
            let nt_hdr: &IMAGE_NT_HEADERS = &*nt_hdr_ptr;
            if nt_hdr.Signature != IMAGE_NT_SIGNATURE {
                return Self::query(address).unwrap_or_default().access.execute;
            }

            let mut section_ptr = image_first_section(nt_hdr);

            for _ in 0..nt_hdr.FileHeader.NumberOfSections {
                let section: &IMAGE_SECTION_HEADER = &*section_ptr;

                if (address as usize) >= (image_base as usize + section.VirtualAddress as usize)
                    && (address as usize)
                        < (image_base as usize
                            + section.VirtualAddress as usize
                            + section.Misc.VirtualSize as usize)
                {
                    return (section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
                        != IMAGE_SECTION_CHARACTERISTICS(0);
                }

                section_ptr = section_ptr.add(1);
            }

            Self::query(address).unwrap_or_default().access.execute
        }
    }

    pub fn system_info() -> SystemInfo {
        let mut sys_info = SYSTEM_INFO::default();
        unsafe { GetSystemInfo(&mut sys_info) };

        SystemInfo {
            page_size: sys_info.dwPageSize,
            allocation_granularity: sys_info.dwAllocationGranularity,
            min_address: sys_info.lpMinimumApplicationAddress as _,
            max_address: sys_info.lpMaximumApplicationAddress as _,
        }
    }

    pub unsafe fn trap_threads<F>(from: *const u8, to: *const u8, len: usize, run_fn: Option<F>)
    where
        F: FnMut(),
    {
        let mut find_me_mbi = MEMORY_BASIC_INFORMATION::default();
        let mut from_mbi = MEMORY_BASIC_INFORMATION::default();
        let mut to_mbi = MEMORY_BASIC_INFORMATION::default();

        VirtualQuery(
            Some(find_me as *const c_void),
            &mut find_me_mbi,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        VirtualQuery(
            Some(from as *const c_void),
            &mut from_mbi,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        VirtualQuery(
            Some(to as *const c_void),
            &mut to_mbi,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        );

        let mut new_protect = PAGE_READWRITE;
        if from_mbi.AllocationBase == find_me_mbi.AllocationBase
            || to_mbi.AllocationBase == find_me_mbi.AllocationBase
        {
            new_protect = PAGE_EXECUTE_READWRITE;
        }

        // Fix LoadLibraryExW hooking crash
        let system_info = VM::system_info();
        let from_page_start = utility::align_down_ptr(from, system_info.page_size as usize);
        let from_page_end =
            utility::align_up_ptr(from.wrapping_add(len), system_info.page_size as usize);
        let vp_start = get_proc_address("kernel32.dll", "VirtualProtect");
        if let Some(vp_start) = vp_start {
            let vp_end = vp_start.wrapping_add(0x20);

            if !(from_page_end < vp_start || vp_end < from_page_start) {
                new_protect = PAGE_EXECUTE_READWRITE;
            }
        } else {
            log::warn!("Failed to get VirtualProtect address");
        }

        if !TRAP_MANAGER_DESTRUCTED.load(Ordering::SeqCst) {
            // not destructed
            let mut trap_manager = TrapManager::instance().lock().unwrap();
            trap_manager.add_trap(from, to, len);
        }

        let mut from_protect = PAGE_PROTECTION_FLAGS::default();
        let mut to_protect = PAGE_PROTECTION_FLAGS::default();

        let _ = VirtualProtect(from as _, len, new_protect, &mut from_protect);
        let _ = VirtualProtect(to as _, len, new_protect, &mut to_protect);

        if let Some(mut run_fn) = run_fn {
            run_fn();
        }

        let _ = VirtualProtect(to as _, len, to_protect, &mut to_protect);
        let _ = VirtualProtect(from as _, len, from_protect, &mut from_protect);
    }
}

static TRAP_MANAGER: LazyLock<Mutex<TrapManager>> =
    LazyLock::new(|| Mutex::new(unsafe { TrapManager::new() }));
static TRAP_MANAGER_DESTRUCTED: AtomicBool = AtomicBool::new(false);

struct TrapInfo {
    from_page_start: *const u8,
    from_page_end: *const u8,
    from: *const u8,
    to_page_start: *const u8,
    to_page_end: *const u8,
    to: *const u8,
    len: usize,
}

struct TrapManager {
    traps: HashMap<usize, TrapInfo>,
    trap_veh: *mut c_void,
}

unsafe impl Send for TrapManager {}

impl Drop for TrapManager {
    fn drop(&mut self) {
        if !self.trap_veh.is_null() {
            unsafe {
                RemoveVectoredExceptionHandler(self.trap_veh);
            }
        }
        TRAP_MANAGER_DESTRUCTED.store(true, Ordering::SeqCst);
    }
}

impl TrapManager {
    unsafe fn new() -> Self {
        Self {
            traps: HashMap::new(),
            trap_veh: AddVectoredExceptionHandler(1, Some(trap_handler)),
        }
    }

    pub fn instance() -> &'static Mutex<TrapManager> {
        &TRAP_MANAGER
    }

    pub fn find_trap(&self, address: *const u8) -> Option<&TrapInfo> {
        let search = self.traps.iter().find(|(_, trap)| {
            address >= trap.from && (address as usize) < (trap.from as usize + trap.len)
        });

        search.map(|(_, trap)| trap)
    }

    pub fn find_trap_page(&self, address: *const u8) -> Option<&TrapInfo> {
        let search = self
            .traps
            .iter()
            .find(|(_, trap)| address >= trap.from_page_start || address < trap.from_page_end);

        if let Some((_, trap)) = search {
            return Some(trap);
        }

        let search = self
            .traps
            .iter()
            .find(|(_, trap)| address >= trap.to_page_start || address < trap.to_page_end);

        search.map(|(_, trap)| trap)
    }

    pub fn add_trap(&mut self, from: *const u8, to: *const u8, len: usize) {
        let from_page_start = utility::align_down(from as usize, 0x1000);
        let from_page_end = utility::align_up(from as usize + len, 0x1000);
        let to_page_start = utility::align_down(to as usize, 0x1000);
        let to_page_end = utility::align_up(to as usize + len, 0x1000);

        let trap = TrapInfo {
            from_page_start: from_page_start as *const u8,
            from_page_end: from_page_end as *const u8,
            from,
            to_page_start: to_page_start as *const u8,
            to_page_end: to_page_end as *const u8,
            to,
            len,
        };

        self.traps.insert(from as usize, trap);
    }
}

unsafe extern "system" fn trap_handler(exceptioninfo: *mut EXCEPTION_POINTERS) -> i32 {
    let exp = exceptioninfo.as_ref().unwrap();
    let exception_code = exp.ExceptionRecord.as_ref().unwrap().ExceptionCode;

    if exception_code != EXCEPTION_ACCESS_VIOLATION {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let trap_manager = TrapManager::instance().lock().unwrap();
    let faulting_address =
        exp.ExceptionRecord.as_ref().unwrap().ExceptionInformation[1] as *const u8;
    let trap = trap_manager.find_trap(faulting_address);

    if trap.is_none() {
        if trap_manager.find_trap_page(faulting_address).is_some() {
            return EXCEPTION_CONTINUE_EXECUTION;
        } else {
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }
    let trap = trap.unwrap();

    let ctx = exp.ContextRecord;

    for i in 0..trap.len {
        fix_ip(ctx, trap.from.add(i), trap.to.add(i));
    }

    EXCEPTION_CONTINUE_EXECUTION
}

// IMAGE_FIRST_SECTION implementation
unsafe fn image_first_section(nt_header: &IMAGE_NT_HEADERS) -> *mut IMAGE_SECTION_HEADER {
    let base_address = nt_header as *const _ as usize;
    let optional_header_offset = std::mem::size_of::<IMAGE_FILE_HEADER>();
    let optional_header_size = nt_header.FileHeader.SizeOfOptionalHeader as usize;

    let section_header_address = base_address + optional_header_offset + optional_header_size;

    section_header_address as *mut IMAGE_SECTION_HEADER
}

#[cfg(target_arch = "x86_64")]
unsafe fn fix_ip(ctx: *mut CONTEXT, old_ip: *const u8, new_ip: *const u8) {
    let mut ip = ctx.as_mut().unwrap().Rip as usize;

    if ip == old_ip as usize {
        ip = new_ip as usize;
    }

    ctx.as_mut().unwrap().Rip = ip as u64;
}

#[cfg(target_arch = "x86")]
unsafe fn fix_ip(ctx: *mut CONTEXT, old_ip: *const u8, new_ip: *const u8) {
    let mut ip = ctx.as_mut().unwrap().Eip as usize;

    if ip == old_ip as usize {
        ip = new_ip as usize;
    }

    ctx.as_mut().unwrap().Eip = ip as u32;
}

unsafe fn get_proc_address(module: &str, name: &str) -> Option<*const u8> {
    let module_name = utility::to_null_terminated_string(module);
    let module = GetModuleHandleA(PCSTR::from_raw(module_name.as_ptr())).ok()?;
    let name = utility::to_null_terminated_string(name);
    let proc = GetProcAddress(module, PCSTR::from_raw(name.as_ptr()))?;

    Some(std::mem::transmute(proc))
}

#[inline(never)]
fn find_me() {}
