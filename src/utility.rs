pub unsafe fn store<T: Copy>(address: *mut u8, value: T) {
    unsafe {
        let size = size_of::<T>();

        let value_bytes = std::slice::from_raw_parts(&value as *const T as *const u8, size);
        std::ptr::copy_nonoverlapping(value_bytes.as_ptr(), address, size);
    }
}

pub fn align_up(address: usize, align: usize) -> usize {
    (address + align - 1) & !(align - 1)
}

pub fn align_down(address: usize, align: usize) -> usize {
    address & !(align - 1)
}

pub fn align_up_ptr<T>(address: *const T, align: usize) -> *const T {
    let address = address as usize;
    align_up(address, align) as *const T
}

pub fn align_down_ptr<T>(address: *const T, align: usize) -> *const T {
    let address = address as usize;
    align_down(address, align) as *const T
}

pub fn to_null_terminated_string(string: &str) -> Vec<u8> {
    let mut string = string.to_string();
    string.push('\0');
    string.into_bytes()
}
