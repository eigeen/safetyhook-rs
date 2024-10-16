pub unsafe fn store<T: Copy>(address: *mut u8, value: T) {
    let size = size_of::<T>();

    let value_bytes = std::slice::from_raw_parts(&value as *const T as *const u8, size);
    std::ptr::copy_nonoverlapping(value_bytes.as_ptr(), address, size);
}

pub fn align_up(address: usize, align: usize) -> usize {
    (address + align - 1) & !(align - 1)
}

pub fn align_down(address: usize, align: usize) -> usize {
    address & !(align - 1)
}
