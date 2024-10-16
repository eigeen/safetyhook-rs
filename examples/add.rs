extern "C" fn add(a: i32, b: i32) -> i32 {
    a + b
}

extern "C" fn add_hooked(a: i32, b: i32) -> i32 {
    a + b + 10
}

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    eprintln!("original add(1, 2) = {}", add(1, 2));

    let hook = unsafe { safetyhook::create_inline(add as _, add_hooked as _).unwrap() };

    eprintln!("hooked add(1, 2) = {}", add(1, 2));

    drop(hook);

    eprintln!("original add(1, 2) = {}", add(1, 2));
}
