extern crate core;

pub mod android_library;
pub mod android_loader;
mod hook_manager;

#[cfg(test)]
mod tests {
    use rand::Rng;
    use std::collections::HashMap;
    use std::ffi::CString;
    use std::os::raw::c_char;
    use libc::{chmod, close, free, fstat, ftruncate, gettimeofday, lstat, malloc, mkdir, open, read, strncpy, umask, write};

    use crate::android_loader::AndroidLoader;

    extern "C" fn arc4random() -> u32 {
        rand::thread_rng().gen()
    }


    #[test]
    fn load_android_libraries() {
        println!("Page size: {}", region::page::size());

        let mut hooks = HashMap::new();
        hooks.insert("arc4random".to_owned(), arc4random as usize);
        hooks.insert("chmod".to_owned(), chmod as usize);
        hooks.insert("close".to_owned(), close as usize);
        hooks.insert("free".to_owned(), free as usize);
        hooks.insert("fstat".to_owned(), fstat as usize);
        hooks.insert("ftruncate".to_owned(), ftruncate as usize);
        hooks.insert("gettimeofday".to_owned(), gettimeofday as usize);
        hooks.insert("lstat".to_owned(), lstat as usize);
        hooks.insert("malloc".to_owned(), malloc as usize);
        hooks.insert("mkdir".to_owned(), mkdir as usize);
        hooks.insert("open".to_owned(), open as usize);
        hooks.insert("read".to_owned(), read as usize);
        hooks.insert("strncpy".to_owned(), strncpy as usize);
        hooks.insert("umask".to_owned(), umask as usize);
        hooks.insert("write".to_owned(), write as usize);

        let store_services_core =
            AndroidLoader::load_library_with_hooks("lib/x86_64/libstoreservicescore.so", hooks)
                .expect("Cannot load StoreServicesCore");

        println!("Library loaded. Let's start.");
        let load_library_with_path: extern "C" fn(*const c_char) -> i32 =
            unsafe { std::mem::transmute(store_services_core.get_symbol("kq56gsgHG6").unwrap()) }; // Sph98paBcz abort
        let library_path = CString::new("lib/x86_64/").unwrap();
        let ret = load_library_with_path(library_path.as_ptr() as *const c_char);
        println!("provisioning path, ADI returned {}", ret);

        let set_android_identifier: extern "C" fn(*const c_char, u32) -> i32 =
            unsafe { std::mem::transmute(store_services_core.get_symbol("Sph98paBcz").unwrap()) }; // Sph98paBcz abort
                                                                                                   // println!("{:p}", set_android_identifier as *const ());
        let identifier = "f213456789abcde0";
        let str = CString::new(identifier).unwrap();
        let len = identifier.len() as u32;
        let ret = set_android_identifier(str.as_ptr() as *const c_char, len);
        println!("Fin ? ADI returned {}", ret);
    }
}
