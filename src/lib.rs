mod android_library;
mod android_loader;
mod page_utils;

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use libc::{SIG_DFL, signal, SIGSEGV};
    use crate::android_loader::AndroidLoader;

    extern "C" fn my_dlopen() {
        todo!();
    }

    fn symbol_loader(symbol_name: &str) -> Option<extern "C" fn()> {
        match symbol_name {
            "dlopen" => Some(my_dlopen),
            _ => None
        }
    }

    #[test]
    fn load_android_libraries() {
        unsafe { signal(SIGSEGV, SIG_DFL); }
        let mut loader = AndroidLoader::new(symbol_loader);
        let store_services_core = loader.load_library("lib/x86_64/libstoreservicescore.so").expect("Cannot load StoreServicesCore");

        println!("Library loaded. Let's start.");
        let set_android_identifier: extern "C" fn(*const i8, u32) -> i32 = unsafe { std::mem::transmute(store_services_core.get_symbol("Sph98paBcz")) }; // Sph98paBcz abort
        // println!("{:p}", set_android_identifier as *const ());
        let identifier = "f213456789abcde0";
        let str = CString::new(identifier).unwrap();
        let len = identifier.len() as u32;
        set_android_identifier(str.as_ptr(), len);
    }
}
