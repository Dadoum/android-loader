extern crate core;

pub mod android_library;
pub mod android_loader;

#[cfg(test)]
mod tests {
    use std::ffi::{c_char, c_void, CStr, CString};
    use std::ptr::null_mut;
    use once_cell::sync::Lazy;
    use crate::android_library::AndroidLibrary;
    use crate::android_loader::AndroidLoader;

    static LOADER: Lazy<AndroidLoader> = Lazy::new(|| AndroidLoader::new(symbol_loader).unwrap());

    unsafe extern "C" fn my_dlopen(name: *const c_char) -> *mut c_void {
        let name = CStr::from_ptr(name).to_str().unwrap();
        if name == "libCoreADI.so" {
            println!("Library requested: {}", name);
            let core_adi = Box::new(LOADER.load_library("lib/x86_64/libCoreADI.so").expect("Cannot load libCoreADI"));
            Box::leak(core_adi) as *mut AndroidLibrary as *mut c_void
        } else {
            null_mut()
        }
    }

    unsafe extern "C" fn my_dlsym(handle: &'static mut AndroidLibrary, symbol: *const c_char) -> *mut c_void {
        let symbol = CStr::from_ptr(symbol).to_str().unwrap();
        println!("Symbol requested: {}", symbol);
        match handle.get_symbol(symbol) {
            Some(func) => func as *mut c_void,
            None => null_mut()
        }
    }

    fn symbol_loader(symbol_name: &str) -> Option<extern "C" fn()> {
        match symbol_name {
            "dlopen" => Some(unsafe { std::mem::transmute(my_dlopen as *mut c_void) }),
            "dlsym" => Some(unsafe { std::mem::transmute(my_dlsym as *mut c_void) }),
            _ => None
        }
    }

    #[test]
    fn load_android_libraries() {
        let store_services_core = LOADER.load_library("lib/x86_64/libstoreservicescore.so").expect("Cannot load StoreServicesCore");

        println!("Library loaded. Let's start.");
        let set_android_identifier: extern "C" fn(*const c_char, u32) -> i32 = unsafe { std::mem::transmute(store_services_core.get_symbol("Sph98paBcz")) }; // Sph98paBcz abort
        // println!("{:p}", set_android_identifier as *const ());
        let identifier = "f213456789abcde0";
        let str = CString::new(identifier).unwrap();
        let len = identifier.len() as u32;
        let ret = set_android_identifier(str.as_ptr() as *const c_char, len);
        println!("Fin ? ADI returned {}", ret);
    }
}
