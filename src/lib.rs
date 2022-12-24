mod android_loader;
mod page_utils;
mod android_library;

#[cfg(test)]
mod tests {
    use crate::android_loader::AndroidLoader;

    #[test]
    fn load_android_libraries() {
        let mut loader = AndroidLoader::new();
        let core_adi = loader.load_library("lib/x86_64/libCoreADI.so").expect("Cannot load CoreADI");
        let store_services_core = loader.load_library("lib/x86_64/libstoreservicescore.so").expect("Cannot load StoreServicesCore");

        println!("Loaded ! Let's start ^^");
        let set_android_identifier: extern "C" fn() -> i32 = unsafe { std::mem::transmute(store_services_core.get_symbol("Sph98paBcz")) }; // Sph98paBcz abort
        // println!("{:p}", set_android_identifier as *const ());
        set_android_identifier();
    }
}
