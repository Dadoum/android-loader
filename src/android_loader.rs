use std::alloc::alloc;
use crate::android_library::{AndroidLibrary, Shift, Symbol};
use crate::hook_manager;
use anyhow::Result;
use elfloader::arch::{aarch64, arm, x86, x86_64};
use elfloader::{
    ElfBinary, ElfLoader, ElfLoaderErr, LoadableHeaders, RelocationEntry, RelocationType,
};
use memmap2::MmapOptions;
use region::Protection;
use std::cmp::max;
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::os::raw::{c_char, c_void};
use std::ptr::null_mut;
use xmas_elf::program::{ProgramHeader, Type};
use xmas_elf::sections::SectionData;
use xmas_elf::symbol_table::Entry;

pub struct AndroidLoader {}

impl AndroidLoader {
    extern "C" fn pthread_stub() -> i32 {
        0
    }

    extern "C" fn undefined_symbol_stub() {
        panic!("tried to call an undefined symbol");
    }

    #[cfg(feature = "hacky_hooks")]
    unsafe extern "C" fn dlopen(name: *const c_char) -> *mut c_void {
        use crate::hook_manager::{get_caller, get_hooks, get_range};

        let caller = get_caller();
        println!("Caller: {:p}", caller as *const ());
        let parent_hooks = get_hooks(get_range(caller).unwrap()).unwrap();
        println!("Parent hooks: {:?}", parent_hooks);
        //println!("Caller: {:p}", get_caller() as *const ());
        let name = CStr::from_ptr(name).to_str().unwrap();
        println!("Library requested: {}", name);
        match Self::load_library_with_hooks(name, parent_hooks) {
            Ok(lib) => Box::into_raw(Box::new(lib)) as *mut c_void,
            Err(_) => null_mut(),
        }
    }

    #[cfg(not(feature = "hacky_hooks"))]
    unsafe extern "C" fn dlopen(name: *const c_char) -> *mut c_void {
        use crate::hook_manager::get_hooks;

        let hooks = get_hooks();
        println!("Hooks: {:?}", hooks);
        let name = CStr::from_ptr(name).to_str().unwrap();
        println!("Library requested: {}", name);
        match Self::load_library_with_hooks(name, hooks) {
            Ok(lib) => Box::into_raw(Box::new(lib)) as *mut c_void,
            Err(_) => null_mut(),
        }
    }

    unsafe extern "C" fn dlsym(library: *mut AndroidLibrary, symbol: *const c_char) -> *mut c_void {
        let symbol = CStr::from_ptr(symbol).to_str().unwrap();
        println!("Symbol requested: {}", symbol);
        match library.as_ref().and_then(|lib| lib.get_symbol(symbol)) {
            Some(func) => func as *mut c_void,
            None => null_mut(),
        }
    }

    unsafe extern "C" fn dlclose(library: *mut AndroidLibrary) {
        let _ = Box::from_raw(library);
    }

    #[cfg(feature = "hacky_hooks")]
    fn symbol_finder(symbol_name: &str, library: &AndroidLibrary) -> *const () {
        // Check if this function is hooked for this library
        if let Some(func) = library.hooks.get(symbol_name) {
            *func as *const ()
        // pthread functions are problematic, let's ignore them
        } else {
            Self::get_libc_symbol(symbol_name)
        }
    }

    #[cfg(not(feature = "hacky_hooks"))]
    fn symbol_finder(symbol_name: &str, library: &AndroidLibrary) -> *const () {
        // Check if this function is hooked for this library
        use crate::hook_manager::get_hooks;

        if let Some(func) = get_hooks().get(symbol_name) {
            *func as *const ()
        // pthread functions are problematic, let's ignore them
        } else {
            Self::get_libc_symbol(symbol_name)
        }
    }

    fn get_libc_symbol(symbol_name: &str) -> *const () {
        if symbol_name.starts_with("pthread_") {
            Self::pthread_stub as *const ()
        } else {
            match symbol_name {
                "dlopen" => Self::dlopen as *const (),
                "dlsym" => Self::dlsym as *const (),
                "dlclose" => Self::dlclose as *const (),
                _ => Self::undefined_symbol_stub as *const ()
            }
        }
    }

    pub fn load_library(path: &str) -> Result<AndroidLibrary> {
        Self::load_library_with_hooks(path, HashMap::new())
    }

    pub fn load_library_with_hooks(
        path: &str,
        hooks: HashMap<String, usize>,
    ) -> Result<AndroidLibrary> {
        let file = fs::read(path)?;
        let bin = ElfBinary::new(file.as_slice())?;

        Ok(bin.load::<Self, AndroidLibrary>(hooks)?)
    }
}

impl AndroidLoader {
    fn absolute_reloc(library: &mut AndroidLibrary, entry: RelocationEntry, addend: usize) {
        let addr = library.memory_map.as_mut_ptr() as usize;
        let symbol = Self::symbol_finder(&library.symbols[entry.index as usize].name, library);

        // addend is always 0, but we still add it to be safe
        // converted to an array in the systme endianess
        let val = addend.wrapping_add(symbol as usize);
        let relocated = val.to_ne_bytes();

        let offset = library.shift_address(addr + entry.offset as usize) - addr;
        library.memory_map[offset..offset + relocated.len()].copy_from_slice(&relocated);
    }

    fn relative_reloc(library: &mut AndroidLibrary, entry: RelocationEntry, addend: usize) {
        let addr = library.memory_map.as_mut_ptr() as usize;
        let val = library.shift_address(addend
            .wrapping_add(addr));

        let relocated = val.to_ne_bytes();

        let offset = library.shift_address(addr + entry.offset as usize) - addr;
        library.memory_map[offset..offset + relocated.len()].copy_from_slice(&relocated);
    }

    #[cfg(not(target_arch="aarch64"))]
    const MAX_PAGE_SIZE: usize = 4096;

    #[cfg(target_arch="aarch64")]
    const MAX_PAGE_SIZE: usize = 65536;
}

impl ElfLoader<AndroidLibrary> for AndroidLoader {
    fn allocate(
        load_headers: LoadableHeaders,
        elf_binary: &ElfBinary,
        hooks: HashMap<String, usize>,
    ) -> Result<AndroidLibrary, ElfLoaderErr> {
        let mut minimum = usize::MAX;
        let mut maximum = usize::MIN;

        for header in load_headers {
            if header.get_type() == Ok(Type::Load) {
                let start = region::page::floor(header.virtual_addr() as *const ()) as usize;
                let end = region::page::ceil(
                    (start as usize + max(header.file_size(), header.mem_size()) as usize)
                        as *const (),
                ) as usize;

                if start < minimum {
                    minimum = start;
                }

                if end > maximum {
                    maximum = end;
                }
            }
        }

        let alloc_start = region::page::floor(minimum as *const ()) as usize;
        debug_assert!(alloc_start <= minimum);
        let alloc_end = region::page::ceil(maximum as *const ()) as usize;
        debug_assert!(alloc_end >= maximum);

        let dyn_symbol_section = elf_binary.file.find_section_by_name(".dynsym").unwrap();
        let dyn_symbol_table = dyn_symbol_section.get_data(&elf_binary.file).unwrap();
        let symbols = match dyn_symbol_table {
            SectionData::DynSymbolTable64(entries) => entries
                .iter()
                .map(|s| Symbol {
                    name: elf_binary.symbol_name(s).to_string(),
                    value: s.value() as usize,
                })
                .collect(),
            SectionData::DynSymbolTable32(entries) => entries
                .iter()
                .map(|s| Symbol {
                    name: elf_binary.symbol_name(s).to_string(),
                    value: s.value() as usize,
                })
                .collect(),
            _ => Vec::new(),
        };

        let length = (region::page::ceil((alloc_end - alloc_start) as *const usize) as usize / 4096) * region::page::size();

        if let Ok(map) = MmapOptions::new().len(length).map_anon() {
            println!("Mapped {:x} to {:x}. (sanity check: {:x})", map.as_ptr() as usize, map.as_ptr() as usize + length, region::page::ceil((map.as_ptr() as usize + length) as *const usize) as usize);

            #[cfg(feature = "hacky_hooks")]
            {
                hook_manager::set_hooks(
                    map.as_ptr_range().start as usize..map.as_ptr_range().end as usize,
                    hooks.clone(),
                );
                Ok(AndroidLibrary {
                    memory_map: map,
                    address_shifts: Vec::new(),
                    last_address: 0,
                    symbols,
                    hooks
                })
            }
            #[cfg(not(feature = "hacky_hooks"))]
            {
                hook_manager::add_hooks(hooks);
                Ok(AndroidLibrary {
                    memory_map: map,
                    address_shifts: Vec::new(),
                    last_address: 0,
                    symbols,
                })
            }
        } else {
            Err(ElfLoaderErr::ElfParser {
                source: "Memory mapping failed!",
            })
        }
    }

    fn load(
        library: &mut AndroidLibrary,
        program_header: &ProgramHeader,
        region: &[u8],
    ) -> Result<(), ElfLoaderErr> {
        let virtual_addr = program_header.virtual_addr() as usize;
        let mem_size = program_header.mem_size() as usize;
        let file_size = program_header.file_size() as usize;
        let addr = library.memory_map.as_ptr() as usize;

        if library.shift_address(addr + virtual_addr) < library.last_address {
            println!("Shift needed; addr: {:x}, last_addr: {:x}", addr + virtual_addr, library.last_address);
            library.address_shifts.push(Shift {
                from: addr + virtual_addr,
                shift: library.last_address - (addr + virtual_addr)
            });
        }

        let shifted_start = library.shift_address(addr + virtual_addr) as usize;
        let shifted_end = library.shift_address(addr + virtual_addr + mem_size) as usize;
        let start_addr = region::page::floor(shifted_start as *const c_void) as *mut c_void;
        let end_addr = region::page::ceil(shifted_end as *const c_void);
        print!(
            "{:x} - {:x} (mem_sz: {}, file_sz: {}) [",
            start_addr as usize, end_addr as usize, mem_size, file_size
        );

        let is_standard_page = true; // region::page::size() <= Self::MAX_PAGE_SIZE;

        let flags = program_header.flags();
        let mut prot = Protection::NONE.bits();
        if flags.is_read() || !is_standard_page {
            print!("R");
            prot |= Protection::READ.bits();
        } else {
            print!("-");
        }
        if flags.is_write() || !is_standard_page {
            print!("W");
            prot |= Protection::WRITE.bits();
        } else {
            print!("-");
        }

        if flags.is_execute() || !is_standard_page {
            println!("X]");
            prot |= Protection::EXECUTE.bits();
        } else {
            println!("-]");
        }

        println!("Writing...");
        library.memory_map[shifted_start - addr..shifted_start + file_size - addr].copy_from_slice(region);

        println!("Protecting...");
        unsafe {
            region::protect(
                start_addr,
                end_addr as usize - start_addr as usize,
                Protection::from_bits_truncate(prot),
            )
            .unwrap()
        };

        println!("Done !");
        library.last_address = end_addr as usize;

        Ok(())
    }

    fn relocate(library: &mut AndroidLibrary, entry: RelocationEntry) -> Result<(), ElfLoaderErr> {
        match entry.rtype {
            RelocationType::x86(relocation) => {
                let addend = usize::from_ne_bytes(
                    library.memory_map[entry.offset as usize
                        ..entry.offset as usize + std::mem::size_of::<usize>()]
                        .try_into()
                        .unwrap(),
                );
                match relocation {
                    x86::RelocationTypes::R_386_GLOB_DAT | x86::RelocationTypes::R_386_JMP_SLOT => {
                        Self::absolute_reloc(library, entry, 0);
                        Ok(())
                    }

                    x86::RelocationTypes::R_386_RELATIVE => {
                        Self::relative_reloc(library, entry, addend);
                        Ok(())
                    }

                    x86::RelocationTypes::R_386_32 => {
                        Self::absolute_reloc(library, entry, addend);
                        Ok(())
                    }

                    _ => {
                        eprintln!("Unhandled relocation: {:?}", relocation);
                        Err(ElfLoaderErr::UnsupportedRelocationEntry)
                    }
                }
            }

            RelocationType::x86_64(relocation) => {
                let addend = entry
                    .addend
                    .ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?
                    as usize;
                match relocation {
                    x86_64::RelocationTypes::R_AMD64_JMP_SLOT
                    | x86_64::RelocationTypes::R_AMD64_GLOB_DAT
                    | x86_64::RelocationTypes::R_AMD64_64 => {
                        Self::absolute_reloc(library, entry, addend);
                        Ok(())
                    }

                    x86_64::RelocationTypes::R_AMD64_RELATIVE => {
                        Self::relative_reloc(library, entry, addend);
                        Ok(())
                    }

                    _ => {
                        eprintln!("Unhandled relocation: {:?}", relocation);
                        Err(ElfLoaderErr::UnsupportedRelocationEntry)
                    }
                }
            }

            RelocationType::Arm(relocation) => {
                let addend = usize::from_ne_bytes(
                    library.memory_map[entry.offset as usize
                        ..entry.offset as usize + std::mem::size_of::<usize>()]
                        .try_into()
                        .unwrap(),
                );
                match relocation {
                    arm::RelocationTypes::R_ARM_GLOB_DAT
                    | arm::RelocationTypes::R_ARM_JUMP_SLOT => {
                        Self::absolute_reloc(library, entry, 0);
                        Ok(())
                    }

                    arm::RelocationTypes::R_ARM_RELATIVE => {
                        Self::relative_reloc(library, entry, addend);
                        Ok(())
                    }

                    arm::RelocationTypes::R_ARM_ABS32 => {
                        Self::absolute_reloc(library, entry, addend);
                        Ok(())
                    }

                    _ => {
                        eprintln!("Unhandled relocation: {:?}", relocation);
                        Err(ElfLoaderErr::UnsupportedRelocationEntry)
                    }
                }
            }

            RelocationType::AArch64(relocation) => {
                let addend = entry
                    .addend
                    .ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?
                    as usize;
                match relocation {
                    aarch64::RelocationTypes::R_AARCH64_JUMP_SLOT
                    | aarch64::RelocationTypes::R_AARCH64_GLOB_DAT
                    | aarch64::RelocationTypes::R_AARCH64_ABS64 => {
                        Self::absolute_reloc(library, entry, addend);
                        Ok(())
                    }

                    aarch64::RelocationTypes::R_AARCH64_RELATIVE => {
                        Self::relative_reloc(library, entry, addend);
                        Ok(())
                    }

                    _ => {
                        eprintln!("Unhandled relocation: {:?}", relocation);
                        Err(ElfLoaderErr::UnsupportedRelocationEntry)
                    }
                }
            }
        }
    }
}
