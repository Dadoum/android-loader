use crate::hook_manager;
use crate::sysv64;
use anyhow::Result;
use memmap2::{MmapOptions, MmapMut};
use region::Protection;
use std::cmp::max;
use std::collections::HashMap;
use std::error::Error;
use std::ffi::CStr;
use std::fmt::{Display, Formatter};
use std::fs;
use std::os::raw::{c_char, c_void};
use std::path::PathBuf;
use std::ptr::null_mut;
use xmas_elf::ElfFile;
use xmas_elf::program::{ProgramHeader, Type};
use xmas_elf::sections::{SectionData, SectionHeader, ShType};
use xmas_elf::symbol_table::{DynEntry64, Entry};
use crate::hook_manager::get_hooks;
use crate::relocation_types::{RelocationType, RelocType};

#[repr(C)]
struct GnuHashTable {
    pub(crate) nbuckets: u32,
    pub(crate) symoffset: u32,
    pub(crate) bloom_size: u32,
    pub(crate) bloom_shift: u32
}

impl GnuHashTable {
    fn hash(symbol_name: &str) -> u32 {
        let mut h: u32 = 5381;

        for c in symbol_name.chars() {
            h = (h << 5).wrapping_add(h.wrapping_add(c as u32));
        }

        h
    }

    pub fn lookup(&self, symbol_name: &str) -> u32 {
        0
    }
}

pub struct AndroidLibrary<'a> {
    pub(crate) file: Vec<u8>,
    pub(crate) elf_file: ElfFile<'a>,
    pub(crate) memory_map: MmapMut,
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub(crate) dyn_symbols: &'a [DynEntry64],
    #[cfg(any(target_arch = "x86", target_arch = "arm"))]
    pub(crate) dyn_symbols: &'a [DynEntry32],
    pub(crate) gnu_hash_table: Option<*const GnuHashTable>
}

impl AndroidLibrary<'_> {
    pub fn get_symbol(&self, symbol_name: &str) -> Option<*const ()> {
        match self.gnu_hash_table {
            Some(hash_table) => {
                self.dyn_symbols.iter().find(|sym| sym.get_name(&self.elf_file) == Ok(symbol_name)).map(|s| s.value() as *const ())
            }
            None => self.dyn_symbols.iter().find(|sym| sym.get_name(&self.elf_file) == Ok(symbol_name)).map(|s| s.value() as *const ())
        }
        // the typically way to do this uses hashes, but this works fine if not maximally efficient
    }
    #[sysv64]
    fn pthread_stub() -> i32 {
        0
    }

    #[sysv64]
    fn undefined_symbol_stub() {
        panic!("tried to call an undefined symbol");
    }

    #[sysv64]
    unsafe fn dlopen(name: *const c_char) -> *mut c_void {
        use crate::hook_manager::get_hooks;
        let mut path_str = CStr::from_ptr(name).to_str().unwrap();

        let _path: String;
        #[cfg(target_family = "windows")]
        {
            _path = path_str.chars()
                .map(|x| match x {
                    '\\' => '/',
                    c => c
                }).collect::<String>();

            path_str = _path.as_str();
        }

        println!("Loading {}", path_str);
        match Self::load(path_str) {
            Ok(lib) => Box::into_raw(Box::new(lib)) as *mut c_void,
            Err(_) => null_mut(),
        }
    }

    #[sysv64]
    unsafe fn dlsym(library: *mut AndroidLibrary, symbol: *const c_char) -> *mut c_void {
        let symbol = CStr::from_ptr(symbol).to_str().unwrap();
        println!("Symbol requested: {}", symbol);
        match library.as_ref().and_then(|lib| lib.get_symbol(symbol)) {
            Some(func) => func as *mut c_void,
            None => null_mut(),
        }
    }

    #[sysv64]
    unsafe fn dlclose(library: *mut AndroidLibrary) {
        let _ = Box::from_raw(library);
    }

    fn symbol_finder(symbol_name: &str, hooks: &HashMap<String, usize>) -> *const () {
        // Check if this function is hooked for this library

        if let Some(func) = hooks.get(symbol_name) {
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

    fn absolute_reloc<T: Entry>(elf_file: &ElfFile, memory_map: &mut MmapMut, dynsym: &[T], hooks: &HashMap<String, usize>, index: usize, offset: usize, addend: usize) {
        let name = dynsym[index].get_name(elf_file);
        let symbol = Self::symbol_finder(name.unwrap(), hooks);

        // addend is always 0, but we still add it to be safe
        // converted to an array in the systme endianess
        let relocated = addend.wrapping_add(symbol as usize).to_ne_bytes();
        memory_map[offset..offset + relocated.len()].copy_from_slice(&relocated);
    }

    fn relative_reloc(memory_map: &mut MmapMut, offset: usize, addend: usize) {
        let relocated = addend
            .wrapping_add(memory_map.as_mut_ptr() as usize)
            .to_ne_bytes();

        memory_map[offset..offset + relocated.len()].copy_from_slice(&relocated);
    }

    #[cfg(not(target_arch="aarch64"))]
    const MAX_PAGE_SIZE: usize = 4096;

    #[cfg(target_arch="aarch64")]
    const MAX_PAGE_SIZE: usize = 65536;

    pub fn load(path: &str) -> Result<AndroidLibrary> {
        let elf_file = ElfFile::new(fs::read(path)?).map_err(|err| AndroidLoaderErr::ElfParsingError(err.to_string()))?;

        let mut minimum = usize::MAX;
        let mut maximum = usize::MIN;

        for header in elf_file.program_iter() {
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
        let alloc_end = region::page::ceil(maximum as *const ()) as usize;

        let mut memory_map = MmapOptions::new().len(alloc_end - alloc_start).map_anon()?;

        for program_header in elf_file.program_iter() {
            if program_header.get_type() == Ok(Type::Load) {
                let data = match program_header {
                    ProgramHeader::Ph32(inner) => inner.raw_data(&elf_file),
                    ProgramHeader::Ph64(inner) => inner.raw_data(&elf_file),
                };

                let virtual_addr = program_header.virtual_addr() as usize;
                let mem_size = program_header.mem_size() as usize;
                let file_size = program_header.file_size() as usize;
                let addr = memory_map.as_ptr() as usize;

                let start_addr = region::page::floor((addr + virtual_addr) as *const c_void) as *mut c_void;
                let end_addr = region::page::ceil((addr + virtual_addr + mem_size) as *const c_void);
                print!(
                    "{:x} - {:x} (mem_sz: {}, file_sz: {}) [",
                    start_addr as usize, end_addr as usize, mem_size, file_size
                );

                let is_standard_page = region::page::size() <= Self::MAX_PAGE_SIZE;

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
                memory_map[virtual_addr..virtual_addr + file_size].copy_from_slice(data);

                unsafe {
                    region::protect(
                        start_addr,
                        end_addr as usize - start_addr as usize,
                        Protection::from_bits_truncate(prot),
                    )?;
                }
            }
        }

        let hooks = get_hooks();
        let mut dyn_symbols: &[DynEntry64] = &[];
        let mut gnu_hash_table = None;
        for section in elf_file.section_iter() {
            match section.get_type() {
                Ok(ShType::Hash) => {
                    if section.get_name(&elf_file) == Ok(".gnu.hash") {
                        gnu_hash_table = Some(section.address() as *const GnuHashTable);
                    }
                }
                Ok(ShType::DynSym) => {
                    dyn_symbols = match section.get_data(&elf_file).map_err(|err| AndroidLoaderErr::ElfParsingError(err.to_string()))? { // FIXME expensive
                        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                        SectionData::DynSymbolTable64(entries) => entries,
                        #[cfg(any(target_arch = "x86", target_arch = "arm"))]
                        SectionData::DynSymbolTable32(entries) => entries,
                        _ => return Err(AndroidLoaderErr::ElfParsingError("Unsupported Dynamic symbol table data".to_string()).into())
                    };
                }
                Ok(ShType::Rel) | Ok(ShType::Rela) => {
                    match section.get_data(&elf_file) {
                        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                        Ok(SectionData::Rela64(relocations)) => {
                            for relocation in relocations {
                                match RelocationType::from(relocation.get_type()) {
                                    RelocationType::Absolute | RelocationType::GlobalData | RelocationType::JumpSlot => {
                                        Self::absolute_reloc(&elf_file, &mut memory_map, dyn_symbols, &hooks, relocation.get_symbol_table_index() as usize, relocation.get_offset() as usize, relocation.get_addend() as usize);
                                    }
                                    RelocationType::Relative => {
                                        Self::relative_reloc(&mut memory_map, relocation.get_offset() as usize, relocation.get_addend() as usize);
                                    }
                                    RelocationType::Unknown(reloc_number) => {
                                        return Err(AndroidLoaderErr::UnsupportedRelocation(reloc_number).into());
                                    }
                                }
                            }
                        }
                        #[cfg(any(target_arch = "x86", target_arch = "arm"))]
                        Ok(SectionData::Rel32(relocations)) => {
                            let addend = usize::from_ne_bytes(
                                library.memory_map[entry.offset as usize
                                    ..entry.offset as usize + std::mem::size_of::<usize>()]
                                    .try_into()
                                    .unwrap(),
                            );
                            for relocation in relocations.iter() {
                                for relocation in relocations {
                                    match RelocationType::from(relocation.get_type()) {
                                        RelocationType::Absolute => {
                                            Self::absolute_reloc(&mut android_library, dyn_symbol_section.unwrap(), &hooks, relocation.get_symbol_table_index() as usize, relocation.get_offset() as usize, 0);
                                        }
                                        RelocationType::GlobalData | RelocationType::JumpSlot => {
                                            Self::absolute_reloc(&mut android_library, dyn_symbol_section.unwrap(), &hooks, relocation.get_symbol_table_index() as usize, relocation.get_offset() as usize, addend);
                                        }
                                        RelocationType::Relative => {
                                            Self::relative_reloc(&mut android_library, relocation.get_offset() as usize, addend);
                                        }
                                        RelocationType::Unknown(reloc_number) => {
                                            return Err(AndroidLoaderErr::UnsupportedRelocation(reloc_number).into());
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        let mut android_library = AndroidLibrary {
            file,
            elf_file,
            memory_map,
            gnu_hash_table,
            dyn_symbols
        };

        Ok(android_library)
    }
}

#[derive(Debug)]
enum AndroidLoaderErr {
    ElfParsingError(String),
    UnsupportedRelocation(RelocType)
}

impl Display for AndroidLoaderErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "AndroidLoaderErr::{self:?}")
    }
}

impl Error for AndroidLoaderErr {}

#[cfg(test)]
mod tests {
    use crate::android_library::GnuHashTable;

    #[test]
    fn gnu_hash_tests() {
        assert_eq!(GnuHashTable::hash(""), 0x00001505);
        assert_eq!(GnuHashTable::hash("printf"), 0x156b2bb8);
        assert_eq!(GnuHashTable::hash("exit"), 0x7c967e3f);
    }
}
