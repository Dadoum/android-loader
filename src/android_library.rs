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
use std::{fs, slice};
use std::os::raw::{c_char, c_void};
use std::path::PathBuf;
use std::ptr::null_mut;
use xmas_elf::ElfFile;
use xmas_elf::program::{ProgramHeader, Type};
use xmas_elf::sections::{SectionData, SectionHeader, ShType};
use xmas_elf::symbol_table::{DynEntry64, DynEntry32, Entry};
use zero::{read, read_str};

use crate::hook_manager::get_hooks;
use crate::relocation_types::{RelocationType, RelocType};

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
type DynEntry = DynEntry64;
#[cfg(any(target_arch = "x86", target_arch = "arm"))]
type DynEntry = DynEntry32;

// GnuHashTable adapted from goblin code

#[repr(C)]
pub(crate) struct GnuHashTable<'a> {
    /// Index of the first symbol in the `.dynsym` table which is accessible with
    /// the hash table
    symindex: u32,
    /// Shift count used in the bloom filter
    shift2: u32,
    /// 2 bit bloom filter on `chains`
    // Either 32 or 64-bit depending on the class of object
    bloom_filter: &'a [usize],
    /// GNU hash table bucket array; indexes start at 0. This array holds symbol
    /// table indexes and contains the index of hashes in `chains`
    buckets: &'a [u32],
    /// Hash values; indexes start at 0. This array holds symbol table indexes.
    chains: &'a [u32], // => chains[dynsyms.len() - symindex]
    dynsyms: &'a [DynEntry],
}

impl<'a> GnuHashTable<'a> {
    unsafe fn new(hashtab: &'a [u8], dynsyms: &'a [DynEntry]) -> GnuHashTable<'a> {
        let [nbuckets, symindex, maskwords, shift2] =
            (hashtab.as_ptr() as *const u32 as *const [u32; 4]).read();

        let hashtab = &hashtab[16..];
        {
            // SAFETY: Condition to check for an overflow
            //   size_of(chains) + size_of(buckets) + size_of(bloom_filter) == size_of(hashtab)
            const U32_SIZE: usize = std::mem::size_of::<u32>();
            const INT_SIZE: usize = std::mem::size_of::<isize>();

            let chains_size = (dynsyms.len() - symindex as usize).checked_mul(U32_SIZE);
            let buckets_size = (nbuckets as usize).checked_mul(U32_SIZE);
            let bloom_size = (maskwords as usize).checked_mul(INT_SIZE);

            let total_size = match (chains_size, buckets_size, bloom_size) {
                (Some(a), Some(b), Some(c)) => {
                    a.checked_add(b).and_then(|t| t.checked_add(c))
                }
                _ => None,
            };
        }

        let bloom_filter_ptr = hashtab.as_ptr() as *const usize;
        let buckets_ptr = bloom_filter_ptr.add(maskwords as usize) as *const u32;
        let chains_ptr = buckets_ptr.add(nbuckets as usize);
        let bloom_filter = slice::from_raw_parts(bloom_filter_ptr, maskwords as usize);
        let buckets = slice::from_raw_parts(buckets_ptr, nbuckets as usize);
        let chains = slice::from_raw_parts(chains_ptr, dynsyms.len() - symindex as usize);
        Self {
            symindex,
            shift2,
            bloom_filter,
            buckets,
            chains,
            dynsyms,
        }
    }

    fn hash(symbol_name: &str) -> u32 {
        let mut h: u32 = 5381;

        for c in symbol_name.chars() {
            h = (h << 5).wrapping_add(h.wrapping_add(c as u32));
        }

        h
    }

    pub unsafe fn lookup(&self, android_library: &AndroidLibrary, symbol: &str, dynstrtab: &[u8]) -> Option<*const ()> {
        let hash = Self::hash(symbol);

        const MASK_LOWEST_BIT: u32 = 0xffff_fffe;
        let bucket = self.buckets[hash as usize % self.buckets.len()];

        // Empty hash chain, symbol not present
        if bucket < self.symindex {
            return None;
        }
        // Walk the chain until the symbol is found or the chain is exhausted.
        let chain_idx = bucket - self.symindex;
        let hash = hash & MASK_LOWEST_BIT;
        let chains = &self.chains.get((chain_idx as usize)..)?;
        let dynsyms = &self.dynsyms.get((bucket as usize)..)?;
        for (hash2, symb) in chains.iter().zip(dynsyms.iter()) {
            if (hash == (hash2 & MASK_LOWEST_BIT))
                && (symbol == read_str(&dynstrtab[(symb.name() as usize)..]))
            {
                return Some(android_library.memory_map.as_ptr().offset(symb.value() as isize) as *const ());
            }
            // Chain ends with an element with the lowest bit set to 1.
            if hash2 & 1 == 1 {
                break;
            }
        }
        None
    }
}

pub struct AndroidLibrary<'a> {
    pub(crate) file: Box<Vec<u8>>,
    pub(crate) memory_map: MmapMut,
    pub(crate) dyn_symbols: &'a [DynEntry],
    pub(crate) dyn_strs: &'a [u8],
    pub(crate) gnu_hash_table: Option<GnuHashTable<'a>>
}

impl AndroidLibrary<'_> {
    pub fn get_symbol(&self, symbol_name: &str) -> Option<*const ()> {
        let elf_file = ElfFile::new(&self.file).unwrap();
        match &self.gnu_hash_table {
            Some(hash_table) => {
                unsafe {
                    hash_table.lookup(&self, symbol_name, self.dyn_strs)
                }
            }
            None => unsafe { self.dyn_symbols.iter().find(|sym| sym.get_name(&elf_file) == Ok(symbol_name)).map(|s| self.memory_map.as_ptr().offset(s.value() as isize) as *const ()) }
        }
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

    fn absolute_reloc<T: Entry>(elf_file: &ElfFile, memory_map: &mut MmapMut, dynsym: &[T], dynstrings: &[u8], hooks: &HashMap<String, usize>, index: usize, offset: usize, addend: usize) {
        let name =
            read_str(&dynstrings[(dynsym[index].name() as usize)..]);
        let symbol = Self::symbol_finder(name, hooks);

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

    pub fn load<'a>(path: &str) -> Result<AndroidLibrary<'a>> {
        let file = Box::new(fs::read(path)?);
        let file_leak_ptr = Box::into_raw(file);
        let file_leak = unsafe { file_leak_ptr.as_ref().unwrap() };
        let elf_file = ElfFile::new(&file_leak).map_err(|err| AndroidLoaderErr::ElfParsingError(err.to_string()))?;

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
        let mut dyn_symbols: &[DynEntry] = &[];
        let mut dyn_strings: &[u8] = &[];
        let mut gnu_hash_table = None;

        for section in elf_file.section_iter() {
            match section.get_type() {
                Ok(ShType::OsSpecific(0x6FFFFFF6)) => unsafe {
                    gnu_hash_table = Some(GnuHashTable::new(section.raw_data(&elf_file), dyn_symbols));
                }
                Ok(ShType::StrTab) => {
                    if section.get_name(&elf_file) == Ok(".dynstr") {
                        dyn_strings = section.raw_data(&elf_file);
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
                                        Self::absolute_reloc(&elf_file, &mut memory_map, dyn_symbols, dyn_strings, &hooks, relocation.get_symbol_table_index() as usize, relocation.get_offset() as usize, relocation.get_addend() as usize);
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

        let android_library = AndroidLibrary {
            file: unsafe { Box::from_raw(file_leak_ptr) },
            memory_map,
            gnu_hash_table,
            dyn_symbols,
            dyn_strs: dyn_strings
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
