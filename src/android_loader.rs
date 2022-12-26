use std::cmp::max;
use std::ffi::c_void;
use elfloader::{ElfBinary, ElfLoader, ElfLoaderErr, LoadableHeaders, RelocationEntry, RelocationType};
use memmap2::MmapOptions;
use std::fs;
use std::mem::size_of;
use dlopen2::symbor::Library;
use elfloader::arch::{x86, x86_64, arm, aarch64};
use libc::{PROT_EXEC, PROT_READ, PROT_WRITE, size_t};
use xmas_elf::program::{ProgramHeader, Type};
use xmas_elf::sections::SectionData;
use xmas_elf::symbol_table::Entry;
use crate::android_library::{AndroidLibrary, Symbol};
use crate::page_utils::{page_end, page_start};

type SymbolLoader = fn(symbol_name: &str) -> Option<extern "C" fn()>;

pub struct AndroidLoader {
    symbol_loader: SymbolLoader,
    libc: Library
}

#[derive(Debug)]
pub enum AndroidLoaderErr {
    ElfError(ElfLoaderErr),
    LibcLoadError(dlopen2::Error),
    FileError(std::io::Error)
}

impl From<ElfLoaderErr> for AndroidLoaderErr {
    fn from(err: ElfLoaderErr) -> Self {
        AndroidLoaderErr::ElfError(err)
    }
}

impl From<std::io::Error> for AndroidLoaderErr {
    fn from(err: std::io::Error) -> Self {
        AndroidLoaderErr::FileError(err)
    }
}

impl From<dlopen2::Error> for AndroidLoaderErr {
    fn from(err: dlopen2::Error) -> Self {
        AndroidLoaderErr::LibcLoadError(err)
    }
}

impl AndroidLoader {
    pub fn new(symbol_loader: SymbolLoader) -> Result<AndroidLoader, AndroidLoaderErr> {
        Ok(AndroidLoader {
            symbol_loader,
            libc: Library::open_self()?
        })
    }

    extern "C" fn no_pthread() -> i32 {
        println!("pthread: no crash plz");
        0
    }

    fn symbol_finder(&self, symbol_name: &str) -> Option<extern "C" fn()> {
        if let Some(val) = (self.symbol_loader)(symbol_name) {
            return Some(val);
        }

        unsafe {
            if symbol_name.starts_with("pthread_") {
                return Some(std::mem::transmute(AndroidLoader::no_pthread as *mut ()));
            }

            match self.libc.symbol(symbol_name) {
                Ok(sym) => Some(*sym),
                Err(_) => None
            }
        }
    }

    pub fn load_library(&self, path: &str) -> Result<AndroidLibrary, AndroidLoaderErr> {
        let file = fs::read(path)?;
        let bin = ElfBinary::new(file.as_slice())?;

        Ok(bin.load(self)?)
    }
}

extern "C" fn undefined_symbol_handler() {
    panic!("Undefined function called.");
}

impl AndroidLoader {
    const WORD_SIZE: usize = size_of::<usize>();

    fn absolute_reloc(&self, library: &mut AndroidLibrary, entry: RelocationEntry, addend: usize) {
        let offset = entry.offset as usize;

        let symbol = match self.symbol_finder(library.symbols[entry.index as usize].name.as_str()) {
            Some(func) => func,
            None => undefined_symbol_handler as extern "C" fn()
        };

        let num = symbol as usize + addend;
        let data: [u8; AndroidLoader::WORD_SIZE] = bytemuck::cast(num);
        library.memory_map[offset..offset + AndroidLoader::WORD_SIZE].copy_from_slice(&data);
        // unsafe { *((library.memory_map.as_mut_ptr() as u64 + offset as u64) as *mut usize) = num; }
    }

    fn relative_reloc(&self, library: &mut AndroidLibrary, entry: RelocationEntry, addend: usize) {
        let offset = entry.offset as usize;
        let map = &mut library.memory_map;

        let num = map.as_mut_ptr() as usize + addend;
        let data: [u8; AndroidLoader::WORD_SIZE] = bytemuck::cast(num);
        map[offset..offset + AndroidLoader::WORD_SIZE].copy_from_slice(&data);
    }
}

impl ElfLoader<AndroidLibrary> for AndroidLoader {
    fn allocate(&self, load_headers: LoadableHeaders, elf_binary: &ElfBinary) -> Result<AndroidLibrary, ElfLoaderErr> {
        let mut minimum = usize::MAX;
        let mut maximum = usize::MIN;

        for header in load_headers {
            match header.get_type() {
                Ok(Type::Load) => {
                    let start = page_start(header.virtual_addr() as usize);
                    let end = page_end(start + max(header.file_size(), header.mem_size()) as usize);

                    if start < minimum {
                        minimum = start;
                    }

                    if end > maximum {
                        maximum = end;
                    }
                }
                _ => ()
            }
        }

        let alloc_start = page_start(minimum as usize);
        debug_assert!(alloc_start <= minimum as usize);
        let alloc_end = page_end(maximum as usize);
        debug_assert!(alloc_end >= maximum as usize);

        let dyn_symbol_section = elf_binary.file.find_section_by_name(".dynsym").unwrap();
        let dyn_symbol_table = dyn_symbol_section.get_data(&elf_binary.file).unwrap();
        let symbols = match dyn_symbol_table {
            SectionData::DynSymbolTable64(entries)
            => entries.iter().map(|s| Symbol {
                name: elf_binary.symbol_name(s).to_string(),
                value: s.value() as usize
            }).collect(),
            SectionData::DynSymbolTable32(entries)
            => entries.iter().map(|s| Symbol {
                name: elf_binary.symbol_name(s).to_string(),
                value: s.value() as usize
            }).collect(),
            _ => Vec::new()
        };

        if let Ok(map) = MmapOptions::new()
            .len(alloc_end - alloc_start)
            .map_anon() {
            Ok(AndroidLibrary {
                memory_map: map,
                symbols
            })
        } else {
            Err(ElfLoaderErr::ElfParser {
                source: "Memory mapping failed!"
            })
        }
    }

    fn load(&self, library: &mut AndroidLibrary, program_header: &ProgramHeader, region: &[u8]) -> Result<(), ElfLoaderErr> {
        let offset = program_header.offset() as usize;
        let mem_size = program_header.mem_size() as usize;
        // let program::Ph64(header) = program_header;
        let addr = library.memory_map.as_ptr() as usize;
        println!("{:x} - {:x} ({})", page_start(addr + offset), page_end(addr + offset + mem_size), offset + mem_size);
        library.memory_map[offset..offset + region.len()].copy_from_slice(region);


        /*
        unsafe {
            let start = page_start(addr + offset);
            let mapped = libc::mmap(
                start as *mut c_void,
                (page_end(addr + offset + mem_size) - start) as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                MAP_FIXED|MAP_PRIVATE|MAP_ANON,
                -1,
                0
            );
            // if mapped == MAP_FAILED {
            //     return Result::Err(ElfLoaderErr::ElfParser {
            //         source: "AAAAAAAAAAAAAa"
            //     });
            // }

        }
        // */

        let flags = program_header.flags();
        let mut prot = 0;
        if flags.is_read() {
            prot |= PROT_READ;
        }
        if flags.is_execute() {
            prot |= PROT_EXEC;
        }
        if flags.is_write() {
            prot |= PROT_WRITE;
        }

        let addr = library.memory_map.as_ptr() as usize;
        unsafe { libc::mprotect(page_start(addr + offset as usize) as *mut c_void, (page_end(addr + region.len()) - addr) as size_t, prot) };
        Ok(())
    }

    fn relocate(&self, library: &mut AndroidLibrary, entry: RelocationEntry) -> Result<(), ElfLoaderErr> {
        match entry.rtype {
            RelocationType::x86(relocation) => {
                match relocation {
                    x86::RelocationTypes::R_386_GLOB_DAT |
                    x86::RelocationTypes::R_386_JMP_SLOT |
                    x86::RelocationTypes::R_386_32 => Err(ElfLoaderErr::UnsupportedRelocationEntry),

                    x86::RelocationTypes::R_386_RELATIVE => Err(ElfLoaderErr::UnsupportedRelocationEntry),

                    _ => Err(ElfLoaderErr::UnsupportedRelocationEntry)
                }
            }

            RelocationType::x86_64(relocation) => {
                let addend = entry.addend.ok_or(ElfLoaderErr::UnsupportedRelocationEntry)? as usize;
                match relocation {
                    x86_64::RelocationTypes::R_AMD64_JMP_SLOT |
                    x86_64::RelocationTypes::R_AMD64_GLOB_DAT |
                    x86_64::RelocationTypes::R_AMD64_64 => Ok(self.absolute_reloc(library, entry, addend)),

                    x86_64::RelocationTypes::R_AMD64_RELATIVE => Ok(self.relative_reloc(library, entry, addend)),

                    _ => Err(ElfLoaderErr::UnsupportedRelocationEntry)
                }
            }

            RelocationType::Arm(relocation) => {
                match relocation {
                    arm::RelocationTypes::R_ARM_JUMP_SLOT |
                    arm::RelocationTypes::R_ARM_GLOB_DAT  |
                    arm::RelocationTypes::R_ARM_ABS32 => Err(ElfLoaderErr::UnsupportedRelocationEntry),

                    arm::RelocationTypes::R_ARM_RELATIVE => Err(ElfLoaderErr::UnsupportedRelocationEntry),

                    _ => Err(ElfLoaderErr::UnsupportedRelocationEntry)
                }
            }

            RelocationType::AArch64(relocation) => {
                let addend = entry.addend.ok_or(ElfLoaderErr::UnsupportedRelocationEntry)? as usize;
                match relocation {
                    aarch64::RelocationTypes::R_AARCH64_JUMP_SLOT |
                    aarch64::RelocationTypes::R_AARCH64_GLOB_DAT  |
                    aarch64::RelocationTypes::R_AARCH64_ABS64 => Ok(self.absolute_reloc(library, entry, addend)),

                    aarch64::RelocationTypes::R_AARCH64_RELATIVE => Ok(self.relative_reloc(library, entry, addend)),

                    _ => Err(ElfLoaderErr::UnsupportedRelocationEntry)
                }
            }
        }
    }
}