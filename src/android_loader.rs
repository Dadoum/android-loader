use elfloader::{ElfBinary, ElfLoader, ElfLoaderErr, Flags, LoadableHeaders, RelocationEntry, RelocationType, VAddr};
use memmap2::{MmapMut, MmapOptions};
use std::fs;
use elfloader::arch::{x86, x86_64, arm, aarch64};
use xmas_elf::program::Type;
use xmas_elf::sections::SectionData;
use xmas_elf::symbol_table::Entry;
use crate::android_library::{AndroidLibrary, Symbol};
use crate::page_utils::{page_end, page_start};

type SymbolLoader = fn(symbol_name: &str) -> Option<extern "C" fn()>;

pub struct AndroidLoader {
    // libc: SymbolLoader
}

#[derive(Debug)]
pub enum AndroidLoaderErr {
    ElfError(ElfLoaderErr),
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

impl AndroidLoader {
    pub fn new() -> AndroidLoader {
        AndroidLoader {

        }
    }

    fn symbol_finder(&self, symbol_name: &str) -> Option<extern "C" fn()> {
        None
    }

    pub fn load_library(&mut self, path: &str) -> Result<AndroidLibrary, AndroidLoaderErr> {
        let file = fs::read(path)?;
        let bin = ElfBinary::new(file.as_slice())?;
        let android_lib_mut = bin.load(self)?;

        let dyn_symbol_section = bin.file.find_section_by_name(".dynsym").unwrap();
        let dyn_symbol_table = dyn_symbol_section.get_data(&bin.file).unwrap();

        let symbols = match dyn_symbol_table {
            SectionData::DynSymbolTable64(entries)
            => entries.iter().map(|s| Symbol {
                name: bin.symbol_name(s).to_string(),
                value: s.value() as usize
            }).collect(),
            SectionData::DynSymbolTable32(entries)
            => Vec::new(),
            _ => Vec::new()
        };

        Ok(AndroidLibrary {
            memory_map: android_lib_mut.memory_map.make_exec()?,
            symbols
        })
    }
}

extern "C" fn undefined_symbol_handler() {
    panic!("Undefined function called.");
}

struct AndroidLibraryMut {
    memory_map: MmapMut
}

impl ElfLoader<AndroidLibraryMut> for AndroidLoader {
    fn allocate(&mut self, load_headers: LoadableHeaders) -> Result<AndroidLibraryMut, ElfLoaderErr> {
        let mut minimum = u64::MAX;
        let mut maximum = u64::MIN;

        for header in load_headers {
            if header.get_type() == Ok(Type::Load) {
                let start = header.virtual_addr();
                let end = header.virtual_addr() + header.file_size();

                if start < minimum {
                    minimum = start;
                }

                if end > maximum {
                    maximum = end;
                }
            }
        }

        let alloc_start = page_start(minimum as usize);
        debug_assert!(alloc_start <= minimum as usize);
        let alloc_end = page_end(maximum as usize);
        debug_assert!(alloc_end >= maximum as usize);

        eprintln!("Allocation size: {}", alloc_end - alloc_start);

        if let Ok(map) = MmapOptions::new()
            .len(alloc_end - alloc_start)
            .map_anon() {
            Ok(AndroidLibraryMut {
                memory_map: map
            })
        } else {
            Err(ElfLoaderErr::ElfParser {
                source: "Memory mapping failed!"
            })
        }
    }

    fn load(&mut self, library: &mut AndroidLibraryMut, flags: Flags, offset: VAddr, region: &[u8]) -> Result<(), ElfLoaderErr> {
        eprintln!("region base {:x} size: {}", offset, region.len());
        library.memory_map[offset as usize..offset as usize + region.len()].copy_from_slice(region);
        Ok(())
    }

    fn relocate(&mut self, library: &mut AndroidLibraryMut, entry: RelocationEntry) -> Result<(), ElfLoaderErr> {
        let offset = entry.offset as usize;
        let mut map = &mut library.memory_map;

        let symbol = match self.symbol_finder("") {
            Some(func) => func,
            None => undefined_symbol_handler as extern "C" fn()
        };

        match entry.rtype {
            RelocationType::x86(relocation) => {
                match relocation {
                    x86::RelocationTypes::R_386_32 | x86::RelocationTypes::R_386_GLOB_DAT | x86::RelocationTypes::R_386_JMP_SLOT => {
                        Err(ElfLoaderErr::UnsupportedRelocationEntry)
                    }
                    x86::RelocationTypes::R_386_RELATIVE => {
                        Err(ElfLoaderErr::UnsupportedRelocationEntry)
                    }
                    _ => {
                        Err(ElfLoaderErr::UnsupportedRelocationEntry)
                    }
                }
            }

            RelocationType::x86_64(relocation) => {
                match relocation {
                    x86_64::RelocationTypes::R_AMD64_JMP_SLOT | x86_64::RelocationTypes::R_AMD64_GLOB_DAT | x86_64::RelocationTypes::R_AMD64_64 => {
                        let num = symbol as u64 + entry.addend.ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;
                        let mut data: [u8; 8] = bytemuck::cast(num);
                        map[offset..offset + 8].copy_from_slice(&data);
                        Ok(())
                    }
                    x86_64::RelocationTypes::R_AMD64_RELATIVE => {
                        let num = map.as_mut_ptr() as u64 + entry.addend.ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;
                        println!("relative {:x}", num);
                        let data: [u8; 8] = bytemuck::cast(num);
                        map[offset..offset + 8].copy_from_slice(&data);
                        Ok(())
                    }
                    _ => {
                        Err(ElfLoaderErr::UnsupportedRelocationEntry)
                    }
                }
            }

            RelocationType::Arm(relocation) => {
                match relocation {
                    _ => {
                        Err(ElfLoaderErr::UnsupportedRelocationEntry)
                    }
                }
            }

            RelocationType::AArch64(relocation) => {
                match relocation {
                    _ => {
                        Err(ElfLoaderErr::UnsupportedRelocationEntry)
                    }
                }
            }
        }
    }
}