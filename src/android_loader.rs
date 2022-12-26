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
        eprintln!("Page size: {}", page_size::get());
        Ok(AndroidLoader {
            symbol_loader,
            libc: Library::open_self()?
        })
    }

    extern "C" fn no_pthread() -> i32 {
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
            if header.get_type() == Ok(Type::Load) {
                let start = page_start(header.virtual_addr() as usize);
                let end = page_end(start + max(header.file_size(), header.mem_size()) as usize);

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
        // let offset = program_header.offset() as usize;
        let virtual_addr = program_header.virtual_addr() as usize;
        let mem_size = program_header.mem_size() as usize;
        let file_size = program_header.file_size() as usize;
        let addr = library.memory_map.as_ptr() as usize;
        print!("{:x} - {:x} (mem_sz: {}, file_sz: {}) [", page_start(addr + virtual_addr), page_end(addr + virtual_addr + mem_size), mem_size, file_size);

        let flags = program_header.flags();
        let mut prot = 0;
        if flags.is_read() {
            print!("R");
            prot |= PROT_READ;
        } else {
            print!("-");
        }
        if flags.is_write() {
            print!("W");
            prot |= PROT_WRITE;
        } else {
            print!("-");
        }
        if flags.is_execute() {
            println!("X]");
            prot |= PROT_EXEC;
        } else {
            println!("-]");
        }
        library.memory_map[virtual_addr..virtual_addr + file_size].copy_from_slice(region);

        if file_size < mem_size {

        }

        let addr = library.memory_map.as_ptr() as usize;
        unsafe { libc::mprotect(page_start(addr + virtual_addr) as *mut c_void, (page_end(addr + virtual_addr + file_size) - page_start(addr + virtual_addr)) as size_t, prot) };
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
                    x86_64::RelocationTypes::R_AMD64_64 => {
                        self.absolute_reloc(library, entry, addend);
                        Ok(())
                    },

                    x86_64::RelocationTypes::R_AMD64_RELATIVE => {
                        self.relative_reloc(library, entry, addend);
                        Ok(())
                    },

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
                    aarch64::RelocationTypes::R_AARCH64_ABS64 => {
                        self.absolute_reloc(library, entry, addend);
                        Ok(())
                    },

                    aarch64::RelocationTypes::R_AARCH64_RELATIVE => {
                        self.relative_reloc(library, entry, addend);
                        Ok(())
                    },

                    _ => Err(ElfLoaderErr::UnsupportedRelocationEntry)
                }
            }
        }
    }
}
