use std::ffi::{c_char, c_void};
use elfloader::{ElfBinary, ElfLoader, ElfLoaderErr, Flags, LoadableHeaders, RelocationEntry, RelocationType, VAddr};
use libc::{MAP_ANONYMOUS, MAP_PRIVATE, mmap, PROT_NONE, SIG_DFL, signal, SIGSEGV};
use memmap2::{Mmap, MmapMut, MmapOptions};
use page_size;
use std::fs;
use std::ptr::null;
use elfloader::arch::{x86, x86_64, arm, aarch64};
use xmas_elf::program::Type;
use xmas_elf::sections::SectionData;
use xmas_elf::symbol_table::Entry;

pub fn page_start(v: usize) -> usize {
    v & !(page_size::get() - 1)
}
pub fn page_align(v: usize) -> usize {
    v & (page_size::get() - 1)
}

pub fn page_end(v: usize) -> usize {
    page_start(v + (page_size::get() - 1))
}

struct AndroidLoader {
    current_map: Option<MmapMut>,
    loaded_maps: Vec<Mmap>
}

impl AndroidLoader {
    pub fn new() -> AndroidLoader {
        AndroidLoader {
            current_map: None,
            loaded_maps: Vec::new()
        }
    }

    pub fn load_library(mut self, binary: &ElfBinary) -> Result<AndroidLoader, ElfLoaderErr> {
        binary.load(&mut self)?;

        if let Some(map) = self.current_map {
            match map.make_exec() {
                Ok(executable_map) => {
                    self.loaded_maps.push(executable_map);
                    Ok(AndroidLoader {
                        current_map: None,
                        loaded_maps: self.loaded_maps
                    })
                }
                Err(error) => {
                    Err(ElfLoaderErr::ElfParser {
                        source: "Mmap failed"
                    })
                }
            }
        } else {
            Err(ElfLoaderErr::ElfParser {
                source: "Failed to load ELF file??"
            })
        }
    }

    pub fn get_symbol(&self, binary: &ElfBinary, symbol_name: &str) -> *mut c_void {
        // let hash = elf_hash(symbol_name);
        let dyn_symbol_section = binary.file.find_section_by_name(".dynsym").unwrap();
        let dyn_symbol_table = dyn_symbol_section.get_data(&binary.file).unwrap();

        println!("{:x}", self.loaded_maps[1].as_ptr() as usize);

        if let SectionData::DynSymbolTable64(entries) = dyn_symbol_table {
            for entry in entries {
                if entry.get_name(&binary.file) == Ok(symbol_name) {
                    println!("val: {:x}", entry.value());
                    return unsafe { std::mem::transmute(self.loaded_maps[1].as_ptr() as usize + entry.value() as usize) };
                }
            }
        }
        eprintln!("Symbol not found :(");
        unsafe { std::mem::transmute(null::<u8>()) }
    }
}

extern "C" fn undefined_symbol_handler() {
    panic!("Undefined function called.");
}

impl ElfLoader for AndroidLoader {
    fn allocate(&mut self, load_headers: LoadableHeaders) -> Result<(), ElfLoaderErr> {
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
            self.current_map = Some(map);
            Ok(())
        } else {
            Err(ElfLoaderErr::ElfParser {
                source: "Memory mapping failed!"
            })
        }
    }

    fn load(&mut self, flags: Flags, offset: VAddr, region: &[u8]) -> Result<(), ElfLoaderErr> {
        if let Some(map) = &mut self.current_map {
            eprintln!("region base {:x} size: {}", offset, region.len());

            map[offset as usize..offset as usize + region.len()].copy_from_slice(region);
            Ok(())
        } else {
            Err(ElfLoaderErr::ElfParser {
                source: "Memory has not been allocated before!"
            })
        }
    }

    fn relocate(&mut self, entry: RelocationEntry) -> Result<(), ElfLoaderErr> {
        if let Some(map) = &mut self.current_map {
            let offset = entry.offset as usize;

            match entry.rtype {
                RelocationType::x86(relocation) => {
                    match relocation {
                        x86::RelocationTypes::R_386_32 => {
                            Err(ElfLoaderErr::UnsupportedRelocationEntry)
                        }
                        x86::RelocationTypes::R_386_GLOB_DAT => {
                            Err(ElfLoaderErr::UnsupportedRelocationEntry)
                        }
                        x86::RelocationTypes::R_386_JMP_SLOT => {
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
                    let symbol = undefined_symbol_handler as extern "C" fn();
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
        } else {
            Err(ElfLoaderErr::ElfParser {
                source: "Memory has not been allocated before!"
            })
        }
    }
}

fn main() {
    let mut loader = AndroidLoader::new();
    let core_adi_file = fs::read("lib/x86_64/libCoreADI.so").expect("Cannot read CoreADI");
    let core_adi = ElfBinary::new(core_adi_file.as_slice()).expect("Failed preliminary load of CoreADI");
    loader = loader.load_library(&core_adi).expect("Cannot load CoreADI");
    let store_services_core_file = fs::read("lib/x86_64/libstoreservicescore.so").expect("Cannot read StoreServicesCore");
    let store_services_core = ElfBinary::new(store_services_core_file.as_slice()).expect("Failed preliminary load of StoreServicesCore");
    loader = loader.load_library(&store_services_core).expect("Cannot load StoreServicesCore");

    println!("Loaded ! Let's start ^^");
    let set_android_identifier: extern "C" fn() -> i32 = unsafe { std::mem::transmute(loader.get_symbol(&store_services_core, "Sph98paBcz")) }; // Sph98paBcz abort
    println!("{:p}", set_android_identifier as *const ());
    set_android_identifier();
}
