use std::collections::HashMap;
use elfloader::ElfBinary;

use memmap2::MmapMut;
use xmas_elf::sections::SectionData;

pub(crate) struct Symbol {
    pub(crate) name: String,
    pub(crate) value: usize,
}

pub struct AndroidLibrary {
    pub(crate) memory_map: MmapMut,
    pub(crate) symbols: HashMap<String, Symbol>,
    pub(crate) strings: HashMap<usize, String>,
}

impl AndroidLibrary {
    fn hash_symbol_name_gnu(symbol_name: &str) -> u32 {
        let mut h: u32 = 5381;

        for c in symbol_name.chars() {
            h = (h << 5).wrapping_add(h.wrapping_add(c as u32));
        }

        h
    }

    pub fn get_symbol(&self, symbol_name: &str) -> Option<*const ()> {
        // the typically way to do this uses hashes, but this works fine if not maximally efficient
        self.symbols.get(symbol_name).map(|symbol| { unsafe { self.memory_map.as_ptr().offset(symbol.value as isize) as *const () } })
    }
}

#[cfg(test)]
mod tests {
    use crate::android_library::AndroidLibrary;

    #[test]
    fn gnu_hash_tests() {
        assert_eq!(AndroidLibrary::hash_symbol_name_gnu(""), 0x00001505);
        assert_eq!(AndroidLibrary::hash_symbol_name_gnu("printf"), 0x156b2bb8);
        assert_eq!(AndroidLibrary::hash_symbol_name_gnu("exit"), 0x7c967e3f);
    }
}
