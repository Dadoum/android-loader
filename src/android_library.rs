use std::{ops::Range, collections::HashMap};

use dlopen2::symbor::Library;
use memmap2::MmapMut;

pub(crate) struct Symbol {
    pub(crate) name: String,
    pub(crate) value: usize,
}

pub struct AndroidLibrary {
    pub(crate) memory_map: MmapMut,
    pub(crate) symbols: Vec<Symbol>,
    pub(crate) libc: Library
    pub(crate) hooks: HashMap<String, usize>,
}

impl AndroidLibrary {
    pub fn get_symbol(&self, symbol_name: &str) -> Option<*const ()> {
        // the typically way to do this uses hashes, but this works fine if not maximally efficient
        self.symbols
            .iter()
            .find(|s| s.name == symbol_name)
            .map(|s| unsafe { self.memory_map.as_ptr().offset(s.value as isize) as *const () })
    }

    pub fn get_range(&self) -> Range<usize> {
        self.memory_map.as_ptr_range().start as usize..self.memory_map.as_ptr_range().end as usize
    }
}
