use std::collections::HashMap;

use memmap2::MmapMut;

#[derive(Debug)]
pub(crate) struct Symbol {
    pub(crate) name: String,
    pub(crate) value: usize,
}

#[derive(Debug)]
pub(crate) struct Shift {
    pub(crate) from: usize,
    pub(crate) shift: usize
}

pub struct AndroidLibrary {
    pub(crate) memory_map: MmapMut,
    pub(crate) symbols: Vec<Symbol>,

    pub(crate) last_address: usize,
    pub(crate) address_shifts: Vec<Shift>,

    #[cfg(feature = "hacky_hooks")]
    // IMPORTANT: Updating this will NOT change the hooks in use, they MUST be specified during load
    pub(crate) hooks: HashMap<String, usize>,
}

impl AndroidLibrary {
    pub(crate) fn shift_address(&self, address: usize) -> usize {
        let mut addr = address;
        for shift in self.address_shifts.iter().rev() {
            if addr >= shift.from {
                addr += shift.shift;
                // println!("Shift of {:x} to {:x} (shift starting from {:x})", address, addr, shift.from);
                break;
            }
        }
        addr
    }

    pub fn get_symbol(&self, symbol_name: &str) -> Option<*const ()> {
        // the typically way to do this uses hashes, but this works fine if not maximally efficient
        self.symbols
            .iter()
            .find(|s| s.name == symbol_name)
            .map(|s| unsafe { self.shift_address(self.memory_map.as_ptr().offset(s.value as isize) as usize) as *const () })
    }
}
