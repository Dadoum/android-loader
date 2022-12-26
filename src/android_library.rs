use memmap2::MmapMut;

pub(crate) struct Symbol {
    pub(crate) name: String,
    pub(crate) value: usize
}

pub struct AndroidLibrary {
    pub(crate) memory_map: MmapMut,
    pub(crate) symbols: Vec<Symbol>
}

impl AndroidLibrary {
    pub fn get_symbol(&self, symbol_name: &str) -> Option<extern "C" fn()> {
        // we don't use Elf hashes, because I'm to lazy to figure out how to get the functions from
        // hashes and memory_map without triggering the borrow checker.
        let mut symbol_value = None;

        for symbol in &self.symbols {
            if symbol.name == symbol_name {
                symbol_value = Some(symbol.value);
            }
        }

        match symbol_value {
            Some(val) => Some(unsafe { std::mem::transmute(self.memory_map.as_ptr() as usize + val) }),
            None => None
        }
    }
}
