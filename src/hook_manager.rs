use lazy_static::lazy_static;
use std::{arch::asm, collections::HashMap, ops::Range, sync::Mutex};
#[inline(always)]
#[cfg(target_arch = "aarch64")]
/// Get the caller of the current function
/// MUST be inlined, otherwise the caller will be the function that calls this one
// On aarch64, the caller is stored in lr, which is the return address
pub fn get_caller() -> usize {
    let lr: usize;
    unsafe { asm!("mov {}, lr", out(reg) lr) };
    lr
}

#[inline(always)]
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
/// Get the caller of the current function
/// MUST be inlined, otherwise the caller will be the function that calls this one
// On x86, the caller is stored on the stack, so we just read the bottom of the stack
// TODO: Verify that this is correct
pub fn get_caller() -> usize {
    let rbp: usize;
    unsafe { asm!("mov {}, rbp", out(reg) rbp) };
    rbp
}

pub struct Hook {
    original: usize,
    hook: usize,
    caller: usize,
}

impl Clone for Hook {
    fn clone(&self) -> Self {
        Hook {
            original: self.original,
            hook: self.hook,
            caller: self.caller,
        }
    }
}

//struct HookList {
//   hooks: Vec<Hook>,
//}

// Global HashMap of memory range -> HookList
lazy_static! {
    static ref HOOKS: Mutex<HashMap<Range<usize>, Vec<Hook>>> = Mutex::new(HashMap::new());
}

pub fn get_range(point: usize) -> Range<usize> {
    let mut range = Range { start: 0, end: 0 };
    let hooks = HOOKS.lock().unwrap();
    for (key, _) in hooks.iter() {
        if key.contains(&point) {
            range = key.start..key.end;
            break;
        }
    }
    range
}

pub fn get_hooks(range: Range<usize>) -> Option<Vec<Hook>> {
    let hooks = HOOKS.lock().unwrap();
    hooks.get(&range).cloned()
}

pub fn add_hook(range: Range<usize>, hook: Hook) {
    let mut hooks = HOOKS.lock().unwrap();
    let hook_list = hooks.entry(range).or_insert(Vec::new());
    hook_list.push(hook);
}
