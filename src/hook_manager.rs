use lazy_static::lazy_static;
use std::{arch::asm, collections::HashMap, ops::Range, sync::Mutex};

lazy_static! {
    // Create a Mutex, surrounding a HashMap of Range<usize> -> HashMap<String, usize>
    // The Range<usize> is the range of memory that the library is mapped to
    // The HashMap<String, usize> is the list of hooks, where the key is the name of the hook, and the value is the address of the hook
    static ref HOOKS: Mutex<HashMap<Range<usize>, HashMap<String, usize>>> =
        Mutex::new(HashMap::new());
}

/// Get the range containing the given point, or None if no range contains it
pub fn get_range(point: usize) -> Option<Range<usize>> {
    let mut range = None;
    // Get the lock on the global HashMap
    let hooks = HOOKS.lock().unwrap();
    // Iterate over the keys of the HashMap
    for (key, _) in hooks.iter() {
        // If the key contains the point, we found the range
        if key.contains(&point) {
            range = Some(key.start..key.end);
            break;
        }
    }
    range
}

/// Get the list of hooks for the given range, or None if no such range exists
pub fn get_hooks(range: Range<usize>) -> Option<HashMap<String, usize>> {
    let hooks = HOOKS.lock().unwrap();
    hooks.get(&range).cloned()
}

/// Set the list of hooks for the given range
pub fn set_hooks(range: Range<usize>, hooks: HashMap<String, usize>) {
    let mut hook_list = HOOKS.lock().unwrap();
    hook_list.insert(range, hooks);
}

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