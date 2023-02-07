use lazy_static::lazy_static;
use std::{collections::HashMap, sync::Mutex};
use std::sync::MutexGuard;

lazy_static! {
    static ref HOOKS: Mutex<HashMap<String, usize>> = Mutex::new(HashMap::new());
}

/// Get the list of hooks
pub fn get_hooks<'a>() -> MutexGuard<'a, HashMap<String, usize>> {
    let hooks = HOOKS.lock().unwrap();
    hooks
}

/// Add a list of hooks to the global list
pub fn add_hooks(hooks: HashMap<String, usize>) {
    let mut global_hooks = HOOKS.lock().unwrap();
    for (key, value) in hooks.iter() {
        global_hooks.insert(key.clone(), *value);
    }
}
