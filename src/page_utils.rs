pub fn page_start(v: usize) -> usize {
    v & !(page_size::get() - 1)
}

pub fn page_end(v: usize) -> usize {
    page_start(v + (page_size::get() - 1))
}
