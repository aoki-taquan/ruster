#[derive(Debug, Default, Clone, Copy)]
pub struct Counters {
    pub rx: u64,
    pub tx: u64,
    pub drop: u64,
}

impl Counters {
    pub fn inc_drop(&mut self) {
        self.drop += 1;
    }
}
