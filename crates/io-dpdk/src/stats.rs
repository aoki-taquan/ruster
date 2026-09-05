#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendStat {
    AllocationFailed,
    TxAccepted,
    TxRejected,
    Cancelled,
    Abandoned,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct BackendStats {
    allocation_failed: u64,
    tx_accepted: u64,
    tx_rejected: u64,
    cancelled: u64,
    abandoned: u64,
}

impl BackendStats {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            allocation_failed: 0,
            tx_accepted: 0,
            tx_rejected: 0,
            cancelled: 0,
            abandoned: 0,
        }
    }

    pub fn record(&mut self, stat: BackendStat) {
        let counter = match stat {
            BackendStat::AllocationFailed => &mut self.allocation_failed,
            BackendStat::TxAccepted => &mut self.tx_accepted,
            BackendStat::TxRejected => &mut self.tx_rejected,
            BackendStat::Cancelled => &mut self.cancelled,
            BackendStat::Abandoned => &mut self.abandoned,
        };
        *counter = counter.saturating_add(1);
    }

    #[must_use]
    pub const fn snapshot(&self) -> BackendStatsSnapshot {
        BackendStatsSnapshot {
            allocation_failed: self.allocation_failed,
            tx_accepted: self.tx_accepted,
            tx_rejected: self.tx_rejected,
            cancelled: self.cancelled,
            abandoned: self.abandoned,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendStatsSnapshot {
    pub allocation_failed: u64,
    pub tx_accepted: u64,
    pub tx_rejected: u64,
    pub cancelled: u64,
    pub abandoned: u64,
}

#[cfg(test)]
mod tests {
    use super::{BackendStat, BackendStats};

    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let mut stats = BackendStats {
            tx_accepted: u64::MAX,
            ..BackendStats::new()
        };
        stats.record(BackendStat::TxAccepted);
        assert_eq!(stats.snapshot().tx_accepted, u64::MAX);
    }
}
