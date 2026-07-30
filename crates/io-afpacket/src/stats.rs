#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendStat {
    GeometryRejected,
    DescriptorRejected,
    StatusRejected,
    OwnershipRejected,
    SyscallError,
    MmapError,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct BackendStats {
    geometry_rejected: u64,
    descriptor_rejected: u64,
    status_rejected: u64,
    ownership_rejected: u64,
    syscall_errors: u64,
    mmap_errors: u64,
}

impl BackendStats {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            geometry_rejected: 0,
            descriptor_rejected: 0,
            status_rejected: 0,
            ownership_rejected: 0,
            syscall_errors: 0,
            mmap_errors: 0,
        }
    }

    pub fn record(&mut self, stat: BackendStat) {
        let counter = match stat {
            BackendStat::GeometryRejected => &mut self.geometry_rejected,
            BackendStat::DescriptorRejected => &mut self.descriptor_rejected,
            BackendStat::StatusRejected => &mut self.status_rejected,
            BackendStat::OwnershipRejected => &mut self.ownership_rejected,
            BackendStat::SyscallError => &mut self.syscall_errors,
            BackendStat::MmapError => &mut self.mmap_errors,
        };
        *counter = counter.saturating_add(1);
    }

    #[must_use]
    pub const fn snapshot(&self) -> BackendStatsSnapshot {
        BackendStatsSnapshot {
            geometry_rejected: self.geometry_rejected,
            descriptor_rejected: self.descriptor_rejected,
            status_rejected: self.status_rejected,
            ownership_rejected: self.ownership_rejected,
            syscall_errors: self.syscall_errors,
            mmap_errors: self.mmap_errors,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendStatsSnapshot {
    pub geometry_rejected: u64,
    pub descriptor_rejected: u64,
    pub status_rejected: u64,
    pub ownership_rejected: u64,
    pub syscall_errors: u64,
    pub mmap_errors: u64,
}

#[cfg(test)]
mod tests {
    use super::{BackendStat, BackendStats};

    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let mut stats = BackendStats {
            geometry_rejected: u64::MAX,
            ..BackendStats::new()
        };
        stats.record(BackendStat::GeometryRejected);
        assert_eq!(stats.snapshot().geometry_rejected, u64::MAX);
    }
}
