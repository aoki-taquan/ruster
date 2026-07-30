use crate::{FrameSize, SampleStats};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    Human,
    JsonLines,
    Both,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResultRow {
    pub case: &'static str,
    pub size: FrameSize,
    pub batch: usize,
    pub checksum_passes: u8,
    pub seed: u64,
    pub repetitions_per_sample: usize,
    pub timed_allocations: u64,
    pub stats: SampleStats,
    pub digest: u16,
}

impl ResultRow {
    #[must_use]
    pub fn human_header() -> &'static str {
        "case                 size         batch passes  p50 ns/op  p95 ns/op   Mops/s allocs"
    }

    #[must_use]
    pub fn to_human_line(&self) -> String {
        format!(
            "{:<20} {:<12} {:>5} {:>6} {:>10.2} {:>10.2} {:>8.3} {:>6}",
            self.case,
            self.size.label(),
            self.batch,
            self.checksum_passes,
            self.stats.p50_ns,
            self.stats.p95_ns,
            self.stats.million_per_second(),
            self.timed_allocations,
        )
    }

    #[must_use]
    pub fn to_json_line(&self) -> String {
        format!(
            concat!(
                "{{\"schema_version\":{},\"kind\":\"measurement\",",
                "\"case\":\"{}\",\"size\":\"{}\",",
                "\"backend_bytes\":{},\"ethernet_bytes_including_fcs\":{},",
                "\"wire_bytes_with_preamble_ifg\":{},\"ipv4_total_bytes\":{},",
                "\"batch\":{},\"checksum_passes\":{},\"seed\":{},",
                "\"samples\":{},\"repetitions_per_sample\":{},",
                "\"min_ns_per_op\":{:.6},\"p50_ns_per_op\":{:.6},",
                "\"p95_ns_per_op\":{:.6},\"mad_ns_per_op\":{:.6},",
                "\"million_ops_per_second\":{:.6},",
                "\"timed_allocations\":{},\"digest\":{}}}"
            ),
            SCHEMA_VERSION,
            self.case,
            self.size.label(),
            self.size.backend_bytes(),
            self.size.ethernet_bytes_including_fcs(),
            self.size.wire_bytes_with_preamble_ifg(),
            self.size.ipv4_total_bytes(),
            self.batch,
            self.checksum_passes,
            self.seed,
            self.stats.samples,
            self.repetitions_per_sample,
            self.stats.min_ns,
            self.stats.p50_ns,
            self.stats.p95_ns,
            self.stats.mad_ns,
            self.stats.million_per_second(),
            self.timed_allocations,
            self.digest,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_line_has_stable_schema_and_unambiguous_wire_metadata() {
        let row = ResultRow {
            case: "plain-ipv4",
            size: FrameSize::Wire64,
            batch: 32,
            checksum_passes: 0,
            seed: 7,
            repetitions_per_sample: 10,
            timed_allocations: 0,
            stats: SampleStats {
                samples: 3,
                min_ns: 1.0,
                p50_ns: 2.0,
                p95_ns: 3.0,
                mad_ns: 1.0,
            },
            digest: 42,
        };
        assert_eq!(
            row.to_json_line(),
            concat!(
                "{\"schema_version\":1,\"kind\":\"measurement\",",
                "\"case\":\"plain-ipv4\",\"size\":\"wire64\",",
                "\"backend_bytes\":60,\"ethernet_bytes_including_fcs\":64,",
                "\"wire_bytes_with_preamble_ifg\":84,\"ipv4_total_bytes\":46,",
                "\"batch\":32,\"checksum_passes\":0,\"seed\":7,",
                "\"samples\":3,\"repetitions_per_sample\":10,",
                "\"min_ns_per_op\":1.000000,\"p50_ns_per_op\":2.000000,",
                "\"p95_ns_per_op\":3.000000,\"mad_ns_per_op\":1.000000,",
                "\"million_ops_per_second\":500.000000,",
                "\"timed_allocations\":0,\"digest\":42}"
            )
        );
    }
}
