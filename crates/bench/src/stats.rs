/// Distribution summary for normalized nanoseconds per packet or operation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SampleStats {
    pub samples: usize,
    pub min_ns: f64,
    pub p50_ns: f64,
    pub p95_ns: f64,
    pub mad_ns: f64,
}

impl SampleStats {
    #[must_use]
    pub fn from_samples(samples: &[f64]) -> Option<Self> {
        if samples.is_empty()
            || samples
                .iter()
                .any(|sample| !sample.is_finite() || *sample <= 0.0)
        {
            return None;
        }
        let mut ordered = samples.to_vec();
        ordered.sort_by(f64::total_cmp);
        let p50_ns = median(&ordered);
        let p95_index = (ordered.len() * 95).div_ceil(100).saturating_sub(1);
        let p95_ns = ordered[p95_index];
        let mut deviations = ordered
            .iter()
            .map(|sample| (sample - p50_ns).abs())
            .collect::<Vec<_>>();
        deviations.sort_by(f64::total_cmp);
        Some(Self {
            samples: ordered.len(),
            min_ns: ordered[0],
            p50_ns,
            p95_ns,
            mad_ns: median(&deviations),
        })
    }

    #[must_use]
    pub fn million_per_second(self) -> f64 {
        if self.p50_ns == 0.0 {
            f64::INFINITY
        } else {
            1_000.0 / self.p50_ns
        }
    }
}

fn median(ordered: &[f64]) -> f64 {
    let middle = ordered.len() / 2;
    if ordered.len().is_multiple_of(2) {
        (ordered[middle - 1] + ordered[middle]) / 2.0
    } else {
        ordered[middle]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_uses_median_nearest_rank_p95_and_mad() {
        let stats = SampleStats::from_samples(&[9.0, 1.0, 5.0, 3.0, 7.0]).unwrap();
        assert_eq!(
            stats,
            SampleStats {
                samples: 5,
                min_ns: 1.0,
                p50_ns: 5.0,
                p95_ns: 9.0,
                mad_ns: 2.0,
            }
        );
        assert_eq!(stats.million_per_second(), 200.0);
    }

    #[test]
    fn invalid_or_empty_samples_are_rejected() {
        assert!(SampleStats::from_samples(&[]).is_none());
        assert!(SampleStats::from_samples(&[f64::NAN]).is_none());
        assert!(SampleStats::from_samples(&[0.0]).is_none());
        assert!(SampleStats::from_samples(&[-1.0]).is_none());
    }
}
