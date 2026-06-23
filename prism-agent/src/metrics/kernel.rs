use prism_core::{
    events::metrics::{METRIC_COUNTER_FIELDS, MetricCounters},
    ids::CgroupId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricSnapshot {
    cgroup_id: CgroupId,
    counters: MetricCounters,
}

impl MetricSnapshot {
    #[must_use]
    pub const fn new(cgroup_id: CgroupId, counters: MetricCounters) -> Self {
        Self {
            cgroup_id,
            counters,
        }
    }

    #[must_use]
    pub const fn from_raw(cgroup_id: u64, raw: [u64; METRIC_COUNTER_FIELDS]) -> Self {
        Self::new(CgroupId::new(cgroup_id), MetricCounters::from_raw(raw))
    }

    #[must_use]
    pub const fn cgroup_id(self) -> CgroupId {
        self.cgroup_id
    }

    #[must_use]
    pub const fn counters(self) -> MetricCounters {
        self.counters
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_converts_raw_counter_layout() {
        let snapshot =
            MetricSnapshot::from_raw(42, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);

        assert_eq!(snapshot.cgroup_id(), CgroupId::new(42));
        assert_eq!(snapshot.counters().cpu_runtime_ns, 1);
        assert_eq!(snapshot.counters().drop_count, 14);
    }
}
