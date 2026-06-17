use bytemuck::{Pod, Zeroable};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroable, Pod)]
pub struct MetricEvent {
    pub cgroup_id: u64,
    pub timestamp_ns: u64,
    pub cpu_runtime_ns: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::*;

    #[test]
    fn metric_event_has_stable_layout() {
        assert_eq!(size_of::<MetricEvent>(), 40);
        assert_eq!(align_of::<MetricEvent>(), 8);
    }
}
