use bytemuck::{Pod, Zeroable};

pub const METRIC_COUNTER_FIELDS: usize = 14;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Zeroable, Pod)]
pub struct MetricCounters {
    pub cpu_runtime_ns: u64,
    pub memory_current_bytes: u64,
    pub memory_limit_bytes: u64,
    pub memory_pressure_some_total_us: u64,
    pub memory_pressure_full_total_us: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub disk_read_ops: u64,
    pub disk_write_ops: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub drop_count: u64,
}

impl MetricCounters {
    #[must_use]
    pub const fn from_raw(raw: [u64; METRIC_COUNTER_FIELDS]) -> Self {
        Self {
            cpu_runtime_ns: raw[0],
            memory_current_bytes: raw[1],
            memory_limit_bytes: raw[2],
            memory_pressure_some_total_us: raw[3],
            memory_pressure_full_total_us: raw[4],
            disk_read_bytes: raw[5],
            disk_write_bytes: raw[6],
            disk_read_ops: raw[7],
            disk_write_ops: raw[8],
            rx_bytes: raw[9],
            tx_bytes: raw[10],
            rx_packets: raw[11],
            tx_packets: raw[12],
            drop_count: raw[13],
        }
    }

    #[must_use]
    pub const fn into_raw(self) -> [u64; METRIC_COUNTER_FIELDS] {
        [
            self.cpu_runtime_ns,
            self.memory_current_bytes,
            self.memory_limit_bytes,
            self.memory_pressure_some_total_us,
            self.memory_pressure_full_total_us,
            self.disk_read_bytes,
            self.disk_write_bytes,
            self.disk_read_ops,
            self.disk_write_ops,
            self.rx_bytes,
            self.tx_bytes,
            self.rx_packets,
            self.tx_packets,
            self.drop_count,
        ]
    }

    pub fn add_cpu_runtime(&mut self, delta_ns: u64) {
        self.cpu_runtime_ns = self.cpu_runtime_ns.saturating_add(delta_ns);
    }

    pub fn set_memory(
        &mut self,
        current_bytes: u64,
        limit_bytes: u64,
        pressure_some_total_us: u64,
        pressure_full_total_us: u64,
    ) {
        self.memory_current_bytes = current_bytes;
        self.memory_limit_bytes = limit_bytes;
        self.memory_pressure_some_total_us = pressure_some_total_us;
        self.memory_pressure_full_total_us = pressure_full_total_us;
    }

    pub fn set_disk_io(
        &mut self,
        read_bytes: u64,
        write_bytes: u64,
        read_ops: u64,
        write_ops: u64,
    ) {
        self.disk_read_bytes = read_bytes;
        self.disk_write_bytes = write_bytes;
        self.disk_read_ops = read_ops;
        self.disk_write_ops = write_ops;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroable, Pod)]
pub struct MetricEvent {
    pub cgroup_id: u64,
    pub timestamp_ns: u64,
    pub counters: MetricCounters,
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::*;

    #[test]
    fn metric_counters_have_stable_layout() {
        assert_eq!(
            size_of::<MetricCounters>(),
            METRIC_COUNTER_FIELDS * size_of::<u64>()
        );
        assert_eq!(align_of::<MetricCounters>(), align_of::<u64>());
    }

    #[test]
    fn metric_event_has_stable_layout() {
        assert_eq!(size_of::<MetricEvent>(), 128);
        assert_eq!(align_of::<MetricEvent>(), 8);
    }

    #[test]
    fn metric_counters_round_trip_raw_layout() {
        let raw = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let counters = MetricCounters::from_raw(raw);

        assert_eq!(counters.into_raw(), raw);
    }

    #[test]
    fn cpu_runtime_counter_is_monotonic_and_saturating() {
        let mut counters = MetricCounters {
            cpu_runtime_ns: u64::MAX - 2,
            ..MetricCounters::default()
        };

        counters.add_cpu_runtime(7);

        assert_eq!(counters.cpu_runtime_ns, u64::MAX);
    }

    #[test]
    fn memory_counters_are_updated_together() {
        let mut counters = MetricCounters::default();

        counters.set_memory(128, 256, 7, 3);

        assert_eq!(counters.memory_current_bytes, 128);
        assert_eq!(counters.memory_limit_bytes, 256);
        assert_eq!(counters.memory_pressure_some_total_us, 7);
        assert_eq!(counters.memory_pressure_full_total_us, 3);
    }

    #[test]
    fn disk_io_counters_are_updated_together() {
        let mut counters = MetricCounters::default();

        counters.set_disk_io(10, 20, 3, 4);

        assert_eq!(counters.disk_read_bytes, 10);
        assert_eq!(counters.disk_write_bytes, 20);
        assert_eq!(counters.disk_read_ops, 3);
        assert_eq!(counters.disk_write_ops, 4);
    }
}
