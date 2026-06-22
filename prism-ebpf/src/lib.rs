#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_cgroup_id, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::TracePointContext,
};
use core::ptr::addr_of_mut;
use prism_core::events::metrics::{MetricCounters, MetricEvent};

const MAX_CGROUP_METRICS: u32 = 4_096;
const METRIC_RING_BYTES: u32 = 256 * 1_024;
const DROP_COUNTER_KEY: u32 = 0;

#[map]
static mut LIFECYCLE_COUNTER: Array<u64> = Array::with_max_entries(1, 0);

#[map]
static mut CGROUP_METRICS: HashMap<u64, MetricCounters> =
    HashMap::with_max_entries(MAX_CGROUP_METRICS, 0);

#[map]
static mut METRIC_EVENTS: RingBuf = RingBuf::with_byte_size(METRIC_RING_BYTES, 0);

#[map]
static mut METRIC_RING_DROPS: Array<u64> = Array::with_max_entries(1, 0);

#[tracepoint]
pub fn prism_lifecycle(ctx: TracePointContext) -> u32 {
    try_prism_lifecycle(ctx)
}

fn try_prism_lifecycle(_ctx: TracePointContext) -> u32 {
    let cgroup_id = current_cgroup_id();
    record_metric_snapshot(cgroup_id, MetricCounters::default());

    let key = 0;

    let map = addr_of_mut!(LIFECYCLE_COUNTER);

    // SAFETY: The map pointer is created without taking a reference to the
    // mutable static. The map is defined with one u64 slot, the key is constant
    // zero, and the eBPF verifier checks the returned pointer before it is
    // dereferenced.
    let counter = unsafe { (*map).get_ptr_mut(key) };
    if let Some(value) = counter {
        // SAFETY: `value` is a verifier-checked pointer returned from the map
        // lookup above. Only this program mutates the lifecycle proof counter.
        unsafe {
            *value = monotonic_time_ns();
        }
    }

    0
}

fn current_cgroup_id() -> u64 {
    // SAFETY: `bpf_get_current_cgroup_id` is a side-effect-free helper
    // available to tracepoint programs and returns zero if no cgroup can be
    // resolved by the kernel.
    unsafe { bpf_get_current_cgroup_id() }
}

fn monotonic_time_ns() -> u64 {
    // SAFETY: `bpf_ktime_get_ns` is a side-effect-free helper available to
    // tracepoint programs and returns the kernel monotonic clock in
    // nanoseconds.
    unsafe { bpf_ktime_get_ns() }
}

fn record_metric_snapshot(cgroup_id: u64, counters: MetricCounters) {
    let metrics = addr_of_mut!(CGROUP_METRICS);
    // SAFETY: The map pointer is formed without borrowing the mutable static.
    // Key and value are fixed-size POD ABI types shared with user-space.
    let _ = unsafe { (*metrics).insert(&cgroup_id, &counters, 0) };

    emit_metric_event(cgroup_id, counters);
}

fn emit_metric_event(cgroup_id: u64, counters: MetricCounters) {
    let event = MetricEvent {
        cgroup_id,
        timestamp_ns: monotonic_time_ns(),
        counters,
    };
    let events = addr_of_mut!(METRIC_EVENTS);
    // SAFETY: The map pointer is formed without borrowing the mutable static,
    // and `MetricEvent` is a fixed-layout POD type with alignment accepted by
    // the ring buffer helper.
    if unsafe { (*events).output(&event, 0) }.is_err() {
        increment_drop_counter();
    }
}

fn increment_drop_counter() {
    let drops = addr_of_mut!(METRIC_RING_DROPS);
    // SAFETY: The map pointer is formed without borrowing the mutable static.
    // The array contains exactly one u64 entry at `DROP_COUNTER_KEY`.
    let counter = unsafe { (*drops).get_ptr_mut(DROP_COUNTER_KEY) };
    if let Some(value) = counter {
        // SAFETY: `value` is a verifier-checked pointer returned from the map
        // lookup above and points to the only drop counter slot.
        unsafe {
            *value = (*value).saturating_add(1);
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
