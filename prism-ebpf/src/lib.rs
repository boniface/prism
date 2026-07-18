#![no_std]
#![no_main]

use aya_ebpf::helpers::{
    bpf_get_current_pid_tgid, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
};
use aya_ebpf::{
    bindings::TC_ACT_OK,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::{classifier, map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::{TcContext, TracePointContext},
};
use core::ptr::addr_of_mut;
use prism_core::events::metrics::{MetricCounters, MetricEvent};
use prism_core::events::security::{
    FileAccessEvent, NetworkConnectionEvent, ProcessExecEvent, COMM_LEN, FILE_PATH_LEN,
};

const MAX_CGROUP_METRICS: u32 = 4_096;
const METRIC_RING_BYTES: u32 = 256 * 1_024;
const DROP_COUNTER_KEY: u32 = 0;

// Lifecycle proof map.
#[map]
static mut LIFECYCLE_COUNTER: Array<u64> = Array::with_max_entries(1, 0);

// Metrics maps.
#[map]
static mut CGROUP_METRICS: HashMap<u64, MetricCounters> =
    HashMap::with_max_entries(MAX_CGROUP_METRICS, 0);

#[map]
static mut CPU_LAST_RUN_NS: HashMap<u64, u64> = HashMap::with_max_entries(MAX_CGROUP_METRICS, 0);

#[map]
static mut METRIC_EVENTS: RingBuf = RingBuf::with_byte_size(METRIC_RING_BYTES, 0);

#[map]
static mut METRIC_RING_DROPS: Array<u64> = Array::with_max_entries(1, 0);

// Security audit ring buffer — 256 KiB.
#[map]
static mut SECURITY_EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

// File access audit ring buffer — 256 KiB.
#[map]
static mut FILE_ACCESS_EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

// Network security audit ring buffer — 256 KiB.
#[map]
static mut NETWORK_SECURITY_EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

// ---------------------------------------------------------------------------
// Lifecycle proof
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn prism_lifecycle(ctx: TracePointContext) -> u32 {
    try_prism_lifecycle(ctx)
}

fn try_prism_lifecycle(_ctx: TracePointContext) -> u32 {
    let cgroup_id = current_cgroup_id();
    ensure_metric_snapshot(cgroup_id);

    let key = 0;
    let map = addr_of_mut!(LIFECYCLE_COUNTER);
    // SAFETY: The map pointer is created without taking a reference to the
    // mutable static. The map is defined with one u64 slot, the key is
    // constant zero, and the eBPF verifier checks the returned pointer before
    // it is dereferenced.
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

// ---------------------------------------------------------------------------
// execve audit
// ---------------------------------------------------------------------------

#[tracepoint(name = "prism_execve", category = "syscalls")]
pub fn prism_execve(ctx: TracePointContext) -> u32 {
    try_prism_execve(ctx)
}

fn try_prism_execve(_ctx: TracePointContext) -> u32 {
    let ring = addr_of_mut!(SECURITY_EVENTS);

    // SAFETY: The ring buffer pointer is created from the mutable static
    // without taking a reference. The eBPF verifier validates all map
    // accesses before the program runs.
    let Some(mut entry) = (unsafe { (*ring).reserve::<ProcessExecEvent>(0) }) else {
        return 1;
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid & 0xffff_ffff) as u32;
    let parent_pid = ((pid_tgid >> 32) & 0xffff_ffff) as u32;
    let uid = (uid_gid & 0xffff_ffff) as u32;
    let gid = ((uid_gid >> 32) & 0xffff_ffff) as u32;

    let mut comm = [0u8; COMM_LEN];
    let comm_len = match bpf_get_current_comm() {
        Ok(c) => {
            comm = c;
            u16::try_from(comm.iter().position(|&b| b == 0).unwrap_or(COMM_LEN)).unwrap_or(0)
        }
        Err(_) => 0u16,
    };

    // SAFETY: `entry` is a reserved ring buffer slot. Writing through the
    // pointer is safe because the verifier ensures the slot is valid and
    // sized for `ProcessExecEvent`.
    unsafe {
        let event = entry.as_mut_ptr();
        (*event).timestamp_ns = bpf_ktime_get_ns();
        (*event).cgroup_id = current_cgroup_id();
        (*event).pid = pid;
        (*event).ppid = parent_pid;
        (*event).uid = uid;
        (*event).gid = gid;
        (*event).comm_len = comm_len;
        (*event).exe_path_len = 0;
        (*event).reserved = [0u8; 4];
        (*event).comm = comm;
        (*event).exe_path = [0u8; 128];
    }

    entry.submit(0);
    0
}

// ---------------------------------------------------------------------------
// File open audit
// ---------------------------------------------------------------------------

#[tracepoint(name = "prism_file_open", category = "syscalls")]
pub fn prism_file_open(ctx: TracePointContext) -> u32 {
    try_prism_file_open(ctx)
}

fn try_prism_file_open(ctx: TracePointContext) -> u32 {
    let ring = addr_of_mut!(FILE_ACCESS_EVENTS);
    // SAFETY: The ring buffer pointer is created from the mutable static
    // without taking a reference. The eBPF verifier validates all map
    // accesses before the program runs.
    let Some(mut entry) = (unsafe { (*ring).reserve::<FileAccessEvent>(0) }) else {
        return 1;
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let pid = (pid_tgid & 0xffff_ffff) as u32;
    let uid = (uid_gid & 0xffff_ffff) as u32;

    // Offset 24 confirmed against this kernel's sys_enter_openat tracepoint
    // format: `filename` is a `const char *` userspace pointer captured at
    // syscall entry, before the kernel has copied the string in.
    const FILENAME_OFFSET: usize = 24;
    let filename_ptr: u64 = match unsafe { ctx.read_at(FILENAME_OFFSET) } {
        Ok(v) => v,
        Err(_) => {
            entry.discard(0);
            return 1;
        }
    };

    // SAFETY: `entry` is a reserved ring buffer slot sized for FileAccessEvent.
    unsafe {
        let event = entry.as_mut_ptr();
        (*event).timestamp_ns = bpf_ktime_get_ns();
        (*event).cgroup_id = current_cgroup_id();
        (*event).pid = pid;
        (*event).uid = uid;
        (*event).reserved = [0u8; 6];
        (*event).path = [0u8; FILE_PATH_LEN];

        match bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut (*event).path) {
            Ok(bytes) => {
                (*event).path_len = bytes.len() as u16;
            }
            Err(_) => {
                (*event).path_len = 0;
            }
        }
    }
    entry.submit(0);
    0
}

// ---------------------------------------------------------------------------
// TCP connect audit
// ---------------------------------------------------------------------------

#[tracepoint(name = "prism_tcp_connect", category = "syscalls")]
pub fn prism_tcp_connect(ctx: TracePointContext) -> u32 {
    try_prism_tcp_connect(ctx)
}

fn try_prism_tcp_connect(ctx: TracePointContext) -> u32 {
    let ring = addr_of_mut!(NETWORK_SECURITY_EVENTS);
    // SAFETY: The ring buffer pointer is created from the mutable static
    // without taking a reference. The eBPF verifier validates all map
    // accesses before the program runs.
    let Some(mut entry) = (unsafe { (*ring).reserve::<NetworkConnectionEvent>(0) }) else {
        return 1;
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let pid = (pid_tgid & 0xffff_ffff) as u32;
    let uid = (uid_gid & 0xffff_ffff) as u32;
    let mut comm = [0u8; COMM_LEN];
    let comm_len = match bpf_get_current_comm() {
        Ok(c) => {
            comm = c;
            u16::try_from(comm.iter().position(|&b| b == 0).unwrap_or(COMM_LEN)).unwrap_or(0)
        }
        Err(_) => 0u16,
    };

    // Offset 24 confirmed against this kernel's sys_enter_connect tracepoint
    // format: `uservaddr` is a `struct sockaddr *` userspace pointer.
    const UVERVADDR_OFFSET: usize = 24;
    const AF_INET: u16 = 2;
    let mut dst_addr = [0u8; 4];
    let mut dst_port: u16 = 0;

    if let Ok(uservaddr_ptr) = unsafe { ctx.read_at::<u64>(UVERVADDR_OFFSET) } {
        if uservaddr_ptr != 0 {
            let mut sockaddr_buf = [0u8; 8];
            if unsafe { bpf_probe_read_user_buf(uservaddr_ptr as *const u8, &mut sockaddr_buf) }
                .is_ok()
            {
                let sin_family = u16::from_ne_bytes([sockaddr_buf[0], sockaddr_buf[1]]);
                if sin_family == AF_INET {
                    dst_port = u16::from_be_bytes([sockaddr_buf[2], sockaddr_buf[3]]);
                    dst_addr.copy_from_slice(&sockaddr_buf[4..8]);
                }
            }
        }
    }

    // SAFETY: `entry` is a reserved ring buffer slot sized for
    // `NetworkConnectionEvent`. The verifier checks the slot before use.
    unsafe {
        let event = entry.as_mut_ptr();
        (*event).timestamp_ns = bpf_ktime_get_ns();
        (*event).cgroup_id = current_cgroup_id();
        (*event).pid = pid;
        (*event).uid = uid;
        (*event).dst_addr = dst_addr;
        (*event).dst_port = dst_port;
        (*event).comm_len = comm_len;
        (*event).comm = comm;
        (*event).reserved = [0u8; 8];
    }
    entry.submit(0);
    0
}

// ---------------------------------------------------------------------------
// CPU scheduling
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn prism_sched_switch(ctx: TracePointContext) -> u32 {
    try_prism_sched_switch(ctx)
}

fn try_prism_sched_switch(_ctx: TracePointContext) -> u32 {
    let cgroup_id = current_cgroup_id();
    let now_ns = monotonic_time_ns();
    let last_ns = update_last_cpu_timestamp(cgroup_id, now_ns);

    if last_ns > 0 && now_ns > last_ns {
        add_cpu_runtime(cgroup_id, now_ns.saturating_sub(last_ns));
    }

    0
}

// ---------------------------------------------------------------------------
// TC hooks
// ---------------------------------------------------------------------------

#[classifier]
#[allow(clippy::needless_pass_by_value)]
pub fn prism_tc_ingress(ctx: TcContext) -> i32 {
    record_network_rx(&ctx);
    TC_ACT_OK
}

#[classifier]
#[allow(clippy::needless_pass_by_value)]
pub fn prism_tc_egress(ctx: TcContext) -> i32 {
    record_network_tx(&ctx);
    TC_ACT_OK
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn update_last_cpu_timestamp(cgroup_id: u64, now_ns: u64) -> u64 {
    let cpu_last_run = addr_of_mut!(CPU_LAST_RUN_NS);
    // SAFETY: The map pointer is formed without borrowing the mutable static.
    let last_ns = unsafe { (*cpu_last_run).get(&cgroup_id).copied().unwrap_or(0) };
    let _ = unsafe { (*cpu_last_run).insert(&cgroup_id, &now_ns, 0) };
    last_ns
}

fn ensure_metric_snapshot(cgroup_id: u64) {
    let metrics = addr_of_mut!(CGROUP_METRICS);
    // SAFETY: The map pointer is formed without borrowing the mutable static.
    if unsafe { (*metrics).get(&cgroup_id).is_some() } {
        return;
    }
    let counters = MetricCounters::default();
    let _ = unsafe { (*metrics).insert(&cgroup_id, &counters, 0) };
    emit_metric_event(cgroup_id, counters);
}

fn add_cpu_runtime(cgroup_id: u64, delta_ns: u64) {
    let metrics = addr_of_mut!(CGROUP_METRICS);
    // SAFETY: The map pointer is formed without borrowing the mutable static.
    let counter = unsafe { (*metrics).get_ptr_mut(&cgroup_id) };
    if let Some(value) = counter {
        unsafe {
            (*value).add_cpu_runtime(delta_ns);
            emit_metric_event(cgroup_id, *value);
        }
        return;
    }
    let mut counters = MetricCounters::default();
    counters.add_cpu_runtime(delta_ns);
    let _ = unsafe { (*metrics).insert(&cgroup_id, &counters, 0) };
    emit_metric_event(cgroup_id, counters);
}

fn record_network_rx(ctx: &TcContext) {
    let cgroup_id = current_cgroup_id();
    let bytes = u64::from(ctx.len());
    update_network_counters(cgroup_id, bytes, true);
}

fn record_network_tx(ctx: &TcContext) {
    let cgroup_id = current_cgroup_id();
    let bytes = u64::from(ctx.len());
    update_network_counters(cgroup_id, bytes, false);
}

fn update_network_counters(cgroup_id: u64, bytes: u64, ingress: bool) {
    let metrics = addr_of_mut!(CGROUP_METRICS);
    // SAFETY: The map pointer is formed without borrowing the mutable static.
    let counter = unsafe { (*metrics).get_ptr_mut(&cgroup_id) };
    if let Some(value) = counter {
        unsafe {
            if ingress {
                (*value).add_network_rx(bytes, 1);
            } else {
                (*value).add_network_tx(bytes, 1);
            }
            emit_metric_event(cgroup_id, *value);
        }
        return;
    }
    let mut counters = MetricCounters::default();
    if ingress {
        counters.add_network_rx(bytes, 1);
    } else {
        counters.add_network_tx(bytes, 1);
    }
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
    // SAFETY: The map pointer is formed without borrowing the mutable static.
    if unsafe { (*events).output(&event, 0) }.is_err() {
        increment_drop_counter();
    }
}

fn increment_drop_counter() {
    let drops = addr_of_mut!(METRIC_RING_DROPS);
    // SAFETY: The map pointer is formed without borrowing the mutable static.
    let counter = unsafe { (*drops).get_ptr_mut(DROP_COUNTER_KEY) };
    if let Some(value) = counter {
        unsafe {
            *value = (*value).saturating_add(1);
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
