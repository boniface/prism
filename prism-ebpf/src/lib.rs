#![no_std]
#![no_main]

use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_uid_gid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::{Array, RingBuf},
    programs::TracePointContext,
};
use core::ptr::addr_of_mut;
use prism_core::events::security::{ProcessExecEvent, COMM_LEN};

// Lifecycle proof map — one slot updated on every nanosleep tracepoint.
#[map]
static mut LIFECYCLE_COUNTER: Array<u64> = Array::with_max_entries(1, 0);

// Ring buffer for security audit events — 256 KiB.
#[map]
static mut SECURITY_EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

// ---------------------------------------------------------------------------
// Lifecycle proof
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn prism_lifecycle(ctx: TracePointContext) -> u32 {
    try_prism_lifecycle(ctx)
}

fn try_prism_lifecycle(_ctx: TracePointContext) -> u32 {
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
            *value = bpf_ktime_get_ns();
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
        (*event).cgroup_id = 0;
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
