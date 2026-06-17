#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, tracepoint},
    maps::Array,
    programs::TracePointContext,
};
use core::ptr::addr_of_mut;

#[map]
static mut LIFECYCLE_COUNTER: Array<u64> = Array::with_max_entries(1, 0);

#[tracepoint]
pub fn prism_lifecycle(ctx: TracePointContext) -> u32 {
    try_prism_lifecycle(ctx)
}

fn try_prism_lifecycle(_ctx: TracePointContext) -> u32 {
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
            *value = bpf_ktime_get_ns();
        }
    }

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
