// Direct libc::clock_gettime wrappers.
//
// monotonic_ns() uses CLOCK_MONOTONIC — this is the exact same clock
// domain as the kernel's bpf_ktime_get_ns(), so Prism's timestamp_ns
// values are directly comparable with no boot-offset conversion.
//
// realtime_ns() uses CLOCK_REALTIME (wall clock) — this is the domain
// auditd and journald log in.

pub fn monotonic_ns() -> u64 {
    clock_ns(libc::CLOCK_MONOTONIC)
}

pub fn realtime_ns() -> u64 {
    clock_ns(libc::CLOCK_REALTIME)
}

fn clock_ns(clock_id: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid, correctly-sized timespec on the stack, and
    // clock_id is one of the fixed CLOCK_MONOTONIC/CLOCK_REALTIME
    // constants defined by libc. clock_gettime writes into ts and
    // returns 0 on success.
    let result = unsafe { libc::clock_gettime(clock_id, &mut ts) };
    assert_eq!(result, 0, "clock_gettime failed for clock_id={clock_id}");
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_clock_advances() {
        let first = monotonic_ns();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let second = monotonic_ns();
        assert!(second > first);
    }

    #[test]
    fn realtime_clock_is_plausible() {
        // Sanity check: realtime should be some time after 2020-01-01.
        let ns = realtime_ns();
        assert!(ns > 1_577_836_800_000_000_000);
    }
}
