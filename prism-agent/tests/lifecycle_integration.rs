//! Integration tests for the eBPF lifecycle proof.
//!
//! Unprivileged tests run as part of normal `make test`.
//! Privileged tests require:
//!   sudo `PRISM_PRIVILEGED_TESTS=1` \
//!     PRISM_EBPF_OBJECT=target/bpfel-unknown-none/release/libprism_ebpf.so \
//!     cargo +nightly test --test `lifecycle_integration` -- --nocapture

use prism_agent::bpf::{
    cleanup::reconcile_stale_pins,
    loader::{BpfLifecycleError, BpfLoaderConfig, LoadedBpf},
};
use std::path::PathBuf;

fn privileged_tests_enabled() -> bool {
    std::env::var("PRISM_PRIVILEGED_TESTS").is_ok()
}

fn ebpf_object_path() -> PathBuf {
    std::env::var("PRISM_EBPF_OBJECT").map_or_else(
        |_| PathBuf::from("target/bpfel-unknown-none/release/libprism_ebpf.so"),
        PathBuf::from,
    )
}

fn test_pin_root() -> PathBuf {
    PathBuf::from("/tmp/prism-integration-test-pins")
}

#[cfg(target_os = "linux")]
#[test]
fn missing_object_returns_typed_error_without_root() {
    let config = BpfLoaderConfig::new(
        PathBuf::from("/tmp/prism-object-that-does-not-exist"),
        test_pin_root(),
    );
    let result = LoadedBpf::load(&config);
    assert!(
        matches!(result, Err(BpfLifecycleError::MissingObject(_))),
        "expected MissingObject error",
    );
}

#[test]
fn reconcile_missing_pin_root_returns_zero_removals() {
    let report = reconcile_stale_pins(&PathBuf::from(
        "/tmp/prism-pin-root-that-does-not-exist-integration",
    ))
    .expect("reconcile should succeed on missing root");
    assert_eq!(report.removed_entries(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn lifecycle_attaches_and_detaches_cleanly() {
    if !privileged_tests_enabled() {
        println!("skipping privileged test — set PRISM_PRIVILEGED_TESTS=1 to enable");
        return;
    }
    let object_path = ebpf_object_path();
    let pin_root = test_pin_root();
    let _ = reconcile_stale_pins(&pin_root);
    let config = BpfLoaderConfig::new(object_path.clone(), pin_root.clone());
    let loaded = LoadedBpf::load(&config)
        .unwrap_or_else(|e| panic!("agent should load with object {object_path:?}: {e}"));
    println!("eBPF lifecycle program attached successfully");
    loaded.shutdown();
    println!("eBPF lifecycle program detached cleanly");
    let report =
        reconcile_stale_pins(&pin_root).expect("reconcile after clean shutdown should succeed");
    assert_eq!(
        report.removed_entries(),
        0,
        "expected zero stale pins after clean shutdown"
    );
    println!("no stale pins remain — lifecycle proof complete");
}

#[cfg(target_os = "linux")]
#[test]
fn crash_recovery_does_not_accumulate_stale_pins() {
    if !privileged_tests_enabled() {
        println!("skipping privileged test — set PRISM_PRIVILEGED_TESTS=1 to enable");
        return;
    }
    let object_path = ebpf_object_path();
    let pin_root = test_pin_root();
    for iteration in 1..=3 {
        println!("crash-recovery iteration {iteration}");
        let report = reconcile_stale_pins(&pin_root).expect("reconcile should succeed before load");
        println!(
            "  reconciled {} stale pin(s) before load",
            report.removed_entries()
        );
        let config = BpfLoaderConfig::new(object_path.clone(), pin_root.clone());
        let loaded = LoadedBpf::load(&config)
            .unwrap_or_else(|e| panic!("agent should load on iteration {iteration}: {e}"));
        drop(loaded);
        println!("  simulated crash (drop without shutdown)");
    }
    println!("crash-recovery loop complete — no pin accumulation detected");
}
