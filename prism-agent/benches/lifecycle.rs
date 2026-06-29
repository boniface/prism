use std::path::Path;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use prism_agent::bpf::reconcile_stale_pins;
use prism_agent::config::{SecurityEventField, SecuritySettings};
use prism_agent::metrics::MetricSnapshot;
use prism_agent::security::fields::redact_and_cap_field;
use prism_core::events::metrics::METRIC_COUNTER_FIELDS;
use prism_core::events::security::ProcessExecEvent;
use std::fmt::Write as _;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Pin reconciliation benchmarks
// ---------------------------------------------------------------------------

fn bench_empty_pin_reconciliation(criterion: &mut Criterion) {
    criterion.bench_function("empty_pin_reconciliation", |bencher| {
        let temp_dir = TempDir::new().expect("tempdir should be created");
        bencher.iter(|| {
            reconcile_stale_pins(temp_dir.path()).expect("empty pin root should reconcile");
        });
    });
}

fn bench_missing_pin_reconciliation(criterion: &mut Criterion) {
    criterion.bench_function("missing_pin_reconciliation", |bencher| {
        bencher.iter(|| {
            reconcile_stale_pins(Path::new("/tmp/prism-missing-pin-root-bench"))
                .expect("missing pin root should reconcile");
        });
    });
}

// ---------------------------------------------------------------------------
// Event decode benchmarks
// ---------------------------------------------------------------------------

fn bench_process_exec_event_decode(criterion: &mut Criterion) {
    let mut comm = [0u8; 16];
    comm[..4].copy_from_slice(b"bash");
    let mut exe_path = [0u8; 128];
    exe_path[..13].copy_from_slice(b"/usr/bin/bash");

    let raw_event = ProcessExecEvent {
        timestamp_ns: 1_000_000_000,
        cgroup_id: 42,
        pid: 1234,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        comm_len: 4,
        exe_path_len: 13,
        reserved: [0u8; 4],
        comm,
        exe_path,
    };

    let bytes = bytemuck::bytes_of(&raw_event);

    criterion.bench_function("process_exec_event_decode", |bencher| {
        bencher.iter(|| {
            let mut raw = [0u8; core::mem::size_of::<ProcessExecEvent>()];
            raw.copy_from_slice(&bytes[..core::mem::size_of::<ProcessExecEvent>()]);
            let _event: ProcessExecEvent = bytemuck::pod_read_unaligned(&raw);
        });
    });
}

// ---------------------------------------------------------------------------
// Label sanitization benchmarks
// ---------------------------------------------------------------------------

fn bench_label_sanitization(criterion: &mut Criterion) {
    let inputs = [
        ("short_clean", "bash"),
        (
            "long_clean",
            "this-is-a-longer-label-value-that-needs-truncation",
        ),
        ("with_redaction", "password=secret123"),
        ("unicode", "cgroup-service-name"),
    ];

    let mut group = criterion.benchmark_group("label_sanitization");
    let patterns = vec![
        "password".to_owned(),
        "secret".to_owned(),
        "token".to_owned(),
    ];

    for (name, input) in inputs {
        group.bench_with_input(BenchmarkId::new("redact_and_cap", name), input, |b, i| {
            b.iter(|| redact_and_cap_field(i, 64, &patterns));
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Field policy benchmarks
// ---------------------------------------------------------------------------

fn bench_field_policy_lookup(criterion: &mut Criterion) {
    let mut settings = SecuritySettings::default();
    settings
        .process_exec_fields
        .push(SecurityEventField::ExecutablePath);
    settings
        .process_exec_fields
        .push(SecurityEventField::CommandLine);

    criterion.bench_function("field_policy_lookup", |bencher| {
        bencher.iter(|| {
            let _allowed = settings
                .process_exec_fields
                .contains(&SecurityEventField::ExecutablePath);
        });
    });
}

// ---------------------------------------------------------------------------
// Metric snapshot benchmarks
// ---------------------------------------------------------------------------

fn bench_metric_snapshot_render(criterion: &mut Criterion) {
    let snapshots: Vec<MetricSnapshot> = (0..100_u64)
        .map(|i| {
            let raw = [i * 1000; METRIC_COUNTER_FIELDS];
            MetricSnapshot::from_raw(i, raw)
        })
        .collect();

    criterion.bench_function("metric_snapshot_render_100_cgroups", |bencher| {
        bencher.iter_batched(
            || snapshots.clone(),
            |snaps| {
                let mut output = String::with_capacity(snaps.len() * 256);
                for snap in &snaps {
                    let _ = write!(
                        output,
                        "prism_cpu_runtime_ns{{cgroup_id=\"{}\"}} {}",
                        snap.cgroup_id().value(),
                        snap.counters().cpu_runtime_ns,
                    );
                }
                output
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    lifecycle_benches,
    bench_empty_pin_reconciliation,
    bench_missing_pin_reconciliation,
);

criterion_group!(event_benches, bench_process_exec_event_decode,);

criterion_group!(
    field_benches,
    bench_label_sanitization,
    bench_field_policy_lookup,
);

criterion_group!(metrics_benches, bench_metric_snapshot_render,);

criterion_main!(
    lifecycle_benches,
    event_benches,
    field_benches,
    metrics_benches,
);
