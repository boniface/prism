use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};
use prism_agent::bpf::reconcile_stale_pins;
use tempfile::TempDir;

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

criterion_group!(
    benches,
    bench_empty_pin_reconciliation,
    bench_missing_pin_reconciliation
);
criterion_main!(benches);
