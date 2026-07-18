use std::fs;
use std::path::PathBuf;

use clap::Parser;
use csv::Writer;
use serde::Serialize;

#[path = "../clock.rs"]
mod clock;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 100)]
    count: u32,
    #[arg(long, default_value_t = 50)]
    interval_ms: u64,
    #[arg(long, default_value = "/tmp/prism-harness/file-markers")]
    marker_dir: PathBuf,
    #[arg(long, default_value = "ground_truth_file_access.csv")]
    output: PathBuf,
}

#[derive(Serialize)]
struct GroundTruthRecord {
    marker: String,
    event_type: &'static str,
    t0_monotonic_ns: u64,
    t0_realtime_ns: u64,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.marker_dir)?;

    let mut writer = Writer::from_path(&args.output)?;

    for seq in 0..args.count {
        let marker = format!("p{seq:07x}");
        let file_path = args.marker_dir.join(&marker);

        let t0_monotonic_ns = clock::monotonic_ns();
        let t0_realtime_ns = clock::realtime_ns();

        // Open (creating if needed) and immediately close — this triggers
        // the openat syscall the sys_enter_openat tracepoint captures.
        let _ = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&file_path)?;

        writer.serialize(GroundTruthRecord {
            marker: marker.clone(),
            event_type: "file_access",
            t0_monotonic_ns,
            t0_realtime_ns,
        })?;
        writer.flush()?;

        std::thread::sleep(std::time::Duration::from_millis(args.interval_ms));
    }

    println!("generated {} file access events", args.count);
    Ok(())
}
