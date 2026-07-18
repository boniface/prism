use std::ffi::CString;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use clap::Parser;
use csv::Writer;
use nix::unistd::{fork, execv, ForkResult, getpid};
use nix::sys::wait::waitpid;
use serde::Serialize;
use nix::libc::prctl;
use nix::libc::PR_SET_NAME;

#[path = "../clock.rs"]
mod clock;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 100)]
    count: u32,
    #[arg(long, default_value_t = 50)]
    interval_ms: u64,
    #[arg(long, default_value = "/tmp/prism-harness/exec-markers")]
    marker_dir: PathBuf,
    #[arg(long, default_value = "ground_truth_exec.csv")]
    output: PathBuf,
}

#[derive(Serialize)]
struct GroundTruthRecord {
    marker: String,
    event_type: &'static str,
    pid: u32,
    t0_monotonic_ns: u64,
    t0_realtime_ns: u64,
}

fn set_process_name(name: &str) {
    let c_name = CString::new(name).unwrap_or_else(|_| CString::new("unknown").unwrap());
    unsafe {
        prctl(PR_SET_NAME, c_name.as_ptr() as usize, 0, 0, 0);
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.marker_dir)?;
    let true_bin = ["/bin/true", "/usr/bin/true"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("could not locate /bin/true or /usr/bin/true");

    let mut writer = Writer::from_path(&args.output)?;

    for seq in 0..args.count {
        let marker = format!("p{seq:07x}");
        let link_path = args.marker_dir.join(&marker);
        let _ = fs::remove_file(&link_path);
        symlink(true_bin, &link_path)?;

        let t0_monotonic_ns = clock::monotonic_ns();
        let t0_realtime_ns = clock::realtime_ns();

        let pid = unsafe { fork()? };

        match pid {
            ForkResult::Parent { child } => {
                let _ = waitpid(child, None);
                let my_pid = getpid().as_raw();
                writer.serialize(GroundTruthRecord {
                    marker: marker.clone(),
                    event_type: "exec",
                    pid: my_pid as u32,
                    t0_monotonic_ns,
                    t0_realtime_ns,
                })?;
                writer.flush()?;
                std::thread::sleep(std::time::Duration::from_millis(args.interval_ms));
            }
            ForkResult::Child => {
                // Set the process name to the marker so comm field shows it
                set_process_name(&marker);
                let path = CString::new(link_path.to_str().unwrap())?;
                let args: Vec<CString> = vec![];
                let _ = execv(&path, &args);
                return Ok(());
            }
        }
    }

    println!("generated {} exec events", args.count);
    Ok(())
}
