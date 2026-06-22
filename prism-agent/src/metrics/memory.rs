use std::{
    fs, io,
    path::{Path, PathBuf},
};

use prism_core::events::metrics::MetricCounters;
use thiserror::Error;

use crate::metadata::CgroupV2Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryMetricsReader {
    cgroup_root: PathBuf,
}

impl MemoryMetricsReader {
    #[must_use]
    pub fn new(cgroup_root: PathBuf) -> Self {
        Self { cgroup_root }
    }

    #[must_use]
    pub fn system() -> Self {
        Self::new(PathBuf::from("/sys/fs/cgroup"))
    }

    /// Reads cgroup v2 memory metrics into the shared metric counter layout.
    ///
    /// # Errors
    ///
    /// Returns an error when a present memory file cannot be read or contains
    /// malformed counter data. Missing memory files are treated as zero values.
    pub fn read_counters(
        &self,
        cgroup_path: &CgroupV2Path,
    ) -> Result<MetricCounters, MetricReadError> {
        let dir = self.metric_dir(cgroup_path);
        let current_bytes = read_optional_u64(&dir.join("memory.current"))?.unwrap_or(0);
        let limit_bytes = read_memory_limit(&dir.join("memory.max"))?.unwrap_or(0);
        let pressure = read_pressure(&dir.join("memory.pressure"))?.unwrap_or_default();
        let mut counters = MetricCounters::default();
        counters.set_memory(
            current_bytes,
            limit_bytes,
            pressure.some_total_us,
            pressure.full_total_us,
        );
        Ok(counters)
    }

    fn metric_dir(&self, cgroup_path: &CgroupV2Path) -> PathBuf {
        self.cgroup_root.join(relative_cgroup_path(cgroup_path))
    }
}

#[derive(Debug, Error)]
pub enum MetricReadError {
    #[error("failed to read metric file {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse metric file {path}: {reason}")]
    Parse { path: PathBuf, reason: &'static str },
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct PressureTotals {
    some_total_us: u64,
    full_total_us: u64,
}

fn relative_cgroup_path(cgroup_path: &CgroupV2Path) -> &Path {
    cgroup_path
        .as_path()
        .strip_prefix(Path::new("/"))
        .unwrap_or(cgroup_path.as_path())
}

fn read_optional_u64(path: &Path) -> Result<Option<u64>, MetricReadError> {
    read_optional_string(path)?
        .map(|contents| parse_u64(path, contents.trim()))
        .transpose()
}

fn read_memory_limit(path: &Path) -> Result<Option<u64>, MetricReadError> {
    read_optional_string(path)?
        .map(|contents| {
            let value = contents.trim();
            if value == "max" {
                return Ok(0);
            }
            parse_u64(path, value)
        })
        .transpose()
}

fn read_pressure(path: &Path) -> Result<Option<PressureTotals>, MetricReadError> {
    read_optional_string(path)?
        .map(|contents| parse_pressure(path, &contents))
        .transpose()
}

fn read_optional_string(path: &Path) -> Result<Option<String>, MetricReadError> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(MetricReadError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn parse_u64(path: &Path, value: &str) -> Result<u64, MetricReadError> {
    value.parse().map_err(|_| MetricReadError::Parse {
        path: path.to_path_buf(),
        reason: "expected unsigned integer",
    })
}

fn parse_pressure(path: &Path, contents: &str) -> Result<PressureTotals, MetricReadError> {
    let mut totals = PressureTotals::default();

    for line in contents.lines().filter(|line| !line.is_empty()) {
        if line.starts_with("some ") {
            totals.some_total_us = parse_pressure_total(path, line)?;
        } else if line.starts_with("full ") {
            totals.full_total_us = parse_pressure_total(path, line)?;
        }
    }

    Ok(totals)
}

fn parse_pressure_total(path: &Path, line: &str) -> Result<u64, MetricReadError> {
    line.split_ascii_whitespace()
        .find_map(|field| field.strip_prefix("total="))
        .ok_or_else(|| MetricReadError::Parse {
            path: path.to_path_buf(),
            reason: "missing pressure total",
        })
        .and_then(|total| parse_u64(path, total))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn reads_cgroup_v2_memory_files() {
        let fixture = MemoryFixture::new("/kubepods.slice/pod-a");
        fixture.write("memory.current", "4096\n");
        fixture.write("memory.max", "8192\n");
        fixture.write(
            "memory.pressure",
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=7\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=3\n",
        );

        let counters = fixture.read();

        assert_eq!(counters.memory_current_bytes, 4096);
        assert_eq!(counters.memory_limit_bytes, 8192);
        assert_eq!(counters.memory_pressure_some_total_us, 7);
        assert_eq!(counters.memory_pressure_full_total_us, 3);
    }

    #[test]
    fn missing_memory_files_return_zero_counters() {
        let fixture = MemoryFixture::new("/missing");

        let counters = fixture.read();

        assert_eq!(counters, MetricCounters::default());
    }

    #[test]
    fn memory_max_unlimited_is_zero_limit() {
        let fixture = MemoryFixture::new("/system.slice/prism.service");
        fixture.write("memory.current", "1024\n");
        fixture.write("memory.max", "max\n");

        let counters = fixture.read();

        assert_eq!(counters.memory_current_bytes, 1024);
        assert_eq!(counters.memory_limit_bytes, 0);
    }

    #[test]
    fn invalid_memory_file_returns_parse_error() {
        let fixture = MemoryFixture::new("/bad");
        fixture.write("memory.current", "not-a-number\n");

        let error = fixture
            .reader
            .read_counters(&fixture.cgroup_path)
            .expect_err("invalid metric should fail");

        assert!(matches!(error, MetricReadError::Parse { .. }));
    }

    struct MemoryFixture {
        _temp_dir: TempDir,
        reader: MemoryMetricsReader,
        cgroup_path: CgroupV2Path,
        metric_dir: PathBuf,
    }

    impl MemoryFixture {
        fn new(path: &str) -> Self {
            let temp_dir = TempDir::new().expect("tempdir should be created");
            let cgroup_path = CgroupV2Path::new(path).expect("cgroup path should parse");
            let metric_dir = temp_dir.path().join(relative_cgroup_path(&cgroup_path));
            fs::create_dir_all(&metric_dir).expect("metric dir should be created");
            let reader = MemoryMetricsReader::new(temp_dir.path().to_path_buf());

            Self {
                _temp_dir: temp_dir,
                reader,
                cgroup_path,
                metric_dir,
            }
        }

        fn write(&self, name: &str, contents: &str) {
            fs::write(self.metric_dir.join(name), contents).expect("metric file should be written");
        }

        fn read(&self) -> MetricCounters {
            self.reader
                .read_counters(&self.cgroup_path)
                .expect("memory metrics should read")
        }
    }
}
