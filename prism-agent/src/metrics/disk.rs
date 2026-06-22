use std::{
    fs, io,
    path::{Path, PathBuf},
};

use prism_core::events::metrics::MetricCounters;

use crate::{
    metadata::CgroupV2Path,
    metrics::memory::{MetricReadError, relative_cgroup_path},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskIoMetricsReader {
    cgroup_root: PathBuf,
}

impl DiskIoMetricsReader {
    #[must_use]
    pub fn new(cgroup_root: PathBuf) -> Self {
        Self { cgroup_root }
    }

    #[must_use]
    pub fn system() -> Self {
        Self::new(PathBuf::from("/sys/fs/cgroup"))
    }

    /// Reads cgroup v2 disk I/O metrics into the shared metric counter layout.
    ///
    /// # Errors
    ///
    /// Returns an error when a present `io.stat` file cannot be read or
    /// contains malformed values. A missing `io.stat` file returns zeroed disk
    /// counters.
    pub fn read_counters(
        &self,
        cgroup_path: &CgroupV2Path,
    ) -> Result<MetricCounters, MetricReadError> {
        let path = self.metric_dir(cgroup_path).join("io.stat");
        let Some(contents) = read_optional_string(&path)? else {
            return Ok(MetricCounters::default());
        };
        let totals = parse_io_stat(&path, &contents)?;
        let mut counters = MetricCounters::default();
        counters.set_disk_io(
            totals.read_bytes,
            totals.write_bytes,
            totals.read_ops,
            totals.write_ops,
        );
        Ok(counters)
    }

    fn metric_dir(&self, cgroup_path: &CgroupV2Path) -> PathBuf {
        self.cgroup_root.join(relative_cgroup_path(cgroup_path))
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct DiskTotals {
    read_bytes: u64,
    write_bytes: u64,
    read_ops: u64,
    write_ops: u64,
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

fn parse_io_stat(path: &Path, contents: &str) -> Result<DiskTotals, MetricReadError> {
    contents
        .lines()
        .filter(|line| !line.is_empty())
        .try_fold(DiskTotals::default(), |totals, line| {
            parse_io_stat_line(path, totals, line)
        })
}

fn parse_io_stat_line(
    path: &Path,
    mut totals: DiskTotals,
    line: &str,
) -> Result<DiskTotals, MetricReadError> {
    for field in line.split_ascii_whitespace().skip(1) {
        let Some((name, value)) = field.split_once('=') else {
            return Err(parse_error(path));
        };
        let value = parse_u64(path, value)?;
        match name {
            "rbytes" => totals.read_bytes = totals.read_bytes.saturating_add(value),
            "wbytes" => totals.write_bytes = totals.write_bytes.saturating_add(value),
            "rios" => totals.read_ops = totals.read_ops.saturating_add(value),
            "wios" => totals.write_ops = totals.write_ops.saturating_add(value),
            _ => {}
        }
    }

    Ok(totals)
}

fn parse_u64(path: &Path, value: &str) -> Result<u64, MetricReadError> {
    value.parse().map_err(|_| parse_error(path))
}

fn parse_error(path: &Path) -> MetricReadError {
    MetricReadError::Parse {
        path: path.to_path_buf(),
        reason: "expected cgroup v2 io.stat key=value counters",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn reads_cgroup_v2_io_stat_totals() {
        let fixture = DiskFixture::new("/kubepods.slice/pod-a");
        fixture.write(
            "8:0 rbytes=100 wbytes=200 rios=3 wios=4 dbytes=5 dios=6\n8:16 rbytes=7 wbytes=11 rios=13 wios=17\n",
        );

        let counters = fixture.read();

        assert_eq!(counters.disk_read_bytes, 107);
        assert_eq!(counters.disk_write_bytes, 211);
        assert_eq!(counters.disk_read_ops, 16);
        assert_eq!(counters.disk_write_ops, 21);
    }

    #[test]
    fn missing_io_stat_returns_zero_counters() {
        let fixture = DiskFixture::new("/system.slice/prism.service");

        let counters = fixture.read();

        assert_eq!(counters, MetricCounters::default());
    }

    #[test]
    fn invalid_io_stat_returns_parse_error() {
        let fixture = DiskFixture::new("/bad");
        fixture.write("8:0 rbytes=abc\n");

        let error = fixture
            .reader
            .read_counters(&fixture.cgroup_path)
            .expect_err("invalid io.stat should fail");

        assert!(matches!(error, MetricReadError::Parse { .. }));
    }

    struct DiskFixture {
        _temp_dir: TempDir,
        reader: DiskIoMetricsReader,
        cgroup_path: CgroupV2Path,
        metric_dir: PathBuf,
    }

    impl DiskFixture {
        fn new(path: &str) -> Self {
            let temp_dir = TempDir::new().expect("tempdir should be created");
            let cgroup_path = CgroupV2Path::new(path).expect("cgroup path should parse");
            let metric_dir = temp_dir.path().join(relative_cgroup_path(&cgroup_path));
            fs::create_dir_all(&metric_dir).expect("metric dir should be created");
            let reader = DiskIoMetricsReader::new(temp_dir.path().to_path_buf());

            Self {
                _temp_dir: temp_dir,
                reader,
                cgroup_path,
                metric_dir,
            }
        }

        fn write(&self, contents: &str) {
            fs::write(self.metric_dir.join("io.stat"), contents)
                .expect("io.stat should be written");
        }

        fn read(&self) -> MetricCounters {
            self.reader
                .read_counters(&self.cgroup_path)
                .expect("disk metrics should read")
        }
    }
}
