use std::{
    collections::HashSet,
    fmt::Write as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;

use crate::{
    bpf::{BpfLifecycleError, LoadedBpf},
    config::{PrometheusLabel, PrometheusSettings},
    metrics::MetricSnapshot,
};

pub trait MetricSnapshotSource: Send + Sync {
    /// Reads point-in-time metric snapshots for one scrape.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing metric source cannot be read.
    fn metric_snapshots(&self) -> Result<Vec<MetricSnapshot>, PrometheusError>;
}

pub struct BpfMetricSource {
    loaded_bpf: Mutex<LoadedBpf>,
}

impl BpfMetricSource {
    #[must_use]
    pub fn new(loaded_bpf: LoadedBpf) -> Self {
        Self {
            loaded_bpf: Mutex::new(loaded_bpf),
        }
    }
}

impl MetricSnapshotSource for BpfMetricSource {
    fn metric_snapshots(&self) -> Result<Vec<MetricSnapshot>, PrometheusError> {
        self.loaded_bpf
            .lock()
            .map_err(|_| PrometheusError::SnapshotLock)?
            .metric_snapshots()
            .map_err(PrometheusError::Bpf)
    }
}

#[derive(Debug, Default)]
pub struct StaticMetricSource {
    snapshots: Vec<MetricSnapshot>,
}

impl StaticMetricSource {
    #[must_use]
    pub fn new(snapshots: Vec<MetricSnapshot>) -> Self {
        Self { snapshots }
    }
}

impl MetricSnapshotSource for StaticMetricSource {
    fn metric_snapshots(&self) -> Result<Vec<MetricSnapshot>, PrometheusError> {
        Ok(self.snapshots.clone())
    }
}

pub struct PrometheusExporter {
    source: Arc<dyn MetricSnapshotSource>,
    controls: CardinalityControls,
    series: SeriesTracker,
    started_at: Instant,
    scrape_count: AtomicU64,
}

impl PrometheusExporter {
    #[must_use]
    pub fn new(source: Arc<dyn MetricSnapshotSource>, settings: &PrometheusSettings) -> Self {
        Self {
            source,
            controls: CardinalityControls::from(settings),
            series: SeriesTracker::new(settings.series_limit),
            started_at: Instant::now(),
            scrape_count: AtomicU64::new(0),
        }
    }

    /// Renders one Prometheus text-format scrape.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured metric source cannot provide
    /// infrastructure metric snapshots.
    pub fn render(&self) -> Result<String, PrometheusError> {
        let snapshots = self.source.metric_snapshots()?;
        let scrape_count = self.scrape_count.fetch_add(1, Ordering::Relaxed) + 1;
        let mut output = String::with_capacity(4096 + snapshots.len().saturating_mul(1024));
        render_self_metrics(
            &mut output,
            scrape_count,
            self.started_at.elapsed().as_secs(),
        );
        for snapshot in &snapshots {
            self.render_snapshot(&mut output, snapshot);
        }
        render_cardinality_metrics(&mut output, &self.series);
        Ok(output)
    }

    fn render_snapshot(&self, output: &mut String, snapshot: &MetricSnapshot) {
        let labels = self.controls.labels_for(snapshot);
        let counters = snapshot.counters();

        self.render_metric(
            output,
            "prism_cgroup_cpu_runtime_ns",
            &labels,
            counters.cpu_runtime_ns,
        );
        self.render_metric(
            output,
            "prism_cgroup_memory_current_bytes",
            &labels,
            counters.memory_current_bytes,
        );
        self.render_metric(
            output,
            "prism_cgroup_memory_limit_bytes",
            &labels,
            counters.memory_limit_bytes,
        );
        self.render_metric(
            output,
            "prism_cgroup_disk_read_bytes",
            &labels,
            counters.disk_read_bytes,
        );
        self.render_metric(
            output,
            "prism_cgroup_disk_write_bytes",
            &labels,
            counters.disk_write_bytes,
        );
        self.render_metric(output, "prism_cgroup_rx_bytes", &labels, counters.rx_bytes);
        self.render_metric(output, "prism_cgroup_tx_bytes", &labels, counters.tx_bytes);
        self.render_metric(
            output,
            "prism_cgroup_rx_packets",
            &labels,
            counters.rx_packets,
        );
        self.render_metric(
            output,
            "prism_cgroup_tx_packets",
            &labels,
            counters.tx_packets,
        );
        self.render_metric(
            output,
            "prism_cgroup_drops_total",
            &labels,
            counters.drop_count,
        );
    }

    fn render_metric(&self, output: &mut String, name: &str, labels: &str, value: u64) {
        if self.series.allow(name, labels) {
            let _ = writeln!(output, "{name}{labels} {value}");
        }
    }
}

pub struct PrometheusServer {
    listener: TcpListener,
    exporter: Arc<PrometheusExporter>,
}

impl PrometheusServer {
    /// Binds a Prometheus HTTP server.
    ///
    /// # Errors
    ///
    /// Returns an error when the listener cannot bind the requested address.
    pub async fn bind(
        settings: &PrometheusSettings,
        source: Arc<dyn MetricSnapshotSource>,
    ) -> Result<Self, PrometheusError> {
        let listener = TcpListener::bind(settings.listen_addr)
            .await
            .map_err(PrometheusError::Bind)?;
        Ok(Self {
            listener,
            exporter: Arc::new(PrometheusExporter::new(source, settings)),
        })
    }

    /// Runs the server until the cancellation token is triggered.
    ///
    /// # Errors
    ///
    /// Returns an error when accepting a connection fails.
    pub async fn run(self, shutdown: CancellationToken) -> Result<(), PrometheusError> {
        loop {
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted.map_err(PrometheusError::Accept)?;
                    let exporter = Arc::clone(&self.exporter);
                    tokio::spawn(async move {
                        if let Err(error) = handle_connection(stream, exporter).await {
                            tracing::debug!(%error, "failed to serve prometheus scrape");
                        }
                    });
                }
            }
        }
    }

    #[cfg(test)]
    fn local_addr(&self) -> std::net::SocketAddr {
        self.listener
            .local_addr()
            .expect("bound listener should have a local address")
    }
}

#[derive(Debug, Error)]
pub enum PrometheusError {
    #[error("failed to bind prometheus listener")]
    Bind(#[source] std::io::Error),
    #[error("failed to accept prometheus connection")]
    Accept(#[source] std::io::Error),
    #[error("failed to read prometheus request")]
    Read(#[source] std::io::Error),
    #[error("failed to write prometheus response")]
    Write(#[source] std::io::Error),
    #[error("failed to lock metric snapshot source")]
    SnapshotLock,
    #[error("failed to read eBPF metric snapshots")]
    Bpf(#[source] BpfLifecycleError),
}

fn render_self_metrics(output: &mut String, scrape_count: u64, uptime_seconds: u64) {
    output.push_str("# HELP prism_agent_up Whether the Prism agent exporter is running.\n");
    output.push_str("# TYPE prism_agent_up gauge\n");
    output.push_str("prism_agent_up 1\n");
    output.push_str("# HELP prism_agent_uptime_seconds Prism agent exporter uptime in seconds.\n");
    output.push_str("# TYPE prism_agent_uptime_seconds counter\n");
    let _ = writeln!(output, "prism_agent_uptime_seconds {uptime_seconds}");
    output.push_str("# HELP prism_agent_scrapes_total Prometheus scrapes served by this agent.\n");
    output.push_str("# TYPE prism_agent_scrapes_total counter\n");
    let _ = writeln!(output, "prism_agent_scrapes_total {scrape_count}");
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CardinalityControls {
    label_allowlist: Vec<PrometheusLabel>,
    max_label_value_len: usize,
    expensive_dimensions_enabled: bool,
}

impl CardinalityControls {
    fn labels_for(&self, snapshot: &MetricSnapshot) -> String {
        let labels = self
            .label_allowlist
            .iter()
            .filter(|label| self.expensive_dimensions_enabled || !label.is_high_cardinality())
            .filter_map(|label| {
                label_value(*label, snapshot).map(|value| {
                    format!(
                        "{}=\"{}\"",
                        label.name(),
                        sanitize_label_value(&value, self.max_label_value_len)
                    )
                })
            })
            .collect::<Vec<_>>();

        if labels.is_empty() {
            return String::new();
        }

        format!("{{{}}}", labels.join(","))
    }
}

impl From<&PrometheusSettings> for CardinalityControls {
    fn from(settings: &PrometheusSettings) -> Self {
        Self {
            label_allowlist: settings.label_allowlist.clone(),
            max_label_value_len: settings.max_label_value_len,
            expensive_dimensions_enabled: settings.expensive_dimensions_enabled,
        }
    }
}

#[derive(Debug)]
struct SeriesTracker {
    limit: usize,
    active: Mutex<HashSet<String>>,
    dropped: AtomicU64,
}

impl SeriesTracker {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            active: Mutex::new(HashSet::with_capacity(limit.min(1024))),
            dropped: AtomicU64::new(0),
        }
    }

    fn allow(&self, name: &str, labels: &str) -> bool {
        let key = format!("{name}{labels}");
        let Ok(mut active) = self.active.lock() else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        };

        if active.contains(&key) {
            return true;
        }

        if active.len() >= self.limit {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        active.insert(key);
        true
    }

    fn active_count(&self) -> usize {
        self.active.lock().map_or(0, |active| active.len())
    }

    fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

fn render_cardinality_metrics(output: &mut String, series: &SeriesTracker) {
    output.push_str("# HELP prism_metric_series_active Active Prometheus metric series.\n");
    output.push_str("# TYPE prism_metric_series_active gauge\n");
    let _ = writeln!(
        output,
        "prism_metric_series_active {}",
        series.active_count()
    );
    output.push_str(
        "# HELP prism_metric_series_dropped_total Metric series dropped by cardinality controls.\n",
    );
    output.push_str("# TYPE prism_metric_series_dropped_total counter\n");
    let _ = writeln!(
        output,
        "prism_metric_series_dropped_total {}",
        series.dropped_count()
    );
}

fn label_value(label: PrometheusLabel, snapshot: &MetricSnapshot) -> Option<String> {
    match label {
        PrometheusLabel::CgroupId => Some(snapshot.cgroup_id().value().to_string()),
        PrometheusLabel::ContainerId
        | PrometheusLabel::ContainerName
        | PrometheusLabel::Namespace
        | PrometheusLabel::PodName => None,
    }
}

fn sanitize_label_value(value: &str, max_len: usize) -> String {
    value
        .chars()
        .filter_map(|character| match character {
            '"' | '\\' => None,
            '\n' | '\r' | '\t' => Some('_'),
            character if character.is_control() => None,
            character => Some(character),
        })
        .take(max_len)
        .collect()
}

async fn handle_connection(
    mut stream: TcpStream,
    exporter: Arc<PrometheusExporter>,
) -> Result<(), PrometheusError> {
    let mut buffer = [0_u8; 1024];
    let bytes_read = stream
        .read(&mut buffer)
        .await
        .map_err(PrometheusError::Read)?;
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .unwrap_or("/");

    let (status, content_type, body) = if path == "/metrics" {
        (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            exporter.render()?,
        )
    } else {
        (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".to_owned(),
        )
    };
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(PrometheusError::Write)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use prism_core::{events::metrics::MetricCounters, ids::CgroupId};
    use tokio::net::TcpStream;

    use super::*;

    #[test]
    fn renders_prometheus_text_for_infrastructure_metrics() {
        let mut counters = MetricCounters::default();
        counters.add_cpu_runtime(42);
        counters.add_network_rx(100, 2);
        let exporter = PrometheusExporter::new(
            Arc::new(StaticMetricSource::new(vec![MetricSnapshot::new(
                CgroupId::new(7),
                counters,
            )])),
            &PrometheusSettings::default(),
        );

        let output = exporter.render().expect("metrics should render");

        assert!(output.contains("prism_agent_up 1\n"));
        assert!(output.contains("prism_cgroup_cpu_runtime_ns{cgroup_id=\"7\"} 42\n"));
        assert!(output.contains("prism_cgroup_rx_bytes{cgroup_id=\"7\"} 100\n"));
        assert!(!output.contains("container_name"));
        assert!(output.contains("prism_metric_series_active 10\n"));
        assert!(output.contains("prism_metric_series_dropped_total 0\n"));
    }

    #[test]
    fn label_values_are_sanitized_and_bounded() {
        let value = sanitize_label_value("abc\"\\\n\tdef", 5);

        assert_eq!(value, "abc__");
    }

    #[test]
    fn series_limit_drops_excess_infrastructure_series() {
        let settings = PrometheusSettings {
            series_limit: 1,
            ..PrometheusSettings::default()
        };
        let exporter = PrometheusExporter::new(
            Arc::new(StaticMetricSource::new(vec![MetricSnapshot::new(
                CgroupId::new(7),
                MetricCounters::default(),
            )])),
            &settings,
        );

        let output = exporter.render().expect("metrics should render");

        assert!(output.contains("prism_cgroup_cpu_runtime_ns{cgroup_id=\"7\"} 0\n"));
        assert!(!output.contains("prism_cgroup_memory_current_bytes{cgroup_id=\"7\"}"));
        assert!(output.contains("prism_metric_series_active 1\n"));
        assert!(output.contains("prism_metric_series_dropped_total 9\n"));
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_prometheus_text() {
        let source = Arc::new(StaticMetricSource::new(Vec::new()));
        let settings = PrometheusSettings {
            listen_addr: "127.0.0.1:0".parse().expect("addr should parse"),
            ..PrometheusSettings::default()
        };
        let server = PrometheusServer::bind(&settings, source)
            .await
            .expect("server should bind");
        let addr = server.local_addr();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(server.run(shutdown.clone()));

        let mut stream = TcpStream::connect(addr)
            .await
            .expect("server should accept connection");
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .expect("request should write");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .expect("response should read");
        shutdown.cancel();
        task.await
            .expect("server task should join")
            .expect("server should stop cleanly");

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("text/plain; version=0.0.4"));
        assert!(response.contains("prism_agent_up 1"));
    }
}
