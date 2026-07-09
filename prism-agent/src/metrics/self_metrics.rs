use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Self-metrics for the agent itself.
#[derive(Debug)]
pub struct SelfMetrics {
    start_time: Instant,
    scrapes: AtomicU64,
    queue_depth: AtomicU64,
    dropped_events: AtomicU64,
    otlp_export_failures: AtomicU64,
    otlp_export_retries: AtomicU64,
    otlp_exporter_up: AtomicU64,
}

impl Default for SelfMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl SelfMetrics {
    #[must_use]
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            scrapes: AtomicU64::new(0),
            queue_depth: AtomicU64::new(0),
            dropped_events: AtomicU64::new(0),
            otlp_export_failures: AtomicU64::new(0),
            otlp_export_retries: AtomicU64::new(0),
            otlp_exporter_up: AtomicU64::new(1),
        }
    }

    /// Increments the scrape counter.
    pub fn record_scrape(&self) {
        self.scrapes.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the number of scrapes.
    #[must_use]
    pub fn scrape_count(&self) -> u64 {
        self.scrapes.load(Ordering::Relaxed)
    }

    /// Returns the agent uptime in seconds.
    #[must_use]
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Updates the current event queue depth.
    pub fn set_queue_depth(&self, depth: u64) {
        self.queue_depth.store(depth, Ordering::Relaxed);
    }

    /// Returns the current queue depth.
    #[must_use]
    pub fn queue_depth(&self) -> u64 {
        self.queue_depth.load(Ordering::Relaxed)
    }

    /// Increments the dropped events counter.
    pub fn record_drop(&self) {
        self.dropped_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the total dropped events.
    #[must_use]
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    /// Increments the OTLP export failure counter.
    pub fn record_otlp_failure(&self) {
        self.otlp_export_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the total OTLP export failures.
    #[must_use]
    pub fn otlp_export_failures(&self) -> u64 {
        self.otlp_export_failures.load(Ordering::Relaxed)
    }

    /// Increments the OTLP export retry counter.
    pub fn record_otlp_retry(&self) {
        self.otlp_export_retries.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the total OTLP export retries.
    #[must_use]
    pub fn otlp_export_retries(&self) -> u64 {
        self.otlp_export_retries.load(Ordering::Relaxed)
    }

    /// Sets the OTLP exporter status.
    pub fn set_otlp_up(&self, up: bool) {
        self.otlp_exporter_up
            .store(u64::from(up), Ordering::Relaxed);
    }

    /// Returns whether the OTLP exporter is up.
    #[must_use]
    pub fn otlp_up(&self) -> u64 {
        self.otlp_exporter_up.load(Ordering::Relaxed)
    }
}

/// Renders self-metrics in Prometheus text format.
pub fn render_self_metrics(metrics: &SelfMetrics, version: &str, health_status: u64) -> String {
    let mut output = String::with_capacity(1024);

    // Agent info
    output.push_str("# HELP prism_agent_build_info Build metadata for the agent.\n");
    output.push_str("# TYPE prism_agent_build_info gauge\n");
    let _ = writeln!(output, "prism_agent_build_info{{version=\"{version}\"}} 1");

    output.push_str("# HELP prism_agent_up Whether the Prism agent exporter is running.\n");
    output.push_str("# TYPE prism_agent_up gauge\n");
    let _ = writeln!(output, "prism_agent_up 1");

    output.push_str("# HELP prism_agent_health_status Health status: 0=unhealthy, 1=healthy.\n");
    output.push_str("# TYPE prism_agent_health_status gauge\n");
    let _ = writeln!(output, "prism_agent_health_status {health_status}");

    output.push_str("# HELP prism_agent_uptime_seconds Prism agent exporter uptime in seconds.\n");
    output.push_str("# TYPE prism_agent_uptime_seconds counter\n");
    let _ = writeln!(
        output,
        "prism_agent_uptime_seconds {}",
        metrics.uptime_seconds()
    );

    output.push_str("# HELP prism_agent_scrapes_total Prometheus scrapes served by this agent.\n");
    output.push_str("# TYPE prism_agent_scrapes_total counter\n");
    let _ = writeln!(
        output,
        "prism_agent_scrapes_total {}",
        metrics.scrape_count()
    );

    output.push_str("# HELP prism_event_queue_depth Current depth of the security event queue.\n");
    output.push_str("# TYPE prism_event_queue_depth gauge\n");
    let _ = writeln!(output, "prism_event_queue_depth {}", metrics.queue_depth());

    output.push_str(
        "# HELP prism_dropped_events_total Total events dropped due to queue overflow.\n",
    );
    output.push_str("# TYPE prism_dropped_events_total counter\n");
    let _ = writeln!(
        output,
        "prism_dropped_events_total {}",
        metrics.dropped_events()
    );

    output.push_str("# HELP prism_otlp_export_failures_total OTLP export failures.\n");
    output.push_str("# TYPE prism_otlp_export_failures_total counter\n");
    let _ = writeln!(
        output,
        "prism_otlp_export_failures_total {}",
        metrics.otlp_export_failures()
    );

    output.push_str("# HELP prism_otlp_export_retries_total OTLP export retry attempts.\n");
    output.push_str("# TYPE prism_otlp_export_retries_total counter\n");
    let _ = writeln!(
        output,
        "prism_otlp_export_retries_total {}",
        metrics.otlp_export_retries()
    );

    output.push_str(
        "# HELP prism_otlp_exporter_up Whether the OTLP exporter is healthy (1) or failed (0).\n",
    );
    output.push_str("# TYPE prism_otlp_exporter_up gauge\n");
    let _ = writeln!(output, "prism_otlp_exporter_up {}", metrics.otlp_up());

    output
}
