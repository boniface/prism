use std::{
    time::{Duration, UNIX_EPOCH},
    vec,
};

use async_trait::async_trait;
use opentelemetry::{
    Context, KeyValue,
    trace::{
        Span, SpanContext, SpanId, SpanKind, TraceContextExt, TraceFlags, TraceId, TraceState,
        Tracer, TracerProvider,
    },
};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::trace::SdkTracerProvider;
use prism_core::events::SpanEvent;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    config::OtlpSettings,
    runtime::{KernelEventReceiver, RuntimeError},
};

const TRACE_EXPORT_TASK: &str = "otlp-trace-exporter";
const RETRY_BACKOFF: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpTraceExporterConfig {
    endpoint: String,
    batch_size: usize,
    retry_attempts: usize,
    shutdown_timeout: Duration,
}

impl OtlpTraceExporterConfig {
    #[must_use]
    pub fn new(settings: &OtlpSettings) -> Self {
        Self {
            endpoint: settings.endpoint.clone(),
            batch_size: settings.trace_batch_size,
            retry_attempts: settings.trace_retry_attempts,
            shutdown_timeout: Duration::from_millis(settings.trace_shutdown_timeout_ms),
        }
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    #[must_use]
    pub const fn batch_size(&self) -> usize {
        self.batch_size
    }

    #[must_use]
    pub const fn retry_attempts(&self) -> usize {
        self.retry_attempts
    }

    #[must_use]
    pub const fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }
}

#[async_trait]
pub trait TraceSpanSink: Send {
    async fn export_batch(&mut self, spans: &[SpanEvent]) -> Result<(), RuntimeError>;
    async fn shutdown(&mut self, timeout: Duration) -> Result<(), RuntimeError>;
}

#[derive(Debug)]
pub struct OtlpTraceExporter {
    provider: SdkTracerProvider,
}

impl OtlpTraceExporter {
    /// Creates a new OTLP gRPC trace exporter.
    ///
    /// # Errors
    ///
    /// Returns an error when the OTLP span exporter cannot be built.
    pub fn new(config: &OtlpTraceExporterConfig) -> Result<Self, anyhow::Error> {
        let exporter = SpanExporter::builder()
            .with_tonic()
            .with_endpoint(config.endpoint())
            .build()?;
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .build();

        Ok(Self { provider })
    }
}

#[async_trait]
impl TraceSpanSink for OtlpTraceExporter {
    async fn export_batch(&mut self, spans: &[SpanEvent]) -> Result<(), RuntimeError> {
        let tracer = self.provider.tracer("prism-traces");
        for span in spans {
            emit_span(&tracer, span);
        }

        self.provider.force_flush().map_err(|error| {
            RuntimeError::task_failed(TRACE_EXPORT_TASK, format!("failed to flush spans: {error}"))
        })
    }

    async fn shutdown(&mut self, timeout_duration: Duration) -> Result<(), RuntimeError> {
        self.provider
            .shutdown_with_timeout(timeout_duration)
            .map_err(|error| {
                RuntimeError::task_failed(TRACE_EXPORT_TASK, format!("shutdown failed: {error}"))
            })
    }
}

/// Runs the OTLP trace exporter loop over a bounded span queue.
///
/// # Errors
///
/// Returns an error when the OTLP trace exporter cannot be initialised.
pub async fn run_otlp_trace_exporter(
    settings: OtlpSettings,
    receiver: KernelEventReceiver<SpanEvent>,
    token: CancellationToken,
) -> Result<(), RuntimeError> {
    let config = OtlpTraceExporterConfig::new(&settings);
    let exporter = OtlpTraceExporter::new(&config).map_err(|error| {
        RuntimeError::task_failed(
            TRACE_EXPORT_TASK,
            format!("failed to init trace exporter: {error}"),
        )
    })?;

    info!(endpoint = %config.endpoint(), "OTLP trace exporter started");
    run_trace_export_loop(exporter, receiver, token, config).await
}

async fn run_trace_export_loop<S>(
    mut sink: S,
    mut receiver: KernelEventReceiver<SpanEvent>,
    token: CancellationToken,
    config: OtlpTraceExporterConfig,
) -> Result<(), RuntimeError>
where
    S: TraceSpanSink,
{
    let mut batch = Vec::with_capacity(config.batch_size());

    loop {
        tokio::select! {
            () = token.cancelled() => {
                receiver.close();
                drain_and_shutdown(&mut sink, &mut receiver, &mut batch, &config).await?;
                info!("OTLP trace exporter stopped");
                return Ok(());
            }
            span = receiver.recv() => {
                let Some(span) = span else {
                    flush_with_retry(&mut sink, &mut batch, &config).await;
                    sink.shutdown(config.shutdown_timeout()).await?;
                    info!("OTLP trace exporter stopped");
                    return Ok(());
                };
                batch.push(span);
                if batch.len() >= config.batch_size() {
                    flush_with_retry(&mut sink, &mut batch, &config).await;
                }
            }
        }
    }
}

async fn drain_and_shutdown<S>(
    sink: &mut S,
    receiver: &mut KernelEventReceiver<SpanEvent>,
    batch: &mut Vec<SpanEvent>,
    config: &OtlpTraceExporterConfig,
) -> Result<(), RuntimeError>
where
    S: TraceSpanSink,
{
    timeout(config.shutdown_timeout(), async {
        while let Some(span) = receiver.recv().await {
            batch.push(span);
            if batch.len() >= config.batch_size() {
                flush_with_retry(sink, batch, config).await;
            }
        }
        flush_with_retry(sink, batch, config).await;
        sink.shutdown(config.shutdown_timeout()).await
    })
    .await
    .map_err(|_| RuntimeError::QueueDrainTimeout {
        timeout: config.shutdown_timeout(),
    })?
}

async fn flush_with_retry<S>(
    sink: &mut S,
    batch: &mut Vec<SpanEvent>,
    config: &OtlpTraceExporterConfig,
) where
    S: TraceSpanSink,
{
    if batch.is_empty() {
        return;
    }

    let spans = core::mem::take(batch);
    for attempt in 1..=config.retry_attempts() {
        match sink.export_batch(&spans).await {
            Ok(()) => return,
            Err(error) if attempt < config.retry_attempts() => {
                warn!(%error, attempt, "OTLP trace export failed; retrying");
                sleep(RETRY_BACKOFF).await;
            }
            Err(error) => {
                error!(%error, attempts = config.retry_attempts(), dropped = spans.len(), "OTLP trace export failed");
                return;
            }
        }
    }
}

fn emit_span(tracer: &opentelemetry_sdk::trace::SdkTracer, event: &SpanEvent) {
    let start = UNIX_EPOCH + Duration::from_nanos(event.start_ns);
    let end = start + Duration::from_nanos(event.duration_ns);
    let attributes = vec![
        KeyValue::new("prism.trace_id", hex_encode(&event.trace_id)),
        KeyValue::new("prism.span_id", hex_encode(&event.span_id)),
        KeyValue::new("prism.parent_span_id", hex_encode(&event.parent_span_id)),
        KeyValue::new("prism.cgroup_id", event.cgroup_id.cast_signed()),
        KeyValue::new("prism.protocol", i64::from(event.protocol)),
        KeyValue::new("http.response.status_code", i64::from(event.http_status)),
    ];

    let builder = tracer
        .span_builder("prism.network")
        .with_kind(SpanKind::Server)
        .with_start_time(start)
        .with_attributes(attributes);
    let mut span = match remote_parent_context(event) {
        Some(context) => builder.start_with_context(tracer, &context),
        None => builder.start(tracer),
    };
    span.end_with_timestamp(end);
}

fn remote_parent_context(event: &SpanEvent) -> Option<Context> {
    if event.trace_id == [0; 16] || event.parent_span_id == [0; 8] {
        return None;
    }

    Some(Context::new().with_remote_span_context(SpanContext::new(
        TraceId::from_bytes(event.trace_id),
        SpanId::from_bytes(event.parent_span_id),
        TraceFlags::SAMPLED,
        true,
        TraceState::NONE,
    )))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::bounded_kernel_events;
    use opentelemetry_sdk::{
        Resource,
        error::OTelSdkResult,
        trace::{SpanData, SpanExporter as SdkSpanExporter},
    };
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default)]
    struct InMemoryTraceSink {
        exported: Vec<SpanEvent>,
        failures_remaining: usize,
        shutdowns: usize,
    }

    #[derive(Debug, Default, Clone)]
    struct RecordingSpanExporter {
        spans: Arc<Mutex<Vec<SpanData>>>,
    }

    impl RecordingSpanExporter {
        fn spans(&self) -> Vec<SpanData> {
            self.spans
                .lock()
                .expect("test span lock should not be poisoned")
                .clone()
        }
    }

    impl SdkSpanExporter for RecordingSpanExporter {
        async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
            self.spans
                .lock()
                .expect("test span lock should not be poisoned")
                .extend(batch);
            Ok(())
        }

        fn set_resource(&mut self, _resource: &Resource) {}
    }

    #[async_trait]
    impl TraceSpanSink for InMemoryTraceSink {
        async fn export_batch(&mut self, spans: &[SpanEvent]) -> Result<(), RuntimeError> {
            if self.failures_remaining > 0 {
                self.failures_remaining -= 1;
                return Err(RuntimeError::task_failed("test", "forced failure"));
            }

            self.exported.extend_from_slice(spans);
            Ok(())
        }

        async fn shutdown(&mut self, _timeout: Duration) -> Result<(), RuntimeError> {
            self.shutdowns = self.shutdowns.saturating_add(1);
            Ok(())
        }
    }

    #[tokio::test]
    async fn trace_exporter_batches_spans() {
        let mut sink = InMemoryTraceSink::default();
        let config = test_config(2);
        let mut batch = Vec::with_capacity(config.batch_size());
        batch.push(span_event(1));
        batch.push(span_event(2));

        flush_with_retry(&mut sink, &mut batch, &config).await;

        assert!(batch.is_empty());
        assert_eq!(sink.exported.len(), 2);
    }

    #[tokio::test]
    async fn trace_exporter_retries_failed_exports() {
        let mut sink = InMemoryTraceSink {
            failures_remaining: 1,
            ..InMemoryTraceSink::default()
        };
        let config = test_config(2);
        let mut batch = vec![span_event(1)];

        flush_with_retry(&mut sink, &mut batch, &config).await;

        assert_eq!(sink.exported.len(), 1);
    }

    #[tokio::test]
    async fn export_failures_do_not_block_bounded_queue() {
        let (sender, receiver) = bounded_kernel_events(1);
        let token = CancellationToken::new();
        let sink = InMemoryTraceSink {
            failures_remaining: 8,
            ..InMemoryTraceSink::default()
        };

        sender
            .try_send(span_event(1))
            .expect("first span should fit");
        assert!(sender.try_send(span_event(2)).is_err());
        drop(sender);

        run_trace_export_loop(sink, receiver, token, test_config(1))
            .await
            .expect("loop should exit when sender is dropped");
    }

    #[tokio::test]
    async fn shutdown_drains_queued_spans() {
        let (sender, receiver) = bounded_kernel_events(4);
        let token = CancellationToken::new();
        sender
            .try_send(span_event(1))
            .expect("span should be queued");
        sender
            .try_send(span_event(2))
            .expect("span should be queued");
        token.cancel();

        let sink = InMemoryTraceSink::default();
        run_trace_export_loop(sink, receiver, token, test_config(4))
            .await
            .expect("shutdown should drain queued spans");
    }

    #[tokio::test]
    async fn otlp_trace_exporter_builds_for_bad_endpoint_without_panic() {
        let settings = OtlpSettings {
            endpoint: "not-a-valid-endpoint".to_owned(),
            trace_batch_size: 1,
            trace_retry_attempts: 1,
            trace_shutdown_timeout_ms: 100,
        };
        let config = OtlpTraceExporterConfig::new(&settings);

        drop(OtlpTraceExporter::new(&config));
    }

    #[test]
    fn emitted_span_uses_remote_parent_context_when_available() {
        let exporter = RecordingSpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let tracer = provider.tracer("test");
        let mut event = span_event(7);
        event.trace_id = [4; 16];
        event.parent_span_id = [3; 8];

        emit_span(&tracer, &event);
        provider
            .force_flush()
            .expect("in-memory provider should flush");
        let spans = exporter.spans();

        assert_eq!(spans.len(), 1);
        assert_eq!(
            spans[0].span_context.trace_id(),
            TraceId::from_bytes([4; 16])
        );
        assert_eq!(spans[0].parent_span_id, SpanId::from_bytes([3; 8]));
    }

    #[tokio::test]
    #[ignore = "requires a local OpenTelemetry Collector on PRISM_OTLP_TEST_ENDPOINT or 127.0.0.1:4317"]
    async fn local_collector_receives_span_export() {
        let endpoint = std::env::var("PRISM_OTLP_TEST_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:4317".to_owned());
        let settings = OtlpSettings {
            endpoint,
            trace_batch_size: 1,
            trace_retry_attempts: 1,
            trace_shutdown_timeout_ms: 1_000,
        };
        let config = OtlpTraceExporterConfig::new(&settings);
        let mut exporter =
            OtlpTraceExporter::new(&config).expect("local collector exporter should build");

        exporter
            .export_batch(&[span_event(9)])
            .await
            .expect("collector should accept span export");
        exporter
            .shutdown(config.shutdown_timeout())
            .await
            .expect("collector exporter should shutdown");
    }

    fn test_config(batch_size: usize) -> OtlpTraceExporterConfig {
        OtlpTraceExporterConfig {
            endpoint: "http://127.0.0.1:4317".to_owned(),
            batch_size,
            retry_attempts: 2,
            shutdown_timeout: Duration::from_millis(100),
        }
    }

    const fn span_event(seed: u8) -> SpanEvent {
        SpanEvent {
            trace_id: [seed; 16],
            span_id: [seed; 8],
            parent_span_id: [0; 8],
            cgroup_id: seed as u64,
            start_ns: 1_000,
            duration_ns: 10,
            http_status: 200,
            protocol: 1,
            reserved: [0; 5],
        }
    }
}
