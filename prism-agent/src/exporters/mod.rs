pub mod otlp;
pub mod traces;

pub use otlp::OtlpLogsExporter;
pub use traces::{
    OtlpTraceExporter, OtlpTraceExporterConfig, TraceSpanSink, run_otlp_trace_exporter,
};
