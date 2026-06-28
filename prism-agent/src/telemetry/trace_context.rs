use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    str,
};

use prism_core::events::SpanEvent;
use thiserror::Error;

use crate::{
    config::TraceSettings,
    runtime::{KernelEventReceiver, KernelEventSender, bounded_kernel_events},
};

pub const MAX_TRACE_HEADER_SCAN_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceId([u8; 16]);

impl TraceId {
    /// Creates a non-zero W3C trace id.
    ///
    /// # Errors
    ///
    /// Returns [`TraceContextError::InvalidTraceId`] when the id is all zero.
    pub const fn new(bytes: [u8; 16]) -> Result<Self, TraceContextError> {
        if all_zero_16(&bytes) {
            Err(TraceContextError::InvalidTraceId)
        } else {
            Ok(Self(bytes))
        }
    }

    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceSpanId([u8; 8]);

impl TraceSpanId {
    /// Creates a non-zero W3C span id.
    ///
    /// # Errors
    ///
    /// Returns [`TraceContextError::InvalidSpanId`] when the id is all zero.
    pub const fn new(bytes: [u8; 8]) -> Result<Self, TraceContextError> {
        if all_zero_8(bytes) {
            Err(TraceContextError::InvalidSpanId)
        } else {
            Ok(Self(bytes))
        }
    }

    #[must_use]
    pub const fn bytes(self) -> [u8; 8] {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceParent {
    trace_id: TraceId,
    parent_span_id: TraceSpanId,
    sampled: bool,
}

impl TraceParent {
    #[must_use]
    pub const fn new(trace_id: TraceId, parent_span_id: TraceSpanId, sampled: bool) -> Self {
        Self {
            trace_id,
            parent_span_id,
            sampled,
        }
    }

    #[must_use]
    pub const fn trace_id(self) -> TraceId {
        self.trace_id
    }

    #[must_use]
    pub const fn parent_span_id(self) -> TraceSpanId {
        self.parent_span_id
    }

    #[must_use]
    pub const fn sampled(self) -> bool {
        self.sampled
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanProtocol {
    Connection,
    Http1,
    Postgres,
    Redis,
}

impl SpanProtocol {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Connection => 0,
            Self::Http1 => 1,
            Self::Postgres => 2,
            Self::Redis => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpanBuildInput {
    trace_parent: Option<TraceParent>,
    cgroup_id: u64,
    start_ns: u64,
    duration_ns: u64,
    http_status: Option<u16>,
    protocol: SpanProtocol,
}

impl SpanBuildInput {
    #[must_use]
    pub const fn new(
        trace_parent: Option<TraceParent>,
        cgroup_id: u64,
        start_ns: u64,
        duration_ns: u64,
        http_status: Option<u16>,
        protocol: SpanProtocol,
    ) -> Self {
        Self {
            trace_parent,
            cgroup_id,
            start_ns,
            duration_ns,
            http_status,
            protocol,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpanBuilder {
    settings: TraceSettings,
}

impl SpanBuilder {
    #[must_use]
    pub const fn new(settings: TraceSettings) -> Self {
        Self { settings }
    }

    #[must_use]
    pub fn build(&self, input: &SpanBuildInput) -> Option<SpanEvent> {
        let trace_parent = input.trace_parent;
        if trace_parent.is_none() && !self.settings.create_root_spans {
            return None;
        }

        let trace_id = trace_parent.map_or_else(
            || derive_trace_id(input),
            |parent| parent.trace_id().bytes(),
        );
        let span_id = derive_span_id(input, trace_id);
        let parent_span_id =
            trace_parent.map_or([0_u8; 8], |parent| parent.parent_span_id().bytes());

        Some(SpanEvent {
            trace_id,
            span_id,
            parent_span_id,
            cgroup_id: input.cgroup_id,
            start_ns: input.start_ns,
            duration_ns: input.duration_ns,
            http_status: input.http_status.unwrap_or(0),
            protocol: input.protocol.code(),
            reserved: [0; 5],
        })
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TraceContextError {
    #[error("trace header scan exceeds parser size limit")]
    HeaderScanTooLarge,
    #[error("traceparent header contains invalid UTF-8")]
    InvalidUtf8,
    #[error("traceparent header has invalid format")]
    InvalidFormat,
    #[error("traceparent version is invalid")]
    InvalidVersion,
    #[error("trace id is invalid")]
    InvalidTraceId,
    #[error("span id is invalid")]
    InvalidSpanId,
    #[error("trace flags are invalid")]
    InvalidTraceFlags,
}

/// Parses a W3C `traceparent` header value.
///
/// # Errors
///
/// Returns a structured error when any field is malformed or when trace/span
/// ids are all zero.
pub fn parse_traceparent(value: &str) -> Result<TraceParent, TraceContextError> {
    let bytes = value.trim().as_bytes();
    if bytes.len() != 55 {
        return Err(TraceContextError::InvalidFormat);
    }
    if bytes[2] != b'-' || bytes[35] != b'-' || bytes[52] != b'-' {
        return Err(TraceContextError::InvalidFormat);
    }

    let version = parse_hex_u8(bytes.get(0..2).ok_or(TraceContextError::InvalidFormat)?)?;
    if version != 0 {
        return Err(TraceContextError::InvalidVersion);
    }

    let trace_id = TraceId::new(parse_hex_16(
        bytes.get(3..35).ok_or(TraceContextError::InvalidFormat)?,
    )?)?;
    let parent_span_id = TraceSpanId::new(parse_hex_8(
        bytes.get(36..52).ok_or(TraceContextError::InvalidFormat)?,
    )?)?;
    let flags = parse_hex_u8(bytes.get(53..55).ok_or(TraceContextError::InvalidFormat)?)
        .map_err(|_| TraceContextError::InvalidTraceFlags)?;

    Ok(TraceParent::new(trace_id, parent_span_id, flags & 1 == 1))
}

/// Extracts a visible W3C `traceparent` header from an HTTP/1 packet.
///
/// # Errors
///
/// Returns an error for oversized header scans, malformed header UTF-8, or
/// invalid trace context values.
pub fn extract_visible_traceparent(
    packet: &[u8],
) -> Result<Option<TraceParent>, TraceContextError> {
    if packet.len() > MAX_TRACE_HEADER_SCAN_BYTES {
        return Err(TraceContextError::HeaderScanTooLarge);
    }

    let Some(start_line_end) = find_lf(packet, 0) else {
        return Ok(None);
    };
    let mut offset = start_line_end + 1;

    while offset < packet.len() {
        let Some(line_end) = find_lf(packet, offset) else {
            return Ok(None);
        };
        let mut line = packet
            .get(offset..line_end)
            .ok_or(TraceContextError::InvalidFormat)?;
        line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            return Ok(None);
        }

        if let Some(value) = traceparent_header_value(line) {
            let value = str::from_utf8(value).map_err(|_| TraceContextError::InvalidUtf8)?;
            return parse_traceparent(value).map(Some);
        }

        offset = line_end + 1;
    }

    Ok(None)
}

#[must_use]
pub fn bounded_span_queue(
    capacity: usize,
) -> (KernelEventSender<SpanEvent>, KernelEventReceiver<SpanEvent>) {
    bounded_kernel_events(capacity)
}

fn traceparent_header_value(line: &[u8]) -> Option<&[u8]> {
    let separator = line.iter().position(|byte| *byte == b':')?;
    let name = line.get(..separator)?;
    let value = line.get(separator + 1..)?;
    if name.eq_ignore_ascii_case(b"traceparent") {
        Some(trim_ascii(value))
    } else {
        None
    }
}

fn trim_ascii(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &value[start..end]
}

fn find_lf(packet: &[u8], offset: usize) -> Option<usize> {
    packet
        .get(offset..)?
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|index| offset + index)
}

fn parse_hex_16(bytes: &[u8]) -> Result<[u8; 16], TraceContextError> {
    let mut parsed = [0_u8; 16];
    parse_hex_into(bytes, &mut parsed)?;
    Ok(parsed)
}

fn parse_hex_8(bytes: &[u8]) -> Result<[u8; 8], TraceContextError> {
    let mut parsed = [0_u8; 8];
    parse_hex_into(bytes, &mut parsed)?;
    Ok(parsed)
}

fn parse_hex_into(bytes: &[u8], output: &mut [u8]) -> Result<(), TraceContextError> {
    if bytes.len() != output.len() * 2 {
        return Err(TraceContextError::InvalidFormat);
    }

    for (index, chunk) in bytes.chunks_exact(2).enumerate() {
        output[index] = parse_hex_u8(chunk)?;
    }
    Ok(())
}

fn parse_hex_u8(bytes: &[u8]) -> Result<u8, TraceContextError> {
    if bytes.len() != 2 {
        return Err(TraceContextError::InvalidFormat);
    }

    let high = hex_value(bytes[0])?;
    let low = hex_value(bytes[1])?;
    Ok((high << 4) | low)
}

fn hex_value(byte: u8) -> Result<u8, TraceContextError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(TraceContextError::InvalidFormat),
    }
}

fn derive_trace_id(input: &SpanBuildInput) -> [u8; 16] {
    let first = hash_span_input(input, 0);
    let second = hash_span_input(input, 1);
    let mut trace_id = [0_u8; 16];
    trace_id[..8].copy_from_slice(&first.to_be_bytes());
    trace_id[8..].copy_from_slice(&second.to_be_bytes());
    if trace_id == [0; 16] {
        trace_id[15] = 1;
    }
    trace_id
}

fn derive_span_id(input: &SpanBuildInput, trace_id: [u8; 16]) -> [u8; 8] {
    let mut hasher = DefaultHasher::new();
    trace_id.hash(&mut hasher);
    input.cgroup_id.hash(&mut hasher);
    input.start_ns.hash(&mut hasher);
    input.duration_ns.hash(&mut hasher);
    input.protocol.code().hash(&mut hasher);
    let mut span_id = hasher.finish().to_be_bytes();
    if span_id == [0; 8] {
        span_id[7] = 1;
    }
    span_id
}

fn hash_span_input(input: &SpanBuildInput, seed: u8) -> u64 {
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    input.cgroup_id.hash(&mut hasher);
    input.start_ns.hash(&mut hasher);
    input.duration_ns.hash(&mut hasher);
    input.http_status.hash(&mut hasher);
    input.protocol.code().hash(&mut hasher);
    hasher.finish()
}

const fn all_zero_16(bytes: &[u8; 16]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

const fn all_zero_8(bytes: [u8; 8]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_traceparent() {
        let parent = parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
            .expect("traceparent should parse");

        assert!(parent.sampled());
        assert_eq!(
            parent.trace_id().bytes(),
            [
                0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
                0x47, 0x36
            ]
        );
    }

    #[test]
    fn rejects_all_zero_trace_id() {
        let error = parse_traceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01")
            .expect_err("zero trace id should fail");

        assert_eq!(error, TraceContextError::InvalidTraceId);
    }

    #[test]
    fn extracts_visible_traceparent_header() {
        let packet = b"GET / HTTP/1.1\r\nHost: local\r\nTraceParent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\r\n";

        let parent = extract_visible_traceparent(packet)
            .expect("extract should succeed")
            .expect("traceparent should be visible");

        assert_eq!(
            parent.parent_span_id().bytes(),
            [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7]
        );
    }

    #[test]
    fn missing_trace_context_skips_root_span_by_default() {
        let builder = SpanBuilder::new(TraceSettings::default());
        let input = SpanBuildInput::new(None, 42, 10, 5, Some(200), SpanProtocol::Http1);

        assert!(builder.build(&input).is_none());
    }

    #[test]
    fn missing_trace_context_creates_root_span_when_configured() {
        let builder = SpanBuilder::new(TraceSettings {
            create_root_spans: true,
            span_queue_capacity: 8,
        });
        let input = SpanBuildInput::new(None, 42, 10, 5, Some(200), SpanProtocol::Http1);

        let span = builder.build(&input).expect("root span should be built");

        assert_ne!(span.trace_id, [0; 16]);
        assert_ne!(span.span_id, [0; 8]);
        assert_eq!(span.parent_span_id, [0; 8]);
        assert_eq!(span.http_status, 200);
        assert_eq!(span.protocol, SpanProtocol::Http1.code());
    }

    #[test]
    fn visible_trace_context_creates_correlated_span() {
        let parent = parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
            .expect("traceparent should parse");
        let builder = SpanBuilder::new(TraceSettings::default());
        let input = SpanBuildInput::new(Some(parent), 42, 10, 5, Some(204), SpanProtocol::Http1);

        let span = builder.build(&input).expect("span should be built");

        assert_eq!(span.trace_id, parent.trace_id().bytes());
        assert_eq!(span.parent_span_id, parent.parent_span_id().bytes());
    }

    #[tokio::test]
    async fn span_queue_is_bounded() {
        let (sender, _receiver) = bounded_span_queue(1);
        let builder = SpanBuilder::new(TraceSettings {
            create_root_spans: true,
            span_queue_capacity: 1,
        });
        let input = SpanBuildInput::new(None, 42, 10, 5, Some(200), SpanProtocol::Http1);
        let span = builder.build(&input).expect("span should be built");

        assert!(sender.try_send(span).is_ok());
        assert!(sender.try_send(span).is_err());
    }
}
