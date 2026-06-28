use thiserror::Error;

pub const MAX_HTTP_PACKET_BYTES: usize = 8 * 1024;
const MAX_HTTP_START_LINE_BYTES: usize = 1024;
const MAX_HTTP_METHOD_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpKind {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Trace,
    Connect,
    Other,
}

impl HttpMethod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
            Self::Other => "OTHER",
        }
    }
}

impl TryFrom<&[u8]> for HttpMethod {
    type Error = HttpParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.is_empty() || value.len() > MAX_HTTP_METHOD_BYTES {
            return Err(HttpParseError::InvalidMethod);
        }

        if !value.iter().copied().all(is_http_token_byte) {
            return Err(HttpParseError::InvalidMethod);
        }

        Ok(match value {
            b"GET" => Self::Get,
            b"POST" => Self::Post,
            b"PUT" => Self::Put,
            b"DELETE" => Self::Delete,
            b"PATCH" => Self::Patch,
            b"HEAD" => Self::Head,
            b"OPTIONS" => Self::Options,
            b"TRACE" => Self::Trace,
            b"CONNECT" => Self::Connect,
            _ => Self::Other,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
}

impl HttpVersion {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

impl TryFrom<&[u8]> for HttpVersion {
    type Error = HttpParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value {
            b"HTTP/1.0" => Ok(Self::Http10),
            b"HTTP/1.1" => Ok(Self::Http11),
            _ => Err(HttpParseError::InvalidVersion),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpStatus {
    code: u16,
}

impl HttpStatus {
    /// Creates a validated HTTP status code.
    ///
    /// # Errors
    ///
    /// Returns [`HttpParseError::InvalidStatus`] when the code is outside the
    /// three digit HTTP status range.
    pub const fn new(code: u16) -> Result<Self, HttpParseError> {
        if code >= 100 && code <= 999 {
            Ok(Self { code })
        } else {
            Err(HttpParseError::InvalidStatus)
        }
    }

    #[must_use]
    pub const fn code(self) -> u16 {
        self.code
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpMetadata {
    kind: HttpKind,
    method: Option<HttpMethod>,
    status: Option<HttpStatus>,
    version: HttpVersion,
}

impl HttpMetadata {
    #[must_use]
    pub const fn request(method: HttpMethod, version: HttpVersion) -> Self {
        Self {
            kind: HttpKind::Request,
            method: Some(method),
            status: None,
            version,
        }
    }

    #[must_use]
    pub const fn response(status: HttpStatus, version: HttpVersion) -> Self {
        Self {
            kind: HttpKind::Response,
            method: None,
            status: Some(status),
            version,
        }
    }

    #[must_use]
    pub const fn kind(self) -> HttpKind {
        self.kind
    }

    #[must_use]
    pub const fn method(self) -> Option<HttpMethod> {
        self.method
    }

    #[must_use]
    pub const fn status(self) -> Option<HttpStatus> {
        self.status
    }

    #[must_use]
    pub const fn version(self) -> HttpVersion {
        self.version
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HttpMetrics {
    requests_total: u64,
    responses_total: u64,
}

impl HttpMetrics {
    #[must_use]
    pub const fn requests_total(self) -> u64 {
        self.requests_total
    }

    #[must_use]
    pub const fn responses_total(self) -> u64 {
        self.responses_total
    }
}

#[derive(Debug, Default)]
pub struct HttpMetricTracker {
    metrics: HttpMetrics,
}

impl HttpMetricTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, metadata: Option<&HttpMetadata>) {
        let Some(metadata) = metadata else {
            return;
        };

        match metadata.kind() {
            HttpKind::Request => {
                self.metrics.requests_total = self.metrics.requests_total.saturating_add(1);
            }
            HttpKind::Response => {
                self.metrics.responses_total = self.metrics.responses_total.saturating_add(1);
            }
        }
    }

    #[must_use]
    pub const fn metrics(&self) -> HttpMetrics {
        self.metrics
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HttpParseError {
    #[error("HTTP packet exceeds parser size limit")]
    PacketTooLarge,
    #[error("HTTP start line exceeds parser size limit")]
    StartLineTooLarge,
    #[error("HTTP start line is invalid")]
    InvalidStartLine,
    #[error("HTTP method is invalid")]
    InvalidMethod,
    #[error("HTTP version is invalid")]
    InvalidVersion,
    #[error("HTTP status is invalid")]
    InvalidStatus,
}

/// Parses visible HTTP/1.x metadata from a bounded packet.
///
/// Only the start line is inspected. Paths, headers, and bodies are not stored
/// or returned.
///
/// # Errors
///
/// Returns an error for oversized packets or malformed HTTP-looking start
/// lines. Incomplete or non-HTTP packets return `Ok(None)`.
pub fn parse_http1_metadata(packet: &[u8]) -> Result<Option<HttpMetadata>, HttpParseError> {
    if packet.len() > MAX_HTTP_PACKET_BYTES {
        return Err(HttpParseError::PacketTooLarge);
    }

    let Some(line) = start_line(packet) else {
        return Ok(None);
    };

    if line.len() > MAX_HTTP_START_LINE_BYTES {
        return Err(HttpParseError::StartLineTooLarge);
    }

    if line.starts_with(b"HTTP/") {
        return parse_response_line(line).map(Some);
    }

    parse_request_line(line)
}

fn start_line(packet: &[u8]) -> Option<&[u8]> {
    let index = packet.iter().position(|byte| *byte == b'\n')?;
    let line = packet.get(..index)?;
    Some(line.strip_suffix(b"\r").unwrap_or(line))
}

fn parse_request_line(line: &[u8]) -> Result<Option<HttpMetadata>, HttpParseError> {
    let mut fields = line.splitn(3, |byte| *byte == b' ');
    let Some(method) = fields.next() else {
        return Ok(None);
    };
    let Some(target) = fields.next() else {
        return Ok(None);
    };
    let Some(version) = fields.next() else {
        return Ok(None);
    };

    if method.is_empty() || target.is_empty() {
        return Ok(None);
    }

    if !version.starts_with(b"HTTP/") {
        return Ok(None);
    }

    let method = HttpMethod::try_from(method)?;
    let version = HttpVersion::try_from(version)?;

    Ok(Some(HttpMetadata::request(method, version)))
}

fn parse_response_line(line: &[u8]) -> Result<HttpMetadata, HttpParseError> {
    let mut fields = line.splitn(3, |byte| *byte == b' ');
    let Some(version) = fields.next() else {
        return Err(HttpParseError::InvalidStartLine);
    };
    let Some(status) = fields.next() else {
        return Err(HttpParseError::InvalidStartLine);
    };

    let version = HttpVersion::try_from(version)?;
    let status = parse_status(status)?;

    Ok(HttpMetadata::response(status, version))
}

fn parse_status(status: &[u8]) -> Result<HttpStatus, HttpParseError> {
    if status.len() != 3 || !status.iter().all(u8::is_ascii_digit) {
        return Err(HttpParseError::InvalidStatus);
    }

    let code = status
        .iter()
        .copied()
        .fold(0_u16, |acc, byte| (acc * 10) + u16::from(byte - b'0'));
    HttpStatus::new(code)
}

const fn is_http_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_visible_request_metadata_without_path_or_headers() {
        let packet = b"GET /private/customer/123 HTTP/1.1\r\nAuthorization: Bearer secret\r\n\r\n";

        let metadata = parse_http1_metadata(packet)
            .expect("parser should succeed")
            .expect("request should be visible");

        assert_eq!(metadata.kind(), HttpKind::Request);
        assert_eq!(metadata.method(), Some(HttpMethod::Get));
        assert_eq!(metadata.status(), None);
        assert_eq!(metadata.version(), HttpVersion::Http11);
    }

    #[test]
    fn parses_visible_response_status() {
        let packet = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

        let metadata = parse_http1_metadata(packet)
            .expect("parser should succeed")
            .expect("response should be visible");

        assert_eq!(metadata.kind(), HttpKind::Response);
        assert_eq!(metadata.status().map(HttpStatus::code), Some(404));
        assert_eq!(metadata.method(), None);
    }

    #[test]
    fn incomplete_packet_returns_no_metadata() {
        assert_eq!(parse_http1_metadata(b"GET / HTTP/1.1"), Ok(None));
    }

    #[test]
    fn non_http_packet_returns_no_metadata() {
        assert_eq!(parse_http1_metadata(b"\x16\x03\x01\x00\x2a\n"), Ok(None));
    }

    #[test]
    fn oversized_packet_is_rejected_before_parsing() {
        let packet = vec![b'G'; MAX_HTTP_PACKET_BYTES + 1];

        assert_eq!(
            parse_http1_metadata(&packet),
            Err(HttpParseError::PacketTooLarge)
        );
    }

    #[test]
    fn oversized_start_line_is_rejected() {
        let mut packet = vec![b'A'; MAX_HTTP_START_LINE_BYTES + 1];
        packet.push(b'\n');

        assert_eq!(
            parse_http1_metadata(&packet),
            Err(HttpParseError::StartLineTooLarge)
        );
    }

    #[test]
    fn metric_tracker_counts_only_visible_metadata() {
        let mut tracker = HttpMetricTracker::new();
        let request =
            parse_http1_metadata(b"POST /login HTTP/1.1\r\n\r\n").expect("parser should succeed");
        let response = parse_http1_metadata(b"HTTP/1.1 204 No Content\r\n\r\n")
            .expect("parser should succeed");

        tracker.observe(request.as_ref());
        tracker.observe(response.as_ref());
        tracker.observe(None);

        assert_eq!(tracker.metrics().requests_total(), 1);
        assert_eq!(tracker.metrics().responses_total(), 1);
    }
}
