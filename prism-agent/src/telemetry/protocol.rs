use thiserror::Error;

use crate::config::ApplicationTelemetrySettings;

pub const MAX_PROTOCOL_PACKET_BYTES: usize = 8 * 1024;
const MAX_SQL_KEYWORD_BYTES: usize = 16;
const MAX_REDIS_COMMAND_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostgresMessage {
    Query,
    Parse,
    Bind,
    Execute,
    Close,
    Describe,
    Sync,
    Terminate,
    Other(u8),
}

impl From<u8> for PostgresMessage {
    fn from(value: u8) -> Self {
        match value {
            b'Q' => Self::Query,
            b'P' => Self::Parse,
            b'B' => Self::Bind,
            b'E' => Self::Execute,
            b'C' => Self::Close,
            b'D' => Self::Describe,
            b'S' => Self::Sync,
            b'X' => Self::Terminate,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlOperation {
    Select,
    Insert,
    Update,
    Delete,
    Create,
    Alter,
    Drop,
    Commit,
    Rollback,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostgresMetadata {
    message: PostgresMessage,
    operation: Option<SqlOperation>,
}

impl PostgresMetadata {
    #[must_use]
    pub const fn new(message: PostgresMessage, operation: Option<SqlOperation>) -> Self {
        Self { message, operation }
    }

    #[must_use]
    pub const fn message(self) -> PostgresMessage {
        self.message
    }

    #[must_use]
    pub const fn operation(self) -> Option<SqlOperation> {
        self.operation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisCommand {
    Get,
    Set,
    Del,
    Exists,
    Expire,
    HGet,
    HSet,
    LPush,
    RPush,
    Publish,
    Subscribe,
    Other,
}

impl RedisCommand {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Set => "SET",
            Self::Del => "DEL",
            Self::Exists => "EXISTS",
            Self::Expire => "EXPIRE",
            Self::HGet => "HGET",
            Self::HSet => "HSET",
            Self::LPush => "LPUSH",
            Self::RPush => "RPUSH",
            Self::Publish => "PUBLISH",
            Self::Subscribe => "SUBSCRIBE",
            Self::Other => "OTHER",
        }
    }
}

impl TryFrom<&[u8]> for RedisCommand {
    type Error = ProtocolParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.is_empty() || value.len() > MAX_REDIS_COMMAND_BYTES {
            return Err(ProtocolParseError::InvalidRedisCommand);
        }

        classify_redis_command(value).ok_or(ProtocolParseError::InvalidRedisCommand)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedisMetadata {
    command: RedisCommand,
}

impl RedisMetadata {
    #[must_use]
    pub const fn new(command: RedisCommand) -> Self {
        Self { command }
    }

    #[must_use]
    pub const fn command(self) -> RedisCommand {
        self.command
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolMetrics {
    postgres_messages_total: u64,
    redis_commands_total: u64,
}

impl ProtocolMetrics {
    #[must_use]
    pub const fn postgres_messages_total(self) -> u64 {
        self.postgres_messages_total
    }

    #[must_use]
    pub const fn redis_commands_total(self) -> u64 {
        self.redis_commands_total
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolMetricTracker {
    settings: ApplicationTelemetrySettings,
    metrics: ProtocolMetrics,
}

impl ProtocolMetricTracker {
    #[must_use]
    pub const fn new(settings: ApplicationTelemetrySettings) -> Self {
        Self {
            settings,
            metrics: ProtocolMetrics {
                postgres_messages_total: 0,
                redis_commands_total: 0,
            },
        }
    }

    pub fn observe_postgres(&mut self, metadata: Option<&PostgresMetadata>) {
        if self.settings.postgres_enabled && metadata.is_some() {
            self.metrics.postgres_messages_total =
                self.metrics.postgres_messages_total.saturating_add(1);
        }
    }

    pub fn observe_redis(&mut self, metadata: Option<&RedisMetadata>) {
        if self.settings.redis_enabled && metadata.is_some() {
            self.metrics.redis_commands_total = self.metrics.redis_commands_total.saturating_add(1);
        }
    }

    #[must_use]
    pub const fn metrics(&self) -> ProtocolMetrics {
        self.metrics
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolParseError {
    #[error("protocol packet exceeds parser size limit")]
    PacketTooLarge,
    #[error("protocol packet declares an invalid frame length")]
    InvalidFrameLength,
    #[error("Postgres query is invalid")]
    InvalidPostgresQuery,
    #[error("Redis frame is invalid")]
    InvalidRedisFrame,
    #[error("Redis command is invalid")]
    InvalidRedisCommand,
}

/// Parses bounded Postgres frontend metadata without returning raw SQL text.
///
/// # Errors
///
/// Returns an error for oversized packets, invalid frame lengths, or invalid
/// simple query frames. Incomplete packets return `Ok(None)`.
pub fn parse_postgres_metadata(
    packet: &[u8],
) -> Result<Option<PostgresMetadata>, ProtocolParseError> {
    if packet.len() > MAX_PROTOCOL_PACKET_BYTES {
        return Err(ProtocolParseError::PacketTooLarge);
    }
    if packet.len() < 5 {
        return Ok(None);
    }

    let message = PostgresMessage::from(packet[0]);
    let length = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]) as usize;
    if length < 4 {
        return Err(ProtocolParseError::InvalidFrameLength);
    }

    let frame_len = length
        .checked_add(1)
        .ok_or(ProtocolParseError::InvalidFrameLength)?;
    if frame_len > packet.len() {
        return Ok(None);
    }

    let operation = match message {
        PostgresMessage::Query => Some(classify_sql_operation(&packet[5..frame_len])?),
        PostgresMessage::Parse => classify_parse_message(&packet[5..frame_len]),
        PostgresMessage::Bind
        | PostgresMessage::Execute
        | PostgresMessage::Close
        | PostgresMessage::Describe
        | PostgresMessage::Sync
        | PostgresMessage::Terminate
        | PostgresMessage::Other(_) => None,
    };

    Ok(Some(PostgresMetadata::new(message, operation)))
}

/// Parses bounded Redis RESP metadata without returning keys, values, or args.
///
/// # Errors
///
/// Returns an error for oversized packets or invalid RESP command frames.
/// Incomplete or non-array packets return `Ok(None)`.
pub fn parse_redis_metadata(packet: &[u8]) -> Result<Option<RedisMetadata>, ProtocolParseError> {
    if packet.len() > MAX_PROTOCOL_PACKET_BYTES {
        return Err(ProtocolParseError::PacketTooLarge);
    }
    if packet.first().copied() != Some(b'*') {
        return Ok(None);
    }

    let Some(array_line_end) = find_crlf(packet, 0) else {
        return Ok(None);
    };
    if parse_decimal(&packet[1..array_line_end]).unwrap_or(0) == 0 {
        return Err(ProtocolParseError::InvalidRedisFrame);
    }

    let bulk_len_offset = array_line_end + 2;
    if packet.get(bulk_len_offset).copied() != Some(b'$') {
        return Err(ProtocolParseError::InvalidRedisFrame);
    }
    let Some(command_len_line_end) = find_crlf(packet, bulk_len_offset) else {
        return Ok(None);
    };
    let command_len = parse_decimal(&packet[bulk_len_offset + 1..command_len_line_end])
        .ok_or(ProtocolParseError::InvalidRedisFrame)?;
    if command_len == 0 || command_len > MAX_REDIS_COMMAND_BYTES {
        return Err(ProtocolParseError::InvalidRedisCommand);
    }

    let command_start = command_len_line_end + 2;
    let command_end = command_start
        .checked_add(command_len)
        .ok_or(ProtocolParseError::InvalidRedisFrame)?;
    if command_end + 2 > packet.len() {
        return Ok(None);
    }
    if packet.get(command_end..command_end + 2) != Some(b"\r\n") {
        return Err(ProtocolParseError::InvalidRedisFrame);
    }

    let command = RedisCommand::try_from(&packet[command_start..command_end])?;
    Ok(Some(RedisMetadata::new(command)))
}

fn classify_parse_message(frame: &[u8]) -> Option<SqlOperation> {
    let statement_end = frame.iter().position(|byte| *byte == 0)?;
    let query_start = statement_end.checked_add(1)?;
    classify_sql_operation(frame.get(query_start..)?).ok()
}

fn classify_sql_operation(query: &[u8]) -> Result<SqlOperation, ProtocolParseError> {
    let keyword = query
        .iter()
        .copied()
        .skip_while(u8::is_ascii_whitespace)
        .take_while(u8::is_ascii_alphabetic)
        .take(MAX_SQL_KEYWORD_BYTES)
        .collect::<Vec<_>>();

    if keyword.is_empty() {
        return Err(ProtocolParseError::InvalidPostgresQuery);
    }

    Ok(classify_sql_keyword(&keyword))
}

fn classify_redis_command(value: &[u8]) -> Option<RedisCommand> {
    if value.eq_ignore_ascii_case(b"GET") {
        return Some(RedisCommand::Get);
    }
    if value.eq_ignore_ascii_case(b"SET") {
        return Some(RedisCommand::Set);
    }
    if value.eq_ignore_ascii_case(b"DEL") {
        return Some(RedisCommand::Del);
    }
    if value.eq_ignore_ascii_case(b"EXISTS") {
        return Some(RedisCommand::Exists);
    }
    if value.eq_ignore_ascii_case(b"EXPIRE") {
        return Some(RedisCommand::Expire);
    }
    if value.eq_ignore_ascii_case(b"HGET") {
        return Some(RedisCommand::HGet);
    }
    if value.eq_ignore_ascii_case(b"HSET") {
        return Some(RedisCommand::HSet);
    }
    if value.eq_ignore_ascii_case(b"LPUSH") {
        return Some(RedisCommand::LPush);
    }
    if value.eq_ignore_ascii_case(b"RPUSH") {
        return Some(RedisCommand::RPush);
    }
    if value.eq_ignore_ascii_case(b"PUBLISH") {
        return Some(RedisCommand::Publish);
    }
    if value.eq_ignore_ascii_case(b"SUBSCRIBE") {
        return Some(RedisCommand::Subscribe);
    }
    value
        .iter()
        .copied()
        .all(is_ascii_alpha)
        .then_some(RedisCommand::Other)
}

fn classify_sql_keyword(keyword: &[u8]) -> SqlOperation {
    if keyword.eq_ignore_ascii_case(b"SELECT") {
        return SqlOperation::Select;
    }
    if keyword.eq_ignore_ascii_case(b"INSERT") {
        return SqlOperation::Insert;
    }
    if keyword.eq_ignore_ascii_case(b"UPDATE") {
        return SqlOperation::Update;
    }
    if keyword.eq_ignore_ascii_case(b"DELETE") {
        return SqlOperation::Delete;
    }
    if keyword.eq_ignore_ascii_case(b"CREATE") {
        return SqlOperation::Create;
    }
    if keyword.eq_ignore_ascii_case(b"ALTER") {
        return SqlOperation::Alter;
    }
    if keyword.eq_ignore_ascii_case(b"DROP") {
        return SqlOperation::Drop;
    }
    if keyword.eq_ignore_ascii_case(b"COMMIT") {
        return SqlOperation::Commit;
    }
    if keyword.eq_ignore_ascii_case(b"ROLLBACK") {
        return SqlOperation::Rollback;
    }
    SqlOperation::Other
}

fn find_crlf(packet: &[u8], offset: usize) -> Option<usize> {
    packet
        .get(offset..)?
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|index| offset + index)
}

fn parse_decimal(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }

    bytes.iter().try_fold(0_usize, |acc, byte| {
        acc.checked_mul(10)?
            .checked_add(usize::from(byte.saturating_sub(b'0')))
    })
}

const fn is_ascii_alpha(byte: u8) -> bool {
    byte.is_ascii_alphabetic()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_simple_query_returns_only_operation_metadata() {
        let packet = postgres_packet(b'Q', b"SELECT * FROM customers WHERE token = 'secret'\0");

        let metadata = parse_postgres_metadata(&packet)
            .expect("parser should succeed")
            .expect("metadata should be visible");

        assert_eq!(metadata.message(), PostgresMessage::Query);
        assert_eq!(metadata.operation(), Some(SqlOperation::Select));
        assert!(!format!("{metadata:?}").contains("customers"));
        assert!(!format!("{metadata:?}").contains("secret"));
    }

    #[test]
    fn postgres_incomplete_frame_returns_no_metadata() {
        assert_eq!(parse_postgres_metadata(b"Q\0\0\0\x20SEL"), Ok(None));
    }

    #[test]
    fn redis_resp_array_returns_only_command_metadata() {
        let packet = b"*2\r\n$3\r\nGET\r\n$16\r\nsession-token-42\r\n";

        let metadata = parse_redis_metadata(packet)
            .expect("parser should succeed")
            .expect("metadata should be visible");

        assert_eq!(metadata.command(), RedisCommand::Get);
        assert!(!format!("{metadata:?}").contains("session-token"));
    }

    #[test]
    fn protocol_classifiers_are_ascii_case_insensitive() {
        let postgres = postgres_packet(b'Q', b"SeLeCt * FROM users WHERE token = 'secret'\0");
        let redis = b"*2\r\n$3\r\ngEt\r\n$9\r\nsecret-id\r\n";

        let postgres_metadata = parse_postgres_metadata(&postgres)
            .expect("postgres parser should succeed")
            .expect("postgres metadata should be visible");
        let redis_metadata = parse_redis_metadata(redis)
            .expect("redis parser should succeed")
            .expect("redis metadata should be visible");

        assert_eq!(postgres_metadata.operation(), Some(SqlOperation::Select));
        assert_eq!(redis_metadata.command(), RedisCommand::Get);
    }

    #[test]
    fn redis_incomplete_command_returns_no_metadata() {
        assert_eq!(parse_redis_metadata(b"*2\r\n$3\r\nGE"), Ok(None));
    }

    #[test]
    fn oversized_protocol_packet_is_rejected() {
        let packet = vec![b'*'; MAX_PROTOCOL_PACKET_BYTES + 1];

        assert_eq!(
            parse_redis_metadata(&packet),
            Err(ProtocolParseError::PacketTooLarge)
        );
        assert_eq!(
            parse_postgres_metadata(&packet),
            Err(ProtocolParseError::PacketTooLarge)
        );
    }

    #[test]
    fn protocol_metrics_are_opt_in() {
        let postgres = PostgresMetadata::new(PostgresMessage::Query, Some(SqlOperation::Select));
        let redis = RedisMetadata::new(RedisCommand::Get);
        let mut disabled = ProtocolMetricTracker::new(ApplicationTelemetrySettings::default());

        disabled.observe_postgres(Some(&postgres));
        disabled.observe_redis(Some(&redis));

        assert_eq!(disabled.metrics().postgres_messages_total(), 0);
        assert_eq!(disabled.metrics().redis_commands_total(), 0);

        let mut enabled = ProtocolMetricTracker::new(ApplicationTelemetrySettings {
            postgres_enabled: true,
            redis_enabled: true,
        });
        enabled.observe_postgres(Some(&postgres));
        enabled.observe_redis(Some(&redis));

        assert_eq!(enabled.metrics().postgres_messages_total(), 1);
        assert_eq!(enabled.metrics().redis_commands_total(), 1);
    }

    fn postgres_packet(message: u8, payload: &[u8]) -> Vec<u8> {
        let length = u32::try_from(payload.len() + 4).expect("test payload length should fit u32");
        let mut packet = Vec::with_capacity(payload.len() + 5);
        packet.push(message);
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }
}
