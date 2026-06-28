use std::collections::HashMap;

use prism_core::ids::CgroupId;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IpAddress {
    #[must_use]
    pub const fn is_encrypted_port(port: u16) -> bool {
        matches!(port, 443 | 5432 | 6379)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionEndpoint {
    address: IpAddress,
    port: u16,
}

impl ConnectionEndpoint {
    #[must_use]
    pub const fn new(address: IpAddress, port: u16) -> Self {
        Self { address, port }
    }

    #[must_use]
    pub const fn address(self) -> IpAddress {
        self.address
    }

    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionEvent {
    pid: u32,
    cgroup_id: CgroupId,
    protocol: TransportProtocol,
    source: ConnectionEndpoint,
    destination: ConnectionEndpoint,
    timestamp_ns: u64,
}

impl ConnectionEvent {
    #[must_use]
    pub const fn new(
        pid: u32,
        cgroup_id: CgroupId,
        protocol: TransportProtocol,
        source: ConnectionEndpoint,
        destination: ConnectionEndpoint,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            pid,
            cgroup_id,
            protocol,
            source,
            destination,
            timestamp_ns,
        }
    }

    #[must_use]
    pub const fn pid(self) -> u32 {
        self.pid
    }

    #[must_use]
    pub const fn cgroup_id(self) -> CgroupId {
        self.cgroup_id
    }

    #[must_use]
    pub const fn protocol(self) -> TransportProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn source(self) -> ConnectionEndpoint {
        self.source
    }

    #[must_use]
    pub const fn destination(self) -> ConnectionEndpoint {
        self.destination
    }

    #[must_use]
    pub const fn timestamp_ns(self) -> u64 {
        self.timestamp_ns
    }

    #[must_use]
    pub const fn is_encrypted_transport(self) -> bool {
        IpAddress::is_encrypted_port(self.destination.port())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConnectionKey {
    pid: u32,
    cgroup_id: CgroupId,
    protocol: TransportProtocol,
    source: ConnectionEndpoint,
    destination: ConnectionEndpoint,
}

impl From<ConnectionEvent> for ConnectionKey {
    fn from(event: ConnectionEvent) -> Self {
        Self {
            pid: event.pid(),
            cgroup_id: event.cgroup_id(),
            protocol: event.protocol(),
            source: event.source(),
            destination: event.destination(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionState {
    event: ConnectionEvent,
    opened_at_ns: u64,
    last_seen_ns: u64,
}

impl ConnectionState {
    #[must_use]
    pub const fn event(self) -> ConnectionEvent {
        self.event
    }

    #[must_use]
    pub const fn opened_at_ns(self) -> u64 {
        self.opened_at_ns
    }

    #[must_use]
    pub const fn last_seen_ns(self) -> u64 {
        self.last_seen_ns
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionSpan {
    event: ConnectionEvent,
    start_ns: u64,
    duration_ns: u64,
}

impl ConnectionSpan {
    #[must_use]
    pub const fn event(self) -> ConnectionEvent {
        self.event
    }

    #[must_use]
    pub const fn start_ns(self) -> u64 {
        self.start_ns
    }

    #[must_use]
    pub const fn duration_ns(self) -> u64 {
        self.duration_ns
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionMetrics {
    active: usize,
    opened_total: u64,
    closed_total: u64,
    encrypted_total: u64,
    plaintext_total: u64,
}

impl ConnectionMetrics {
    #[must_use]
    pub const fn active(self) -> usize {
        self.active
    }

    #[must_use]
    pub const fn opened_total(self) -> u64 {
        self.opened_total
    }

    #[must_use]
    pub const fn closed_total(self) -> u64 {
        self.closed_total
    }

    #[must_use]
    pub const fn encrypted_total(self) -> u64 {
        self.encrypted_total
    }

    #[must_use]
    pub const fn plaintext_total(self) -> u64 {
        self.plaintext_total
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConnectionError {
    #[error("connection close timestamp is before open timestamp")]
    NegativeDuration,
}

#[derive(Debug, Default)]
pub struct ConnectionTracker {
    active: HashMap<ConnectionKey, ConnectionState>,
    metrics: ConnectionMetrics,
}

impl ConnectionTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open(&mut self, event: ConnectionEvent) {
        let key = ConnectionKey::from(event);
        let state = ConnectionState {
            event,
            opened_at_ns: event.timestamp_ns(),
            last_seen_ns: event.timestamp_ns(),
        };

        if self.active.insert(key, state).is_none() {
            self.metrics.opened_total = self.metrics.opened_total.saturating_add(1);
            if event.is_encrypted_transport() {
                self.metrics.encrypted_total = self.metrics.encrypted_total.saturating_add(1);
            } else {
                self.metrics.plaintext_total = self.metrics.plaintext_total.saturating_add(1);
            }
        }
        self.metrics.active = self.active.len();
    }

    /// Closes a connection and returns a connection-level span.
    ///
    /// # Errors
    ///
    /// Returns an error when the close timestamp is earlier than the open
    /// timestamp. Unknown connections are ignored and return `Ok(None)`.
    pub fn close(
        &mut self,
        event: ConnectionEvent,
        closed_at_ns: u64,
    ) -> Result<Option<ConnectionSpan>, ConnectionError> {
        let Some(state) = self.active.remove(&ConnectionKey::from(event)) else {
            self.metrics.active = self.active.len();
            return Ok(None);
        };

        if closed_at_ns < state.opened_at_ns() {
            self.active.insert(ConnectionKey::from(event), state);
            self.metrics.active = self.active.len();
            return Err(ConnectionError::NegativeDuration);
        }

        self.metrics.closed_total = self.metrics.closed_total.saturating_add(1);
        self.metrics.active = self.active.len();

        Ok(Some(ConnectionSpan {
            event: state.event(),
            start_ns: state.opened_at_ns(),
            duration_ns: closed_at_ns.saturating_sub(state.opened_at_ns()),
        }))
    }

    pub fn touch(&mut self, event: ConnectionEvent) {
        if let Some(state) = self.active.get_mut(&ConnectionKey::from(event)) {
            state.last_seen_ns = state.last_seen_ns.max(event.timestamp_ns());
        }
    }

    #[must_use]
    pub fn metrics(&self) -> ConnectionMetrics {
        self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_and_plaintext_connections_produce_connection_spans() {
        let mut tracker = ConnectionTracker::new();
        let encrypted = event(100, 443, 10);
        let plaintext = event(101, 80, 20);

        tracker.open(encrypted);
        tracker.open(plaintext);
        let encrypted_span = tracker
            .close(encrypted, 40)
            .expect("close should succeed")
            .expect("span should be emitted");
        let plaintext_span = tracker
            .close(plaintext, 50)
            .expect("close should succeed")
            .expect("span should be emitted");

        assert_eq!(encrypted_span.duration_ns(), 30);
        assert_eq!(plaintext_span.duration_ns(), 30);
        assert_eq!(tracker.metrics().encrypted_total(), 1);
        assert_eq!(tracker.metrics().plaintext_total(), 1);
        assert_eq!(tracker.metrics().closed_total(), 2);
        assert_eq!(tracker.metrics().active(), 0);
    }

    #[test]
    fn duplicate_open_updates_state_without_double_counting() {
        let mut tracker = ConnectionTracker::new();
        let connection = event(7, 443, 10);

        tracker.open(connection);
        tracker.open(ConnectionEvent::new(
            connection.pid(),
            connection.cgroup_id(),
            connection.protocol(),
            connection.source(),
            connection.destination(),
            20,
        ));

        assert_eq!(tracker.metrics().opened_total(), 1);
        assert_eq!(tracker.metrics().active(), 1);
    }

    #[test]
    fn close_before_open_returns_error_and_preserves_connection() {
        let mut tracker = ConnectionTracker::new();
        let connection = event(7, 443, 10);
        tracker.open(connection);

        let error = tracker
            .close(connection, 5)
            .expect_err("negative duration should fail");

        assert_eq!(error, ConnectionError::NegativeDuration);
        assert_eq!(tracker.metrics().active(), 1);
    }

    #[test]
    fn connection_event_has_no_payload_capture_field() {
        assert_eq!(core::mem::size_of::<ConnectionEvent>(), 64);
    }

    fn event(pid: u32, port: u16, timestamp_ns: u64) -> ConnectionEvent {
        ConnectionEvent::new(
            pid,
            CgroupId::new(42),
            TransportProtocol::Tcp,
            ConnectionEndpoint::new(IpAddress::V4([127, 0, 0, 1]), 50_000),
            ConnectionEndpoint::new(IpAddress::V4([10, 0, 0, 1]), port),
            timestamp_ns,
        )
    }
}
