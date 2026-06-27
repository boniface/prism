pub mod connection;

pub use connection::{
    ConnectionEndpoint, ConnectionEvent, ConnectionMetrics, ConnectionSpan, ConnectionState,
    ConnectionTracker, IpAddress, TransportProtocol,
};
