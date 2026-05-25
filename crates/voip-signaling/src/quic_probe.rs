//! QUIC path probing (spec/06 §6.6, spec/08 §8.1.4).
//!
//! The signaling server listens for QUIC connections on 5 elastic IPs.
//! When a client migrates its QUIC connection to a different server IP,
//! the server observes the client's new source address and reflects it
//! back as a PathProbeResponse (type ID 0x0200) on the QUIC stream.
//!
//! Current implementation: well-structured stub. The actual QUIC listener
//! will be wired up when `voip-client` is ready for path probing.

use std::net::SocketAddr;

use prost::Message;
use tracing::info;

use crate::state::{type_id, FramedMessage};

/// Build a PathProbeResponse framed message for a QUIC path probe.
///
/// Per spec/08 §8.1.4: Sent on the QUIC stream when the client migrates
/// its connection to a different signaling server IP.
pub fn build_path_probe_response(
    server_ip: &str,
    observed_ip: &str,
    observed_port: u32,
    timestamp_ms: u64,
) -> FramedMessage {
    let response = voip_core::proto::signaling::PathProbeResponse {
        server_ip: server_ip.to_owned(),
        observed_ip: observed_ip.to_owned(),
        observed_port,
        timestamp_ms,
    };
    let payload = response.encode_to_vec();
    FramedMessage {
        type_id: type_id::PATH_PROBE_RESPONSE,
        payload,
    }
}

/// Encode a PathProbeResponse into the wire format for sending on a QUIC stream.
///
/// This uses the same 2-byte type prefix + prost payload framing as WebSocket,
/// but is sent on a raw QUIC stream instead.
pub fn encode_path_probe_response(
    server_ip: &str,
    observed_ip: &str,
    observed_port: u32,
) -> Vec<u8> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let msg = build_path_probe_response(server_ip, observed_ip, observed_port, now_ms);
    msg.to_bytes()
}

/// Configuration for the QUIC path probing listener.
#[derive(Debug, Clone)]
pub struct QuicProbeConfig {
    /// The list of server IPs to listen on for QUIC connections.
    pub server_ips: Vec<String>,
    /// The QUIC listen port (default: 443).
    pub port: u16,
    /// Maximum concurrent QUIC connections per IP.
    pub max_connections: u32,
}

impl Default for QuicProbeConfig {
    fn default() -> Self {
        Self {
            server_ips: Vec::new(),
            port: 443,
            max_connections: 100,
        }
    }
}

/// A QUIC path probing server stub.
///
/// In production, this would:
/// 1. Create a `quinn::Endpoint` for each server IP
/// 2. Accept QUIC connections
/// 3. Monitor connection migration events
/// 4. When a client migrates to a new path, observe the new source IP:port
/// 5. Send PathProbeResponse (0x0200) on a QUIC stream with the observed address
///
/// The actual QUIC listener requires quinn + rustls with self-signed certs
/// and will be wired up when the voip-client crate implements path probing.
pub struct QuicProbeServer {
    config: QuicProbeConfig,
}

impl QuicProbeServer {
    /// Create a new QUIC probe server with the given configuration.
    pub fn new(config: QuicProbeConfig) -> Self {
        Self { config }
    }

    /// Start the QUIC probe server (stub — logs readiness but does not bind).
    ///
    /// In production, this would:
    /// ```ignore
    /// let cert = rcgen::generate_simple_self_signed([...])?;
    /// let rustls_cfg = quinn::ServerConfig::with_crypto(Arc::new(cert));
    /// for ip in &self.config.server_ips {
    ///     let addr = format!("{}:{}", ip, self.config.port);
    ///     let endpoint = quinn::Endpoint::server(rustls_cfg.clone(), addr.parse()?)?;
    ///     tokio::spawn(accept_loop(endpoint));
    /// }
    /// ```
    pub async fn start(&self) -> Result<(), QuicProbeError> {
        info!(
            ips = ?self.config.server_ips,
            port = self.config.port,
            max_connections = self.config.max_connections,
            "QUIC path probing server stub — 5 IPs configured. \
             Actual quinn listener will be initialized when voip-client is ready."
        );

        // Stub: no actual QUIC listener is bound yet.
        // When quinn is wired up, this function will:
        //   1. Generate self-signed TLS certificate (rcgen)
        //   2. Create quinn::ServerConfig with rustls
        //   3. Bind a quinn::Endpoint on each server_ip:port
        //   4. For each incoming connection:
        //      a. Accept the connection
        //      b. Wait for connection migration (PATH_CHALLENGE from client)
        //      c. On migration, observe new source IP:port
        //      d. Open a QUIC stream and send PathProbeResponse
        //      e. The client uses 5 observed addresses to classify NAT

        for ip in &self.config.server_ips {
            info!(
                ip,
                port = self.config.port,
                "QUIC probe listener stub: would bind on this address"
            );
        }

        Ok(())
    }
}

/// Errors from the QUIC path probing server.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum QuicProbeError {
    #[error("QUIC bind failed: {0}")]
    BindFailed(String),

    #[error("TLS configuration error: {0}")]
    TlsError(String),

    #[error("QUIC connection error: {0}")]
    ConnectionError(String),
}

/// Handle a QUIC connection migration event (production stub).
///
/// When a client migrates its QUIC connection to a new server IP,
/// this function is called to reflect the observed address back to
/// the client as a PathProbeResponse.
///
/// In production, this would be called from the quinn accept loop
/// when a connection's remote address changes.
#[allow(dead_code)]
pub fn handle_path_migration(
    server_ip: &str,
    observed_addr: SocketAddr,
) -> Vec<u8> {
    let observed_ip = observed_addr.ip().to_string();
    let observed_port = observed_addr.port() as u32;

    info!(
        server_ip,
        observed_ip = %observed_ip,
        observed_port,
        "QUIC path migration detected — building PathProbeResponse"
    );

    encode_path_probe_response(server_ip, &observed_ip, observed_port)
}
