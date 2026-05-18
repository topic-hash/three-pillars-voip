//! Main connection manager implementing the full fallback chain.
//!
//! Implements the decision tree from spec/09 §9.9:
//!
//! ```text
//! IPv6 Direct → QUIC Simultaneous Open (Cone NAT) →
//! QUIC Port Prediction (Symmetric NAT) →
//! MASQUE/HTTP3 → MASQUE/HTTP2 → Push Retry
//! ```
//!
//! The connection manager:
//! - Takes NAT info from both peers
//! - Decides which method to try based on the decision tree
//! - Manages the QUIC connection lifecycle
//! - Reports ConnectionMethod on success, or CallEndReason on failure

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use voip_core::proto::signaling::{NatInfo as ProtoNatInfo, PeerRecord, ProxyRecord};
use voip_core::{
    CallEndReason, ConnectionMethod, NATInfo, NATType,
    VoIPConfig,
};

use crate::error::ConnectError;
use crate::masque::MasqueTunnel;
use crate::migration::ConnectionMigrator;
use crate::nat_probe::NATProber;
use crate::probe::PortPredictionProber;

/// Helper: extract NATInfo from an optional proto NatInfo.
fn proto_nat_info_to_native(proto: Option<&ProtoNatInfo>) -> NATInfo {
    proto
        .map(|n| NATInfo::from(n.clone()))
        .unwrap_or(NATInfo::no_nat())
}

/// The established VoIP connection, wrapping a QUIC connection and metadata.
pub struct VoipConnection {
    /// The underlying QUIC connection
    pub quic_connection: Connection,
    /// How the connection was established
    pub method: ConnectionMethod,
    /// Optional MASQUE tunnel (if connection is relayed)
    pub masque_tunnel: Option<MasqueTunnel>,
}

impl VoipConnection {
    /// Create a direct P2P connection wrapper.
    pub fn new_direct(connection: Connection, method: ConnectionMethod) -> Self {
        Self {
            quic_connection: connection,
            method,
            masque_tunnel: None,
        }
    }

    /// Create a MASQUE-relayed connection.
    pub fn new_masque(connection: Connection, method: ConnectionMethod, tunnel: MasqueTunnel) -> Self {
        Self {
            quic_connection: connection,
            method,
            masque_tunnel: Some(tunnel),
        }
    }

    /// Open a bidirectional QUIC stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), ConnectError> {
        self.quic_connection
            .open_bi()
            .await
            .map_err(ConnectError::QuicError)
    }

    /// Accept a bidirectional QUIC stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), ConnectError> {
        self.quic_connection
            .accept_bi()
            .await
            .map_err(ConnectError::QuicError)
    }

    /// Get the remote address of the peer.
    pub fn remote_address(&self) -> SocketAddr {
        self.quic_connection.remote_address()
    }

    /// Close the connection.
    pub async fn close(&self, code: u64, reason: &str) {
        self.quic_connection.close(VarInt::from_u64(code).unwrap_or(VarInt::MAX), reason.as_bytes());
    }
}

/// The main connection manager that implements the fallback chain.
pub struct ConnectionManager {
    /// QUIC endpoint for outgoing connections
    endpoint: Endpoint,
    /// Configuration
    config: Arc<VoIPConfig>,
    /// NAT prober for classifying local NAT
    nat_prober: Arc<RwLock<Option<NATProber>>>,
    /// Port prediction prober
    prediction_prober: PortPredictionProber,
    /// Connection migrator for handling network changes
    migrator: ConnectionMigrator,
    /// Local NAT info (cached)
    local_nat_info: Arc<RwLock<Option<NATInfo>>>,
    /// Whether UDP is blocked
    udp_blocked: Arc<RwLock<bool>>,
}

impl ConnectionManager {
    /// Create a new ConnectionManager.
    pub fn new(config: Arc<VoIPConfig>) -> Result<Self, ConnectError> {
        let endpoint = Self::create_endpoint()?;

        Ok(Self {
            endpoint,
            config: config.clone(),
            nat_prober: Arc::new(RwLock::new(None)),
            prediction_prober: PortPredictionProber::new(config.clone()),
            migrator: ConnectionMigrator::new(config),
            local_nat_info: Arc::new(RwLock::new(None)),
            udp_blocked: Arc::new(RwLock::new(false)),
        })
    }

    /// Create a ConnectionManager with an existing QUIC endpoint.
    pub fn with_endpoint(endpoint: Endpoint, config: Arc<VoIPConfig>) -> Self {
        Self {
            endpoint,
            prediction_prober: PortPredictionProber::new(config.clone()),
            migrator: ConnectionMigrator::new(config.clone()),
            config: config,
            nat_prober: Arc::new(RwLock::new(None)),
            local_nat_info: Arc::new(RwLock::new(None)),
            udp_blocked: Arc::new(RwLock::new(false)),
        }
    }

    /// Set the NAT prober (called after signaling server connection is established).
    pub async fn set_nat_prober(&self, prober: NATProber) {
        let nat_info = prober.cached_nat_info().await;
        *self.local_nat_info.write().await = nat_info;
        *self.nat_prober.write().await = Some(prober);
    }

    /// Set the local NAT info directly.
    pub async fn set_local_nat_info(&self, info: NATInfo) {
        *self.local_nat_info.write().await = Some(info);
    }

    /// Get the local NAT info.
    pub async fn local_nat_info(&self) -> Option<NATInfo> {
        self.local_nat_info.read().await.clone()
    }

    /// Set whether UDP is blocked.
    pub async fn set_udp_blocked(&self, blocked: bool) {
        *self.udp_blocked.write().await = blocked;
    }

    /// Probe the local NAT via QUIC path probing.
    pub async fn probe_nat(&self) -> Result<NATInfo, ConnectError> {
        let prober = self.nat_prober.read().await;
        if let Some(prober) = prober.as_ref() {
            let result = prober.probe().await.map_err(|e| ConnectError::NatProbeFailed(e.to_string()))?;
            *self.local_nat_info.write().await = Some(result.clone());
            Ok(result)
        } else {
            Err(ConnectError::NatProbeFailed(
                "NAT prober not initialized (no signaling server connection)".to_string(),
            ))
        }
    }

    /// Establish a connection to a peer, trying the full fallback chain.
    ///
    /// This implements the decision tree from spec/09 §9.9.
    #[instrument(skip(self, peer, proxy_records), fields(peer_id = %peer.peer_id))]
    pub async fn establish_connection(
        &self,
        peer: &PeerRecord,
        connection_id: &[u8],
        proxy_records: &[ProxyRecord],
    ) -> Result<VoipConnection, ConnectError> {
        let local_nat = self.local_nat_info.read().await.clone();
        let udp_blocked = *self.udp_blocked.read().await;

        let peer_nat = proto_nat_info_to_native(peer.nat_info.as_ref());

        info!(
            local_nat = ?local_nat.as_ref().map(|n| n.nat_type),
            peer_nat = ?peer_nat.nat_type,
            udp_blocked,
            "Starting connection establishment"
        );

        // Step 1: IPv6 Direct
        // If both peers have IPv6 addresses, try direct connection first.
        if !peer.ipv6_addresses.is_empty() && !udp_blocked {
            if let Some(conn) = self.try_ipv6_direct(peer).await {
                info!(method = ?ConnectionMethod::Ipv6Direct, "Connected via IPv6 Direct");
                return Ok(conn);
            }
        }

        // Mixed IPv6 + IPv4: if one side has IPv6 and the other has IPv4,
        // the IPv6 side connects to the IPv4 peer via the IPv4 path.
        // (The decision tree says "YES → IPv6 + IPv4 mixed" but this
        // reduces to the IPv4 path for the side that has it.)

        // Step 2: QUIC Simultaneous Open (Cone NAT)
        // If at least one peer has Cone NAT, QUIC simultaneous open works.
        let local_has_cone = local_nat
            .as_ref()
            .map(|n| n.nat_type == NATType::Cone)
            .unwrap_or(false);
        let peer_has_cone = peer_nat.nat_type == NATType::Cone;

        if (local_has_cone || peer_has_cone) && !udp_blocked {
            if let Some(conn) = self.try_simultaneous_open(peer, connection_id).await {
                info!(method = ?ConnectionMethod::Ipv4Cone, "Connected via QUIC Simultaneous Open");
                return Ok(conn);
            }
        }

        // Step 3: QUIC Port Prediction (Symmetric NAT)
        // If both have predictable (sequential/pseudo) NAT, try port prediction.
        let local_predictable = local_nat
            .as_ref()
            .map(|n| n.nat_type.is_predictable())
            .unwrap_or(false);
        let peer_predictable = peer_nat.nat_type.is_predictable();

        if (local_predictable || peer_predictable) && !udp_blocked {
            if let Some(conn) = self
                .try_port_prediction(peer, &local_nat, connection_id)
                .await
            {
                info!(method = ?ConnectionMethod::Ipv4Prediction, "Connected via QUIC Port Prediction");
                return Ok(conn);
            }
        }

        // Step 4: MASQUE over HTTP/3 (UDP available)
        if self.config.masque_fallback_enabled && !proxy_records.is_empty() {
            if !udp_blocked {
                if let Ok(tunnel) = self
                    .try_masque_http3(proxy_records, connection_id)
                    .await
                {
                    info!(method = ?ConnectionMethod::Masque, "Connected via MASQUE/HTTP3");
                    // The QUIC connection through the tunnel wraps MoQ
                    let conn = tunnel.quic_connection().clone();
                    return Ok(VoipConnection::new_masque(
                        conn,
                        ConnectionMethod::Masque,
                        tunnel,
                    ));
                }
            }

            // Step 5: MASQUE over HTTP/2 (UDP blocked)
            if let Ok(tunnel) = self.try_masque_http2(proxy_records, connection_id).await {
                info!(method = ?ConnectionMethod::MasqueHttp2, "Connected via MASQUE/HTTP2");
                let conn = tunnel.quic_connection().clone();
                return Ok(VoipConnection::new_masque(
                    conn,
                    ConnectionMethod::MasqueHttp2,
                    tunnel,
                ));
            }
        }

        // Step 6: All methods failed — Push Retry
        // Determine the appropriate failure reason
        let reason = if udp_blocked {
            CallEndReason::FailedUdpBlocked
        } else {
            let local_random = local_nat
                .as_ref()
                .map(|n| n.nat_type == NATType::SymmetricRandom)
                .unwrap_or(false);
            let peer_random = peer_nat.nat_type == NATType::SymmetricRandom;

            if local_random && peer_random {
                CallEndReason::FailedIpv4Random
            } else if proxy_records.is_empty() {
                CallEndReason::FailedMasqueUnreachable
            } else {
                CallEndReason::FailedNetwork
            }
        };

        warn!(reason = ?reason, "All connection methods failed");
        Err(ConnectError::AllMethodsFailed)
    }

    /// Step 1: Try IPv6 direct connection.
    ///
    /// Both peers must have IPv6 addresses. The QUIC endpoint will use
    /// Happy Eyeballs v2 (built into quinn) to try IPv6 first.
    async fn try_ipv6_direct(&self, peer: &PeerRecord) -> Option<VoipConnection> {
        for addr_str in &peer.ipv6_addresses {
            match addr_str.parse::<SocketAddr>() {
                Ok(addr) => {
                    match self
                        .try_quic_connect(addr, self.config.quic_connect_timeout_ms)
                        .await
                    {
                        Ok(conn) => {
                            return Some(VoipConnection::new_direct(
                                conn,
                                ConnectionMethod::Ipv6Direct,
                            ))
                        }
                        Err(e) => {
                            debug!(addr = %addr, error = %e, "IPv6 direct connection failed");
                        }
                    }
                }
                Err(e) => {
                    debug!(addr = %addr_str, error = %e, "Invalid IPv6 address");
                }
            }
        }
        None
    }

    /// Step 2: Try QUIC simultaneous open (Cone NAT).
    ///
    /// Per spec/09 §9.2: Both peers send QUIC PATH_CHALLENGE to each other's
    /// reflexive addresses. Cone NAT allows inbound from any destination,
    /// so the PATH_CHALLENGE arrives and the peer responds.
    async fn try_simultaneous_open(
        &self,
        peer: &PeerRecord,
        _connection_id: &[u8],
    ) -> Option<VoipConnection> {
        for addr_str in &peer.ipv4_reflexive {
            match addr_str.parse::<SocketAddr>() {
                Ok(addr) => {
                    // Attempt QUIC connection to the peer's reflexive address
                    // using the pre-agreed Connection ID
                    match self
                        .try_quic_connect(addr, self.config.quic_connect_timeout_ms)
                        .await
                    {
                        Ok(conn) => {
                            info!(
                                addr = %addr,
                                "QUIC simultaneous open succeeded (Cone NAT)"
                            );
                            return Some(VoipConnection::new_direct(
                                conn,
                                ConnectionMethod::Ipv4Cone,
                            ));
                        }
                        Err(e) => {
                            debug!(
                                addr = %addr,
                                error = %e,
                                "QUIC simultaneous open failed for address"
                            );
                        }
                    }
                }
                Err(e) => {
                    debug!(addr = %addr_str, error = %e, "Invalid IPv4 reflexive address");
                }
            }
        }
        None
    }

    /// Step 3: Try QUIC port prediction (Symmetric NAT).
    ///
    /// Per spec/09 §9.3: Send QUIC PATH_CHALLENGE to the peer's predicted
    /// port range. If the peer's NAT assigned a port in our predicted range,
    /// the PATH_CHALLENGE arrives and the connection is established.
    async fn try_port_prediction(
        &self,
        peer: &PeerRecord,
        local_nat: &Option<NATInfo>,
        connection_id: &[u8],
    ) -> Option<VoipConnection> {
        let peer_nat = proto_nat_info_to_native(peer.nat_info.as_ref());

        // We need at least one peer with prediction data
        let peer_prediction = peer_nat.prediction.as_ref();
        let local_prediction = local_nat.as_ref().and_then(|n| n.prediction.as_ref());

        if peer_prediction.is_none() && local_prediction.is_none() {
            return None;
        }

        // Try connecting to the peer's predicted port range
        if let Some(prediction) = peer_prediction {
            let ip = &prediction.external_ip;
            let start = prediction.predicted_port_start as u16;
            let end = prediction.predicted_port_end as u16;

            debug!(
                ip = %ip,
                port_start = start,
                port_end = end,
                confidence = ?prediction.confidence,
                "Attempting port prediction to peer"
            );

            match self
                .prediction_prober
                .probe_range(
                    &self.endpoint,
                    ip,
                    start,
                    end,
                    connection_id,
                    self.config.quic_prediction_timeout_ms,
                )
                .await
            {
                Ok(conn) => {
                    info!("Port prediction succeeded");
                    return Some(VoipConnection::new_direct(
                        conn,
                        ConnectionMethod::Ipv4Prediction,
                    ));
                }
                Err(e) => {
                    debug!(error = %e, "Port prediction to peer failed");
                }
            }
        }

        None
    }

    /// Step 4: Try MASQUE CONNECT-UDP via HTTP/3.
    async fn try_masque_http3(
        &self,
        proxy_records: &[ProxyRecord],
        connection_id: &[u8],
    ) -> Result<MasqueTunnel, ConnectError> {
        // Convert connection_id to call_id string for MASQUE coordination
        let call_id = hex::encode(connection_id);

        for proxy in proxy_records.iter().take(self.config.masque_max_proxy_attempts as usize) {
            match MasqueTunnel::connect_http3(&proxy.proxy_url, &call_id).await {
                Ok(tunnel) => {
                    info!(proxy_url = %proxy.proxy_url, "MASQUE HTTP/3 tunnel established");
                    return Ok(tunnel);
                }
                Err(e) => {
                    warn!(proxy_url = %proxy.proxy_url, error = %e, "MASQUE HTTP/3 failed");
                }
            }
        }
        Err(ConnectError::MasqueUnreachable)
    }

    /// Step 5: Try MASQUE CONNECT-UDP via HTTP/2.
    async fn try_masque_http2(
        &self,
        proxy_records: &[ProxyRecord],
        connection_id: &[u8],
    ) -> Result<MasqueTunnel, ConnectError> {
        let call_id = hex::encode(connection_id);

        for proxy in proxy_records.iter().take(self.config.masque_max_proxy_attempts as usize) {
            match MasqueTunnel::connect_http2(&proxy.proxy_url, &call_id).await {
                Ok(tunnel) => {
                    info!(proxy_url = %proxy.proxy_url, "MASQUE HTTP/2 tunnel established");
                    return Ok(tunnel);
                }
                Err(e) => {
                    warn!(proxy_url = %proxy.proxy_url, error = %e, "MASQUE HTTP/2 failed");
                }
            }
        }
        Err(ConnectError::MasqueUnreachable)
    }

    /// Attempt a QUIC connection to the given address with a timeout.
    async fn try_quic_connect(
        &self,
        addr: SocketAddr,
        timeout_ms: u64,
    ) -> Result<Connection, ConnectError> {
        let server_name = "voip-peer"; // QUIC server name for TLS SNI
        let connect_timeout = Duration::from_millis(timeout_ms);

        let connecting = self
            .endpoint
            .connect(addr, server_name)
            .map_err(|e| ConnectError::NetworkError(e.to_string()))?;

        let connection = tokio::time::timeout(connect_timeout, connecting)
            .await
            .map_err(|_| ConnectError::QuicTimeout(timeout_ms))?
            .map_err(ConnectError::QuicError)?;

        Ok(connection)
    }

    /// Create a QUIC endpoint for outgoing connections.
    fn create_endpoint() -> Result<Endpoint, ConnectError> {
        let client_config = crate::tls::dangerous_quinn_client_config()
            .map_err(|e| ConnectError::NetworkError(e))?;

        let mut endpoint = Endpoint::client("[::]:0".parse().unwrap())
            .map_err(|e| ConnectError::NetworkError(e.to_string()))?;
        endpoint.set_default_client_config(client_config);

        Ok(endpoint)
    }

    /// Get the QUIC endpoint reference.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Get the connection migrator.
    pub fn migrator(&self) -> &ConnectionMigrator {
        &self.migrator
    }

    /// Re-probe NAT after a network change.
    pub async fn reprobe_nat(&self) -> Result<NATInfo, ConnectError> {
        let prober = self.nat_prober.read().await;
        if let Some(prober) = prober.as_ref() {
            prober.invalidate_cache().await;
            let result = prober.probe().await.map_err(|e| ConnectError::NatProbeFailed(e.to_string()))?;
            *self.local_nat_info.write().await = Some(result.clone());
            Ok(result)
        } else {
            Err(ConnectError::NatProbeFailed(
                "NAT prober not initialized".to_string(),
            ))
        }
    }
}

/// Hex encoding utility for connection IDs.
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }
}
