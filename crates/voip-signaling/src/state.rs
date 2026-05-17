//! Server-side in-memory state.
//!
//! Holds the connected peers registry, active calls registry,
//! rate-limiting state, MASQUE proxy coordination data,
//! server Ed25519 signing key, and DHT bootstrap nodes.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use prost::Message;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info};

use crate::error::SignalingError;
use crate::rate_limit::{RateLimitConfig, RateLimiter};
use voip_core::VoIPConfig;

// ── Wire type IDs (2-byte prefix, big-endian) ──────────────────────────
// See spec/08 §8.1.1

pub mod type_id {
    pub const CALL_REQUEST_CS: u16 = 0x0001; // Client → Server
    pub const CALL_REQUEST_SC: u16 = 0x0002; // Server → Client (forwarded)
    pub const CALL_ACCEPT_CS: u16 = 0x0003;
    pub const CALL_ACCEPT_SC: u16 = 0x0004;
    pub const CALL_REJECT_CS: u16 = 0x0005;
    pub const CALL_REJECT_SC: u16 = 0x0006;
    pub const CALL_FAILED: u16 = 0x0007; // Either direction
    pub const CALL_ENDED: u16 = 0x0008; // Either direction
    #[allow(dead_code)]
    pub const PUSH_RETRY: u16 = 0x0009; // Server → Client
    pub const PEER_REGISTER: u16 = 0x0100; // Client → Server
    pub const PEER_UNREGISTER: u16 = 0x0101; // Client → Server
    #[allow(dead_code)]
    pub const PATH_PROBE_RESPONSE: u16 = 0x0200; // Server → Client (QUIC stream)
    pub const MASQUE_RELAY_NEEDED: u16 = 0x0300; // Server → Client
    pub const ERROR: u16 = 0x8001; // Server → Client
}

// ── Framed message (2-byte type + prost payload) ───────────────────────

/// A framed message ready to be sent over the WebSocket.
/// Wire format: `[type_id: u16 BE][prost payload]`
#[derive(Debug, Clone)]
pub struct FramedMessage {
    pub type_id: u16,
    pub payload: Vec<u8>,
}

impl FramedMessage {
    /// Encode into the wire format: 2-byte big-endian type ID + prost payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_message(self.type_id, &self.payload)
    }

    /// Decode a framed message from the wire format.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let (type_id, payload) = decode_message(data).ok()?;
        Some(Self { type_id, payload })
    }

    /// Build an Error framed message to send to a client.
    pub fn error(code: u32, message: impl Into<String>) -> Self {
        let payload = voip_core::proto::signaling::Error {
            code,
            message: message.into(),
        }
        .encode_to_vec();
        Self {
            type_id: type_id::ERROR,
            payload,
        }
    }
}

// ── Channel sender to push messages into a session ─────────────────────

/// Handle used by the server state to push framed messages into a
/// connected peer's WebSocket session task.
pub type SessionSender = mpsc::Sender<FramedMessage>;

// ── Peer entry ─────────────────────────────────────────────────────────

/// Information kept about each registered / connected peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub display_name: String,
    pub ipv6_addresses: Vec<String>,
    pub ipv4_reflexive: Vec<String>,
    pub nat_type: i32, // NATType enum value
    pub status: i32,   // PeerStatus enum value
    pub fcm_token: Option<String>,
    pub last_seen: u64,
}

/// A connected peer: their info + a channel to send WS messages.
#[derive(Debug)]
pub struct PeerEntry {
    pub info: PeerInfo,
    /// Channel to push framed messages into the session task.
    /// `None` if the peer is registered via REST but not WebSocket-connected.
    pub sender: Option<SessionSender>,
}

// ── Call entry ─────────────────────────────────────────────────────────

/// In-memory state for an active call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEntry {
    pub call_id: String,
    pub caller_id: String,
    pub callee_id: String,
    /// CallState enum value.
    pub state: i32,
    /// ConnectionMethod enum value.
    pub connection_method: i32,
    /// DiscoveryMethod enum value.
    pub discovery_method: i32,
    pub created_at: u64,
    pub connected_at: Option<u64>,
    pub ended_at: Option<u64>,
    pub failure_reason: Option<String>,
    pub retry_count: u32,
}

// ── MASQUE proxy record ────────────────────────────────────────────────

/// A known MASQUE proxy (served by `GET /v1/proxies`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyInfo {
    pub node_id: String,
    pub proxy_url: String,
    pub capacity: u32,
    pub region: String,
    pub latency_hint_ms: u32,
}

// ── Shared application state ───────────────────────────────────────────

/// The shared state accessible from all handlers and sessions.
#[derive(Debug, Clone)]
pub struct AppState {
    pub inner: Arc<InnerState>,
}

#[derive(Debug)]
pub struct InnerState {
    /// Connected / registered peers.
    pub peers: RwLock<HashMap<String, PeerEntry>>,
    /// Active calls.
    pub calls: RwLock<HashMap<String, CallEntry>>,
    /// Rate limiter.
    pub rate_limiter: RateLimiter,
    /// Known MASQUE proxies.
    pub proxies: RwLock<Vec<ProxyInfo>>,
    /// Signaling server elastic IPs for QUIC path probing.
    #[allow(dead_code)]
    pub server_ips: Vec<String>,
    /// Server Ed25519 signing key for JWT.
    pub signing_key: SigningKey,
    /// VoIP configuration.
    pub config: VoIPConfig,
    /// DHT bootstrap node multiaddresses.
    pub dht_bootstrap: RwLock<Vec<String>>,
}

impl AppState {
    /// Create a new `AppState` with the given rate-limit config, server IPs,
    /// signing key, and VoIP config.
    pub fn new(
        rate_limit_config: RateLimitConfig,
        server_ips: Vec<String>,
        signing_key: SigningKey,
        config: VoIPConfig,
    ) -> Self {
        let dht_nodes = config.dht_bootstrap_nodes.clone();
        Self {
            inner: Arc::new(InnerState {
                peers: RwLock::new(HashMap::new()),
                calls: RwLock::new(HashMap::new()),
                rate_limiter: RateLimiter::new(rate_limit_config),
                proxies: RwLock::new(Vec::new()),
                server_ips,
                signing_key,
                config,
                dht_bootstrap: RwLock::new(dht_nodes),
            }),
        }
    }

    /// Return the server's verifying key (public key).
    pub fn verifying_key(&self) -> VerifyingKey {
        self.inner.signing_key.verifying_key()
    }

    // ── Peer operations ────────────────────────────────────────────────

    /// Register a peer. If the peer already exists, update their info.
    /// If `sender` is provided, the peer is WebSocket-connected.
    pub async fn register_peer(
        &self,
        info: PeerInfo,
        sender: Option<SessionSender>,
    ) -> crate::error::Result<()> {
        let peer_id = info.peer_id.clone();
        let mut peers = self.inner.peers.write().await;

        if let Some(existing) = peers.get_mut(&peer_id) {
            info!(
                peer_id = %peer_id,
                "peer re-registered / updated"
            );
            existing.info = info;
            if sender.is_some() {
                existing.sender = sender;
            }
        } else {
            info!(peer_id = %peer_id, "peer registered");
            peers.insert(
                peer_id.clone(),
                PeerEntry { info, sender },
            );
        }
        Ok(())
    }

    /// Unregister a peer (DELETE /v1/peers/{peer_id} or PeerUnregister message).
    pub async fn unregister_peer(&self, peer_id: &str) -> crate::error::Result<()> {
        let mut peers = self.inner.peers.write().await;
        if peers.remove(peer_id).is_some() {
            info!(peer_id, "peer unregistered");
            self.inner.rate_limiter.remove_peer(peer_id).await;
        }
        Ok(())
    }

    /// Disconnect a peer's WebSocket session (remove sender, mark offline).
    pub async fn disconnect_peer(&self, peer_id: &str) {
        let mut peers = self.inner.peers.write().await;
        if let Some(entry) = peers.get_mut(peer_id) {
            entry.sender = None;
            entry.info.status = 1; // PEER_OFFLINE
            info!(peer_id, "peer WebSocket disconnected, marked offline");
        } else {
            debug!(peer_id, "peer disconnect but not found in registry");
        }
        self.inner.rate_limiter.remove_peer(peer_id).await;
    }

    /// Look up a peer by peer_id. Returns a clone of the info.
    pub async fn get_peer(&self, peer_id: &str) -> Option<PeerInfo> {
        let peers = self.inner.peers.read().await;
        peers.get(peer_id).map(|e| e.info.clone())
    }

    /// Send a framed message to a connected peer's WebSocket session.
    /// Returns `Err` if the peer is not connected or the send fails.
    pub async fn send_to_peer(
        &self,
        peer_id: &str,
        msg: FramedMessage,
    ) -> crate::error::Result<()> {
        let peers = self.inner.peers.read().await;
        let entry = peers
            .get(peer_id)
            .ok_or_else(|| SignalingError::UnknownPeer(peer_id.to_owned()))?;

        let sender = entry
            .sender
            .as_ref()
            .ok_or_else(|| SignalingError::PeerOffline(peer_id.to_owned()))?;

        sender
            .send(msg)
            .await
            .map_err(|_| SignalingError::PeerOffline(peer_id.to_owned()))?;
        Ok(())
    }

    // ── Call operations ────────────────────────────────────────────────

    /// Create a new call entry. Fails if the call_id already exists or
    /// either peer is unknown.
    pub async fn create_call(&self, call: CallEntry) -> crate::error::Result<()> {
        // Validate caller and callee exist
        {
            let peers = self.inner.peers.read().await;
            if !peers.contains_key(&call.caller_id) {
                return Err(SignalingError::UnknownPeer(call.caller_id.clone()));
            }
            if !peers.contains_key(&call.callee_id) {
                return Err(SignalingError::UnknownPeer(call.callee_id.clone()));
            }
        }

        let mut calls = self.inner.calls.write().await;
        if calls.contains_key(&call.call_id) {
            return Err(SignalingError::CallAlreadyExists(call.call_id.clone()));
        }
        info!(call_id = %call.call_id, caller = %call.caller_id, callee = %call.callee_id, "call created");
        calls.insert(call.call_id.clone(), call);
        Ok(())
    }

    /// Update a call's state.
    pub async fn update_call_state(
        &self,
        call_id: &str,
        new_state: i32,
    ) -> crate::error::Result<()> {
        let mut calls = self.inner.calls.write().await;
        let call = calls
            .get_mut(call_id)
            .ok_or_else(|| SignalingError::InvalidCallId(call_id.to_owned()))?;
        call.state = new_state;
        debug!(call_id, new_state, "call state updated");
        Ok(())
    }

    /// End a call: set state to ENDED and record end time.
    pub async fn end_call(
        &self,
        call_id: &str,
        reason: Option<String>,
    ) -> crate::error::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut calls = self.inner.calls.write().await;
        let call = calls
            .get_mut(call_id)
            .ok_or_else(|| SignalingError::InvalidCallId(call_id.to_owned()))?;
        call.state = 4; // CALL_ENDED
        call.ended_at = Some(now);
        call.failure_reason = reason;
        debug!(call_id, "call ended");
        Ok(())
    }

    /// Remove a call from the active calls registry.
    pub async fn remove_call(&self, call_id: &str) {
        let mut calls = self.inner.calls.write().await;
        if calls.remove(call_id).is_some() {
            debug!(call_id, "call removed from registry");
        }
    }

    /// Get a call by ID.
    pub async fn get_call(&self, call_id: &str) -> Option<CallEntry> {
        let calls = self.inner.calls.read().await;
        calls.get(call_id).cloned()
    }

    // ── MASQUE proxy operations ────────────────────────────────────────

    /// Get the list of known MASQUE proxies.
    pub async fn get_proxies(&self) -> Vec<ProxyInfo> {
        self.inner.proxies.read().await.clone()
    }

    /// Add a MASQUE proxy to the known list.
    #[allow(dead_code)]
    pub async fn add_proxy(&self, proxy: ProxyInfo) {
        self.inner.proxies.write().await.push(proxy);
    }

    /// Coordinate MASQUE relay: when both peers need a relay, send
    /// MasqueRelayNeeded to both peers.
    pub async fn coordinate_masque_relay(
        &self,
        call_id: &str,
        caller_id: &str,
        callee_id: &str,
    ) -> crate::error::Result<()> {
        crate::masque::send_relay_needed(self, call_id, caller_id, callee_id).await
    }

    // ── DHT bootstrap ─────────────────────────────────────────────────

    /// Get the list of DHT bootstrap node multiaddresses.
    pub async fn get_dht_bootstrap(&self) -> Vec<String> {
        self.inner.dht_bootstrap.read().await.clone()
    }

    // ── Utility ────────────────────────────────────────────────────────

    /// Return the list of signaling server IPs for QUIC path probing.
    #[allow(dead_code)]
    pub fn server_ips(&self) -> &[String] {
        &self.inner.server_ips
    }
}

/// Helper: get current unix timestamp in seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Standalone encode / decode functions ───────────────────────────────

/// Encode a message into the wire format: 2-byte big-endian type ID + prost payload.
///
/// This is the canonical framing function used by `FramedMessage::to_bytes`
/// and can also be used directly for constructing raw framed messages
/// (e.g., PathProbeResponse on QUIC streams).
pub fn encode_message(type_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + payload.len());
    buf.extend_from_slice(&type_id.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Decode a framed message from the wire format.
///
/// Returns `(type_id, payload)` on success, or a `SignalingError` if the
/// input is too short (fewer than 2 bytes for the type prefix).
pub fn decode_message(data: &[u8]) -> Result<(u16, Vec<u8>), SignalingError> {
    if data.len() < 2 {
        return Err(SignalingError::InvalidMessage(
            "message too short: need at least 2 bytes for type ID".to_owned(),
        ));
    }
    let type_id = u16::from_be_bytes([data[0], data[1]]);
    let payload = data[2..].to_vec();
    Ok((type_id, payload))
}

/// Extract the client's IP address from the connection info.
/// Used by `GET /v1/myip`.
pub fn extract_client_ip(addr: SocketAddr) -> (String, u16, u8) {
    let ip_str = addr.ip().to_string();
    let version = if addr.is_ipv6() { 6 } else { 4 };
    (ip_str, addr.port(), version)
}
