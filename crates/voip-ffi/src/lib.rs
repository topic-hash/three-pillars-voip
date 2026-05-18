//! # voip-ffi
//!
//! UniFFI bindings that expose a simplified API to Kotlin/Swift for the
//! Three Pillars VoIP project.
//!
//! Uses the UDL-based workflow: the `voip.udl` file defines the interface,
//! and `uniffi::uniffi_bindgen::generate_scaffolding` in `build.rs` generates
//! the FFI glue code.

use std::sync::Arc;
use tokio::sync::RwLock;

use voip_client::{client::Client, error::ClientError};
use voip_core::VoIPConfig;

// Include the auto-generated scaffolding from proc-macro approach.
// This generates the UniFfiTag type and FFI scaffolding functions.
uniffi::setup_scaffolding!("voip");

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// FFI-safe error type exposed to Kotlin/Swift.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum VoipError {
    NotInitialized,
    CallInProgress,
    NoActiveCall,
    ConnectionFailed(String),
    CallSetupTimeout(String),
    CallRejected(String),
    NatTraversalFailed(String),
    MasqueFailed(String),
    Internal(String),
}

impl std::fmt::Display for VoipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VoipError::NotInitialized => write!(f, "Client not initialized"),
            VoipError::CallInProgress => write!(f, "Call already in progress"),
            VoipError::NoActiveCall => write!(f, "No active call"),
            VoipError::ConnectionFailed(s) => write!(f, "Connection failed: {}", s),
            VoipError::CallSetupTimeout(s) => write!(f, "Call setup timeout: {}", s),
            VoipError::CallRejected(s) => write!(f, "Call rejected: {}", s),
            VoipError::NatTraversalFailed(s) => write!(f, "NAT traversal failed: {}", s),
            VoipError::MasqueFailed(s) => write!(f, "MASQUE relay failed: {}", s),
            VoipError::Internal(s) => write!(f, "Internal error: {}", s),
        }
    }
}

impl From<ClientError> for VoipError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::NotInitialized => VoipError::NotInitialized,
            ClientError::CallInProgress => VoipError::CallInProgress,
            ClientError::NoActiveCall => VoipError::NoActiveCall,
            ClientError::ConnectionFailed(s) => VoipError::ConnectionFailed(s),
            ClientError::CallSetupTimeout(s) => VoipError::CallSetupTimeout(s),
            ClientError::CallRejected(s) => VoipError::CallRejected(s),
            ClientError::NatTraversalFailed(s) => VoipError::NatTraversalFailed(s),
            ClientError::MasqueFailed(s) => VoipError::MasqueFailed(s),
            ClientError::Audio(s) => VoipError::Internal(s),
            ClientError::Core(e) => VoipError::Internal(e.to_string()),
            ClientError::AllMethodsFailed => VoipError::Internal("all connection methods failed".to_string()),
            ClientError::QuicTimeout(ms) => VoipError::CallSetupTimeout(format!("QUIC timeout after {}ms", ms)),
            ClientError::PredictionFailedRandom => VoipError::NatTraversalFailed("random NAT both sides".to_string()),
            ClientError::UdpBlocked => VoipError::ConnectionFailed("UDP blocked".to_string()),
            ClientError::TcpBlocked => VoipError::ConnectionFailed("TCP blocked".to_string()),
            ClientError::MasqueUnreachable => VoipError::MasqueFailed("proxy unreachable".to_string()),
            ClientError::MigrationFailed(s) => VoipError::ConnectionFailed(format!("migration: {}", s)),
            ClientError::NetworkError(s) => VoipError::ConnectionFailed(s),
            ClientError::SignalingError(s) => VoipError::ConnectionFailed(s),
            ClientError::PeerTimeout => VoipError::CallSetupTimeout("peer timeout".to_string()),
            ClientError::NatProbeError(s) => VoipError::NatTraversalFailed(s),
            ClientError::ProbeError(s) => VoipError::NatTraversalFailed(s),
            ClientError::AudioError(s) => VoipError::Internal(s),
            ClientError::MigrationTimeout(ms) => VoipError::ConnectionFailed(format!("migration timeout {}ms", ms)),
        }
    }
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CallState {
    Idle,
    Ringing,
    Incoming,
    Connected,
    Ended,
}

impl From<voip_client::client::CallState> for CallState {
    fn from(s: voip_client::client::CallState) -> Self {
        match s {
            voip_client::client::CallState::Idle => CallState::Idle,
            voip_client::client::CallState::Ringing => CallState::Ringing,
            voip_client::client::CallState::Incoming => CallState::Incoming,
            voip_client::client::CallState::Connected => CallState::Connected,
            voip_client::client::CallState::Ended => CallState::Ended,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectionMethod {
    None,
    Ipv6Direct,
    Ipv4Cone,
    Ipv4Prediction,
    Masque,
    MasqueHttp2,
}

impl From<voip_core::proto::signaling::ConnectionMethod> for ConnectionMethod {
    fn from(m: voip_core::proto::signaling::ConnectionMethod) -> Self {
        match m {
            voip_core::proto::signaling::ConnectionMethod::ConnNone => ConnectionMethod::None,
            voip_core::proto::signaling::ConnectionMethod::ConnIpv6Direct => ConnectionMethod::Ipv6Direct,
            voip_core::proto::signaling::ConnectionMethod::ConnIpv4Cone => ConnectionMethod::Ipv4Cone,
            voip_core::proto::signaling::ConnectionMethod::ConnIpv4Prediction => ConnectionMethod::Ipv4Prediction,
            voip_core::proto::signaling::ConnectionMethod::ConnMasque => ConnectionMethod::Masque,
            voip_core::proto::signaling::ConnectionMethod::ConnMasqueHttp2 => ConnectionMethod::MasqueHttp2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum NATType {
    None,
    Cone,
    SymmetricSequential,
    SymmetricPseudo,
    SymmetricRandom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DiscoveryMethod {
    Dht,
    Signaling,
    Cache,
}

// ---------------------------------------------------------------------------
// Records (dictionaries)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, uniffi::Record)]
pub struct VoipConfig {
    pub discovery_privacy_first: bool,
    pub dht_lookup_timeout_ms: u64,
    pub dht_bootstrap_nodes: Vec<String>,
    pub signaling_server_url: String,
    pub masque_fallback_enabled: bool,
    pub push_retry_enabled: bool,
    pub quic_connect_timeout_ms: u64,
    pub call_ring_timeout_ms: u64,
}

impl Default for VoipConfig {
    fn default() -> Self {
        Self::from(&VoIPConfig::default())
    }
}

impl VoipConfig {
    pub fn to_core_config(&self) -> VoIPConfig {
        let mut config = VoIPConfig::default();
        config.discovery_privacy_first = self.discovery_privacy_first;
        config.dht_lookup_timeout_ms = self.dht_lookup_timeout_ms;
        config.dht_bootstrap_nodes = self.dht_bootstrap_nodes.clone();
        config.masque_fallback_enabled = self.masque_fallback_enabled;
        config.push_retry_enabled = self.push_retry_enabled;
        config.quic_connect_timeout_ms = self.quic_connect_timeout_ms;
        config.call_ring_timeout_ms = self.call_ring_timeout_ms;
        config
    }
}

impl From<&VoIPConfig> for VoipConfig {
    fn from(c: &VoIPConfig) -> Self {
        Self {
            discovery_privacy_first: c.discovery_privacy_first,
            dht_lookup_timeout_ms: c.dht_lookup_timeout_ms,
            dht_bootstrap_nodes: c.dht_bootstrap_nodes.clone(),
            signaling_server_url: String::new(),
            masque_fallback_enabled: c.masque_fallback_enabled,
            push_retry_enabled: c.push_retry_enabled,
            quic_connect_timeout_ms: c.quic_connect_timeout_ms,
            call_ring_timeout_ms: c.call_ring_timeout_ms,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ConnectionInfo {
    pub method: ConnectionMethod,
    pub rtt_ms: u32,
    pub packet_loss_pct: f32,
    pub jitter_ms: u32,
    pub discovery_method: DiscoveryMethod,
}

impl From<voip_client::client::ConnectionInfo> for ConnectionInfo {
    fn from(info: voip_client::client::ConnectionInfo) -> Self {
        Self {
            method: info.method.into(),
            rtt_ms: info.rtt_ms,
            packet_loss_pct: info.packet_loss_pct,
            jitter_ms: info.jitter_ms,
            discovery_method: DiscoveryMethod::Dht,
        }
    }
}

#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct CallStats {
    pub duration_secs: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
}

impl From<voip_client::client::CallStats> for CallStats {
    fn from(s: voip_client::client::CallStats) -> Self {
        Self {
            duration_secs: s.duration_secs,
            bytes_sent: s.bytes_sent,
            bytes_received: s.bytes_received,
            packets_sent: s.packets_sent,
            packets_received: s.packets_received,
            packets_lost: s.packets_lost,
        }
    }
}

// ---------------------------------------------------------------------------
// Tokio runtime (shared across all FFI calls)
// ---------------------------------------------------------------------------

fn runtime() -> &'static tokio::runtime::Runtime {
    use once_cell::sync::Lazy;
    static RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime for VoIP FFI")
    });
    &RUNTIME
}

// ---------------------------------------------------------------------------
// VoipClient — main interface
// ---------------------------------------------------------------------------

#[derive(uniffi::Object)]
pub struct VoipClient {
    inner: Arc<RwLock<Option<Client>>>,
    config: VoipConfig,
}

#[uniffi::export]
impl VoipClient {
    #[uniffi::constructor]
    pub fn new(config: VoipConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
            config,
        }
    }

    pub fn init(&self) -> Result<(), VoipError> {
        let core_config = self.config.to_core_config();
        let client = Client::new(core_config);
        runtime().block_on(async {
            client.init().await?;
            let mut inner = self.inner.write().await;
            *inner = Some(client);
            Ok(())
        })
    }

    pub fn call(&self, peer_id: String) -> Result<(), VoipError> {
        runtime().block_on(async {
            let inner = self.inner.read().await;
            let client = inner.as_ref().ok_or(VoipError::NotInitialized)?;
            client.call(&peer_id).await?;
            Ok(())
        })
    }

    pub fn hangup(&self) -> Result<(), VoipError> {
        runtime().block_on(async {
            let inner = self.inner.read().await;
            let client = inner.as_ref().ok_or(VoipError::NotInitialized)?;
            client.hangup().await?;
            Ok(())
        })
    }

    pub fn mute(&self) -> Result<(), VoipError> {
        runtime().block_on(async {
            let inner = self.inner.read().await;
            let client = inner.as_ref().ok_or(VoipError::NotInitialized)?;
            client.mute().await?;
            Ok(())
        })
    }

    pub fn unmute(&self) -> Result<(), VoipError> {
        runtime().block_on(async {
            let inner = self.inner.read().await;
            let client = inner.as_ref().ok_or(VoipError::NotInitialized)?;
            client.unmute().await?;
            Ok(())
        })
    }

    pub fn get_call_state(&self) -> CallState {
        runtime().block_on(async {
            let inner = self.inner.read().await;
            if let Some(client) = inner.as_ref() {
                client.call_state().await.into()
            } else {
                CallState::Idle
            }
        })
    }

    pub fn get_connection_info(&self) -> Option<ConnectionInfo> {
        runtime().block_on(async {
            let inner = self.inner.read().await;
            if let Some(client) = inner.as_ref() {
                client.connection_info().await.map(ConnectionInfo::from)
            } else {
                None
            }
        })
    }

    pub fn get_call_stats(&self) -> CallStats {
        runtime().block_on(async {
            let inner = self.inner.read().await;
            if let Some(client) = inner.as_ref() {
                client.call_stats().await.into()
            } else {
                CallStats::default()
            }
        })
    }

    pub fn is_muted(&self) -> bool {
        runtime().block_on(async {
            let inner = self.inner.read().await;
            if let Some(client) = inner.as_ref() {
                client.is_muted().await
            } else {
                false
            }
        })
    }

    pub fn shutdown(&self) -> Result<(), VoipError> {
        runtime().block_on(async {
            let mut inner = self.inner.write().await;
            if let Some(client) = inner.take() {
                client.shutdown().await?;
            }
            Ok(())
        })
    }
}
