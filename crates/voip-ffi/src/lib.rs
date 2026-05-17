//! # voip-ffi
//!
//! UniFFI bindings that expose a simplified API to Kotlin/Swift for the
//! Three Pillars VoIP project.
//!
//! This crate implements the FFI interface described in `voip.udl` using
//! the UniFFI proc-macro approach (recommended for uniffi 0.28+). The UDL
//! file is provided as a reference specification and can also be used with
//! the `uniffi-bindgen` CLI for foreign binding generation.
//!
//! # Usage (Kotlin)
//!
//! ```kotlin
//! val config = VoipConfig(
//!     discoveryPrivacyFirst = true,
//!     dhtLookupTimeoutMs = 200,
//!     // ...
//! )
//! val client = VoipClient(config)
//! client.init()
//! client.call("peer-abc123")
//! ```
//!
//! # Usage (Swift)
//!
//! ```swift
//! let config = VoipConfig(
//!     discoveryPrivacyFirst: true,
//!     dhtLookupTimeoutMs: 200,
//!     // ...
//! )
//! let client = VoipClient(config: config)
//! try client.init()
//! try client.call(peerId: "peer-abc123")
//! ```
//!
//! # Generating Foreign Bindings
//!
//! ```bash
//! # Build the library
//! cargo build --release -p voip-ffi
//!
//! # Generate Kotlin bindings
//! uniffi-bindgen generate --library target/release/libvoip_ffi.so --language kotlin --out-dir bindings/kotlin
//!
//! # Generate Swift bindings
//! uniffi-bindgen generate --library target/release/libvoip_ffi.so --language swift --out-dir bindings/swift
//! ```

use std::sync::Arc;
use tokio::sync::RwLock;

use voip_client::{Client, error::ClientError};
use voip_core::VoIPConfig;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// FFI-safe error type exposed to Kotlin/Swift.
///
/// Maps directly to the `[Error] enum VoipError` in `voip.udl`.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VoipError {
    #[error("Client not initialized")]
    #[uniffi(error)]
    NotInitialized,
    #[error("Call already in progress")]
    #[uniffi(error)]
    CallInProgress,
    #[error("No active call")]
    #[uniffi(error)]
    NoActiveCall,
    #[error("Connection failed: {0}")]
    #[uniffi(error)]
    ConnectionFailed(String),
    #[error("Call setup timeout: {0}")]
    #[uniffi(error)]
    CallSetupTimeout(String),
    #[error("Call rejected: {0}")]
    #[uniffi(error)]
    CallRejected(String),
    #[error("NAT traversal failed: {0}")]
    #[uniffi(error)]
    NatTraversalFailed(String),
    #[error("MASQUE relay failed: {0}")]
    #[uniffi(error)]
    MasqueFailed(String),
    #[error("Internal error: {0}")]
    #[uniffi(error)]
    Internal(String),
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
        }
    }
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// The current state of a VoIP call, observable by the UI layer.
///
/// Maps to `enum CallState` in `voip.udl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CallState {
    /// No call in progress.
    Idle,
    /// Outgoing call is ringing (waiting for peer to accept).
    Ringing,
    /// Incoming call is ringing (waiting for user to accept).
    Incoming,
    /// Call is connected — media is flowing.
    Connected,
    /// Call has ended.
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

/// How the direct P2P connection was established.
///
/// Maps to `enum ConnectionMethod` in `voip.udl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectionMethod {
    /// Not yet connected.
    None,
    /// Direct IPv6 connection.
    Ipv6Direct,
    /// IPv4 Cone NAT — QUIC simultaneous open.
    Ipv4Cone,
    /// IPv4 Symmetric NAT — QUIC path probing + port prediction.
    Ipv4Prediction,
    /// MASQUE CONNECT-UDP relay (RFC 9298) — bidirectional.
    Masque,
    /// MASQUE CONNECT-UDP over HTTP/2 (UDP-blocked fallback).
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

/// NAT type classification as detected by QUIC path probing.
///
/// Maps to `enum NATType` in `voip.udl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum NATType {
    /// IPv6, no NAT involved.
    None,
    /// Full-Cone or Restricted-Cone NAT.
    Cone,
    /// Symmetric NAT with +1/+2 delta.
    SymmetricSequential,
    /// Symmetric NAT with +1 to +5 delta.
    SymmetricPseudo,
    /// Symmetric NAT with random allocation.
    SymmetricRandom,
}

/// How a peer was discovered.
///
/// Maps to `enum DiscoveryMethod` in `voip.udl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DiscoveryMethod {
    /// Found via DHT lookup.
    Dht,
    /// Found via signaling server.
    Signaling,
    /// Found in local peer address book cache.
    Cache,
}

// ---------------------------------------------------------------------------
// Records (dictionaries)
// ---------------------------------------------------------------------------

/// Configuration for the VoIP client, serializable for mobile storage.
///
/// Maps to `dictionary VoipConfig` in `voip.udl`.
/// See spec/11_Implementation_Stack.md §11.3 for full documentation.
#[derive(Debug, Clone, uniffi::Record)]
pub struct VoipConfig {
    /// Discovery priority: true = DHT first (privacy), false = signaling first (speed).
    pub discovery_privacy_first: bool,
    /// DHT lookup timeout before falling back to signaling (ms).
    pub dht_lookup_timeout_ms: u64,
    /// DHT bootstrap nodes (hardcoded fallback).
    pub dht_bootstrap_nodes: Vec<String>,
    /// Signaling server URL.
    pub signaling_server_url: String,
    /// Enable MASQUE CONNECT-UDP fallback.
    pub masque_fallback_enabled: bool,
    /// Enable push notification retry for failed connections.
    pub push_retry_enabled: bool,
    /// QUIC connection timeout (ms).
    pub quic_connect_timeout_ms: u64,
    /// Call ring timeout (ms).
    pub call_ring_timeout_ms: u64,
}

impl Default for VoipConfig {
    fn default() -> Self {
        Self::from(&VoIPConfig::default())
    }
}

impl VoipConfig {
    /// Convert to the core config type.
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

/// Information about the current connection method and quality metrics.
///
/// Maps to `dictionary ConnectionInfo` in `voip.udl`.
/// Observable by the UI layer to display connection quality.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ConnectionInfo {
    /// How the connection was established.
    pub method: ConnectionMethod,
    /// Measured round-trip time in milliseconds.
    pub rtt_ms: u32,
    /// Packet loss percentage (0-100).
    pub packet_loss_pct: f32,
    /// Jitter in milliseconds.
    pub jitter_ms: u32,
    /// How the peer was discovered.
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

/// Statistics about a completed or in-progress call.
///
/// Maps to `dictionary CallStats` in `voip.udl`.
#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct CallStats {
    /// Call duration in seconds.
    pub duration_secs: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Total packets sent.
    pub packets_sent: u64,
    /// Total packets received.
    pub packets_received: u64,
    /// Total packets lost.
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

/// Get or create the global tokio runtime for async operations.
///
/// The runtime is lazily initialized on first access and lives for the
/// duration of the process. All FFI methods that need async operations
/// use `runtime().block_on()` to bridge sync→async.
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

/// The main VoIP client object exposed to Kotlin/Swift.
///
/// This is the primary interface for the mobile application layer.
/// It manages call lifecycle, connection state, and audio routing.
///
/// Maps to `interface VoipClient` in `voip.udl`.
///
/// # Thread Safety
///
/// All methods are safe to call from any thread. The underlying
/// client uses async Rust with tokio for all I/O operations.
/// A shared tokio runtime is used internally to bridge the
/// synchronous FFI calls to the async client methods.
#[derive(uniffi::Object)]
pub struct VoipClient {
    inner: Arc<RwLock<Option<Client>>>,
    config: VoipConfig,
}

#[uniffi::export]
impl VoipClient {
    /// Create a new VoipClient with the given configuration.
    ///
    /// The client is not yet initialized; call `init()` before
    /// placing or receiving calls.
    #[uniffi::constructor]
    pub fn new(config: VoipConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
            config,
        }
    }

    /// Initialize the VoIP client.
    ///
    /// Connects to the signaling server, bootstraps the DHT,
    /// and performs NAT probing. Must be called before any other
    /// method except `get_call_state()`.
    ///
    /// # Errors
    ///
    /// Returns `VoipError` if initialization fails (e.g., network
    /// unreachable, signaling server down).
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

    /// Place a call to the given peer.
    ///
    /// The `peer_id` is the hex-encoded Ed25519 public key of the
    /// peer (32 bytes → 64 hex characters). Returns immediately;
    /// call state transitions are observable via `get_call_state()`.
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if `init()` was not called
    /// - `CallInProgress` if a call is already active
    pub fn call(&self, peer_id: String) -> Result<(), VoipError> {
        runtime().block_on(async {
            let inner = self.inner.read().await;
            let client = inner.as_ref().ok_or(VoipError::NotInitialized)?;
            client.call(&peer_id).await?;
            Ok(())
        })
    }

    /// Hang up the current call.
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if `init()` was not called
    /// - `NoActiveCall` if no call is in progress
    pub fn hangup(&self) -> Result<(), VoipError> {
        runtime().block_on(async {
            let inner = self.inner.read().await;
            let client = inner.as_ref().ok_or(VoipError::NotInitialized)?;
            client.hangup().await?;
            Ok(())
        })
    }

    /// Mute the local audio (stop sending audio to peer).
    ///
    /// The peer will receive silence indicator. The call remains
    /// connected; only the audio send path is muted.
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if `init()` was not called
    /// - `NoActiveCall` if no call is in progress
    pub fn mute(&self) -> Result<(), VoipError> {
        runtime().block_on(async {
            let inner = self.inner.read().await;
            let client = inner.as_ref().ok_or(VoipError::NotInitialized)?;
            client.mute().await?;
            Ok(())
        })
    }

    /// Unmute the local audio (resume sending audio to peer).
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if `init()` was not called
    /// - `NoActiveCall` if no call is in progress
    pub fn unmute(&self) -> Result<(), VoipError> {
        runtime().block_on(async {
            let inner = self.inner.read().await;
            let client = inner.as_ref().ok_or(VoipError::NotInitialized)?;
            client.unmute().await?;
            Ok(())
        })
    }

    /// Get the current call state.
    ///
    /// Returns `Idle` if the client has not been initialized.
    /// This method never fails and is safe to poll from the UI layer.
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

    /// Get information about the current connection.
    ///
    /// Returns `None` if not connected. The `ConnectionInfo` includes
    /// the connection method (IPv6 direct, QUIC simultaneous open,
    /// port prediction, MASQUE), quality metrics (RTT, packet loss,
    /// jitter), and how the peer was discovered.
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

    /// Get call statistics for the current or most recent call.
    ///
    /// Returns zeroed stats if no call has been made.
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

    /// Get whether the client is currently muted.
    ///
    /// Returns `false` if the client is not initialized.
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

    /// Shut down the client gracefully.
    ///
    /// Ends any active call and releases network resources.
    /// After shutdown, `init()` must be called again before
    /// the client can be used.
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
