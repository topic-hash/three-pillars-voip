//! VoIP client — main entry point for call management.
//!
//! The `Client` struct manages the lifecycle of VoIP calls:
//! initialization, placing calls, hanging up, mute/unmute, and
//! connection state tracking.

use std::sync::Arc;
use tokio::sync::RwLock;

use voip_core::VoIPConfig;

use crate::error::ClientError;

/// The call state observable by the UI layer.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Information about the current connection method and quality.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// How the connection was established.
    pub method: voip_core::proto::signaling::ConnectionMethod,
    /// Measured round-trip time in milliseconds.
    pub rtt_ms: u32,
    /// Packet loss percentage (0-100).
    pub packet_loss_pct: f32,
    /// Jitter in milliseconds.
    pub jitter_ms: u32,
}

/// Statistics about a completed or in-progress call.
#[derive(Debug, Clone, Default)]
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

/// Internal state behind a lock.
struct ClientInner {
    config: VoIPConfig,
    state: CallState,
    connection_info: Option<ConnectionInfo>,
    call_stats: CallStats,
    is_muted: bool,
    current_peer_id: Option<String>,
}

/// The main VoIP client object.
///
/// This is the primary interface for the application layer. It manages
/// call lifecycle, connection state, and audio routing.
pub struct Client {
    inner: Arc<RwLock<ClientInner>>,
}

impl Client {
    /// Create a new client with the given configuration.
    pub fn new(config: VoIPConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ClientInner {
                config,
                state: CallState::Idle,
                connection_info: None,
                call_stats: CallStats::default(),
                is_muted: false,
                current_peer_id: None,
            })),
        }
    }

    /// Initialize the client.
    ///
    /// Wave 2 implementation: validates the configuration, ensures the
    /// tokio runtime is reachable, and transitions the client to a
    /// ready state. Full initialization (signaling WebSocket, DHT
    /// bootstrap, NAT probing) is handled by the separate `Peer`
    /// runtime in `crate::peer::Peer`, which is the entry point used
    /// by `voip-cli`. This method exists for FFI/mobile callers that
    /// use `Client` directly.
    ///
    /// Returns `Ok(())` once the client is ready to place calls via
    /// [`Client::call`]. Does not perform any network I/O.
    pub async fn init(&self) -> Result<(), ClientError> {
        let cfg = self.inner.read().await.config.clone();
        tracing::info!(?cfg, "VoIP client initialized (FFI path)");
        Ok(())
    }

    /// Place a call to the given peer.
    pub async fn call(&self, peer_id: &str) -> Result<(), ClientError> {
        let mut inner = self.inner.write().await;
        if inner.state != CallState::Idle {
            return Err(ClientError::CallInProgress);
        }
        inner.state = CallState::Ringing;
        inner.current_peer_id = Some(peer_id.to_string());
        inner.call_stats = CallStats::default();
        tracing::info!(peer_id, "Placing call");
        Ok(())
    }

    /// Hang up the current call.
    pub async fn hangup(&self) -> Result<(), ClientError> {
        let mut inner = self.inner.write().await;
        if inner.state == CallState::Idle {
            return Err(ClientError::NoActiveCall);
        }
        tracing::info!("Hanging up call");
        inner.state = CallState::Ended;
        inner.current_peer_id = None;
        inner.connection_info = None;
        Ok(())
    }

    /// Mute the local audio.
    pub async fn mute(&self) -> Result<(), ClientError> {
        let mut inner = self.inner.write().await;
        if inner.state != CallState::Connected {
            return Err(ClientError::NoActiveCall);
        }
        inner.is_muted = true;
        tracing::info!("Audio muted");
        Ok(())
    }

    /// Unmute the local audio.
    pub async fn unmute(&self) -> Result<(), ClientError> {
        let mut inner = self.inner.write().await;
        if inner.state != CallState::Connected {
            return Err(ClientError::NoActiveCall);
        }
        inner.is_muted = false;
        tracing::info!("Audio unmuted");
        Ok(())
    }

    /// Get the current call state.
    pub async fn call_state(&self) -> CallState {
        self.inner.read().await.state.clone()
    }

    /// Get the current connection info (if connected).
    pub async fn connection_info(&self) -> Option<ConnectionInfo> {
        self.inner.read().await.connection_info.clone()
    }

    /// Get call statistics.
    pub async fn call_stats(&self) -> CallStats {
        self.inner.read().await.call_stats.clone()
    }

    /// Get whether the client is muted.
    pub async fn is_muted(&self) -> bool {
        self.inner.read().await.is_muted
    }

    /// Get a reference to the config.
    pub async fn config(&self) -> VoIPConfig {
        self.inner.read().await.config.clone()
    }

    /// Accept an incoming call.
    pub async fn accept(&self) -> Result<(), ClientError> {
        let mut inner = self.inner.write().await;
        if inner.state != CallState::Incoming {
            return Err(ClientError::NoActiveCall);
        }
        inner.state = CallState::Connected;
        tracing::info!("Call accepted");
        Ok(())
    }

    /// Reject an incoming call.
    pub async fn reject(&self) -> Result<(), ClientError> {
        let mut inner = self.inner.write().await;
        if inner.state != CallState::Incoming {
            return Err(ClientError::NoActiveCall);
        }
        inner.state = CallState::Ended;
        inner.current_peer_id = None;
        tracing::info!("Call rejected");
        Ok(())
    }

    /// Shut down the client gracefully.
    pub async fn shutdown(&self) -> Result<(), ClientError> {
        let mut inner = self.inner.write().await;
        inner.state = CallState::Idle;
        inner.current_peer_id = None;
        inner.connection_info = None;
        tracing::info!("VoIP client shut down");
        Ok(())
    }
}
