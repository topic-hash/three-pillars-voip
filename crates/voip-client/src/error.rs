//! Client error types.
//!
//! Extends the core VoipError with client-specific errors for connection
//! management, NAT probing, port prediction, and audio operations.

use thiserror::Error;

/// Errors that can occur in the VoIP client.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The client is not initialized.
    #[error("Client not initialized")]
    NotInitialized,

    /// A call is already in progress.
    #[error("Call already in progress")]
    CallInProgress,

    /// No call is currently active.
    #[error("No active call")]
    NoActiveCall,

    /// Connection failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Timeout during call setup.
    #[error("Call setup timeout: {0}")]
    CallSetupTimeout(String),

    /// The peer rejected the call.
    #[error("Call rejected: {0}")]
    CallRejected(String),

    /// NAT traversal failed.
    #[error("NAT traversal failed: {0}")]
    NatTraversalFailed(String),

    /// MASQUE relay failed.
    #[error("MASQUE relay failed: {0}")]
    MasqueFailed(String),

    /// Audio subsystem error.
    #[error("Audio error: {0}")]
    Audio(String),

    /// All connection methods failed.
    #[error("All connection methods failed")]
    AllMethodsFailed,

    /// QUIC connection timeout.
    #[error("QUIC connection timeout after {0}ms")]
    QuicTimeout(u64),

    /// Port prediction failed — both peers behind random NAT.
    #[error("Port prediction failed: both peers behind random NAT")]
    PredictionFailedRandom,

    /// UDP blocked by firewall.
    #[error("UDP blocked by firewall")]
    UdpBlocked,

    /// TCP port 443 also blocked — no MASQUE possible.
    #[error("TCP port 443 also blocked — no MASQUE possible")]
    TcpBlocked,

    /// MASQUE proxy unreachable.
    #[error("MASQUE proxy unreachable")]
    MasqueUnreachable,

    /// Connection migration failed.
    #[error("Connection migration failed: {0}")]
    MigrationFailed(String),

    /// Network error.
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Signaling error.
    #[error("Signaling error: {0}")]
    SignalingError(String),

    /// Timeout waiting for peer response.
    #[error("Timeout waiting for peer response")]
    PeerTimeout,

    /// NAT probe error.
    #[error("NAT probe error: {0}")]
    NatProbeError(String),

    /// Port prediction probe error.
    #[error("Port prediction error: {0}")]
    ProbeError(String),

    /// Audio codec error.
    #[error("Audio codec error: {0}")]
    AudioError(String),

    /// Connection migration timeout.
    #[error("Connection migration timeout: {0}ms")]
    MigrationTimeout(u64),

    /// Core error.
    #[error(transparent)]
    Core(#[from] voip_core::error::VoipError),
}

impl From<quinn::ConnectionError> for ClientError {
    fn from(e: quinn::ConnectionError) -> Self {
        ClientError::NetworkError(e.to_string())
    }
}

impl From<voip_core::error::MasqueError> for ClientError {
    fn from(e: voip_core::error::MasqueError) -> Self {
        ClientError::MasqueFailed(e.to_string())
    }
}
