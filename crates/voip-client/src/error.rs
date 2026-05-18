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

impl From<ConnectError> for ClientError {
    fn from(e: ConnectError) -> Self {
        ClientError::ConnectionFailed(e.to_string())
    }
}

impl From<MasqueError> for ClientError {
    fn from(e: MasqueError) -> Self {
        ClientError::MasqueFailed(e.to_string())
    }
}

// ============================================================================
// Local error types not present in voip-core
// ============================================================================

/// Connection establishment errors.
#[derive(Debug, Error)]
pub enum ConnectError {
    /// QUIC transport error.
    #[error("QUIC error: {0}")]
    QuicError(#[from] quinn::ConnectionError),

    /// Network-level error.
    #[error("Network error: {0}")]
    NetworkError(String),

    /// QUIC connection timed out.
    #[error("QUIC connection timeout after {0}ms")]
    QuicTimeout(u64),

    /// NAT probe failed.
    #[error("NAT probe failed: {0}")]
    NatProbeFailed(String),

    /// All connection methods exhausted.
    #[error("All connection methods failed")]
    AllMethodsFailed,

    /// MASQUE proxy unreachable.
    #[error("MASQUE proxy unreachable")]
    MasqueUnreachable,
}

/// MASQUE tunnel errors.
#[derive(Debug, Error)]
pub enum MasqueError {
    /// HTTP/3 protocol error.
    #[error("HTTP/3 error: {0}")]
    Http3Error(String),

    /// HTTP/2 protocol error.
    #[error("HTTP/2 error: {0}")]
    Http2Error(String),

    /// CONNECT-UDP request rejected by proxy.
    #[error("CONNECT-UDP rejected with status {0}")]
    ConnectUdpRejected(u16),

    /// Waiting for peer to connect to proxy.
    #[error("Waiting for peer to connect to MASQUE proxy")]
    WaitingForPeer,

    /// Tunnel has been closed.
    #[error("MASQUE tunnel closed")]
    TunnelClosed,

    /// Failed to send datagram through tunnel.
    #[error("Datagram send failed: {0}")]
    DatagramSendFailed(String),

    /// Failed to receive datagram from tunnel.
    #[error("Datagram receive failed: {0}")]
    DatagramRecvFailed(String),

    /// TLS handshake error.
    #[error("TLS error: {0}")]
    TlsError(String),

    /// All MASQUE transport paths failed.
    #[error("All MASQUE transports failed")]
    AllTransportsFailed,
}

/// Connection migration errors.
#[derive(Debug, Error)]
pub enum MigrationError {
    /// Migration timed out.
    #[error("Connection migration timeout after {0}ms")]
    Timeout(u64),

    /// Path validation failed.
    #[error("Path validation failed: {0}")]
    PathValidationFailed(String),
}

/// NAT probe errors.
#[derive(Debug, Error)]
pub enum NatProbeError {
    /// Not connected to signaling server.
    #[error("Not connected to signaling server")]
    NotConnected,

    /// Probe timed out.
    #[error("Probe timeout for {0}")]
    ProbeTimeout(String),

    /// QUIC path migration failed during probe.
    #[error("Migration failed for {ip}: {reason}")]
    MigrationFailed {
        /// The IP being probed.
        ip: String,
        /// Failure reason.
        reason: String,
    },

    /// Not enough successful probes to classify NAT.
    #[error("Insufficient probes: got {got}, need {need}")]
    InsufficientProbes {
        /// Number of successful probes.
        got: usize,
        /// Required minimum probes.
        need: usize,
    },
}

/// Port prediction probe errors.
#[derive(Debug, Error)]
pub enum ProbeError {
    /// All predicted ports exhausted.
    #[error("All predicted ports exhausted")]
    AllPortsExhausted,

    /// Probe timed out.
    #[error("Port prediction probe timeout after {0}ms")]
    ProbeTimeout(u64),

    /// No prediction data available.
    #[error("Port prediction not available")]
    PredictionNotAvailable,

    /// QUIC connection error.
    #[error("QUIC error: {0}")]
    QuicError(#[from] quinn::ConnectionError),
}

/// Audio codec errors.
#[derive(Debug, Error)]
pub enum AudioError {
    /// Encoder creation or operation failed.
    #[error("Encoder error: {0}")]
    EncoderError(String),

    /// Decoder creation or operation failed.
    #[error("Decoder error: {0}")]
    DecoderError(String),

    /// Input frame size doesn't match expected.
    #[error("Invalid frame size: got {0} samples")]
    InvalidFrameSize(usize),

    /// Output buffer too small.
    #[error("Buffer too small: need {need}, have {have}")]
    BufferTooSmall {
        /// Required buffer size.
        need: usize,
        /// Actual buffer size.
        have: usize,
    },
}

/// MoQ session errors.
#[derive(Debug, Error)]
pub enum MoqError {
    /// MoQ session is in an invalid state for this operation.
    #[error("Invalid MoQ session state: expected {expected}, got {got}")]
    InvalidState {
        expected: &'static str,
        got: String,
    },

    /// QUIC transport error during MoQ operation.
    #[error("Transport error: {0}")]
    TransportError(String),

    /// Failed to send a QUIC datagram.
    #[error("Datagram send failed: {0}")]
    DatagramSendFailed(String),

    /// Failed to receive a QUIC datagram.
    #[error("Datagram receive failed: {0}")]
    DatagramRecvFailed(String),

    /// Received datagram is too short to parse.
    #[error("Datagram too short: got {got} bytes, need at least {need}")]
    DatagramTooShort {
        got: usize,
        need: usize,
    },

    /// Invalid datagram type received.
    #[error("Invalid datagram type: 0x{0:02x}")]
    InvalidDatagramType(u8),

    /// Unexpected MoQ control message type.
    #[error("Unexpected message type: expected 0x{expected:x}, got 0x{got:x}")]
    UnexpectedMessageType {
        expected: u64,
        got: u64,
    },

    /// MoQ protocol version negotiation failed.
    #[error("Version negotiation failed: no compatible version")]
    VersionNegotiationFailed,

    /// Track namespace not found.
    #[error("Track not found: {0}")]
    TrackNotFound(String),

    /// Subscription error from the publisher.
    #[error("Subscription error: code {code}, reason: {reason}")]
    SubscribeError {
        code: u64,
        reason: String,
    },
}
