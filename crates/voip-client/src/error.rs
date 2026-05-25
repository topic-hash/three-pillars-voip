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

/// Audio pipeline errors.
#[derive(Debug, Error)]
pub enum PipelineError {
    /// Encoder error during pipeline operation.
    #[error("Pipeline encoder error: {0}")]
    EncoderError(AudioError),

    /// Decoder error during pipeline operation.
    #[error("Pipeline decoder error: {0}")]
    DecoderError(AudioError),

    /// Invalid frame size passed to pipeline.
    #[error("Invalid frame size: expected {expected}, got {got}")]
    InvalidFrameSize {
        /// Expected number of samples.
        expected: usize,
        /// Actual number of samples provided.
        got: usize,
    },

    /// MoQ datagram error in pipeline.
    #[error("Pipeline MoQ error: {0}")]
    MoqError(#[from] MoqError),

    /// Pipeline is in an invalid state for this operation.
    #[error("Pipeline invalid state: {0}")]
    InvalidState(String),
}

impl From<AudioError> for PipelineError {
    fn from(e: AudioError) -> Self {
        match &e {
            AudioError::EncoderError(_) => PipelineError::EncoderError(e),
            AudioError::DecoderError(_) => PipelineError::DecoderError(e),
            AudioError::InvalidFrameSize(n) => PipelineError::InvalidFrameSize {
                expected: 960,
                got: *n,
            },
            AudioError::BufferTooSmall { need, have } => PipelineError::InvalidState(
                format!("Buffer too small: need {}, have {}", need, have),
            ),
        }
    }
}

/// Proxy server errors (3.20/3.21 — volunteer proxy node and anti-abuse).
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Maximum concurrent sessions exceeded.
    #[error("Session capacity exceeded: max {max}, active {active}")]
    CapacityExceeded {
        /// Maximum allowed sessions.
        max: u32,
        /// Currently active sessions.
        active: u32,
    },

    /// Session duration limit exceeded.
    #[error("Session duration exceeded: limit {limit_secs}s, actual {actual_secs}s")]
    DurationExceeded {
        /// Maximum allowed duration in seconds.
        limit_secs: u64,
        /// Actual session duration in seconds.
        actual_secs: u64,
    },

    /// Datagram rate limit exceeded.
    #[error("Datagram rate exceeded: max {max}/s, current {current}/s")]
    DatagramRateExceeded {
        /// Maximum allowed datagrams per second.
        max: u32,
        /// Current datagram rate per second.
        current: u32,
    },

    /// Datagram size exceeds limit.
    #[error("Datagram too large: max {max} bytes, got {got} bytes")]
    DatagramSizeExceeded {
        /// Maximum allowed datagram size.
        max: usize,
        /// Actual datagram size.
        got: usize,
    },

    /// Bandwidth limit exceeded.
    #[error("Bandwidth exceeded: max {max_bps} bps, current {current_bps} bps")]
    BandwidthExceeded {
        /// Maximum allowed bandwidth in bps.
        max_bps: u64,
        /// Current bandwidth in bps.
        current_bps: u64,
    },

    /// Target port is not allowed (blocked list).
    #[error("Target port {port} is not allowed")]
    PortBlocked {
        /// The blocked port number.
        port: u16,
    },

    /// ProxyToken validation failed.
    #[error("ProxyToken validation failed: {0}")]
    TokenValidationFailed(String),

    /// Session not found.
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    /// Proxy server I/O error.
    #[error("Proxy I/O error: {0}")]
    IoError(String),

    /// QUIC endpoint error.
    #[error("QUIC endpoint error: {0}")]
    QuicError(String),

    /// Certificate error.
    #[error("Certificate error: {0}")]
    CertError(#[from] CertError),

    /// Token error.
    #[error("Token error: {0}")]
    TokenError(#[from] ProxyTokenError),
}

/// ProxyToken errors (3.22 — token signing/verification).
#[derive(Debug, Error)]
pub enum ProxyTokenError {
    /// Invalid signature.
    #[error("Invalid ProxyToken signature")]
    InvalidSignature,

    /// Token has expired.
    #[error("ProxyToken expired at {expires_at}")]
    Expired {
        /// Unix timestamp when the token expired.
        expires_at: u64,
    },

    /// Base64 decode error.
    #[error("Base64 decode error: {0}")]
    Base64DecodeError(String),

    /// Serialization error.
    #[error("Token serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error.
    #[error("Token deserialization error: {0}")]
    DeserializationError(String),

    /// Missing required field.
    #[error("Missing field: {0}")]
    MissingField(String),

    /// Ed25519 signing error.
    #[error("Ed25519 signing error: {0}")]
    SigningError(String),

    /// Ed25519 verification error.
    #[error("Ed25519 verification error: {0}")]
    VerificationError(String),
}

/// Certificate provisioning errors (3.23 — cert provisioning).
#[derive(Debug, Error)]
pub enum CertError {
    /// ACME challenge failed (Let's Encrypt).
    #[error("ACME challenge failed: {0}")]
    AcmeChallengeFailed(String),

    /// Certificate not yet provisioned.
    #[error("Certificate not provisioned")]
    NotProvisioned,

    /// Self-signed certificate generation failed.
    #[error("Self-signed cert generation failed: {0}")]
    SelfSignedGenerationFailed(String),

    /// Invalid domain name for ACME.
    #[error("Invalid domain: {0}")]
    InvalidDomain(String),

    /// TLS configuration error.
    #[error("TLS config error: {0}")]
    TlsConfigError(String),

    /// I/O error during certificate storage.
    #[error("Certificate I/O error: {0}")]
    IoError(String),

    /// Quinn server config creation failed.
    #[error("Server config error: {0}")]
    ServerConfigError(String),

    /// rcgen certificate generation error.
    #[error("rcgen error: {0}")]
    RcgenError(String),
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
