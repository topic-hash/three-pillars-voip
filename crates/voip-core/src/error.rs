//! Error types mapping to spec error codes.
//!
//! Defines the `VoipError` enum with variants for each error category
//! (Network, Timeout, NAT, MASQUE, etc.) and maps them to `CallEndReason`
//! from the spec. Error codes follow the spec/08 §8.5 range (1001-9999).

use crate::types::CallEndReason;

/// Error codes from spec/08 §8.5.
///
/// These codes are used in the `Error` message (type ID 0x8001)
/// sent from the signaling server to the client.
pub mod error_codes {
    // Peer errors (1001-1099)
    /// Requested peer_id is not registered
    pub const UNKNOWN_PEER: u32 = 1001;
    /// Requested peer is offline
    pub const PEER_OFFLINE: u32 = 1002;
    /// Call ID not found or expired
    pub const INVALID_CALL_ID: u32 = 1003;
    /// Duplicate call_id
    pub const CALL_ALREADY_EXISTS: u32 = 1004;
    /// Peer not part of this call
    pub const NOT_CALL_PARTICIPANT: u32 = 1005;

    // Protocol errors (2001-2099)
    /// Too many requests — slow down
    pub const RATE_LIMITED: u32 = 2001;
    /// JWT token missing, expired, or invalid
    pub const INVALID_JWT: u32 = 2002;
    /// Protobuf decode error or unknown type
    pub const INVALID_MESSAGE: u32 = 2003;

    // MASQUE errors (3001-3099)
    /// No MASQUE proxy available
    pub const MASQUE_NO_PROXY: u32 = 3001;
    /// Proxy connection timed out
    pub const MASQUE_PROXY_TIMEOUT: u32 = 3002;
    /// MASQUE proxy coordination unavailable
    pub const MASQUE_COORDINATION_FAILED: u32 = 3003;

    // Internal error
    /// Server-side error (check logs)
    pub const INTERNAL_ERROR: u32 = 9999;
}

/// The main error type for the VoIP system.
///
/// Each variant maps to a `CallEndReason` for inclusion in call
/// failure messages.
#[derive(Debug, thiserror::Error)]
pub enum VoipError {
    // === Network errors ===
    /// QUIC connection failed
    #[error("QUIC connection failed: {0}")]
    QuicConnectionFailed(String),

    /// QUIC handshake timeout
    #[error("QUIC handshake timeout")]
    QuicHandshakeTimeout,

    /// Connection migration failed
    #[error("Connection migration failed")]
    MigrationFailed,

    // === NAT errors ===
    /// NAT probing failed
    #[error("NAT probing failed: {0}")]
    NatProbeFailed(String),

    /// Both peers behind symmetric NAT with random port allocation
    #[error("Both peers have random NAT — prediction impossible")]
    NatRandomBothSides,

    /// UDP blocked by firewall
    #[error("UDP blocked by firewall")]
    UdpBlocked,

    /// Both UDP and TCP port 443 blocked
    #[error("TCP port 443 also blocked — no MASQUE possible")]
    TcpBlocked,

    // === MASQUE errors ===
    /// MASQUE proxy unreachable
    #[error("MASQUE proxy unreachable: {0}")]
    MasqueProxyUnreachable(String),

    /// MASQUE tunnel setup failed
    #[error("MASQUE tunnel setup failed: {0}")]
    MasqueTunnelFailed(String),

    /// MASQUE tunnel disconnected during active call
    #[error("MASQUE tunnel disconnected during call")]
    MasqueTunnelDisconnected,

    /// No MASQUE proxy available
    #[error("No MASQUE proxy available")]
    MasqueNoProxy,

    /// ProxyToken validation failed
    #[error("ProxyToken validation failed")]
    ProxyTokenInvalid,

    // === Signaling errors ===
    /// Signaling server error
    #[error("Signaling server error: {0}")]
    SignalingError(String),

    /// JWT authentication failed
    #[error("JWT authentication failed: {0}")]
    JwtAuthFailed(String),

    /// Rate limited
    #[error("Rate limited")]
    RateLimited,

    /// Peer not found
    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    /// Peer is offline
    #[error("Peer offline: {0}")]
    PeerOffline(String),

    // === State machine errors ===
    /// Invalid state transition attempted
    #[error("Invalid state transition: {from:?} → {to:?}: {reason}")]
    InvalidTransition {
        from: String,
        to: String,
        reason: String,
    },

    /// Call already exists
    #[error("Call already exists: {0}")]
    CallAlreadyExists(String),

    // === DHT errors ===
    /// DHT lookup failed
    #[error("DHT lookup failed: {0}")]
    DhtLookupFailed(String),

    /// DHT record verification failed
    #[error("DHT record verification failed")]
    DhtRecordVerificationFailed,

    // === Crypto errors ===
    /// Ed25519 signature verification failed
    #[error("Ed25519 signature verification failed")]
    SignatureVerificationFailed,

    /// Invalid key material
    #[error("Invalid key material: {0}")]
    InvalidKeyMaterial(String),

    // === Internal errors ===
    /// Internal server/client error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl VoipError {
    /// Maps this error to a `CallEndReason` for inclusion in CallFailed/CallEnded messages.
    pub fn to_call_end_reason(&self) -> CallEndReason {
        match self {
            // Network errors → FailedNetwork or MigrationFailed
            VoipError::QuicConnectionFailed(_) => CallEndReason::FailedNetwork,
            VoipError::QuicHandshakeTimeout => CallEndReason::Timeout,
            VoipError::MigrationFailed => CallEndReason::MigrationFailed,

            // NAT errors
            VoipError::NatProbeFailed(_) => CallEndReason::FailedNetwork,
            VoipError::NatRandomBothSides => CallEndReason::FailedIpv4Random,
            VoipError::UdpBlocked => CallEndReason::FailedUdpBlocked,
            VoipError::TcpBlocked => CallEndReason::FailedTcpBlocked,

            // MASQUE errors
            VoipError::MasqueProxyUnreachable(_) => CallEndReason::FailedMasqueUnreachable,
            VoipError::MasqueTunnelFailed(_) => CallEndReason::FailedMasqueUnreachable,
            VoipError::MasqueTunnelDisconnected => CallEndReason::FailedMasqueUnreachable,
            VoipError::MasqueNoProxy => CallEndReason::FailedMasqueUnreachable,
            VoipError::ProxyTokenInvalid => CallEndReason::FailedMasqueUnreachable,

            // Signaling errors
            VoipError::SignalingError(_) => CallEndReason::FailedNetwork,
            VoipError::JwtAuthFailed(_) => CallEndReason::FailedNetwork,
            VoipError::RateLimited => CallEndReason::FailedNetwork,
            VoipError::PeerNotFound(_) => CallEndReason::FailedNetwork,
            VoipError::PeerOffline(_) => CallEndReason::Timeout,

            // State machine errors
            VoipError::InvalidTransition { .. } => CallEndReason::FailedNetwork,
            VoipError::CallAlreadyExists(_) => CallEndReason::FailedNetwork,

            // DHT errors
            VoipError::DhtLookupFailed(_) => CallEndReason::FailedNetwork,
            VoipError::DhtRecordVerificationFailed => CallEndReason::FailedNetwork,

            // Crypto errors
            VoipError::SignatureVerificationFailed => CallEndReason::FailedNetwork,
            VoipError::InvalidKeyMaterial(_) => CallEndReason::FailedNetwork,

            // Internal
            VoipError::Internal(_) => CallEndReason::FailedNetwork,
        }
    }

    /// Returns the error code for signaling server Error messages.
    ///
    /// Maps this error to the appropriate code from spec/08 §8.5.
    pub fn to_error_code(&self) -> u32 {
        match self {
            VoipError::PeerNotFound(_) => error_codes::UNKNOWN_PEER,
            VoipError::PeerOffline(_) => error_codes::PEER_OFFLINE,
            VoipError::CallAlreadyExists(_) => error_codes::CALL_ALREADY_EXISTS,
            VoipError::RateLimited => error_codes::RATE_LIMITED,
            VoipError::JwtAuthFailed(_) => error_codes::INVALID_JWT,
            VoipError::SignalingError(_) => error_codes::INVALID_MESSAGE,
            VoipError::MasqueNoProxy => error_codes::MASQUE_NO_PROXY,
            VoipError::MasqueProxyUnreachable(_) => error_codes::MASQUE_PROXY_TIMEOUT,
            VoipError::ProxyTokenInvalid => error_codes::MASQUE_COORDINATION_FAILED,
            _ => error_codes::INTERNAL_ERROR,
        }
    }

    /// Returns true if this error is recoverable (retry with backoff).
    ///
    /// See spec/11 §11.5 for the error handling rules.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            VoipError::QuicHandshakeTimeout
                | VoipError::NatProbeFailed(_)
                | VoipError::DhtLookupFailed(_)
                | VoipError::SignalingError(_)
        )
    }

    /// Returns true if this error can be resolved by connection migration.
    pub fn is_migratable(&self) -> bool {
        matches!(
            self,
            VoipError::MigrationFailed | VoipError::MasqueTunnelDisconnected
        )
    }

    /// Returns true if this error is fatal (call fails honestly).
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            VoipError::NatRandomBothSides
                | VoipError::UdpBlocked
                | VoipError::TcpBlocked
                | VoipError::MasqueNoProxy
                | VoipError::PeerNotFound(_)
                | VoipError::SignatureVerificationFailed
                | VoipError::DhtRecordVerificationFailed
        )
    }

    /// Returns true if push retry should be attempted for this error.
    pub fn should_push_retry(&self) -> bool {
        matches!(
            self,
            VoipError::NatRandomBothSides | VoipError::MasqueProxyUnreachable(_)
        )
    }
}
