//! Error types mapping to spec error codes.
//!
//! Defines the `VoipError` enum with variants for each error category
//! (Network, Timeout, NAT, MASQUE, etc.) and maps them to `CallEndReason`
//! from the spec. Error codes follow the spec/08 §8.5 range (1001-9999).

use crate::types::{CallEndReason, CallState, ConnectionMethod};

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
    /// QUIC handshake failed
    #[error("QUIC handshake failed: {reason}")]
    QuicHandshakeFailed {
        reason: String,
    },

    /// QUIC connection was lost after establishment
    #[error("QUIC connection lost: {reason}")]
    ConnectionLost {
        reason: String,
    },

    /// Connection migration failed
    #[error("Connection migration failed: {reason}")]
    MigrationFailed {
        reason: String,
    },

    /// Network interface changed (WiFi → cellular, etc.)
    #[error("Network interface changed")]
    NetworkChanged,

    // === Timeout errors ===
    /// Call ringing timeout
    #[error("Call ringing timeout after {timeout_ms}ms")]
    RingingTimeout {
        timeout_ms: u64,
    },

    /// Connection attempt timeout
    #[error("Connection attempt timeout after {timeout_ms}ms")]
    ConnectTimeout {
        timeout_ms: u64,
    },

    /// QUIC path probe timeout
    #[error("QUIC path probe timeout to server IP {server_ip}")]
    PathProbeTimeout {
        server_ip: String,
    },

    /// DHT lookup timeout
    #[error("DHT lookup timeout for peer {peer_id}")]
    DhtLookupTimeout {
        peer_id: String,
    },

    // === NAT errors ===
    /// Both peers behind symmetric NAT with random port allocation
    #[error("Both peers behind IPv4 Symmetric NAT with random allocation — prediction impossible")]
    Ipv4RandomNat,

    /// UDP blocked by firewall
    #[error("UDP blocked by firewall")]
    UdpBlocked,

    /// Both UDP and TCP port 443 blocked
    #[error("UDP blocked AND TCP port 443 blocked — no MASQUE possible")]
    TcpBlocked,

    /// NAT probe cache expired
    #[error("NAT probe cache expired (TTL {ttl_secs}s)")]
    NatCacheExpired {
        ttl_secs: u64,
    },

    /// Port prediction miss — predicted range did not match
    #[error("Port prediction miss: predicted {predicted_start}-{predicted_end}, actual {actual_port}")]
    PredictionMiss {
        predicted_start: u32,
        predicted_end: u32,
        actual_port: u32,
    },

    // === MASQUE errors ===
    /// No MASQUE proxy available
    #[error("No MASQUE proxy available")]
    MasqueNoProxy,

    /// MASQUE proxy connection timeout
    #[error("MASQUE proxy connection timeout after {timeout_ms}ms")]
    MasqueProxyTimeout {
        timeout_ms: u64,
    },

    /// MASQUE proxy coordination failed
    #[error("MASQUE proxy coordination failed: {reason}")]
    MasqueCoordinationFailed {
        reason: String,
    },

    /// All MASQUE transports failed (HTTP/3 and HTTP/2)
    #[error("All MASQUE transports failed (HTTP/3 and HTTP/2)")]
    MasqueAllTransportsFailed,

    /// MASQUE tunnel disconnected during active call
    #[error("MASQUE tunnel disconnected: {reason}")]
    MasqueTunnelDisconnected {
        reason: String,
    },

    // === Signaling errors ===
    /// Unknown peer
    #[error("Unknown peer: {peer_id}")]
    UnknownPeer {
        peer_id: String,
    },

    /// Peer is offline
    #[error("Peer is offline: {peer_id}")]
    PeerOffline {
        peer_id: String,
    },

    /// Invalid call ID
    #[error("Invalid call ID: {call_id}")]
    InvalidCallId {
        call_id: String,
    },

    /// Call already exists
    #[error("Call already exists: {call_id}")]
    CallAlreadyExists {
        call_id: String,
    },

    /// Not a participant in this call
    #[error("Not a participant in call {call_id}")]
    NotCallParticipant {
        call_id: String,
    },

    /// Rate limited
    #[error("Rate limited")]
    RateLimited,

    /// Authentication error
    #[error("Authentication error: {reason}")]
    Authentication {
        reason: String,
    },

    /// Invalid message format
    #[error("Invalid message: {reason}")]
    InvalidMessage {
        reason: String,
    },

    // === State machine errors ===
    /// Invalid state transition attempted
    #[error("Invalid state transition from {from:?} to {to:?}: {reason}")]
    InvalidStateTransition {
        from: CallState,
        to: CallState,
        reason: &'static str,
    },

    /// Push retry attempts exhausted
    #[error("Push retry exhausted after {attempts} attempts")]
    RetryExhausted {
        attempts: u32,
    },

    /// Call was rejected by the callee
    #[error("Call rejected by callee")]
    Rejected,

    // === Internal errors ===
    /// Internal server/client error
    #[error("Internal error: {reason}")]
    Internal {
        reason: String,
    },

    /// Cryptographic operation failed
    #[error("Crypto error: {reason}")]
    Crypto {
        reason: String,
    },

    /// Serialization/deserialization error
    #[error("Serialization error: {reason}")]
    Serialization {
        reason: String,
    },

    /// All connection methods failed
    #[error("All connection methods failed for peer {peer_id}")]
    AllMethodsFailed {
        peer_id: String,
    },
}

impl VoipError {
    /// Maps this error to a `CallEndReason` for inclusion in CallFailed/CallEnded messages.
    pub fn to_call_end_reason(&self) -> CallEndReason {
        match self {
            // Network errors → FailedNetwork or MigrationFailed
            VoipError::QuicHandshakeFailed { .. } => CallEndReason::FailedNetwork,
            VoipError::ConnectionLost { .. } => CallEndReason::FailedNetwork,
            VoipError::MigrationFailed { .. } => CallEndReason::MigrationFailed,
            VoipError::NetworkChanged => CallEndReason::MigrationFailed,

            // Timeout errors → Timeout
            VoipError::RingingTimeout { .. } => CallEndReason::Timeout,
            VoipError::ConnectTimeout { .. } => CallEndReason::Timeout,
            VoipError::PathProbeTimeout { .. } => CallEndReason::Timeout,
            VoipError::DhtLookupTimeout { .. } => CallEndReason::Timeout,

            // NAT errors
            VoipError::Ipv4RandomNat => CallEndReason::FailedIpv4Random,
            VoipError::UdpBlocked => CallEndReason::FailedUdpBlocked,
            VoipError::TcpBlocked => CallEndReason::FailedTcpBlocked,
            VoipError::NatCacheExpired { .. } => CallEndReason::Timeout,
            VoipError::PredictionMiss { .. } => CallEndReason::FailedIpv4Random,

            // MASQUE errors
            VoipError::MasqueNoProxy => CallEndReason::FailedMasqueUnreachable,
            VoipError::MasqueProxyTimeout { .. } => CallEndReason::FailedMasqueUnreachable,
            VoipError::MasqueCoordinationFailed { .. } => CallEndReason::FailedMasqueUnreachable,
            VoipError::MasqueAllTransportsFailed => CallEndReason::FailedTcpBlocked,
            VoipError::MasqueTunnelDisconnected { .. } => CallEndReason::FailedMasqueUnreachable,

            // Signaling errors
            VoipError::UnknownPeer { .. } => CallEndReason::FailedNetwork,
            VoipError::PeerOffline { .. } => CallEndReason::Timeout,
            VoipError::InvalidCallId { .. } => CallEndReason::FailedNetwork,
            VoipError::CallAlreadyExists { .. } => CallEndReason::FailedNetwork,
            VoipError::NotCallParticipant { .. } => CallEndReason::FailedNetwork,
            VoipError::RateLimited => CallEndReason::FailedNetwork,
            VoipError::Authentication { .. } => CallEndReason::FailedNetwork,
            VoipError::InvalidMessage { .. } => CallEndReason::FailedNetwork,

            // State machine errors
            VoipError::InvalidStateTransition { .. } => CallEndReason::FailedNetwork,
            VoipError::RetryExhausted { .. } => CallEndReason::FailedIpv4Random,
            VoipError::Rejected => CallEndReason::Rejected,

            // Internal errors
            VoipError::Internal { .. } => CallEndReason::FailedNetwork,
            VoipError::Crypto { .. } => CallEndReason::FailedNetwork,
            VoipError::Serialization { .. } => CallEndReason::FailedNetwork,
            VoipError::AllMethodsFailed { .. } => CallEndReason::FailedIpv4Random,
        }
    }

    /// Returns the error code for signaling server Error messages.
    ///
    /// Maps this error to the appropriate code from spec/08 §8.5.
    pub fn to_error_code(&self) -> u32 {
        match self {
            VoipError::UnknownPeer { .. } => error_codes::UNKNOWN_PEER,
            VoipError::PeerOffline { .. } => error_codes::PEER_OFFLINE,
            VoipError::InvalidCallId { .. } => error_codes::INVALID_CALL_ID,
            VoipError::CallAlreadyExists { .. } => error_codes::CALL_ALREADY_EXISTS,
            VoipError::NotCallParticipant { .. } => error_codes::NOT_CALL_PARTICIPANT,
            VoipError::RateLimited => error_codes::RATE_LIMITED,
            VoipError::Authentication { .. } => error_codes::INVALID_JWT,
            VoipError::InvalidMessage { .. } => error_codes::INVALID_MESSAGE,
            VoipError::MasqueNoProxy => error_codes::MASQUE_NO_PROXY,
            VoipError::MasqueProxyTimeout { .. } => error_codes::MASQUE_PROXY_TIMEOUT,
            VoipError::MasqueCoordinationFailed { .. } => error_codes::MASQUE_COORDINATION_FAILED,
            _ => error_codes::INTERNAL_ERROR,
        }
    }

    /// Returns true if this error is recoverable (retry with backoff).
    ///
    /// See spec/11 §11.5 for the error handling rules.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            VoipError::PathProbeTimeout { .. }
                | VoipError::DhtLookupTimeout { .. }
                | VoipError::NatCacheExpired { .. }
                | VoipError::PredictionMiss { .. }
        )
    }

    /// Returns true if this error can be resolved by connection migration.
    pub fn is_migratable(&self) -> bool {
        matches!(
            self,
            VoipError::NetworkChanged | VoipError::MigrationFailed { .. }
        )
    }

    /// Returns true if this error is fatal (call fails honestly).
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            VoipError::Ipv4RandomNat
                | VoipError::UdpBlocked
                | VoipError::TcpBlocked
                | VoipError::MasqueNoProxy
                | VoipError::MasqueAllTransportsFailed
                | VoipError::Rejected
                | VoipError::RetryExhausted { .. }
                | VoipError::AllMethodsFailed { .. }
        )
    }

    /// Returns true if push retry should be attempted for this error.
    pub fn should_push_retry(&self) -> bool {
        matches!(
            self,
            VoipError::Ipv4RandomNat
                | VoipError::PredictionMiss { .. }
                | VoipError::RetryExhausted { .. }
        )
    }
}

/// Error type for signaling protocol operations.
#[derive(Debug, thiserror::Error)]
pub enum SignalingError {
    /// WebSocket connection failed
    #[error("WebSocket connection failed: {reason}")]
    ConnectionFailed {
        reason: String,
    },

    /// WebSocket connection closed unexpectedly
    #[error("WebSocket connection closed unexpectedly")]
    ConnectionClosed,

    /// Message encoding error
    #[error("Message encoding error: {0}")]
    EncodeError(String),

    /// Message decoding error
    #[error("Message decoding error: {0}")]
    DecodeError(String),

    /// Unknown message type
    #[error("Unknown message type: {type_id:#06x}")]
    UnknownMessageType {
        type_id: u16,
    },
}

/// Error type for DHT operations.
#[derive(Debug, thiserror::Error)]
pub enum DhtError {
    /// DHT lookup failed
    #[error("DHT lookup failed for key {key}: {reason}")]
    LookupFailed {
        key: String,
        reason: String,
    },

    /// DHT registration failed
    #[error("DHT registration failed: {reason}")]
    RegistrationFailed {
        reason: String,
    },

    /// DHT bootstrap failed
    #[error("DHT bootstrap failed: {reason}")]
    BootstrapFailed {
        reason: String,
    },

    /// No connected DHT peers
    #[error("No connected DHT peers")]
    NoPeers,

    /// Record verification failed
    #[error("Record verification failed: {reason}")]
    VerificationFailed {
        reason: String,
    },

    /// Record expired
    #[error("Record expired at {expired_at}")]
    RecordExpired {
        expired_at: u64,
    },
}

/// Error type for MASQUE tunnel operations.
#[derive(Debug, thiserror::Error)]
pub enum MasqueError {
    /// No proxy available
    #[error("No MASQUE proxy available")]
    NoProxy,

    /// Proxy connection timeout
    #[error("Proxy connection timeout after {timeout_ms}ms")]
    ProxyTimeout {
        timeout_ms: u64,
    },

    /// CONNECT-UDP request rejected
    #[error("CONNECT-UDP request rejected: status {status}")]
    ConnectRejected {
        status: u16,
    },

    /// All transports failed (HTTP/3 and HTTP/2)
    #[error("All MASQUE transports failed")]
    AllTransportsFailed,

    /// Tunnel disconnected
    #[error("MASQUE tunnel disconnected: {reason}")]
    TunnelDisconnected {
        reason: String,
    },

    /// Proxy capacity exceeded
    #[error("Proxy capacity exceeded (max {max_sessions})")]
    CapacityExceeded {
        max_sessions: u32,
    },

    /// Proxy token validation failed
    #[error("Proxy token validation failed: {reason}")]
    TokenValidationFailed {
        reason: String,
    },
}

impl From<MasqueError> for VoipError {
    fn from(value: MasqueError) -> Self {
        match value {
            MasqueError::NoProxy => VoipError::MasqueNoProxy,
            MasqueError::ProxyTimeout { timeout_ms } => VoipError::MasqueProxyTimeout { timeout_ms },
            MasqueError::AllTransportsFailed => VoipError::MasqueAllTransportsFailed,
            MasqueError::TunnelDisconnected { reason } => {
                VoipError::MasqueTunnelDisconnected { reason }
            }
            MasqueError::ConnectRejected { .. } => VoipError::MasqueCoordinationFailed {
                reason: "CONNECT-UDP rejected".to_string(),
            },
            MasqueError::CapacityExceeded { .. } => VoipError::MasqueNoProxy,
            MasqueError::TokenValidationFailed { reason } => VoipError::MasqueCoordinationFailed {
                reason,
            },
        }
    }
}
