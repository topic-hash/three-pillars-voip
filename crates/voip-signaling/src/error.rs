//! Signaling-specific error types.
//!
//! Error codes are defined in spec/08_API_Specification.md §8.5.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use thiserror::Error;

// ── Wire-level error codes (sent in Error message type 0x8001) ──────────

/// Error codes sent to clients in the `Error` protobuf message (type ID 0x8001).
/// See spec/08 §8.5 for the authoritative list.
pub mod codes {
    // Peer errors (1xxx)
    pub const UNKNOWN_PEER: u32 = 1001;
    pub const PEER_OFFLINE: u32 = 1002;
    pub const INVALID_CALL_ID: u32 = 1003;
    pub const CALL_ALREADY_EXISTS: u32 = 1004;
    pub const NOT_CALL_PARTICIPANT: u32 = 1005;

    // Rate-limit / auth errors (2xxx)
    pub const RATE_LIMITED: u32 = 2001;
    pub const INVALID_JWT: u32 = 2002;
    pub const INVALID_MESSAGE: u32 = 2003;

    // MASQUE errors (3xxx)
    pub const MASQUE_NO_PROXY: u32 = 3001;
    pub const MASQUE_PROXY_TIMEOUT: u32 = 3002;
    pub const MASQUE_COORDINATION_FAILED: u32 = 3003;

    // Internal
    pub const INTERNAL_ERROR: u32 = 9999;
}

// ── JSON error response body for REST endpoints ─────────────────────────

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub code: u32,
    pub message: String,
}

// ── Signaling error enum ────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SignalingError {
    #[error("unknown peer: {0}")]
    UnknownPeer(String),

    #[error("peer offline: {0}")]
    PeerOffline(String),

    #[error("invalid call ID: {0}")]
    InvalidCallId(String),

    #[error("call already exists: {0}")]
    CallAlreadyExists(String),

    #[error("not a call participant: {0}")]
    NotCallParticipant(String),

    #[error("rate limited")]
    RateLimited,

    #[error("invalid JWT: {0}")]
    InvalidJwt(String),

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("MASQUE no proxy available")]
    MasqueNoProxy,

    #[error("MASQUE proxy timeout")]
    MasqueProxyTimeout,

    #[error("MASQUE coordination failed")]
    MasqueCoordinationFailed,

    #[error("internal error: {0}")]
    Internal(String),
}

impl SignalingError {
    /// Return the wire-level error code for this error.
    pub fn code(&self) -> u32 {
        match self {
            Self::UnknownPeer(_) => codes::UNKNOWN_PEER,
            Self::PeerOffline(_) => codes::PEER_OFFLINE,
            Self::InvalidCallId(_) => codes::INVALID_CALL_ID,
            Self::CallAlreadyExists(_) => codes::CALL_ALREADY_EXISTS,
            Self::NotCallParticipant(_) => codes::NOT_CALL_PARTICIPANT,
            Self::RateLimited => codes::RATE_LIMITED,
            Self::InvalidJwt(_) => codes::INVALID_JWT,
            Self::InvalidMessage(_) => codes::INVALID_MESSAGE,
            Self::MasqueNoProxy => codes::MASQUE_NO_PROXY,
            Self::MasqueProxyTimeout => codes::MASQUE_PROXY_TIMEOUT,
            Self::MasqueCoordinationFailed => codes::MASQUE_COORDINATION_FAILED,
            Self::Internal(_) => codes::INTERNAL_ERROR,
        }
    }

    /// Return the HTTP status code for REST responses.
    pub fn http_status(&self) -> StatusCode {
        match self {
            Self::UnknownPeer(_) | Self::PeerOffline(_) => StatusCode::NOT_FOUND,
            Self::InvalidCallId(_) | Self::InvalidMessage(_) => StatusCode::BAD_REQUEST,
            Self::CallAlreadyExists(_) => StatusCode::CONFLICT,
            Self::NotCallParticipant(_) => StatusCode::FORBIDDEN,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::InvalidJwt(_) => StatusCode::UNAUTHORIZED,
            Self::MasqueNoProxy | Self::MasqueProxyTimeout | Self::MasqueCoordinationFailed => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for SignalingError {
    fn into_response(self) -> Response {
        let status = self.http_status();
        let body = ErrorResponse {
            code: self.code(),
            message: self.to_string(),
        };
        (status, Json(body)).into_response()
    }
}

/// Convenience type alias used across the crate.
pub type Result<T> = std::result::Result<T, SignalingError>;
