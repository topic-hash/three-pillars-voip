//! DHT-specific error types.
//!
//! These errors cover all failure modes for the DHT discovery layer
//! as specified in spec/06 §6.2 and the ROADMAP Steps 1.4–1.9.

use thiserror::Error;

/// Errors that can occur during DHT operations.
#[derive(Debug, Error)]
pub enum DhtError {
    // === Node lifecycle errors ===

    /// The DHT node has not been started or is not connected.
    #[error("DHT node not started")]
    DhtNotStarted,

    /// Bootstrapping into the DHT network failed.
    #[error("DHT bootstrap failed: {0:?}")]
    BootstrapFailed(Vec<String>),

    /// No peers are currently connected to this DHT node.
    #[error("No peers connected to DHT")]
    NoPeersConnected,

    // === Lookup errors ===

    /// A DHT lookup timed out before returning a result.
    #[error("DHT lookup timed out for key {key} after {elapsed_ms}ms")]
    LookupTimeout {
        /// The key that was being looked up.
        key: String,
        /// How long we waited before giving up.
        elapsed_ms: u64,
    },

    /// A DHT lookup failed for a reason other than timeout.
    #[error("DHT lookup failed for key {key}: {reason}")]
    LookupFailed {
        /// The key that was being looked up.
        key: String,
        /// Why the lookup failed.
        reason: String,
    },

    /// The requested record was not found in the DHT.
    #[error("Record not found for key: {key}")]
    NotFound {
        /// The DHT key that was looked up.
        key: String,
    },

    // === Store errors ===

    /// Storing a record in the DHT failed.
    #[error("DHT store failed for key {key}: {reason}")]
    StoreFailed {
        /// The key that failed to be stored.
        key: String,
        /// Why the store failed.
        reason: String,
    },

    // === Record validation errors ===

    /// A record has expired (TTL exceeded).
    #[error("Record expired at {expired_at} for key: {key}")]
    RecordExpired {
        /// The DHT key of the expired record.
        key: String,
        /// Unix timestamp when the record expired.
        expired_at: u64,
    },

    /// A record's Ed25519 signature is invalid.
    #[error("Invalid signature for record: {key}")]
    InvalidSignature {
        /// The DHT key of the record with the bad signature.
        key: String,
    },

    /// The requested username was not found.
    #[error("Username not found: {username}")]
    UsernameNotFound {
        /// The username that was searched for.
        username: String,
    },

    // === Fallback errors ===

    /// The DHT lookup failed and a fallback to the signaling server is required.
    #[error("DHT lookup failed; signaling fallback required")]
    SignalingFallbackRequired,

    // === Infrastructure errors ===

    /// Serialization or deserialization error for a DHT record.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// A libp2p swarm error.
    #[error("Swarm error: {0}")]
    Swarm(String),

    /// An error from the underlying transport.
    #[error("Transport error: {0}")]
    Transport(String),

    /// Bootstrapping the DHT failed (legacy single-reason variant).
    #[error("Bootstrap failed: {0}")]
    BootstrapFailedSingle(String),

    /// The record data is invalid or corrupt.
    #[error("Invalid record data: {0}")]
    InvalidRecord(String),

    /// The DHT node is not connected / not bootstrapped.
    #[error("DHT node not connected")]
    NotConnected,

    /// Failed to put a record into the DHT (legacy variant).
    #[error("Failed to put record: {reason}")]
    PutFailed {
        /// Why the put failed.
        reason: String,
    },

    /// A record's Ed25519 signature is invalid (legacy variant for record_type).
    #[error("Invalid signature for record type: {record_type}")]
    InvalidSignatureLegacy {
        /// The type of record that failed verification.
        record_type: String,
    },

    /// The record has expired (legacy variant).
    #[error("Record expired: published at {published_at}, TTL {ttl_secs}s")]
    Expired {
        /// Unix timestamp when the record was published.
        published_at: u64,
        /// Record time-to-live in seconds.
        ttl_secs: u32,
    },

    /// Core error propagation.
    #[error(transparent)]
    Core(#[from] voip_core::VoipError),

    /// An HTTP request to the signaling server failed.
    #[error("HTTP error: {0}")]
    Http(String),
}

impl DhtError {
    /// Create a timeout error with the given key and duration.
    pub fn timeout(key: impl Into<String>, elapsed_ms: u64) -> Self {
        Self::LookupTimeout {
            key: key.into(),
            elapsed_ms,
        }
    }

    /// Create a not-found error for the given key.
    pub fn not_found(key: impl Into<String>) -> Self {
        Self::NotFound { key: key.into() }
    }

    /// Create an invalid-signature error for the given key.
    pub fn invalid_signature(key: impl Into<String>) -> Self {
        Self::InvalidSignature { key: key.into() }
    }
}
