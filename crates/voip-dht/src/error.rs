//! DHT-specific error types.

use thiserror::Error;

/// Errors that can occur during DHT operations.
#[derive(Debug, Error)]
pub enum DhtError {
    /// The DHT lookup timed out before returning a result.
    #[error("DHT lookup timed out after {timeout_ms}ms")]
    Timeout {
        /// How long we waited before giving up.
        timeout_ms: u64,
    },

    /// The requested record was not found in the DHT.
    #[error("Record not found for key: {key}")]
    NotFound {
        /// The DHT key that was looked up.
        key: String,
    },

    /// A record's Ed25519 signature is invalid.
    #[error("Invalid signature for record: {record_type}")]
    InvalidSignature {
        /// The type of record that failed verification.
        record_type: String,
    },

    /// The DHT node is not connected / not bootstrapped.
    #[error("DHT node not connected")]
    NotConnected,

    /// Failed to put a record into the DHT.
    #[error("Failed to put record: {reason}")]
    PutFailed {
        /// Why the put failed.
        reason: String,
    },

    /// The record has expired (TTL exceeded).
    #[error("Record expired: published at {published_at}, TTL {ttl_secs}s")]
    Expired {
        /// Unix timestamp when the record was published.
        published_at: u64,
        /// Record time-to-live in seconds.
        ttl_secs: u32,
    },

    /// Serialization or deserialization error for a DHT record.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// A libp2p swarm error.
    #[error("Swarm error: {0}")]
    Swarm(String),

    /// An error from the underlying transport.
    #[error("Transport error: {0}")]
    Transport(String),

    /// Bootstrapping the DHT failed.
    #[error("Bootstrap failed: {0}")]
    BootstrapFailed(String),

    /// The record data is invalid or corrupt.
    #[error("Invalid record data: {0}")]
    InvalidRecord(String),

    /// Core error propagation.
    #[error(transparent)]
    Core(#[from] voip_core::CoreError),
}

impl DhtError {
    /// Create a timeout error with the given duration.
    pub fn timeout(timeout_ms: u64) -> Self {
        Self::Timeout { timeout_ms }
    }

    /// Create a not-found error for the given key.
    pub fn not_found(key: impl Into<String>) -> Self {
        Self::NotFound { key: key.into() }
    }

    /// Create an invalid-signature error for the given record type.
    pub fn invalid_signature(record_type: impl Into<String>) -> Self {
        Self::InvalidSignature {
            record_type: record_type.into(),
        }
    }
}
