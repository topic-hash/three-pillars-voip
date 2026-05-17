//! voip-core: Shared types and Protobuf definitions for Three Pillars VoIP.
//!
//! This crate contains:
//!   - Protobuf-generated types from `proto/signaling.proto`
//!   - Rust-native type wrappers with ergonomic APIs
//!   - Configuration constants (spec/11 §11.3)
//!   - Call state machine (spec/07 §7.3.1)
//!   - Error types mapping to spec error codes (spec/08 §8.5)
//!   - Cryptographic utilities (spec/08 §8.6, §8.7)

/// Protobuf-generated signaling messages from `proto/signaling.proto`.
///
/// Wire format: 2-byte message type (uint16, big-endian) + prost-encoded payload.
/// See spec/08_API_Specification.md §8.1.1 for type ID assignments.
pub mod signaling {
    include!(concat!(env!("OUT_DIR"), "/voip.signaling.rs"));
}

/// Re-export of the protobuf types as `proto`, used by other modules
/// in this crate and by dependent crates for concise type references.
pub mod proto {
    pub use crate::signaling::*;
}

pub mod config;
pub mod crypto;
pub mod error;
pub mod state;
pub mod types;
