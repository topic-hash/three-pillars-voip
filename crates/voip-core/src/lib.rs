//! Three Pillars VoIP — Core types and definitions
//!
//! This crate contains shared types, Protobuf definitions, state machines,
//! configuration, error types, and crypto utilities. No I/O, no network,
//! no filesystem — pure types only.

pub mod proto {
    pub mod signaling {
        include!(concat!(env!("OUT_DIR"), "/voip.signaling.rs"));
    }
    pub mod internal {
        include!(concat!(env!("OUT_DIR"), "/voip.internal.rs"));
    }
}

pub mod config;
pub mod crypto;
pub mod error;
pub mod state;
pub mod types;

// Re-exports for convenience
pub use config::VoIPConfig;
pub use crypto::{generate_connection_id, generate_ed25519_keypair, peer_id_from_public_key};
pub use error::VoipError;
pub use state::CallStateMachine;
pub use types::*;
