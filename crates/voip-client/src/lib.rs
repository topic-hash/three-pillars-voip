//! voip-client: Client library for the Three Pillars VoIP Relay-Free Architecture.
//!
//! This crate handles:
//! - QUIC connections (quinn-based) with connection migration support
//! - NAT traversal via QUIC path probing (replaces STUN)
//! - MASQUE CONNECT-UDP tunnels (HTTP/3 and HTTP/2 fallback)
//! - Media over QUIC (MoQ) session management
//! - Opus audio codec
//! - Port prediction probing for Symmetric NAT
//! - QUIC connection migration for network changes
//!
//! # Connection Fallback Chain
//!
//! The client attempts connections in this order:
//! 1. IPv6 Direct
//! 2. QUIC Simultaneous Open (Cone NAT)
//! 3. QUIC Port Prediction (Symmetric NAT)
//! 4. MASQUE/HTTP3 relay
//! 5. MASQUE/HTTP2 relay
//! 6. Push Retry
//!
//! See spec/09_Data_Flows.md §9.9 for the full decision tree.

pub mod audio;
pub mod client;
pub mod connection;
pub mod error;
pub mod masque;
pub mod migration;
pub mod moq;
pub mod nat_probe;
pub mod peer_cache;
pub mod pipeline;
pub mod probe;
pub mod proxy;
pub mod push_retry;
pub mod signaling_client;
pub mod tls;

// Re-export key types from voip-core for convenience
pub use voip_core::config::VoIPConfig;
pub use voip_core::types::{
    NATInfo, NATType, CallEndReason, CallState, ConnectionMethod, DiscoveryMethod,
    MasqueTransport, MediaType, NATProbingState, PeerStatus, PortPredictionData,
    PredictionConfidence, ProbeMethod, ProxyLifecycleState, PushRetryState,
    TrackInfo, TunnelStatus,
};
pub use voip_core::error::VoipError;
pub use voip_core::state::CallStateMachine;

// Re-export local error types
pub use error::{
    AudioError, CertError, ClientError, ConnectError, MasqueError, MigrationError, MoqError, NatProbeError,
    PipelineError, ProbeError, ProxyError, ProxyTokenError,
};
