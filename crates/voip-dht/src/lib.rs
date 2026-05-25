//! # voip-dht
//!
//! Distributed Hash Table node using libp2p KadDHT for the
//! Three Pillars VoIP Minimal-Relay Architecture.
//!
//! This crate implements the DHT discovery layer described in
//! spec/06_Discovery_Signaling.md §6.2:
//!
//! - **Peer record storage**: `SHA-256("voip:{peer_id}")` → signed `PeerRecord`
//! - **Username resolution**: `SHA-256("voip-name:{username}")` → signed `UsernameRecord`
//! - **Proxy record storage**: `SHA-256("masque-proxy:{node_id}")` → signed `ProxyRecord`
//!
//! Mobile clients perform lookups only; desktop/laptop clients run full DHT nodes
//! that maintain routing tables and answer queries.
//!
//! # ROADMAP Steps Implemented
//!
//! - **Step 1.4**: libp2p KadDHT node: bootstrap, lookup, store (DISC-01, DISC-05)
//! - **Step 1.5**: DHT record signing and verification
//! - **Step 1.6**: DHT fallback: timeout → signaling server (DISC-03)
//! - **Step 1.7**: Username → Peer ID resolution: two-step DHT lookup
//! - **Step 1.8**: DHT record refresh: re-publish before TTL expiry (every 30 min)
//! - **Step 1.9**: Mobile DHT constraint: lookup-only API, no full routing node

pub mod node;
pub mod discovery;
pub mod record;
pub mod error;

pub use node::DhtNode;
pub use discovery::{DiscoveryService, DiscoveryMode, SignalingClient};
pub use error::DhtError;
pub use record::{
    peer_record_key, username_record_key, proxy_record_key,
    sign_peer_record, verify_peer_record,
    sign_proxy_record, verify_proxy_record,
    sign_username_record, verify_username_record,
    PeerRecord, UsernameRecord, ProxyRecord,
    NatInfo, NatType, PortPrediction, PredictionConfidence,
    TrackAnnouncement, MediaType, PeerStatus,
};
