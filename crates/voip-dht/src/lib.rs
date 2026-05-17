//! # voip-dht
//!
//! Distributed Hash Table node using libp2p KadDHT for the
//! Three Pillars VoIP Relay-Free Architecture.
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

pub mod node;
pub mod discovery;
pub mod record;
pub mod error;

pub use node::DhtNode;
pub use discovery::Discovery;
pub use error::DhtError;
