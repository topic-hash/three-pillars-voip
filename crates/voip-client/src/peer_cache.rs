//! Client-side peer address book with discovery_method tracking and TTL.
//!
//! Per ROADMAP 3.14 and spec/06: previously discovered peers are cached
//! locally so they can be found in <5ms on subsequent lookups, without
//! hitting the signaling server or DHT.
//!
//! # Thread Safety
//!
//! The address book uses `RwLock<HashMap>` for thread-safe concurrent access.
//! Reads (lookups) are fast because they only acquire a read lock.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use tracing::{debug, info, instrument, warn};

use voip_core::proto::signaling::PeerRecord;
use voip_core::DiscoveryMethod;

/// Client-side peer address book with discovery_method tracking and TTL.
///
/// Per ROADMAP 3.14: previously discovered peers found in <5ms.
///
/// Each cached entry tracks *how* the peer was discovered (DHT, signaling
/// server, or cache hit) and when, so the client can:
/// - Prefer fresher records over stale ones
/// - Fall back from cache to DHT/signaling when TTL expires
/// - Report the discovery method for diagnostics
pub struct PeerAddressBook {
    /// Map from peer_id to cached peer entry.
    peers: RwLock<HashMap<String, CachedPeer>>,
    /// Default time-to-live for cache entries.
    default_ttl: Duration,
}

/// A cached peer entry with metadata about how and when it was discovered.
struct CachedPeer {
    /// The peer record from the signaling server or DHT.
    record: PeerRecord,
    /// How this peer was originally discovered.
    discovered_via: DiscoveryMethod,
    /// When this entry was added/refreshed.
    discovered_at: Instant,
    /// Time-to-live for this entry (may differ from the book default).
    ttl: Duration,
}

impl CachedPeer {
    /// Returns `true` if this entry has exceeded its TTL.
    fn is_expired(&self) -> bool {
        self.discovered_at.elapsed() > self.ttl
    }
}

impl PeerAddressBook {
    /// Create a new, empty `PeerAddressBook`.
    ///
    /// # Arguments
    ///
    /// * `default_ttl` — The default time-to-live for cache entries.
    ///   A typical value is 5 minutes (300 s), matching `nat_cache_ttl_secs`.
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            default_ttl,
        }
    }

    /// Create an address book with a 5-minute default TTL.
    pub fn default_settings() -> Self {
        Self::new(Duration::from_secs(300))
    }

    /// Insert or update a peer in the address book.
    ///
    /// If the peer already exists, its record is updated and the
    /// discovery timestamp is refreshed. The `discovered_via` field
    /// is always updated to reflect the most recent discovery method.
    ///
    /// # Arguments
    ///
    /// * `record` — The peer record to cache.
    /// * `discovered_via` — How the peer was discovered this time.
    #[instrument(skip(self, record), fields(peer_id = %record.peer_id))]
    pub fn insert(&self, record: PeerRecord, discovered_via: DiscoveryMethod) {
        let peer_id = record.peer_id.clone();

        let entry = CachedPeer {
            record,
            discovered_via,
            discovered_at: Instant::now(),
            ttl: self.default_ttl,
        };

        let mut peers = self.peers.write().expect("PeerAddressBook lock poisoned");
        peers.insert(peer_id, entry);

        debug!("Peer inserted/updated in address book");
    }

    /// Look up a peer by ID.
    ///
    /// Returns the cached `PeerRecord` and its `DiscoveryMethod` if the
    /// entry exists and has not expired. Returns `None` otherwise.
    ///
    /// Per ROADMAP 3.14: a cache hit should take <5ms (no network I/O).
    #[instrument(skip(self), fields(peer_id = %peer_id))]
    pub fn get(&self, peer_id: &str) -> Option<(PeerRecord, DiscoveryMethod)> {
        let peers = self.peers.read().expect("PeerAddressBook lock poisoned");

        let cached = peers.get(peer_id)?;
        if cached.is_expired() {
            debug!("Peer cache entry expired");
            return None;
        }

        Some((cached.record.clone(), cached.discovered_via))
    }

    /// Invalidate (remove) a specific peer from the address book.
    ///
    /// Call this when a peer is known to be offline or its record
    /// has changed on the signaling server and the cache is stale.
    #[instrument(skip(self), fields(peer_id = %peer_id))]
    pub fn invalidate(&self, peer_id: &str) {
        let mut peers = self.peers.write().expect("PeerAddressBook lock poisoned");
        if peers.remove(peer_id).is_some() {
            debug!("Peer invalidated in address book");
        }
    }

    /// Remove all expired entries from the address book.
    ///
    /// Returns the number of entries removed.
    ///
    /// Call this periodically (e.g., every 60 s) to prevent unbounded
    /// memory growth.
    pub fn cleanup_expired(&self) -> usize {
        let mut peers = self.peers.write().expect("PeerAddressBook lock poisoned");
        let before = peers.len();

        peers.retain(|_, entry| {
            !entry.is_expired()
        });

        let removed = before - peers.len();
        if removed > 0 {
            info!(removed, remaining = peers.len(), "Cleaned up expired peer cache entries");
        }
        removed
    }

    /// Get the number of entries in the address book (including expired
    /// entries that haven't been cleaned up yet).
    pub fn len(&self) -> usize {
        self.peers.read().expect("PeerAddressBook lock poisoned").len()
    }

    /// Check if the address book is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the default TTL for new entries.
    pub fn default_ttl(&self) -> Duration {
        self.default_ttl
    }

    /// Clear the entire address book.
    pub fn clear(&self) {
        let mut peers = self.peers.write().expect("PeerAddressBook lock poisoned");
        peers.clear();
        info!("Peer address book cleared");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use voip_core::proto::signaling::{NatInfo, PeerStatus};

    fn make_peer_record(peer_id: &str, ttl_seconds: u32) -> PeerRecord {
        PeerRecord {
            peer_id: peer_id.to_string(),
            display_name: format!("Peer {}", peer_id),
            ipv6_addresses: vec![],
            ipv4_reflexive: vec!["203.0.113.5:42000".to_string()],
            nat_info: Some(NatInfo::default()),
            tracks: vec![],
            status: PeerStatus::PeerOnline as i32,
            timestamp: 0,
            ttl_seconds,
            signature: vec![],
        }
    }

    #[test]
    fn test_insert_and_get() {
        let book = PeerAddressBook::default_settings();
        let record = make_peer_record("peer-abc", 300);

        book.insert(record.clone(), DiscoveryMethod::Dht);
        let result = book.get("peer-abc");

        assert!(result.is_some());
        let (cached_record, method) = result.expect("just checked");
        assert_eq!(cached_record.peer_id, "peer-abc");
        assert_eq!(method, DiscoveryMethod::Dht);
    }

    #[test]
    fn test_get_missing_peer() {
        let book = PeerAddressBook::default_settings();
        assert!(book.get("nonexistent").is_none());
    }

    #[test]
    fn test_invalidate() {
        let book = PeerAddressBook::default_settings();
        let record = make_peer_record("peer-xyz", 300);

        book.insert(record, DiscoveryMethod::Signaling);
        assert!(book.get("peer-xyz").is_some());

        book.invalidate("peer-xyz");
        assert!(book.get("peer-xyz").is_none());
    }

    #[test]
    fn test_cleanup_expired() {
        let book = PeerAddressBook::new(Duration::from_millis(50));
        let record = make_peer_record("peer-exp", 0); // ttl_seconds=0 will use min 60s, but Instant-based TTL is 50ms from book

        book.insert(record, DiscoveryMethod::Cache);

        // Not expired yet
        assert!(book.get("peer-exp").is_some());

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(80));

        // get() should return None due to expiry
        assert!(book.get("peer-exp").is_none());

        // cleanup should remove the expired entry
        let removed = book.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(book.len(), 0);
    }

    #[test]
    fn test_update_existing_peer() {
        let book = PeerAddressBook::default_settings();

        let mut record1 = make_peer_record("peer-update", 300);
        record1.display_name = "Original".to_string();
        book.insert(record1, DiscoveryMethod::Dht);

        let mut record2 = make_peer_record("peer-update", 300);
        record2.display_name = "Updated".to_string();
        book.insert(record2, DiscoveryMethod::Signaling);

        let (cached, method) = book.get("peer-update").expect("should exist");
        assert_eq!(cached.display_name, "Updated");
        assert_eq!(method, DiscoveryMethod::Signaling);
    }

    #[test]
    fn test_clear() {
        let book = PeerAddressBook::default_settings();
        book.insert(make_peer_record("p1", 300), DiscoveryMethod::Dht);
        book.insert(make_peer_record("p2", 300), DiscoveryMethod::Signaling);

        assert_eq!(book.len(), 2);
        book.clear();
        assert_eq!(book.len(), 0);
    }

    #[test]
    fn test_multiple_discovery_methods() {
        let book = PeerAddressBook::default_settings();

        book.insert(make_peer_record("p-dht", 300), DiscoveryMethod::Dht);
        book.insert(make_peer_record("p-sig", 300), DiscoveryMethod::Signaling);
        book.insert(make_peer_record("p-cache", 300), DiscoveryMethod::Cache);

        assert_eq!(book.get("p-dht").map(|(_, m)| m), Some(DiscoveryMethod::Dht));
        assert_eq!(book.get("p-sig").map(|(_, m)| m), Some(DiscoveryMethod::Signaling));
        assert_eq!(book.get("p-cache").map(|(_, m)| m), Some(DiscoveryMethod::Cache));
    }
}
