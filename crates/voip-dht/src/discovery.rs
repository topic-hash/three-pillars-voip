//! Discovery layer for the Three Pillars VoIP DHT.
//!
//! Implements the two-tier discovery architecture from spec §6.1:
//!
//! | Mode            | Order                           | Default? |
//! |----------------|----------------------------------|----------|
//! | Privacy-first  | DHT → Signaling server fallback  | Yes      |
//! | Speed-first    | Signaling server → DHT fallback  | No       |
//!
//! **Why default is Privacy-first:** The signaling server behind Cloudflare
//! gives one US corporation and any government with jurisdiction complete
//! visibility into the user's social graph. The DHT distributes this
//! information across thousands of nodes — no single entity sees the
//! full picture.
//!
//! # Operations
//!
//! - `discover_peer(peer_id)`: Lookup a peer's connection data via DHT
//!   and/or signaling server. Falls back according to the configured mode.
//! - `discover_peer_by_username(username)`: Two-step DHT lookup — username → peer_id,
//!   then peer_id → full PeerRecord.
//! - `discover_proxy()`: Find available MASQUE proxy nodes. Queries DHT
//!   for proxy records, optionally falls back to signaling server.
//! - `get_bootstrap_nodes()`: Get DHT bootstrap nodes from the signaling server.

use std::time::Duration;

use tokio::time::timeout;
use tracing::{debug, info, warn};

use voip_core::VoIPConfig;

use crate::error::DhtError;
use crate::node::DhtNode;
use crate::record::{PeerRecord, ProxyRecord, UsernameRecord};

// ---------------------------------------------------------------------------
// Discovery mode
// ---------------------------------------------------------------------------

/// The discovery priority mode.
///
/// Configurable per-user via a single application setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMode {
    /// DHT first (~80ms), fall back to signaling server if DHT fails.
    /// Default. Higher privacy — no single entity sees the social graph.
    PrivacyFirst,
    /// Signaling server first (~5ms), fall back to DHT if server unreachable.
    /// Lower latency but the signaling server operator sees lookups.
    SpeedFirst,
}

impl Default for DiscoveryMode {
    fn default() -> Self {
        Self::PrivacyFirst
    }
}

impl From<bool> for DiscoveryMode {
    fn from(privacy_first: bool) -> Self {
        if privacy_first {
            DiscoveryMode::PrivacyFirst
        } else {
            DiscoveryMode::SpeedFirst
        }
    }
}

// ---------------------------------------------------------------------------
// Signaling server client (stub)
// ---------------------------------------------------------------------------

/// A minimal signaling server client for fallback lookups.
///
/// In production, this would use QUIC/WebSocket to the signaling server.
/// For now, it provides the interface and a stub implementation.
#[derive(Debug, Clone)]
pub struct SignalingClient {
    /// Base URL of the signaling server (e.g., "https://signal.example.com").
    server_url: String,
}

impl SignalingClient {
    /// Create a new signaling client pointing at the given server URL.
    pub fn new(server_url: String) -> Self {
        Self { server_url }
    }

    /// Look up a peer by ID on the signaling server.
    ///
    /// Corresponds to `GET /v1/peers/{peer_id}`.
    pub async fn lookup_peer(&self, _peer_id: &str) -> Result<PeerRecord, DhtError> {
        // TODO: Implement actual HTTP request to signaling server.
        // For now, return not found to exercise the fallback path.
        warn!("Signaling server lookup not yet implemented");
        Err(DhtError::not_found("signaling:peer"))
    }

    /// Resolve a username on the signaling server.
    ///
    /// Corresponds to `GET /v1/peers/lookup?username={username}`.
    pub async fn lookup_username(&self, _username: &str) -> Result<String, DhtError> {
        // TODO: Implement actual HTTP request.
        warn!("Signaling server username lookup not yet implemented");
        Err(DhtError::not_found("signaling:username"))
    }

    /// Get available MASQUE proxies from the signaling server.
    ///
    /// Corresponds to `GET /v1/proxies`.
    pub async fn get_proxies(&self) -> Result<Vec<ProxyRecord>, DhtError> {
        // TODO: Implement actual HTTP request.
        warn!("Signaling server proxy lookup not yet implemented");
        Err(DhtError::not_found("signaling:proxies"))
    }

    /// Get DHT bootstrap nodes from the signaling server.
    ///
    /// Corresponds to `GET /v1/dht/bootstrap`.
    pub async fn get_bootstrap_nodes(&self) -> Result<Vec<String>, DhtError> {
        // TODO: Implement actual HTTP request.
        warn!("Signaling server bootstrap node lookup not yet implemented");
        Err(DhtError::not_found("signaling:bootstrap"))
    }

    /// Get the server URL.
    pub fn server_url(&self) -> &str {
        &self.server_url
    }
}

// ---------------------------------------------------------------------------
// DiscoveryService
// ---------------------------------------------------------------------------

/// The discovery layer that coordinates DHT and signaling lookups.
///
/// Provides the high-level discovery operations used by the VoIP client:
/// - Peer discovery by ID or username
/// - MASQUE proxy discovery
/// - Configurable privacy-first / speed-first mode
/// - Record refresh for keeping DHT records alive
///
/// # ROADMAP Steps Implemented
///
/// - Step 1.6: DHT fallback → signaling server (DISC-03)
/// - Step 1.7: Username → Peer ID resolution: two-step DHT lookup
/// - Step 1.8: DHT record refresh: re-publish before TTL expiry (every 30 min)
/// - Step 1.9: Mobile DHT constraint: lookup-only API, no full routing node
pub struct DiscoveryService {
    /// The DHT node for distributed lookups.
    dht_node: DhtNode,
    /// The signaling server URL.
    #[allow(dead_code)]
    signaling_url: String,
    /// The signaling server client.
    signaling: SignalingClient,
    /// The discovery priority mode.
    privacy_first: bool,
    /// Timeout for DHT lookups before falling back.
    dht_timeout_ms: u64,
}

impl DiscoveryService {
    /// Create a new discovery service with the given DHT node, signaling URL, and config.
    ///
    /// The config determines:
    /// - `discovery_privacy_first`: Whether to try DHT first (true) or signaling first (false)
    /// - `dht_lookup_timeout_ms`: How long to wait for DHT before falling back
    pub fn new(dht_node: DhtNode, signaling_url: String, config: &VoIPConfig) -> Self {
        let signaling = SignalingClient::new(signaling_url.clone());
        Self {
            dht_node,
            signaling_url,
            signaling,
            privacy_first: config.discovery_privacy_first,
            dht_timeout_ms: config.dht_lookup_timeout_ms,
        }
    }

    /// Get the current discovery mode.
    pub fn mode(&self) -> DiscoveryMode {
        DiscoveryMode::from(self.privacy_first)
    }

    /// Set the discovery mode.
    pub fn set_mode(&mut self, privacy_first: bool) {
        self.privacy_first = privacy_first;
    }

    // -----------------------------------------------------------------------
    // Peer discovery (Step 1.6: DHT fallback)
    // -----------------------------------------------------------------------

    /// Discover a peer by their peer ID.
    ///
    /// Looks up the peer's `PeerRecord` using the configured discovery mode:
    /// - **Privacy-first (default)**: Try DHT first, fall back to signaling.
    /// - **Speed-first**: Try signaling first, fall back to DHT.
    pub async fn discover_peer(&mut self, peer_id: &str) -> Result<PeerRecord, DhtError> {
        if self.privacy_first {
            // Try DHT first.
            info!(peer_id, mode = "privacy-first", "Discovering peer");
            match self.discover_peer_dht(peer_id).await {
                Ok(record) => {
                    debug!(peer_id, "Peer found via DHT");
                    Ok(record)
                }
                Err(dht_err) => {
                    warn!(peer_id, error = %dht_err, "DHT lookup failed, falling back to signaling");
                    self.discover_peer_signaling(peer_id).await
                }
            }
        } else {
            // Try signaling first.
            info!(peer_id, mode = "speed-first", "Discovering peer");
            match self.discover_peer_signaling(peer_id).await {
                Ok(record) => {
                    debug!(peer_id, "Peer found via signaling");
                    Ok(record)
                }
                Err(sig_err) => {
                    warn!(peer_id, error = %sig_err, "Signaling lookup failed, falling back to DHT");
                    self.discover_peer_dht(peer_id).await
                }
            }
        }
    }

    /// Discover a peer via the DHT only.
    async fn discover_peer_dht(&self, peer_id: &str) -> Result<PeerRecord, DhtError> {
        let dht_timeout = Duration::from_millis(self.dht_timeout_ms);
        let result = timeout(dht_timeout, self.dht_node.get_peer_record(peer_id)).await;

        match result {
            Ok(Ok(data)) => {
                let record = PeerRecord::decode(&data)?;
                if record.is_expired() {
                    return Err(DhtError::RecordExpired {
                        key: peer_id.to_string(),
                        expired_at: record.timestamp + record.ttl_seconds as u64,
                    });
                }
                Ok(record)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(DhtError::LookupTimeout {
                key: peer_id.to_string(),
                elapsed_ms: self.dht_timeout_ms,
            }),
        }
    }

    /// Discover a peer via the signaling server only.
    async fn discover_peer_signaling(&self, peer_id: &str) -> Result<PeerRecord, DhtError> {
        let signaling_timeout = Duration::from_millis(50);
        let result = timeout(signaling_timeout, self.signaling.lookup_peer(peer_id)).await;

        match result {
            Ok(Ok(record)) => Ok(record),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(DhtError::LookupTimeout {
                key: peer_id.to_string(),
                elapsed_ms: 50,
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Username resolution (Step 1.7: Two-step DHT lookup)
    // -----------------------------------------------------------------------

    /// Discover a peer by username (two-step DHT lookup).
    ///
    /// Per spec §6.2.5:
    /// 1. Look up `SHA-256("voip-name:{username}")` → `UsernameRecord` (contains peer_id)
    /// 2. Look up `SHA-256("voip:{peer_id}")` → `PeerRecord`
    ///
    /// Total: ~160ms (often cached after the first lookup).
    /// The username record is published alongside the peer record and
    /// refreshed every 30 minutes (per spec §6.2.5).
    pub async fn discover_peer_by_username(
        &mut self,
        username: &str,
    ) -> Result<PeerRecord, DhtError> {
        if self.privacy_first {
            match self.resolve_username_dht(username).await {
                Ok(record) => Ok(record),
                Err(_) => {
                    warn!("DHT username resolution failed, falling back to signaling");
                    self.resolve_username_signaling(username).await
                }
            }
        } else {
            match self.resolve_username_signaling(username).await {
                Ok(record) => Ok(record),
                Err(_) => {
                    warn!("Signaling username resolution failed, falling back to DHT");
                    self.resolve_username_dht(username).await
                }
            }
        }
    }

    /// Resolve a username via the DHT (two-step lookup).
    async fn resolve_username_dht(&self, username: &str) -> Result<PeerRecord, DhtError> {
        let dht_timeout = Duration::from_millis(self.dht_timeout_ms);

        // Step 1: username → peer_id
        info!(username, "Resolving username via DHT (step 1: username → peer_id)");
        let username_data = timeout(
            dht_timeout,
            self.dht_node.get_username_record(username),
        )
        .await
        .map_err(|_| DhtError::LookupTimeout {
            key: format!("voip-name:{username}"),
            elapsed_ms: self.dht_timeout_ms,
        })??;

        let username_record = UsernameRecord::decode(&username_data)?;

        // Step 2: peer_id → PeerRecord
        info!(
            username,
            peer_id = username_record.peer_id,
            "Resolving username via DHT (step 2: peer_id → PeerRecord)"
        );
        self.discover_peer_dht(&username_record.peer_id).await
    }

    /// Resolve a username via the signaling server.
    async fn resolve_username_signaling(&self, username: &str) -> Result<PeerRecord, DhtError> {
        info!(username, "Resolving username via signaling server");
        let signaling_timeout = Duration::from_millis(50);

        let peer_id = timeout(
            signaling_timeout,
            self.signaling.lookup_username(username),
        )
        .await
        .map_err(|_| DhtError::LookupTimeout {
            key: format!("signaling:username:{username}"),
            elapsed_ms: 50,
        })??;

        // Then get the full peer record.
        self.discover_peer_signaling(&peer_id).await
    }

    // -----------------------------------------------------------------------
    // Proxy discovery (Step 1.6: DHT fallback for proxy records)
    // -----------------------------------------------------------------------

    /// Discover available MASQUE proxy nodes.
    ///
    /// Per spec §6.8:
    /// 1. DHT lookup for proxy records (`SHA-256("masque-proxy:{node_id}")`)
    /// 2. Filter out expired/full/distant proxies
    /// 3. Measure latency to top 3 candidates
    /// 4. Select proxy with lowest measured latency
    ///
    /// Falls back to signaling server (`GET /v1/proxies`) if DHT fails.
    pub async fn discover_proxy(&self) -> Result<Vec<ProxyRecord>, DhtError> {
        if self.privacy_first {
            match self.discover_proxy_dht().await {
                Ok(proxies) if !proxies.is_empty() => Ok(proxies),
                _ => {
                    warn!("DHT proxy discovery failed, falling back to signaling");
                    self.discover_proxy_signaling().await
                }
            }
        } else {
            match self.discover_proxy_signaling().await {
                Ok(proxies) if !proxies.is_empty() => Ok(proxies),
                _ => {
                    warn!("Signaling proxy discovery failed, falling back to DHT");
                    self.discover_proxy_dht().await
                }
            }
        }
    }

    /// Discover proxies via the DHT.
    ///
    /// Note: This requires knowing the node_ids of proxy nodes. In practice,
    /// this would be done by iterating known node IDs or using a DHT prefix
    /// query. For now, this is a simplified implementation that expects the
    /// caller to provide candidate node IDs.
    async fn discover_proxy_dht(&self) -> Result<Vec<ProxyRecord>, DhtError> {
        // TODO: Implement full proxy discovery via DHT.
        // In production, this would:
        // 1. Query the DHT for all keys matching "masque-proxy:*" prefix
        // 2. Filter out expired records
        // 3. Filter out full-capacity proxies
        // 4. Measure latency to top candidates
        // 5. Return sorted by latency
        //
        // For now, return empty to exercise fallback path.
        warn!("DHT proxy discovery not fully implemented");
        Ok(Vec::new())
    }

    /// Discover proxies via the signaling server.
    async fn discover_proxy_signaling(&self) -> Result<Vec<ProxyRecord>, DhtError> {
        self.signaling.get_proxies().await
    }

    /// Select the best proxy from a list of candidates.
    ///
    /// Implements the proxy selection algorithm from spec §6.8.2:
    /// 1. Filter out expired, full, or distant proxies
    /// 2. Sort by latency hint
    /// 3. Return the best candidate
    pub fn select_proxy<'a>(
        &self,
        candidates: &'a [ProxyRecord],
        max_region_distance: Option<&str>,
    ) -> Option<&'a ProxyRecord> {
        candidates
            .iter()
            .filter(|p| !p.is_expired())
            .filter(|p| p.capacity > 0) // Not full (simplified: capacity > 0)
            .filter(|p| {
                // Filter by region if specified.
                max_region_distance.is_none() || p.region.is_empty()
            })
            .min_by_key(|p| p.latency_hint_ms)
    }

    // -----------------------------------------------------------------------
    // Record publishing
    // -----------------------------------------------------------------------

    /// Publish a PeerRecord to the DHT.
    ///
    /// Also publishes the corresponding UsernameRecord if the record
    /// has a display_name set.
    pub async fn publish_peer_record(
        &self,
        record: &PeerRecord,
    ) -> Result<(), DhtError> {
        let data = record.encode()?;
        self.dht_node.put_peer_record(&record.peer_id, &data).await?;

        // Also publish the username mapping if display_name is set.
        if !record.display_name.is_empty() {
            let username_record =
                UsernameRecord::new_unsigned(record.display_name.clone(), record.peer_id.clone());
            // Note: In production, the username record must be signed by the
            // same key as the peer record. The signing key would be passed in.
            let username_data = username_record.encode()?;
            self.dht_node
                .put_username_record(&record.display_name, &username_data)
                .await?;
        }

        info!(peer_id = record.peer_id, "Published peer record to DHT");
        Ok(())
    }

    /// Publish a ProxyRecord to the DHT.
    pub async fn publish_proxy_record(
        &self,
        record: &ProxyRecord,
    ) -> Result<(), DhtError> {
        let data = record.encode()?;
        self.dht_node.put_proxy_record(&record.node_id, &data).await?;
        info!(node_id = record.node_id, "Published proxy record to DHT");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Record refresh (Step 1.8: Re-publish before TTL expiry)
    // -----------------------------------------------------------------------

    /// Start a background task that re-publishes records at the given interval.
    ///
    /// Per spec §6.2.2 and ROADMAP Step 1.8, DHT records have a 1-hour TTL
    /// and should be re-published every 30 minutes (before the TTL expires).
    ///
    /// # Arguments
    ///
    /// * `records` - List of (key, value) pairs to re-publish.
    /// * `interval_secs` - How often to re-publish (default: 1800 = 30 minutes).
    pub fn start_record_refresh(
        &mut self,
        records: Vec<(Vec<u8>, Vec<u8>)>,
        interval_secs: u64,
    ) {
        self.dht_node.start_record_refresh(records, interval_secs);
    }

    /// Stop the record refresh background task.
    pub fn stop_record_refresh(&mut self) {
        self.dht_node.stop_record_refresh();
    }

    // -----------------------------------------------------------------------
    // Bootstrap node discovery
    // -----------------------------------------------------------------------

    /// Get DHT bootstrap nodes from the signaling server.
    ///
    /// Corresponds to `GET /v1/dht/bootstrap`.
    ///
    /// This is used when the hardcoded bootstrap nodes are unreachable
    /// and the client needs to find active DHT nodes to join the network.
    pub async fn get_bootstrap_nodes(&self) -> Result<Vec<String>, DhtError> {
        self.signaling.get_bootstrap_nodes().await
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// Shut down the discovery layer and underlying DHT node.
    pub async fn shutdown(&self) -> Result<(), DhtError> {
        self.dht_node.shutdown().await
    }
}
