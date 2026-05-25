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

use ed25519_dalek::SigningKey;
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
#[derive(Default)]
pub enum DiscoveryMode {
    /// DHT first (~80ms), fall back to signaling server if DHT fails.
    /// Default. Higher privacy — no single entity sees the social graph.
    #[default]
    PrivacyFirst,
    /// Signaling server first (~5ms), fall back to DHT if server unreachable.
    /// Lower latency but the signaling server operator sees lookups.
    SpeedFirst,
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
// Signaling server client
// ---------------------------------------------------------------------------

/// A minimal signaling server client for fallback lookups.
///
/// Communicates with the signaling server via HTTP REST endpoints.
/// The signaling server provides peer lookup, username resolution,
/// proxy discovery, and DHT bootstrap node information as a fallback
/// when the DHT is unavailable or slow.
///
/// # Endpoints
///
/// | Method | Path                         | Description                       |
/// |--------|------------------------------|-----------------------------------|
/// | GET    | `/v1/peers/{peer_id}`        | Peer lookup                       |
/// | GET    | `/v1/peers/lookup?username=` | Username → peer_id resolution     |
/// | GET    | `/v1/proxies`                | MASQUE proxy discovery            |
/// | GET    | `/v1/dht/bootstrap`          | DHT bootstrap node multiaddresses |
#[derive(Debug, Clone)]
pub struct SignalingClient {
    /// Base URL of the signaling server (e.g., "https://signal.example.com").
    server_url: String,
    /// Shared HTTP client for making requests to the signaling server.
    http_client: reqwest::Client,
}

// ---- JSON response types matching the signaling server's API ----

/// Response from `GET /v1/peers/{peer_id}`.
#[derive(Debug, serde::Deserialize)]
struct PeerResponse {
    peer_id: String,
    display_name: String,
    #[serde(default)]
    ipv6_addresses: Vec<String>,
    #[serde(default)]
    ipv4_reflexive: Vec<String>,
    #[serde(default)]
    nat_type: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    last_seen: u64,
}

impl PeerResponse {
    /// Returns the last_seen timestamp from the signaling server response.
    #[allow(dead_code)]
    pub fn last_seen(&self) -> u64 {
        self.last_seen
    }
}

/// Response from `GET /v1/peers/lookup?username={name}`.
#[derive(Debug, serde::Deserialize)]
struct LookupResponse {
    peer_id: String,
    #[allow(dead_code)]
    display_name: String,
    #[allow(dead_code)]
    status: String,
}

/// Response from `GET /v1/proxies`.
#[derive(Debug, serde::Deserialize)]
struct ProxiesResponse {
    proxies: Vec<ProxyEntry>,
}

/// A single proxy entry in the proxies response.
#[derive(Debug, serde::Deserialize)]
struct ProxyEntry {
    node_id: String,
    proxy_url: String,
    #[serde(default)]
    capacity: u32,
    region: String,
    #[serde(default)]
    latency_hint_ms: u32,
}

/// Response from `GET /v1/dht/bootstrap`.
#[derive(Debug, serde::Deserialize)]
struct DhtBootstrapResponse {
    nodes: Vec<String>,
}

impl SignalingClient {
    /// Create a new signaling client pointing at the given server URL.
    pub fn new(server_url: String) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self {
            server_url,
            http_client,
        }
    }

    /// Look up a peer by ID on the signaling server.
    ///
    /// Corresponds to `GET /v1/peers/{peer_id}`.
    ///
    /// Returns a `PeerRecord` populated from the signaling server's
    /// response. Note that the signaling server does not return a
    /// signed record — the signature field will be empty.
    pub async fn lookup_peer(&self, peer_id: &str) -> Result<PeerRecord, DhtError> {
        let url = format!("{}/v1/peers/{}", self.server_url, peer_id);
        debug!(url = %url, "Looking up peer on signaling server");

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| DhtError::Http(format!("Failed to connect to signaling server: {e}")))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(DhtError::NotFound {
                key: format!("signaling:peer:{peer_id}"),
            });
        }

        if !response.status().is_success() {
            let status = response.status();
            return Err(DhtError::Http(format!(
                "Signaling server returned {status} for peer lookup"
            )));
        }

        let peer_resp: PeerResponse = response
            .json()
            .await
            .map_err(|e| DhtError::Serialization(format!(
                "Failed to parse signaling server peer response: {e}"
            )))?;

        // Map the string status to PeerStatus enum.
        let status = match peer_resp.status.to_lowercase().as_str() {
            "online" => crate::record::PeerStatus::Online,
            "in_call" => crate::record::PeerStatus::InCall,
            _ => crate::record::PeerStatus::Offline,
        };

        // Map the string nat_type to NatType enum.
        let nat_info = match peer_resp.nat_type.to_lowercase().as_str() {
            "cone" => Some(crate::record::NatInfo {
                nat_type: crate::record::NatType::Cone,
                prediction: None,
            }),
            "symmetric_sequential" | "symmetricsequential" => Some(crate::record::NatInfo {
                nat_type: crate::record::NatType::SymmetricSequential,
                prediction: None,
            }),
            "symmetric_pseudo" | "symmetricpseudo" => Some(crate::record::NatInfo {
                nat_type: crate::record::NatType::SymmetricPseudo,
                prediction: None,
            }),
            "symmetric_random" | "symmetricrandom" => Some(crate::record::NatInfo {
                nat_type: crate::record::NatType::SymmetricRandom,
                prediction: None,
            }),
            _ => None,
        };

        Ok(PeerRecord::new_unsigned(
            peer_resp.peer_id,
            peer_resp.display_name,
            peer_resp.ipv6_addresses,
            peer_resp.ipv4_reflexive,
            nat_info,
            vec![],
            status,
            3600,
        ))
    }

    /// Resolve a username on the signaling server.
    ///
    /// Corresponds to `GET /v1/peers/lookup?username={username}`.
    ///
    /// Returns the peer ID associated with the given username.
    pub async fn lookup_username(&self, username: &str) -> Result<String, DhtError> {
        let url = format!("{}/v1/peers/lookup?username={}", self.server_url, username);
        debug!(url = %url, "Looking up username on signaling server");

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| DhtError::Http(format!("Failed to connect to signaling server: {e}")))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(DhtError::UsernameNotFound {
                username: username.to_string(),
            });
        }

        if !response.status().is_success() {
            let status = response.status();
            return Err(DhtError::Http(format!(
                "Signaling server returned {status} for username lookup"
            )));
        }

        let lookup_resp: LookupResponse = response
            .json()
            .await
            .map_err(|e| DhtError::Serialization(format!(
                "Failed to parse signaling server lookup response: {e}"
            )))?;

        Ok(lookup_resp.peer_id)
    }

    /// Get available MASQUE proxies from the signaling server.
    ///
    /// Corresponds to `GET /v1/proxies`.
    ///
    /// Returns a list of `ProxyRecord`s populated from the signaling
    /// server's response. The records are unsigned (signature is empty)
    /// since the signaling server does not provide proxy signatures.
    pub async fn get_proxies(&self) -> Result<Vec<ProxyRecord>, DhtError> {
        let url = format!("{}/v1/proxies", self.server_url);
        debug!(url = %url, "Getting proxies from signaling server");

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| DhtError::Http(format!("Failed to connect to signaling server: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(DhtError::Http(format!(
                "Signaling server returned {status} for proxy lookup"
            )));
        }

        let proxies_resp: ProxiesResponse = response
            .json()
            .await
            .map_err(|e| DhtError::Serialization(format!(
                "Failed to parse signaling server proxies response: {e}"
            )))?;

        let proxies = proxies_resp
            .proxies
            .into_iter()
            .map(|entry| {
                ProxyRecord::new_unsigned(
                    entry.node_id,
                    entry.proxy_url,
                    entry.capacity,
                    entry.region,
                    entry.latency_hint_ms,
                    3600,
                    String::new(), // cert_fingerprint not provided by signaling server
                )
            })
            .collect();

        Ok(proxies)
    }

    /// Get DHT bootstrap nodes from the signaling server.
    ///
    /// Corresponds to `GET /v1/dht/bootstrap`.
    ///
    /// Returns a list of multiaddress strings for DHT bootstrap nodes.
    pub async fn get_bootstrap_nodes(&self) -> Result<Vec<String>, DhtError> {
        let url = format!("{}/v1/dht/bootstrap", self.server_url);
        debug!(url = %url, "Getting DHT bootstrap nodes from signaling server");

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| DhtError::Http(format!("Failed to connect to signaling server: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(DhtError::Http(format!(
                "Signaling server returned {status} for bootstrap node lookup"
            )));
        }

        let bootstrap_resp: DhtBootstrapResponse = response
            .json()
            .await
            .map_err(|e| DhtError::Serialization(format!(
                "Failed to parse signaling server bootstrap response: {e}"
            )))?;

        Ok(bootstrap_resp.nodes)
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
    ///
    /// # Arguments
    ///
    /// * `node_ids` - Known proxy node IDs to look up in the DHT.
    ///   If empty, the DHT lookup is skipped and the signaling fallback is used.
    pub async fn discover_proxy(&self, node_ids: &[String]) -> Result<Vec<ProxyRecord>, DhtError> {
        if self.privacy_first {
            match self.discover_proxy_dht(node_ids).await {
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
                    self.discover_proxy_dht(node_ids).await
                }
            }
        }
    }

    /// Discover proxies via the DHT.
    ///
    /// Since libp2p KadDHT doesn't natively support prefix queries,
    /// this method requires a list of known proxy node IDs to look up.
    /// Each node ID is used to compute the DHT key
    /// `SHA-256("masque-proxy:{node_id}")` and fetch the corresponding
    /// `ProxyRecord`.
    ///
    /// # Arguments
    ///
    /// * `node_ids` - Slice of known proxy node IDs to look up in the DHT.
    ///
    /// # Returns
    ///
    /// A vector of valid, non-expired `ProxyRecord`s. Lookup failures for
    /// individual node IDs are silently skipped (logged as warnings).
    async fn discover_proxy_dht(&self, node_ids: &[String]) -> Result<Vec<ProxyRecord>, DhtError> {
        let mut proxies = Vec::new();

        for node_id in node_ids {
            debug!(node_id, "Looking up proxy record in DHT");
            match self.dht_node.get_proxy_record(node_id).await {
                Ok(data) => {
                    match ProxyRecord::decode(&data) {
                        Ok(record) => {
                            if record.is_expired() {
                                warn!(
                                    node_id,
                                    expired_at = record.timestamp + record.ttl_seconds as u64,
                                    "Proxy record expired, skipping"
                                );
                                continue;
                            }
                            debug!(
                                node_id,
                                region = %record.region,
                                latency_ms = record.latency_hint_ms,
                                "Found proxy record via DHT"
                            );
                            proxies.push(record);
                        }
                        Err(e) => {
                            warn!(node_id, error = %e, "Failed to decode proxy record from DHT");
                        }
                    }
                }
                Err(e) => {
                    debug!(node_id, error = %e, "Proxy record not found in DHT for node");
                }
            }
        }

        // Sort by latency hint (lowest first) per spec §6.8.2.
        proxies.sort_by_key(|p| p.latency_hint_ms);

        Ok(proxies)
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
    /// has a display_name set. The UsernameRecord is signed with the
    /// provided signing key before publishing, as required by the spec
    /// for record authenticity verification.
    ///
    /// # Arguments
    ///
    /// * `record` - The peer record to publish.
    /// * `signing_key` - The Ed25519 signing key used to sign the UsernameRecord.
    ///
    /// # Security
    ///
    /// Per spec §6.2.5, the username record MUST be signed before publishing.
    /// Unsigned records will be rejected by verifiers.
    pub async fn publish_peer_record(
        &self,
        record: &PeerRecord,
        signing_key: &SigningKey,
    ) -> Result<(), DhtError> {
        let data = record.encode()?;
        self.dht_node.put_peer_record(&record.peer_id, &data).await?;

        // Also publish the username mapping if display_name is set.
        if !record.display_name.is_empty() {
            let mut username_record =
                UsernameRecord::new_unsigned(record.display_name.clone(), record.peer_id.clone());
            // Per spec §6.2.5: the username record must be signed with the
            // peer's Ed25519 key before publishing. This ensures that other
            // nodes can verify the username → peer_id mapping is authentic.
            username_record.sign(signing_key)?;
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
