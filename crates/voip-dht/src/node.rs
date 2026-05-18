//! DHT node using libp2p KadDHT.
//!
//! The `DhtNode` wraps a libp2p `Swarm` configured with Kademlia DHT
//! and provides high-level operations for storing and retrieving records.
//!
//! # Architecture (from spec §6.2)
//!
//! - **Desktop/laptop clients** run full DHT nodes: they store routing
//!   tables, answer queries from other nodes, and store/forward data.
//! - **Mobile clients** perform lookups only: they do not maintain
//!   routing tables or answer queries (battery constraint).
//! - **Bootstrap nodes** are 3-5 long-lived desktop nodes included
//!   in the app binary as fallback seeds.
//!
//! # Record Keys
//!
//! | Record       | Key                                  |
//! |-------------|--------------------------------------|
//! | PeerRecord  | `SHA-256("voip:{peer_id}")`          |
//! | UsernameRecord | `SHA-256("voip-name:{username}")` |
//! | ProxyRecord | `SHA-256("masque-proxy:{node_id}")`  |

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::time::Duration;

use futures::StreamExt;
use libp2p::kad::{
    self, Behaviour as KademliaBehaviour, Config as KademliaConfig,
    Event as KademliaEvent, GetRecordOk,
    QueryId, QueryResult, Quorum, Record, RecordKey,
    store::MemoryStore,
};
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{Multiaddr, PeerId as Libp2pPeerId, SwarmBuilder};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use voip_core::VoIPConfig;

use crate::error::DhtError;
use crate::record::{peer_record_key, proxy_record_key, username_record_key};

// ---------------------------------------------------------------------------
// Command/response pattern for async DHT operations
// ---------------------------------------------------------------------------

/// Commands sent from the public API to the swarm event loop.
enum DhtCommand {
    /// Put a record into the DHT.
    PutRecord {
        key: RecordKey,
        value: Vec<u8>,
        respond_to: oneshot::Sender<Result<(), DhtError>>,
    },
    /// Get a record from the DHT.
    GetRecord {
        key: RecordKey,
        respond_to: oneshot::Sender<Result<Vec<u8>, DhtError>>,
    },
    /// Bootstrap the DHT (join the network).
    Bootstrap {
        respond_to: oneshot::Sender<Result<(), DhtError>>,
    },
    /// Add a bootstrap node address.
    AddBootstrapNode {
        peer_id: Libp2pPeerId,
        addr: Multiaddr,
    },
    /// Shut down the event loop.
    Shutdown,
}

// ---------------------------------------------------------------------------
// DhtNode
// ---------------------------------------------------------------------------

/// A DHT node backed by libp2p KadDHT.
///
/// Provides methods for putting and getting records from the distributed
/// hash table. The node runs an internal event loop on a background task.
///
/// # Mobile vs Desktop Mode
///
/// Per spec §6.2.3, mobile clients perform lookups only and do not
/// maintain routing tables or answer queries from other nodes. This
/// conserves battery. Desktop/laptop clients run full DHT nodes.
pub struct DhtNode {
    /// Channel to send commands to the swarm event loop.
    cmd_tx: mpsc::Sender<DhtCommand>,
    /// Whether this node is running in mobile (lookup-only) mode.
    is_mobile: bool,
    /// Handle for the record refresh background task.
    refresh_handle: Option<tokio::task::JoinHandle<()>>,
}

impl DhtNode {
    /// Create a new DHT node and connect to the given bootstrap nodes.
    ///
    /// If `is_mobile` is true, the node operates in lookup-only mode
    /// (no routing table maintenance, no answering queries from other nodes).
    pub async fn new(bootstrap_nodes: Vec<Multiaddr>, is_mobile: bool) -> Result<Self, DhtError> {
        let (cmd_tx, cmd_rx) = mpsc::channel(64);

        // Build the libp2p swarm with Kademlia DHT.
        let (swarm, local_peer_id) = Self::build_swarm(is_mobile)?;

        // Start the event loop.
        let node = Self {
            cmd_tx,
            is_mobile,
            refresh_handle: None,
        };

        // Spawn event loop
        let ev_cmd_rx = cmd_rx;
        tokio::spawn(async move {
            Self::event_loop(swarm, ev_cmd_rx).await;
        });

        // Add bootstrap nodes.
        for addr in &bootstrap_nodes {
            info!("Adding bootstrap node: {addr}");
            // Parse peer ID from the multiaddr
            if let Some(peer_id) = extract_peer_id(addr) {
                let _ = node
                    .cmd_tx
                    .send(DhtCommand::AddBootstrapNode {
                        peer_id,
                        addr: addr.clone(),
                    })
                    .await;
            }
        }

        // Bootstrap the DHT.
        node.bootstrap().await?;

        info!(
            peer_id = local_peer_id.to_string(),
            mobile = is_mobile,
            "DHT node created and bootstrapped"
        );

        Ok(node)
    }

    /// Create a DHT node from a VoIPConfig.
    pub async fn from_config(config: &VoIPConfig) -> Result<Self, DhtError> {
        let bootstrap_addrs: Vec<Multiaddr> = config
            .dht_bootstrap_nodes
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        // Default to non-mobile (full node). Caller can use new() directly for mobile.
        Self::new(bootstrap_addrs, false).await
    }

    /// Run the swarm event loop.
    ///
    /// This processes both libp2p swarm events and DHT commands from
    /// the public API.
    async fn event_loop(
        mut swarm: Swarm<KademliaBehaviour<MemoryStore>>,
        mut cmd_rx: mpsc::Receiver<DhtCommand>,
    ) {
        // Track pending queries: QueryId → oneshot sender.
        let mut pending_put: HashMap<QueryId, oneshot::Sender<Result<(), DhtError>>> =
            HashMap::new();
        let mut pending_get: HashMap<QueryId, oneshot::Sender<Result<Vec<u8>, DhtError>>> =
            HashMap::new();
        let mut pending_bootstrap: HashMap<QueryId, oneshot::Sender<Result<(), DhtError>>> =
            HashMap::new();

        loop {
            tokio::select! {
                // Process swarm events.
                event = swarm.select_next_some() => {
                    Self::handle_swarm_event(
                        &mut swarm,
                        event,
                        &mut pending_put,
                        &mut pending_get,
                        &mut pending_bootstrap,
                    );
                }

                // Process commands from the public API.
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(DhtCommand::PutRecord { key, value, respond_to }) => {
                            let record = Record::new(key, value);
                            match swarm.behaviour_mut().put_record(record, Quorum::One) {
                                Ok(query_id) => {
                                    debug!("Put record query started: {query_id:?}");
                                    pending_put.insert(query_id, respond_to);
                                }
                                Err(e) => {
                                    let _ = respond_to.send(Err(DhtError::StoreFailed {
                                        key: format!("{:?}", e),
                                        reason: e.to_string(),
                                    }));
                                }
                            }
                        }
                        Some(DhtCommand::GetRecord { key, respond_to }) => {
                            let query_id = swarm.behaviour_mut().get_record(key);
                            debug!("Get record query started: {query_id:?}");
                            pending_get.insert(query_id, respond_to);
                        }
                        Some(DhtCommand::Bootstrap { respond_to }) => {
                            match swarm.behaviour_mut().bootstrap() {
                                Ok(query_id) => {
                                    debug!("Bootstrap query started: {query_id:?}");
                                    pending_bootstrap.insert(query_id, respond_to);
                                }
                                Err(e) => {
                                    let _ = respond_to.send(Err(DhtError::BootstrapFailed(
                                        vec![e.to_string()],
                                    )));
                                }
                            }
                        }
                        Some(DhtCommand::AddBootstrapNode { peer_id, addr }) => {
                            swarm.behaviour_mut().add_address(&peer_id, addr);
                            debug!("Added bootstrap node: {peer_id}");
                        }
                        Some(DhtCommand::Shutdown) | None => {
                            info!("DHT node shutting down");
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Handle a swarm event.
    fn handle_swarm_event(
        _swarm: &mut Swarm<KademliaBehaviour<MemoryStore>>,
        event: SwarmEvent<KademliaEvent>,
        pending_put: &mut HashMap<QueryId, oneshot::Sender<Result<(), DhtError>>>,
        pending_get: &mut HashMap<QueryId, oneshot::Sender<Result<Vec<u8>, DhtError>>>,
        pending_bootstrap: &mut HashMap<QueryId, oneshot::Sender<Result<(), DhtError>>>,
    ) {
        match event {
            SwarmEvent::Behaviour(KademliaEvent::OutboundQueryProgressed {
                result,
                id,
                ..
            }) => {
                match result {
                    QueryResult::PutRecord(result) => {
                        if let Some(sender) = pending_put.remove(&id) {
                            match result {
                                Ok(_) => {
                                    debug!("Put record succeeded: {id:?}");
                                    let _ = sender.send(Ok(()));
                                }
                                Err(e) => {
                                    warn!("Put record failed: {e}");
                                    let _ = sender.send(Err(DhtError::StoreFailed {
                                        key: format!("{id:?}"),
                                        reason: e.to_string(),
                                    }));
                                }
                            }
                        }
                    }
                    QueryResult::GetRecord(result) => {
                        if let Some(sender) = pending_get.remove(&id) {
                            match result {
                                Ok(ok) => {
                                    // Handle the GetRecordOk enum variants.
                                    match ok {
                                        GetRecordOk::FoundRecord(record) => {
                                            debug!(
                                                "Get record succeeded: key={:?}, {} bytes",
                                                record.record.key,
                                                record.record.value.len()
                                            );
                                            let _ = sender.send(Ok(record.record.value));
                                        }
                                        GetRecordOk::FinishedWithNoAdditionalRecord { .. } => {
                                            // No additional records found; this is fine for
                                            // single-record lookups.
                                            let _ = sender.send(Err(DhtError::NotFound {
                                                key: format!("{id:?}"),
                                            }));
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Get record failed: {e}");
                                    let _ = sender.send(Err(DhtError::LookupFailed {
                                        key: format!("{id:?}"),
                                        reason: e.to_string(),
                                    }));
                                }
                            }
                        }
                    }
                    QueryResult::Bootstrap(result) => {
                        if let Some(sender) = pending_bootstrap.remove(&id) {
                            match result {
                                Ok(_) => {
                                    debug!("Bootstrap succeeded: {id:?}");
                                    let _ = sender.send(Ok(()));
                                }
                                Err(e) => {
                                    warn!("Bootstrap failed: {e}");
                                    let _ = sender.send(Err(DhtError::BootstrapFailed(
                                        vec![e.to_string()],
                                    )));
                                }
                            }
                        }
                    }
                    other => {
                        debug!("Unhandled query result: {other:?}");
                    }
                }
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on: {address}");
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                debug!("Connection established with: {peer_id}");
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                debug!("Connection closed with {peer_id}: {cause:?}");
            }
            _ => {
                // Ignore other swarm events.
            }
        }
    }

    /// Build the libp2p swarm with Kademlia DHT behaviour.
    fn build_swarm(
        is_mobile: bool,
    ) -> Result<(Swarm<KademliaBehaviour<MemoryStore>>, Libp2pPeerId), DhtError> {
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = local_key.public().to_peer_id();

        // Build the swarm with QUIC transport.
        // The Kademlia behaviour is constructed inside the closure because
        // SwarmBuilder::with_behaviour takes a single-argument closure that
        // receives the Keypair.
        let swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_quic()
            .with_behaviour(|keypair| {
                let peer_id = keypair.public().to_peer_id();
                let store = MemoryStore::new(peer_id);
                let protocol_name = libp2p::StreamProtocol::try_from_owned(
                    "/ipfs/kad/1.0.0".to_string(),
                )
                .expect("valid protocol name");
                let mut kad_config = KademliaConfig::new(protocol_name);

                if is_mobile {
                    // Mobile: lookup-only mode (spec §6.2.3).
                    // Shorter query timeout, don't act as a provider or store records for others.
                    kad_config.set_query_timeout(Duration::from_secs(5));
                } else {
                    // Desktop: full DHT node mode.
                    kad_config.set_query_timeout(Duration::from_secs(10));
                    // Enable record replication.
                    if let Some(factor) = NonZeroUsize::new(kad::K_VALUE.get()) {
                        kad_config.set_replication_factor(factor);
                    }
                }

                let mut behaviour = KademliaBehaviour::with_config(peer_id, store, kad_config);

                if is_mobile {
                    // Per spec §6.2.3: mobile clients must NOT maintain routing tables
                    // or answer queries from other nodes. Setting Mode::Client disables
                    // routing table maintenance and stops the node from answering
                    // queries — it only performs lookups.
                    behaviour.set_mode(Some(kad::Mode::Client));
                }

                behaviour
            })
            .expect("with_behaviour cannot fail when returning behaviour directly")
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(30)))
            .build();

        Ok((swarm, local_peer_id))
    }

    /// Bootstrap the DHT (join the network from seed nodes).
    pub async fn bootstrap(&self) -> Result<(), DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DhtCommand::Bootstrap { respond_to: tx })
            .await
            .map_err(|_| DhtError::NotConnected)?;
        rx.await.map_err(|_| DhtError::NotConnected)?
    }

    /// Store a record in the DHT.
    ///
    /// The key is derived from the record type and identifier:
    /// - PeerRecord: `SHA-256("voip:{peer_id}")`
    /// - UsernameRecord: `SHA-256("voip-name:{username}")`
    /// - ProxyRecord: `SHA-256("masque-proxy:{node_id}")`
    pub async fn put_record(&self, key: &[u8], value: &[u8]) -> Result<(), DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DhtCommand::PutRecord {
                key: RecordKey::new(&key),
                value: value.to_vec(),
                respond_to: tx,
            })
            .await
            .map_err(|_| DhtError::NotConnected)?;
        rx.await.map_err(|_| DhtError::NotConnected)?
    }

    /// Retrieve a record from the DHT.
    ///
    /// Returns the raw bytes of the record value. The caller is
    /// responsible for decoding the appropriate record type.
    pub async fn get_record(&self, key: &[u8]) -> Result<Vec<u8>, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DhtCommand::GetRecord {
                key: RecordKey::new(&key),
                respond_to: tx,
            })
            .await
            .map_err(|_| DhtError::NotConnected)?;
        rx.await.map_err(|_| DhtError::NotConnected)?
    }

    // -----------------------------------------------------------------------
    // High-level convenience methods
    // -----------------------------------------------------------------------

    /// Store a `PeerRecord` in the DHT.
    ///
    /// Key: `SHA-256("voip:{peer_id}")`
    pub async fn put_peer_record(
        &self,
        peer_id: &str,
        record_data: &[u8],
    ) -> Result<(), DhtError> {
        let key = peer_record_key(peer_id);
        self.put_record(&key, record_data).await
    }

    /// Retrieve a `PeerRecord` from the DHT.
    ///
    /// Key: `SHA-256("voip:{peer_id}")`
    pub async fn get_peer_record(&self, peer_id: &str) -> Result<Vec<u8>, DhtError> {
        let key = peer_record_key(peer_id);
        self.get_record(&key).await
    }

    /// Store a `UsernameRecord` in the DHT.
    ///
    /// Key: `SHA-256("voip-name:{username}")`
    pub async fn put_username_record(
        &self,
        username: &str,
        record_data: &[u8],
    ) -> Result<(), DhtError> {
        let key = username_record_key(username);
        self.put_record(&key, record_data).await
    }

    /// Retrieve a `UsernameRecord` from the DHT.
    ///
    /// Key: `SHA-256("voip-name:{username}")`
    pub async fn get_username_record(&self, username: &str) -> Result<Vec<u8>, DhtError> {
        let key = username_record_key(username);
        self.get_record(&key).await
    }

    /// Store a `ProxyRecord` in the DHT.
    ///
    /// Key: `SHA-256("masque-proxy:{node_id}")`
    pub async fn put_proxy_record(
        &self,
        node_id: &str,
        record_data: &[u8],
    ) -> Result<(), DhtError> {
        let key = proxy_record_key(node_id);
        self.put_record(&key, record_data).await
    }

    /// Retrieve a `ProxyRecord` from the DHT.
    ///
    /// Key: `SHA-256("masque-proxy:{node_id}")`
    pub async fn get_proxy_record(&self, node_id: &str) -> Result<Vec<u8>, DhtError> {
        let key = proxy_record_key(node_id);
        self.get_record(&key).await
    }

    /// Shut down the DHT node.
    pub async fn shutdown(&self) -> Result<(), DhtError> {
        self.cmd_tx
            .send(DhtCommand::Shutdown)
            .await
            .map_err(|_| DhtError::NotConnected)
    }

    /// Whether this node is in mobile (lookup-only) mode.
    pub fn is_mobile(&self) -> bool {
        self.is_mobile
    }

    /// Start a background task that re-publishes records at the given interval.
    ///
    /// Per spec §6.2.2 and ROADMAP Step 1.8, DHT records have a 1-hour TTL
    /// and should be re-published every 30 minutes (before the TTL expires).
    ///
    /// # Arguments
    ///
    /// * `records` - List of (key, value) pairs to re-publish.
    /// * `interval_secs` - How often to re-publish (e.g., 1800 = 30 minutes).
    pub fn start_record_refresh(
        &mut self,
        records: Vec<(Vec<u8>, Vec<u8>)>,
        interval_secs: u64,
    ) {
        self.stop_record_refresh();

        let cmd_tx = self.cmd_tx.clone();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

            loop {
                interval.tick().await;

                for (key, value) in &records {
                    let (tx, rx) = oneshot::channel();
                    let cmd = DhtCommand::PutRecord {
                        key: RecordKey::new(&key),
                        value: value.clone(),
                        respond_to: tx,
                    };

                    if cmd_tx.send(cmd).await.is_err() {
                        tracing::warn!("Record refresh: DHT node shut down");
                        return;
                    }

                    match rx.await {
                        Ok(Ok(())) => {
                            tracing::debug!("Record refreshed successfully");
                        }
                        Ok(Err(e)) => {
                            tracing::warn!("Record refresh failed: {e}");
                        }
                        Err(_) => {
                            tracing::warn!("Record refresh: DHT node shut down");
                            return;
                        }
                    }
                }
            }
        });

        self.refresh_handle = Some(handle);
    }

    /// Stop the record refresh background task.
    pub fn stop_record_refresh(&mut self) {
        if let Some(handle) = self.refresh_handle.take() {
            handle.abort();
        }
    }
}

/// Extract a PeerId from a Multiaddr, if present.
fn extract_peer_id(addr: &Multiaddr) -> Option<Libp2pPeerId> {
    addr.iter().find_map(|component| {
        if let libp2p::multiaddr::Protocol::P2p(peer_id) = component {
            Some(peer_id)
        } else {
            None
        }
    })
}
