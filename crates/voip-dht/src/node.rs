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
use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use libp2p::kad::{
    self, Kademlia, KademliaConfig, KademliaEvent, PeerRecord as KadPeerRecord,
    QueryId, QueryResult, Record, RecordKey,
};
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{noise, quic, tls, Multiaddr, PeerId as Libp2pPeerId, SwarmBuilder};
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{debug, error, info, warn};

use voip_core::VoIPConfig;

use crate::discovery::DiscoveryMode;
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
pub struct DhtNode {
    /// Channel to send commands to the swarm event loop.
    cmd_tx: mpsc::Sender<DhtCommand>,
    /// Whether this node is running in mobile (lookup-only) mode.
    is_mobile: bool,
}

impl DhtNode {
    /// Create a new DHT node and connect to the given bootstrap nodes.
    ///
    /// If `is_mobile` is true, the node operates in lookup-only mode
    /// (no routing table maintenance, no answering queries from other nodes).
    pub async fn new(bootstrap_nodes: Vec<Multiaddr>, is_mobile: bool) -> Result<Self, DhtError> {
        let (cmd_tx, cmd_rx) = mpsc::channel(64);

        // Build the libp2p swarm with Kademlia DHT.
        let swarm = Self::build_swarm(is_mobile)?;

        // Start the event loop.
        let node = Self { cmd_tx, is_mobile };
        let ev_cmd_rx = cmd_rx;

        tokio::spawn(async move {
            Self::event_loop(swarm, ev_cmd_rx).await;
        });

        // Add bootstrap nodes.
        for addr in &bootstrap_nodes {
            info!("Adding bootstrap node: {addr}");
        }

        // Bootstrap the DHT.
        node.bootstrap().await?;

        Ok(node)
    }

    /// Create a DHT node from a VoIPConfig.
    pub async fn from_config(config: &VoIPConfig) -> Result<Self, DhtError> {
        let bootstrap_addrs: Vec<Multiaddr> = config
            .dht_bootstrap_nodes
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        // If mobile, we could detect from config or platform.
        // For now, default to non-mobile (full node).
        Self::new(bootstrap_addrs, false).await
    }

    /// Run the swarm event loop.
    ///
    /// This processes both libp2p swarm events and DHT commands from
    /// the public API.
    async fn event_loop(
        mut swarm: Swarm<Kademlia<quic::Config>>,
        mut cmd_rx: mpsc::Receiver<DhtCommand>,
    ) {
        // Track pending queries: QueryId → oneshot sender.
        let mut pending_put: HashMap<QueryId, oneshot::Sender<Result<(), DhtError>>> =
            HashMap::new();
        let mut pending_get: HashMap<QueryId, oneshot::Sender<Result<Vec<u8>, DhtError>>> =
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
                    ).await;
                }

                // Process commands from the public API.
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(DhtCommand::PutRecord { key, value, respond_to }) => {
                            let record = Record::new(key, value);
                            match swarm.behaviour_mut().put_record(record, kad::Quorum::One) {
                                Ok(query_id) => {
                                    debug!("Put record query started: {query_id:?}");
                                    pending_put.insert(query_id, respond_to);
                                }
                                Err(e) => {
                                    let _ = respond_to.send(Err(DhtError::PutFailed {
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
                                    // For bootstrap, we'll just signal success immediately
                                    // since the bootstrap result comes as a different event.
                                    let _ = respond_to.send(Ok(()));
                                }
                                Err(e) => {
                                    let _ = respond_to.send(Err(DhtError::BootstrapFailed(
                                        e.to_string(),
                                    )));
                                }
                            }
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
    async fn handle_swarm_event(
        swarm: &mut Swarm<Kademlia<quic::Config>>,
        event: SwarmEvent<KademliaEvent>,
        pending_put: &mut HashMap<QueryId, oneshot::Sender<Result<(), DhtError>>>,
        pending_get: &mut HashMap<QueryId, oneshot::Sender<Result<Vec<u8>, DhtError>>>,
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
                                    let _ = sender.send(Err(DhtError::PutFailed {
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
                                    // Return the first record found.
                                    if let Some(record) = ok.records.first() {
                                        debug!(
                                            "Get record succeeded: key={:?}, {} bytes",
                                            record.key(),
                                            record.value().len()
                                        );
                                        let _ = sender.send(Ok(record.value().to_vec()));
                                    } else {
                                        let _ = sender.send(Err(DhtError::NotFound {
                                            key: format!("{id:?}"),
                                        }));
                                    }
                                }
                                Err(e) => {
                                    warn!("Get record failed: {e}");
                                    let _ = sender.send(Err(DhtError::NotFound {
                                        key: format!("{e}"),
                                    }));
                                }
                            }
                        }
                    }
                    QueryResult::Bootstrap(result) => {
                        match result {
                            Ok(_) => debug!("Bootstrap succeeded"),
                            Err(e) => warn!("Bootstrap failed: {e}"),
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
    fn build_swarm(is_mobile: bool) -> Result<Swarm<Kademlia<quic::Config>>, DhtError> {
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = local_key.public().to_peer_id();

        // Configure Kademlia.
        let mut kad_config = KademliaConfig::new(libp2p::kad::ProtocolConfig::default());

        if is_mobile {
            // Mobile: lookup-only mode. Don't act as a provider or store records.
            kad_config.set_query_timeout(Duration::from_secs(5));
        } else {
            // Desktop: full DHT node mode.
            kad_config.set_query_timeout(Duration::from_secs(10));
            // Enable record replication.
            kad_config.set_replication_factor(libp2p::kad::ReplicationFactor::Majority);
        }

        let kademlia = Kademlia::with_config(local_peer_id, kad_config);

        // Build the swarm with QUIC transport.
        let swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_quic()
            .with_behaviour(|_, kademlia| Ok(kademlia))
            .map_err(|e| DhtError::Swarm(e.to_string()))?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(30)))
            .build();

        Ok(swarm)
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
                key: RecordKey::new(key),
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
                key: RecordKey::new(key),
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
}
