//! Media over QUIC (MoQ) draft-17 session management.
//!
//! Implements MoQ control messages and datagram delivery per spec/05:
//!
//! - **Track namespace:** `voip/{peer_id}/audio/opus-48k`
//! - **Priority:** Audio (0) > Video keyframe (1) > Video delta (2) > Screen (3)
//! - **Datagram format:** Type(1B) + Alias(4B) + Seq(varint) + Timestamp(varint) + Payload
//!
//! The MoQ layer sits entirely on top of QUIC. The Three Pillars handle
//! connectivity; MoQ handles what rides on top: track management,
//! prioritization, codec negotiation, and media delivery patterns.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use quinn::{Connection, RecvStream, SendStream};
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use voip_core::VoIPConfig;

use crate::error::MoqError;

// =============================================================================
// Constants
// =============================================================================

/// MoQ datagram type identifier for media data.
pub const DATAGRAM_TYPE_MEDIA: u8 = 0x01;

/// MoQ control stream type identifier.
pub const CONTROL_STREAM_TYPE: u8 = 0x00;

/// MoQ priority values per spec/05 §5.6.
pub mod priority {
    /// Audio — highest priority, voice is the critical path.
    pub const AUDIO: u8 = 0;
    /// Video keyframe — enables decoder reset after packet loss.
    pub const VIDEO_KEYFRAME: u8 = 1;
    /// Video delta frame — important but less critical than keyframes.
    pub const VIDEO_DELTA: u8 = 2;
    /// Screen share — loss-tolerant, lower refresh rate acceptable.
    pub const SCREEN_SHARE: u8 = 3;
}

/// MoQ control message type IDs (draft-17).
pub mod msg_type {
    pub const CLIENT_SETUP: u64 = 0x01;
    pub const SERVER_SETUP: u64 = 0x02;
    pub const ANNOUNCE: u64 = 0x03;
    pub const ANNOUNCE_OK: u64 = 0x04;
    pub const ANNOUNCE_ERROR: u64 = 0x05;
    pub const UNSUBSCRIBE: u64 = 0x0A;
    pub const SUBSCRIBE: u64 = 0x06;
    pub const SUBSCRIBE_OK: u64 = 0x07;
    pub const SUBSCRIBE_ERROR: u64 = 0x08;
    pub const TRACK_UPDATE: u64 = 0x10;
    pub const CONNECTION_MIGRATION: u64 = 0x20;
}

// =============================================================================
// Track Namespace
// =============================================================================

/// A MoQ track namespace identifying a media stream.
///
/// Convention from spec/05 §5.5:
/// ```text
/// voip/{peer_id}/audio/opus-48k
/// voip/{peer_id}/video/vp9-720p
/// voip/{peer_id}/screen/vp9-1080p
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrackNamespace {
    /// Full track namespace string.
    pub namespace: String,
    /// Track alias (4-byte identifier assigned at SUBSCRIBE_OK).
    pub alias: u32,
    /// Priority for sending (0 = highest).
    pub priority: u8,
}

impl TrackNamespace {
    /// Create an audio track namespace for the given peer.
    pub fn audio(peer_id: &str) -> Self {
        Self {
            namespace: format!("voip/{}/audio/opus-48k", peer_id),
            alias: 0, // Assigned during SUBSCRIBE_OK
            priority: priority::AUDIO,
        }
    }

    /// Create a video track namespace for the given peer.
    pub fn video(peer_id: &str) -> Self {
        Self {
            namespace: format!("voip/{}/video/vp9-720p", peer_id),
            alias: 0,
            priority: priority::VIDEO_KEYFRAME,
        }
    }

    /// Create a screen share track namespace for the given peer.
    pub fn screen(peer_id: &str) -> Self {
        Self {
            namespace: format!("voip/{}/screen/vp9-1080p", peer_id),
            alias: 0,
            priority: priority::SCREEN_SHARE,
        }
    }

    /// Set the track alias (assigned when SUBSCRIBE_OK is received).
    pub fn with_alias(mut self, alias: u32) -> Self {
        self.alias = alias;
        self
    }

    /// Parse the media type from the namespace string.
    pub fn media_type(&self) -> MediaType {
        if self.namespace.contains("/audio/") {
            MediaType::Audio
        } else if self.namespace.contains("/video/") {
            MediaType::Video
        } else if self.namespace.contains("/screen/") {
            MediaType::Screen
        } else {
            MediaType::Unknown
        }
    }
}

/// Media type extracted from a track namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    Audio,
    Video,
    Screen,
    Unknown,
}

// =============================================================================
// MoQ Datagram
// =============================================================================

/// A MoQ media datagram per spec/11 §11.6.
///
/// Wire format:
/// ```text
/// +------+--------+---------+-----------+---------+
/// | Type | Alias  | Seq     | Timestamp | Payload |
/// | 1B   | 4B     | varint  | varint    | ...     |
/// +------+--------+---------+-----------+---------+
/// ```
#[derive(Debug, Clone)]
pub struct MoqDatagram {
    /// Datagram type (0x01 for media).
    pub datagram_type: u8,
    /// Track alias (4 bytes, assigned at SUBSCRIBE_OK).
    pub track_alias: u32,
    /// Monotonically increasing sequence number per track.
    pub sequence: u64,
    /// Media timestamp in track's clock rate.
    pub timestamp: u64,
    /// Encoded media frame payload (Opus packet, VP9 frame, etc.).
    pub payload: Bytes,
}

impl MoqDatagram {
    /// Create a new media datagram.
    pub fn new(track_alias: u32, sequence: u64, timestamp: u64, payload: Bytes) -> Self {
        Self {
            datagram_type: DATAGRAM_TYPE_MEDIA,
            track_alias,
            sequence,
            timestamp,
            payload,
        }
    }

    /// Create an audio datagram for an Opus packet.
    pub fn audio(track_alias: u32, sequence: u64, timestamp: u64, opus_data: Bytes) -> Self {
        Self::new(track_alias, sequence, timestamp, opus_data)
    }

    /// Encode the datagram to bytes for sending over QUIC datagram.
    ///
    /// Wire format: Type(1B) + Alias(4B) + Seq(varint) + Timestamp(varint) + Payload
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.payload.len() + 20);
        buf.put_u8(self.datagram_type);
        buf.put_u32(self.track_alias);
        encode_varint(&mut buf, self.sequence);
        encode_varint(&mut buf, self.timestamp);
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }

    /// Decode a datagram from bytes received over QUIC.
    pub fn decode(data: &[u8]) -> Result<Self, MoqError> {
        if data.len() < 5 {
            return Err(MoqError::DatagramTooShort {
                got: data.len(),
                need: 5,
            });
        }

        let mut cursor = data;
        let datagram_type = cursor.get_u8();

        if datagram_type != DATAGRAM_TYPE_MEDIA {
            return Err(MoqError::InvalidDatagramType(datagram_type));
        }

        let track_alias = cursor.get_u32();
        let (sequence, seq_len) = decode_varint(cursor);
        cursor.advance(seq_len);

        let (timestamp, ts_len) = decode_varint(cursor);
        cursor.advance(ts_len);

        let payload = Bytes::copy_from_slice(cursor);

        Ok(Self {
            datagram_type,
            track_alias,
            sequence,
            timestamp,
            payload,
        })
    }

    /// Get the datagram's effective priority based on track alias.
    ///
    /// In practice, the sender should use the priority from the
    /// TrackNamespace, not infer it from the datagram. This is a
    /// convenience method for logging and diagnostics.
    pub fn effective_priority(&self) -> u8 {
        // Default to medium priority; actual priority comes from TrackNamespace
        priority::AUDIO
    }
}

// =============================================================================
// MoQ Control Messages
// =============================================================================

/// MoQ CLIENT_SETUP message (draft-17 §7.1).
///
/// Sent by the client on the control stream after QUIC handshake.
/// Contains supported versions and role.
#[derive(Debug, Clone)]
pub struct ClientSetup {
    /// Supported MoQ protocol versions (draft-17 = 0xff000011).
    pub versions: Vec<u64>,
    /// Role: publisher (0x01), subscriber (0x02), or both (0x03).
    pub role: u8,
    /// Path (optional, for multi-tenant proxies).
    pub path: Option<String>,
}

impl ClientSetup {
    /// Draft-17 version number.
    pub const DRAFT_17: u64 = 0xff000011;

    /// Create a CLIENT_SETUP for a VoIP client (publisher + subscriber).
    pub fn voip_default() -> Self {
        Self {
            versions: vec![Self::DRAFT_17],
            role: 0x03, // both publisher and subscriber
            path: None,
        }
    }

    /// Encode to bytes for sending on the control stream.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(64);
        encode_varint(&mut buf, msg_type::CLIENT_SETUP);
        encode_varint(&mut buf, self.versions.len() as u64);
        for &v in &self.versions {
            encode_varint(&mut buf, v);
        }
        encode_varint(&mut buf, self.role as u64);
        if let Some(ref path) = self.path {
            encode_varint(&mut buf, path.len() as u64);
            buf.extend_from_slice(path.as_bytes());
        }
        buf.freeze()
    }
}

/// MoQ SERVER_SETUP message (draft-17 §7.2).
///
/// Sent by the server (or peer) in response to CLIENT_SETUP.
#[derive(Debug, Clone)]
pub struct ServerSetup {
    /// Selected MoQ protocol version.
    pub version: u64,
    /// Role: publisher, subscriber, or both.
    pub role: u8,
    /// Path (optional).
    pub path: Option<String>,
}

impl ServerSetup {
    /// Decode a SERVER_SETUP from bytes on the control stream.
    pub fn decode(data: &[u8]) -> Result<Self, MoqError> {
        let mut cursor = data;
        let (msg_type_val, mt_len) = decode_varint(cursor);
        cursor.advance(mt_len);

        if msg_type_val != msg_type::SERVER_SETUP {
            return Err(MoqError::UnexpectedMessageType {
                expected: msg_type::SERVER_SETUP,
                got: msg_type_val,
            });
        }

        let (version, v_len) = decode_varint(cursor);
        cursor.advance(v_len);

        let (role, r_len) = decode_varint(cursor);
        cursor.advance(r_len);

        let path = if cursor.has_remaining() {
            let (path_len, pl_len) = decode_varint(cursor);
            cursor.advance(pl_len);
            if cursor.len() >= path_len as usize {
                Some(String::from_utf8_lossy(&cursor[..path_len as usize]).to_string())
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            version,
            role: role as u8,
            path,
        })
    }
}

/// MoQ ANNOUNCE message (draft-17 §8.1).
///
/// Publisher announces a track namespace that it will publish.
#[derive(Debug, Clone)]
pub struct Announce {
    /// Track namespace being announced.
    pub namespace: String,
    /// Track parameters (codec, bitrate, etc.).
    pub parameters: Vec<TrackParameter>,
}

/// MoQ SUBSCRIBE message (draft-17 §8.2).
///
/// Subscriber requests to receive a track.
#[derive(Debug, Clone)]
pub struct Subscribe {
    /// Subscribe ID (client-assigned, unique per subscription).
    pub subscribe_id: u64,
    /// Track namespace to subscribe to.
    pub namespace: String,
    /// Track name within the namespace.
    pub track_name: String,
    /// Priority for this subscription (0 = highest).
    pub priority: u8,
    /// Start point for the subscription (latest, earliest, or absolute).
    pub start: StartPoint,
}

/// Start point for a MoQ subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartPoint {
    /// Start from the newest available object.
    Latest,
    /// Start from the earliest available object.
    Earliest,
    /// Start from an absolute group/object position.
    Absolute { group: u64, object: u64 },
}

/// MoQ SUBSCRIBE_OK message (draft-17 §8.3).
///
/// Publisher confirms subscription and provides the track alias.
#[derive(Debug, Clone)]
pub struct SubscribeOk {
    /// Subscribe ID this response is for.
    pub subscribe_id: u64,
    /// Track alias assigned by the publisher for this subscription.
    pub track_alias: u32,
    /// Expiry time for the subscription in seconds (0 = no expiry).
    pub expires: u64,
}

/// MoQ ANNOUNCE_OK message.
#[derive(Debug, Clone)]
pub struct AnnounceOk {
    /// Namespace that was confirmed.
    pub namespace: String,
}

/// A track parameter key-value pair for codec negotiation.
#[derive(Debug, Clone)]
pub struct TrackParameter {
    /// Parameter key (e.g., "codec", "bitrate", "samplerate").
    pub key: String,
    /// Parameter value.
    pub value: String,
}

/// MoQ TrackUpdate message (spec/08 §8.9, Step 3.13).
///
/// Sent in-channel to add/remove tracks and subscriptions mid-call.
#[derive(Debug, Clone)]
pub struct TrackUpdate {
    /// Subscribe ID being updated.
    pub subscribe_id: u64,
    /// New priority for the track.
    pub priority: u8,
}

/// MoQ ConnectionMigration in-channel message (spec/08 §8.8, Step 3.12).
///
/// Sent over the existing QUIC stream after a network change.
#[derive(Debug, Clone)]
pub struct ConnectionMigrationMsg {
    /// New IPv6 addresses after migration.
    pub new_ipv6_addresses: Vec<String>,
    /// New IPv4 reflexive addresses after migration.
    pub new_ipv4_reflexive: Vec<String>,
}

// =============================================================================
// Quality Feedback
// =============================================================================

/// MoQ quality feedback report (spec/05, replaces RTCP).
///
/// Sent periodically at 1Hz (configurable) to provide quality
/// information about received tracks.
#[derive(Debug, Clone)]
pub struct QualityReport {
    /// Track alias this report is for.
    pub track_alias: u32,
    /// Sequence number of the last received object.
    pub last_seq: u64,
    /// Number of objects received.
    pub received: u64,
    /// Number of objects lost (missing sequence numbers).
    pub lost: u64,
    /// Measured round-trip time in microseconds.
    pub rtt_us: u64,
    /// Jitter in microseconds.
    pub jitter_us: u64,
    /// Timestamp when this report was generated.
    pub report_time: Instant,
}

impl QualityReport {
    /// Create a new quality report.
    pub fn new(track_alias: u32) -> Self {
        Self {
            track_alias,
            last_seq: 0,
            received: 0,
            lost: 0,
            rtt_us: 0,
            jitter_us: 0,
            report_time: Instant::now(),
        }
    }

    /// Calculate the packet loss percentage.
    pub fn loss_percentage(&self) -> f64 {
        let total = self.received + self.lost;
        if total == 0 {
            0.0
        } else {
            (self.lost as f64 / total as f64) * 100.0
        }
    }
}

// =============================================================================
// MoQ Session
// =============================================================================

/// State of a MoQ session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// No session established.
    Idle,
    /// CLIENT_SETUP sent, waiting for SERVER_SETUP.
    SettingUp,
    /// Session is active — tracks can be announced/subscribed.
    Active,
    /// Session is closing.
    Closing,
    /// Session has been closed.
    Closed,
}

/// A MoQ session established on a QUIC connection.
///
/// Manages the lifecycle of a MoQ session:
/// 1. CLIENT_SETUP / SERVER_SETUP exchange
/// 2. Track announcement and subscription
/// 3. Media datagram send/receive
/// 4. Quality feedback reporting
/// 5. Track updates and connection migration
pub struct MoqSession {
    /// The underlying QUIC connection.
    connection: Connection,
    /// Current session state.
    state: Arc<RwLock<SessionState>>,
    /// Active track subscriptions (subscribe_id → TrackNamespace).
    subscriptions: Arc<RwLock<Vec<TrackSubscription>>>,
    /// Announced tracks (namespace → TrackNamespace).
    announced: Arc<RwLock<Vec<TrackNamespace>>>,
    /// Quality report state (track_alias → QualityReport).
    quality_reports: Arc<RwLock<Vec<QualityReport>>>,
    /// Configuration.
    config: Arc<VoIPConfig>,
    /// Next subscribe ID counter.
    next_subscribe_id: Arc<RwLock<u64>>,
    /// Control stream (send side).
    control_send: Arc<RwLock<Option<SendStream>>>,
    /// Control stream (receive side).
    control_recv: Arc<RwLock<Option<RecvStream>>>,
}

/// An active track subscription.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TrackSubscription {
    subscribe_id: u64,
    namespace: TrackNamespace,
    start: StartPoint,
}

impl MoqSession {
    /// Create a new MoQ session on an existing QUIC connection.
    ///
    /// The connection should already be established (via Three Pillars
    /// connection manager or MASQUE tunnel).
    pub fn new(connection: Connection, config: Arc<VoIPConfig>) -> Self {
        Self {
            connection,
            state: Arc::new(RwLock::new(SessionState::Idle)),
            subscriptions: Arc::new(RwLock::new(Vec::new())),
            announced: Arc::new(RwLock::new(Vec::new())),
            quality_reports: Arc::new(RwLock::new(Vec::new())),
            config,
            next_subscribe_id: Arc::new(RwLock::new(0)),
            control_send: Arc::new(RwLock::new(None)),
            control_recv: Arc::new(RwLock::new(None)),
        }
    }

    /// Perform the MoQ session setup handshake.
    ///
    /// 1. Open a bidirectional control stream
    /// 2. Send CLIENT_SETUP
    /// 3. Receive and parse SERVER_SETUP from the control stream
    ///
    /// Per spec/05 §5.4: "QUIC handshake (1 RTT) → MoQ session setup
    /// on QUIC connection → client announces tracks"
    ///
    /// After a successful CLIENT_SETUP/SERVER_SETUP exchange, the session
    /// transitions to the `Active` state and tracks can be announced/subscribed.
    #[instrument(skip(self))]
    pub async fn setup(&self) -> Result<(), MoqError> {
        let mut state = self.state.write().await;
        if *state != SessionState::Idle {
            return Err(MoqError::InvalidState {
                expected: "Idle",
                got: format!("{:?}", *state),
            });
        }

        *state = SessionState::SettingUp;
        drop(state);

        // Step 1: Open a bidirectional control stream
        let (send, recv) = self.connection.open_bi().await.map_err(|e| {
            MoqError::TransportError(format!("open control stream: {}", e))
        })?;

        *self.control_send.write().await = Some(send);
        *self.control_recv.write().await = Some(recv);

        // Step 2: Send CLIENT_SETUP
        let client_setup = ClientSetup::voip_default();
        let setup_bytes = client_setup.encode();

        {
            let mut control_send = self.control_send.write().await;
            if let Some(ref mut send) = *control_send {
                send.write_all(&setup_bytes).await.map_err(|e| {
                    MoqError::TransportError(format!("send CLIENT_SETUP: {}", e))
                })?;
            }
        }

        // Step 3: Receive SERVER_SETUP from the control stream
        // Per ROADMAP 3.5: after sending CLIENT_SETUP, read the response
        // from the control stream, parse the type byte to determine the
        // message type, and for SERVER_SETUP (type 0x02), decode and
        // validate the version.
        {
            let mut control_recv = self.control_recv.write().await;
            let recv_stream = control_recv
                .as_mut()
                .ok_or_else(|| MoqError::TransportError("control receive stream missing".to_string()))?;

            // Read the response — we need at least enough bytes for the message type varint
            let mut buf = [0u8; 1024];
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                recv_stream.read(&mut buf),
            )
            .await
            .map_err(|_| MoqError::TransportError("SERVER_SETUP read timeout".to_string()))?
            .map_err(|e| MoqError::TransportError(format!("read SERVER_SETUP: {}", e)))?
            .unwrap_or(0);

            if n == 0 {
                return Err(MoqError::TransportError(
                    "control stream closed before SERVER_SETUP received".to_string(),
                ));
            }

            // Parse the message type varint from the start of the buffer
            let (msg_type_val, _type_len) = decode_varint(&buf[..n]);

            match msg_type_val {
                0x02 => {
                    // SERVER_SETUP — decode the version and role
                    let server_setup = ServerSetup::decode(&buf[..n])?;
                    debug!(
                        version = server_setup.version,
                        role = server_setup.role,
                        "Received SERVER_SETUP"
                    );

                    // Validate that the server selected a compatible version
                    if server_setup.version != ClientSetup::DRAFT_17 {
                        warn!(
                            server_version = server_setup.version,
                            expected = ClientSetup::DRAFT_17,
                            "Server selected unexpected MoQ version"
                        );
                        return Err(MoqError::VersionNegotiationFailed);
                    }

                    info!(
                        version = server_setup.version,
                        "MoQ session setup complete (SERVER_SETUP verified)"
                    );
                }
                other => {
                    // Unexpected message type during setup handshake
                    return Err(MoqError::UnexpectedMessageType {
                        expected: msg_type::SERVER_SETUP,
                        got: other,
                    });
                }
            }
        }

        *self.state.write().await = SessionState::Active;
        Ok(())
    }

    /// Accept a MoQ session from an incoming QUIC connection.
    ///
    /// Called by the peer that accepted the QUIC connection.
    /// Reads CLIENT_SETUP, sends SERVER_SETUP.
    #[instrument(skip(self))]
    pub async fn accept(&self) -> Result<(), MoqError> {
        let mut state = self.state.write().await;
        if *state != SessionState::Idle {
            return Err(MoqError::InvalidState {
                expected: "Idle",
                got: format!("{:?}", *state),
            });
        }

        *state = SessionState::SettingUp;
        drop(state);

        // Accept a bidirectional stream (the control stream from the client)
        let (send, recv) = self.connection.accept_bi().await.map_err(|e| {
            MoqError::TransportError(format!("accept control stream: {}", e))
        })?;

        *self.control_send.write().await = Some(send);
        *self.control_recv.write().await = Some(recv);

        // Read CLIENT_SETUP from the client
        // For now, send SERVER_SETUP in response
        let server_setup_bytes = {
            let mut buf = BytesMut::with_capacity(32);
            encode_varint(&mut buf, msg_type::SERVER_SETUP);
            encode_varint(&mut buf, ClientSetup::DRAFT_17);
            encode_varint(&mut buf, 0x03); // role: both
            buf.freeze()
        };

        {
            let mut control_send = self.control_send.write().await;
            if let Some(ref mut send) = *control_send {
                send.write_all(&server_setup_bytes).await.map_err(|e| {
                    MoqError::TransportError(format!("send SERVER_SETUP: {}", e))
                })?;
            }
        }

        info!("MoQ session accepted (SERVER_SETUP sent)");

        *self.state.write().await = SessionState::Active;
        Ok(())
    }

    /// Announce a track namespace that this peer will publish.
    ///
    /// Per spec/05 §5.5, typical namespaces:
    /// - `voip/{peer_id}/audio/opus-48k`
    /// - `voip/{peer_id}/video/vp9-720p`
    #[instrument(skip(self))]
    pub async fn announce(&self, namespace: TrackNamespace) -> Result<(), MoqError> {
        let state = self.state.read().await;
        if *state != SessionState::Active {
            return Err(MoqError::InvalidState {
                expected: "Active",
                got: format!("{:?}", *state),
            });
        }
        drop(state);

        // Send ANNOUNCE on the control stream
        let mut buf = BytesMut::with_capacity(namespace.namespace.len() + 16);
        encode_varint(&mut buf, msg_type::ANNOUNCE);
        encode_varint(&mut buf, namespace.namespace.len() as u64);
        buf.extend_from_slice(namespace.namespace.as_bytes());

        {
            let mut control_send = self.control_send.write().await;
            if let Some(ref mut send) = *control_send {
                send.write_all(&buf.freeze()).await.map_err(|e| {
                    MoqError::TransportError(format!("send ANNOUNCE: {}", e))
                })?;
            }
        }

        // Track the announcement locally
        self.announced.write().await.push(namespace.clone());

        info!(namespace = %namespace.namespace, "Track announced");
        Ok(())
    }

    /// Subscribe to a track namespace.
    ///
    /// Per spec/05 §5.4: "Peer subscribes to audio track — MoQ subscribe message"
    #[instrument(skip(self))]
    pub async fn subscribe(
        &self,
        namespace: TrackNamespace,
        start: StartPoint,
    ) -> Result<u64, MoqError> {
        let state = self.state.read().await;
        if *state != SessionState::Active {
            return Err(MoqError::InvalidState {
                expected: "Active",
                got: format!("{:?}", *state),
            });
        }
        drop(state);

        // Assign a subscribe ID
        let subscribe_id = {
            let mut next = self.next_subscribe_id.write().await;
            let id = *next;
            *next += 1;
            id
        };

        // Parse namespace into namespace + track name
        let (ns, track_name) = parse_namespace(&namespace.namespace);

        // Send SUBSCRIBE on the control stream
        let mut buf = BytesMut::with_capacity(namespace.namespace.len() + 32);
        encode_varint(&mut buf, msg_type::SUBSCRIBE);
        encode_varint(&mut buf, subscribe_id);
        encode_varint(&mut buf, ns.len() as u64);
        buf.extend_from_slice(ns.as_bytes());
        encode_varint(&mut buf, track_name.len() as u64);
        buf.extend_from_slice(track_name.as_bytes());
        encode_varint(&mut buf, namespace.priority as u64);
        // Start point encoding
        match start {
            StartPoint::Latest => encode_varint(&mut buf, 0x01),
            StartPoint::Earliest => encode_varint(&mut buf, 0x02),
            StartPoint::Absolute { group, object } => {
                encode_varint(&mut buf, 0x03);
                encode_varint(&mut buf, group);
                encode_varint(&mut buf, object);
            }
        }

        {
            let mut control_send = self.control_send.write().await;
            if let Some(ref mut send) = *control_send {
                send.write_all(&buf.freeze()).await.map_err(|e| {
                    MoqError::TransportError(format!("send SUBSCRIBE: {}", e))
                })?;
            }
        }

        // Track the subscription locally
        self.subscriptions.write().await.push(TrackSubscription {
            subscribe_id,
            namespace: namespace.clone(),
            start,
        });

        info!(
            subscribe_id,
            namespace = %namespace.namespace,
            "Track subscribed"
        );

        Ok(subscribe_id)
    }

    /// Send a media datagram over the QUIC connection.
    ///
    /// Per spec/11 §11.6, the datagram is sent as a QUIC datagram
    /// (RFC 9221), which provides unreliable, unordered delivery —
    /// ideal for real-time media.
    #[instrument(skip(self, datagram), fields(alias = datagram.track_alias, seq = datagram.sequence))]
    pub async fn send_datagram(&self, datagram: &MoqDatagram) -> Result<(), MoqError> {
        let state = self.state.read().await;
        if *state != SessionState::Active {
            return Err(MoqError::InvalidState {
                expected: "Active",
                got: format!("{:?}", *state),
            });
        }
        drop(state);

        let encoded = datagram.encode();
        self.connection
            .send_datagram(encoded)
            .map_err(|e| MoqError::DatagramSendFailed(format!("{}", e)))?;

        Ok(())
    }

    /// Receive a media datagram from the QUIC connection.
    ///
    /// Reads a QUIC datagram and decodes the MoQ datagram header.
    pub async fn recv_datagram(&self) -> Result<MoqDatagram, MoqError> {
        let state = self.state.read().await;
        if *state != SessionState::Active {
            return Err(MoqError::InvalidState {
                expected: "Active",
                got: format!("{:?}", *state),
            });
        }
        drop(state);

        let data = self
            .connection
            .read_datagram()
            .await
            .map_err(|e| MoqError::DatagramRecvFailed(format!("{}", e)))?;

        MoqDatagram::decode(&data)
    }

    /// Send a quality feedback report.
    ///
    /// Per spec/05: "Quality feedback via MoQ — replaces RTCP"
    /// Sent periodically at 1Hz (configurable via MoqFeedbackIntervalMs).
    pub async fn send_quality_report(&self, report: &QualityReport) -> Result<(), MoqError> {
        let mut buf = BytesMut::with_capacity(64);
        // Feedback message type (custom for VoIP MoQ)
        encode_varint(&mut buf, 0x80); // feedback type
        encode_varint(&mut buf, report.track_alias as u64);
        encode_varint(&mut buf, report.last_seq);
        encode_varint(&mut buf, report.received);
        encode_varint(&mut buf, report.lost);
        encode_varint(&mut buf, report.rtt_us);

        {
            let mut control_send = self.control_send.write().await;
            if let Some(ref mut send) = *control_send {
                send.write_all(&buf.freeze()).await.map_err(|e| {
                    MoqError::TransportError(format!("send quality report: {}", e))
                })?;
            }
        }

        debug!(
            track_alias = report.track_alias,
            last_seq = report.last_seq,
            received = report.received,
            lost = report.lost,
            loss_pct = format!("{:.1}%", report.loss_percentage()),
            "Quality report sent"
        );

        Ok(())
    }

    /// Send a TrackUpdate message (Step 3.13).
    ///
    /// Add/remove tracks and subscriptions mid-call.
    pub async fn send_track_update(&self, update: &TrackUpdate) -> Result<(), MoqError> {
        let mut buf = BytesMut::with_capacity(16);
        encode_varint(&mut buf, msg_type::TRACK_UPDATE);
        encode_varint(&mut buf, update.subscribe_id);
        encode_varint(&mut buf, update.priority as u64);

        {
            let mut control_send = self.control_send.write().await;
            if let Some(ref mut send) = *control_send {
                send.write_all(&buf.freeze()).await.map_err(|e| {
                    MoqError::TransportError(format!("send track update: {}", e))
                })?;
            }
        }

        info!(
            subscribe_id = update.subscribe_id,
            priority = update.priority,
            "Track update sent"
        );
        Ok(())
    }

    /// Send a ConnectionMigration message (Step 3.12).
    ///
    /// In-channel message sent over the existing QUIC stream after
    /// a network change, providing new address information.
    pub async fn send_migration_message(
        &self,
        msg: &ConnectionMigrationMsg,
    ) -> Result<(), MoqError> {
        let mut buf = BytesMut::with_capacity(256);
        encode_varint(&mut buf, msg_type::CONNECTION_MIGRATION);
        encode_varint(&mut buf, msg.new_ipv6_addresses.len() as u64);
        for addr in &msg.new_ipv6_addresses {
            encode_varint(&mut buf, addr.len() as u64);
            buf.extend_from_slice(addr.as_bytes());
        }
        encode_varint(&mut buf, msg.new_ipv4_reflexive.len() as u64);
        for addr in &msg.new_ipv4_reflexive {
            encode_varint(&mut buf, addr.len() as u64);
            buf.extend_from_slice(addr.as_bytes());
        }

        {
            let mut control_send = self.control_send.write().await;
            if let Some(ref mut send) = *control_send {
                send.write_all(&buf.freeze()).await.map_err(|e| {
                    MoqError::TransportError(format!("send migration message: {}", e))
                })?;
            }
        }

        info!(
            ipv6_count = msg.new_ipv6_addresses.len(),
            ipv4_count = msg.new_ipv4_reflexive.len(),
            "Connection migration message sent"
        );
        Ok(())
    }

    /// Close the MoQ session gracefully.
    pub async fn close(&self) -> Result<(), MoqError> {
        *self.state.write().await = SessionState::Closing;

        // Close the QUIC connection (this implicitly closes all streams)
        self.connection
            .close(quinn::VarInt::from_u32(0), b"moq session closed");

        *self.state.write().await = SessionState::Closed;
        info!("MoQ session closed");
        Ok(())
    }

    /// Get the current session state.
    pub async fn state(&self) -> SessionState {
        *self.state.read().await
    }

    /// Get the QUIC connection reference.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Get the list of announced tracks.
    pub async fn announced_tracks(&self) -> Vec<TrackNamespace> {
        self.announced.read().await.clone()
    }

    /// Get the list of subscribed tracks.
    pub async fn subscribed_tracks(&self) -> Vec<TrackNamespace> {
        self.subscriptions
            .read()
            .await
            .iter()
            .map(|s| s.namespace.clone())
            .collect()
    }

    /// Get the quality report for a specific track.
    pub async fn quality_report(&self, track_alias: u32) -> Option<QualityReport> {
        self.quality_reports
            .read()
            .await
            .iter()
            .find(|r| r.track_alias == track_alias)
            .cloned()
    }

    /// Record a received datagram for quality tracking.
    pub async fn record_received_datagram(&self, datagram: &MoqDatagram) {
        let mut reports = self.quality_reports.write().await;
        if let Some(report) = reports.iter_mut().find(|r| r.track_alias == datagram.track_alias) {
            report.last_seq = datagram.sequence;
            report.received += 1;
        } else {
            let mut report = QualityReport::new(datagram.track_alias);
            report.last_seq = datagram.sequence;
            report.received = 1;
            reports.push(report);
        }
    }

    /// Start the quality feedback loop.
    ///
    /// Sends quality reports at the configured interval (default: 1Hz).
    pub async fn start_feedback_loop(&self) {
        let interval_ms = self.config.moq_feedback_interval_ms;
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            let state = self.state.read().await;
            if *state != SessionState::Active {
                break;
            }
            drop(state);

            let reports = self.quality_reports.read().await;
            for report in reports.iter() {
                if let Err(e) = self.send_quality_report(report).await {
                    warn!(error = %e, "Failed to send quality report");
                }
            }
        }
    }
}

// =============================================================================
// Varint Encoding/Decoding (QUIC-style variable-length integers)
// =============================================================================

/// Encode a varint into a byte buffer (QUIC-style, draft-17).
fn encode_varint(buf: &mut BytesMut, value: u64) {
    if value < 0x40 {
        buf.put_u8(value as u8);
    } else if value < 0x4000 {
        buf.put_u16(0x4000 | value as u16);
    } else if value < 0x40000000 {
        buf.put_u32(0x80000000 | value as u32);
    } else {
        buf.put_u64(0xC000000000000000 | value);
    }
}

/// Decode a varint from a byte slice.
/// Returns (value, bytes_consumed).
fn decode_varint(data: &[u8]) -> (u64, usize) {
    if data.is_empty() {
        return (0, 0);
    }

    let first = data[0];
    let prefix = first >> 6;

    match prefix {
        0 => (first as u64, 1),
        1 => {
            if data.len() < 2 {
                return (0, 0);
            }
            let val = u16::from_be_bytes([data[0], data[1]]) & 0x3FFF;
            (val as u64, 2)
        }
        2 => {
            if data.len() < 4 {
                return (0, 0);
            }
            let val = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) & 0x3FFFFFFF;
            (val as u64, 4)
        }
        3 => {
            if data.len() < 8 {
                return (0, 0);
            }
            let val = u64::from_be_bytes([
                data[0], data[1], data[2], data[3],
                data[4], data[5], data[6], data[7],
            ]) & 0x3FFFFFFFFFFFFFFF;
            (val, 8)
        }
        _ => unreachable!(),
    }
}

/// Parse a MoQ namespace into (namespace_prefix, track_name).
fn parse_namespace(full: &str) -> (&str, &str) {
    // voip/{peer_id}/audio/opus-48k → namespace = "voip/{peer_id}", track = "audio/opus-48k"
    let parts: Vec<&str> = full.splitn(3, '/').collect();
    if parts.len() >= 3 {
        (format!("{}/{}", parts[0], parts[1]).leak(), parts[2])
    } else {
        (full, "")
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encoding_single_byte() {
        let mut buf = BytesMut::new();
        encode_varint(&mut buf, 0);
        assert_eq!(&buf[..], &[0x00]);

        let mut buf = BytesMut::new();
        encode_varint(&mut buf, 63);
        assert_eq!(&buf[..], &[0x3F]);
    }

    #[test]
    fn test_varint_encoding_two_bytes() {
        let mut buf = BytesMut::new();
        encode_varint(&mut buf, 64);
        assert_eq!(&buf[..], &[0x40, 0x40]);

        let mut buf = BytesMut::new();
        encode_varint(&mut buf, 16383);
        assert_eq!(&buf[..], &[0x7F, 0xFF]);
    }

    #[test]
    fn test_varint_roundtrip() {
        for &val in &[0, 1, 63, 64, 16383, 16384, 1073741823] {
            let mut buf = BytesMut::new();
            encode_varint(&mut buf, val);
            let (decoded, len) = decode_varint(&buf);
            assert_eq!(decoded, val, "Roundtrip failed for {}", val);
            assert_eq!(len, buf.len(), "Length mismatch for {}", val);
        }
    }

    #[test]
    fn test_datagram_encode_decode() {
        let datagram = MoqDatagram::new(
            0x00000042, // track alias
            12345,       // sequence
            48000,       // timestamp (1 second at 48kHz)
            Bytes::from_static(b"opus-payload-here"),
        );

        let encoded = datagram.encode();
        let decoded = MoqDatagram::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.datagram_type, DATAGRAM_TYPE_MEDIA);
        assert_eq!(decoded.track_alias, 0x00000042);
        assert_eq!(decoded.sequence, 12345);
        assert_eq!(decoded.timestamp, 48000);
        assert_eq!(&decoded.payload[..], b"opus-payload-here");
    }

    #[test]
    fn test_datagram_too_short() {
        let data = [0x01, 0x00]; // Only 2 bytes, need at least 5
        let result = MoqDatagram::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_track_namespace_audio() {
        let ns = TrackNamespace::audio("peer123");
        assert_eq!(ns.namespace, "voip/peer123/audio/opus-48k");
        assert_eq!(ns.priority, priority::AUDIO);
        assert_eq!(ns.media_type(), MediaType::Audio);
    }

    #[test]
    fn test_track_namespace_video() {
        let ns = TrackNamespace::video("peer456");
        assert_eq!(ns.namespace, "voip/peer456/video/vp9-720p");
        assert_eq!(ns.priority, priority::VIDEO_KEYFRAME);
        assert_eq!(ns.media_type(), MediaType::Video);
    }

    #[test]
    fn test_quality_report_loss_percentage() {
        let mut report = QualityReport::new(42);
        report.received = 95;
        report.lost = 5;
        let pct = report.loss_percentage();
        assert!((pct - 5.0).abs() < 0.01);
    }

    #[test]
    fn test_client_setup_encode() {
        let setup = ClientSetup::voip_default();
        let encoded = setup.encode();
        assert!(!encoded.is_empty());
        // First varint should be CLIENT_SETUP message type
        let (msg_type, _) = decode_varint(&encoded);
        assert_eq!(msg_type, msg_type::CLIENT_SETUP);
    }
}
