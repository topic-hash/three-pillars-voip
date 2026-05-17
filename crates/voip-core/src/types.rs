//! Rust-native types that map to proto enums but are more ergonomic.
//!
//! These types provide a clean Rust API over the generated protobuf types,
//! with `From` conversions for seamless interoperability.

use crate::proto;

// ============================================================================
// NATType
// ============================================================================

/// Detected NAT behavior type.
///
/// Maps to `voip.signaling.NATType` in the proto schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum NATType {
    /// IPv6, no NAT involved
    None = 0,
    /// Full-Cone or Restricted-Cone NAT
    Cone = 1,
    /// Symmetric NAT with +1/+2 delta
    SymmetricSequential = 2,
    /// Symmetric NAT with +1 to +5 delta
    SymmetricPseudo = 3,
    /// Symmetric NAT with random allocation
    SymmetricRandom = 4,
}

impl From<proto::NatType> for NATType {
    fn from(value: proto::NatType) -> Self {
        match value {
            proto::NatType::None => NATType::None,
            proto::NatType::Cone => NATType::Cone,
            proto::NatType::SymmetricSequential => NATType::SymmetricSequential,
            proto::NatType::SymmetricPseudo => NATType::SymmetricPseudo,
            proto::NatType::SymmetricRandom => NATType::SymmetricRandom,
        }
    }
}

impl From<NATType> for proto::NatType {
    fn from(value: NATType) -> Self {
        match value {
            NATType::None => proto::NatType::None,
            NATType::Cone => proto::NatType::Cone,
            NATType::SymmetricSequential => proto::NatType::SymmetricSequential,
            NATType::SymmetricPseudo => proto::NatType::SymmetricPseudo,
            NATType::SymmetricRandom => proto::NatType::SymmetricRandom,
        }
    }
}

impl NATType {
    /// Returns true if this NAT type supports port prediction.
    pub fn is_predictable(&self) -> bool {
        matches!(self, NATType::SymmetricSequential | NATType::SymmetricPseudo)
    }

    /// Returns true if this is IPv6 with no NAT.
    pub fn is_no_nat(&self) -> bool {
        matches!(self, NATType::None)
    }
}

// ============================================================================
// PredictionConfidence
// ============================================================================

/// Confidence level for port prediction.
///
/// Maps to `voip.signaling.PredictionConfidence` in the proto schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum PredictionConfidence {
    /// Delta is constant, +/-1-2 ports, high confidence
    Sequential = 0,
    /// Delta varies +1 to +5, +/-5-8 ports, medium confidence
    PseudoSequential = 1,
    /// Cannot predict, do not attempt
    Random = 2,
}

impl From<proto::PredictionConfidence> for PredictionConfidence {
    fn from(value: proto::PredictionConfidence) -> Self {
        match value {
            proto::PredictionConfidence::Sequential => PredictionConfidence::Sequential,
            proto::PredictionConfidence::PseudoSequential => PredictionConfidence::PseudoSequential,
            proto::PredictionConfidence::Random => PredictionConfidence::Random,
        }
    }
}

impl From<PredictionConfidence> for proto::PredictionConfidence {
    fn from(value: PredictionConfidence) -> Self {
        match value {
            PredictionConfidence::Sequential => proto::PredictionConfidence::Sequential,
            PredictionConfidence::PseudoSequential => proto::PredictionConfidence::PseudoSequential,
            PredictionConfidence::Random => proto::PredictionConfidence::Random,
        }
    }
}

impl PredictionConfidence {
    /// Returns true if prediction is worth attempting.
    pub fn is_predictable(&self) -> bool {
        !matches!(self, PredictionConfidence::Random)
    }
}

// ============================================================================
// ProbeMethod
// ============================================================================

/// Method used for NAT probing.
///
/// Maps to `voip.signaling.ProbeMethod` in the proto schema.
/// In v7+, this is always `QuicPathProbing` (STUN is eliminated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ProbeMethod {
    /// QUIC connection migration to 5 server IPs (v7+)
    QuicPathProbing = 0,
}

impl From<proto::ProbeMethod> for ProbeMethod {
    fn from(value: proto::ProbeMethod) -> Self {
        match value {
            proto::ProbeMethod::QuicPathProbing => ProbeMethod::QuicPathProbing,
        }
    }
}

impl From<ProbeMethod> for proto::ProbeMethod {
    fn from(value: ProbeMethod) -> Self {
        match value {
            ProbeMethod::QuicPathProbing => proto::ProbeMethod::QuicPathProbing,
        }
    }
}

// ============================================================================
// DiscoveryMethod
// ============================================================================

/// How a peer was discovered.
///
/// Maps to `voip.signaling.DiscoveryMethod` in the proto schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum DiscoveryMethod {
    /// Found via DHT lookup
    Dht = 0,
    /// Found via signaling server
    Signaling = 1,
    /// Found in local peer address book cache
    Cache = 2,
}

impl From<proto::DiscoveryMethod> for DiscoveryMethod {
    fn from(value: proto::DiscoveryMethod) -> Self {
        match value {
            proto::DiscoveryMethod::Dht => DiscoveryMethod::Dht,
            proto::DiscoveryMethod::Signaling => DiscoveryMethod::Signaling,
            proto::DiscoveryMethod::Cache => DiscoveryMethod::Cache,
        }
    }
}

impl From<DiscoveryMethod> for proto::DiscoveryMethod {
    fn from(value: DiscoveryMethod) -> Self {
        match value {
            DiscoveryMethod::Dht => proto::DiscoveryMethod::Dht,
            DiscoveryMethod::Signaling => proto::DiscoveryMethod::Signaling,
            DiscoveryMethod::Cache => proto::DiscoveryMethod::Cache,
        }
    }
}

// ============================================================================
// MediaType
// ============================================================================

/// Type of media track.
///
/// Maps to `voip.signaling.MediaType` in the proto schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum MediaType {
    /// Audio track
    Audio = 0,
    /// Video track
    Video = 1,
    /// Screen share track
    Screen = 2,
}

impl From<proto::MediaType> for MediaType {
    fn from(value: proto::MediaType) -> Self {
        match value {
            proto::MediaType::Audio => MediaType::Audio,
            proto::MediaType::Video => MediaType::Video,
            proto::MediaType::Screen => MediaType::Screen,
        }
    }
}

impl From<MediaType> for proto::MediaType {
    fn from(value: MediaType) -> Self {
        match value {
            MediaType::Audio => proto::MediaType::Audio,
            MediaType::Video => proto::MediaType::Video,
            MediaType::Screen => proto::MediaType::Screen,
        }
    }
}

// ============================================================================
// CallState
// ============================================================================

/// State of a call in the call lifecycle state machine.
///
/// Maps to `voip.signaling.CallState` in the proto schema.
/// See spec/07 §7.3.1 for the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CallState {
    /// Call is ringing (waiting for callee to accept)
    Ringing = 0,
    /// Callee has accepted, connection attempt in progress
    Accepted = 1,
    /// P2P connection established, media flowing
    Connected = 2,
    /// Connection attempt or active call failed
    Failed = 3,
    /// Call ended normally
    Ended = 4,
}

impl From<proto::CallState> for CallState {
    fn from(value: proto::CallState) -> Self {
        match value {
            proto::CallState::Ringing => CallState::Ringing,
            proto::CallState::Accepted => CallState::Accepted,
            proto::CallState::Connected => CallState::Connected,
            proto::CallState::Failed => CallState::Failed,
            proto::CallState::Ended => CallState::Ended,
        }
    }
}

impl From<CallState> for proto::CallState {
    fn from(value: CallState) -> Self {
        match value {
            CallState::Ringing => proto::CallState::Ringing,
            CallState::Accepted => proto::CallState::Accepted,
            CallState::Connected => proto::CallState::Connected,
            CallState::Failed => proto::CallState::Failed,
            CallState::Ended => proto::CallState::Ended,
        }
    }
}

// ============================================================================
// SubscriptionState
// ============================================================================

/// State of a MoQ track subscription.
///
/// Maps to `voip.signaling.SubscriptionState` in the proto schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SubscriptionState {
    /// Subscription pending
    Pending = 0,
    /// Subscription active, receiving media
    Active = 1,
    /// Subscription paused
    Paused = 2,
    /// Subscription ended
    Ended = 3,
}

impl From<proto::SubscriptionState> for SubscriptionState {
    fn from(value: proto::SubscriptionState) -> Self {
        match value {
            proto::SubscriptionState::Pending => SubscriptionState::Pending,
            proto::SubscriptionState::Active => SubscriptionState::Active,
            proto::SubscriptionState::Paused => SubscriptionState::Paused,
            proto::SubscriptionState::Ended => SubscriptionState::Ended,
        }
    }
}

impl From<SubscriptionState> for proto::SubscriptionState {
    fn from(value: SubscriptionState) -> Self {
        match value {
            SubscriptionState::Pending => proto::SubscriptionState::Pending,
            SubscriptionState::Active => proto::SubscriptionState::Active,
            SubscriptionState::Paused => proto::SubscriptionState::Paused,
            SubscriptionState::Ended => proto::SubscriptionState::Ended,
        }
    }
}

// ============================================================================
// PeerStatus
// ============================================================================

/// Current availability status of a peer.
///
/// Maps to `voip.signaling.PeerStatus` in the proto schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum PeerStatus {
    /// Peer is online and available
    Online = 0,
    /// Peer is offline
    Offline = 1,
    /// Peer is in an active call
    InCall = 2,
}

impl From<proto::PeerStatus> for PeerStatus {
    fn from(value: proto::PeerStatus) -> Self {
        match value {
            proto::PeerStatus::Online => PeerStatus::Online,
            proto::PeerStatus::Offline => PeerStatus::Offline,
            proto::PeerStatus::InCall => PeerStatus::InCall,
        }
    }
}

impl From<PeerStatus> for proto::PeerStatus {
    fn from(value: PeerStatus) -> Self {
        match value {
            PeerStatus::Online => proto::PeerStatus::Online,
            PeerStatus::Offline => proto::PeerStatus::Offline,
            PeerStatus::InCall => proto::PeerStatus::InCall,
        }
    }
}

// ============================================================================
// ConnectionMethod
// ============================================================================

/// How the P2P connection was established.
///
/// Maps to `voip.signaling.ConnectionMethod` in the proto schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ConnectionMethod {
    /// Not yet connected
    None = 0,
    /// Direct IPv6 connection (Pillar 1)
    Ipv6Direct = 1,
    /// IPv4 Cone NAT — QUIC simultaneous open (Pillar 2)
    Ipv4Cone = 2,
    /// IPv4 Symmetric NAT — QUIC path probing + port prediction (Pillar 3)
    Ipv4Prediction = 3,
    /// MASQUE CONNECT-UDP relay over HTTP/3 (RFC 9298)
    Masque = 4,
    /// MASQUE CONNECT-UDP over HTTP/2 (UDP-blocked fallback)
    MasqueHttp2 = 5,
}

impl From<proto::ConnectionMethod> for ConnectionMethod {
    fn from(value: proto::ConnectionMethod) -> Self {
        match value {
            proto::ConnectionMethod::None => ConnectionMethod::None,
            proto::ConnectionMethod::Ipv6Direct => ConnectionMethod::Ipv6Direct,
            proto::ConnectionMethod::Ipv4Cone => ConnectionMethod::Ipv4Cone,
            proto::ConnectionMethod::Ipv4Prediction => ConnectionMethod::Ipv4Prediction,
            proto::ConnectionMethod::Masque => ConnectionMethod::Masque,
            proto::ConnectionMethod::MasqueHttp2 => ConnectionMethod::MasqueHttp2,
        }
    }
}

impl From<ConnectionMethod> for proto::ConnectionMethod {
    fn from(value: ConnectionMethod) -> Self {
        match value {
            ConnectionMethod::None => proto::ConnectionMethod::None,
            ConnectionMethod::Ipv6Direct => proto::ConnectionMethod::Ipv6Direct,
            ConnectionMethod::Ipv4Cone => proto::ConnectionMethod::Ipv4Cone,
            ConnectionMethod::Ipv4Prediction => proto::ConnectionMethod::Ipv4Prediction,
            ConnectionMethod::Masque => proto::ConnectionMethod::Masque,
            ConnectionMethod::MasqueHttp2 => proto::ConnectionMethod::MasqueHttp2,
        }
    }
}

impl ConnectionMethod {
    /// Returns a human-readable label for this connection method.
    pub fn label(&self) -> &'static str {
        match self {
            ConnectionMethod::None => "Not Connected",
            ConnectionMethod::Ipv6Direct => "IPv6 Direct",
            ConnectionMethod::Ipv4Cone => "QUIC Simultaneous Open",
            ConnectionMethod::Ipv4Prediction => "QUIC Port Prediction",
            ConnectionMethod::Masque => "MASQUE/HTTP3",
            ConnectionMethod::MasqueHttp2 => "MASQUE/HTTP2",
        }
    }

    /// Returns true if this is a direct P2P connection (no relay).
    pub fn is_direct(&self) -> bool {
        matches!(
            self,
            ConnectionMethod::Ipv6Direct
                | ConnectionMethod::Ipv4Cone
                | ConnectionMethod::Ipv4Prediction
        )
    }

    /// Returns true if this connection uses a MASQUE relay.
    pub fn is_relayed(&self) -> bool {
        matches!(self, ConnectionMethod::Masque | ConnectionMethod::MasqueHttp2)
    }
}

// ============================================================================
// CallEndReason
// ============================================================================

/// Reason a call ended or failed.
///
/// Maps to `voip.signaling.CallEndReason` in the proto schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CallEndReason {
    /// Normal call end
    Normal = 0,
    /// Callee rejected the call
    Rejected = 1,
    /// Connection attempt timed out
    Timeout = 2,
    /// Both peers IPv4 Symmetric random, no prediction possible
    FailedIpv4Random = 3,
    /// UDP blocked by firewall
    FailedUdpBlocked = 4,
    /// Network error after connection
    FailedNetwork = 5,
    /// Connection migration failed
    MigrationFailed = 6,
    /// All MASQUE proxies unreachable
    FailedMasqueUnreachable = 7,
    /// UDP blocked AND TCP port 443 blocked — no MASQUE possible
    FailedTcpBlocked = 8,
}

impl From<proto::CallEndReason> for CallEndReason {
    fn from(value: proto::CallEndReason) -> Self {
        match value {
            proto::CallEndReason::Normal => CallEndReason::Normal,
            proto::CallEndReason::Rejected => CallEndReason::Rejected,
            proto::CallEndReason::Timeout => CallEndReason::Timeout,
            proto::CallEndReason::FailedIpv4Random => CallEndReason::FailedIpv4Random,
            proto::CallEndReason::FailedUdpBlocked => CallEndReason::FailedUdpBlocked,
            proto::CallEndReason::FailedNetwork => CallEndReason::FailedNetwork,
            proto::CallEndReason::MigrationFailed => CallEndReason::MigrationFailed,
            proto::CallEndReason::FailedMasqueUnreachable => CallEndReason::FailedMasqueUnreachable,
            proto::CallEndReason::FailedTcpBlocked => CallEndReason::FailedTcpBlocked,
        }
    }
}

impl From<CallEndReason> for proto::CallEndReason {
    fn from(value: CallEndReason) -> Self {
        match value {
            CallEndReason::Normal => proto::CallEndReason::Normal,
            CallEndReason::Rejected => proto::CallEndReason::Rejected,
            CallEndReason::Timeout => proto::CallEndReason::Timeout,
            CallEndReason::FailedIpv4Random => proto::CallEndReason::FailedIpv4Random,
            CallEndReason::FailedUdpBlocked => proto::CallEndReason::FailedUdpBlocked,
            CallEndReason::FailedNetwork => proto::CallEndReason::FailedNetwork,
            CallEndReason::MigrationFailed => proto::CallEndReason::MigrationFailed,
            CallEndReason::FailedMasqueUnreachable => proto::CallEndReason::FailedMasqueUnreachable,
            CallEndReason::FailedTcpBlocked => proto::CallEndReason::FailedTcpBlocked,
        }
    }
}

impl CallEndReason {
    /// Returns a human-readable description of the end reason.
    pub fn description(&self) -> &'static str {
        match self {
            CallEndReason::Normal => "Normal call end",
            CallEndReason::Rejected => "Call declined",
            CallEndReason::Timeout => "Connection attempt timed out",
            CallEndReason::FailedIpv4Random => {
                "Network incompatibility — direct connection not possible. Retry sent."
            }
            CallEndReason::FailedUdpBlocked => {
                "Network does not allow voice calls — UDP is blocked"
            }
            CallEndReason::FailedNetwork => {
                "Call failed — secure connection could not be established"
            }
            CallEndReason::MigrationFailed => "Call dropped — network change failed",
            CallEndReason::FailedMasqueUnreachable => "All MASQUE proxies unreachable",
            CallEndReason::FailedTcpBlocked => {
                "UDP blocked AND TCP port 443 blocked — no MASQUE possible"
            }
        }
    }

    /// Returns true if this reason indicates a failure (not normal end or rejection).
    pub fn is_failure(&self) -> bool {
        matches!(
            self,
            CallEndReason::Timeout
                | CallEndReason::FailedIpv4Random
                | CallEndReason::FailedUdpBlocked
                | CallEndReason::FailedNetwork
                | CallEndReason::MigrationFailed
                | CallEndReason::FailedMasqueUnreachable
                | CallEndReason::FailedTcpBlocked
        )
    }

    /// Returns true if push retry should be attempted for this failure reason.
    pub fn should_retry(&self) -> bool {
        matches!(
            self,
            CallEndReason::FailedIpv4Random | CallEndReason::FailedMasqueUnreachable
        )
    }
}

// ============================================================================
// Composite Structs
// ============================================================================

/// Port prediction data for symmetric NAT traversal.
///
/// Rust-native representation of `voip.signaling.PortPrediction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortPredictionData {
    /// External IPv4 address
    pub external_ip: String,
    /// Start of predicted port range (1024-65535)
    pub predicted_port_start: u32,
    /// End of predicted port range (>= predicted_port_start)
    pub predicted_port_end: u32,
    /// Confidence level of prediction
    pub confidence: PredictionConfidence,
    /// Last known external port from QUIC path probing
    pub base_port: u32,
    /// Average delta between allocations (e.g., +1 for sequential)
    pub delta_pattern: i32,
    /// When the probe was performed (unix timestamp, seconds)
    pub probed_at: u64,
    /// How NAT was probed (always QuicPathProbing in v7+)
    pub probe_method: ProbeMethod,
}

impl PortPredictionData {
    /// Creates a new port prediction from a proto PortPrediction message.
    pub fn from_proto(proto: &proto::PortPrediction) -> Self {
        Self {
            external_ip: proto.external_ip.clone(),
            predicted_port_start: proto.predicted_port_start,
            predicted_port_end: proto.predicted_port_end,
            confidence: proto.confidence().into(),
            base_port: proto.base_port,
            delta_pattern: proto.delta_pattern,
            probed_at: proto.probed_at,
            probe_method: proto.probe_method().into(),
        }
    }

    /// Converts to a proto PortPrediction message.
    pub fn to_proto(&self) -> proto::PortPrediction {
        proto::PortPrediction {
            external_ip: self.external_ip.clone(),
            predicted_port_start: self.predicted_port_start,
            predicted_port_end: self.predicted_port_end,
            confidence: self.confidence.into(),
            base_port: self.base_port,
            delta_pattern: self.delta_pattern,
            probed_at: self.probed_at,
            probe_method: self.probe_method.into(),
        }
    }

    /// Returns the size of the predicted port range.
    pub fn range_size(&self) -> u32 {
        self.predicted_port_end.saturating_sub(self.predicted_port_start) + 1
    }

    /// Returns true if the prediction is worth attempting.
    pub fn is_usable(&self) -> bool {
        self.confidence.is_predictable() && self.predicted_port_start > 0 && self.predicted_port_end >= self.predicted_port_start
    }
}

/// MoQ track announcement information.
///
/// Rust-native representation of `voip.signaling.TrackAnnouncement`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackInfo {
    /// Track namespace (e.g., "voip/peer-abc/audio/opus-48k")
    pub track_namespace: String,
    /// Codec identifier (e.g., "opus-48k")
    pub codec: String,
    /// MoQ send ordering priority (0 = highest)
    pub priority: u32,
    /// Type of media
    pub media_type: MediaType,
    /// Maximum bitrate in bps
    pub bitrate_max: u32,
    /// Minimum bitrate in bps
    pub bitrate_min: u32,
    /// Duration of each media frame in milliseconds
    pub frame_duration_ms: u32,
}

impl TrackInfo {
    /// Creates a TrackInfo from a proto TrackAnnouncement message.
    pub fn from_proto(proto: &proto::TrackAnnouncement) -> Self {
        Self {
            track_namespace: proto.track_namespace.clone(),
            codec: proto.codec.clone(),
            priority: proto.priority,
            media_type: proto.media_type().into(),
            bitrate_max: proto.bitrate_max,
            bitrate_min: proto.bitrate_min,
            frame_duration_ms: proto.frame_duration_ms,
        }
    }

    /// Converts to a proto TrackAnnouncement message.
    pub fn to_proto(&self) -> proto::TrackAnnouncement {
        proto::TrackAnnouncement {
            track_namespace: self.track_namespace.clone(),
            codec: self.codec.clone(),
            priority: self.priority,
            media_type: self.media_type.into(),
            bitrate_max: self.bitrate_max,
            bitrate_min: self.bitrate_min,
            frame_duration_ms: self.frame_duration_ms,
        }
    }
}

/// NAT information for a peer.
///
/// Rust-native representation of `voip.signaling.NATInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NATInfo {
    /// Detected NAT type
    pub nat_type: NATType,
    /// Port prediction data (None if IPv6 or Cone NAT)
    pub prediction: Option<PortPredictionData>,
}

impl NATInfo {
    /// Creates a NATInfo with no NAT (IPv6).
    pub fn no_nat() -> Self {
        Self {
            nat_type: NATType::None,
            prediction: None,
        }
    }

    /// Creates a NATInfo for cone NAT.
    pub fn cone_nat() -> Self {
        Self {
            nat_type: NATType::Cone,
            prediction: None,
        }
    }

    /// Creates a NATInfo for symmetric NAT with prediction.
    pub fn symmetric_with_prediction(prediction: PortPredictionData) -> Self {
        let nat_type = match prediction.confidence {
            PredictionConfidence::Sequential => NATType::SymmetricSequential,
            PredictionConfidence::PseudoSequential => NATType::SymmetricPseudo,
            PredictionConfidence::Random => NATType::SymmetricRandom,
        };
        Self {
            nat_type,
            prediction: Some(prediction),
        }
    }

    /// Creates a NATInfo from a proto NATInfo message.
    pub fn from_proto(proto: &proto::NatInfo) -> Self {
        Self {
            nat_type: proto.nat_type().into(),
            prediction: proto.prediction.as_ref().map(PortPredictionData::from_proto),
        }
    }

    /// Converts to a proto NATInfo message.
    pub fn to_proto(&self) -> proto::NatInfo {
        proto::NatInfo {
            nat_type: self.nat_type.into(),
            prediction: self.prediction.as_ref().map(|p| p.to_proto()),
        }
    }

    /// Returns true if this peer can be reached via direct connection.
    pub fn supports_direct(&self) -> bool {
        matches!(
            self.nat_type,
            NATType::None | NATType::Cone | NATType::SymmetricSequential | NATType::SymmetricPseudo
        )
    }
}
