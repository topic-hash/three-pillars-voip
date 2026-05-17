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

impl From<proto::signaling::NatType> for NATType {
    fn from(value: proto::signaling::NatType) -> Self {
        match value {
            proto::signaling::NatType::NatNone => NATType::None,
            proto::signaling::NatType::NatCone => NATType::Cone,
            proto::signaling::NatType::NatSymmetricSequential => NATType::SymmetricSequential,
            proto::signaling::NatType::NatSymmetricPseudo => NATType::SymmetricPseudo,
            proto::signaling::NatType::NatSymmetricRandom => NATType::SymmetricRandom,
        }
    }
}

impl From<NATType> for proto::signaling::NatType {
    fn from(value: NATType) -> Self {
        match value {
            NATType::None => proto::signaling::NatType::NatNone,
            NATType::Cone => proto::signaling::NatType::NatCone,
            NATType::SymmetricSequential => proto::signaling::NatType::NatSymmetricSequential,
            NATType::SymmetricPseudo => proto::signaling::NatType::NatSymmetricPseudo,
            NATType::SymmetricRandom => proto::signaling::NatType::NatSymmetricRandom,
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

impl From<proto::signaling::PredictionConfidence> for PredictionConfidence {
    fn from(value: proto::signaling::PredictionConfidence) -> Self {
        match value {
            proto::signaling::PredictionConfidence::Sequential => PredictionConfidence::Sequential,
            proto::signaling::PredictionConfidence::PseudoSequential => PredictionConfidence::PseudoSequential,
            proto::signaling::PredictionConfidence::Random => PredictionConfidence::Random,
        }
    }
}

impl From<PredictionConfidence> for proto::signaling::PredictionConfidence {
    fn from(value: PredictionConfidence) -> Self {
        match value {
            PredictionConfidence::Sequential => proto::signaling::PredictionConfidence::Sequential,
            PredictionConfidence::PseudoSequential => proto::signaling::PredictionConfidence::PseudoSequential,
            PredictionConfidence::Random => proto::signaling::PredictionConfidence::Random,
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

impl From<proto::signaling::ProbeMethod> for ProbeMethod {
    fn from(value: proto::signaling::ProbeMethod) -> Self {
        match value {
            proto::signaling::ProbeMethod::QuicPathProbing => ProbeMethod::QuicPathProbing,
        }
    }
}

impl From<ProbeMethod> for proto::signaling::ProbeMethod {
    fn from(value: ProbeMethod) -> Self {
        match value {
            ProbeMethod::QuicPathProbing => proto::signaling::ProbeMethod::QuicPathProbing,
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

impl From<proto::signaling::DiscoveryMethod> for DiscoveryMethod {
    fn from(value: proto::signaling::DiscoveryMethod) -> Self {
        match value {
            proto::signaling::DiscoveryMethod::DiscoveryDht => DiscoveryMethod::Dht,
            proto::signaling::DiscoveryMethod::DiscoverySignaling => DiscoveryMethod::Signaling,
            proto::signaling::DiscoveryMethod::DiscoveryCache => DiscoveryMethod::Cache,
        }
    }
}

impl From<DiscoveryMethod> for proto::signaling::DiscoveryMethod {
    fn from(value: DiscoveryMethod) -> Self {
        match value {
            DiscoveryMethod::Dht => proto::signaling::DiscoveryMethod::DiscoveryDht,
            DiscoveryMethod::Signaling => proto::signaling::DiscoveryMethod::DiscoverySignaling,
            DiscoveryMethod::Cache => proto::signaling::DiscoveryMethod::DiscoveryCache,
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

impl From<proto::signaling::MediaType> for MediaType {
    fn from(value: proto::signaling::MediaType) -> Self {
        match value {
            proto::signaling::MediaType::MediaAudio => MediaType::Audio,
            proto::signaling::MediaType::MediaVideo => MediaType::Video,
            proto::signaling::MediaType::MediaScreen => MediaType::Screen,
        }
    }
}

impl From<MediaType> for proto::signaling::MediaType {
    fn from(value: MediaType) -> Self {
        match value {
            MediaType::Audio => proto::signaling::MediaType::MediaAudio,
            MediaType::Video => proto::signaling::MediaType::MediaVideo,
            MediaType::Screen => proto::signaling::MediaType::MediaScreen,
        }
    }
}

// ============================================================================
// CallState
// ============================================================================

/// State of a call in the call lifecycle.
///
/// Maps to `voip.signaling.CallState` in the proto schema.
/// See spec/07 §7.3.1 for the state machine.
///
/// Note: The state machine (`crate::state::CallStateMachine`) uses its own
/// `CallState` which includes an additional `Idle` variant for the
/// pre-call state. This type maps to the on-the-wire proto representation.
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

impl From<proto::signaling::CallState> for CallState {
    fn from(value: proto::signaling::CallState) -> Self {
        match value {
            proto::signaling::CallState::CallRinging => CallState::Ringing,
            proto::signaling::CallState::CallAccepted => CallState::Accepted,
            proto::signaling::CallState::CallConnected => CallState::Connected,
            proto::signaling::CallState::CallFailed => CallState::Failed,
            proto::signaling::CallState::CallEnded => CallState::Ended,
        }
    }
}

impl From<CallState> for proto::signaling::CallState {
    fn from(value: CallState) -> Self {
        match value {
            CallState::Ringing => proto::signaling::CallState::CallRinging,
            CallState::Accepted => proto::signaling::CallState::CallAccepted,
            CallState::Connected => proto::signaling::CallState::CallConnected,
            CallState::Failed => proto::signaling::CallState::CallFailed,
            CallState::Ended => proto::signaling::CallState::CallEnded,
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

impl From<proto::signaling::SubscriptionState> for SubscriptionState {
    fn from(value: proto::signaling::SubscriptionState) -> Self {
        match value {
            proto::signaling::SubscriptionState::SubPending => SubscriptionState::Pending,
            proto::signaling::SubscriptionState::SubActive => SubscriptionState::Active,
            proto::signaling::SubscriptionState::SubPaused => SubscriptionState::Paused,
            proto::signaling::SubscriptionState::SubEnded => SubscriptionState::Ended,
        }
    }
}

impl From<SubscriptionState> for proto::signaling::SubscriptionState {
    fn from(value: SubscriptionState) -> Self {
        match value {
            SubscriptionState::Pending => proto::signaling::SubscriptionState::SubPending,
            SubscriptionState::Active => proto::signaling::SubscriptionState::SubActive,
            SubscriptionState::Paused => proto::signaling::SubscriptionState::SubPaused,
            SubscriptionState::Ended => proto::signaling::SubscriptionState::SubEnded,
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

impl From<proto::signaling::PeerStatus> for PeerStatus {
    fn from(value: proto::signaling::PeerStatus) -> Self {
        match value {
            proto::signaling::PeerStatus::PeerOnline => PeerStatus::Online,
            proto::signaling::PeerStatus::PeerOffline => PeerStatus::Offline,
            proto::signaling::PeerStatus::PeerInCall => PeerStatus::InCall,
        }
    }
}

impl From<PeerStatus> for proto::signaling::PeerStatus {
    fn from(value: PeerStatus) -> Self {
        match value {
            PeerStatus::Online => proto::signaling::PeerStatus::PeerOnline,
            PeerStatus::Offline => proto::signaling::PeerStatus::PeerOffline,
            PeerStatus::InCall => proto::signaling::PeerStatus::PeerInCall,
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

impl From<proto::signaling::ConnectionMethod> for ConnectionMethod {
    fn from(value: proto::signaling::ConnectionMethod) -> Self {
        match value {
            proto::signaling::ConnectionMethod::ConnNone => ConnectionMethod::None,
            proto::signaling::ConnectionMethod::ConnIpv6Direct => ConnectionMethod::Ipv6Direct,
            proto::signaling::ConnectionMethod::ConnIpv4Cone => ConnectionMethod::Ipv4Cone,
            proto::signaling::ConnectionMethod::ConnIpv4Prediction => ConnectionMethod::Ipv4Prediction,
            proto::signaling::ConnectionMethod::ConnMasque => ConnectionMethod::Masque,
            proto::signaling::ConnectionMethod::ConnMasqueHttp2 => ConnectionMethod::MasqueHttp2,
        }
    }
}

impl From<ConnectionMethod> for proto::signaling::ConnectionMethod {
    fn from(value: ConnectionMethod) -> Self {
        match value {
            ConnectionMethod::None => proto::signaling::ConnectionMethod::ConnNone,
            ConnectionMethod::Ipv6Direct => proto::signaling::ConnectionMethod::ConnIpv6Direct,
            ConnectionMethod::Ipv4Cone => proto::signaling::ConnectionMethod::ConnIpv4Cone,
            ConnectionMethod::Ipv4Prediction => proto::signaling::ConnectionMethod::ConnIpv4Prediction,
            ConnectionMethod::Masque => proto::signaling::ConnectionMethod::ConnMasque,
            ConnectionMethod::MasqueHttp2 => proto::signaling::ConnectionMethod::ConnMasqueHttp2,
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

impl From<proto::signaling::CallEndReason> for CallEndReason {
    fn from(value: proto::signaling::CallEndReason) -> Self {
        match value {
            proto::signaling::CallEndReason::EndNormal => CallEndReason::Normal,
            proto::signaling::CallEndReason::EndRejected => CallEndReason::Rejected,
            proto::signaling::CallEndReason::EndTimeout => CallEndReason::Timeout,
            proto::signaling::CallEndReason::EndFailedIpv4Random => CallEndReason::FailedIpv4Random,
            proto::signaling::CallEndReason::EndFailedUdpBlocked => CallEndReason::FailedUdpBlocked,
            proto::signaling::CallEndReason::EndFailedNetwork => CallEndReason::FailedNetwork,
            proto::signaling::CallEndReason::EndMigrationFailed => CallEndReason::MigrationFailed,
            proto::signaling::CallEndReason::EndFailedMasqueUnreachable => CallEndReason::FailedMasqueUnreachable,
            proto::signaling::CallEndReason::EndFailedTcpBlocked => CallEndReason::FailedTcpBlocked,
        }
    }
}

impl From<CallEndReason> for proto::signaling::CallEndReason {
    fn from(value: CallEndReason) -> Self {
        match value {
            CallEndReason::Normal => proto::signaling::CallEndReason::EndNormal,
            CallEndReason::Rejected => proto::signaling::CallEndReason::EndRejected,
            CallEndReason::Timeout => proto::signaling::CallEndReason::EndTimeout,
            CallEndReason::FailedIpv4Random => proto::signaling::CallEndReason::EndFailedIpv4Random,
            CallEndReason::FailedUdpBlocked => proto::signaling::CallEndReason::EndFailedUdpBlocked,
            CallEndReason::FailedNetwork => proto::signaling::CallEndReason::EndFailedNetwork,
            CallEndReason::MigrationFailed => proto::signaling::CallEndReason::EndMigrationFailed,
            CallEndReason::FailedMasqueUnreachable => proto::signaling::CallEndReason::EndFailedMasqueUnreachable,
            CallEndReason::FailedTcpBlocked => proto::signaling::CallEndReason::EndFailedTcpBlocked,
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
// Helper: convert i32 proto enum field to our native enum
// ============================================================================

/// Convert a prost i32 enum field to our native enum via the proto enum.
/// Falls back to the default (discriminant 0) on unknown values.
fn i32_to_native_enum<E, N>(value: i32) -> N
where
    E: TryFrom<i32> + Into<N>,
{
    E::try_from(value)
        .ok()
        .map(Into::into)
        .unwrap_or_else(|| {
            // Fall back to value 0, which is the proto3 default
            E::try_from(0).ok().map(Into::into).unwrap()
        })
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

impl From<proto::signaling::PortPrediction> for PortPredictionData {
    fn from(proto: proto::signaling::PortPrediction) -> Self {
        Self {
            external_ip: proto.external_ip,
            predicted_port_start: proto.predicted_port_start,
            predicted_port_end: proto.predicted_port_end,
            confidence: i32_to_native_enum::<proto::signaling::PredictionConfidence, _>(proto.confidence),
            base_port: proto.base_port,
            delta_pattern: proto.delta_pattern,
            probed_at: proto.probed_at,
            probe_method: i32_to_native_enum::<proto::signaling::ProbeMethod, _>(proto.probe_method),
        }
    }
}

impl From<PortPredictionData> for proto::signaling::PortPrediction {
    fn from(data: PortPredictionData) -> Self {
        Self {
            external_ip: data.external_ip,
            predicted_port_start: data.predicted_port_start,
            predicted_port_end: data.predicted_port_end,
            confidence: proto::signaling::PredictionConfidence::from(data.confidence) as i32,
            base_port: data.base_port,
            delta_pattern: data.delta_pattern,
            probed_at: data.probed_at,
            probe_method: proto::signaling::ProbeMethod::from(data.probe_method) as i32,
        }
    }
}

impl PortPredictionData {
    /// Returns the size of the predicted port range.
    pub fn range_size(&self) -> u32 {
        self.predicted_port_end.saturating_sub(self.predicted_port_start) + 1
    }

    /// Returns true if the prediction is worth attempting.
    pub fn is_usable(&self) -> bool {
        self.confidence.is_predictable()
            && self.predicted_port_start > 0
            && self.predicted_port_end >= self.predicted_port_start
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

impl From<proto::signaling::TrackAnnouncement> for TrackInfo {
    fn from(proto: proto::signaling::TrackAnnouncement) -> Self {
        Self {
            track_namespace: proto.track_namespace,
            codec: proto.codec,
            priority: proto.priority,
            media_type: i32_to_native_enum::<proto::signaling::MediaType, _>(proto.media_type),
            bitrate_max: proto.bitrate_max,
            bitrate_min: proto.bitrate_min,
            frame_duration_ms: proto.frame_duration_ms,
        }
    }
}

impl From<TrackInfo> for proto::signaling::TrackAnnouncement {
    fn from(data: TrackInfo) -> Self {
        Self {
            track_namespace: data.track_namespace,
            codec: data.codec,
            priority: data.priority,
            media_type: proto::signaling::MediaType::from(data.media_type) as i32,
            bitrate_max: data.bitrate_max,
            bitrate_min: data.bitrate_min,
            frame_duration_ms: data.frame_duration_ms,
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

impl From<proto::signaling::NatInfo> for NATInfo {
    fn from(proto: proto::signaling::NatInfo) -> Self {
        Self {
            nat_type: i32_to_native_enum::<proto::signaling::NatType, _>(proto.nat_type),
            prediction: proto.prediction.map(Into::into),
        }
    }
}

impl From<NATInfo> for proto::signaling::NatInfo {
    fn from(data: NATInfo) -> Self {
        Self {
            nat_type: proto::signaling::NatType::from(data.nat_type) as i32,
            prediction: data.prediction.map(Into::into),
        }
    }
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

    /// Returns true if this peer can be reached via direct connection.
    pub fn supports_direct(&self) -> bool {
        matches!(
            self.nat_type,
            NATType::None | NATType::Cone | NATType::SymmetricSequential | NATType::SymmetricPseudo
        )
    }
}
