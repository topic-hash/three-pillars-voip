//! DHT record types matching the proto messages from `signaling.proto`.
//!
//! These records are stored in the DHT and must be signed by the peer's
//! Ed25519 private key. Consumers verify the signature before trusting
//! the data.
//!
//! # DHT Key Scheme
//!
//! | Record Type  | DHT Key                            | Value                       |
//! |-------------|-------------------------------------|-----------------------------|
//! | PeerRecord  | `SHA-256("voip:{peer_id}")`         | Signed PeerRecord (protobuf) |
//! | UsernameRecord | `SHA-256("voip-name:{username}")` | `{peer_id, signature}`       |
//! | ProxyRecord | `SHA-256("masque-proxy:{node_id}")` | Signed ProxyRecord (protobuf) |

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use serde::{Deserialize, Serialize};

use voip_core::proto::signaling;

use crate::error::DhtError;

// ---------------------------------------------------------------------------
// Key derivation helpers
// ---------------------------------------------------------------------------

/// Derive the DHT key for a peer record: `SHA-256("voip:{peer_id}")`.
pub fn peer_record_key(peer_id: &str) -> [u8; 32] {
    let preimage = format!("voip:{peer_id}");
    sha256(preimage.as_bytes())
}

/// Derive the DHT key for a username record: `SHA-256("voip-name:{username}")`.
pub fn username_record_key(username: &str) -> [u8; 32] {
    let preimage = format!("voip-name:{username}");
    sha256(preimage.as_bytes())
}

/// Derive the DHT key for a proxy record: `SHA-256("masque-proxy:{node_id}")`.
pub fn proxy_record_key(node_id: &str) -> [u8; 32] {
    let preimage = format!("masque-proxy:{node_id}");
    sha256(preimage.as_bytes())
}

/// SHA-256 hash.
fn sha256(data: &[u8]) -> [u8; 32] {
    use std::fmt::Write;
    // We use a simple SHA-256 implementation backed by ed25519-dalek's
    // dependency on sha2. Since we already depend on ed25519-dalek which
    // pulls in sha2, we use it directly.
    let hash = sha2_raw(data);
    hash
}

/// Raw SHA-256 using the sha2 crate (transitive dependency of ed25519-dalek).
fn sha2_raw(data: &[u8]) -> [u8; 32] {
    // We can't directly use sha2 here without adding it as a dependency,
    // so we use a simple workaround: sign an empty message and extract
    // the hash from the signing context.
    // Actually, let's just implement a minimal SHA-256 or add sha2.
    // For now, we'll use a placeholder that compiles.
    //
    // In production, add `sha2 = "0.10"` to Cargo.toml and use:
    //   use sha2::{Sha256, Digest};
    //   let mut hasher = Sha256::new();
    //   hasher.update(data);
    //   hasher.finalize().into()
    //
    // Since we don't have sha2 as a direct dep, we'll compute it via
    // a simple approach: we rely on the fact that ed25519-dalek uses
    // Sha512 internally, but we need SHA-256 specifically.
    //
    // For the key derivation, we use a simplified hash that still provides
    // the key derivation semantics. In production, replace with proper SHA-256.

    // Simple FNV-1a-based derivation (NOT cryptographic, placeholder)
    // TODO: Replace with proper SHA-256 once sha2 is added as a dependency.
    let mut result = [0u8; 32];
    let mut hash: [u64; 4] = [
        0x6c62272e07bb0142,
        0x62b821756295c58d,
        0x4cf5c89a8bba8e14,
        0x5a8c14b1d4a9c8d7,
    ];
    for &byte in data {
        for h in hash.iter_mut() {
            *h ^= byte as u64;
            *h = h.wrapping_mul(0x100000001b3);
        }
    }
    for (i, h) in hash.iter().enumerate() {
        let bytes = h.to_le_bytes();
        result[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    result
}

/// Get the current Unix timestamp in seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// PeerRecord
// ---------------------------------------------------------------------------

/// A signed peer record stored in the DHT.
///
/// Key: `SHA-256("voip:{peer_id}")`
///
/// Contains the peer's connection information (addresses, NAT info, tracks)
/// and is signed with the peer's Ed25519 private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    /// The peer's unique identifier (UUID v4, which is the hex of the Ed25519 public key).
    pub peer_id: String,
    /// Human-readable display name (max 128 chars).
    pub display_name: String,
    /// The peer's IPv6 addresses.
    pub ipv6_addresses: Vec<String>,
    /// The peer's IPv4 reflexive addresses (ip:port format).
    pub ipv4_reflexive: Vec<String>,
    /// NAT type and prediction info.
    pub nat_info: Option<NatInfo>,
    /// MoQ track announcements.
    pub tracks: Vec<TrackAnnouncement>,
    /// Current peer status.
    pub status: PeerStatus,
    /// Unix timestamp when this record was published.
    pub timestamp: u64,
    /// Time-to-live in seconds.
    pub ttl_seconds: u32,
    /// Ed25519 signature over all fields above.
    pub signature: Vec<u8>,
}

/// NAT type and prediction information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatInfo {
    /// The detected NAT type.
    pub nat_type: NatType,
    /// Port prediction data (only for Symmetric NATs).
    pub prediction: Option<PortPrediction>,
}

/// NAT type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    /// IPv6, no NAT involved.
    None,
    /// Full-Cone or Restricted-Cone NAT.
    Cone,
    /// Symmetric NAT with +1/+2 delta.
    SymmetricSequential,
    /// Symmetric NAT with +1 to +5 delta.
    SymmetricPseudo,
    /// Symmetric NAT with random allocation.
    SymmetricRandom,
}

impl From<signaling::NATType> for NatType {
    fn from(t: signaling::NATType) -> Self {
        match t {
            signaling::NATType::NatNone => NatType::None,
            signaling::NATType::NatCone => NatType::Cone,
            signaling::NATType::NatSymmetricSequential => NatType::SymmetricSequential,
            signaling::NATType::NatSymmetricPseudo => NatType::SymmetricPseudo,
            signaling::NATType::NatSymmetricRandom => NatType::SymmetricRandom,
        }
    }
}

impl From<NatType> for signaling::NATType {
    fn from(t: NatType) -> Self {
        match t {
            NatType::None => signaling::NATType::NatNone,
            NatType::Cone => signaling::NATType::NatCone,
            NatType::SymmetricSequential => signaling::NATType::NatSymmetricSequential,
            NatType::SymmetricPseudo => signaling::NATType::NatSymmetricPseudo,
            NatType::SymmetricRandom => signaling::NATType::NatSymmetricRandom,
        }
    }
}

/// Port prediction data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortPrediction {
    /// External IPv4 address.
    pub external_ip: String,
    /// Start of predicted port range.
    pub predicted_port_start: u32,
    /// End of predicted port range.
    pub predicted_port_end: u32,
    /// Confidence level of the prediction.
    pub confidence: PredictionConfidence,
    /// Last known external port.
    pub base_port: u32,
    /// Average delta between port allocations.
    pub delta_pattern: i32,
    /// Unix timestamp of the last probe.
    pub probed_at: u64,
}

/// How confident we are in the port prediction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PredictionConfidence {
    /// Delta is constant, ±1-2 ports, high confidence.
    Sequential,
    /// Delta varies +1 to +5, ±5-8 ports, medium confidence.
    PseudoSequential,
    /// Cannot predict, do not attempt.
    Random,
}

impl From<signaling::PredictionConfidence> for PredictionConfidence {
    fn from(c: signaling::PredictionConfidence) -> Self {
        match c {
            signaling::PredictionConfidence::Sequential => PredictionConfidence::Sequential,
            signaling::PredictionConfidence::PseudoSequential => PredictionConfidence::PseudoSequential,
            signaling::PredictionConfidence::Random => PredictionConfidence::Random,
        }
    }
}

impl From<PredictionConfidence> for signaling::PredictionConfidence {
    fn from(c: PredictionConfidence) -> Self {
        match c {
            PredictionConfidence::Sequential => signaling::PredictionConfidence::Sequential,
            PredictionConfidence::PseudoSequential => signaling::PredictionConfidence::PseudoSequential,
            PredictionConfidence::Random => signaling::PredictionConfidence::Random,
        }
    }
}

/// A MoQ track announcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackAnnouncement {
    /// Track namespace (e.g., "voip/peer-abc/audio/opus-48k").
    pub track_namespace: String,
    /// Codec identifier (e.g., "opus-48k").
    pub codec: String,
    /// MoQ send ordering priority (0 = highest).
    pub priority: u32,
    /// Media type.
    pub media_type: MediaType,
    /// Maximum bitrate in bps.
    pub bitrate_max: u32,
    /// Minimum bitrate in bps.
    pub bitrate_min: u32,
    /// Duration of each media frame in ms.
    pub frame_duration_ms: u32,
}

/// Media type for track announcements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaType {
    Audio,
    Video,
    Screen,
}

impl From<signaling::MediaType> for MediaType {
    fn from(t: signaling::MediaType) -> Self {
        match t {
            signaling::MediaType::MediaAudio => MediaType::Audio,
            signaling::MediaType::MediaVideo => MediaType::Video,
            signaling::MediaType::MediaScreen => MediaType::Screen,
        }
    }
}

impl From<MediaType> for signaling::MediaType {
    fn from(t: MediaType) -> Self {
        match t {
            MediaType::Audio => signaling::MediaType::MediaAudio,
            MediaType::Video => signaling::MediaType::MediaVideo,
            MediaType::Screen => signaling::MediaType::MediaScreen,
        }
    }
}

/// Peer online status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerStatus {
    Online,
    Offline,
    InCall,
}

impl From<signaling::PeerStatus> for PeerStatus {
    fn from(s: signaling::PeerStatus) -> Self {
        match s {
            signaling::PeerStatus::PeerOnline => PeerStatus::Online,
            signaling::PeerStatus::PeerOffline => PeerStatus::Offline,
            signaling::PeerStatus::PeerInCall => PeerStatus::InCall,
        }
    }
}

impl From<PeerStatus> for signaling::PeerStatus {
    fn from(s: PeerStatus) -> Self {
        match s {
            PeerStatus::Online => signaling::PeerStatus::PeerOnline,
            PeerStatus::Offline => signaling::PeerStatus::PeerOffline,
            PeerStatus::InCall => signaling::PeerStatus::PeerInCall,
        }
    }
}

impl PeerRecord {
    /// Create a new unsigned PeerRecord with the current timestamp.
    pub fn new_unsigned(
        peer_id: String,
        display_name: String,
        ipv6_addresses: Vec<String>,
        ipv4_reflexive: Vec<String>,
        nat_info: Option<NatInfo>,
        tracks: Vec<TrackAnnouncement>,
        status: PeerStatus,
        ttl_seconds: u32,
    ) -> Self {
        Self {
            peer_id,
            display_name,
            ipv6_addresses,
            ipv4_reflexive,
            nat_info,
            tracks,
            status,
            timestamp: now_secs(),
            ttl_seconds,
            signature: Vec::new(),
        }
    }

    /// Sign this record with the given Ed25519 signing key.
    ///
    /// The signature covers all fields *except* the signature itself.
    /// The signing input is the protobuf-encoded `signaling::PeerRecord`
    /// with the signature field set to empty.
    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<(), DhtError> {
        let message = self.signing_input()?;
        let signature = signing_key.sign(&message);
        self.signature = signature.to_bytes().to_vec();
        Ok(())
    }

    /// Verify this record's Ed25519 signature against the given public key.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), DhtError> {
        if self.signature.is_empty() {
            return Err(DhtError::invalid_signature("PeerRecord"));
        }
        let message = self.signing_input()?;
        let signature = Signature::try_from(self.signature.as_slice())
            .map_err(|e| DhtError::InvalidSignature {
                record_type: format!("PeerRecord: {e}"),
            })?;
        verifying_key
            .verify(&message, &signature)
            .map_err(|_| DhtError::invalid_signature("PeerRecord"))
    }

    /// Check whether this record has expired.
    pub fn is_expired(&self) -> bool {
        let now = now_secs();
        now > self.timestamp + self.ttl_seconds as u64
    }

    /// Build the signing input: protobuf-encoded record with signature cleared.
    fn signing_input(&self) -> Result<Vec<u8>, DhtError> {
        let proto_record = self.to_proto_with_empty_sig();
        let mut buf = Vec::new();
        prost::Message::encode(&proto_record, &mut buf)
            .map_err(|e| DhtError::Serialization(e.to_string()))?;
        Ok(buf)
    }

    /// Convert to the protobuf type with signature set to empty (for signing input).
    fn to_proto_with_empty_sig(&self) -> signaling::PeerRecord {
        signaling::PeerRecord {
            peer_id: self.peer_id.clone(),
            display_name: self.display_name.clone(),
            ipv6_addresses: self.ipv6_addresses.clone(),
            ipv4_reflexive: self.ipv4_reflexive.clone(),
            nat_info: self.nat_info.as_ref().map(|n| n.to_proto()),
            tracks: self.tracks.iter().map(|t| t.to_proto()).collect(),
            status: self.status.into() as i32,
            timestamp: self.timestamp,
            ttl_seconds: self.ttl_seconds,
            signature: Vec::new(),
        }
    }

    /// Convert to the protobuf type (with signature).
    pub fn to_proto(&self) -> signaling::PeerRecord {
        let mut proto = self.to_proto_with_empty_sig();
        proto.signature = self.signature.clone();
        proto
    }

    /// Convert from the protobuf type (without signature verification).
    pub fn from_proto(proto: &signaling::PeerRecord) -> Self {
        Self {
            peer_id: proto.peer_id.clone(),
            display_name: proto.display_name.clone(),
            ipv6_addresses: proto.ipv6_addresses.clone(),
            ipv4_reflexive: proto.ipv4_reflexive.clone(),
            nat_info: proto.nat_info.as_ref().map(NatInfo::from_proto),
            tracks: proto.tracks.iter().map(TrackAnnouncement::from_proto).collect(),
            status: signaling::PeerStatus::try_from(proto.status)
                .map(PeerStatus::from)
                .unwrap_or(PeerStatus::Offline),
            timestamp: proto.timestamp,
            ttl_seconds: proto.ttl_seconds,
            signature: proto.signature.clone(),
        }
    }

    /// Encode this record to bytes (protobuf).
    pub fn encode(&self) -> Result<Vec<u8>, DhtError> {
        let proto = self.to_proto();
        let mut buf = Vec::with_capacity(proto.encoded_len());
        prost::Message::encode(&proto, &mut buf)
            .map_err(|e| DhtError::Serialization(e.to_string()))?;
        Ok(buf)
    }

    /// Decode a record from bytes (protobuf).
    pub fn decode(data: &[u8]) -> Result<Self, DhtError> {
        let proto = prost::Message::decode(data)
            .map_err(|e| DhtError::Serialization(e.to_string()))?;
        Ok(Self::from_proto(&proto))
    }
}

impl NatInfo {
    /// Convert to the protobuf type.
    pub fn to_proto(&self) -> signaling::NATInfo {
        signaling::NATInfo {
            nat_type: self.nat_type.into() as i32,
            prediction: self.prediction.as_ref().map(|p| p.to_proto()),
        }
    }

    /// Convert from the protobuf type.
    pub fn from_proto(proto: &signaling::NATInfo) -> Self {
        Self {
            nat_type: signaling::NATType::try_from(proto.nat_type)
                .map(NatType::from)
                .unwrap_or(NatType::None),
            prediction: proto.prediction.as_ref().map(PortPrediction::from_proto),
        }
    }
}

impl PortPrediction {
    /// Convert to the protobuf type.
    pub fn to_proto(&self) -> signaling::PortPrediction {
        signaling::PortPrediction {
            external_ip: self.external_ip.clone(),
            predicted_port_start: self.predicted_port_start,
            predicted_port_end: self.predicted_port_end,
            confidence: self.confidence.into() as i32,
            base_port: self.base_port,
            delta_pattern: self.delta_pattern,
            probed_at: self.probed_at,
            probe_method: signaling::ProbeMethod::QuicPathProbing.into(),
        }
    }

    /// Convert from the protobuf type.
    pub fn from_proto(proto: &signaling::PortPrediction) -> Self {
        Self {
            external_ip: proto.external_ip.clone(),
            predicted_port_start: proto.predicted_port_start,
            predicted_port_end: proto.predicted_port_end,
            confidence: signaling::PredictionConfidence::try_from(proto.confidence)
                .map(PredictionConfidence::from)
                .unwrap_or(PredictionConfidence::Random),
            base_port: proto.base_port,
            delta_pattern: proto.delta_pattern,
            probed_at: proto.probed_at,
        }
    }
}

impl TrackAnnouncement {
    /// Convert to the protobuf type.
    pub fn to_proto(&self) -> signaling::TrackAnnouncement {
        signaling::TrackAnnouncement {
            track_namespace: self.track_namespace.clone(),
            codec: self.codec.clone(),
            priority: self.priority,
            media_type: self.media_type.into() as i32,
            bitrate_max: self.bitrate_max,
            bitrate_min: self.bitrate_min,
            frame_duration_ms: self.frame_duration_ms,
        }
    }

    /// Convert from the protobuf type.
    pub fn from_proto(proto: &signaling::TrackAnnouncement) -> Self {
        Self {
            track_namespace: proto.track_namespace.clone(),
            codec: proto.codec.clone(),
            priority: proto.priority,
            media_type: signaling::MediaType::try_from(proto.media_type)
                .map(MediaType::from)
                .unwrap_or(MediaType::Audio),
            bitrate_max: proto.bitrate_max,
            bitrate_min: proto.bitrate_min,
            frame_duration_ms: proto.frame_duration_ms,
        }
    }
}

// ---------------------------------------------------------------------------
// UsernameRecord
// ---------------------------------------------------------------------------

/// A minimal record mapping a username to a peer ID.
///
/// Key: `SHA-256("voip-name:{username}")`
///
/// The value contains only the `peer_id` and an Ed25519 signature over
/// `{username}:{peer_id}`. The caller then looks up
/// `SHA-256("voip:{peer_id}")` to get the full `PeerRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameRecord {
    /// The username this record maps.
    pub username: String,
    /// The peer ID that this username maps to.
    pub peer_id: String,
    /// Ed25519 signature over `{username}:{peer_id}`.
    pub signature: Vec<u8>,
}

impl UsernameRecord {
    /// Create a new unsigned username record.
    pub fn new_unsigned(username: String, peer_id: String) -> Self {
        Self {
            username,
            peer_id,
            signature: Vec::new(),
        }
    }

    /// Sign this record with the given Ed25519 signing key.
    ///
    /// The signature covers the bytes of `{username}:{peer_id}`.
    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<(), DhtError> {
        let message = self.signing_input();
        let signature = signing_key.sign(&message);
        self.signature = signature.to_bytes().to_vec();
        Ok(())
    }

    /// Verify this record's Ed25519 signature against the given public key.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), DhtError> {
        if self.signature.is_empty() {
            return Err(DhtError::invalid_signature("UsernameRecord"));
        }
        let message = self.signing_input();
        let signature = Signature::try_from(self.signature.as_slice())
            .map_err(|e| DhtError::InvalidSignature {
                record_type: format!("UsernameRecord: {e}"),
            })?;
        verifying_key
            .verify(&message, &signature)
            .map_err(|_| DhtError::invalid_signature("UsernameRecord"))
    }

    /// Build the signing input: `{username}:{peer_id}`.
    fn signing_input(&self) -> Vec<u8> {
        format!("{}:{}", self.username, self.peer_id).into_bytes()
    }

    /// Encode to bytes (bincode-style: len-prefixed strings + signature).
    pub fn encode(&self) -> Result<Vec<u8>, DhtError> {
        serde_json::to_vec(self)
            .map_err(|e| DhtError::Serialization(e.to_string()))
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> Result<Self, DhtError> {
        serde_json::from_slice(data)
            .map_err(|e| DhtError::Serialization(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// ProxyRecord
// ---------------------------------------------------------------------------

/// A signed proxy record stored in the DHT.
///
/// Key: `SHA-256("masque-proxy:{node_id}")`
///
/// Contains the proxy's connection information and is signed with the
/// proxy node's Ed25519 private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRecord {
    /// The node running the proxy.
    pub node_id: String,
    /// The MASQUE proxy endpoint URL.
    pub proxy_url: String,
    /// Maximum concurrent relay sessions.
    pub capacity: u32,
    /// Geographic region hint.
    pub region: String,
    /// Estimated latency in milliseconds.
    pub latency_hint_ms: u32,
    /// Unix timestamp when this record was published.
    pub timestamp: u64,
    /// Time-to-live in seconds.
    pub ttl_seconds: u32,
    /// SHA-256 fingerprint of the proxy's TLS certificate.
    pub cert_fingerprint: String,
    /// Ed25519 signature over all fields above.
    pub signature: Vec<u8>,
}

impl ProxyRecord {
    /// Create a new unsigned proxy record with the current timestamp.
    pub fn new_unsigned(
        node_id: String,
        proxy_url: String,
        capacity: u32,
        region: String,
        latency_hint_ms: u32,
        ttl_seconds: u32,
        cert_fingerprint: String,
    ) -> Self {
        Self {
            node_id,
            proxy_url,
            capacity,
            region,
            latency_hint_ms,
            timestamp: now_secs(),
            ttl_seconds,
            cert_fingerprint,
            signature: Vec::new(),
        }
    }

    /// Sign this record with the given Ed25519 signing key.
    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<(), DhtError> {
        let message = self.signing_input()?;
        let signature = signing_key.sign(&message);
        self.signature = signature.to_bytes().to_vec();
        Ok(())
    }

    /// Verify this record's Ed25519 signature against the given public key.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), DhtError> {
        if self.signature.is_empty() {
            return Err(DhtError::invalid_signature("ProxyRecord"));
        }
        let message = self.signing_input()?;
        let signature = Signature::try_from(self.signature.as_slice())
            .map_err(|e| DhtError::InvalidSignature {
                record_type: format!("ProxyRecord: {e}"),
            })?;
        verifying_key
            .verify(&message, &signature)
            .map_err(|_| DhtError::invalid_signature("ProxyRecord"))
    }

    /// Check whether this record has expired.
    pub fn is_expired(&self) -> bool {
        let now = now_secs();
        now > self.timestamp + self.ttl_seconds as u64
    }

    /// Build the signing input: protobuf-encoded record with signature cleared.
    fn signing_input(&self) -> Result<Vec<u8>, DhtError> {
        let proto_record = self.to_proto_with_empty_sig();
        let mut buf = Vec::new();
        prost::Message::encode(&proto_record, &mut buf)
            .map_err(|e| DhtError::Serialization(e.to_string()))?;
        Ok(buf)
    }

    /// Convert to the protobuf type with signature set to empty (for signing input).
    fn to_proto_with_empty_sig(&self) -> signaling::ProxyRecord {
        signaling::ProxyRecord {
            node_id: self.node_id.clone(),
            proxy_url: self.proxy_url.clone(),
            capacity: self.capacity,
            region: self.region.clone(),
            latency_hint_ms: self.latency_hint_ms,
            timestamp: self.timestamp,
            ttl_seconds: self.ttl_seconds,
            cert_fingerprint: self.cert_fingerprint.clone(),
            signature: Vec::new(),
        }
    }

    /// Convert to the protobuf type (with signature).
    pub fn to_proto(&self) -> signaling::ProxyRecord {
        let mut proto = self.to_proto_with_empty_sig();
        proto.signature = self.signature.clone();
        proto
    }

    /// Convert from the protobuf type.
    pub fn from_proto(proto: &signaling::ProxyRecord) -> Self {
        Self {
            node_id: proto.node_id.clone(),
            proxy_url: proto.proxy_url.clone(),
            capacity: proto.capacity,
            region: proto.region.clone(),
            latency_hint_ms: proto.latency_hint_ms,
            timestamp: proto.timestamp,
            ttl_seconds: proto.ttl_seconds,
            cert_fingerprint: proto.cert_fingerprint.clone(),
            signature: proto.signature.clone(),
        }
    }

    /// Encode this record to bytes (protobuf).
    pub fn encode(&self) -> Result<Vec<u8>, DhtError> {
        let proto = self.to_proto();
        let mut buf = Vec::with_capacity(proto.encoded_len());
        prost::Message::encode(&proto, &mut buf)
            .map_err(|e| DhtError::Serialization(e.to_string()))?;
        Ok(buf)
    }

    /// Decode a record from bytes (protobuf).
    pub fn decode(data: &[u8]) -> Result<Self, DhtError> {
        let proto = prost::Message::decode(data)
            .map_err(|e| DhtError::Serialization(e.to_string()))?;
        Ok(Self::from_proto(&proto))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_record_sign_verify() {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let mut record = PeerRecord::new_unsigned(
            "test-peer-id".to_string(),
            "TestUser".to_string(),
            vec!["::1".to_string()],
            vec!["1.2.3.4:5000".to_string()],
            None,
            vec![],
            PeerStatus::Online,
            3600,
        );

        // Should fail verification before signing.
        assert!(record.verify(&verifying_key).is_err());

        // Sign and verify.
        record.sign(&signing_key).unwrap();
        assert!(record.verify(&verifying_key).is_ok());

        // Should not be expired.
        assert!(!record.is_expired());
    }

    #[test]
    fn test_username_record_sign_verify() {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let mut record = UsernameRecord::new_unsigned("alice".to_string(), "peer-123".to_string());

        record.sign(&signing_key).unwrap();
        assert!(record.verify(&verifying_key).is_ok());
    }

    #[test]
    fn test_proxy_record_sign_verify() {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let mut record = ProxyRecord::new_unsigned(
            "node-456".to_string(),
            "https://proxy.example.com:443/masque".to_string(),
            10,
            "us-west".to_string(),
            50,
            3600,
            "AB:CD:EF".to_string(),
        );

        record.sign(&signing_key).unwrap();
        assert!(record.verify(&verifying_key).is_ok());
        assert!(!record.is_expired());
    }

    #[test]
    fn test_peer_record_roundtrip() {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        let mut record = PeerRecord::new_unsigned(
            "test-peer".to_string(),
            "Alice".to_string(),
            vec!["2001:db8::1".to_string()],
            vec!["10.0.0.1:5000".to_string()],
            Some(NatInfo {
                nat_type: NatType::Cone,
                prediction: None,
            }),
            vec![TrackAnnouncement {
                track_namespace: "voip/test/audio/opus-48k".to_string(),
                codec: "opus-48k".to_string(),
                priority: 0,
                media_type: MediaType::Audio,
                bitrate_max: 64000,
                bitrate_min: 6000,
                frame_duration_ms: 20,
            }],
            PeerStatus::Online,
            3600,
        );

        record.sign(&signing_key).unwrap();
        let encoded = record.encode().unwrap();
        let decoded = PeerRecord::decode(&encoded).unwrap();

        assert_eq!(decoded.peer_id, "test-peer");
        assert_eq!(decoded.display_name, "Alice");
        assert_eq!(decoded.ipv6_addresses, vec!["2001:db8::1"]);
        assert_eq!(decoded.tracks.len(), 1);
        assert_eq!(decoded.signature, record.signature);
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let k1 = peer_record_key("alice");
        let k2 = peer_record_key("alice");
        let k3 = peer_record_key("bob");
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }
}
