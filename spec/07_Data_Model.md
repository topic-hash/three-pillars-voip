# 7. Data Model

> Part of: Three Pillars VoIP Minimal-Relay Architecture Specification (TS-2025-001 v8.0)  
> See also: [Discovery & Signaling](06_Discovery_Signaling.md) | [API Specification](08_API_Specification.md) | [Data Persistence](10_Data_Persistence.md)

---

## 7.1 Business Objects

### 7.1.1 Peer

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `peer_id` | `string` | Unique identifier | UUID v4, immutable |
| `display_name` | `string` | Human-readable name | Max 128 chars, UTF-8 |
| `ipv6_addresses` | `repeated string` | Current IPv6 addresses | Valid IPv6, may be empty |
| `ipv4_reflexive` | `repeated string` | QUIC-path-probe-learned IPv4 addresses | `ip:port` format, may be empty |
| `nat_type` | `NATType` | Detected NAT behavior | Enum: NONE, CONE, SYMMETRIC_SEQUENTIAL, SYMMETRIC_PSEUDO, SYMMETRIC_RANDOM |
| `port_prediction` | `PortPrediction?` | Current port prediction | Null if IPv6 or Cone NAT |
| `tracks` | `repeated TrackAnnouncement` | MoQ tracks this peer publishes | At least 1 (audio) |
| `last_seen` | `uint64` | Unix timestamp of last registration | Seconds since epoch |
| `status` | `PeerStatus` | Current availability | Enum: ONLINE, OFFLINE, IN_CALL |
| `discovery_method` | `DiscoveryMethod` | How this peer was discovered | Enum: DHT, SIGNALING, CACHE (also used for MASQUE proxy discovery) |

### 7.1.2 Call

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `call_id` | `string` | Unique call identifier | UUID v4, immutable |
| `caller_id` | `string` | Peer ID of the caller | Must reference existing Peer |
| `callee_id` | `string` | Peer ID of the callee | Must reference existing Peer |
| `state` | `CallState` | Current call state | Enum: RINGING, ACCEPTED, CONNECTED, FAILED, ENDED |
| `connection_method` | `ConnectionMethod` | How P2P was established | Enum: IPV6_DIRECT, IPV4_CONE, IPV4_PREDICTION, CONN_MASQUE, CONN_MASQUE_HTTP2, NONE |
| `discovery_method` | `DiscoveryMethod` | How peer was discovered | Enum: DHT, SIGNALING |
| `created_at` | `uint64` | When the call was initiated | Unix timestamp |
| `connected_at` | `uint64?` | When P2P was established | Null until connected |
| `ended_at` | `uint64?` | When the call ended | Null until ended |
| `failure_reason` | `string?` | Why the call failed | Null if call succeeded |
| `retry_count` | `uint32` | Number of push-retry attempts | 0-3 |

### 7.1.3 PortPrediction

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `external_ip` | `string` | External IPv4 address | Valid IPv4 |
| `predicted_port_start` | `uint32` | Start of predicted range | 1024-65535 |
| `predicted_port_end` | `uint32` | End of predicted range | Must be >= predicted_port_start |
| `confidence` | `PredictionConfidence` | Confidence level | Enum: SEQUENTIAL, PSEUDO_SEQUENTIAL, RANDOM |
| `base_port` | `uint32` | Last known external port from path probe | Used for delta calculation |
| `delta_pattern` | `int32` | Average delta between allocations | e.g., +1 for sequential |
| `probed_at` | `uint64` | When the probe was performed | Unix timestamp |
| `probe_method` | `ProbeMethod` | How NAT was probed | Enum: QUIC_PATH_PROBING (always this value in v7+) |

### 7.1.4 Track, Subscription — Same as v6.0

(See v6.0 spec for TrackAnnouncement, TrackSubscription, QualityReport — no changes.)

---

## 7.2 Full Protobuf Message Schemas

```protobuf
syntax = "proto3";
package voip.signaling;

// ==================== ENUMS ====================

enum NATType {
  NAT_NONE = 0;
  NAT_CONE = 1;
  NAT_SYMMETRIC_SEQUENTIAL = 2;
  NAT_SYMMETRIC_PSEUDO = 3;
  NAT_SYMMETRIC_RANDOM = 4;
}

enum PredictionConfidence {
  SEQUENTIAL = 0;
  PSEUDO_SEQUENTIAL = 1;
  RANDOM = 2;
}

enum ProbeMethod {
  QUIC_PATH_PROBING = 0;    // QUIC connection migration to 5 server IPs (v7+)
  // No STUN probe method exists. STUN is eliminated in v7+.
}

enum DiscoveryMethod {
  DISCOVERY_DHT = 0;        // Found via DHT lookup
  DISCOVERY_SIGNALING = 1;  // Found via signaling server
  DISCOVERY_CACHE = 2;      // Found in local peer address book cache
}

enum MediaType {
  MEDIA_AUDIO = 0;
  MEDIA_VIDEO = 1;
  MEDIA_SCREEN = 2;
}

enum CallState {
  CALL_RINGING = 0;
  CALL_ACCEPTED = 1;
  CALL_CONNECTED = 2;
  CALL_FAILED = 3;
  CALL_ENDED = 4;
}

enum SubscriptionState {
  SUB_PENDING = 0;
  SUB_ACTIVE = 1;
  SUB_PAUSED = 2;
  SUB_ENDED = 3;
}

enum PeerStatus {
  PEER_ONLINE = 0;
  PEER_OFFLINE = 1;
  PEER_IN_CALL = 2;
}

enum ConnectionMethod {
  CONN_NONE = 0;
  CONN_IPV6_DIRECT = 1;
  CONN_IPV4_CONE = 2;
  CONN_IPV4_PREDICTION = 3;
  CONN_MASQUE          = 4;            // MASQUE CONNECT-UDP relay (RFC 9298) over HTTP/3
  CONN_MASQUE_HTTP2    = 5;         // MASQUE CONNECT-UDP over HTTP/2 (UDP-blocked fallback)
}

enum CallEndReason {
  END_NORMAL = 0;
  END_REJECTED = 1;
  END_TIMEOUT = 2;
  END_FAILED_IPV4_RANDOM = 3;
  END_FAILED_UDP_BLOCKED = 4;
  END_FAILED_NETWORK = 5;
  END_MIGRATION_FAILED = 6;
  END_FAILED_MASQUE_UNREACHABLE = 7;  // All MASQUE proxies unreachable (HTTP/3 and HTTP/2)
  END_FAILED_TCP_BLOCKED        = 8;   // UDP blocked AND TCP port 443 blocked — no MASQUE possible
}

// ==================== COMPOSITE MESSAGES ====================

message PortPrediction {
  string external_ip = 1;
  uint32 predicted_port_start = 2;
  uint32 predicted_port_end = 3;
  PredictionConfidence confidence = 4;
  uint32 base_port = 5;                    // Last known external port from QUIC path probing
  int32 delta_pattern = 6;
  uint64 probed_at = 7;
  ProbeMethod probe_method = 8;            // Always QUIC_PATH_PROBING in v7+
}

message TrackAnnouncement {
  string track_namespace = 1;
  string codec = 2;
  uint32 priority = 3;
  MediaType media_type = 4;
  uint32 bitrate_max = 5;
  uint32 bitrate_min = 6;
  uint32 frame_duration_ms = 7;
}

message TrackSubscription {
  string track_namespace = 1;
  uint32 track_alias = 2;
}

message NATInfo {
  NATType nat_type = 1;
  PortPrediction prediction = 2;
}

// ==================== SIGNALING MESSAGES ====================

message CallRequest {
  string call_id = 1;
  string caller_id = 2;
  string callee_id = 3;
  repeated string ipv6_addresses = 4;
  repeated string ipv4_reflexive = 5;      // QUIC-path-probe-learned IPv4 addresses
  NATInfo nat_info = 6;
  repeated TrackAnnouncement tracks = 7;
  DiscoveryMethod discovery_method = 8;     // How the caller discovered the callee
  uint64 timestamp = 9;
}

message CallAccept {
  string call_id = 1;
  repeated string ipv6_addresses = 2;
  repeated string ipv4_reflexive = 3;      // QUIC-path-probe-learned IPv4 addresses
  NATInfo nat_info = 4;
  repeated TrackAnnouncement tracks = 5;
  repeated TrackSubscription subscriptions = 6;
  uint64 timestamp = 7;
}

message CallReject {
  string call_id = 1;
  string reason = 2;
  CallEndReason end_reason = 3;
}

message CallFailed {
  string call_id = 1;
  CallEndReason reason = 2;
  string description = 3;
  uint64 timestamp = 4;
}

message CallEnded {
  string call_id = 1;
  CallEndReason reason = 2;
  uint64 duration_seconds = 3;
  ConnectionMethod method = 4;
  DiscoveryMethod discovery_method = 5;    // How peer was discovered
  uint64 timestamp = 6;
}

// ==================== PUSH RETRY ====================

message PushRetry {
  string call_id = 1;
  string caller_id = 2;
  string callee_id = 3;
  CallEndReason reason = 4;
  uint32 retry_attempt = 5;            // 1, 2, or 3
  uint64 retry_after_ms = 6;           // Delay before peer should retry
}

// ==================== MASQUE PROXY DISCOVERY ====================

message ProxyRecord {
  string node_id = 1;              // Node running the proxy
  string proxy_url = 2;            // e.g., "https://proxy.example.com:443/masque"
  uint32 capacity = 3;             // Max concurrent relay sessions
  string region = 4;               // Geographic region hint
  uint32 latency_hint_ms = 5;      // Estimated latency in ms
  uint64 timestamp = 6;            // When this record was published
  uint32 ttl_seconds = 7;          // Time-to-live for this record
}

// ==================== REGISTRATION MESSAGES ====================

message PeerRegister {
  string peer_id = 1;
  string display_name = 2;
  repeated string ipv6_addresses = 3;
  repeated string ipv4_reflexive = 4;      // QUIC-path-probe-learned, ip:port format
  NATInfo nat_info = 5;
  repeated TrackAnnouncement tracks = 6;
  PeerStatus status = 7;
  string fcm_token = 8;                    // Firebase Cloud Messaging token for push retry
}

message PeerUnregister {
  string peer_id = 1;
}

// ==================== IN-CHANNEL SIGNALING ====================

message InChannelMessage {
  oneof payload {
    ConnectionMigration connection_migration = 1;
    TrackUpdate track_update = 2;
    QualityReport quality_report = 3;
  }
}

message ConnectionMigration {
  repeated string new_ipv6_addresses = 1;
  repeated string new_ipv4_reflexive = 2;
  PortPrediction new_prediction = 3;
}

message TrackUpdate {
  repeated TrackAnnouncement added = 1;
  repeated string removed = 2;
  repeated TrackSubscription subscribed = 3;
  repeated uint32 unsubscribed = 4;
}

message QualityReport {
  uint32 track_alias = 1;
  uint32 packets_received = 2;
  uint32 packets_lost = 3;
  uint32 bytes_received = 4;
  uint32 average_rtt_ms = 5;
  uint32 jitter_ms = 6;
  uint64 report_period_start = 7;
  uint64 report_period_end = 8;
}
```

### 7.2.2 NAT Probe Messages (Internal)

```protobuf
syntax = "proto3";
package voip.internal;

// These messages are NOT sent on the wire. They are used internally
// by the voip-client NAT probe module to serialize probe results to
// local cache. Never transmitted between peers or to the signaling server.
// v7.0: All probes use QUIC path probing (connection migration to
// signaling server's 5 elastic IPs). STUN is eliminated.

message NATProbeResult {
  string server_ip = 1;           // Signaling server IP probed via QUIC path migration
  uint32 local_port = 2;          // Local port used for the QUIC connection
  string external_ip = 3;         // External IPv4 reflected by signaling server
  uint32 external_port = 4;       // External port reflected by signaling server
  uint64 timestamp_ms = 5;        // When the probe was sent (unix milliseconds)
  uint32 rtt_ms = 6;              // Round-trip time of the QUIC path migration
}

message NATProbeCache {
  repeated NATProbeResult probes = 1;
  int32 average_delta = 2;
  int32 delta_variance = 3;
  PredictionConfidence confidence = 4;
  uint64 cache_timestamp = 5;
  uint32 cache_ttl_seconds = 6;
}
```

---

## 7.3 State Machines

### 7.3.1 Call Lifecycle State Machine

(Same structure as v6.0 with added retry_count tracking. States: IDLE → RINGING → ACCEPTED → CONNECTED → ENDED, or → FAILED.)

### 7.3.2 MoQ Session Lifecycle State Machine

(Same as v6.0. No changes.)

### 7.3.3 NAT Probing Lifecycle State Machine

```
┌───────────┐
│   IDLE    │
└─────┬─────┘
      │ Application startup / Network change
      ▼
┌───────────┐
│  PROBING  │──── QUIC path migration to 5 signaling server IPs
└─────┬─────┘
      │ All 5 reflected addresses received
      ▼
┌───────────┐
│ ANALYZING │──── Computing deltas, classifying NAT type
└─────┬─────┘
      │ Pattern determined
      ▼
┌───────────┐
│  CACHED   │──── Prediction cached for use in calls
└─────┬─────┘
      │ TTL expired / Network change / Before call
      ▼
┌───────────┐
│ REFRESHING│──── Quick 2-path refresh to verify pattern
└─────┬─────┘
      │ Pattern still valid
      ▼
┌───────────┐
│  CACHED   │
└───────────┘
```

### 7.3.4 Push Retry State Machine (NEW)

```
┌───────────┐
│   IDLE    │
└─────┬─────┘
      │ Call fails (END_FAILED_IPV4_RANDOM)
      ▼
┌───────────┐
│  PUSHING  │──── Send PushRetry to peer via FCM
└─────┬─────┘
      │ Peer receives push
      ▼
┌───────────┐
│  WAITING  │──── Wait retry_after_ms (5s, 15s, 45s)
└─────┬─────┘
      │ Peer re-probes NAT and retries
      ├── Success → CONNECTED
      └── Fail + attempts < 3 → back to PUSHING
         Fail + attempts >= 3 → PERMANENTLY_FAILED
```

---

## 7.4 Object Relationships

```
Peer 1 ──────────────────── Call ──────────────────── Peer 2
  │                                                   │
  ├── NATInfo                                         ├── NATInfo
  │     └── PortPrediction (if Symmetric)             │     └── PortPrediction
  │                                                     │
  ├── TrackAnnouncement[] ──── Subscription[] ◀────────┤
  │                                                     │
  └── NATProbeResult[] (cached)                        └── NATProbeResult[] (cached)

DiscoveryMethod: DHT or SIGNALING
PushRetry: Call → PushRetry → Peer re-attempts
```
