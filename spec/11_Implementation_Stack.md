# 11. Implementation Stack

> Part of: Three Pillars VoIP Relay-Free Architecture Specification (TS-2025-001 v8.0)  
> See also: [Architecture Overview](01_Architecture_Overview.md) | [Pillar 3: QUIC](04_Pillar3_QUIC.md) | [API Specification](08_API_Specification.md)

---

## 11.1 Technology Stack

### Language: Rust

Rust is the implementation language for all components: signaling server, client library, DHT node, and platform bindings. The choice is driven by:

1. **No garbage collector.** VoIP audio paths require deterministic latency. GC pauses cause audible glitches. Rust's ownership model eliminates this at compile time.
2. **MoQ reference implementation.** `moq-rs` by Kixelated is the only mature MoQ implementation. It is written in Rust.
3. **QUIC + DHT ecosystem.** Rust has production-grade QUIC (quinn, quiche, s2n-quic) and DHT (libp2p with KadDHT) implementations with native APIs.

### Async Runtime: tokio

All async I/O uses tokio with the `rt-multi-thread` runtime.

- **Signal handling:** tokio handles SIGINT/SIGTERM for graceful shutdown
- **Timer wheel:** tokio::time for path probe timeouts, call setup timeouts, NAT cache TTL
- **UDP socket:** tokio::net::UdpSocket for QUIC
- **TCP listener:** tokio::net for signaling server REST API

---

## 11.2 Library Choices

### QUIC: quinn

```
quinn = "0.11"
```

quinn is selected for the following reasons:

- **Pure Rust.** No C FFI required. This simplifies cross-compilation for mobile (Android/iOS) and eliminates a class of unsafe code.
- **Connection migration.** Full support for QUIC PATH_CHALLENGE/PATH_RESPONSE, which is core to the QUIC-native NAT traversal strategy.
- **Datagram support.** RFC 9221 QUIC datagrams are supported for MoQ media delivery.
- **Happy Eyeballs v2.** Built-in support for RFC 8305 — IPv6 gets a 25ms head start over IPv4.
- **Multi-path probing.** Quinn supports migrating a connection to a new path, which is exactly what the 5-IP NAT probing strategy requires.

Alternative considered: **quiche** (Cloudflare). Battle-tested but requires C FFI. s2n-quic (AWS) is also excellent. All three are viable; quinn wins on pure-Rust ergonomics for the NAT probing use case.

### DHT: libp2p with KadDHT

```
libp2p = { version = "0.53", features = ["kad", "noise", "tcp", "quic", "websocket", "tls", "dns", "ping", "identify"] }
```

libp2p's KadDHT implementation provides:

- **Kademlia DHT** with standard k-bucket routing
- **QUIC transport** — DHT nodes communicate over QUIC, consistent with the single-protocol architecture
- **Bootstrap protocol** — join the DHT from seed nodes
- **Record storage** — store and retrieve peer connection data
- **S/Kademlia roadmap** — proof-of-work node IDs and disjoint paths can be added as a custom extension

### MoQ: moq-rs (adapted as reference)

```
moq-rs (git dependency, adapted from https://github.com/kixelated/moq-rs)
```

moq-rs serves as the reference implementation for MoQ protocol behavior. The implementation adapts its approach but implements MoQ directly from draft-ietf-moq-transport-17, using moq-rs as a behavioral reference and test oracle.

### Protobuf: prost

```
prost = "0.13"
prost-types = "0.13"
```

### Audio Codec: opus

```
opus = "0.3"
```

### Signaling Server: tokio + tungstenite + axum

```
axum = "0.7"
tokio-tungstenite = "0.24"
tower = "0.5"
```

### MASQUE: h3 + h3-quinn

```
h3 = "0.7"
h3-quinn = "0.7"
```

h3 is the standard HTTP/3 implementation for quinn. CONNECT-UDP (RFC 9298) is implemented as an HTTP extension on top of h3. The MASQUE tunnel module lives in voip-client as `masque_tunnel.rs`.

### Push Notifications: Firebase Cloud Messaging

```
fcmlib = "0.2"  # Firebase Cloud Messaging admin SDK for Rust
```

Push notifications are used for failed-call retry only. When a call fails due to NAT incompatibility, a push notification is sent to the peer. The peer's app wakes up, re-probes its NAT, and auto-retries the connection.

### Mobile: UniFFI

```
uniffi = "0.28"
```

### Build: Cargo Workspace, Monorepo

```
three-pillars-voip/
├── Cargo.toml              # Workspace root
├── crates/
│   ├── voip-core/          # Shared types, Protobuf definitions, state machines
│   ├── voip-signaling/     # Signaling server binary (QUIC listener, 5 IPs)
│   ├── voip-client/        # Client library (QUIC + MoQ + NAT probe + audio)
│   ├── voip-dht/           # DHT node (libp2p KadDHT, lookup + store)
│   └── voip-ffi/           # UniFFI bindings for mobile
├── proto/
│   ├── signaling.proto     # Signaling messages (from Data Model)
│   └── internal.proto      # Internal NAT probe messages
├── mobile/
│   ├── android/            # Android AAR wrapper
│   └── ios/                # iOS XCFramework wrapper
└── tests/
    ├── integration/        # Integration tests (two clients + signaling server)
    └── e2e/                # End-to-end NAT simulation tests
```

**Note:** The `voip-stun` crate from v6.0 has been eliminated. NAT probing is now a module within `voip-client` that uses QUIC connection migration to the signaling server's 5 elastic IPs. No separate STUN protocol stack.

---

## 11.3 Configuration Constants

```rust
struct VoIPConfig {
    // === QUIC Path Probing (replaces STUN) ===
    /// Number of signaling server IPs to probe for NAT classification
    path_probe_count: u32,              // default: 5
    /// Timeout per QUIC path migration probe
    path_probe_timeout_ms: u64,         // default: 1000
    /// Time-to-live for NAT probe cache
    nat_cache_ttl_secs: u64,            // default: 300 (5 minutes)
    /// Number of path probes for quick refresh (before call)
    path_refresh_count: u32,            // default: 2
    /// Maximum variance in delta before reclassifying NAT
    nat_delta_variance_threshold: u32,  // default: 3

    // === Port Prediction ===
    /// Margin for sequential NAT prediction
    prediction_margin_sequential: u32,  // default: 3 (range of 7 ports)
    /// Margin for pseudo-sequential NAT prediction
    prediction_margin_pseudo: u32,      // default: 8 (range of 17 ports)
    /// Maximum prediction probe packets per side
    prediction_max_probes: u32,         // default: 17

    // === QUIC Connection ===
    /// Timeout for initial QUIC handshake
    quic_connect_timeout_ms: u64,       // default: 5000
    /// Timeout for port prediction probing phase
    quic_prediction_timeout_ms: u64,    // default: 3000
    /// Maximum idle timeout for established QUIC connection
    quic_idle_timeout_ms: u64,          // default: 30000
    /// QUIC ALPN protocol identifier
    quic_alpn: String,                  // default: "moq-00"

    // === Discovery ===
    /// Discovery priority: true = DHT first (privacy), false = signaling first (speed)
    discovery_privacy_first: bool,      // default: true
    /// DHT lookup timeout before falling back to signaling
    dht_lookup_timeout_ms: u64,         // default: 200
    /// DHT bootstrap nodes (hardcoded fallback)
    dht_bootstrap_nodes: Vec<String>,   // default: 3-5 seed nodes
    /// DHT record TTL
    dht_record_ttl_secs: u64,           // default: 3600

    // === Push Retry ===
    /// Enable push notification retry for failed connections
    push_retry_enabled: bool,           // default: true
    /// Initial retry delay in seconds
    push_retry_initial_delay_secs: u64,  // default: 5
    /// Maximum retry attempts
    push_retry_max_attempts: u32,       // default: 3
    /// Retry backoff multiplier
    push_retry_backoff_multiplier: u32, // default: 3

    // === MASQUE Fallback ===
    /// Enable MASQUE CONNECT-UDP fallback when direct P2P fails
    masque_fallback_enabled: bool,        // default: true
    /// Timeout for MASQUE proxy discovery
    masque_discovery_timeout_ms: u64,     // default: 2000
    /// Timeout for HTTP/3 + CONNECT-UDP tunnel setup
    masque_connect_timeout_ms: u64,       // default: 3000
    /// Maximum number of proxy candidates to try
    masque_max_proxy_attempts: u32,       // default: 3
    /// Whether this node can act as a MASQUE proxy (desktop only)
    masque_proxy_enabled: bool,           // default: false
    /// Maximum concurrent relay sessions when acting as proxy
    masque_proxy_max_sessions: u32,       // default: 10

    // === Call Setup ===
    call_ring_timeout_ms: u64,          // default: 30000
    call_connect_timeout_ms: u64,       // default: 10000

    // === Connection Migration ===
    migration_path_timeout_ms: u64,     // default: 5000
    migration_max_reprobes: u32,        // default: 1

    // === Signaling Server ===
    rate_limit_calls_per_min: u32,      // default: 10
    rate_limit_registrations_per_min: u32, // default: 6
    rate_limit_ws_messages_per_sec: u32, // default: 30
    jwt_expiry_secs: u64,              // default: 3600
    /// Signaling server elastic IPs for QUIC path probing
    signaling_server_ips: Vec<String>,  // default: 5 IPs

    // === Session Tickets (0-RTT) ===
    session_ticket_ttl_secs: u64,       // default: 86400

    // === MoQ ===
    moq_feedback_interval_ms: u64,      // default: 1000
}
```

---

## 11.4 Opus Codec Configuration

Same as v6.0 — no changes.

```rust
struct OpusConfig {
    sample_rate: u32,                   // 48000
    channels: u8,                       // 1
    application: opus::Application,     // OPUS_APPLICATION_VOIP
    bitrate: opus::Bitrate,             // VBR, max 64000
    bitrate_min: i32,                   // 6000
    frame_duration_ms: u32,             // 20
    fec: bool,                          // true
    dtx: bool,                          // true
    complexity: u8,                     // 10
    frame_size: usize,                  // 960
}
```

---

## 11.5 Error Handling Rules

### Recoverable (retry with backoff)

| Error | Recovery | Max Retries | Backoff |
|-------|----------|-------------|---------|
| QUIC path probe timeout | Retry next server IP | 2 | 500ms fixed |
| DHT lookup timeout | Fall back to signaling server | 1 | None (immediate) |
| QUIC Initial timeout | Retry with next address | 1 per type | None (immediate) |
| Port prediction miss | Push notification retry | 3 | 5s, 15s, 45s |
| MoQ SUBSCRIBE rejected | Retry with different parameters | 1 | None |

### Migratable (connection migration)

| Error | Recovery | Timeout |
|-------|----------|---------|
| WiFi → cellular switch | QUIC connection migration | 5 seconds |
| New WiFi network | QUIC migration + NAT re-probe | 5 seconds + 50ms probe |
| IPv6 prefix change | QUIC migration only | 5 seconds |

### Fatal (call fails honestly)

| Error | User Message | Logged As |
|-------|-------------|-----------|
| Both IPv4, both Symmetric random | "Network incompatibility — direct connection not possible. Retry sent." | `END_FAILED_IPV4_RANDOM` |
| UDP blocked by firewall | "Network does not allow voice calls — UDP is blocked" | `END_FAILED_UDP_BLOCKED` (only after MASQUE over HTTP/2 also fails) |
| IPv6 firewalls block both sides | "Network does not allow direct connections" | `END_FAILED_IPV6_FIREWALL` |
| Connection migration timeout | "Call dropped — network change failed" | `END_MIGRATION_FAILED` |
| QUIC handshake failure | "Call failed — secure connection could not be established" | `END_FAILED_NETWORK` |
| Callee rejects call | "Call declined" | `END_REJECTED` |

---

## 11.6 MoQ Wire Format Mapping

Same as v6.0 — no changes. MoQ wire format is independent of the NAT traversal mechanism.

### MoQ Datagram Format

```
+------+--------+---------+-----------+---------+
| Type | Alias  | Seq     | Timestamp | Payload |
| 1B   | 4B     | varint  | varint    | ...     |
+------+--------+---------+-----------+---------+

Type: 0x01 (media datagram)
Alias: 4-byte track alias assigned at SUBSCRIBE_OK
Seq: monotonically increasing per track (varint encoding)
Timestamp: media timestamp in track's clock rate (varint encoding)
Payload: encoded media frame (Opus packet, VP9 frame, etc.)
```

---

## 11.7 Authentication Implementation

Same as v6.0 — Ed25519 JWT, peer_id = public key hex. No changes.

---

## 11.8 Acceptance Tests

### Connectivity Tests

| Test ID | Scenario | Pass Criteria |
|---------|----------|---------------|
| CONN-01 | IPv6 direct connection | QUIC connection established in <300ms |
| CONN-02 | IPv4 Cone NAT (QUIC simultaneous open) | QUIC simultaneous open succeeds in <300ms |
| CONN-03 | IPv4 Symmetric NAT sequential (QUIC path probing) | Port prediction succeeds in <500ms |
| CONN-04 | IPv4 Symmetric NAT random | Call fails with `END_FAILED_IPV4_RANDOM`, push retry sent |
| CONN-05 | UDP blocked | MASQUE over HTTP/2 attempted first, then `END_FAILED_UDP_BLOCKED` if TCP 443 also blocked |
| CONN-06 | Mixed IPv6 + IPv4 Symmetric | Connection succeeds via IPv6 in <300ms |

### Discovery Tests

| Test ID | Scenario | Pass Criteria |
|---------|----------|---------------|
| DISC-01 | DHT lookup (privacy-first mode) | Peer found via DHT in <200ms |
| DISC-02 | Signaling lookup (speed-first mode) | Peer found via signaling in <20ms |
| DISC-03 | DHT timeout, fall back to signaling | Signaling succeeds within 250ms total |
| DISC-04 | Signaling blocked, fall back to DHT | DHT succeeds within 300ms total |
| DISC-05 | DHT register + lookup round-trip | Registration followed by lookup returns correct data |

### NAT Probe Tests

| Test ID | Scenario | Pass Criteria |
|---------|----------|---------------|
| NAT-01 | Sequential NAT via QUIC path probing | 5 path probes detect SEQUENTIAL, prediction range ±3 |
| NAT-02 | Pseudo-sequential NAT via QUIC path probing | 5 path probes detect PSEUDO_SEQUENTIAL, range ±8 |
| NAT-03 | Random NAT via QUIC path probing | 5 path probes detect RANDOM, no prediction attempted |
| NAT-04 | Cone NAT via QUIC path probing | Same external port across all 5 probes |
| NAT-05 | IPv6 fast-path via /myip | GET /v1/myip returns IPv6, skip NAT probing |
| NAT-06 | Cache TTL expiry | Prediction cache invalidated after 5 minutes |
| NAT-07 | Cache invalidation on network change | Network change triggers full re-probe |

### Push Retry Tests

| Test ID | Scenario | Pass Criteria |
|---------|----------|---------------|
| RETRY-01 | Push notification sent on NAT failure | PushRetry message delivered to peer |
| RETRY-02 | Auto-retry on network change | Peer re-probes and retries within 10s of network change |
| RETRY-03 | Scheduled retry backoff | Retries at 5s, 15s, 45s intervals |
| RETRY-04 | Max retry exhaustion | After 3 attempts, call marked as permanently failed |

### Migration Tests

| Test ID | Scenario | Pass Criteria |
|---------|----------|---------------|
| MIG-01 | WiFi → cellular during call | Call continues, audio gap <300ms |
| MIG-02 | Cellular → WiFi during call | Call continues, audio gap <300ms |
| MIG-03 | IPv6 → different IPv6 prefix | QUIC migration succeeds |
| MIG-04 | Migration timeout | Call fails with END_MIGRATION_FAILED after 5s |

### MASQUE Fallback Tests

| Test ID | Scenario | Pass Criteria |
|---------|----------|---------------|
| MASQUE-01 | All pillars fail, MASQUE proxy available | Call connects via MASQUE relay, method = CONN_MASQUE |
| MASQUE-02 | MASQUE proxy discovery via DHT | Proxy record found in DHT, valid and reachable |
| MASQUE-03 | MASQUE proxy discovery via signaling | GET /v1/proxies returns reachable proxy |
| MASQUE-04 | MASQUE relay with UDP blocked | MASQUE over HTTP/2 (TCP) used instead, method = CONN_MASQUE_HTTP2 |
| MASQUE-05 | All proxies unreachable | Call fails with END_FAILED_MASQUE_UNREACHABLE, push retry sent |
| MASQUE-06 | Volunteer proxy node | Desktop client advertises proxy in DHT, peers discover and use it |

---

## 11.9 Security Considerations

### Connection ID Uniqueness

Same as v6.0. 12-byte CSPRNG-generated. P(collision) < 10^-20.

### 0-RTT Replay Protection

Same as v6.0. No media in 0-RTT data. Session tickets are single-use.

### DHT Security

- **Data signing:** All DHT records are signed by the peer's Ed25519 private key. Consumers verify before trusting.
- **Sybil attacks (KadDHT):** Regular Kademlia is vulnerable. Mitigated by: short TTL (1 hour), multiple independent lookup paths, and the signaling server as an authoritative fallback. S/Kademlia (v2) adds proof-of-work node IDs.
- **Eclipse attacks:** An adversary controlling nodes near a target key can block lookups. Mitigated by: the signaling server provides a completely separate discovery path, so eclipsing the DHT doesn't block discovery.
- **Stale data:** DHT records have a 1-hour TTL and are re-published before expiry. Stale records are rejected by consumers based on timestamp.

### Path Probing Amplification

QUIC path probes are standard QUIC packets (~120 bytes) with standard QUIC responses (~120 bytes). Amplification factor is ~1:1. No DDoS concern.

### Denial of Service

Same rate limits as v6.0: 10 calls/min, 6 registrations/min, 30 WebSocket messages/sec.

---

## 11.10 Deployment: Oracle Free + Cloudflare Free

### Signaling Server

| Component | Configuration |
|-----------|--------------|
| Compute | Oracle Cloud Always Free: 2× AMD micro (1/8 OCPU, 1GB RAM each) |
| Network | 5 elastic IPs for QUIC path probing |
| Domain | Behind Cloudflare Free plan (ECH enabled) |
| QUIC | Quinn listener on all 5 IPs |
| WebSocket | `wss://signal.example.com/v1/ws` |
| REST | `https://signal.example.com/v1/*` |
| Push | Firebase Cloud Messaging free tier |

### DHT Nodes

| Component | Configuration |
|-----------|--------------|
| Bootstrap | 3-5 hardcoded seed nodes (community-run desktops) |
| Client nodes | Desktop/laptop clients run full DHT nodes |
| Mobile | Mobile clients do lookup only, no routing |

**Total monthly cost: $0** (excluding domain registration ~$10/year)
