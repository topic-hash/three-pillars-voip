# ROADMAP.md — Development Roadmap

> This document defines the build order. Each milestone is a tag.
> Milestones are sequential — do not start the next one until the current one passes all acceptance tests.
>
> **Phase boundaries are git merge gates.** See `AGENTS.md` §5 Git Strategy.

---

## v8.0 — Foundation (Current)

The baseline. QUIC-native NAT traversal, MASQUE relay fallback, DHT discovery, MoQ media. All in Rust.

Fallback chain: IPv6 (~72% direct) → QUIC Simultaneous Open (Cone NAT, ~26%) → QUIC Port Prediction (Symmetric NAT, ~0.5%) → MASQUE over HTTP/3 (UDP available) → MASQUE over HTTP/2 (UDP blocked, ~2-4%) → Push Retry (~1%)

### Phase 1: Core Types & DHT

| Step | Crate | What | Acceptance |
|------|-------|------|------------|
| 1.1 | `voip-core` | Protobuf definitions compiled via prost | `cargo build` passes, generated types match spec |
| 1.2 | `voip-core` | State machines: CallState, SubscriptionState, NATType, PredictionConfidence, DiscoveryMethod | Unit tests for every state transition |
| 1.3 | `voip-core` | Domain types: PeerId, TrackAlias, ConnectionId, VoIPConfig, OpusConfig | All types constructed, validated, serialized |
| 1.4 | `voip-dht` | libp2p KadDHT node: bootstrap, lookup, store | DISC-01, DISC-05 pass |
| 1.5 | `voip-dht` | DHT record signing and verification | Records signed by Ed25519, consumers verify |
| 1.6 | `voip-dht` | DHT fallback: timeout → signaling server | DISC-03 passes |
| 1.7 | `voip-dht` | Username → Peer ID resolution: two-step DHT lookup (`voip-name:{username}` → peer_id → `voip:{peer_id}` → PeerRecord) | Username lookup returns full PeerRecord in <160ms |
| 1.8 | `voip-dht` | DHT record refresh: re-publish before TTL expiry (every 30 min), background task | Records remain current without manual re-registration |
| 1.9 | `voip-dht` | Mobile DHT constraint: lookup-only API, no full routing node | Mobile bindings do not expose DHT routing/storage APIs |

### Phase 2: Signaling Server

| Step | Crate | What | Acceptance |
|------|-------|------|------------|
| 2.1 | `voip-signaling` | REST API: POST/PUT/DELETE/GET /v1/peers | SIG-05 passes (JWT validation) |
| 2.2 | `voip-signaling` | WebSocket API: message framing (2-byte type + Protobuf) | Binary round-trip matches |
| 2.3 | `voip-signaling` | Call signaling: CallRequest → forward → CallAccept/Reject | SIG-01, SIG-02, SIG-03 pass |
| 2.4 | `voip-signaling` | Rate limiting (10 calls/min, 6 reg/min, 30 msg/sec) | SIG-04 passes |
| 2.5 | `voip-signaling` | OpenAPI spec via utoipa | `GET /v1/openapi.json` returns valid spec |
| 2.6 | `voip-signaling` | JWT auth: Ed25519, peer_id = public key hex | Registration, token refresh, invalid token rejection |
| 2.7 | `voip-signaling` | QUIC path probing: 5-IP listener, address reflection | NAT-01 through NAT-04 pass with QUIC path probing |
| 2.8 | `voip-signaling` | `/v1/myip` IPv6 fast-path endpoint | NAT-05 passes |
| 2.9 | `voip-signaling` | Push notification relay (Firebase Cloud Messaging) | RETRY-01 passes |
| 2.10 | `voip-signaling` | Additional REST endpoints: GET /v1/peers/lookup?username, GET /v1/proxies, GET /v1/dht/bootstrap, POST /v1/proxy-token | All endpoints return correct data, ProxyToken signed and verifiable |
| 2.11 | `voip-signaling` | Error message type (0x8001) + all error codes from spec/08 §8.5 | Error responses use correct codes (1001-9999) for each failure scenario |
| 2.12 | `voip-signaling` | MasqueRelayNeeded message (type ID 0x0300): detect when both peers RANDOM or UDP blocked, send proxy URL to both peers | MASQUE coordination message delivered to both peers within 100ms of detection |

### Phase 3: QUIC + MoQ Client

| Step | Crate | What | Acceptance |
|------|-------|------|------------|
| 3.1 | `voip-client` | QUIC connection via quinn: connect, accept, send datagram, open stream | Connects to another quinn endpoint in 1 RTT |
| 3.2 | `voip-client` | QUIC path probing: migrate to 5 signaling server IPs, collect reflected addresses | NAT-01 through NAT-04 pass via QUIC (not STUN) |
| 3.3 | `voip-client` | Port prediction: delta analysis, predicted range, QUIC hole punching | CONN-03 passes in simulated network |
| 3.4 | `voip-client` | Connection migration: PATH_CHALLENGE/PATH_RESPONSE on address change | MIG-01, MIG-02 pass |
| 3.5 | `voip-client` | MoQ control messages: CLIENT_SETUP, SERVER_SETUP, ANNOUNCE, SUBSCRIBE | MoQ session establishes on existing QUIC connection |
| 3.6 | `voip-client` | MoQ datagram send/receive: track alias + sequence + timestamp + payload | Audio datagrams flow in both directions |
| 3.7 | `voip-client` | MoQ feedback: periodic quality reports at 1Hz | MED-05 passes |
| 3.8 | `voip-client` | Connection ID pre-agreement: caller generates 12-byte CSPRNG, include in CallRequest, callee validates on incoming packets | Connection ID in CallRequest, peer validates before responding to PATH_CHALLENGE |
| 3.9 | `voip-client` | QUIC simultaneous open for Cone NAT: both sides send PATH_CHALLENGE to peer's reflexive address simultaneously | Cone NAT connection established in <300ms (CONN-02) |
| 3.10 | `voip-client` | Happy Eyeballs v2: IPv6 25ms head start over IPv4 (quinn built-in) | IPv6 attempted first when both address types available |
| 3.11 | `voip-client` | Session ticket storage + 0-RTT resumption for reconnections | Reconnection completes in <100ms (0-RTT) |
| 3.12 | `voip-client` | In-channel ConnectionMigration message: send new addresses after network change over existing QUIC stream | Peer receives new address and reconnects without call drop |
| 3.13 | `voip-client` | In-channel TrackUpdate message: add/remove tracks and subscriptions mid-call | Tracks added/removed without MoQ session restart |
| 3.14 | `voip-client` | Client-side peer address book: cache PeerRecords with discovery_method tracking | Previously discovered peers found in <5ms |

### Phase 3.5: MASQUE Fallback

| Step | Crate | What | Acceptance |
|------|-------|------|------------|
| 3.15 | `voip-client` | MASQUE CONNECT-UDP over HTTP/3: bidirectional model, both peers connect outbound to proxy, proxy bridges by call_id | MASQUE-01 passes |
| 3.16 | `voip-client` | MASQUE CONNECT-UDP over HTTP/2 (RFC 9297 §5): CONNECT-UDP on HTTP/2 stream, capsule framing, UDP-blocked fallback | MASQUE-04 passes (UDP blocked → HTTP/2 fallback, CONN_MASQUE_HTTP2) |
| 3.17 | `voip-client` | DHT proxy discovery: lookup ProxyRecord in KadDHT, verify Ed25519 signature | MASQUE-02 passes |
| 3.18 | `voip-client` | Signaling proxy discovery: GET /v1/proxies, handle MasqueRelayNeeded from signaling server | MASQUE-03 passes |
| 3.19 | `voip-client` | MASQUE fallback integration: automatic fallback chain after pillar failure (HTTP/3 first, HTTP/2 if UDP blocked) | MASQUE-04, MASQUE-05 pass |
| 3.20 | `voip-client` | Volunteer proxy node: desktop clients run HTTP/3 + HTTP/2 dual-stack MASQUE proxy on port 443 | MASQUE-06 passes |
| 3.21 | `voip-client` | MASQUE anti-abuse: capacity (10 sessions), duration (4h), datagram rate (500/s), size (1200B), bandwidth (1 Mbps), target port restriction | Limits enforced, violations trigger graceful close |
| 3.22 | `voip-client` | ProxyToken: client requests from signaling server (POST /v1/proxy-token), presents in CONNECT-UDP header | ProxyToken validated at proxy, rejected without valid token |
| 3.23 | `voip-client` | Proxy certificate provisioning: Let's Encrypt (rustls-acme), self-signed with DHT trust-on-first-use, or Cloudflare Tunnel | Proxy obtains valid TLS certificate, clients connect successfully |
| 3.24 | `voip-client` | MASQUE tunnel recovery: RECOVERING state, re-discovery, reconnection on proxy failure during active call | MASQUE tunnel re-established within 600ms after proxy disconnect |
| 3.25 | `voip-client` | MASQUE proxy cache (client-side): store ProxyRecord[] and last-used proxy, 1-hour TTL | Proxies cached locally, re-lookup avoided for cached proxies |

### Phase 4: Audio Pipeline & Push Retry

| Step | Crate | What | Acceptance |
|------|-------|------|------------|
| 4.1 | `voip-client` | Opus encode/decode: VOIP mode, 48kHz, 20ms frames, FEC, DTX | Encode → decode round-trip produces intelligible audio |
| 4.2 | `voip-client` | Audio pipeline: capture → encode → MoQ datagram → QUIC send | End-to-end latency <200ms on LAN |
| 4.3 | `voip-client` | MoQ priority: audio packets sent before any queued video | MED-02 passes |
| 4.4 | `voip-client` | FEC: 5% packet loss still produces intelligible audio (MOS > 3.0) | MED-03 passes |
| 4.5 | `voip-client` | DTX: silence suppression, bandwidth drops below 1kbps | MED-04 passes |
| 4.6 | `voip-client` | Push notification: send PushRetry on NAT failure | RETRY-01, RETRY-02 pass |
| 4.7 | `voip-client` | Auto-retry: scheduled retry with exponential backoff (5s, 15s, 45s) | RETRY-03, RETRY-04 pass |

### Phase 5: End-to-End Integration

| Step | Crate | What | Acceptance |
|------|-------|------|------------|
| 5.1 | all | IPv6 direct connection | CONN-01, SIG-01, MED-01 pass |
| 5.2 | all | IPv4 Cone NAT (QUIC simultaneous open) | CONN-02 passes |
| 5.3 | all | IPv4 Symmetric NAT sequential (QUIC path probing + prediction) | CONN-03 passes |
| 5.4 | all | IPv4 Symmetric NAT random → honest failure + push retry | CONN-04 passes |
| 5.5 | all | UDP blocked → MASQUE over HTTP/2 → honest failure only if TCP 443 also blocked | CONN-05 passes |
| 5.6 | all | Mixed IPv6 + IPv4 Symmetric — connection succeeds via IPv6 in <300ms | CONN-06 passes |
| 5.7 | all | DHT discovery: privacy-first mode | DISC-01 through DISC-05 pass |
| 5.8 | all | Signaling blocked → DHT fallback | DISC-04 passes |
| 5.9 | all | All migration tests | MIG-01 through MIG-04 pass |
| 5.10 | all | MASQUE fallback: all pillars fail, MASQUE succeeds (HTTP/3 and HTTP/2) | MASQUE-01 through MASQUE-06 pass |
| 5.11 | all | NAT cache TTL expiry — prediction cache invalidated after 5 minutes | NAT-06 passes |
| 5.12 | all | NAT cache invalidation on network change — full re-probe triggered | NAT-07 passes |
| 5.13 | all | Call rejection flow — CallReject with reason, call ends cleanly | CallReject handled correctly by both signaling server and client |
| 5.14 | all | MASQUE tunnel recovery during active call | MASQUE tunnel re-established within 600ms |

### Phase 6: Mobile Bindings

| Step | Crate | What | Acceptance |
|------|-------|------|------------|
| 6.1 | `voip-ffi` | UniFFI bridge: expose voip-client API to Kotlin/Swift, DHT lookup-only (no routing) | Generated bindings compile without errors, no DHT routing APIs exposed |
| 6.2 | `mobile/android` | Android AAR with Kotlin bindings | AAR builds, demo app makes a call |
| 6.3 | `mobile/ios` | iOS XCFramework with Swift bindings | Framework builds, demo app makes a call |

---

## v8.1 — Hardening

After v8.0 passes all acceptance tests. No new features — only robustness.

- Fuzz testing: Protobuf decoder, QUIC packet handling, DHT record parsing
- Network simulation: variable latency, packet loss, jitter, reordering
- Load testing: signaling server with 1000 concurrent WebSocket connections
- Security audit: JWT validation, Connection ID entropy, DHT Sybil resistance
- S/Kademlia upgrade: proof-of-work node IDs, disjoint lookup paths
- MASQUE abuse reporting: GOAWAY frames, IP blacklist, DHT reputation records for volunteer proxies

---

## v8.2 — Video & Screen Share

Adds video tracks to the existing MoQ infrastructure. No architectural changes.

- Video track: VP9 encoding, MoQ track namespace `voip/{peer_id}/video/vp9-720p`
- Screen share track: VP9 encoding, `voip/{peer_id}/screen/vp9-1080p`
- Adaptive bitrate: read QUIC congestion state, adjust VP9 bitrate
- MoQ priority: audio (0) > video keyframe (1) > video delta (2) > screen (3)

---

## v9.0 — Group Calls via MoQ Relay

The first and only time a relay enters the architecture. MoQ relay is a standardized, privacy-preserving media forwarder — it does not decrypt, store, or transcode media.

---

## What Is NOT on the Roadmap

- **TURN/DERP relay** — replaced by MASQUE CONNECT-UDP
- **ICE candidate gathering** — eliminated, replaced by QUIC simultaneous open
- **RTP/SRTP compatibility** — this is not an RTP system
- **SIP/SDP signaling** — this is not a SIP system
- **End-to-end encryption beyond TLS 1.3** — future work
- **Recording server** — media is never stored server-side
- **Transcoding** — Opus is the only audio codec; VP9 is the only video codec
