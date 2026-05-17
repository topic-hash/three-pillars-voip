# 6. Discovery & Signaling

> Part of: Three Pillars VoIP Relay-Free Architecture Specification (TS-2025-001 v8.0)  
> See also: [Architecture Overview](01_Architecture_Overview.md) | [Data Model: Signaling Messages](07_Data_Model.md) | [API: Signaling Server](08_API_Specification.md) | [Data Flows](09_Data_Flows.md)

---

## 6.1 Discovery Architecture

Discovery uses two layers with user-selectable priority:

| Layer | Protocol | Latency | Privacy | Censorship Resistance |
|-------|----------|---------|---------|----------------------|
| DHT (libp2p KadDHT → S/Kademlia v2) | Distributed hash table | ~80ms | High — no single entity sees social graph | High — no entity to subpoena |
| Signaling Server | QUIC + Protobuf | ~5ms | Low — Cloudflare + governments can see social graph | Low — can be blocked or compelled |

**User toggle:** The application exposes a single setting:
- **Privacy-first (default):** DHT → Signaling server. Try DHT first (~80ms), fall back to signaling server if DHT lookup fails.
- **Speed-first:** Signaling server → DHT. Try signaling server first (~5ms), fall back to DHT if server is unreachable.

**Why default is Privacy-first:** The signaling server behind Cloudflare gives one US corporation and any government with jurisdiction complete visibility into the user's social graph (who they look up, when, how often). The DHT distributes this information across thousands of nodes — no single entity sees the full picture. For a privacy-focused VoIP application, privacy-first is the correct default.

---

## 6.2 DHT Discovery Layer

### 6.2.1 Implementation: libp2p KadDHT

The initial implementation uses libp2p KadDHT (regular Kademlia). This is battle-tested in production (IPFS, libp2p ecosystem) and provides the core censorship-resistant discovery capability.

**Roadmap to S/Kademlia (v2):** Regular Kademlia lacks Sybil resistance and disjoint lookup paths. S/Kademlia adds:
- Proof-of-work on node ID generation (makes Sybil attacks expensive)
- Disjoint lookup paths (attacker must control nodes on both paths to block discovery)

S/Kademlia will be implemented as a hardening step after the initial KadDHT deployment proves stable.

### 6.2.2 DHT Operation

| Operation | How | Latency |
|-----------|-----|---------|
| Register | Store `{username/peer_id → connection_data}` in DHT | ~80ms (recursive put) |
| Lookup | Find peer's connection data by username/peer_id | ~80ms (recursive lookup) |
| Refresh | Re-publish registration before TTL expires (60 min) | Background |
| Bootstrap | Get initial DHT node list from signaling server or hardcoded seeds | ~50ms |

### 6.2.3 Mobile Constraints

- **Mobile clients do NOT run full DHT nodes.** They perform lookups only. Full DHT nodes require maintaining routing tables and answering queries from other nodes, which drains battery.
- **Desktop/laptop clients run full DHT nodes.** They store routing tables, answer queries, and store/forward data. This is the infrastructure — users' always-on devices are the DHT.
- **Bootstrap:** The signaling server provides a list of active DHT nodes on registration. Hardcoded seed nodes (3-5 long-lived desktop nodes) are included in the app binary as fallback.

### 6.2.4 DHT Stored Data

```
Key:   SHA-256("voip:{peer_id}")
Value: PeerRecord (Protobuf, signed by Ed25519)
```

Data is signed by the peer's Ed25519 private key. Consumers verify the signature before trusting the data.

### 6.2.5 Username → Peer ID Resolution

Users find each other by human-readable username (e.g., "alice"), not by UUID. The DHT and signaling server both provide username-to-peer_id resolution:

**DHT resolution:**
```
Key:   SHA-256("voip-name:{username}")
Value: { peer_id: string, signature: bytes }
```
- The value contains only the `peer_id` and an Ed25519 signature over `{username}:{peer_id}`.
- The caller then looks up `SHA-256("voip:{peer_id}")` to get the full `PeerRecord`.
- Two DHT lookups: ~160ms total (often cached after the first).
- The username record is published alongside the peer record and refreshed every 30 minutes.

**Signaling server resolution:**
```
GET /v1/peers/lookup?username=alice

Response:
{
  "peer_id": "uuid-v4",
  "display_name": "Alice",
  "status": "ONLINE"
}
```
- Single REST call: ~5ms.
- Returns only the peer_id, display_name, and status. Full connection data requires a separate `GET /v1/peers/{peer_id}` call.

**Why two-step DHT lookup:** Storing the full PeerRecord under the username key would duplicate data and create a consistency problem (two records to keep in sync). The username record is minimal — just the mapping — and the peer record is the authoritative source of connection data.

---

## 6.3 Signaling Server

### 6.3.1 Role

The signaling server is a lightweight coordination service. It exchanges peer addresses, predicted port ranges, and MoQ track information. It **NEVER** forwards media packets. Its role is complete after 4 messages (~100ms).

Key properties:
- **No media path:** The signaling server never sees, touches, or forwards media packets. It cannot relay media even if compromised.
- **No encryption keys:** The signaling server does not participate in the QUIC/TLS handshake. It never has access to session keys or media content.
- **Minimal lifetime:** The server's involvement ends after address exchange. The entire signaling interaction is ~4 messages, ~700 bytes, ~100ms.
- **No state after call setup:** Once both peers have each other's address and track info, the server has no further role.
- **QUIC path probing endpoint:** The signaling server has 5 elastic IPs and reflects observed addresses for NAT classification.
- **IPv6 fast-path:** `GET /v1/myip` returns the client's observed IP address. If IPv6, skip NAT probing entirely.

### 6.3.2 Deployment: $0/Month

| Component | Provider | Cost |
|-----------|----------|------|
| Signaling server | Oracle Cloud Always Free (2 AMD micro, 1GB each) | $0 |
| CDN + ECH censorship shield | Cloudflare Free plan | $0 |
| QUIC path probing | 5 elastic IPs on Oracle Free instance | $0 |
| DHT bootstrap | Signaling server provides node lists | $0 |
| Push notifications | Firebase Cloud Messaging (free tier) | $0 |

**Total infrastructure cost: $0/month.**

### 6.3.3 Privacy Acknowledgment

The signaling server behind Cloudflare is NOT censorship-resistant. Cloudflare terminates TLS and sees:
- Full request URLs (`/lookup?user=bob`)
- User IP addresses
- Frequency and timing of all lookups
- Complete social graph (who contacts whom and when)

This data is accessible via subpoena to Cloudflare or any government with jurisdiction. This is the tradeoff for 5ms discovery speed. The DHT layer exists precisely to provide a private alternative.

---

## 6.4 Signaling Protocol (Protocol Buffers)

The signaling server uses Protocol Buffers for efficient binary encoding. Typical message size: <200 bytes (vs. 2-5KB for SIP/SDP).

**Authoritative schema:** `proto/signaling.proto` is the source of truth. That file is compiled by `prost-build` to generate Rust types. The schema in [Data Model](07_Data_Model.md) is a human-readable rendering — if the two disagree, `proto/signaling.proto` wins.

**Key messages in the signaling exchange:**

| Message | Purpose | Key Fields |
|---------|---------|------------|
| `CallRequest` | Caller initiates call | `caller_id`, `callee_id`, `ipv6_addresses`, `ipv4_reflexive`, `nat_info`, `tracks`, `discovery_method` |
| `CallAccept` | Callee accepts call | `ipv6_addresses`, `ipv4_reflexive`, `nat_info`, `tracks`, `subscriptions` |
| `CallReject` | Callee rejects call | `reason`, `end_reason` |
| `CallFailed` | Connection attempt failed | `reason`, `description` |
| `CallEnded` | Call terminated normally | `reason`, `duration_seconds`, `method` |
| `PeerRegister` | Register/update peer presence | `peer_id`, `display_name`, `ipv6_addresses`, `ipv4_reflexive`, `nat_info`, `tracks`, `status` |
| `PeerUnregister` | Remove peer presence | `peer_id` |
| `PushRetry` | Request peer to retry connection | `call_id`, `caller_id`, `reason` |

**Wire framing:** Each WebSocket message has a 2-byte type prefix followed by the Protobuf payload.

---

## 6.5 Typical Signaling Exchange

1. A → Server: `CallRequest` (with IPv6 address, or IPv4 + port prediction + MoQ track announcements)
2. Server → B: `CallRequest` (forwarded)
3. B → Server: `CallAccept` (with IPv6 address, or IPv4 + port prediction + MoQ track announcements + subscriptions)
4. Server → A: `CallAccept` (forwarded)
5. **Server's role is complete.** A and B now connect directly via QUIC, then establish MoQ session.

Total signaling messages: 4. Total signaling data: ~700 bytes. Server involvement: <100ms. Server never sees media. Server never decrypts media. Server cannot relay media even if compromised.

---

## 6.6 NAT Probing Sequence (QUIC-Native)

```
On application startup:
  1. Check IPv6 availability on all interfaces
  2. Fast-path: GET /v1/myip on signaling server
     → If IPv6: skip NAT probing entirely. Done.
  3. If IPv4-only: probe NAT via QUIC path probing
     → Migrate QUIC connection to each of signaling server's 5 elastic IPs
     → Server reflects observed IP:port for each migration
     → Note: This is QUIC connection migration, NOT STUN. Same QUIC connection.
  4. Analyze port allocation pattern (sequential / pseudo-sequential / random)
  5. Cache: { external_ip, base_port, delta_pattern, confidence, timestamp }

Before each call:
  6. If IPv6 available: signal IPv6 address, done
  7. If IPv4 with cached prediction:
     a. Refresh: 2 quick path probes (verify pattern hasn't changed)
     b. Predict: external_port based on pattern + time since last probe
     c. Signal predicted range to peer
  8. If prediction confidence is RANDOM:
     a. Signal only the path-probe-learned reflexive address
     b. Connection attempt will use QUIC simultaneous open
     c. If peer is also IPv4-only Symmetric random: call fails
     d. Push notification sent for retry when network changes

After network change:
  9. QUIC connection migration handles the path change
  10. MoQ session continues on migrated connection
  11. Re-probe NAT from scratch (Steps 3-5)
  12. Signal new predicted range through existing QUIC connection
```

---

## 6.7 Combined Connection Flow

```
┌─────────────────────────────────────────────────────────┐
│               DISCOVERY (DHT or Signaling)                │
│  DHT: ~80ms, private, censorship-resistant               │
│  Signaling: ~5ms, visible to Cloudflare + governments    │
│  User chooses priority via toggle                        │
│  (exchanges peer addresses + predicted port ranges)      │
│  (exchanges MoQ track namespace + subscription info)     │
└──────────┬──────────────────────────┬───────────────────┘
           │                          │
     Step 1: Exchange              Step 1: Exchange
     peer addresses                peer addresses
     + MoQ track info              + MoQ track info
           │                          │
           ▼                          ▼
┌──────────────────┐        ┌──────────────────┐
│   ENDPOINT A     │        │   ENDPOINT B     │
└──────────────────┘        └──────────────────┘

Step 2: A checks for IPv6
  → Has IPv6? Signal IPv6 address. Skip to Step 5.
  → No IPv6? Continue to Step 3.

Step 3: A probes own NAT via QUIC path probing (if IPv4)
  → Migrate QUIC connection to 5 signaling server IPs
  → Analyze port allocation pattern from reflected addresses
  → Predict external port range for this call

Step 4: A and B exchange addresses + predicted port ranges + MoQ track info
  → A signals: "my IPv6 address is [2001:db8::1]" OR
               "my IPv4 predicted range is 203.0.113.5:42004-42010"
  → A announces: "my audio track is voip/a/audio/opus-48k"
  → B signals same for its side
  → B subscribes to A's audio track, A subscribes to B's audio track
  → Discovery layer's role is now COMPLETE.

Step 5: Direct QUIC connection
  → If IPv6 available: QUIC connect to peer's IPv6 address (1 RTT)
  → If IPv4 Cone NAT: QUIC simultaneous open (PATH_CHALLENGE) (1 RTT)
  → If IPv4 Symmetric NAT: QUIC PATH_CHALLENGE to predicted range (1-2 RTTs)
  → Connection ID validates incoming packets immediately

Step 6: MoQ session on QUIC connection
  → MoQ track announcements confirmed
  → Peer subscribes to audio track
  → Media flows as MoQ datagrams with Opus audio
  → MoQ priority ensures audio packets go first
  → MoQ feedback replaces RTCP

Step 7: Media flows directly A ←→ B
  → MoQ datagrams carry Opus audio
  → MoQ feedback carries quality reports
  → QUIC streams carry signaling updates
  → No relay. No intermediary. Direct P2P.

Step 8: Network change (WiFi → cellular, new WiFi, etc.)
  → QUIC connection migration (1 RTT, no call drop)
  → MoQ session continues on migrated connection
  → Re-probe NAT via QUIC path probing (if IPv4)
  → If IPv6, just migrate (no NAT to re-probe)
  → Signal new address through existing QUIC connection

Step 9 (failure only): Connection failed
  Step 9a: Signaling server detects MASQUE needed (both RANDOM or UDP blocked)
    → Server sends MasqueRelayNeeded to BOTH peers with proxy URL
    → Both peers connect to MASQUE proxy via HTTP/3 + TLS 1.3
    → Both send CONNECT-UDP with same call_id
    → Proxy matches requests and bridges tunnels
    → If proxy responds 200 OK to both → tunnel MoQ through proxy → CONNECTED, method = CONN_MASQUE
    → If proxy unreachable → try next proxy candidate
  Step 9b: If UDP is entirely blocked
    → MASQUE over HTTP/2 (TCP) to same proxy
    → CONNECT-UDP on HTTP/2 stream (RFC 9297 §5 capsules)
    → Same proxy, same call_id matching — MoQ works through tunnel
    → If TCP port 443 also blocked → fall through to push retry
  Step 9c: Push retry (only if MASQUE over both HTTP/3 and HTTP/2 fails)
    → Send PushRetry notification to peer
    → Peer auto-retries on network change
    → Scheduled retry with exponential backoff (5s, 15s, 45s, give up)
```

---

## 6.8 MASQUE Proxy Discovery

### 6.8.1 DHT Proxy Records

The DHT stores proxy records with key `SHA-256("masque-proxy:{node_id}")`. Each ProxyRecord contains:

- `proxy_url`: The MASQUE proxy endpoint (e.g., `https://proxy.example.com:443/masque`)
- `capacity`: Maximum concurrent relay sessions
- `region`: Geographic region hint for proximity-based selection
- `latency_hint`: Estimated latency in milliseconds
- Signed by the node's Ed25519 key

### 6.8.2 Proxy Selection Algorithm

1. **DHT lookup**: Query `SHA-256("masque-proxy:{node_id}")` for available proxies
2. **Filter**: Remove proxies that are full (capacity reached) or in distant regions
3. **Measure latency**: Ping top 3 candidates to measure actual round-trip time
4. **Select**: Choose the proxy with the lowest measured latency

### 6.8.3 Signaling Server Fallback

If DHT lookup fails or returns no results, the signaling server provides a fallback:

- `GET /v1/proxies` returns a list of known MASQUE proxy addresses
- Proxies returned by the signaling server may be fewer than DHT results, but are guaranteed reachable

### 6.8.4 Volunteer Proxy Nodes

- Desktop clients can opt-in to run proxy nodes
- Proxy capability is advertised via DHT ProxyRecord
- Volunteer proxies are like Tor Snowflake — variable quality but very high censorship resistance
- Mobile clients do NOT run proxy nodes (battery constraint)
