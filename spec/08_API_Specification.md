# 8. API Specification

> Part of: Three Pillars VoIP Relay-Free Architecture Specification (TS-2025-001 v8.0)

---

## 8.1 Signaling Server API

### 8.1.1 WebSocket API

**Endpoint:** `wss://signal.example.com/v1/ws`

**Authentication:** JWT token in query parameter `?token=<jwt>`.

**Message Framing:** 2-byte type prefix + Protobuf payload:

| Type ID | Message Type | Direction |
|---------|-------------|-----------|
| 0x0001 | `CallRequest` | Client → Server |
| 0x0002 | `CallRequest` | Server → Client (forwarded) |
| 0x0003 | `CallAccept` | Client → Server |
| 0x0004 | `CallAccept` | Server → Client (forwarded) |
| 0x0005 | `CallReject` | Client → Server |
| 0x0006 | `CallReject` | Server → Client (forwarded) |
| 0x0007 | `CallFailed` | Either direction |
| 0x0008 | `CallEnded` | Either direction |
| 0x0009 | `PushRetry` | Server → Client |
| 0x0100 | `PeerRegister` | Client → Server |
| 0x0101 | `PeerUnregister` | Client → Server |
| 0x0200 | `PathProbeResponse` | Server → Client (on QUIC stream, not WebSocket) |
| 0x0300 | `MasqueRelayNeeded` | Server → Client |
| 0x8001 | `Error` | Server → Client |

### 8.1.2 REST API

**Base URL:** `https://signal.example.com/v1`

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/peers` | Register a new peer |
| `PUT` | `/peers/{peer_id}` | Update peer registration |
| `DELETE` | `/peers/{peer_id}` | Unregister a peer |
| `GET` | `/peers/{peer_id}` | Get peer info |
| `GET` | `/peers/lookup?username={name}` | Resolve username to peer_id |
| `GET` | `/peers/{peer_id}/status` | Get online status |
| `GET` | `/myip` | **NEW** Returns client's observed IP address (IPv6 or IPv4). Used for IPv6 fast-path. |
| `POST` | `/probe` | **NEW** QUIC path probing endpoint. Client migrates QUIC connection to this server, server reflects observed address. Requires QUIC connection. |
| `GET` | `/proxies` | Returns list of known MASQUE proxy addresses |
| `GET` | `/dht/bootstrap` | Returns list of active DHT node multiaddresses for bootstrap |
| `POST` | `/proxy-token` | Issues a ProxyToken for anti-abuse verification at MASQUE proxy |

### 8.1.3 `/myip` Response

```json
{
  "ip": "2001:db8::1",
  "ip_version": 6,
  "port": 54321,
  "observed_at": 1715673600
}
```

If the server sees an IPv6 address, the client skips NAT probing entirely.

### 8.1.4 QUIC Path Probing (`/probe`)

The signaling server listens for QUIC connections on 5 elastic IPs. When a client migrates its QUIC connection to a different server IP, the server observes the client's new source address and reflects it back on the QUIC stream:

```
1. Client connects to signaling server on IP_1 via QUIC
2. Client migrates connection to IP_2 (PATH_CHALLENGE on new path)
3. Server sees client's source address from IP_2 path
4. Server sends PathProbeResponse on QUIC stream:
   { "server_ip": "IP_2", "observed_ip": "203.0.113.5", "observed_port": 42001 }
5. Repeat for IP_3, IP_4, IP_5
6. Client now has 5 observed addresses → compute deltas → classify NAT
```

### 8.1.5 Signaling Server Behavior

- Server does NOT validate PortPrediction values. Forwards as-is.
- Server does NOT verify TrackAnnouncement namespaces. Forwards as-is.
- Server DOES verify caller_id and callee_id exist and are registered.
- Server DOES enforce rate limits.
- Server MAY log call metadata for analytics. MUST NOT log media content or session keys.
- Server DOES relay PushRetry messages via Firebase Cloud Messaging.

---

## 8.2 DHT Discovery API

### 8.2.1 DHT Operations (voip-dht crate)

```rust
trait DhtDiscovery {
    /// Register peer data in the DHT.
    /// Key = SHA-256("voip:{peer_id}"), Value = signed peer record.
    async fn register(&mut self, peer: &PeerRecord) -> Result<(), DhtError>;

    /// Look up a peer by peer_id in the DHT.
    /// Returns the signed peer record if found.
    async fn lookup(&mut self, peer_id: &str) -> Result<PeerRecord, DhtError>;

    /// Bootstrap into the DHT using known seed nodes.
    async fn bootstrap(&mut self, seeds: &[Multiaddr]) -> Result<(), DhtError>;

    /// Get the list of currently connected DHT nodes (for diagnostics).
    fn connected_peers(&self) -> Vec<PeerId>;
}
```

### 8.2.2 DHT Bootstrap Flow

1. Client starts, connects to signaling server
2. Client requests DHT bootstrap nodes: `GET /v1/dht/bootstrap`
3. Server returns list of active DHT node multiaddresses
4. Client bootstraps into DHT using these nodes
5. **Fallback:** If signaling server is unreachable, client uses hardcoded seed nodes from app binary

---

## 8.3 Client MoQ Interface

(Same structure as v6.0 §8.2 with MoQSession, TrackPublisher, TrackSubscriber, etc. No changes to MoQ API.)

---

## 8.4 QUIC Connection Management API

(Same structure as v6.0 §8.3 with VoIPConnectionManager, ConnectParams, etc. Key changes:)

- **Step 1: IPv6 Direct** — same
- **Step 2: IPv4 Cone NAT** — uses QUIC PATH_CHALLENGE instead of raw UDP hole punch
- **Step 3: Port Prediction** — sends QUIC PATH_CHALLENGE to predicted range instead of raw QUIC Initial

### Updated Connection Establishment Strategy

**Step 2: IPv4 Cone NAT (QUIC simultaneous open)**

```
For each IPv4 address in ipv4_reflexive:
    Send QUIC PATH_CHALLENGE to peer's reflexive address
    Peer sends QUIC PATH_CHALLENGE to our reflexive address
    Both NATs allow inbound (Cone = destination-independent mapping)
    If handshake completes → CONNECTED, method = CONN_IPV4_CONE
```

**Step 3: Port Prediction (QUIC hole punching)**

```
Predict target port range from port_prediction params
For each port in predicted_port_start..=predicted_port_end:
    Send QUIC PATH_CHALLENGE to target_ip:port with pre-agreed Connection ID
    The peer's QUIC stack recognizes the Connection ID and responds
    If PATH_RESPONSE received → hole punched AND connection validated in one step
    → CONNECTED, method = CONN_IPV4_PREDICTION
```

**Step 4: MASQUE Fallback (automatic when Steps 1-3 all fail)**

```
Discover proxy via DHT or signaling server
If UDP available:
  Open HTTP/3 connection to proxy on port 443
  Send CONNECT-UDP request
  → CONNECTED, method = CONN_MASQUE
If UDP blocked:
  Open HTTP/2 connection to proxy on port 443 (TCP)
  Send CONNECT-UDP request on HTTP/2 stream (RFC 9297 §5 capsules)
  → CONNECTED, method = CONN_MASQUE_HTTP2
Tunnel MoQ datagrams through proxy (QUIC through tunnel, MoQ works unchanged)
```

**Step 5: Push Retry (when MASQUE over both HTTP/3 and HTTP/2 fails)**

---

## 8.6 MASQUE Tunnel API

```rust
trait MasqueTunnel {
    /// Establish MASQUE CONNECT-UDP tunnel to target peer.
    /// Called automatically when all Three Pillars fail.
    async fn connect_via_proxy(
        &mut self,
        proxy_url: &str,
        target_ip: &str,
        target_port: u16,
    ) -> Result<MasqueConnection, MasqueError>;

    /// Discover available MASQUE proxies via DHT or signaling.
    async fn discover_proxies(&mut self) -> Result<Vec<ProxyRecord>, MasqueError>;

    /// Get the current MASQUE tunnel status.
    fn tunnel_status(&self) -> TunnelStatus;
}

enum TunnelStatus {
    NotNeeded,      // Direct P2P established
    Connecting,     // MASQUE tunnel being established
    Active,         // MASQUE relay in use (HTTP/3)
    ActiveHttp2,    // MASQUE relay in use (HTTP/2, UDP blocked)
    Failed,         // MASQUE over both transports failed, falling back to push retry
}
```

---

## 8.5 Error Codes

The `Error` message (type ID 0x8001) uses the following error codes in the `code` field:

| Code | Name | Description |
|------|------|-------------|
| 1001 | `UNKNOWN_PEER` | Requested peer_id is not registered |
| 1002 | `PEER_OFFLINE` | Requested peer is offline |
| 1003 | `INVALID_CALL_ID` | Call ID not found or expired |
| 1004 | `CALL_ALREADY_EXISTS` | Duplicate call_id |
| 1005 | `NOT_CALL_PARTICIPANT` | Peer not part of this call |
| 2001 | `RATE_LIMITED` | Too many requests — slow down |
| 2002 | `INVALID_JWT` | JWT token missing, expired, or invalid |
| 2003 | `INVALID_MESSAGE` | Protobuf decode error or unknown type |
| 3001 | `MASQUE_NO_PROXY` | No MASQUE proxy available |
| 3002 | `MASQUE_PROXY_TIMEOUT` | Proxy connection timed out |
| 3003 | `MASQUE_COORDINATION_FAILED` | MASQUE proxy coordination unavailable — no reachable proxy |
| 9999 | `INTERNAL_ERROR` | Server-side error (check logs) |

---

## 8.6 JWT Authentication

### 8.6.1 JWT Structure

The signaling server authenticates clients via JWT tokens. The token is passed as a query parameter on the WebSocket connection: `wss://signal.example.com/v1/ws?token=<jwt>`.

**Token claims:**

| Claim | Type | Description |
|-------|------|-------------|
| `sub` | `string` | Peer ID (UUID v4) — the authenticated peer |
| `iat` | `uint64` | Issued at (unix seconds) |
| `exp` | `uint64` | Expiration time (unix seconds) |
| `pub_key` | `string` | Ed25519 public key (hex-encoded) — used for DHT record verification |

**Token issuance:** The client generates an Ed25519 key pair on first launch. The public key becomes the peer_id (hex-encoded). The client sends the public key to the signaling server, which issues a JWT signed with the server's private key.

**Token refresh:** Tokens expire after 1 hour (`jwt_expiry_secs`). The client refreshes the token via `POST /v1/token/refresh` before expiry.

**Token validation:** The signaling server validates the JWT signature, checks `exp`, and confirms the `sub` (peer_id) matches a registered peer.

---

## 8.7 Connection ID Pre-Agreement

Before QUIC hole punching (Pillar 2, Step 5), both peers need to know the Connection ID that will identify the QUIC connection. The Connection ID is generated by the caller and exchanged during signaling.

### 8.7.1 Connection ID Generation

The caller generates a 12-byte Connection ID using a CSPRNG (cryptographically secure pseudo-random number generator). The probability of collision is < 10^-20 for any reasonable number of concurrent calls.

### 8.7.2 Connection ID Exchange

The Connection ID is included in the `CallRequest` message as a new field:

```protobuf
message CallRequest {
  // ... existing fields ...
  bytes connection_id = 10; // 12-byte CSPRNG-generated QUIC Connection ID for this call
}
```

The callee receives the `connection_id` in the forwarded `CallRequest`. When the callee's QUIC stack receives a packet with this Connection ID, it immediately recognizes it as belonging to the expected call — no signaling round-trip needed.

### 8.7.3 Security

- The Connection ID is sent over the signaling server's TLS 1.3 connection, so it is not visible to network observers.
- The Connection ID is single-use — it identifies one call. After the call, it is discarded.
- An attacker who guesses the Connection ID still cannot complete the QUIC handshake without the TLS 1.3 key exchange.

---

## 8.8 MoQ Session Setup Messages

After the QUIC connection is established (via any Pillar or MASQUE), the MoQ session is set up using MoQ control messages on the QUIC stream. The following messages are exchanged:

### 8.8.1 Message Sequence

```
Caller (publisher)                    Callee (subscriber)
  │                                        │
  │ 1. CLIENT_SETUP                        │
  │    {versions: [draft-17],              │
  │     role: PUBLISHER+SUBSCRIBER}        │
  │───────────────────────────────────────▶│
  │                                        │
  │ 2. SERVER_SETUP                        │
  │    {version: draft-17,                 │
  │     role: PUBLISHER+SUBSCRIBER}        │
  │◀───────────────────────────────────────│
  │                                        │
  │ 3. ANNOUNCE                            │
  │    {namespace: "voip/{caller_id}"}     │
  │───────────────────────────────────────▶│
  │                                        │
  │ 4. ANNOUNCE_OK                         │
  │    {namespace: "voip/{caller_id}"}     │
  │◀───────────────────────────────────────│
  │                                        │
  │ 5. ANNOUNCE                            │
  │    {namespace: "voip/{callee_id}"}     │
  │◀───────────────────────────────────────│
  │                                        │
  │ 6. ANNOUNCE_OK                         │
  │    {namespace: "voip/{callee_id}"}     │
  │───────────────────────────────────────▶│
  │                                        │
  │ 7. SUBSCRIBE                           │
  │    {track: "voip/{caller_id}/audio/    │
  │     opus-48k", priority: 0}            │
  │◀───────────────────────────────────────│
  │                                        │
  │ 8. SUBSCRIBE_OK                        │
  │    {track_alias: 0x00000001}           │
  │───────────────────────────────────────▶│
  │                                        │
  │ 9. SUBSCRIBE                           │
  │    {track: "voip/{callee_id}/audio/    │
  │     opus-48k", priority: 0}            │
  │───────────────────────────────────────▶│
  │                                        │
  │ 10. SUBSCRIBE_OK                       │
  │    {track_alias: 0x00000002}           │
  │◀───────────────────────────────────────│
  │                                        │
  │ 11. Media datagrams flow               │
  │     (Opus audio as MoQ datagrams       │
  │      with track_alias in header)       │
  │◀──────────────────────────────────────▶│
```

### 8.8.2 Track Namespace Convention

Each peer announces a namespace `voip/{peer_id}` and publishes tracks within it:

| Track | Namespace | Priority | Codec |
|-------|-----------|----------|-------|
| Audio | `voip/{peer_id}/audio/opus-48k` | 0 (highest) | Opus 48kHz |
| Video | `voip/{peer_id}/video/vp9-720p` | 1-2 | VP9 720p |
| Screen | `voip/{peer_id}/screen/vp9-1080p` | 3 (lowest) | VP9 1080p |

### 8.8.3 MoQ Datagram Format

MoQ datagrams carry media frames with a compact header for efficient demultiplexing:

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

### 8.5.1 PushRetry Message (server-initiated)

When a call fails due to NAT incompatibility, the signaling server sends a PushRetry to the peer via Firebase Cloud Messaging:

```json
{
  "call_id": "uuid",
  "caller_id": "alice-peer-id",
  "reason": "END_FAILED_IPV4_RANDOM",
  "retry_attempt": 1,
  "retry_after_ms": 5000
}
```

### 8.5.2 Client Auto-Retry Logic

```rust
/// Handle push retry notification.
/// Re-probes NAT and attempts reconnection.
async fn handle_push_retry(&mut self, retry: PushRetry) -> Result<(), RetryError> {
    // 1. Re-probe NAT via QUIC path probing
    let new_prediction = self.probe_nat().await?;
    
    // 2. Attempt reconnection with new prediction
    match self.connect(retry.caller_id).await {
        Ok(conn) => Ok(()),
        Err(_) if retry.retry_attempt < 3 => {
            // Schedule next retry with exponential backoff
            let delay = 5 * 3u64.pow(retry.retry_attempt - 1);
            self.schedule_retry(retry.caller_id, retry.retry_attempt + 1, delay);
            Err(RetryError::WillRetry)
        }
        Err(e) => Err(RetryError::PermanentFailure(e)),
    }
}
```
