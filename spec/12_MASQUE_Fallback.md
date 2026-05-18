# 12. MASQUE CONNECT-UDP Fallback

> Part of: Three Pillars VoIP Minimal-Relay Architecture Specification (TS-2025-001 v8.0)
> See also: [Architecture Overview](01_Architecture_Overview.md) | [Discovery & Signaling](06_Discovery_Signaling.md) | [Data Flows](09_Data_Flows.md) | [Implementation Stack](11_Implementation_Stack.md)

---

## 12.1 Overview

When all Three Pillars fail (IPv6, QUIC simultaneous open, QUIC port prediction), MASQUE CONNECT-UDP (RFC 9298) provides automatic relay. Both peers establish HTTP/3 connections to a MASQUE proxy discovered via DHT or signaling server. Each peer sends a CONNECT-UDP request. The proxy bridges the two tunnels, forwarding UDP datagrams between them.

**Key properties:**
- **Automatic:** No user opt-in required. MASQUE activates seamlessly when the Three Pillars fail.
- **Censorship-resistant:** Traffic is inside TLS 1.3 over HTTP/3 — indistinguishable from ordinary HTTPS browsing. A firewall cannot block MASQUE without blocking all HTTPS.
- **Metadata-protected:** Unlike TURN, which leaks peer IP addresses and port numbers in cleartext, MASQUE wraps everything inside TLS 1.3. The proxy sees the target address, but network observers see nothing.
- **Transparent to MoQ:** The MoQ session runs over the MASQUE tunnel as if it were a direct QUIC connection. MoQ does not need to know it is being relayed.
- **Bidirectional:** Both peers connect to the proxy. This is essential because the proxy cannot directly reach a peer behind Symmetric NAT — the peer must initiate the connection outward.

**When MASQUE over HTTP/3 is used (UDP available):**
1. Both peers IPv4-only, both behind Symmetric NAT with random port allocation (~5% of connections)
2. IPv6 firewalls block both sides (~0.5% of connections)
3. Both IPv4, both Symmetric, one or both random (~5% of connections)

**When MASQUE over HTTP/2 is used (UDP blocked):**
1. UDP is entirely blocked by a firewall on one or both sides (~3% of connections). HTTP/3 (QUIC) requires UDP, so MASQUE over HTTP/3 cannot work. Both peers fall back to MASQUE over HTTP/2 (TCP), connecting to the same proxy on port 443 via TCP+TLS 1.3. The proxy bridges the two HTTP/2 CONNECT-UDP tunnels identically to the HTTP/3 case.

**When both fail (the ~1% honest failure):**
- UDP is blocked AND TCP port 443 is also blocked (no HTTP/2 possible)
- All MASQUE proxies are unreachable via both HTTP/3 and HTTP/2
- Push notification retry is the only remaining option

---

## 12.2 Protocol Mechanics

### 12.2.1 Bidirectional Tunnel Model

MASQUE relay in this architecture uses a **bidirectional tunnel model**: both peers establish CONNECT-UDP tunnels to the same proxy, and the proxy bridges the two tunnels. This is necessary because the proxy cannot directly reach a peer behind Symmetric NAT — the peer must initiate the connection outward to the proxy.

**Why unidirectional CONNECT-UDP doesn't work:** The simple CONNECT-UDP model (one peer connects to proxy, proxy opens UDP to the other peer) only works when the target peer is directly reachable. In the exact scenario where MASQUE is needed — both peers behind Symmetric NAT — neither peer is directly reachable from the proxy. Both peers must initiate outbound connections to the proxy, and the proxy bridges them.

### 12.2.2 CONNECT-UDP Request Format

MASQUE CONNECT-UDP is an HTTP/3 extension defined in RFC 9298. Each peer sends an HTTP/3 request with the CONNECT method and the `:protocol` pseudo-header set to `connect-udp`.

**Peer A's request (targets a well-known relay endpoint on the proxy):**
```
HEADERS frame:
  :method = CONNECT
  :protocol = connect-udp
  :path = /masque
  :authority = proxy.example.com:443
  connect-udp-target-host = voip-relay
  connect-udp-target-port = 0
  x-voip-call-id = <call_id>
  x-voip-peer-id = <peer_A_id>

  (all inside TLS 1.3 — invisible to network observers)
```

**Peer B's request (targets the same relay endpoint):**
```
HEADERS frame:
  :method = CONNECT
  :protocol = connect-udp
  :path = /masque
  :authority = proxy.example.com:443
  connect-udp-target-host = voip-relay
  connect-udp-target-port = 0
  x-voip-call-id = <call_id>
  x-voip-peer-id = <peer_B_id>

  (all inside TLS 1.3 — invisible to network observers)
```

The proxy matches the two CONNECT-UDP requests by `x-voip-call-id` and bridges them. When both peers have connected, the proxy forwards datagrams received from Peer A to Peer B's tunnel and vice versa.

### 12.2.3 CONNECT-UDP Response

```
HEADERS frame:
  :status = 200

  (proxy is now bridging datagrams between the two peers)
```

If the proxy cannot match the peer (e.g., the other peer hasn't connected yet), it returns:
```
HEADERS frame:
  :status = 504
  content-type: text/plain

  "Waiting for peer — retry after 5 seconds"
```

The client retries the CONNECT-UDP request after the indicated delay. The signaling server has already informed both peers to attempt MASQUE relay, so the peer should connect within seconds.

### 12.2.4 Datagram Flow (Bidirectional)

After both CONNECT-UDP tunnels are established, the proxy bridges datagrams between them:

```
Peer A ←→ HTTP/3 ←→ Proxy ←→ HTTP/3 ←→ Peer B

MoQ datagram inside HTTP/3 datagram inside QUIC inside TLS 1.3
```

1. Peer A sends a MoQ datagram → wrapped in HTTP/3 datagram → sent to proxy over QUIC/TLS 1.3
2. Proxy receives the HTTP/3 datagram on Peer A's tunnel
3. Proxy forwards the datagram payload to Peer B's tunnel as an HTTP/3 datagram
4. Peer B receives the HTTP/3 datagram → unwraps → delivers MoQ datagram

The reverse path is identical. The proxy acts as a simple datagram bridge — it does not inspect or modify the MoQ payload. MoQ media is end-to-end encrypted by QUIC between the peers (the QUIC connection that carries MoQ is established through the MASQUE tunnel, so the proxy only sees encrypted QUIC packets, not the plaintext media).

**Important:** The MoQ session's QUIC connection is established between the two peers *through* the MASQUE tunnel. The proxy sees only QUIC packets (encrypted), not the MoQ datagrams inside them. This means the proxy cannot inspect, modify, or filter media content.

### 12.2.5 Signaling-Assisted MASQUE Coordination

The signaling server plays a critical role in coordinating MASQUE relay. When a call fails (both peers behind random Symmetric NAT, or UDP blocked), the signaling server:

1. Detects that MASQUE relay is needed (based on NAT types exchanged in CallRequest/CallAccept)
2. Selects a MASQUE proxy (from its known proxy list or queries the DHT)
3. Sends `MasqueRelayNeeded` to both peers with the proxy URL and call_id
4. Both peers connect to the proxy and send CONNECT-UDP requests with the same call_id
5. The proxy matches the two requests and bridges them

This coordination is essential — without it, Peer B would not know to connect to a proxy.

---

## 12.3 MASQUE Tunnel Lifecycle

### 12.3.1 State Machine

```
┌───────────┐
│   IDLE    │
└─────┬─────┘
      │ Three Pillars failed
      ▼
┌──────────────┐
│ DISCOVERING  │──── DHT/signaling lookup for proxy
└─────┬────────┘
      │ Proxy record found
      ▼
┌──────────────┐
│ CONNECTING   │──── HTTP/3 + TLS 1.3 handshake to proxy
└─────┬────────┘     + CONNECT-UDP request
      │ 200 OK
      ▼
┌──────────────┐
│   TUNNELING  │──── MoQ session through CONNECT-UDP tunnel
└─────┬────────┘
      │ Proxy disconnect / error
      ▼
┌──────────────┐
│  RECOVERING  │──── Try next proxy candidate
└─────┬────────┘
      │ Another proxy available
      │ ──────────→ back to CONNECTING
      │ No more proxies
      ▼
┌──────────────┐
│   FAILED     │──── Push notification retry
└──────────────┘
```

### 12.3.2 Tunnel Setup Timing

| Phase | Duration | Description |
|-------|----------|-------------|
| Proxy discovery | 50-200ms | DHT lookup or signaling server query |
| HTTP/3 + TLS 1.3 handshake | 100-200ms | 1-RTT (0-RTT if session resumption) |
| CONNECT-UDP request/response | 50-100ms | Single request-response on HTTP/3 stream |
| MoQ session setup | 50-100ms | Track announcement + subscription |
| **Total additional latency** | **250-600ms** | Over direct P2P baseline |

The user experiences a call setup time of approximately 500-800ms (250ms Pillar attempt + 250-600ms MASQUE fallback). This is comparable to legacy VoIP systems that use TURN relay.

### 12.3.3 Tunnel Failure During Active Call

If the MASQUE proxy disconnects or becomes unreachable during an active call:

1. The HTTP/3 connection drops. The client detects this via QUIC idle timeout or connection error.
2. The client enters RECOVERING state.
3. The client queries DHT/signaling for a new proxy (50-200ms).
4. If a new proxy is found, the client establishes a new HTTP/3 + CONNECT-UDP tunnel (150-300ms).
5. The MoQ session is re-established on the new tunnel (50-100ms).
6. Audio gap: 250-600ms. This is noticeable but comparable to a brief network hiccup.
7. If no new proxy is found, the call fails with `END_FAILED_MASQUE_UNREACHABLE`.

---

## 12.4 MoQ-over-MASQUE Specifics

### 12.4.1 MTU Considerations

The MASQUE tunnel adds HTTP/3 datagram framing overhead on top of QUIC datagram overhead. The effective MTU for MoQ datagrams is reduced:

| Layer | Overhead |
|-------|----------|
| QUIC datagram header | ~4 bytes |
| HTTP/3 datagram quarter stream ID | 8 bytes (varint) |
| **Total MASQUE overhead** | **~12 bytes** |

With a typical path MTU of 1280 bytes (IPv6 minimum) and QUIC/UDP/IP overhead of ~48 bytes, the effective MoQ payload MTU through MASQUE is approximately **1220 bytes**. This is sufficient for Opus audio frames (typically 80-120 bytes) and VP9 video frames (fragmented across multiple datagrams if needed).

For Opus audio at 48kHz with 20ms frames, the typical packet size is 80-120 bytes — well within the MASQUE tunnel MTU. No fragmentation needed for audio.

### 12.4.2 Latency Impact

The MASQUE tunnel adds one extra network hop (client → proxy → peer) compared to direct P2P. The latency increase is approximately equal to the round-trip time between the client and the proxy plus the round-trip time between the proxy and the peer.

In practice:
- **Same-region proxy:** +10-30ms additional latency
- **Cross-region proxy:** +50-100ms additional latency

The proxy selection algorithm (§6.8.2 in Discovery & Signaling) minimizes this by preferring same-region proxies with the lowest measured latency.

### 12.4.3 MoQ Session Transparency

MoQ operates identically over a MASQUE tunnel as over a direct QUIC connection. The tunnel is transparent at the MoQ layer:

- Track namespaces are unchanged (`voip/{peer_id}/audio/opus-48k`)
- Subscribe/publish messages are sent on the QUIC stream within the HTTP/3 connection
- MoQ datagrams are sent as HTTP/3 datagrams through the CONNECT-UDP tunnel
- MoQ quality reports and feedback work identically
- MoQ priority queuing works identically (HTTP/3 respects QUIC stream priorities)

The only difference is that the underlying QUIC connection is established to the proxy rather than to the peer directly. MoQ does not know or care about this.

---

## 12.5 Proxy Authentication

### 12.5.1 TLS 1.3 Authentication

The MASQUE proxy authenticates to the client via its TLS 1.3 certificate. The client validates the certificate chain against the system trust store, exactly as a web browser would. This provides:
- Server authentication (the proxy is who it claims to be)
- Encryption (all traffic is protected by TLS 1.3)
- Integrity (tampering is detected)

### 12.5.2 Client Authentication to Proxy

The proxy does not require client authentication for basic relay functionality. This is by design:
- Requiring client authentication (API keys, tokens) would create a centralized identity system that contradicts the architecture's censorship-resistance goals.
- The proxy cannot see the MoQ media content (end-to-end encrypted by QUIC/TLS between the client and the peer).
- The proxy only sees UDP packet headers (source/destination IP:port), not the content.

However, volunteer proxies MAY implement optional client authentication for anti-abuse purposes (see §12.7).

### 12.5.3 Proxy Certificate Verification

The client verifies the proxy's TLS certificate against the system trust store. If ECH (Encrypted Client Hello) is supported by the proxy, the client uses ECH to hide the domain name from network observers. The proxy's domain appears in the DHT ProxyRecord or signaling server proxy list.

---

## 12.6 UDP-Blocked Scenario: MASQUE over HTTP/2

When UDP is entirely blocked by a firewall, standard HTTP/3 (which requires QUIC, which requires UDP) cannot be used. Instead of falling back to a separate relay mechanism, the same MASQUE CONNECT-UDP protocol runs over HTTP/2 (TCP).

### 12.6.1 Why MASQUE over HTTP/2, Not WebSocket Relay

An earlier version of this spec used a signaling server WebSocket relay for the UDP-blocked case. That approach had a critical flaw: **MoQ is Media over QUIC** — it expects a QUIC connection for both datagrams (media) and streams (control). Over a raw TCP WebSocket relay, there is no QUIC, so MoQ cannot run without a custom adaptation layer.

MASQUE over HTTP/2 solves this elegantly: the CONNECT-UDP tunnel carries QUIC packets between the peers, exactly as it does over HTTP/3. MoQ runs over that QUIC connection unchanged. The proxy relays opaque bytes — it doesn't know or care that they're QUIC packets. One relay model, two transports, MoQ always works.

| | MASQUE over HTTP/2 | WebSocket relay (rejected) |
|---|---|---|
| MoQ works? | ✅ QUIC through tunnel | ❌ No QUIC — custom adaptation needed |
| Encryption | ✅ E2E — QUIC TLS through tunnel | ❌ Unclear — no QUIC TLS |
| Relay operator | MASQUE proxy (same as HTTP/3) | Signaling server (violates "never touch media") |
| Code path | Same as HTTP/3 MASQUE | New custom relay code |
| Head-of-line blocking | Yes (TCP) | Yes (TCP) |

### 12.6.2 HTTP/2 CONNECT-UDP Mechanics (RFC 9297 §5 + RFC 9298)

RFC 9297 §5 defines HTTP Datagrams over HTTP/2 using the Capsule Protocol. Combined with RFC 9298 (CONNECT-UDP), this enables MASQUE over HTTP/2. The request format is identical to the HTTP/3 case:

```
HEADERS frame (HTTP/2):
  :method = CONNECT
  :protocol = connect-udp
  :path = /masque
  :authority = proxy.example.com:443
  connect-udp-target-host = voip-relay
  connect-udp-target-port = 0
  x-voip-call-id = <call_id>
  x-voip-peer-id = <peer_id>
```

After the proxy responds with `:status = 200`, datagrams are exchanged using HTTP/2 capsules (RFC 9297 §5):

```
DATA frame:
  Capsule type: DATAGRAM (RFC 9297 §5.1)
  Length: varint
  Quarter Stream ID: 0 (varint)
  HTTP Datagram Payload: <QUIC packet — opaque to proxy>
```

The proxy bridges datagrams between the two HTTP/2 CONNECT-UDP tunnels, exactly as it does for HTTP/3. The datagram payloads are QUIC packets — the proxy doesn't inspect or modify them. MoQ runs over the QUIC connection through the tunnel.

### 12.6.3 Dual-Stack Proxy: HTTP/3 + HTTP/2 on Port 443

The MASQUE proxy listens on port 443 and accepts both transports:

| Transport | When Used | Connection |
|-----------|----------|------------|
| HTTP/3 (QUIC/UDP) | UDP available | QUIC + TLS 1.3 (1-RTT, or 0-RTT with resumption) |
| HTTP/2 (TCP) | UDP blocked | TCP + TLS 1.3 (2-RTT handshake) |

**ALPN negotiation:** When a client connects to port 443:
- If UDP is available → QUIC handshake with ALPN `h3` → HTTP/3 CONNECT-UDP
- If UDP is blocked → TCP handshake with ALPN `h2` → HTTP/2 CONNECT-UDP

The proxy uses the same `x-voip-call-id` matching logic regardless of transport. A peer connecting via HTTP/3 can be bridged with a peer connecting via HTTP/2 — the proxy forwards datagrams between the two tunnels regardless of their transport.

**Implementation:** Most HTTP server libraries support both HTTP/3 and HTTP/2 on the same port. In Rust, the `h3` crate handles HTTP/3 and `hyper` handles HTTP/2. The proxy module routes incoming CONNECT-UDP requests to the same matching logic regardless of transport.

### 12.6.4 Client Fallback: HTTP/3 → HTTP/2

The client automatically falls back from HTTP/3 to HTTP/2 when UDP is blocked:

```rust
async fn establish_masque_tunnel(&mut self, proxy_url: &str, call_id: &str) -> Result<MasqueTunnel, MasqueError> {
    // Try HTTP/3 first (QUIC/UDP — lower latency, no HOL blocking)
    if !self.udp_blocked {
        if let Ok(tunnel) = self.try_masque_http3(proxy_url, call_id).await {
            return Ok(tunnel); // method = CONN_MASQUE
        }
    }

    // Fall back to HTTP/2 (TCP — works when UDP is blocked)
    if let Ok(tunnel) = self.try_masque_http2(proxy_url, call_id).await {
        return Ok(tunnel); // method = CONN_MASQUE_HTTP2
    }

    Err(MasqueError::AllTransportsFailed)
}
```

### 12.6.5 Head-of-Line Blocking: Honest Tradeoff

MASQUE over HTTP/2 uses TCP, which introduces head-of-line blocking. If a TCP segment is lost, all subsequent segments are delayed until retransmission. For real-time VoIP:

- **Audio:** Late packets are useless — the receiver would rather drop them than wait. TCP's reliable delivery is counterproductive for real-time media.
- **Impact:** ~20-50ms additional latency during packet loss events.
- **Mitigation:** Opus codec with Forward Error Correction (FEC) and Packet Loss Concealment (PLC) hides brief gaps. QUIC's congestion control inside the tunnel adapts to the TCP path.
- **Why it's acceptable:** This only affects the ~3% of calls where UDP is blocked. The alternative is the call not connecting at all.

### 12.6.6 Setup Latency Comparison

| Path | Setup | Additional Latency |
|------|-------|--------------------|
| Direct P2P (Three Pillars) | 1 RTT QUIC handshake | 0ms baseline |
| MASQUE over HTTP/3 | HTTP/3 handshake + CONNECT-UDP | +250-600ms |
| MASQUE over HTTP/2 | TCP + TLS 1.3 + CONNECT-UDP | +350-800ms |

The HTTP/2 path adds approximately 100-200ms over HTTP/3 due to the TCP+TLS handshake (2 RTTs) vs. the QUIC handshake (1 RTT). This is the cost of the UDP-blocked scenario.

**When this also fails (the ~1% honest failure):** If both UDP and TCP port 443 are blocked, no MASQUE tunnel can be established. Push notification retry is the only remaining option.

---

## 12.7 Anti-Abuse for Volunteer Proxy Nodes

### 12.7.1 Problem Statement

Volunteer proxy nodes relay traffic for other users. Without anti-abuse measures, a malicious actor could:

1. **Use the proxy for non-VoIP traffic** (e.g., BitTorrent, DDoS amplification)
2. **Overwhelm the proxy** with excessive concurrent sessions
3. **Use the proxy to harass** specific targets by flooding their IP

### 12.7.2 Anti-Abuse Mechanisms

| Mechanism | Description | Enforced By |
|-----------|-------------|-------------|
| **Session capacity limit** | Each proxy has a maximum concurrent session count (`masque_proxy_max_sessions`, default 10). New CONNECT-UDP requests are rejected with HTTP 503 when capacity is reached. | Proxy |
| **Session duration limit** | Maximum session duration of 4 hours. After 4 hours, the proxy closes the HTTP/3 connection. The client can re-establish a new tunnel. | Proxy |
| **Datagram rate limit** | Maximum 200 datagrams per second per session. VoIP audio at 50 pps (20ms frames) + video at 30 pps = 80 pps typical. 200 pps provides headroom while preventing flooding. | Proxy |
| **Datagram size limit** | Maximum 1280 bytes per datagram. Prevents fragmentation-based attacks and limits bandwidth usage. | Proxy |
| **Target port restriction** | Only UDP ports 1024-65535 are allowed as CONNECT-UDP targets. Well-known ports (0-1023) are rejected. | Proxy |
| **Bandwidth limit** | Maximum 500 Kbps per session (sufficient for Opus audio + VP9 video at 720p). Exceeding this triggers a graceful tunnel close. | Proxy |
| **Peer verification** | Proxy MAY require the client to present a signed timestamp from the signaling server proving the CONNECT-UDP target is a legitimate VoIP peer (not a DDoS target). | Proxy (optional) |

### 12.7.3 Peer Verification (Optional)

For volunteer proxies that want stronger anti-abuse guarantees, the following optional mechanism is defined:

1. Before establishing the MASQUE tunnel, the client requests a `ProxyToken` from the signaling server.
2. The signaling server issues a `ProxyToken` containing the target peer ID, a timestamp, and a signature.
3. The client presents the `ProxyToken` in the CONNECT-UDP request as an HTTP header.
4. The proxy validates the token with the signaling server's public key.
5. If the token is valid and not expired (TTL: 60 seconds), the proxy allows the connection.

This mechanism is optional. Proxies that do not require it accept all CONNECT-UDP requests subject to the rate and capacity limits above. Proxies that do require it reject requests without a valid token with HTTP 401.

### 12.7.4 Abuse Reporting

If a proxy operator detects abuse (e.g., traffic patterns inconsistent with VoIP), they can:
1. Close the abusive session immediately (HTTP/3 GOAWAY frame)
2. Blacklist the client's IP address (temporary, 1 hour)
3. Report the abuse to the DHT by publishing a negative reputation record for the client's node ID

Reputation records are advisory — other proxies are not required to honor them, but they may use them to adjust rate limits or reject connections from known-abusive nodes.

---

## 12.8 Volunteer Proxy Node Operation

### 12.8.1 Who Runs Proxies

- **Desktop/laptop clients** can opt in to run a MASQUE proxy node. This is a separate opt-in from the MASQUE fallback itself (which is automatic, no opt-in). Running a proxy is a conscious choice by users who want to contribute to the network.
- **Mobile clients** do NOT run proxy nodes (battery and bandwidth constraints).
- **Dedicated community servers** may run proxy nodes for reliability.

### 12.8.2 Proxy Advertisement and Certificate Provisioning

When a desktop client opts in to run a proxy:

1. The proxy module starts an HTTP/3 listener on port 443 (or any user-configured port).
2. The proxy obtains a TLS certificate using one of the following methods:
   - **Let's Encrypt (recommended):** The proxy uses ACME (RFC 8555) with HTTP-01 or DNS-01 challenge to obtain a free, trusted certificate. Requires a domain name pointing to the proxy's IP. Automated via the `rustls-acme` crate.
   - **Self-signed with DHT trust:** The proxy generates a self-signed certificate and publishes its fingerprint in the DHT ProxyRecord. Clients verify the fingerprint against the DHT record. This works without a domain name but requires DHT lookup before connection.
   - **Cloudflare Tunnel (easiest):** The proxy runs behind a Cloudflare Tunnel, which provides TLS termination and a domain name. No port forwarding required. Free tier sufficient.
3. The proxy publishes a `ProxyRecord` to the DHT with key `SHA-256("masque-proxy:{node_id}")`.
4. The proxy refreshes the DHT record every 30 minutes (before the 1-hour TTL expires).
5. The proxy un-publishes the DHT record when the user disables proxy mode or closes the application.

**Certificate method affects proxy discoverability:** Let's Encrypt and Cloudflare Tunnel proxies are reachable by any client that trusts the system CA. Self-signed proxies require DHT lookup to verify the fingerprint, which adds ~80ms but works without a domain name.

### 12.8.3 Proxy Resource Usage

| Resource | Expected Usage | Limit |
|----------|---------------|-------|
| CPU | ~2% per session (HTTP/3 framing + UDP forwarding) | 10 sessions = ~20% CPU |
| Memory | ~2 MB per session (HTTP/3 connection state) | 10 sessions = ~20 MB |
| Bandwidth | ~100 Kbps per session (Opus audio) | 10 sessions = ~1 Mbps |
| Upload bandwidth | ~500 Kbps per session (audio + video) | 10 sessions = ~5 Mbps |

These limits are configurable via `masque_proxy_max_sessions`. The default of 10 sessions is conservative — most residential broadband connections can handle this easily.

### 12.8.4 Proxy Lifecycle

```
┌───────────┐
│   OFF     │  (default — proxy not running)
└─────┬─────┘
      │ User enables proxy mode
      ▼
┌──────────────┐
│  STARTING    │──── Bind HTTP/3 listener
└─────┬────────┘     Obtain TLS certificate
      │ Ready
      ▼
┌──────────────┐
│   SERVING    │──── Accept CONNECT-UDP tunnels
└─────┬────────┘     Forward UDP datagrams
      │ User disables / app closes
      ▼
┌──────────────┐
│  SHUTTING    │──── Graceful GOAWAY to active sessions
└─────┬────────┘     Remove DHT ProxyRecord
      │ Done
      ▼
┌───────────┐
│   OFF     │
└───────────┘
```

---

## 12.9 MASQUE vs. TURN: Why MASQUE Wins

| Dimension | TURN (RFC 8656) | MASQUE CONNECT-UDP (RFC 9298) |
|-----------|-----------------|-------------------------------|
| **Censorship resistance** | Distinct protocol fingerprint (TURN allocation messages in cleartext before DTLS). Trivially blocked by DPI. | Traffic indistinguishable from HTTPS (HTTP/3 over QUIC + TLS 1.3). Cannot be blocked without blocking all HTTPS. |
| **Metadata protection** | TURN allocation requests leak peer IP addresses and port numbers in cleartext. Network observers see who is calling whom. | All metadata inside TLS 1.3. Network observers see only a connection to a web server. The proxy sees the target, but observers do not. |
| **Protocol complexity** | TURN requires its own protocol implementation (ALLOCATE, CREATE-PERMISSION, CHANNEL-BIND, REFRESH). Separate from the media transport. | MASQUE is an HTTP/3 extension. Reuses the same HTTP/3 stack used for proxy discovery. No separate protocol. |
| **Deployment** | Requires dedicated TURN servers with public IP addresses. Costly infrastructure. | Any HTTPS server can be a MASQUE proxy. Volunteer desktop nodes can run proxies. No dedicated infrastructure. |
| **Port blocking** | TURN typically uses port 3478 (UDP/TCP). Easily blocked. | MASQUE uses port 443 (HTTPS). Cannot be blocked without collateral damage to all HTTPS. |
| **NAT traversal** | TURN creates a relayed allocation — no better than MASQUE at reaching the peer. Both relay UDP. | MASQUE tunnels UDP through the proxy. Same relay capability, better censorship resistance. |
| **Cost** | $$$ per month for TURN servers | $0 (volunteer proxies + free-tier signaling server) |

**Conclusion:** TURN is strictly inferior to MASQUE on every dimension that matters for this architecture. MASQUE provides the same relay functionality with better censorship resistance, better metadata protection, lower complexity, lower cost, and better deployability.

---

## 12.10 Implementation Notes

### 12.10.1 Rust Crate: h3 + h3-quinn

The MASQUE tunnel is implemented using the `h3` and `h3-quinn` crates:

```rust
use h3::quic::SendDatagramExt;
use h3::ext::Protocol;
use h3_quinn::OpenStreams;
```

The tunnel module lives in `voip-client` as `masque_tunnel.rs`. It is responsible for:
- Proxy discovery (delegated to DHT/signaling)
- HTTP/3 connection establishment
- CONNECT-UDP request/response
- MoQ datagram forwarding through the tunnel
- Tunnel failure detection and recovery

### 12.10.2 Tunnel Module Interface

```rust
pub struct MasqueTunnel {
    proxy_url: String,
    transport: MasqueTransport,
    h3_conn: Option<h3::Connection<h3_quinn::OpenStreams, Bytes>>,      // HTTP/3
    h2_conn: Option<hyper::client::conn::http2::SendRequest<Bytes>>,    // HTTP/2
    connect_udp_stream: SendStream,
    peer_addr: SocketAddr,
}

enum MasqueTransport {
    Http3,  // QUIC/UDP — preferred when UDP is available
    Http2,  // TCP — fallback when UDP is blocked
}

impl MasqueTunnel {
    /// Establish a MASQUE CONNECT-UDP tunnel via HTTP/3 (QUIC/UDP).
    /// Preferred path — lower latency, no head-of-line blocking.
    pub async fn connect_http3(
        proxy_url: &str,
        call_id: &str,
    ) -> Result<Self, MasqueError>;

    /// Establish a MASQUE CONNECT-UDP tunnel via HTTP/2 (TCP).
    /// Fallback path — works when UDP is blocked.
    pub async fn connect_http2(
        proxy_url: &str,
        call_id: &str,
    ) -> Result<Self, MasqueError>;

    /// Send a MoQ datagram through the tunnel.
    pub async fn send_datagram(&mut self, data: Bytes) -> Result<(), MasqueError>;

    /// Receive a MoQ datagram from the tunnel.
    pub async fn recv_datagram(&mut self) -> Result<Bytes, MasqueError>;

    /// Close the tunnel gracefully.
    pub async fn close(&mut self) -> Result<(), MasqueError>;
}
```

### 12.10.3 Estimated Code Size

| Component | Lines of Rust | Description |
|-----------|--------------|-------------|
| `masque_tunnel.rs` | ~1000 | CONNECT-UDP tunnel management, HTTP/3 + HTTP/2 dual transport, proxy connection, datagram forwarding |
| `proxy_discovery.rs` | ~400 | DHT proxy lookup + signaling fallback |
| `proxy_server.rs` | ~800 | Volunteer proxy HTTP/3 + HTTP/2 dual-stack listener + CONNECT-UDP handler |
| `proxy_record.rs` | ~200 | DHT ProxyRecord signing/verification |
| **Total** | **~2400** | |

This is approximately 2.4K lines of Rust on top of the existing codebase. The `h3` and `h3-quinn` crates handle the HTTP/3 protocol mechanics, `hyper` handles the HTTP/2 protocol mechanics, so the implementation focuses on the CONNECT-UDP tunnel logic, dual-transport management, and proxy discovery.

### 12.10.4 Integration with Connection Flow

The MASQUE tunnel is integrated into the connection flow as the automatic fallback after the Three Pillars fail:

```rust
// In voip-client connection manager
async fn establish_connection(&mut self, peer: &PeerRecord) -> Result<Connection, ConnectError> {
    // Pillar 1: IPv6 direct
    if let Some(ipv6) = peer.ipv6_addresses.first() {
        if let Ok(conn) = self.try_quic_connect(ipv6).await {
            return Ok(Connection::new(conn, CONN_IPV6_DIRECT));
        }
    }

    // Pillar 2: QUIC simultaneous open (Cone NAT)
    if self.nat_info.nat_type == NAT_CONE || peer.nat_info.nat_type == NAT_CONE {
        if let Ok(conn) = self.try_simultaneous_open(&peer).await {
            return Ok(Connection::new(conn, CONN_IPV4_CONE));
        }
    }

    // Pillar 3: QUIC path probing + port prediction (Symmetric NAT)
    if let Some(prediction) = &self.nat_info.prediction {
        if prediction.confidence != RANDOM {
            if let Ok(conn) = self.try_port_prediction(&peer, prediction).await {
                return Ok(Connection::new(conn, CONN_IPV4_PREDICTION));
            }
        }
    }

    // MASQUE fallback: automatic, seamless, no user opt-in
    // Try HTTP/3 first (UDP available, lower latency)
    if !self.udp_blocked {
        if let Ok(tunnel) = MasqueTunnel::connect_http3(&proxy_url, call_id).await {
            let conn = Connection::from_masque_tunnel(tunnel);
            return Ok(Connection::new(conn, CONN_MASQUE));
        }
    }

    // UDP blocked? → MASQUE over HTTP/2 (TCP)
    if let Ok(tunnel) = MasqueTunnel::connect_http2(&proxy_url, call_id).await {
        let conn = Connection::from_masque_tunnel(tunnel);
        return Ok(Connection::new(conn, CONN_MASQUE_HTTP2));
    }

    // All methods failed — push retry
    Err(ConnectError::AllMethodsFailed)
}
```

The MASQUE fallback is automatic. The user never sees a prompt, a toggle, or a setting. If direct P2P fails, MASQUE over HTTP/3 is tried. If UDP is blocked (HTTP/3 requires QUIC over UDP), MASQUE over HTTP/2 is tried over TCP. If both fail (UDP and TCP 443 both blocked), the call fails with push retry. One relay model (MASQUE), two transports (HTTP/3 and HTTP/2), MoQ always works through the tunnel.
