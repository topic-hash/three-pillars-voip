# 9. Data Flows

> Part of: Three Pillars VoIP Minimal-Relay Architecture Specification (TS-2025-001 v8.0)

---

## 9.1 IPv6 Direct Connection

(Same as v6.0. Steps 1-10 unchanged. ~250ms total.)

---

## 9.2 IPv4 Cone NAT Connection (QUIC Simultaneous Open)

**Precondition:** Both peers IPv4-only, at least one behind Cone NAT.

```
Peer A (Cone NAT)           Signaling Server            Peer B (any NAT)
  │                               │                           │
  │ 1. QUIC path probe:           │                           │
  │    Migrate to IP_1..IP_5      │                           │
  │◀── "I see you as 203.0.113.5:42000"                       │
  │    (Same address on all 5     │                           │
  │     = Cone NAT confirmed)     │                           │
  │                               │                           │
  │ 2. CallRequest                │                           │
  │   {ipv4: ["203.0.113.5:42000"],│                          │
  │    nat: CONE, tracks: [...]}  │                           │
  │──────────────────────────────▶│                           │
  │                               │ 3. CallRequest (forwarded) │
  │                               │──────────────────────────▶│
  │                               │                           │
  │                               │ 4. CallAccept              │
  │                               │◀──────────────────────────│
  │ 5. CallAccept (forwarded)     │                           │
  │◀──────────────────────────────│                           │
  │                               │                           │
  │ 6. QUIC PATH_CHALLENGE ─────────────────────────────────▶│
  │    to B's reflexive address   │                           │
  │    (Cone NAT: address valid   │                           │
  │     for all destinations)     │                           │
  │                               │                           │
  │ ◀─────────────────────────────────────────────────────── │
  │    QUIC PATH_CHALLENGE from B │                           │
  │                               │                           │
  │ 7. QUIC + MoQ setup + Media   │                           │
  │◀────────────────────────────────────────────────────────▶│
```

**Timing:** Steps 1: ~50ms (QUIC path probing, pre-cached). Steps 2-5: ~100ms. Steps 6-7: ~100ms. **Total: ~250ms.**

---

## 9.3 IPv4 Symmetric NAT Connection (QUIC Path Probing + Port Prediction)

**Precondition:** Both peers IPv4-only, both behind Symmetric NAT with sequential allocation.

```
Peer A (Symmetric NAT)     Signaling Server      Peer B (Symmetric NAT)
  │                               │                           │
  │ 1. QUIC path probing:         │                           │
  │    Migrate to IP_1..IP_5      │                           │
  │    (from same local port 5000)│                           │
  │◀── 42000, 42001, 42002,      │                           │
  │    42003, 42004               │                           │
  │                               │                           │
  │ 2. ANALYZE: delta = +1        │                           │
  │    PREDICT: ~42005 ± 3        │                           │
  │    Range: 42002-42008         │                           │
  │                               │                           │
  │ 3. CallRequest                │                           │
  │   {ipv4: ["203.0.113.5"],     │                           │
  │    prediction: {              │                           │
  │      start: 42002, end: 42008,│                           │
  │      confidence: SEQUENTIAL,  │                           │
  │      probe_method: QUIC_PATH_PROBING},                    │
  │    tracks: [...]}             │                           │
  │──────────────────────────────▶│                           │
  │                               │ 4. CallRequest (forwarded) │
  │                               │──────────────────────────▶│
  │                               │ 5. CallAccept              │
  │                               │◀──────────────────────────│
  │ 6. CallAccept (forwarded)     │                           │
  │◀──────────────────────────────│                           │
  │                               │                           │
  │ 7. QUIC PATH_CHALLENGE to     │                           │
  │    B's predicted range         │                           │
  │    (7 packets: 31004-31010,   │                           │
  │     Connection ID embedded)    │                           │
  │──────────────────────────────────────────────────────────▶│
  │                               │                           │
  │                               │ 8. QUIC PATH_CHALLENGE to  │
  │                               │    A's predicted range      │
  │◀──────────────────────────────────────────────────────────│
  │                               │                           │
  │ 9. NAT match! Connection ID   │                           │
  │    validates. PATH_RESPONSE   │                           │
  │    sent. Hole punched AND     │                           │
  │    connection established     │                           │
  │    in ONE step.               │                           │
  │                               │                           │
  │ 10. MoQ setup. Media flows.   │                           │
  │◀────────────────────────────────────────────────────────▶│
```

**Timing:** Steps 1-2: ~50ms (QUIC path probing, pre-cached). Steps 3-6: ~100ms. Steps 7-9: ~100-200ms. **Total: ~300-400ms.**

---

## 9.4 Call Failure + Push Retry Flow

**Precondition:** Both peers IPv4-only, both behind Symmetric NAT with random allocation.

```
Peer A (Symmetric Random)   Signaling Server      Peer B (Symmetric Random)
  │                               │                           │
  │ 1. QUIC path probing: Random  │                           │
  │    (no pattern detected)       │                           │
  │                               │                           │
  │ 2. CallRequest                │                           │
  │   {nat: SYMMETRIC_RANDOM,     │                           │
  │    prediction: null}           │                           │
  │──────────────────────────────▶│                           │
  │                               │ 3. CallRequest (forwarded) │
  │                               │──────────────────────────▶│
  │                               │ 4. CallAccept              │
  │                               │◀──────────────────────────│
  │                               │                           │
  │ 5. Both RANDOM. Attempt basic │                           │
  │    QUIC simultaneous open     │                           │
  │    (will fail).               │                           │
  │                               │                           │
  │ 6. Timeout (10s)              │                           │
  │                               │                           │
  │ 7. CallFailed                 │                           │
  │   {reason: END_FAILED_IPV4_RANDOM}                        │
  │◀──────────────────────────────│──────────────────────────▶│
  │                               │                           │
  │ 7a. MASQUE fallback attempt   │                           │
  │ 7b. Signaling server detects  │                           │
  │     MASQUE needed (both       │                           │
  │     RANDOM)                   │                           │
  │ 7c. Server sends              │                           │
  │     MasqueRelayNeeded to      │                           │
  │     BOTH peers                │                           │
  │ 7d. Both peers connect to     │                           │
  │     MASQUE proxy via HTTP/3   │                           │
  │ 7e. Both send CONNECT-UDP     │                           │
  │     with same call_id         │                           │
  │ 7f. Proxy matches and bridges │                           │
  │     → tunnel MoQ,             │                           │
  │       method = CONN_MASQUE    │                           │
  │ 7g. If proxy unreachable      │                           │
  │     → try next proxy          │                           │
  │ 7h. If UDP blocked            │                           │
  │     → MASQUE over HTTP/2       │                           │
  │     (see §9.11)               │                           │
  │ 7i. If MASQUE fails via        │                           │
  │     both HTTP/3 and HTTP/2    │                           │
  │     → continue to PushRetry   │                           │
  │                               │                           │
  │ 8. PushRetry via FCM          │                           │
  │                               │──────────────────────────▶│
  │   "Alice tried to call you.   │                           │
  │    Tap to retry."             │                           │
  │                               │                           │
  │ 9. B taps retry (or auto-     │                           │
  │    retries on network change) │                           │
  │                               │                           │
  │ 10. B re-probes NAT, retries  │                           │
  │     connection to A           │                           │
  │◀──────────────────────────────│──────────────────────────▶│
```

---

## 9.5 DHT Discovery Flow

```
Peer A (caller)            DHT Network             Peer B (callee)
  │                           │                           │
  │ 1. DHT lookup:            │                           │
  │    SHA-256("voip:bob")    │                           │
  │──────────────────────────▶│                           │
  │                           │ Recursive lookup          │
  │                           │ through k nodes           │
  │                           │ (~80ms total)             │
  │◀──────────────────────────│                           │
  │ 2. PeerRecord for B:      │                           │
  │    {ipv6, ipv4, nat_type, │                           │
  │     prediction, tracks}   │                           │
  │    (signed by B's key)    │                           │
  │                           │                           │
  │ 3. Verify signature       │                           │
  │                           │                           │
  │ 4. Proceed with direct    │                           │
  │    QUIC connection        │                           │
  │───────────────────────────────────────────────────────▶│
```

**Fallback:** If DHT lookup fails (timeout 200ms), fall back to signaling server.

---

## 9.6 Network Migration Flow

(Same as v6.0 but re-probes via QUIC path probing instead of STUN.)

---

## 9.7 Call Rejection Flow

(Same as v6.0. No changes.)

---

## 9.8 MoQ Session Setup Flow

(Same as v6.0. No changes.)

---

## 9.9 Coverage Flow Decision Tree

```
START: Place/receive call
  │
  ├── A has IPv6 AND B has IPv6?
  │     └── YES → IPv6 Direct
  │
  ├── A has IPv6 OR B has IPv6?
  │     └── YES → IPv6 + IPv4 mixed
  │
  ├── At least one has Cone NAT?
  │     └── YES → QUIC simultaneous open
  │
  ├── Both have sequential/pseudo Symmetric NAT?
  │     └── YES → QUIC path probing + port prediction
  │
  ├── One has sequential, other has random?
  │     └── One-side prediction + probing (PARTIAL ~60%)
  │
  ├── Both have random Symmetric NAT?
  │     └── MASQUE CONNECT-UDP relay → if proxy reachable, CONNECTED
  │
  ├── UDP blocked?
  │     └── MASQUE over HTTP/2 (TCP, RFC 9297 §5) → if proxy reachable via TCP, CONNECTED
  │
  └── All paths failed including MASQUE over HTTP/3 and HTTP/2?
        └── Call Failure + Push Retry
```

---

## 9.10 MASQUE Fallback Flow (Bidirectional)

Both peers establish CONNECT-UDP tunnels to the same proxy. The proxy bridges datagrams between them. This is necessary because the proxy cannot directly reach a peer behind Symmetric NAT.

```
Peer A (random Sym. NAT)  Signaling Server  MASQUE Proxy  Peer B (random Sym. NAT)
  │                            │                  │                    │
  │ 1. CallRequest              │                  │                    │
  │   {nat: SYMMETRIC_RANDOM}   │                  │                    │
  │───────────────────────────▶│                  │                    │
  │                            │ 2. CallRequest   │                    │
  │                            │─────────────────────────────────────▶│
  │                            │                  │                    │
  │                            │ 3. CallAccept    │                    │
  │                            │◀─────────────────────────────────────│
  │ 4. CallAccept (forwarded)  │                  │                    │
  │◀───────────────────────────│                  │                    │
  │                            │                  │                    │
  │ 5. Both try direct P2P     │                  │                    │
  │    (fails — both random)   │                  │                    │
  │                            │                  │                    │
  │ 6. Server detects MASQUE   │                  │                    │
  │    needed (both RANDOM)    │                  │                    │
  │                            │                  │                    │
  │ 7. MasqueRelayNeeded       │                  │                    │
  │   {call_id, proxy_url}     │                  │                    │
  │◀───────────────────────────│─────────────────────────────────────▶│
  │                            │                  │                    │
  │ 8. HTTP/3 + TLS 1.3 to    │                  │ 8. HTTP/3 + TLS   │
  │    proxy                   │                  │     1.3 to proxy  │
  │────────────────────────────────────────────▶│◀───────────────────│
  │                            │                  │                    │
  │ 9. CONNECT-UDP             │                  │ 9. CONNECT-UDP    │
  │   {call_id, peer_A}        │                  │   {call_id, peer_B}│
  │────────────────────────────────────────────▶│◀───────────────────│
  │                            │                  │                    │
  │                            │     10. Proxy matches by call_id      │
  │                            │     Bridges the two tunnels          │
  │                            │                  │                    │
  │ 11. Proxy 200 OK both      │                  │                    │
  │◀────────────────────────────────────────────│───────────────────▶│
  │                            │                  │                    │
  │ 12. MoQ session through    │                  │ 12. MoQ session   │
  │     MASQUE tunnel          │                  │     through tunnel │
  │◀────────────────────────────────────────────────────────────────▶│
  │     MoQ media flows (proxy bridges datagrams, end-to-end encrypted)
  │                            │                  │                    │
```

---

## 9.11 MASQUE over HTTP/2 Flow (UDP Blocked)

When UDP is entirely blocked by a firewall, QUIC (and therefore HTTP/3) cannot be used. Both peers fall back to MASQUE over HTTP/2 (TCP), connecting to the same proxy on port 443. The CONNECT-UDP protocol is identical — only the transport changes from HTTP/3 (QUIC/UDP) to HTTP/2 (TCP). MoQ runs over the QUIC connection through the tunnel, unchanged.

```
Peer A (UDP blocked)      MASQUE Proxy       Peer B (UDP blocked)
  │                            │                       │
  │ 1. TCP + TLS 1.3 to proxy  │                       │
  │───────────────────────────▶│                       │
  │                            │    2. TCP + TLS 1.3   │
  │                            │◀──────────────────────│
  │                            │                       │
  │ 3. CONNECT-UDP on HTTP/2   │                       │
  │   {call_id, peer_A}        │                       │
  │───────────────────────────▶│                       │
  │                            │ 4. CONNECT-UDP on    │
  │                            │    HTTP/2             │
  │                            │    {call_id, peer_B}  │
  │                            │◀──────────────────────│
  │                            │                       │
  │                            │ 5. Proxy matches by   │
  │                            │    call_id, bridges   │
  │                            │    the two tunnels    │
  │                            │                       │
  │ 6. Proxy 200 OK both       │                       │
  │◀──────────────────────────│──────────────────────▶│
  │                            │                       │
  │ 7. MoQ session through     │    MoQ session through│
  │    MASQUE tunnel           │    tunnel             │
  │◀────────────────────────────────────────────────▶│
  │   QUIC packets flow as HTTP/2 capsules (RFC 9297 §5)
  │   MoQ works unchanged — same code path as HTTP/3 MASQUE
  │   method = CONN_MASQUE_HTTP2                    │
  │                            │                       │
```

**Key properties:**
- Same CONNECT-UDP protocol as HTTP/3 MASQUE — only the transport changes.
- MoQ runs over QUIC through the tunnel — same code path, no adaptation layer.
- End-to-end encrypted by QUIC TLS through the tunnel — the proxy sees only opaque QUIC packets.
- TCP head-of-line blocking adds ~20-50ms latency during packet loss events. Opus FEC/PLC mitigates this.
- Setup takes ~350-800ms (2 RTT for TCP+TLS vs 1 RTT for QUIC) — the cost of the UDP-blocked scenario.
- The proxy bridges HTTP/3 and HTTP/2 tunnels interchangeably — one peer can use HTTP/3 while the other uses HTTP/2.
- If both UDP and TCP port 443 are blocked, no MASQUE tunnel is possible. Push retry is the only option.
