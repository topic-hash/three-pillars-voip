# 4. Pillar 3: QUIC — The Single Protocol That Replaces Everything

> Part of: Three Pillars VoIP Minimal-Relay Architecture Specification (TS-2025-001 v8.0)  
> See also: [Architecture Overview](01_Architecture_Overview.md) | [Media Layer: MoQ](05_Media_Layer_MoQ.md) | [API: QUIC Connection Management](08_API_Specification.md)

---

## 4.1 The Problem

The legacy VoIP stack requires 8 separate protocols, each with its own state machine, library, and bugs:

```
SIP → SDP → ICE → STUN → TURN → DTLS → SRTP → RTP
8 libraries, 8 state machines, 5-15 RTTs for setup, relay for 20-30% of calls
```

---

## 4.2 The 8-to-1 Replacement

QUIC (RFC 9000/9001/9002) integrates transport, encryption, multiplexing, and connection management into a single protocol. Combined with Pillar 1 (IPv6) and Pillar 2 (QUIC-Native NAT Traversal), it replaces the entire legacy stack:

| Legacy Protocol | QUIC Replacement | How |
|-----------------|------------------|-----|
| SIP/SDP | Binary signaling on QUIC stream | Protocol Buffers, <500 bytes vs 2-5KB SIP |
| RTP | QUIC datagrams (RFC 9221) | Same media, better congestion control |
| RTCP | QUIC stream (reliable) | Reports arrive reliably, no repetition needed |
| SRTP | TLS 1.3 (integrated in QUIC) | No separate crypto layer |
| DTLS | TLS 1.3 (integrated in QUIC) | Handshake is part of QUIC, 0 extra RTTs |
| STUN Binding | QUIC path probing (Pillar 2) | Connection migration to 5 server IPs reveals observed address |
| ICE | QUIC simultaneous open + port prediction (Pillar 2) | No candidate gathering phase |
| TURN | MASQUE CONNECT-UDP (RFC 9298) | MASQUE over HTTP/3 when UDP available, over HTTP/2 when UDP blocked. Both automatic, no user opt-in. Same CONNECT-UDP protocol, same proxy. |

**Result: One protocol (QUIC), one library, one API. Zero auxiliary protocols.**

---

## 4.3 QUIC Connection ID: The Enabler for Port Prediction

The QUIC Connection ID is the critical feature that makes port prediction practical. In the legacy ICE model:

```
ICE model:
  A sends a binding request to B's predicted address
  B receives it but doesn't know if it's from A or an attacker
  B must check with the signaling server: "is this candidate valid?"
  1 extra RTT through signaling server before B can respond

QUIC model:
  A sends a QUIC packet to B's predicted address range
  The packet carries the Connection ID for this call
  B sees the Connection ID and immediately knows: "this is A's packet"
  B responds directly to A's source address
  0 extra RTTs through signaling server
```

The Connection ID eliminates the signaling round-trip that ICE requires for candidate validation. This means:

- Port prediction probing is faster (no waiting for signaling confirmation)
- More prediction attempts can be made in the same time window
- The connection is validated in a single packet exchange
- No separate STUN binding request/response cycle needed — the QUIC packet IS the probe

---

## 4.4 QUIC Connection Migration: Surviving Network Changes

When a mobile user switches from WiFi to cellular:

- **Legacy:** ICE restart → 2-5 seconds of re-gathering candidates, re-exchanging SDP, re-testing connectivity. Call often drops.
- **QUIC:** Connection migration → 1 RTT (PATH_CHALLENGE/PATH_RESPONSE on new address). Call continues uninterrupted. The Connection ID identifies the packets as belonging to the existing connection, regardless of the new IP address.

This is particularly powerful combined with Pillar 1 (IPv6): when the mobile user moves to a new WiFi network, they may get a new IPv6 prefix. QUIC connection migration handles this transparently — no ICE restart, no call drop, no re-probing of NAT behavior.

For IPv4, after connection migration to a new network, the client re-probes its NAT via QUIC path probing (Pillar 2, Steps 1-3) and signals the new predicted range to the peer through the existing QUIC connection (which is still alive on the old path during migration).

---

## 4.5 QUIC Hole Punching: One-Step NAT Traversal

This is the key innovation that eliminates STUN as a separate protocol. In the legacy approach, NAT hole punching and connection setup are two separate phases:

```
Legacy (STUN + QUIC):
  Phase 1: STUN Binding → learn addresses
  Phase 2: Exchange addresses via signaling
  Phase 3: Raw UDP hole punch (unencrypted)
  Phase 4: QUIC handshake on the now-open path
  Total: 2-4 phases, 2+ RTTs after signaling

QUIC-Native:
  Phase 1: QUIC path probing → learn addresses (same QUIC connection)
  Phase 2: Exchange addresses via signaling or DHT
  Phase 3: QUIC PATH_CHALLENGE → punch + connect in one step
  Total: 1 phase after signaling, the hole-punch packet IS the QUIC connection
```

The PATH_CHALLENGE packet that punches through the NAT is already encrypted by TLS 1.3 and already carries the Connection ID. When it arrives at the peer, the peer immediately knows which call this belongs to and can respond with PATH_RESPONSE. No separate "punch then connect" phases.

---

## 4.6 QUIC 1-RTT Setup: Call Setup in 70-200ms

Legacy VoIP call setup:

```
SIP INVITE (1 RTT) → 100 Trying
SDP offer/answer (1-2 RTTs)
ICE gathering (5-30 seconds, can be parallelized to ~1-2 seconds)
DTLS handshake (2 RTTs)
SRTP key derivation (0 RTTs, part of DTLS)
First media packet

Total: 1000-3000ms typical
```

QUIC call setup:

```
QUIC handshake + TLS 1.3 (1 RTT) → connection established, encryption active
Binary signaling on QUIC stream (0 extra RTTs, pipelined with handshake)
First media datagram (0 extra RTTs, sent immediately after signaling)

Total: 70-200ms (1 RTT)
```

For reconnections (0-RTT QUIC):

```
QUIC 0-RTT resumption → 0 RTTs for handshake
First media datagram included in 0-RTT data

Total: 35-100ms (0 RTTs, one-way latency only)
```

---

## 4.7 QUIC Datagram Reliability for Voice

QUIC datagrams (RFC 9221) provide unreliable, unordered delivery — exactly what VoIP needs. Unlike RTP over UDP, QUIC datagrams benefit from:

- **Congestion control awareness:** The QUIC sender knows when the path is congested and can adapt the Opus codec bitrate proactively, rather than discovering congestion via RTCP receiver reports (which arrive 100-500ms late in the legacy stack).
- **Connection-level multiplexing:** Signaling, RTCP-like reports, and media all share one connection. No head-of-line blocking between streams (QUIC streams are independent), but shared congestion control prevents media from starving signaling.
- **Encryption by default:** Every QUIC packet is encrypted with TLS 1.3. No separate SRTP key negotiation. No DTLS handshake. Encryption is established as part of the QUIC handshake.

---

## 4.8 Performance Claims with Evidence

**Claim: QUIC setup is 5-15x faster than SIP/RTP/ICE.**
- Evidence: Min and Lee (IEEE VTC2024-Fall, 2024) measure 37% reduction in call setup latency with VoIP over QUIC. QUIC 1-RTT handshake (70-200ms) vs. legacy 5-15 RTT stack (1000-3000ms).

**Claim: QUIC connection migration eliminates the 2-5 second ICE restart.**
- Evidence: Liang et al. (IEEE VTC2024-Fall, 2024) confirm 2-3 RTT savings. QUIC migration: 1 RTT (70-200ms) vs. ICE restart: 2000-5000ms.

**Claim: QUIC hole punching replaces STUN hole punching with no loss of functionality.**
- Evidence: QUIC PATH_CHALLENGE/PATH_RESPONSE (RFC 9000 §9) provides the same address-reflection capability as STUN Binding. The first QUIC packet through the NAT is already encrypted and connection-validated, unlike raw UDP hole-punching packets.
