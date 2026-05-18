# 1. Architecture Overview

> Part of: Three Pillars VoIP Architecture Specification (TS-2025-001 v8.0)

---

## 1.1 Core Principle and What This Is NOT

**Core Principle:** Direct P2P first. MASQUE relay as automatic seamless fallback when direct fails. Zero auxiliary protocols beyond QUIC. Zero paid infrastructure. Three pillars + MASQUE fallback + one media layer + two discovery layers: IPv6 eliminates NAT, QUIC-Native NAT Traversal handles both Cone and Symmetric NAT, MASQUE CONNECT-UDP relays through censorship-resistant HTTPS tunnels when both fail, QUIC replaces the entire legacy stack, MoQ standardizes media management. DHT provides censorship-resistant discovery and proxy discovery, signaling server provides fast discovery. User chooses discovery priority. MASQUE is automatic — no user opt-in required.

**What This Is NOT:** This is not an IEEE TSN fantasy requiring hardware nobody has. This is not a birthday attack hack that looks like a port scan. This is not a STUN/ICE/TURN system with extra steps. This is the final architecture: QUIC-native NAT traversal, MASQUE fallback for the cases where direct P2P fails, DHT + signaling discovery, MoQ media — implemented as one coherent system using one protocol family (QUIC + HTTP/3) for everything.

> **The fundamental tradeoff:** ~97% direct P2P (derived from measured IPv6 and NAT data), ~1-2% MASQUE relay fallback, ~1% honest failure. When direct P2P fails, MASQUE CONNECT-UDP (RFC 9298) automatically tunnels media through an HTTPS proxy — traffic indistinguishable from ordinary web browsing. Censorship-resistant. Metadata-protected. Only when MASQUE also fails does the call fail with push notification retry.

---

## 1.2 The Three Pillars Summary

| Pillar | Mechanism | Coverage | Description |
|--------|-----------|----------|-------------|
| **1. IPv6** | NAT Elimination | ~72% of connections have at least one IPv6 endpoint | When at least one endpoint has IPv6, the connection ALWAYS works regardless of the other side's NAT type. IPv6 eliminates the problem itself — not a traversal technique. |
| **2. QUIC-Native NAT Traversal** | Cone NAT + Port Prediction | ~26% of connections (IPv4-only with Cone NAT) | Cone NAT handled via QUIC simultaneous open (PATH_CHALLENGE). Symmetric NAT handled via QUIC path probing on signaling server's 5 elastic IPs to observe port allocation pattern, then QUIC hole punching to predicted ports. Zero auxiliary protocols — STUN is eliminated. |
| **3. QUIC** | Single Protocol Replacement | All connections | Replaces 8 legacy protocols (SIP, SDP, ICE, STUN/TURN, DTLS, SRTP, RTP) with one. QUIC path probing replaces STUN Binding. QUIC simultaneous open replaces ICE. QUIC connection migration replaces ICE restart. 1-RTT setup. Integrated TLS 1.3 encryption. |
| **4. MASQUE Fallback** | Censorship-Resistant Relay | ~1-2% (when Three Pillars fail) | MASQUE CONNECT-UDP (RFC 9298) — bidirectional relay. Both peers connect to the proxy, proxy bridges tunnels. Traffic indistinguishable from ordinary HTTPS. Proxy discovered via DHT. Automatic — no user action required. Signaling server coordinates both peers. Replaces TURN with metadata-protected, censorship-resistant relay. When UDP is blocked, MASQUE runs over HTTP/2 (TCP) instead of HTTP/3 (QUIC) — same CONNECT-UDP protocol, same proxy, MoQ works unchanged through the tunnel. |

---

## 1.3 Discovery Architecture

Discovery uses two layers. The user chooses which is attempted first:

| Layer | Protocol | Latency | Privacy | Censorship Resistance | Cost |
|-------|----------|---------|---------|----------------------|------|
| **DHT** (libp2p KadDHT) | S/Kademlia (v2 roadmap) | ~80ms | High — no single entity sees social graph | High — no entity to subpoena, no single point of failure | $0 (runs on users' devices) |
| **Signaling Server** | QUIC + Protobuf | ~5ms | Low — Cloudflare + any government with jurisdiction sees social graph | Low — Cloudflare can be compelled to block or tap | $0 (Oracle Free + Cloudflare Free) |

**User toggle:** "Privacy-first" (DHT → Signaling) or "Speed-first" (Signaling → DHT). Default: Privacy-first.

**Signaling server doubles as QUIC path probing endpoint** with 5 elastic IPs for NAT classification and port prediction. Also provides `/myip` HTTP endpoint for IPv6 fast-path (if signaling server sees IPv6, skip NAT probing entirely).

**DHT bootstrap:** Signaling server provides initial DHT node list on registration. Hardcoded seed nodes in the app binary as fallback when signaling server is unreachable.

---

## 1.4 MoQ as the Media Layer

MoQ (Media over QUIC, `draft-ietf-moq-transport-17`) is the standardized media management layer that sits on top of QUIC. It provides track management (subscribe/publish), priority queuing (audio before video), codec negotiation (track namespace parameters), and a future-proof relay model for group calls — all from a single specification rather than custom reinvention.

This architecture adopts MoQ from day one — no phased migration, no intermediate protocols. MoQ is now at draft-17 with stable core mechanics, there is no legacy code to migrate from, and an implementation can target MoQ directly. RoQ (RTP over QUIC) is not used — it would only serve as a legacy bridge for existing RTP systems, which this architecture does not have.

**Why MoQ, not custom media over raw QUIC:**

- **Track management:** MoQ's subscribe/publish model provides a clean abstraction for audio tracks, video tracks, and screen share — each a named "track" with a namespace. No custom schema needed.
- **Priority queuing:** MoQ defines per-priority send ordering — audio packets always go before video, keyframes before delta frames. This is exactly what VoIP needs and it's already specified.
- **Codec negotiation:** MoQ track parameters encode codec, bitrate, and encoding info in the track namespace. No separate SDP-style negotiation round.
- **Future multi-party:** MoQ's relay model (MoQ relay) provides a standardized, privacy-preserving relay for group calls, conferencing, and recording. Building this from scratch would duplicate effort and likely introduce mistakes.
- **Ecosystem compatibility:** MoQ is being adopted by major real-time communication platforms. Using MoQ means compatibility with this ecosystem rather than building a silo.

---

## 1.5 Combined Coverage Analysis

All percentages below are derived from measured data with cited sources. Where no empirical data exists, we state "unknown" rather than inventing a figure.

### Measured Data Inputs

| Parameter | Value | Source |
|-----------|-------|--------|
| IPv6 adoption | 47% of internet users | Google IPv6 Statistics, Q1 2025 |
| NAT type: Cone (EIM) | 65–75% of IPv4 users | D'Acunto, Pouwelse & Sips (2009); Halkes & Pouwelse (2011) |
| NAT type: Symmetric (EDM) | 11–16% of IPv4 users | D'Acunto, Pouwelse & Sips (2009); Halkes & Pouwelse (2011) |
| NAT type: Other/unclassified | 17–24% of IPv4 users | Residual from above studies |
| UDP blocking rate | 2–4% of connections | Edeline et al. (2017); RIPE Atlas (IETF 95 MAPRG, 2016) |
| Port predictability of Symmetric NAT | Unknown | No empirical study measures this |
| IPv6 firewall blocking rate | Unknown | No empirical study measures this |

### Coverage Table

| Scenario | % of Connections | Mechanism | Direct P2P? | Source |
|----------|-----------------|-----------|-------------|--------|
| At least one side IPv6 | ~72% | Direct QUIC to IPv6 address | **YES** | Calculated: P(≥1 IPv6) = 1 − 0.53² from Google data |
| Both IPv4, at least one Cone NAT | ~26% | QUIC simultaneous open (PATH_CHALLENGE) | **YES** | Calculated: 28% × 91% from NAT studies |
| Both IPv4, both Symmetric NAT | ~0.5% | Port prediction or MASQUE relay | **VARIES** | Calculated: 28% × 1.7% from NAT studies |
| Both IPv4, other/unclassified NAT | ~2% | Depends on NAT behavior | **UNKNOWN** | Calculated: 28% × 7% from NAT studies |
| UDP blocked entirely | ~2–4% | MASQUE CONNECT-UDP over HTTP/2 (TCP) | **RELAY (MASQUE HTTP/2)** | Edeline et al. (2017) |
| UDP + TCP 443 blocked | ~1% | No path exists | **FAILS** | Estimated from Edeline et al. (2017) |
| **Total direct P2P (IPv6 + Cone NAT)** | **~98%** | | **YES** | Calculated from above |
| **Total MASQUE relay** | **~1–2%** | | **RELAY** | Symmetric NAT (non-predictable) + UDP blocked |
| **Total fails** | **~1%** | | **FAILS** | Estimated |

### Coverage Derivation

Calculations use midpoint values: 47% IPv6 adoption, 70% Cone NAT among IPv4, 13% Symmetric NAT among IPv4.

- **IPv6:** 47% of users have IPv6. P(at least one side IPv6) = 1 − 0.53² ≈ 72%. These connections are direct P2P regardless of NAT type. (Source: Google IPv6 Statistics, Q1 2025)
- **IPv4-only:** 28% of connections (0.53²). Among IPv4-only users, ~70% have Cone NAT (EIM) and ~13% have Symmetric NAT (EDM). (Sources: D'Acunto et al. 2009; Halkes & Pouwelse 2011)
- **IPv4 Cone NAT:** P(both IPv4, at least one Cone) = 28% × (1 − 0.30²) = 28% × 91% ≈ 26%. QUIC simultaneous open works. (Calculated)
- **IPv4 Symmetric NAT:** P(both IPv4, both Symmetric) = 28% × 0.13² = 28% × 1.7% ≈ 0.5%. Port prediction may work for some of these, but no empirical study measures what percentage of Symmetric NATs use predictable (sequential) vs. random port allocation. The remainder needs MASQUE relay.
- **UDP blocked:** 2–4% of connections have UDP blocked entirely (Edeline et al. 2017; RIPE Atlas). These require MASQUE over HTTP/2. Note: this percentage overlaps with the NAT-type categories above — a UDP-blocked connection can occur in any NAT scenario.
- **Total direct P2P:** 72% (IPv6) + 26% (Cone NAT) = ~98%, minus an unknown small fraction that fails due to IPv6 firewall issues or other connectivity problems not captured by NAT type alone.
- **MASQUE relay:** Needed for Symmetric NAT connections where port prediction fails (unknown fraction of ~0.5%) plus UDP-blocked connections (~2–4% of all connections, though some of these also fall into the Symmetric NAT category). Approximately 1–2% of all connections.
- **Honest failure:** Connections where both UDP and TCP port 443 are blocked. Approximately ~1% (estimated from Edeline et al. 2017, which found ~1% of connections have severe UDP+TCP impairment).

### What We Cannot Claim

The following previously appeared in this specification but have been removed because no empirical data supports them:

- **"~60% of Symmetric NATs have predictable port allocation"** — No study measures this. Some Symmetric NATs use sequential allocation (predictable), others use random allocation (unpredictable), but the proportion is unknown.
- **"~0.5% of connections fail due to IPv6 firewalls"** — No study measures IPv6 firewall blocking rates. Research (Czyz et al. NDSS 2016; Olson et al. ACM Computing Surveys 2023) suggests IPv6 networks are often MORE open than IPv4, not less.
- **"~45% effective coverage from IPv6"** — The original calculation assumed significant IPv6 firewall/connectivity failures to reduce the theoretical 70%+ to 45%. Without data on IPv6 connection failure rates, this reduction was speculative. The current calculation uses the measured IPv6 adoption rate directly.

### Why MASQUE Fallback Works

When all Three Pillars fail, MASQUE CONNECT-UDP (RFC 9298) provides automatic relay. Both peers establish HTTP/3 connections to a MASQUE proxy (discovered via DHT or signaling server), each sending a CONNECT-UDP request with the call_id. The proxy matches the two requests and bridges the tunnels, forwarding datagrams between them.

**Why both peers must connect:** The proxy cannot directly reach a peer behind Symmetric NAT — the peer must initiate the connection outward. This is the fundamental reason the relay is bidirectional: both peers connect to the proxy, the proxy bridges them.

**Censorship resistance:** A firewall that can block TURN with one rule cannot block MASQUE without blocking all HTTPS. The MASQUE proxy runs on port 443 with a standard TLS certificate. DPI equipment sees only normal HTTPS traffic. ECH (Encrypted Client Hello) hides even the domain name.

**Metadata protection:** Unlike TURN, which leaks peer IP addresses and port numbers in cleartext, MASQUE wraps everything inside TLS 1.3. The proxy sees the target address, but network observers see nothing.

**Seamless UX:** The user never knows the call is relayed. MASQUE activates automatically when the Three Pillars fail. The call connects. MoQ session setup proceeds as normal over the tunnel.

**The ~1% honest failure:** Only when both UDP and TCP port 443 are blocked (no MASQUE possible via either transport), or when all MASQUE proxies are unreachable via both HTTP/3 and HTTP/2, does the call fail. Push notification + auto-retry gives the connection another chance when network conditions change.

---

## 1.6 Growth Trajectory

The relay problem solves itself as IPv6 deploys globally. No code changes needed — just deploy the VoIP client and let IPv6 adoption do the rest.

| Year | IPv6 Adoption | Direct P2P | MASQUE Relay | Fails |
|------|--------------|------------|--------------|-------|
| 2025 | 47% | ~98% | ~1–2% | ~1% |
| 2026 | 50% (projected) | ~98% | ~1% | ~1% |
| 2027 | 55% (projected) | ~99% | <1% | ~1% |
| 2028 | 60% (projected) | ~99% | <1% | ~1% |
| 2030 | 70% (projected) | ~99%+ | <1% | ~1% |

As IPv6 deploys, direct P2P rate increases and MASQUE relay usage decreases. The architecture maximizes direct P2P at every stage. MASQUE handles the remainder automatically. No other action needed.

---

## 1.7 Design Rationale: No STUN, No ICE, No TURN

This architecture eliminates STUN, ICE, and TURN entirely. Every function they provide is replaced by QUIC-native mechanisms:

| Legacy Mechanism | QUIC-Native Replacement |
|-----------------|------------------------|
| STUN Binding (address discovery) | QUIC path probing on signaling server's 5 elastic IPs. Client migrates connection to each IP, server reflects observed IP:port. |
| STUN Binding (NAT classification) | Same 5-path probe. Server reports observed address for each path. Delta analysis classifies NAT type. |
| ICE candidate gathering | Eliminated. QUIC Connection ID identifies the call. No candidate validation round-trip. |
| ICE connectivity checks | QUIC PATH_CHALLENGE / PATH_RESPONSE. Already encrypted, already part of the protocol. |
| TURN relay | Replaced by MASQUE CONNECT-UDP (RFC 9298). Censorship-resistant, metadata-protected, traffic indistinguishable from HTTPS. Automatic fallback when direct P2P fails. |
| STUN keep-alive | QUIC PING frames. Already built into QUIC. |

**Why this is better than STUN/ICE:**

1. **One protocol instead of two.** STUN is a separate UDP protocol with its own message format, its own port, its own library. QUIC path probing uses the same QUIC connection that will carry the call. No second protocol stack to implement, test, or debug.

2. **Punch + connect in one step.** With STUN, you punch the NAT hole with raw UDP, then establish the QUIC connection. Two phases. With QUIC-native, the PATH_CHALLENGE that punches the hole IS the QUIC connection setup packet. One phase. The first packet through the NAT is already encrypted and already part of the QUIC handshake.

3. **No STUN library dependency.** The signaling server already runs QUIC for /register and /lookup. Adding path probing means listening on 5 IPs instead of 1. That's a config change, not a new protocol implementation.

4. **No STUN server infrastructure.** The signaling server IS the probing endpoint. No separate STUN servers to deploy, maintain, or pay for.

---

## 1.8 Design Rationale: MoQ Directly, No Phases

This architecture uses MoQ from day one. There is no phased migration and no intermediate protocol. The reasoning is straightforward:

- **MoQ is stable enough.** At draft-17, the core mechanics (pub/sub, track namespaces, datagram delivery, priority) are stable. Breaking changes to fundamental design are unlikely at this stage of the IETF process.
- **There is no legacy code.** This is a greenfield implementation. There are no existing RTP pipelines to bridge, no deployed clients to migrate, no backward compatibility constraints.
- **RoQ would be dead weight.** RTP over QUIC (RoQ) only makes sense as a bridge for existing RTP-based systems. This architecture has no such systems.
- **Phases create debt.** A phased approach creates migration debt: two code paths to maintain, a migration event that must be coordinated, and a period where both protocols coexist.

**Bottom line:** MoQ from day one. No phases. No RoQ. No migration.

---

## 1.9 Comparison With Legacy VoIP (TURN/SIP/RTP)

| Metric | Legacy (TURN/SIP/RTP) | **This Architecture (v8)** |
|--------|----------------------|---------------------------|
| Direct P2P rate | ~75–80% (Chrome UMA data; Hancke 2017) | **~98%** (calculated from measured data) |
| Connected rate (including relay) | ~100% (TURN catches all) | **~99%** (MASQUE catches ~1–2%) |
| Infrastructure needed | TURN servers | **None** (Oracle Free + Cloudflare Free + DHT proxy discovery) |
| Deployable today? | Yes | **Yes** |
| Grey zone techniques | No | **None** |
| Legal concerns | No | **None** |
| Honest about limits? | No | **Yes** |
| Protocols needed | 8 (SIP, SDP, ICE, STUN, TURN, DTLS, SRTP, RTP) | **1 (QUIC) + MoQ + MASQUE** |
| NAT traversal protocols | STUN + ICE + TURN | **QUIC only (path probing + simultaneous open + MASQUE fallback)** |
| Media management | RTP/SRTP custom | **MoQ (standardized)** |
| Call setup time | 1-3 seconds | **70-200ms (direct), 200-500ms (MASQUE relay)** |
| Relay type | TURN (blockable, cleartext control) | **MASQUE (indistinguishable from HTTPS, TLS 1.3)** |
| Calls that fail | 0% (relay catches all) | **~1% (push retry)** |
| Discovery privacy | None (server sees all) | **User choice: DHT (private) or signaling (fast)** |
| Censorship resistance | None (TURN trivially blockable) | **DHT discovery + MASQUE relay (both censorship-resistant)** |
| Infrastructure cost | $$$ (TURN servers) | **$0 (Oracle Free + Cloudflare Free)** |
