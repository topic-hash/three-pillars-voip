# Three Pillars VoIP

**Minimal-relay VoIP architecture — ~91% direct P2P, ~8% MASQUE fallback, ~1% honest failure.**

Built in Rust on QUIC + MoQ + MASQUE. No STUN. No ICE. No TURN.

---

## What Is This?

Three Pillars VoIP is a VoIP system that maximizes direct peer-to-peer connections and minimizes relay dependency. When direct P2P fails, MASQUE CONNECT-UDP (RFC 9298) automatically tunnels media through HTTPS proxies — traffic indistinguishable from ordinary web browsing. No user action required. No TURN servers. No metadata leaks.

### The Three Pillars

| Pillar | Mechanism | Coverage |
|--------|-----------|----------|
| **1. IPv6** | NAT elimination | ~45% of connections |
| **2. QUIC-Native NAT Traversal** | Simultaneous open (Cone NAT) + port prediction (Symmetric NAT) | ~46% of connections |
| **3. QUIC + MoQ** | Single protocol replaces SIP, SDP, ICE, STUN/TURN, DTLS, SRTP, RTP | All connections |

### Fallback Chain

When all three pillars fail (~8% of connections), the system falls back automatically:

```
IPv6 Direct → QUIC Simultaneous Open → QUIC Port Prediction → MASQUE/HTTP3 → MASQUE/HTTP2 → Push Retry
```

MASQUE CONNECT-UDP runs over HTTP/3 (QUIC) when UDP is available, or over HTTP/2 (TCP) when UDP is blocked. Same CONNECT-UDP protocol, same proxy, MoQ works unchanged through both tunnel types.

### Coverage Breakdown

| Scenario | % of Connections | Path |
|----------|-----------------|------|
| IPv6 (one or both sides) | ~45% | Direct P2P |
| IPv4 Cone NAT | ~31% | QUIC simultaneous open |
| IPv4 Symmetric NAT (sequential) | ~13% | QUIC port prediction |
| IPv4 Symmetric NAT (random) + UDP blocked | ~8% | MASQUE relay |
| UDP + TCP 443 blocked | ~1% | Honest failure + push retry |
| **Total direct P2P** | **~91%** | |
| **Total connected (incl. MASQUE)** | **~99%** | |

---

## Architecture Highlights

- **No STUN.** QUIC path probing replaces STUN Binding for NAT classification and address discovery. The signaling server reflects observed addresses over the same QUIC connection used for registration — no separate protocol, no separate port.

- **No ICE.** QUIC simultaneous open (PATH_CHALLENGE / PATH_RESPONSE) replaces ICE connectivity checks. QUIC connection migration replaces ICE restart. No candidate gathering phase.

- **No TURN.** MASQUE CONNECT-UDP replaces TURN as the relay mechanism. MASQUE traffic is TLS 1.3 encrypted and runs on port 443 — firewalls that block TURN with one rule cannot block MASQUE without blocking all HTTPS.

- **No RTP/SRTP.** MoQ (Media over QUIC, draft-17) replaces the entire RTP stack. Track-based pub/sub, priority queuing, codec negotiation via track namespace parameters. No SDP.

- **Censorship-resistant relay.** MASQUE proxies are discovered via DHT (libp2p KadDHT). Volunteer desktop nodes run proxies on port 443 with Let's Encrypt certs. No centralized relay infrastructure. DPI equipment sees only normal HTTPS traffic.

- **Zero-cost infrastructure.** Signaling server on Oracle Free Tier + Cloudflare Free. DHT runs on users' devices. Volunteer MASQUE proxies. $0/month.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Rust (2021 edition) |
| Async runtime | tokio |
| QUIC | quinn 0.11 |
| DHT | libp2p KadDHT |
| Media | MoQ (draft-17) over QUIC datagrams |
| Audio codec | Opus (VOIP mode, 48kHz, 20ms frames, FEC, DTX) |
| Relay | MASQUE CONNECT-UDP (h3 + h3-quinn for HTTP/3, h2 for HTTP/2) |
| Signaling | axum + tokio-tungstenite (REST + WebSocket) |
| Protobuf | prost |
| Auth | Ed25519 (JWT, DHT record signing) |
| Mobile | UniFFI → Kotlin / Swift |
| TLS | rustls 0.23 + rustls-acme (Let's Encrypt) |

---

## Project Structure

```
three-pillars-voip/
├── crates/
│   ├── voip-core/          # Shared types, Protobuf, state machines, config, crypto
│   ├── voip-signaling/     # Signaling server (REST + WebSocket + QUIC path probing)
│   ├── voip-client/        # Client library (QUIC + MoQ + NAT probe + MASQUE + audio)
│   ├── voip-dht/           # DHT node (libp2p KadDHT, peer/proxy discovery)
│   └── voip-ffi/           # UniFFI bindings for mobile (Kotlin/Swift)
├── proto/
│   ├── signaling.proto     # Signaling message schemas
│   └── internal.proto      # NAT probe message schemas
├── mobile/
│   ├── android/            # Android AAR wrapper
│   └── ios/                # iOS XCFramework wrapper
├── spec/                   # Architecture specification (13 documents)
├── AGENTS.md               # AI agent instructions
├── CONVENTIONS.md          # Coding conventions
└── ROADMAP.md              # Development roadmap (53 steps, 6 phases)
```

### Module Boundaries

```
voip-ffi → voip-client → voip-core
                        → voip-dht → voip-core
voip-signaling → voip-core
```

- **voip-core**: Types only. No I/O, no network, no filesystem.
- **voip-client**: QUIC connection, MoQ session, NAT probing, MASQUE tunnel, audio pipeline.
- **voip-dht**: KadDHT node, peer lookup, proxy discovery, record signing.
- **voip-signaling**: WebSocket/REST server, peer registry, QUIC path probing reflection.
- **voip-ffi**: Thin UniFFI bridge. Exposes voip-client API to mobile.

---

## Getting Started

### Prerequisites

- Rust 1.75+ (2021 edition)
- Protobuf compiler (`protoc`) — for prost-build
- Opus development headers — for the `opus` crate

### Build

```bash
# Clone
git clone https://github.com/topic-hash/three-pillars-voip.git
cd three-pillars-voip

# Build all crates
cargo build

# Run tests
cargo test

# Check for warnings
cargo clippy
```

### Run Signaling Server

```bash
cargo run -p voip-signaling
```

The server listens on WebSocket and REST endpoints. See `spec/08_API_Specification.md` for the full API.

---

## Discovery

Two discovery layers with user-selectable priority:

| Layer | Latency | Privacy | Censorship Resistance |
|-------|---------|---------|----------------------|
| **DHT** (libp2p KadDHT) | ~80ms | High — no single entity sees social graph | High — no entity to subpoena |
| **Signaling Server** | ~5ms | Low — server sees social graph | Low — can be blocked |

Default: **Privacy-first** (DHT → Signaling fallback). User can toggle to speed-first.

---

## MASQUE Relay

When direct P2P fails, MASQUE CONNECT-UDP (RFC 9298) provides automatic relay:

1. Both peers connect outbound to a MASQUE proxy (discovered via DHT or signaling)
2. Each sends a CONNECT-UDP request with the `call_id`
3. Proxy matches the two requests and bridges the tunnels
4. MoQ session runs unchanged over the tunnel

**Anti-abuse limits** (per proxy session):
- 10 concurrent sessions
- 4 hour maximum duration
- 200 datagrams/second
- 1280 byte max datagram
- 500 Kbps bandwidth cap
- ProxyToken required (signed by signaling server)

**When UDP is blocked:** MASQUE runs over HTTP/2 (TCP) instead of HTTP/3 (QUIC). Same CONNECT-UDP protocol, same proxy. The fallback is automatic.

---

## Specification

The full architecture specification lives in `spec/`:

| # | Document | Description |
|---|----------|-------------|
| 00 | [Index](spec/00_Index.md) | Specification map |
| 01 | [Architecture Overview](spec/01_Architecture_Overview.md) | Core principle, pillars, coverage analysis |
| 02 | [Pillar 1: IPv6](spec/02_Pillar1_IPv6.md) | NAT elimination via IPv6 |
| 03 | [Pillar 2: QUIC NAT Traversal](spec/03_Pillar2_QUIC_NAT_Traversal.md) | Simultaneous open + port prediction |
| 04 | [Pillar 3: QUIC](spec/04_Pillar3_QUIC.md) | Single protocol replacement |
| 05 | [Media Layer: MoQ](spec/05_Media_Layer_MoQ.md) | MoQ as media layer |
| 06 | [Discovery & Signaling](spec/06_Discovery_Signaling.md) | DHT + signaling, connection flow |
| 07 | [Data Model](spec/07_Data_Model.md) | State machines, Protobuf schemas |
| 08 | [API Specification](spec/08_API_Specification.md) | REST, WebSocket, DHT, MASQUE APIs |
| 09 | [Data Flows](spec/09_Data_Flows.md) | Connection scenarios, fallback flows |
| 10 | [Data Persistence](spec/10_Data_Persistence.md) | Storage, caching, session data |
| 11 | [Implementation Stack](spec/11_Implementation_Stack.md) | Tech choices, constants, acceptance tests |
| 12 | [MASQUE Fallback](spec/12_MASQUE_Fallback.md) | MASQUE mechanics, proxy auth, anti-abuse |

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full 53-step development plan across 6 phases.

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | Core types + DHT | Implemented |
| 2 | Signaling server | Implemented |
| 3 | QUIC + MoQ client | Implemented |
| 3.5 | MASQUE fallback | Implemented |
| 4 | Audio pipeline + push retry | Implemented |
| 5 | End-to-end integration | Partial |
| 6 | Mobile bindings (UniFFI) | Scaffolded |

**Current version:** v8.0 (Foundation)

**Future:** v8.1 (Hardening) → v8.2 (Video & Screen Share) → v9.0 (Group Calls via MoQ Relay)

---

## Why Not "Relay-Free"?

This architecture was originally conceived as "relay-free," but honest engineering requires acknowledging that ~8% of connections need MASQUE relay to succeed. Rather than pretending relays don't exist, Three Pillars VoIP **minimizes relay dependency** through three direct P2P pillars that cover ~91% of connections, then uses MASQUE as a censorship-resistant, metadata-protected fallback for the remainder. The relay problem solves itself over time as IPv6 adoption grows globally.

| Year | IPv6 Adoption | Direct P2P | MASQUE Relay |
|------|--------------|------------|--------------|
| 2025 | ~45% | ~91% | ~8% |
| 2027 | ~55% | ~95% | ~4% |
| 2030 | ~70% | ~98% | ~1% |

---

## Comparison With Legacy VoIP

| Metric | Legacy (TURN/SIP/RTP) | Three Pillars VoIP |
|--------|----------------------|-------------------|
| Direct P2P rate | 70–80% | ~91% |
| Connected rate | ~100% (TURN) | ~99% (MASQUE) |
| Protocols | 8 (SIP, SDP, ICE, STUN, TURN, DTLS, SRTP, RTP) | 1 (QUIC) + MoQ + MASQUE |
| Call setup time | 1–3 seconds | 70–200ms (direct), 200–500ms (MASQUE) |
| Relay censorship resistance | None (TURN trivially blockable) | High (indistinguishable from HTTPS) |
| Infrastructure cost | $$$ (TURN servers) | $0 (volunteer MASQUE proxies) |
| Discovery privacy | None (server sees all) | User choice: DHT (private) or signaling (fast) |

---

## License

MIT
