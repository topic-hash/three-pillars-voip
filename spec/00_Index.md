# Three Pillars VoIP Relay-Free Architecture — Specification Index

> **Document ID:** TS-2025-001  
> **Version:** v8.0  
> **Date:** 2025-05-17  
> **Status:** Final  
> **Architecture:** IPv6 + QUIC-Native NAT Traversal + MASQUE Fallback + MoQ on QUIC  
> **Direct P2P Rate:** ~91%  
> **Connected Rate:** ~99% (including MASQUE fallback)

---

## Core Principle

Direct P2P first. MASQUE relay as automatic seamless fallback when direct fails. Zero auxiliary protocols beyond QUIC. Zero paid infrastructure. Three pillars + MASQUE fallback + one media layer + two discovery layers: IPv6 eliminates NAT, QUIC-Native NAT Traversal handles both Cone and Symmetric NAT, MASQUE CONNECT-UDP relays through censorship-resistant HTTPS tunnels when both fail, QUIC replaces the entire legacy stack, MoQ standardizes media management. DHT provides censorship-resistant discovery and proxy discovery, signaling server provides fast discovery. User chooses discovery priority. MASQUE is automatic — no user opt-in required.

## The Fundamental Tradeoff

~91% direct P2P, ~8% MASQUE relay fallback, ~1% honest failure. No TURN, no DERP, no stateless forwarder. When direct P2P fails, MASQUE CONNECT-UDP (RFC 9298) automatically tunnels media through an HTTPS proxy — traffic indistinguishable from ordinary web browsing. When UDP is blocked, MASQUE runs over HTTP/2 (TCP) — same CONNECT-UDP protocol, same proxy, MoQ works unchanged through the tunnel. Only when both UDP and TCP port 443 are blocked does the call fail with push notification retry.

---

## Specification Files

| # | File | Domain | Description |
|---|------|--------|-------------|
| 01 | [Architecture Overview](01_Architecture_Overview.md) | Architecture | Core principle, three pillars + MASQUE fallback summary, MoQ as media layer, coverage analysis, growth trajectory, discovery architecture |
| 02 | [Pillar 1: IPv6](02_Pillar1_IPv6.md) | Network / IPv6 | NAT elimination via IPv6, deployment data, relay-free mechanism, implementation steps |
| 03 | [Pillar 2: QUIC-Native NAT Traversal](03_Pillar2_QUIC_NAT_Traversal.md) | Network / NAT | Cone NAT simultaneous open via QUIC, Symmetric NAT port prediction via QUIC path probing, 5-step algorithm, accuracy analysis, legal analysis |
| 04 | [Pillar 3: QUIC](04_Pillar3_QUIC.md) | Transport | Single protocol replacement, 8-to-1 mapping, Connection ID enabler, connection migration, 1-RTT setup, datagram reliability, QUIC hole punching |
| 05 | [Media Layer: MoQ](05_Media_Layer_MoQ.md) | Media | MoQ rationale, spec status, architecture fit, connection flow integration |
| 06 | [Discovery & Signaling](06_Discovery_Signaling.md) | Control Plane | DHT-first vs signaling-first discovery, user toggle, signaling server role, DHT proxy discovery for MASQUE, Protobuf schema, combined connection flow, MASQUE fallback, push notification retry |
| 07 | [Data Model](07_Data_Model.md) | Data | Business objects, full Protobuf message schemas, state machines, object relationships |
| 08 | [API Specification](08_API_Specification.md) | Interface | Signaling Server API, DHT Discovery API, MASQUE Tunnel API, Client MoQ Interface, QUIC Connection Management API |
| 09 | [Data Flows](09_Data_Flows.md) | Flow | IPv6/Cone NAT/Symmetric NAT connection scenarios, MASQUE fallback flow, DHT discovery flow, failure flows with push retry, network migration flows, call rejection, MoQ session setup |
| 10 | [Data Persistence](10_Data_Persistence.md) | Storage | Signaling server state, client-side cache, session & key material, no server-side media persistence |
| 11 | [Implementation Stack](11_Implementation_Stack.md) | Implementation | Technology stack, library choices, project structure, configuration constants, Opus codec, error handling, MoQ wire format, authentication, MASQUE tunnel implementation, acceptance tests, deployment (Oracle Free + Cloudflare Free) |
| 12 | [MASQUE CONNECT-UDP Fallback](12_MASQUE_Fallback.md) | Relay | MASQUE protocol mechanics, CONNECT-UDP request/response format, tunnel lifecycle state machine, MoQ-over-MASQUE specifics, proxy authentication, UDP-blocked scenario, anti-abuse mechanisms, volunteer proxy operation, MASQUE vs. TURN comparison, implementation notes |

---

## Cross-References

| Topic | Primary File | Referenced In |
|-------|-------------|---------------|
| IPv6 deployment data | 02_Pillar1_IPv6 | 01_Architecture_Overview, 09_Data_Flows |
| QUIC path probing | 03_Pillar2_QUIC_NAT_Traversal | 08_API_Specification, 09_Data_Flows |
| QUIC Connection ID | 04_Pillar3_QUIC | 03_Pillar2_QUIC_NAT_Traversal, 09_Data_Flows |
| MoQ track namespace | 05_Media_Layer_MoQ | 07_Data_Model, 08_API_Specification |
| Discovery (DHT + signaling) | 06_Discovery_Signaling | 07_Data_Model, 08_API_Specification, 09_Data_Flows |
| MASQUE proxy discovery | 06_Discovery_Signaling | 08_API_Specification, 09_Data_Flows, 10_Data_Persistence, 12_MASQUE_Fallback |
| MASQUE tunnel mechanics | 12_MASQUE_Fallback | 06_Discovery_Signaling, 09_Data_Flows, 11_Implementation_Stack |
| Signaling Protobuf | 06_Discovery_Signaling | 07_Data_Model, 08_API_Specification |
| Call state machine | 07_Data_Model | 09_Data_Flows, 10_Data_Persistence |
| NAT probe cache | 10_Data_Persistence | 03_Pillar2_QUIC_NAT_Traversal |
| Rust stack / libraries | 11_Implementation_Stack | 04_Pillar3_QUIC, 05_Media_Layer_MoQ, 08_API_Specification |
| Opus codec config | 11_Implementation_Stack | 05_Media_Layer_MoQ |

---

## Companion Documents

- **Proto files:** `proto/signaling.proto` and `proto/internal.proto` — Authoritative Protobuf schemas. Compiled by `prost-build`. If these disagree with inline schemas in the spec, the `.proto` files win.
- **ADR:** `ADR_Three_Pillars_VoIP_v7.pdf` — Architecture Decision Record (WHY, standalone)
- **Git strategy:** `AGENTS.md` §5 — feature-branch workflow, branch-to-phase mapping, merge commands, conflict resolution, tag gates. The spec defines *what* to build; AGENTS.md defines *how* to deliver it.

---

## Revision History

| Version | Date | Change |
|---------|------|--------|
| v8.0 | 2025-05-17 | Added MASQUE CONNECT-UDP (RFC 9298) as automatic seamless fallback when all Three Pillars fail. ~91% direct P2P + ~8% MASQUE relay = ~99% connected rate. DHT proxy discovery for MASQUE proxy nodes. Traffic indistinguishable from HTTPS — censorship-resistant relay. Principle shift from "zero relay" to "direct first, MASQUE automatic fallback." No user opt-in required. |
| v7.0 | 2025-05-17 | Major revision: eliminated STUN protocol entirely, replaced with QUIC-native path probing and hole punching. Added DHT discovery layer (libp2p KadDHT) with user toggle. Corrected IPv6 coverage to ~45% (sourced from Google stats). Corrected total relay-free rate to ~91%. Added push notification retry for 9% failure. Signaling server deployment on Oracle Free + Cloudflare Free. |
| v6.0 | 2025-05-14 | Initial specification. Single-phase Three Pillars + MoQ architecture. Domain-split into 11 files. |
