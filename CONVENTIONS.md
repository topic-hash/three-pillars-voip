# CONVENTIONS.md — Coding Conventions

> Read after AGENTS.md. These are the coding rules for this project.
> Every agent must follow these when writing or modifying code.

---

## 1. Paradigm

Idiomatic Rust. No OOP patterns, no inheritance simulations, no Go-style interfaces.

- **Enums + match** for all state machines (CallState, SubscriptionState, NATType, PredictionConfidence, DiscoveryMethod)
- **Traits** for capability abstraction (TrackPublisher, TrackSubscriber, NatObserver, DiscoveryProvider)
- **Result<T, E>** for all fallible operations. No unwrap() in library code.
- **Builder pattern** for configuration structs (VoIPConfig, OpusConfig, ConnectParams)
- **Newtype pattern** for domain primitives (PeerId(String), TrackAlias(u32), ConnectionId(Vec<u8>))

---

## 2. Runtime Performance — Zero Copy, Low CPU

### 2.1 Zero-Copy Routes (Critical Path)

- **No `clone()` on media buffers.** Opus-encoded frames pass as `&[u8]` or `Bytes`.
- **Use `bytes::Bytes` for media payloads.** Cheap reference-counted cloning.
- **QUIC datagram send must borrow, not copy.** Use slice references or `Bytes`.
- **MoQ datagram framing writes directly into a pre-allocated buffer.** Use `bytes::BufMut`.

### 2.2 CPU Efficiency

- **No allocations in the audio hot path.** Pre-allocate all buffers at session start.
- **No `format!()` or `String` allocation in the media path.** Use `tracing` with level filtering.
- **QUIC congestion control runs in quinn.** Do not duplicate congestion logic.
- **QUIC path probing runs at most every 5 minutes.** 5 QUIC path migrations, ~50ms total. Negligible CPU.

### 2.3 Allocation Strategy

| Module | Allocation Policy | Rationale |
|--------|-------------------|-----------|
| `voip-client` (NAT probe) | Allocate per-probe (rare, every 5 min) | Not on hot path |
| `voip-client` (media) | Pre-allocate at session start, reuse | 50 frames/sec, zero alloc |
| `voip-client` (MoQ control) | Allocate per message (rare, setup only) | Not on hot path |
| `voip-dht` | Allocate per DHT operation (background) | Not on hot path, runs on desktop only |
| `voip-signaling` | Allocate per message (standard tokio) | Not latency-critical |
| `voip-core` | No heap allocation (types only) | No I/O, no allocation |
| `voip-ffi` | Minimal allocation (bridge only) | Thin wrapper |

### 2.4 Asynchronous Design

- **Tokio tasks:** One task per active call (client-side). One task per WebSocket connection (server-side).
- **No `spawn_blocking` on the media path.** Opus encode/decode is fast enough for tokio.
- **Channel strategy:** `tokio::sync::mpsc` for control messages. `tokio::sync::watch` for shared state.

---

## 3. Error Handling

- **thiserror** for library error types (voip-core, voip-client, voip-dht)
- **anyhow** for application-level errors (voip-signaling binary only)
- **Never panic in library code.** No `unwrap()`, no `expect()`, no `panic!()`.
- **Never silently swallow errors.** Every `Err` is propagated, logged, or handled.
- **Error types are domain-specific.** Each crate defines its own error enum. No `Box<dyn Error>` in public APIs.

---

## 4. Module Boundaries

Boundaries are strict. Dependencies flow one direction:

```
voip-ffi → voip-client → voip-core
                        → voip-dht → voip-core
voip-signaling → voip-core
```

- `voip-core` depends on nothing (no I/O, no network, no filesystem)
- `voip-client` depends on `voip-core` (NAT probing is a module within voip-client, uses QUIC)
- `voip-dht` depends on `voip-core` and `libp2p`
- `voip-signaling` depends on `voip-core` only
- `voip-ffi` depends on `voip-client` only — thin bridge, no logic

**No circular dependencies. No cross-dependencies between sibling crates.**

**No voip-stun crate.** NAT probing is implemented within voip-client using QUIC connection migration. There is no STUN protocol in this architecture.

**MASQUE tunnel module** lives in `voip-client` as `masque_tunnel.rs`. It uses `h3` + `h3-quinn` for HTTP/3 CONNECT-UDP. No separate crate needed — MASQUE is an HTTP/3 extension, not a new protocol.

---

## 5. Documentation

- Every **public** function, struct, enum, and trait must have a `///` doc comment.
- Doc comments explain **why**, not what.
- Signaling server REST API documented with OpenAPI 3.0 via `utoipa`.
- WebSocket messages documented via `.proto` files and generated Markdown.

---

## 6. Naming Conventions

| Element | Convention | Example |
|---------|-----------|---------|
| Crates | kebab-case | `voip-core`, `voip-dht` |
| Structs | PascalCase | `CallRequest`, `PortPrediction` |
| Enums | PascalCase | `CallState`, `NATType`, `DiscoveryMethod` |
| Enum variants | SCREAMING_SNAKE | `NAT_CONE`, `DISCOVERY_DHT` |
| Functions | snake_case | `probe_nat()`, `predict_port_range()` |
| Constants | SCREAMING_SNAKE | `PATH_PROBE_TIMEOUT_MS` |
| Type aliases | PascalCase | `PeerId`, `TrackAlias` |

No Hungarian notation. No type prefixes.

---

## 7. No-Go Zones

- **No `unsafe`** except when wrapping a C library (libopus, quinn FFI). All `unsafe` blocks must have a `// SAFETY:` comment.
- **No global mutable state.** No `lazy_static!` with interior mutability. Pass state explicitly.
- **No async in constructors.** Use `MyStruct::new()` for sync, `MyStruct::init()` for async.
- **No `Box<dyn Trait>` where generics work.** Use `impl Trait` or generics.
- **No `Arc<Mutex<>>` unless truly shared.** Use message passing instead.
- **No `unwrap()` in library code.** Ever.
- **No `todo!()` or `unimplemented!()` in committed code.**
- **No STUN.** There is no STUN protocol in this architecture. Use QUIC path probing.
- **No TURN.** TURN is replaced by MASQUE CONNECT-UDP (RFC 9298). No TURN library, no TURN messages, no TURN port.
