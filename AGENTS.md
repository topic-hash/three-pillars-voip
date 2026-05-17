# AGENTS.md — Read This First

> This document is the mandatory starting point for any AI agent working on the Three Pillars VoIP project.
> Read this entire file before reading the spec or writing any code.

---

## 1. What You Are Building

A VoIP system with direct P2P first and MASQUE relay as automatic seamless fallback. Direct P2P via three mechanisms:

1. **IPv6** — eliminates NAT for ~45% of connections
2. **QUIC-Native NAT Traversal** — Cone NAT via QUIC simultaneous open, Symmetric NAT via QUIC path probing + port prediction for ~46% of connections
3. **QUIC + MoQ** — single protocol replaces the entire legacy VoIP stack (SIP, SDP, ICE, STUN/TURN, DTLS, SRTP, RTP)

Two discovery layers with user-selectable priority:
- **DHT** (libp2p KadDHT) — censorship-resistant, private, ~80ms
- **Signaling server** — fast (~5ms), but visible to Cloudflare and governments

~91% direct P2P, ~8% MASQUE relay, ~1% honest failure.

---

## 2. Read the Spec

Read these files **in order**:

| Order | File | Why |
|-------|------|-----|
| 1 | `spec/00_Index.md` | Map of the entire specification |
| 2 | `spec/01_Architecture_Overview.md` | What the system does and why |
| 3 | `spec/11_Implementation_Stack.md` | Language, libraries, constants, wire formats, acceptance tests |
| 4 | `ROADMAP.md` | Build order — know which milestone you're working on |
| 5 | Then read the rest as needed for your task | |

---

## 3. Decisions Already Made — Do Not Revisit

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | Rust | No GC, moq-rs reference impl, production QUIC + DHT libs |
| Async runtime | tokio | Standard, broadest ecosystem |
| QUIC library | quinn | Pure Rust, connection migration, datagram support |
| DHT library | libp2p KadDHT | Battle-tested, Rust native, S/Kademlia upgrade path |
| MoQ approach | Implement from draft-17, use moq-rs as reference | Not a dependency, it's a behavioral oracle |
| Protobuf | prost | Standard Rust Protobuf |
| Audio codec | Opus, VOIP mode, 48kHz, 20ms frames, FEC on, DTX on | See `spec/11` §11.4 |
| Signaling server | axum + tokio-tungstenite | REST + WebSocket in one binary |
| Mobile bindings | UniFFI | Rust → Kotlin/Swift |
| MASQUE relay fallback | MASQUE CONNECT-UDP (RFC 9298) as automatic seamless fallback | Censorship-resistant, metadata-protected, indistinguishable from HTTPS |
| No STUN. Ever. | STUN is eliminated. QUIC path probing replaces it | QUIC-native NAT traversal |
| No TURN. Ever. | TURN replaced by MASQUE CONNECT-UDP | Censorship-resistant, metadata-protected |
| No phases | MoQ from day one, no RoQ, no raw-QUIC-first migration | See `spec/01` §1.8 |
| Discovery | DHT-first (privacy) or signaling-first (speed), user toggle | See `spec/06` §6.1 |
| Push retry | Failed calls trigger push notification for retry | See `spec/06` §6.7 Step 9 |
| Infrastructure | Oracle Free + Cloudflare Free = $0/month | See `spec/11` §11.10 |

---

## 4. Project Structure

```
three-pillars-voip/
├── AGENTS.md                 ← you are here
├── CONVENTIONS.md            ← coding conventions
├── ROADMAP.md                ← build order and milestones
├── spec/                     ← 11 specification files
├── Cargo.toml                ← workspace root
├── crates/
│   ├── voip-core/            # Shared types, Protobuf definitions, state machines
│   ├── voip-signaling/       # Signaling server binary (QUIC listener, 5 IPs)
│   ├── voip-client/          # Client library (QUIC + MoQ + NAT probe + audio + masque_tunnel)
│   ├── voip-dht/             # DHT node (libp2p KadDHT)
│   └── voip-ffi/             # UniFFI bindings for mobile
├── proto/
│   ├── signaling.proto       # Signaling messages
│   └── internal.proto        # Internal NAT probe messages
├── mobile/
│   ├── android/              # Android AAR wrapper
│   └── ios/                  # iOS XCFramework wrapper
└── tests/
    ├── integration/          # Integration tests
    └── e2e/                  # End-to-end NAT simulation tests
```

**Module boundaries are strict:**

- `voip-core`: types only. No I/O. No network. No filesystem.
- `voip-client`: owns QUIC connection, MoQ session, NAT probing (via QUIC path probing), audio pipeline. Depends on voip-core.
- `voip-dht`: owns DHT node, lookup, storage. Depends on voip-core and libp2p.
- `voip-signaling`: owns WebSocket/REST server, peer registry, QUIC path probing reflection, message forwarding. Depends on voip-core only.
- `voip-ffi`: thin UniFFI layer. Exposes voip-client to mobile. No logic of its own.

**No voip-stun crate.** NAT probing is a module within voip-client that uses QUIC connection migration. No separate STUN protocol exists in this architecture.

---

## 5. How to Work

### Git strategy

#### Delegation model

| Role | Who | Authority |
|------|-----|----------|
| Product Owner | Main agent | Assigns tasks, merges to `main`, resolves conflicts, decides build order |
| Developer | Sub-agent | Implements on `feature/{scope}`, reports back when done |
| Stakeholder | Human | Direction and deliverables only — not individual commits |

#### Branch naming

`feature/{scope}` — one branch per sub-agent assignment.

| Phase | Branch | What |
|-------|--------|------|
| 1 | `feature/core-types` | Steps 1.1–1.3: voip-core Protobuf, state machines, domain types |
| 1 | `feature/dht-node` | Steps 1.4–1.9: voip-dht KadDHT node, lookup, store, username resolution, record refresh, mobile constraints |
| 2 | `feature/signaling-rest` | Steps 2.1, 2.4–2.6, 2.10–2.12: REST API, rate limiting, OpenAPI, JWT, additional endpoints, error codes, MASQUE coordination |
| 2 | `feature/signaling-ws` | Steps 2.2–2.3: WebSocket framing, call signaling |
| 2 | `feature/signaling-probe` | Steps 2.7–2.9: QUIC path probing, /v1/myip, push notification relay |
| 3 | `feature/quic-connect` | Steps 3.1–3.4, 3.8–3.11: QUIC connection, path probing, port prediction, migration, Connection ID, simultaneous open, Happy Eyeballs, 0-RTT |
| 3 | `feature/moq-session` | Steps 3.5–3.7, 3.12–3.13: MoQ control, datagrams, feedback, in-channel signaling |
| 3.5 | `feature/masque-fallback` | Steps 3.15–3.25: MASQUE HTTP/3 + HTTP/2, bidirectional model, DHT proxy discovery, anti-abuse, ProxyToken, certs, tunnel recovery, proxy cache |
| 3.5 | `feature/client-cache` | Step 3.14: Client-side peer address book with discovery_method tracking |
| 4 | `feature/audio-pipeline` | Steps 4.1–4.5: Opus, capture→send, priority, FEC, DTX |
| 4 | `feature/push-retry` | Steps 4.6–4.7: Push notification retry, auto-retry on network change |
| 5 | `feature/e2e-integration` | Steps 5.1–5.14: End-to-end NAT scenario tests, MASQUE integration, cache tests, call rejection, tunnel recovery |
| 6 | `feature/ffi-mobile` | Steps 6.1–6.3: UniFFI, Android AAR, iOS XCFramework, mobile DHT lookup-only |

#### Sub-agent workflow

Each feature branch follows this lifecycle:

```
1. Main agent creates branch from main:
   git checkout main
   git pull origin main
   git checkout -b feature/{scope}

2. Sub-agent implements on that branch, committing as it goes:
   git add -A
   git commit -m "feat(core): add CallStateMachine transitions"

3. Sub-agent reports back with:
   - What was implemented (step numbers from ROADMAP)
   - Which acceptance tests pass
   - Any spec ambiguity encountered
   - Any deviations from the spec (with justification)

4. Main agent validates:
   cargo check && cargo test && cargo clippy

5. Main agent merges:
   git checkout main
   git merge --squash feature/{scope}
   git commit -m "feat(core): voip-core — Protobuf, state machines, domain types (Steps 1.1–1.3)"

6. Branch is deleted:
   git branch -d feature/{scope}
```

#### Commit format

Conventional Commits. Every commit message MUST follow this format:

```
type(scope): description

[optional body with context]
```

**Types:**
| Type | When |
|------|------|
| `feat` | New feature or step completion |
| `fix` | Bug fix |
| `refactor` | Code restructure without behavior change |
| `test` | Adding or updating tests |
| `docs` | Documentation only |
| `chore` | Build, CI, dependencies |

**Scopes:** `core`, `signaling`, `client`, `dht`, `ffi`, `proto`, `spec`

**Examples:**
```
feat(core): add NATType classification and prediction confidence
feat(client): implement QUIC path probing for NAT classification (Step 3.2)
fix(signaling): correct WebSocket message type ID for CallAccept
test(client): add port prediction unit tests for sequential NAT
refactor(dht): extract record signing into standalone module
chore(proto): update signaling.proto with MASQUE HTTP/2 enum values
```

**Squash-merge format** (when main agent merges a feature branch):
```
feat(core): voip-core — Protobuf, state machines, domain types (Steps 1.1–1.3)

- Compiled signaling.proto and internal.proto via prost-build
- Implemented CallStateMachine with all transitions from spec/07
- Added VoIPConfig with all 35 fields and defaults from spec/11
- Ed25519 key generation, DHT record signing, Connection ID CSPRNG
- All unit tests passing, cargo clippy clean
```

#### Merge commands

| Action | Command |
|--------|---------|
| Start feature branch | `git checkout -b feature/{scope} main` |
| Squash-merge to main | `git checkout main && git merge --squash feature/{scope} && git commit` |
| Fast-forward merge (if clean) | `git checkout main && git merge --ff-only feature/{scope}` |
| Abort failed merge | `git merge --abort` |
| Delete merged branch | `git branch -d feature/{scope}` |
| Push main after merge | `git push origin main` |

**Always squash-merge.** Feature branches are implementation scratchpads — main should have one clean commit per feature, not 15 "wip" commits.

#### Conflict resolution

1. **Main agent owns `main`.** Only the main agent resolves merge conflicts.
2. If a squash-merge has conflicts:
   ```
   git checkout main
   git merge --squash feature/{scope}
   # conflicts appear
   git diff --name-only --diff-filter=U    # list conflicting files
   # main agent resolves each conflict, keeping spec-compliant code
   git add <resolved files>
   git commit
   ```
3. **Resolution priority:** spec compliance > existing main code > feature branch code. When in doubt, the spec wins.
4. If two feature branches conflict, merge the first one, then rebase the second:
   ```
   git checkout feature/{scope-2}
   git rebase main
   # resolve conflicts if any
   git checkout main
   git merge --squash feature/{scope-2}
   ```

#### Tag strategy

Tags mark phase completion gates. A tag is only created when ALL acceptance tests for that phase pass.

| Tag | Created When | Gate |
|-----|-------------|------|
| `phase-1` | Steps 1.1–1.9 done | `cargo test -p voip-core && cargo test -p voip-dht` passes, DISC-01 through DISC-05 pass |
| `phase-2` | Steps 2.1–2.12 done | Signaling server starts, SIG-01 through SIG-05 pass, MASQUE coordination works |
| `phase-3` | Steps 3.1–3.14 done | QUIC connect + MoQ session + simultaneous open + 0-RTT + in-channel signaling works, NAT-01 through NAT-04 pass |
| `phase-3.5` | Steps 3.15–3.25 done | MASQUE fallback (HTTP/3 + HTTP/2) works, MASQUE-01 through MASQUE-06 pass |
| `phase-4` | Steps 4.1–4.7 done | Audio pipeline + push retry, MED-01 through MED-05 + RETRY-01 through RETRY-04 pass |
| `phase-5` | Steps 5.1–5.14 done | All end-to-end NAT scenarios pass, MASQUE integration, cache tests, call rejection, tunnel recovery |
| `phase-6` | Steps 6.1–6.3 done | Android AAR + iOS XCFramework build, mobile DHT lookup-only |
| `v0.1.0` | All phases done | Full system works end-to-end |

```bash
# Tag creation
git tag -a phase-1 -m "Phase 1: Core types + DHT — all acceptance tests pass"
git push origin phase-1
```

**No tag = not done.** If a tag doesn't exist, that phase is not complete.

#### Parallel branches within a phase

Branches within the same phase can be developed in parallel by different sub-agents, BUT they cannot be merged in parallel. Merge order within a phase:

| Phase | Merge Order | Reason |
|-------|-------------|--------|
| 1 | `feature/core-types` first, then `feature/dht-node` | dht-node depends on core types |
| 2 | `feature/signaling-rest` → `feature/signaling-ws` → `feature/signaling-probe` | WS needs REST for JWT auth, probe needs WS for address reflection |
| 3 | `feature/quic-connect` → `feature/moq-session` → `feature/client-cache` | MoQ rides on QUIC connection, cache needs both |
| 3.5 | `feature/masque-fallback` (single branch, large scope) | All MASQUE pieces are interdependent |
| 4 | Either order — `feature/audio-pipeline` and `feature/push-retry` are independent | No dependency between them |
| 5 | Single branch — `feature/e2e-integration` | Needs everything before it |
| 6 | Single branch — `feature/ffi-mobile` | Needs everything before it |

#### Initial repo setup

```bash
# One-time: create repo, push initial state
git init
git add -A
git commit -m "init: Three Pillars VoIP — spec, proto, Cargo workspace, empty crates"
git remote add origin https://github.com/topic-hash/three-pillars-voip.git
git push -u origin main

# Each feature branch starts from main
git checkout -b feature/core-types main
```

#### Branch protection rules

- `main` must always compile: `cargo check` must pass
- `main` must never have `unwrap()` outside of tests and binary main
- `main` must never have TODO or FIXME (those belong on feature branches only)
- No direct commits to `main` — everything goes through feature branches and squash-merge

### Engineering process: Two-pass development

Every feature is built in two passes:

**Pass 1 — Rough Draft:**
- Get the structure right: types, traits, function signatures, module layout
- Implement the happy path
- Make it compile and pass basic tests
- Do NOT optimize, do NOT handle edge cases, do NOT write comprehensive tests

**Pass 2 — Fine Draft:**
- Handle all error cases and edge cases from the spec
- Write comprehensive tests covering the acceptance criteria
- Run `cargo clippy` and fix all warnings
- Add doc comments to every public item
- Verify against the relevant spec file

**A feature branch is only ready for merge after Pass 2 is complete.**

### What to do when the spec is ambiguous

1. **Do not guess.** If the spec says something unclear or contradictory, stop.
2. **Escalate to the main agent** with:
   - The spec section and quote that is ambiguous
   - Your interpretation (what you think it means)
   - Any alternatives you considered
   - The impact of each interpretation
3. **The main agent decides.** The sub-agent implements the decision.
4. **The main agent updates the spec** if the ambiguity reveals a spec gap.

---

## 6. Coding Conventions

Read `CONVENTIONS.md` after this file.

---

## 7. Acceptance Criteria

Your work is done when:

1. All acceptance tests from `spec/11` §11.8 pass
2. No compiler warnings (`cargo clippy` is clean)
3. No `unwrap()` in library code (only in tests and binary main)
4. Every public function has a doc comment
5. The relevant spec file was your source of truth

---

## 8. What NOT to Do

- **Do not add a relay OTHER than MASQUE.** TURN, DERP, and custom relay protocols are forbidden. MASQUE CONNECT-UDP is the only relay mechanism.
- **Do not add STUN.** STUN is eliminated. QUIC path probing replaces it. No STUN library, no STUN messages, no STUN port.
- **Do not add TURN.** TURN is replaced by MASQUE CONNECT-UDP. No TURN library, no TURN messages, no TURN port.
- **Do not add ICE.** QUIC simultaneous open and port prediction replace ICE. No candidate gathering.
- **Do not add RoQ.** RTP over QUIC is not part of this architecture.
- **Do not use grey-zone NAT traversal.** No birthday attacks. No port spraying.
- **Do not store media server-side.** The signaling server never touches media. Ever.
- **Do not skip the spec.** Read the spec first.
- **Do not refactor across module boundaries** without the main agent's approval.
