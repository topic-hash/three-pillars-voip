# signaling-ws + signaling-probe Implementation

## Task ID
signaling-ws-probe-implementation

## Agent
main

## Summary
Implemented Phase 2 features for the Three Pillars VoIP signaling server:
- Feature 1: signaling-ws (Steps 2.2-2.3) — message framing + call signaling
- Feature 2: signaling-probe (Steps 2.7-2.9) — QUIC path probing + /v1/myip + push notifications

## Changes Made

### New Files
1. **`crates/voip-signaling/src/push.rs`** — Push notification relay (FCM stub)
   - `PushNotifier` struct with stub FCM implementation (logs notifications)
   - `is_retryable_reason()` — checks END_FAILED_IPV4_RANDOM (3) and END_FAILED_MASQUE_UNREACHABLE (7)
   - `build_push_retry_message()` — creates PushRetry (0x0009) framed message
   - `handle_retryable_failure()` — sends PushRetry via WS + queues FCM push

2. **`crates/voip-signaling/src/quic_probe.rs`** — QUIC path probing stub
   - `QuicProbeConfig` — config for 5-IP QUIC listener
   - `QuicProbeServer` — stub server that logs readiness
   - `build_path_probe_response()` — creates PathProbeResponse (0x0200) framed message
   - `encode_path_probe_response()` — full wire-format encoding for QUIC streams
   - `handle_path_migration()` — stub for processing QUIC connection migration

### Modified Files

3. **`crates/voip-signaling/src/state.rs`** — Added standalone encode/decode functions
   - `encode_message(type_id: u16, payload: &[u8]) -> Vec<u8>` — canonical framing
   - `decode_message(data: &[u8]) -> Result<(u16, Vec<u8>), SignalingError>` — canonical parsing
   - `FramedMessage::to_bytes()` and `from_bytes()` now delegate to these functions

4. **`crates/voip-signaling/src/session.rs`** — Enhanced call signaling
   - `ws_handle_call_accept`: Added participant validation (only callee can accept)
   - `ws_handle_call_reject`: Added participant validation (only callee can reject)
   - `ws_handle_call_failed`: Added participant validation + PushRetry on retryable failures + MASQUE for UDP_BLOCKED
   - `ws_handle_call_ended`: Added participant validation (only call participants can end)

5. **`crates/voip-signaling/src/main.rs`** — Wired up new modules
   - Added `mod push` and `mod quic_probe`
   - Replaced placeholder QUIC spawn with `QuicProbeServer::start()`

6. **`crates/voip-signaling/Cargo.toml`** — Added dependencies
   - `quinn` (workspace) — for QUIC path probing
   - `rustls` (workspace) — TLS for QUIC
   - `rcgen` (workspace) — self-signed cert generation

### /v1/myip Verification
Already correctly implemented in `handlers.rs`:
- Returns `{"ip": "...", "ip_version": 6|4, "port": 54321, "observed_at": 1715673600}`
- Matches spec/08 §8.1.3 format exactly

## Compilation Status
`cargo check -p voip-signaling` — **passes cleanly** with zero errors and zero warnings.
