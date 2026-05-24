# m2-m8 — TOCTOU in Call Creation + Double disconnect_peer Fix

**Agent**: m2-m8
**Date**: 2026-03-04

## Summary

Fixed two bugs in the VoIP signaling server:

1. **M2 (task 9.1)**: TOCTOU race condition in `create_call()` — peers read lock was released before calls write lock was acquired, allowing a peer to be unregistered in the gap.
2. **M8 (tasks 20.1–20.2)**: Double `disconnect_peer()` call — both the forward task and the receive loop cleanup could call `disconnect_peer()` for the same peer.

## Files Changed

- `three-pillars-voip/crates/voip-signaling/src/state.rs`
- `three-pillars-voip/crates/voip-signaling/src/session.rs`

## Changes

### state.rs — `create_call()` (M2)
- Removed inner block scope so the peers read lock is held across the calls write lock acquisition
- No deadlock risk: peers (read) and calls (write) are different RwLock instances

### state.rs — `disconnect_peer()` (M8.1)
- Added idempotent early-return: if `sender.is_none()` and `status == 1`, return immediately
- Prevents redundant state mutation and `rate_limiter.remove_peer()` calls

### session.rs — `handle_ws_connection()` (M8.2)
- Added `Arc<AtomicBool>` (`disconnected`) shared between forward task and receive loop cleanup
- Both paths use `compare_exchange(false, true)` to atomically claim the disconnect
- Only the first caller proceeds to `disconnect_peer()`; the second skips it
- Added `use std::sync::Arc;` import

## Verification

All changes were reviewed against the original code and the task specifications. The edits are minimal and surgical — only the necessary lines were modified.
