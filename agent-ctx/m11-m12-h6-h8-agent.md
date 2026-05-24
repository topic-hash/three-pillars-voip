# Task m11-m12-h6-h8 Work Record

## Agent: m11-m12-h6-h8
## Date: 2026-03-04

## Summary

Implemented 4 bug fixes across 4 files in the three-pillars-voip project:

### M11: Orphaned Accept Task in Simultaneous Open
- **File**: `crates/voip-client/src/connection.rs`
- **Change**: Replaced channel-based racing pattern in `try_simultaneous_open_full()` with `tokio::select!` on pinned `JoinHandle`s. When one side succeeds, the other is explicitly `.abort()`-ed.

### M12: No WebSocket Idle Timeout
- **File**: `crates/voip-core/src/config.rs` — Added `ws_idle_timeout_secs: u64` field (default: 300) to `VoIPConfig`
- **File**: `crates/voip-signaling/src/session.rs` — Wrapped WS receive loop in `tokio::select!` with idle timeout; resets on each message

### H6: H3 Driver Dropped After Tunnel Established
- **File**: `crates/voip-client/src/masque.rs`
- **Change**: Added `h3_driver: Option<...>` field to `MasqueTunnel`; stored h3_driver instead of dropping it in `connect_http3()`

### H8: Loopback QUIC server_task Dropped
- **File**: `crates/voip-client/src/masque.rs`
- **Change**: Changed `create_loopback_quic_pair()` to return `(Connection, JoinHandle<()>)`; added `_server_task: Option<JoinHandle<()>>` field to `MasqueTunnel`; stored server_task instead of dropping it

## All changes verified by reading back the modified files.
