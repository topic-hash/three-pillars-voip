# Agent m3 — Memory Leak in `parse_namespace` Fix

## Task
Fix M3: Memory Leak in `parse_namespace` in `three-pillars-voip/crates/voip-client/src/moq.rs`.

## Summary
Replaced the `parse_namespace` function to remove the `.leak()` call that caused memory to be permanently leaked on every subscription. Changed the return type from `(&str, &str)` to `(String, &str)` so the namespace prefix is properly owned and freed when dropped.

## Files Changed
- `three-pillars-voip/crates/voip-client/src/moq.rs` — lines 1129-1136

## Details
- **Before**: `fn parse_namespace(full: &str) -> (&str, &str)` with `format!(...).leak()` — memory leak on every call
- **After**: `fn parse_namespace(full: &str) -> (String, &str)` with `format!(...)` — properly owned, freed on drop
- **Call site** at line 791 (`subscribe()` method): No changes needed — `String` derefs to `&str`, so `.len()` and `.as_bytes()` work transparently

## Previous Agent Context
- Agent h1 fixed ProxyToken signing ambiguity in `proxy.rs` (unrelated to this fix)
