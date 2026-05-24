# M1 — No Jitter Buffer

**Agent**: m1
**Date**: 2026-03-04
**File changed**: `three-pillars-voip/crates/voip-client/src/pipeline.rs`

## What was done

Added a jitter buffer to `AudioPipeline` to absorb network jitter on the receive path. Without a jitter buffer, out-of-order or slightly delayed packets would cause audible glitches because the pipeline would decode and play packets as soon as they arrive, with no reordering or hold-back delay.

## Changes made

1. **Import**: Added `use std::collections::VecDeque;` at line 12.

2. **`AudioPipeline` struct** (lines 48–57): Added three fields:
   - `jitter_buffer: VecDeque<MoqDatagram>` — holds incoming datagrams sorted by sequence number
   - `jitter_target_ms: u64` — target jitter buffer depth in milliseconds
   - `last_playback_ts: Option<u64>` — timestamp of the last drained datagram

3. **`AudioPipeline::new()` constructor** (lines 97–99): Initialized the three new fields:
   - `jitter_buffer: VecDeque::new()`
   - `jitter_target_ms: 20` (one frame at 20ms frame duration)
   - `last_playback_ts: None`

4. **`buffer_incoming()` method** (lines 207–223): Pushes a received MoQ datagram into the jitter buffer.
   - Drops duplicates (same sequence number already present).
   - Inserts in ascending sequence order so the buffer is always sorted.

5. **`drain_buffer()` method** (lines 226–271): Drains datagrams ready for playback.
   - Converts `jitter_target_ms` to samples at 48kHz.
   - On first playback (no `last_playback_ts`), drains when buffer has ≥2 frames (minimum for jitter compensation).
   - On subsequent playbacks, drains a datagram when:
     - `last_playback_ts - front.timestamp >= jitter_target_samples` (enough hold-back time), OR
     - `now_ts - front.timestamp >= jitter_target_samples * 2` (safety valve to prevent unbounded delay)
   - Updates `last_playback_ts` after draining.
   - Returns datagrams in sequence order.

## Design notes

- The 20ms `jitter_target_ms` matches one Opus frame duration at 48kHz/20ms, providing one frame of jitter absorption while keeping added latency minimal.
- The `VecDeque` is kept sorted by sequence number on insertion, so `drain_buffer()` always processes from the front in playback order.
- The `now_ts` safety valve (`jitter_target_samples * 2`) prevents datagrams from being held indefinitely if the playback clock stalls.
