# 5. Media Layer: Media over QUIC (MoQ)

> Part of: Three Pillars VoIP Relay-Free Architecture Specification (TS-2025-001 v8.0)  
> See also: [Architecture Overview](01_Architecture_Overview.md) | [Pillar 3: QUIC](04_Pillar3_QUIC.md) | [Data Model: Track Objects](07_Data_Model.md) | [API: Client MoQ Interface](08_API_Specification.md)

---

## 5.1 Why MoQ, Not Custom Media Over Raw QUIC

A previous version of this architecture proposed implementing media management directly on raw QUIC datagrams — custom track management, custom priority queuing, custom codec negotiation. This works, but it reinvents what MoQ already standardizes:

- **Track management:** MoQ's subscribe/publish model provides a clean abstraction for audio tracks, video tracks, and screen share — each a named "track" with a namespace. No custom schema needed.
- **Priority queuing:** MoQ defines per-priority send ordering — audio packets always go before video, keyframes before delta frames. This is exactly what VoIP needs and it's already specified.
- **Codec negotiation:** MoQ track parameters encode codec, bitrate, and encoding info in the track namespace. No separate SDP-style negotiation round.
- **Future multi-party:** MoQ's relay model (MoQ relay) provides a standardized, privacy-preserving relay for group calls, conferencing, and recording. Building this from scratch would duplicate effort and likely introduce mistakes.
- **Ecosystem compatibility:** MoQ is being adopted by major real-time communication platforms. Using MoQ means compatibility with this ecosystem rather than building a silo.

---

## 5.2 MoQ Specification Status

Media over QUIC is currently at `draft-ietf-moq-transport-17`. While not yet an RFC, the core mechanics are stable at this stage of the IETF process:

- **Pub/sub model:** Stable since draft-05
- **Track namespace:** Stable since draft-08
- **Datagram delivery:** Stable (built on RFC 9221)
- **Priority:** Stable since draft-10
- **MoQ relay model:** Maturing in recent drafts

At draft-17, the IETF rough consensus on core design is established. Breaking changes to fundamental mechanics are unlikely. The risk of significant rework is low and manageable.

---

## 5.3 How MoQ Fits the Architecture

| Architecture Function | MoQ Mechanism | Benefit |
|-----------------------|---------------|---------|
| Audio track delivery | MoQ track (subscribe + datagrams) | Standardized pub/sub replaces custom media framing |
| Codec negotiation | Track namespace parameters | No SDP-style round, codec info in track name |
| Priority (audio > video > screen) | MoQ send ordering priorities | Audio packets always transmitted first |
| Quality reports | MoQ feedback messages | Replaces RTCP with standardized feedback |
| Future: group calls | MoQ relay | Privacy-preserving relay for multi-party |
| Future: recording | MoQ relay (subscribe to track) | Standardized recording without custom protocol |

---

## 5.4 MoQ Connection Flow (Integrated with Three Pillars)

```
1. QUIC handshake (1 RTT) — Pillar 3 provides transport + encryption
2. MoQ session setup on QUIC connection — client announces tracks
3. Peer subscribes to audio track — MoQ subscribe message
4. Media flows as MoQ datagrams — same unreliable, unordered delivery
5. Quality feedback via MoQ — replaces RTCP
6. Network change → QUIC connection migration — MoQ session continues
```

The MoQ layer sits entirely on top of QUIC. The Three Pillars (IPv6, QUIC-Native NAT Traversal, QUIC transport) handle connectivity. MoQ handles what rides on top of that connectivity: track management, prioritization, codec negotiation, and media delivery patterns. Clean separation of concerns.

---

## 5.5 MoQ Track Namespace Convention

For VoIP, the following track namespace convention is used:

```
voip/{peer_id}/audio/opus-48k
voip/{peer_id}/video/vp9-720p
voip/{peer_id}/screen/vp9-1080p
```

Where:
- `voip` is the top-level namespace for this VoIP application
- `{peer_id}` is the unique peer identifier (matches signaling server or DHT peer ID)
- `audio` / `video` / `screen` are the media types
- `opus-48k` / `vp9-720p` / `vp9-1080p` encode codec and parameters

The track alias is a local 4-byte identifier assigned at subscription time, used in datagram headers for efficient demultiplexing.

---

## 5.6 MoQ Priority Values

| Priority | Media Type | Rationale |
|----------|-----------|-----------|
| 0 (highest) | Audio | Voice is the critical path; any audio gap is immediately perceptible |
| 1 | Video keyframe | Keyframes enable decoder reset after packet loss |
| 2 | Video delta | Delta frames are important but less critical than keyframes |
| 3 (lowest) | Screen share | Loss-tolerant, lower refresh rate is acceptable |

---

## 5.7 Performance Claims with Evidence

**Claim: MoQ provides standardized media management without custom reinvention.**
- Evidence: draft-ietf-moq-transport-17 defines pub/sub track management, priority queuing, and relay model. Core mechanics stable since draft-10+. Adopted by major streaming platforms.
