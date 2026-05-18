# 2. Pillar 1: IPv6 — NAT Elimination

> Part of: Three Pillars VoIP Minimal-Relay Architecture Specification (TS-2025-001 v8.0)  
> See also: [Architecture Overview](01_Architecture_Overview.md) | [Data Flows: IPv6 Direct](09_Data_Flows.md)

---

## 2.1 The Insight

IPv6 gives every device a globally routable address. When at least one VoIP endpoint has IPv6, NAT traversal is unnecessary for that side. The IPv6 endpoint is directly reachable from anywhere on the Internet. The other side — even if behind Symmetric NAT — sends a packet to the IPv6 address, and the IPv6 endpoint responds to the source address. The IPv4 NAT allows the response because it comes from the exact destination the IPv4 endpoint sent to, which matches the NAT's outbound mapping.

This is not a traversal technique — it is the **elimination of the problem itself**.

---

## 2.2 Current Deployment

| Region / Metric | IPv6 Adoption | Source |
|-----------------|---------------|--------|
| Global (Google) | ~45% | Google IPv6 Statistics |
| T-Mobile US (mobile) | 90%+ | APNIC Labs |
| Reliance Jio (mobile) | >92% | APNIC Labs |
| India (overall) | ~62% | APNIC Labs |
| Germany | ~52% | APNIC Labs |
| US (overall) | ~50% | APNIC Labs |
| Enterprise | ~30-40% | Estimated |

**Important:** The global average of ~45% is the correct figure for coverage calculations. The 70%+ figures cited for some markets (US mobile, India) are regional peaks, not global baselines. Using Google's measurement (which tracks actual IPv6 usage across all Google services globally), approximately 45% of Internet connections have IPv6 as of early 2025.

---

## 2.3 How It Eliminates Relay

### When both endpoints have IPv6 (~10% of connections)

Direct QUIC connection. No NAT. No path probing. No simultaneous open. The QUIC connection is established in 1 RTT to the peer's IPv6 address. The only failure mode is a stateful IPv6 firewall that blocks inbound connections — but even then, the firewall allows responses to outbound connections, so at least one side can initiate and the other responds.

### When one endpoint has IPv6 (~35% of connections)

This is the critical insight that is often overlooked. When at least one side has IPv6, the connection ALWAYS works, regardless of the other side's NAT type. Here is the exact mechanism for the hardest case — one IPv6, one IPv4 Symmetric NAT with random allocation:

```
Step 1: B (IPv4, Symmetric NAT) sends a QUIC Initial to A's IPv6 address
  → B's Symmetric NAT creates a mapping: internal B:5000 → external B:42837
    for destination [A's IPv6 address]
  → The mapping allows inbound FROM [A's IPv6 address] TO B:42837

Step 2: A (IPv6) receives the QUIC Initial from B's external address
  → A sees the source address: 198.51.100.7:42837

Step 3: A sends a QUIC response to 198.51.100.7:42837
  → The response arrives at B's Symmetric NAT
  → Source of the response: [A's IPv6 address] — this is the EXACT destination
    that B sent to in Step 1
  → Symmetric NAT rule: allow inbound from the destination that the outbound was sent to
  → MATCH. Packet allowed through. Connection established.
```

The key: A's IPv6 address is the DESTINATION of B's outbound packet, so B's Symmetric NAT allows A's response. This works for ALL Symmetric NAT types — sequential, random, doesn't matter — because the Symmetric NAT's own rule (allow responses from the destination you sent to) is what makes it work.

> **This means: for the ~45% of connections where at least one side has IPv6, the relay problem does not exist. Full stop.**

---

## 2.4 Combined Coverage

- Both IPv6: ~10% of connections → direct P2P
- One IPv6, one IPv4 (any NAT type): ~35% of connections → direct P2P
- **Total from IPv6 alone: ~45% of connections are direct P2P**

---

## 2.5 Implementation Steps

1. VoIP client queries OS for IPv6 addresses on all interfaces (standard API: `getaddrinfo` on Linux/macOS, `NetworkInterface` on Android, `NWPathMonitor` on iOS)
2. **Fast-path:** Before probing NAT, client calls `GET /v1/myip` on signaling server. If signaling server sees an IPv6 address, the client has IPv6. Skip NAT probing entirely. Saves ~50ms and 5 probe packets.
3. Client registers its IPv6 address in the signaling record (or DHT)
4. When placing a call, client attempts QUIC connection to peer's IPv6 address first (Happy Eyeballs v2, RFC 8305, gives IPv6 a 25ms head start over IPv4)
5. If IPv6 succeeds: direct P2P. Done.
6. If IPv6 fails (peer has no IPv6, or IPv6 connectivity broken): fall back to Pillar 2 (QUIC-Native NAT Traversal) on IPv4.

**Required:** QUIC library with Happy Eyeballs v2 support (quinn, quiche, s2n-quic all have this). No infrastructure changes. No special hardware. No relay servers.

---

## 2.6 IPv6 Privacy Extensions

Devices using temporary IPv6 addresses (RFC 4941) must register their current temporary address in the signaling record or DHT before each call. The signaling exchange takes ~100ms. This is already how QUIC with connection migration works — the address may change, but the Connection ID remains stable.

---

## 2.7 Performance Claims with Evidence

**Claim: IPv6 eliminates NAT for ~45% of connections globally.**
- Evidence: ~45% IPv6 adoption (Google IPv6 Stats, Q1 2025). P(at least one side IPv6) = 1 - 0.55² = ~70%. However, not all IPv6 connections succeed due to firewalls and broken IPv6 paths. Conservative effective coverage: ~45% of all connections have at least one working IPv6 endpoint.
- When at least one side has IPv6, the IPv6 endpoint is directly reachable. The IPv4 side's Symmetric NAT allows responses from the IPv6 destination. This works for ALL NAT types on the IPv4 side.
