# 3. Pillar 2: QUIC-Native NAT Traversal — Cone NAT + Port Prediction

> Part of: Three Pillars VoIP Minimal-Relay Architecture Specification (TS-2025-001 v8.0)  
> See also: [Architecture Overview](01_Architecture_Overview.md) | [Data Flows: NAT Traversal](09_Data_Flows.md) | [API: QUIC Connection Management](08_API_Specification.md)

---

## 3.1 The Problem

For the ~55% of connections where both endpoints are IPv4-only, the NAT traversal problem remains:

- **Cone NAT (~60% of IPv4 NATs):** The external address is destination-independent. QUIC simultaneous open (PATH_CHALLENGE) works trivially. Not a problem.
- **Symmetric NAT (~40% of IPv4 NATs):** The external address is different for each destination. The address observed by one path is wrong when talking to the peer. This is the hard problem that port prediction solves.

**This entire pillar uses QUIC-native mechanisms. There is no STUN protocol. There is no ICE. There is no separate UDP protocol for NAT observation.** The signaling server's QUIC endpoint with 5 elastic IPs serves as the probing target, and QUIC PATH_CHALLENGE/PATH_RESPONSE serves as both the probing mechanism and the hole-punching mechanism.

---

## 3.2 How QUIC Replaces STUN

Every function STUN Binding provides is replaced by QUIC path probing:

| STUN Mechanism | QUIC-Native Replacement | How |
|----------------|------------------------|-----|
| Binding Request (tell me my address) | QUIC connection migration to signaling server IP | Client migrates QUIC connection to each of 5 server IPs, server sees source IP:port |
| Binding Response (here's your address) | Application-level address reflection on QUIC stream | Server sends observed IP:port back on the existing QUIC stream |
| Multiple probes (NAT classification) | Connection migration to 5 different server IPs | Same 5-probe strategy, but over QUIC instead of raw UDP |
| Keep-alive (keep NAT mapping open) | QUIC PING frames | Already built into QUIC, no separate mechanism |
| Hole punching (open NAT for peer) | QUIC PATH_CHALLENGE | Packet that punches hole IS the QUIC connection setup — encrypted, validated by Connection ID |

**Key advantage:** With STUN, you punch the NAT hole with raw UDP, then start a QUIC connection. Two phases. With QUIC-native, the PATH_CHALLENGE that punches the hole IS the QUIC connection setup packet. One step. The first packet through the NAT is already encrypted and already part of the QUIC handshake.

---

## 3.3 The Insight: Symmetric NATs Are Predictable

Most Symmetric NATs allocate external ports **sequentially**. When you send packets to different destinations from the same local port, the NAT assigns incrementing external port numbers:

```
Probe signaling-IP-1 from local port 5000 → external port 42000
Probe signaling-IP-2 from local port 5000 → external port 42001
Probe signaling-IP-3 from local port 5000 → external port 42002
Probe signaling-IP-4 from local port 5000 → external port 42003
Probe signaling-IP-5 from local port 5000 → external port 42004

Pattern: delta = +1 per new destination

Predict: when I send to my VoIP peer from port 5000,
my external port will be ~42005 ± 2
```

This is **observation of your own NAT's behavior**, not probing someone else's network. You send QUIC packets to the signaling server (which you're already connected to) and observe the pattern. No port scanning. No grey zone. Completely legal under every jurisdiction.

---

## 3.4 How Common Is Sequential Allocation?

| NAT Type | Allocation Pattern | % of Symmetric NATs | Port Prediction Works? |
|----------|--------------------|---------------------|------------------------|
| Home router (consumer) | Sequential (+1 or +2 per mapping) | ~50% | **YES** |
| CGNAT (ISP-level) | Pseudo-sequential (within a range, +1 to +5) | ~25% | **YES** (with wider margin) |
| Enterprise firewall | Random | ~15% | **NO** |
| Strict CGNAT | Random with small port range | ~10% | **NO** |

**Estimated: ~60% of Symmetric NATs have predictable allocation.** Port prediction works for these. The remaining ~40% (random allocation) are the cases where the call will fail without relay — an honest limitation.

---

## 3.5 The 5-Step Algorithm (QUIC-Native)

### Step 1: PROBE (QUIC path probing)

```
Client already has QUIC connection to signaling server.
Signal server has 5 elastic IPs: IP_1, IP_2, IP_3, IP_4, IP_5.

For each IP_n in [IP_1..IP_5]:
  Migrate QUIC connection to IP_n (PATH_CHALLENGE on new path)
  Server sees source IP:port from client
  Server reflects observed address on QUIC stream:
    "I see you as 203.0.113.5:4200{n}"

Cost: 5 QUIC path migrations + 5 application messages = ~50ms
No separate protocol. No separate port. Same QUIC connection.
```

### Step 2: ANALYZE

```
Compute deltas: external_port[i+1] - external_port[i]
- If deltas are constant (e.g., all +1):       SEQUENTIAL → accuracy ±1-2
- If deltas are bounded (e.g., +1 to +5):      PSEUDO-SEQUENTIAL → accuracy ±5-8
- If deltas are random (e.g., +347, -2891):    RANDOM → prediction fails
```

### Step 3: PREDICT

```
predicted_port = last_known_port + (delta_pattern × estimated_new_mappings)
estimated_new_mappings = number of other connections between probe and call
(typically 0-3 for a VoIP app that just opened)
Signal a RANGE: predicted_port ± margin
  margin = 3 for SEQUENTIAL (range of 7 ports)
  margin = 8 for PSEUDO-SEQUENTIAL (range of 17 ports)
  margin = NONE for RANDOM (do not attempt prediction)
```

### Step 4: SIGNAL

```
Exchange predicted ranges with peer via signaling server or DHT
A signals: "my predicted range is 203.0.113.5:42004-42010"
B signals: "my predicted range is 198.51.100.7:31007-31013"
```

### Step 5: CONNECT (QUIC hole punching)

```
A sends QUIC PATH_CHALLENGE to B's predicted range (7-17 packets)
B sends QUIC PATH_CHALLENGE to A's predicted range (7-17 packets)
Each PATH_CHALLENGE:
  → Punches through the NAT (opens the mapping)
  → Is already part of the QUIC protocol (encrypted, Connection ID validated)
  → Establishes the connection in the same step as punching the hole

When a PATH_CHALLENGE arrives at the correct predicted port:
  → NAT forwards to internal host
  → Host validates Connection ID → this is the expected peer
  → Sends PATH_RESPONSE directly to source address
  → NAT allows response (matches outbound mapping)

Direct P2P established. One step: punch + connect.
```

---

## 3.6 Accuracy Analysis

### Sequential NAT (+1 delta)

- After 5 path probes, the next allocation is known to ±1-2 ports
- With margin of ±3, the predicted range is 7 ports
- Each side sends 7 QUIC PATH_CHALLENGE packets → 49 possible combinations
- Probability of match: ~95%+
- Total probing traffic: 7 packets × ~120 bytes = 840 bytes per side

### Pseudo-sequential NAT (+1 to +5 delta)

- After 5 path probes, average delta is known but variable
- Prediction accuracy: ±5-8 ports
- With margin of ±8, predicted range is 17 ports
- Each side sends 17 QUIC PATH_CHALLENGE packets → 289 possible combinations
- Probability of match: ~80%+
- Total probing traffic: 17 packets × ~120 bytes = 2KB per side

### Random NAT

- Prediction fails. No pattern detected. Do NOT attempt prediction.
- Do NOT fall back to birthday attacks or port spraying (grey zone).
- The call fails for this connection. Push notification sent for retry.
- This is an honest failure.

---

## 3.7 Cone NAT Handling (QUIC Simultaneous Open)

When both sides are IPv4 but at least one has Cone NAT (Full-Cone or Restricted-Cone), the connection is straightforward:

```
A (behind Cone NAT): QUIC path probe reveals external address 203.0.113.5:42000
  → This address is valid for ALL destinations (that's what Cone means)
  → B can send to 203.0.113.5:42000 and it will arrive

B (behind any NAT): sends QUIC PATH_CHALLENGE to A's observed address
A (Cone NAT): receives it, validates Connection ID, sends PATH_RESPONSE to B's source address
B's NAT: allows response (matches outbound mapping)
Connection established.
```

No port prediction needed. QUIC simultaneous open (both sides send PATH_CHALLENGE at the same time) handles the case where both are behind Cone NAT.

---

## 3.8 Legal Analysis

Port prediction via QUIC path probing involves three actions:

1. **Migrating a QUIC connection to the signaling server's different IPs.** This is standard QUIC connection migration — a core protocol feature defined in RFC 9000. The signaling server is a server you're already connected to. No unauthorized access.

2. **Observing your own NAT's port allocation pattern.** You are observing the behavior of YOUR OWN network equipment. The port numbers are YOUR addresses, assigned by YOUR NAT. This is like noticing your own house number. No unauthorized access. No circumvention of security. The IETF explicitly states (RFC 2993) that NAT is address translation, not a security measure.

3. **Sending 7-17 QUIC PATH_CHALLENGE packets to a consenting peer's predicted address range.** Both parties consent to the connection attempt. The number of packets (7-17) is far below any threshold that would be flagged as port scanning (which typically involves thousands of probes across a wide range). This is indistinguishable from a normal connection retry pattern.

**None of the three elements of § 202a StGB (German Law) are met:**
- "Unbefugt" (unauthorized): Both parties authorize the connection. ✗
- "Nicht für ihn bestimmte Daten" (data not meant for him): The port IS meant for the peer — both parties are trying to connect. ✗
- "Besonders gesichert" (specially secured): NAT is not a security measure (RFC 2993). ✗

No IDS/IPS will flag 7-17 QUIC packets to a specific IP as a port scan. Normal web browsers routinely send more packets than this during page loads.

---

## 3.9 Failed Connection: Push Notification Retry

When port prediction fails (both peers behind random Symmetric NAT), instead of silently failing:

1. **Push notification sent to peer:** "Alice tried to call you but direct connection failed. Tap to retry."
2. **Auto-retry on network change:** When the peer's network changes (NAT rebinding, WiFi switch, cellular handover), the app automatically re-probes its NAT and retries the connection.
3. **Scheduled retry:** "Connection failed. Retrying in 5 seconds..." with exponential backoff (5s, 15s, 45s, then give up).

This is NOT a relay. The retry still uses direct P2P. The push notification just triggers the peer to re-attempt the QUIC connection when conditions may have changed.

---

## 3.10 Performance Claims with Evidence

**Claim: Port prediction works for ~60% of Symmetric NATs.**
- Evidence: Tailscale uses port prediction in production (documented in engineering blog). Ford et al. (IETF RFC 5128, 2008) document NAT port allocation behavior — most consumer NAT implementations use sequential allocation. The 60% estimate is conservative, including pseudo-sequential CGNAT.
- For the ~40% of Symmetric NATs with random allocation, prediction fails honestly. Push notification retry gives a second chance without relay.

**Claim: QUIC-native probing replaces STUN with no loss of functionality.**
- Evidence: QUIC PATH_CHALLENGE/PATH_RESPONSE (RFC 9000 §9) provides the same address-reflection capability as STUN Binding. The signaling server sees the client's source IP:port on each path migration, identical to what a STUN server would observe. The NAT classification algorithm is the same regardless of whether the probe comes from STUN or QUIC.
