# 10. Data Persistence

> Part of: Three Pillars VoIP Relay-Free Architecture Specification (TS-2025-001 v8.0)

---

## 10.1 Signaling Server State

### 10.1.1 Peer Registry

(Same as v6.0 — in-memory, no disk writes, 5 min idle timeout.)

Added field: `fcm_token` for push notification delivery.

### 10.1.2 Active Calls

(Same as v6.0 — in-memory, discarded when call reaches CONNECTED.)

### 10.1.3 What the Signaling Server Does NOT Store

(Same as v6.0. Never stores: media, session keys, call history, port predictions, NAT types.)

---

## 10.2 Client-Side Cache

### 10.2.1 NAT Probe Cache

| Data | Storage | TTL | Description |
|------|---------|-----|-------------|
| `NATProbeResult[]` | Local file (SQLite/JSON) | 5 minutes | Last QUIC path probe results |
| `NATPattern` | Local file | 5 minutes | Computed pattern (sequential/pseudo/random) |
| `NATPrediction` | Local file | 5 minutes | Current port prediction range |
| `external_ip` | Local file | 5 minutes | Last known external IPv4 |

**Cache invalidation triggers:**
- Network interface change (WiFi → cellular, new WiFi, etc.)
- TTL expiry (5 minutes)
- Application restart (full re-probe)
- Prediction mismatch (path probe refresh shows different pattern)

**Example cache file:**

```json
{
  "probes": [
    {"server_ip": "10.0.0.1", "local_port": 5000, "external_ip": "203.0.113.5", "external_port": 42000, "rtt_ms": 5},
    {"server_ip": "10.0.0.2", "local_port": 5000, "external_ip": "203.0.113.5", "external_port": 42001, "rtt_ms": 4},
    {"server_ip": "10.0.0.3", "local_port": 5000, "external_ip": "203.0.113.5", "external_port": 42002, "rtt_ms": 6},
    {"server_ip": "10.0.0.4", "local_port": 5000, "external_ip": "203.0.113.5", "external_port": 42003, "rtt_ms": 5},
    {"server_ip": "10.0.0.5", "local_port": 5000, "external_ip": "203.0.113.5", "external_port": 42004, "rtt_ms": 4}
  ],
  "pattern": {
    "type": "SEQUENTIAL",
    "average_delta": 1,
    "delta_variance": 0,
    "base_port": 42004
  },
  "prediction": {
    "external_ip": "203.0.113.5",
    "port_start": 42005,
    "port_end": 42011,
    "confidence": "SEQUENTIAL"
  },
  "nat_type": "NAT_SYMMETRIC_SEQUENTIAL",
  "cached_at": 1715673600,
  "cache_ttl_seconds": 300
}
```

### 10.2.2 Peer Address Book

(Same as v6.0. Added: `last_discovery_method` field tracking DHT vs signaling.)

### 10.2.3 QUIC Session Tickets

(Same as v6.0. No changes.)

### 10.2.4 MASQUE Proxy Cache

| Data | Storage | TTL | Description |
|------|---------|-----|-------------|
| ProxyRecord[] | Local file (SQLite) | 1 hour | Discovered MASQUE proxy nodes |
| Last used proxy | Local file | 24 hours | URL of last successful MASQUE proxy |

---

## 10.3 Session & Key Material

(Same as v6.0. TLS 1.3 keys, Connection IDs, Track Aliases — all in-memory only.)

---

## 10.4 No Server-Side Media Persistence

(Same as v6.0. Design principle, not implementation detail.)

---

## 10.5 Data Lifecycle Summary

| Data | Where | Persisted? | TTL | Cleared When |
|------|-------|-----------|-----|-------------|
| Peer registry | Signaling server (memory) | No | 5 min idle | Server restart, idle timeout |
| Active calls | Signaling server (memory) | No | 30 min max | Call ends or times out |
| FCM tokens | Signaling server (memory) | No | 5 min idle | Server restart, peer unregister |
| NAT probe results | Client (local file) | Yes | 5 min | TTL, network change, app restart |
| NAT prediction | Client (local file) | Yes | 5 min | TTL, network change, app restart |
| Peer address book | Client (SQLite) | Yes | Persistent | User deletion |
| DHT routing table | Client (memory, desktop only) | No | Session | App close |
| QUIC session tickets | Client (keychain) | Yes | 24 hours | Expiry, connection error |
| TLS session keys | Client (memory) | No | Call duration | QUIC connection closes |
| Connection IDs | Client (memory) | No | Call duration | QUIC connection closes |
| Track aliases | Client (memory) | No | Session duration | MoQ session closes |
| Media packets | Never stored | N/A | N/A | Never stored anywhere |
