# Wave 4: Cross-Machine P2P QUIC — Local ↔ GitHub Codespace

## What was achieved

A real bidirectional P2P QUIC connection was established between the
local workspace (Debian 13) and a GitHub Codespace (Ubuntu 24.04),
exchanging a text message end-to-end.

```
Caller (local):
  Sent:     "ping-cross-machine"
  Received: "ack: 0"

Callee (codespace):
  [127.0.0.1:37627] said: ping-cross-machine
```

## The UDP-over-TCP tunnel problem

GitHub Codespaces only forwards TCP ports via `gh codespace ports forward`.
QUIC uses UDP. To carry QUIC packets across the codespace tunnel, a
custom UDP-over-TCP bridge (`scripts/udp_tcp_bridge.py`) was used on
both ends:

```
Local machine                       Codespace
─────────────                       ──────────
voip-cli call                       voip-cli listen
   ↓ UDP 4433                          ↑ UDP 4433
udp_tcp_bridge.py (client)          udp_tcp_bridge.py (server)
   ↓ TCP 4434 (frames)                 ↑ TCP 4434 (frames)
gh codespace ports forward  ←──────── TCP tunnel (SSH)
```

Each UDP datagram is wrapped in a 4-byte length-prefixed frame for
transit over the TCP stream. The frames are de-framed on the codespace
side and re-emitted as UDP datagrams to the local `voip-cli listen`.
QUIC connection IDs and packet payloads traverse the tunnel unchanged,
so the QUIC protocol layers run end-to-end.

This is NOT a production transport — the TCP tunnel defeats QUIC's
head-of-line-blocking benefits. But it proves the P2P protocol stack
works across machines, which was the Wave 4 goal.

## Reproduction

### On the codespace (via SSH):

```bash
# 1. Start the signaling server
RUST_LOG=warn /workspaces/three-pillars-voip/target/debug/voip-signaling-server &

# 2. Init callee identity and start listening
HOME=/tmp/callee /workspaces/three-pillars-voip/target/debug/voip-cli init
HOME=/tmp/callee /workspaces/three-pillars-voip/target/debug/voip-cli listen \
  http://127.0.0.1:8443 --listen 0.0.0.0:4433 &

# 3. Start the UDP↔TCP bridge in server mode
python3 /workspaces/three-pillars-voip/scripts/udp_tcp_bridge.py server \
  --tcp-listen 0.0.0.0:4434 --udp-connect 127.0.0.1:4433 &
```

### On the local machine:

```bash
# 4. Forward the codespace's TCP 4434 to local 4434
gh codespace ports forward 4434:4434 -c <codespace-name> &

# 5. Start the UDP↔TCP bridge in client mode
python3 scripts/udp_tcp_bridge.py client \
  --udp-listen 127.0.0.1:4433 --tcp-connect 127.0.0.1:4434 &

# 6. Start a local signaling server (or forward the codespace's)
RUST_LOG=warn ./target/debug/voip-signaling-server &

# 7. Place the call
voip-cli call http://127.0.0.1:8443 <callee-peer-id> \
  --direct-addr 127.0.0.1:4433 --message "ping-cross-machine"
```

Expected output (caller):
```
Sent:     "ping-cross-machine"
Received: "ack: 0"
Call complete.
```

Expected output (codespace callee log):
```
[127.0.0.1:<port>] said: ping-cross-machine
```

## Why not direct UDP?

GitHub Codespaces does not expose UDP to the public internet — only
TCP via `gh codespace ports forward`. The codespace's public hostname
(`*.app.github.dev`) is a TCP-only reverse proxy.

For true cross-machine UDP/QUIC, you would need:
- A VPS with a public IP (Oracle Free Tier works — this is actually
  the production target per spec/11 §11.10)
- Or a UDP-capable tunnel (WireGuard, Tailscale, etc.)
- Or the production DHT + MASQUE relay architecture (spec/06, spec/12)

The Wave 4 tunnel is a development convenience to prove the protocol
stack works across machines without needing a VPS.
