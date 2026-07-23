#!/usr/bin/env python3
"""Bidirectional UDP↔TCP bridge with length-prefixed framing.

Two modes:
  client (default): UDP listen ↔ TCP connect
    Used on the local machine: local QUIC peer sends UDP to this bridge,
    bridge frames the datagrams and sends over TCP to the codespace.

  server: TCP listen ↔ UDP connect
    Used on the codespace: TCP connection arrives from the port forward,
    bridge de-frames and sends UDP datagrams to the local QUIC listener.

Frame format: 4-byte big-endian length + payload. This preserves UDP
datagram boundaries across the TCP stream.

Usage:
  # Local (client mode):
  python3 udp_tcp_bridge.py client --udp-listen 127.0.0.1:4433 --tcp-connect 127.0.0.1:4434

  # Codespace (server mode):
  python3 udp_tcp_bridge.py server --tcp-listen 0.0.0.0:4434 --udp-connect 127.0.0.1:4433
"""
import argparse
import asyncio
import struct
import sys


async def read_exact(reader, n):
    data = b""
    while len(data) < n:
        chunk = await reader.read(n - len(data))
        if not chunk:
            raise ConnectionError("EOF before n bytes")
        data += chunk
    return data


class UDPClientProtocol(asyncio.DatagramProtocol):
    """UDP peer that talks to a local UDP socket (e.g. quinn listener)."""

    def __init__(self):
        self.peer_addr = None
        self.queue = asyncio.Queue()  # outgoing datagrams from UDP peer

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # Stash the peer's address so we know where to send replies
        self.peer_addr = addr
        # Queue this datagram for the TCP sender
        self.queue.put_nowait(data)


async def server_mode(tcp_listen, udp_connect):
    """TCP listen → UDP connect (codespace side)."""
    tcp_host, tcp_port = tcp_listen.split(":")
    udp_host, udp_port = udp_connect.split(":")

    print(f"[server] TCP {tcp_listen} ↔ UDP {udp_connect}", file=sys.stderr)

    async def handle_tcp_client(reader, writer):
        peer = writer.get_extra_info("peername")
        print(f"[server] TCP connection from {peer}", file=sys.stderr)
        # Set up UDP socket to talk to the local voip-cli listen
        loop = asyncio.get_running_loop()
        transport, udp_proto = await loop.create_datagram_endpoint(
            UDPClientProtocol,
            remote_addr=(udp_host, int(udp_port)),
        )
        # Spawn a task to forward UDP→TCP
        async def udp_to_tcp():
            while True:
                data = await udp_proto.queue.get()
                frame = struct.pack(">I", len(data)) + data
                try:
                    writer.write(frame)
                    await writer.drain()
                except Exception as e:
                    print(f"[server] TCP write failed: {e}", file=sys.stderr)
                    return
        task = asyncio.ensure_future(udp_to_tcp())
        # Main loop: TCP→UDP
        try:
            while True:
                len_bytes = await read_exact(reader, 4)
                (frame_len,) = struct.unpack(">I", len_bytes)
                if frame_len > 65535:
                    print(f"[server] frame too large: {frame_len}", file=sys.stderr)
                    return
                payload = await read_exact(reader, frame_len)
                transport.sendto(payload)
        except (ConnectionError, asyncio.IncompleteReadError) as e:
            print(f"[server] TCP closed: {e}", file=sys.stderr)
        finally:
            task.cancel()
            transport.close()
            writer.close()

    server = await asyncio.start_server(handle_tcp_client, tcp_host, int(tcp_port))
    print(f"[server] listening on {tcp_listen}", file=sys.stderr)
    async with server:
        await server.serve_forever()


async def client_mode(udp_listen, tcp_connect):
    """UDP listen → TCP connect (local side)."""
    udp_host, udp_port = udp_listen.split(":")
    tcp_host, tcp_port = tcp_connect.split(":")

    print(f"[client] UDP {udp_listen} ↔ TCP {tcp_connect}", file=sys.stderr)

    loop = asyncio.get_running_loop()
    transport, udp_proto = await loop.create_datagram_endpoint(
        UDPClientProtocol,
        local_addr=(udp_host, int(udp_port)),
    )
    print(f"[client] UDP listening on {udp_listen}", file=sys.stderr)

    # Wait for the first UDP datagram to arrive, then open TCP
    print("[client] waiting for first UDP datagram...", file=sys.stderr)
    first_data = await udp_proto.queue.get()
    print(f"[client] first datagram received, opening TCP to {tcp_connect}", file=sys.stderr)

    reader, writer = await asyncio.open_connection(tcp_host, int(tcp_port))
    print("[client] TCP connected", file=sys.stderr)

    # Send the first datagram
    frame = struct.pack(">I", len(first_data)) + first_data
    writer.write(frame)
    await writer.drain()

    # Spawn UDP→TCP pump
    async def udp_to_tcp():
        while True:
            data = await udp_proto.queue.get()
            frame = struct.pack(">I", len(data)) + data
            try:
                writer.write(frame)
                await writer.drain()
            except Exception as e:
                print(f"[client] TCP write failed: {e}", file=sys.stderr)
                return

    task = asyncio.ensure_future(udp_to_tcp())

    # Main loop: TCP→UDP
    try:
        while True:
            len_bytes = await read_exact(reader, 4)
            (frame_len,) = struct.unpack(">I", len_bytes)
            if frame_len > 65535:
                print(f"[client] frame too large: {frame_len}", file=sys.stderr)
                break
            payload = await read_exact(reader, frame_len)
            if udp_proto.peer_addr is not None:
                transport.sendto(payload, udp_proto.peer_addr)
    except (ConnectionError, asyncio.IncompleteReadError) as e:
        print(f"[client] TCP closed: {e}", file=sys.stderr)
    finally:
        task.cancel()
        transport.close()
        writer.close()


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)

    p_client = sub.add_parser("client", help="UDP listen → TCP connect")
    p_client.add_argument("--udp-listen", default="127.0.0.1:4433")
    p_client.add_argument("--tcp-connect", default="127.0.0.1:4434")

    p_server = sub.add_parser("server", help="TCP listen → UDP connect")
    p_server.add_argument("--tcp-listen", default="0.0.0.0:4434")
    p_server.add_argument("--udp-connect", default="127.0.0.1:4433")

    args = parser.parse_args()

    try:
        if args.mode == "client":
            asyncio.run(client_mode(args.udp_listen, args.tcp_connect))
        else:
            asyncio.run(server_mode(args.tcp_listen, args.udp_connect))
    except KeyboardInterrupt:
        print("\n[bridge] shutting down", file=sys.stderr)


if __name__ == "__main__":
    main()
