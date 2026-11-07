#!/usr/bin/env python3
"""A stand-in for a WireGuard peer's data plane, for the netns test: WireGuard data
messages (type 4) on a UDP port are opened with the session's receive key and
written to a TUN device; IP packets from the TUN device are sealed with its send
key and sent to the router. No handshake: the session keys are fixed, the same
the router's file gives. The ChaCha20-Poly1305 is OpenSSL's (python-cryptography),
so it checks the router's own implementation.

It pads as Linux does (to a multiple of 16, but never past the MTU), refuses
messages that do not come from the router's address and port, and writes one
line per message it opens ("opened") and per one it refuses ("drop: why").

Usage: wg-peer.py LOCAL_ADDR LOCAL_PORT ROUTER_ADDR ROUTER_PORT TUN
       SEND_KEY_HEX RECEIVE_KEY_HEX PEER_INDEX LOCAL_INDEX MTU"""
import fcntl, os, select, socket, struct, sys
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

(local, local_port, router, router_port, tun_name, send_hex, receive_hex,
 router_index, own_index, mtu) = sys.argv[1:11]
mtu = int(mtu)
send_key = ChaCha20Poly1305(bytes.fromhex(send_hex))
receive_key = ChaCha20Poly1305(bytes.fromhex(receive_hex))
router_index, own_index = int(router_index), int(own_index)

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind((local, int(local_port)))
tun = os.open("/dev/net/tun", os.O_RDWR)
fcntl.ioctl(tun, 0x400454CA, struct.pack("16sH", tun_name.encode(), 0x0001 | 0x1000))
sys.stdout.write("ready\n"); sys.stdout.flush()

counter = 0
seen = set()


def log(line):
    sys.stdout.write(line + "\n"); sys.stdout.flush()


while True:
    ready, _, _ = select.select([udp, tun], [], [])
    if udp in ready:
        message, sender = udp.recvfrom(2048)
        if sender != (router, int(router_port)):
            log(f"drop: from {sender}")
            continue
        if len(message) < 32 or message[0] != 4 or message[1:4] != b"\0\0\0":
            log("drop: not a data message")
            continue
        index, n = struct.unpack("<IQ", message[4:16])
        if index != own_index:
            log(f"drop: receiver index {index}")
            continue
        if n in seen:
            log(f"drop: counter {n} again")
            continue
        try:
            plain = receive_key.decrypt(b"\0\0\0\0" + struct.pack("<Q", n), message[16:], None)
        except Exception:
            log("drop: bad tag")
            continue
        seen.add(n)
        log("opened")
        if plain and plain[0] >> 4 == 4:
            total = struct.unpack("!H", plain[2:4])[0]
            os.write(tun, plain[:total])
    if tun in ready:
        packet = os.read(tun, 2048)
        # As Linux's calculate_skb_padding: a multiple of 16, capped at the MTU.
        padded = packet + b"\0" * (min(mtu, len(packet) + (-len(packet) % 16)) - len(packet))
        body = send_key.encrypt(b"\0\0\0\0" + struct.pack("<Q", counter), padded, None)
        header = b"\x04\0\0\0" + struct.pack("<IQ", router_index, counter)
        counter += 1
        udp.sendto(header + body, (router, int(router_port)))
