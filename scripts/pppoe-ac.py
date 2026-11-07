#!/usr/bin/env python3
"""A stand-in for a PPPoE access concentrator's data plane, for the netns test:
frames of one PPPoE session on `link` are taken out of the session and written to
a TUN device; IP packets from the TUN device are put into the session and sent to
the router. No Discovery or PPP control: the session is fixed.

Usage: pppoe-ac.py LINK TUN SESSION ROUTER_MAC"""
import fcntl, os, select, socket, struct, sys

link, tun_name, session, router = sys.argv[1], sys.argv[2], int(sys.argv[3], 0), sys.argv[4]
router_mac = bytes.fromhex(router.replace(":", ""))
raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x8864))
raw.bind((link, 0))
own_mac = raw.getsockname()[4]
tun = os.open("/dev/net/tun", os.O_RDWR)
# TUNSETIFF with IFF_TUN | IFF_NO_PI.
fcntl.ioctl(tun, 0x400454CA, struct.pack("16sH", tun_name.encode(), 0x0001 | 0x1000))
sys.stdout.write("ready\n"); sys.stdout.flush()
while True:
    ready, _, _ = select.select([raw, tun], [], [])
    if raw in ready:
        frame = raw.recv(2048)
        if len(frame) >= 22 and frame[12:14] == b"\x88\x64" and frame[14:16] == b"\x11\x00" \
                and struct.unpack("!H", frame[16:18])[0] == session \
                and frame[20:22] in (b"\x00\x21", b"\x00\x57"):
            length = struct.unpack("!H", frame[18:20])[0]
            os.write(tun, frame[22:20 + length])
    if tun in ready:
        packet = os.read(tun, 2048)
        protocol = b"\x00\x21" if packet[0] >> 4 == 4 else b"\x00\x57"
        header = struct.pack("!BBHH", 0x11, 0, session, len(packet) + 2) + protocol
        raw.send(router_mac + own_mac + b"\x88\x64" + header + packet)
