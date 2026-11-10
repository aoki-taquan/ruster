#!/usr/bin/env python3
"""A stand-in for the FE's punt of PPPoE control, for the netns test of
ruster-pppoed: PPPoE Discovery frames and PPP control frames (protocol 0x8000 and
up) received on `link` go to `<run>/pppoed/punt.sock` with the punt header
(crates/proto/src/punt.rs), as the FE would send them from
`<run>/fe/punt/pppoed.sock`; frames pppoed sends back are sent out of `link`.

Usage: pppoe-punt-bridge.py LINK RUN_DIR"""
import os, select, socket, struct, sys

link, run = sys.argv[1], sys.argv[2]
DISCOVERY, CONTROL = 4, 5
TO_CONTROL, FROM_CONTROL = 1, 2
PACKET_OUTGOING = 4

raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
raw.bind((link, 0))
os.makedirs(os.path.join(run, "fe", "punt"), mode=0o700, exist_ok=True)
here = os.path.join(run, "fe", "punt", "pppoed.sock")
if os.path.exists(here):
    os.unlink(here)
punt = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
punt.bind(here)
peer = os.path.join(run, "pppoed", "punt.sock")
name = link.encode()
sys.stdout.write("ready\n"); sys.stdout.flush()
while True:
    ready, _, _ = select.select([raw, punt], [], [])
    if raw in ready:
        frame, address = raw.recvfrom(2048)
        if address[2] == PACKET_OUTGOING or len(frame) < 14:
            continue
        kind = frame[12:14]
        why = None
        if kind == b"\x88\x63":
            why = DISCOVERY
        elif kind == b"\x88\x64" and len(frame) >= 22 and frame[14:16] == b"\x11\x00" \
                and struct.unpack("!H", frame[20:22])[0] >= 0x8000:
            why = CONTROL
        if why is not None:
            message = struct.pack("!BBHB", 1, TO_CONTROL, why, len(name)) + name + frame
            try:
                punt.sendto(message, peer)
            except OSError:
                pass
    if punt in ready:
        message, sender = punt.recvfrom(4096)
        if sender != peer or len(message) < 5:
            continue
        version, direction, why, length = struct.unpack("!BBHB", message[:5])
        if version != 1 or direction != FROM_CONTROL or why not in (DISCOVERY, CONTROL):
            continue
        if message[5:5 + length] != name:
            continue
        raw.send(message[5 + length:])
