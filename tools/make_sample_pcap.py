#!/usr/bin/env python3
"""Generate a sample pcap with ECHONET Lite frames (no external libraries)."""
import struct
import sys
import time

CTRL = "192.168.1.10"
DEV = "192.168.1.20"
MCAST = "224.0.23.0"


def ip2b(ip):
    return bytes(int(x) for x in ip.split("."))


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def frame(src, dst, payload, sport=3610, dport=3610):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    pseudo = ip2b(src) + ip2b(dst) + struct.pack("!BBH", 0, 17, len(udp))
    c = csum(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", c) + udp[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0,
                     ip2b(src), ip2b(dst))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    if dst.startswith("224."):
        o = [int(x) for x in dst.split(".")]
        dmac = bytes([0x01, 0x00, 0x5E, o[1] & 0x7F, o[2], o[3]])
    else:
        dmac = bytes.fromhex("020000000002")
    eth = dmac + bytes.fromhex("020000000001") + b"\x08\x00"
    return eth + ip + udp


def el(tid, seoj, deoj, esv, props, props2=None):
    """props: list of (epc, edt_bytes). props2: Get list for SetGet."""
    b = bytes([0x10, 0x81]) + struct.pack("!H", tid) + bytes.fromhex(seoj) + bytes.fromhex(deoj)
    b += bytes([esv, len(props)])
    for epc, edt in props:
        b += bytes([epc, len(edt)]) + edt
    if props2 is not None:
        b += bytes([len(props2)])
        for epc, edt in props2:
            b += bytes([epc, len(edt)]) + edt
    return b


def bitmap_map(epcs):
    bm = bytearray(16)
    for e in epcs:
        bm[e & 0x0F] |= 1 << ((e >> 4) - 8)
    return bytes([len(epcs)]) + bytes(bm)


def main(path):
    ac_get_map = [0x80, 0x81, 0x82, 0x83, 0x88, 0x8A, 0x9D, 0x9E, 0x9F,
                  0xA0, 0xB0, 0xB3, 0xBA, 0xBB, 0xBE, 0x84, 0x85]
    pkts = [
        # 1. Multicast discovery: controller -> all nodes, Get D6
        (CTRL, MCAST, el(1, "05FF01", "0EF001", 0x62, [(0xD6, b"")])),
        # 2. Instance list response
        (DEV, CTRL, el(1, "0EF001", "05FF01", 0x72,
                       [(0xD6, bytes.fromhex("02013001028801"))])),
        # 3. Instance list notification (INF, multicast)
        (DEV, MCAST, el(0, "0EF001", "0EF001", 0x73,
                        [(0xD5, bytes.fromhex("02013001028801"))])),
        # 4. Node profile info
        (CTRL, DEV, el(2, "05FF01", "0EF001", 0x62,
                       [(0x82, b""), (0xD3, b""), (0xD7, b""), (0x8A, b"")])),
        (DEV, CTRL, el(2, "0EF001", "05FF01", 0x72,
                       [(0x82, bytes([1, 14, 1, 0])), (0xD3, bytes.fromhex("000002")),
                        (0xD7, bytes.fromhex("0201300288")), (0x8A, bytes.fromhex("00000B"))])),
        # 5. Property maps of home AC (list form and bitmap form)
        (CTRL, DEV, el(3, "05FF01", "013001", 0x62, [(0x9D, b""), (0x9E, b""), (0x9F, b"")])),
        (DEV, CTRL, el(3, "013001", "05FF01", 0x72,
                       [(0x9D, bytes([4, 0x80, 0x81, 0x88, 0xB0])),
                        (0x9E, bytes([4, 0x80, 0x81, 0xB0, 0xB3])),
                        (0x9F, bitmap_map(ac_get_map))])),
        # 6. AC status
        (CTRL, DEV, el(4, "05FF01", "013001", 0x62,
                       [(0x80, b""), (0x81, b""), (0x82, b""), (0xB0, b""), (0xB3, b""),
                        (0xBB, b""), (0xBE, b""), (0xA0, b""), (0x88, b"")])),
        (DEV, CTRL, el(4, "013001", "05FF01", 0x72,
                       [(0x80, b"\x30"), (0x81, bytes([0x08 | 1])), (0x82, b"\x00\x00\x4A\x00"),
                        (0xB0, b"\x42"), (0xB3, bytes([26])), (0xBB, bytes([28])),
                        (0xBE, bytes([0xFE])), (0xA0, b"\x41"), (0x88, b"\x42")])),
        # 7. SetC -> Set_Res
        (CTRL, DEV, el(5, "05FF01", "013001", 0x61, [(0x80, b"\x31")])),
        (DEV, CTRL, el(5, "013001", "05FF01", 0x71, [(0x80, b"")])),
        # 8. SetGet -> SetGet_Res
        (CTRL, DEV, el(6, "05FF01", "013001", 0x6E,
                       [(0xB0, b"\x43"), (0xB3, bytes([22]))], [(0x80, b""), (0xB0, b"")])),
        (DEV, CTRL, el(6, "013001", "05FF01", 0x7E,
                       [(0xB0, b""), (0xB3, b"")], [(0x80, b"\x30"), (0xB0, b"\x43")])),
        # 9. Get_SNA (unsupported EPC)
        (CTRL, DEV, el(7, "05FF01", "013001", 0x62, [(0xC7, b"")])),
        (DEV, CTRL, el(7, "013001", "05FF01", 0x52, [(0xC7, b"")])),
        # 10. Smart meter
        (CTRL, DEV, el(8, "05FF01", "028801", 0x62,
                       [(0xD3, b""), (0xD7, b""), (0xE1, b""), (0xE0, b""), (0xE7, b""), (0xE8, b"")])),
        (DEV, CTRL, el(8, "028801", "05FF01", 0x72,
                       [(0xD3, struct.pack("!I", 1)), (0xD7, b"\x06"), (0xE1, b"\x01"),
                        (0xE0, struct.pack("!I", 123456)), (0xE7, struct.pack("!i", 1234)),
                        (0xE8, struct.pack("!hh", 105, 0x7FFE))])),
        # 11. INF status change
        (DEV, MCAST, el(0, "013001", "05FF01", 0x73, [(0x80, b"\x31")])),
        # 12. INFC -> INFC_Res
        (DEV, CTRL, el(9, "028801", "05FF01", 0x74,
                       [(0xEA, struct.pack("!HBBBBBI", 2026, 11, 14, 18, 30, 0, 123500))])),
        (CTRL, DEV, el(9, "05FF01", "028801", 0x7A, [(0xEA, b"")])),
        # 12b. Bitmap / array properties (AC air purification method, meter history)
        (CTRL, DEV, el(11, "05FF01", "013001", 0x62, [(0xC6, b"")])),
        (DEV, CTRL, el(11, "013001", "05FF01", 0x72, [(0xC6, b"\x03")])),
        (DEV, CTRL, el(12, "028801", "05FF01", 0x72,
                       [(0xE2, struct.pack("!H", 1) + b"".join(struct.pack("!I", 1000 + i) for i in range(47))
                         + b"\xFF\xFF\xFF\xFE")])),
        # 13. Arbitrary message format
        (CTRL, DEV, bytes([0x10, 0x82, 0x00, 0x0A]) + b"hello"),
        # 14. Truncated frame
        (DEV, CTRL, el(10, "013001", "05FF01", 0x72, [(0x80, b"\x30")])[:-1]),
    ]

    t0 = int(time.time())
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, (s, d, p) in enumerate(pkts):
            fr = frame(s, d, p)
            f.write(struct.pack("<IIII", t0 + i, 0, len(fr), len(fr)))
            f.write(fr)
    print("wrote %d packets to %s" % (len(pkts), path))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "echonet_lite_sample.pcap")
