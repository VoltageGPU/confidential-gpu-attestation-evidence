"""Rewrite the guest's own IPv4 address (and Ethernet MACs) in a classic pcap.

Usage: python pcap_anon.py in.pcap out.pcap <guest-ip> [<guest-ip> ...]
Guest addresses become 10.0.0.2; MACs become 02:00:00:00:00:01/02.
IPv4 header and TCP/UDP checksums are recomputed for every rewritten packet.
"""
import socket, struct, sys

def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

src, dst, guests = sys.argv[1], sys.argv[2], {socket.inet_aton(a) for a in sys.argv[3:]}
NEW = socket.inet_aton("10.0.0.2")
with open(src, "rb") as f:
    data = f.read()
gh, e = data[:24], "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
linktype = struct.unpack(e + "I", gh[20:24])[0]
assert linktype == 1, "only Ethernet captures are handled (got %d)" % linktype
out, pos, n = bytearray(gh), 24, 0
while pos + 16 <= len(data):
    rec = data[pos:pos + 16]
    incl = struct.unpack(e + "IIII", rec)[2]
    frame = bytearray(data[pos + 16:pos + 16 + incl])
    pos += 16 + incl
    if len(frame) >= 34 and frame[12:14] == b"\x08\x00":
        ip = 14
        ihl = (frame[ip] & 0x0F) * 4
        total = struct.unpack("!H", frame[ip + 2:ip + 4])[0]
        s, d = bytes(frame[ip + 12:ip + 16]), bytes(frame[ip + 16:ip + 20])
        out_dir = s in guests
        if s in guests:
            frame[ip + 12:ip + 16] = NEW
        if d in guests:
            frame[ip + 16:ip + 20] = NEW
        frame[0:6] = bytes.fromhex("020000000002" if out_dir else "020000000001")
        frame[6:12] = bytes.fromhex("020000000001" if out_dir else "020000000002")
        frame[ip + 10:ip + 12] = b"\0\0"
        frame[ip + 10:ip + 12] = struct.pack("!H", csum(bytes(frame[ip:ip + ihl])))
        proto = frame[ip + 9]
        l4 = ip + ihl
        end = min(ip + total, len(frame))
        if proto in (6, 17) and end - l4 >= (20 if proto == 6 else 8) and ip + total <= len(frame):
            off = l4 + (16 if proto == 6 else 6)
            frame[off:off + 2] = b"\0\0"
            pseudo = bytes(frame[ip + 12:ip + 20]) + struct.pack("!BBH", 0, proto, end - l4)
            c = csum(pseudo + bytes(frame[l4:end]))
            frame[off:off + 2] = struct.pack("!H", c if (c or proto == 6) else 0xFFFF)
        n += 1
    out += rec + frame
with open(dst, "wb") as f:
    f.write(out)
print("%s: %d packet(s) rewritten" % (dst.rsplit("/", 1)[-1], n))
