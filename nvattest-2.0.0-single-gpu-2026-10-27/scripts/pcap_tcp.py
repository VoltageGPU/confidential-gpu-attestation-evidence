#!/usr/bin/env python3
"""Per-TCP-stream timeline from pcap files: SYN, SYN-ACK, data, RST/FIN, IP TTLs.

Usage: python pcap_tcp.py file.pcap [...]
Only the server side (port 443/80) address is printed. The TTL of packets coming
from the server is shown for the SYN-ACK and for any RST, so a reset injected by
a middlebox (different TTL) can be told apart from one sent by the same host.
"""
import struct
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0].rsplit("\\", 1)[0])
from parse_tls import read_pcap, ip_payload  # noqa: E402


def segments(path):
    for ts, linktype, frame in read_pcap(path):
        parsed = ip_payload(linktype, frame)
        if not parsed or parsed[0] != 4:
            continue
        packet = parsed[1]
        if packet[9] != 6:
            continue
        ihl = (packet[0] & 0x0F) * 4
        total = struct.unpack(">H", packet[2:4])[0]
        ttl = packet[8]
        src, dst = ".".join(map(str, packet[12:16])), ".".join(map(str, packet[16:20]))
        tcp = packet[ihl:total]
        sport, dport = struct.unpack(">HH", tcp[:4])
        doff = (tcp[12] >> 4) * 4
        yield ts, src, dst, sport, dport, tcp[13], ttl, len(tcp) - doff


def main(path):
    streams = {}
    for ts, src, dst, sport, dport, flags, ttl, plen in segments(path):
        if dport in (443, 80):
            key, from_server = (src, sport, dst, dport), False
        elif sport in (443, 80):
            key, from_server = (dst, dport, src, sport), True
        else:
            continue
        streams.setdefault(key, []).append((ts, from_server, flags, ttl, plen))
    print("=== %s : %d stream(s)" % (path, len(streams)))
    t_start = min((ev[0][0] for ev in streams.values()), default=0)
    for n, (key, events) in enumerate(sorted(streams.items(), key=lambda kv: kv[1][0][0]), 1):
        t0 = events[0][0]
        parts = []
        syn_count = sum(1 for e in events if not e[1] and e[2] & 0x02 and not e[2] & 0x10)
        for ts, from_server, flags, ttl, plen in events:
            who = "S" if from_server else "C"
            names = "".join(c for bit, c in ((0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH")) if flags & bit)
            if from_server and (flags & 0x04 or (flags & 0x12) == 0x12):
                names += "(ttl=%d)" % ttl
            if plen or flags & 0x07:
                parts.append("%+.3f %s:%s%s" % (ts - t0, who, names, (" %dB" % plen) if plen else ""))
        got_synack = any(e[1] and (e[2] & 0x12) == 0x12 for e in events)
        server_bytes = sum(e[4] for e in events if e[1])
        rst_ttls = sorted({e[3] for e in events if e[1] and e[2] & 0x04})
        verdict = ("no SYN-ACK (%d SYN sent)" % syn_count if not got_synack else
                   "RST received (ttl %s) after %dB of server data" % ("/".join(map(str, rst_ttls)), server_bytes)
                   if rst_ttls else "server data %dB" % server_bytes)
        print("--- stream %d  %s:%d  t+%.3fs  %s" % (n, key[2], key[3], t0 - t_start, verdict))
        print("    " + "  ".join(parts[:14]) + ("  ..." if len(parts) > 14 else ""))


if __name__ == "__main__":
    for p in sys.argv[1:]:
        main(p)
