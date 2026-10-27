#!/usr/bin/env python3
"""One line per TCP stream: the SYN-ACK(s) received and what happened next.

Usage: python synack_table.py file.pcap [...]
For each SYN-ACK: IP TTL, IP ID, MSS option value, window scale, and whether its
ACK number matches our ISN + 1. Outcome: server data received, RSTs (with TTL),
or silence. Only the server address is printed.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse_tls import read_pcap, ip_payload  # noqa: E402


def tcp_options(raw):
    out, i = {}, 0
    while i < len(raw):
        kind = raw[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        length = raw[i + 1] if i + 1 < len(raw) else 2
        value = raw[i + 2:i + length]
        if kind == 2 and len(value) == 2:
            out["mss"] = struct.unpack(">H", value)[0]
        elif kind == 3 and value:
            out["ws"] = value[0]
        elif kind == 8 and len(value) == 8:
            out["ts"] = struct.unpack(">II", value)
        i += max(length, 2)
    return out


def main(path):
    streams, order = {}, []
    for _ts, linktype, frame in read_pcap(path):
        parsed = ip_payload(linktype, frame)
        if not parsed or parsed[0] != 4:
            continue
        pkt = parsed[1]
        ihl = (pkt[0] & 0x0F) * 4
        total = struct.unpack(">H", pkt[2:4])[0]
        tcp = pkt[ihl:total]
        sport, dport, seq, ack = struct.unpack(">HHII", tcp[:12])
        doff = (tcp[12] >> 4) * 4
        flags = tcp[13]
        to_server = dport in (443, 80)
        key = (pkt[12:16], sport, pkt[16:20], dport) if to_server else (pkt[16:20], dport, pkt[12:16], sport)
        if key not in streams:
            streams[key] = {"isn": None, "syn_ipid": None, "synacks": [], "data": 0, "rst": [], "client_rst": 0}
            order.append(key)
        st = streams[key]
        ipid, ttl = struct.unpack(">H", pkt[4:6])[0], pkt[8]
        if to_server:
            if flags & 0x02 and st["isn"] is None:
                st["isn"], st["syn_ipid"] = seq, ipid
            if flags & 0x04:
                st["client_rst"] += 1
            continue
        if (flags & 0x12) == 0x12:
            opts = tcp_options(tcp[20:doff])
            ack_ok = st["isn"] is not None and ack == (st["isn"] + 1) & 0xFFFFFFFF
            st["synacks"].append("[ttl=%d ipid=%s mss=%s ws=%s ack=%s]" % (
                ttl, "=SYN" if ipid == st["syn_ipid"] else ipid, opts.get("mss", "-"),
                opts.get("ws", "-"), "ok" if ack_ok else "WRONG"))
        if flags & 0x04:
            st["rst"].append(ttl)
        st["data"] += len(tcp) - doff
    print("=== %s" % os.path.basename(path))
    for n, key in enumerate(order, 1):
        st = streams[key]
        server = "%s:%d" % (".".join(map(str, key[2])), key[3])
        if st["rst"] and st["data"] == 0:
            outcome = "no data from server, RST received (ttl %s)" % "/".join(map(str, st["rst"]))
        elif st["data"]:
            outcome = "%d B from server%s" % (st["data"], (", then RST ttl %s after FIN" % "/".join(map(str, st["rst"]))) if st["rst"] else "")
        else:
            outcome = "no data from server, no RST (silence)"
        if st["client_rst"]:
            outcome += "; guest sent %d RST" % st["client_rst"]
        print("%2d %-21s %s -> %s" % (n, server, " ".join(st["synacks"]) or "[no SYN-ACK]", outcome))


if __name__ == "__main__":
    for p in sys.argv[1:]:
        main(p)
