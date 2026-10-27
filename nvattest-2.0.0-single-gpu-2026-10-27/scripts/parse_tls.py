#!/usr/bin/env python3
"""Summarise TLS ClientHello / server first answer per TCP stream from pcap files.

Usage: python3 parse_tls.py file1.pcap [file2.pcap ...]
Prints only TLS/HTTP fields and the server address (port 443/80). Client
addresses and ports are never printed.
"""
import struct
import sys

CIPHERS = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256", 0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256", 0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305", 0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
    0xCCAA: "DHE-RSA-CHACHA20-POLY1305", 0x009E: "DHE-RSA-AES128-GCM-SHA256",
    0x009F: "DHE-RSA-AES256-GCM-SHA384", 0xC023: "ECDHE-ECDSA-AES128-SHA256",
    0xC024: "ECDHE-ECDSA-AES256-SHA384", 0xC027: "ECDHE-RSA-AES128-SHA256",
    0xC028: "ECDHE-RSA-AES256-SHA384", 0xC009: "ECDHE-ECDSA-AES128-SHA",
    0xC00A: "ECDHE-ECDSA-AES256-SHA", 0xC013: "ECDHE-RSA-AES128-SHA",
    0xC014: "ECDHE-RSA-AES256-SHA", 0x009C: "AES128-GCM-SHA256",
    0x009D: "AES256-GCM-SHA384", 0x003C: "AES128-SHA256", 0x003D: "AES256-SHA256",
    0x002F: "AES128-SHA", 0x0035: "AES256-SHA", 0x0067: "DHE-RSA-AES128-SHA256",
    0x006B: "DHE-RSA-AES256-SHA256", 0x0033: "DHE-RSA-AES128-SHA",
    0x0039: "DHE-RSA-AES256-SHA", 0x00FF: "EMPTY_RENEGOTIATION_INFO_SCSV",
}
GROUPS = {
    0x001D: "x25519", 0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
    0x001E: "x448", 0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
    0x0103: "ffdhe6144", 0x0104: "ffdhe8192", 0x11EC: "X25519MLKEM768",
    0x6399: "X25519Kyber768Draft00",
}
SIGALGS = {
    0x0403: "ecdsa_secp256r1_sha256", 0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512", 0x0807: "ed25519", 0x0808: "ed448",
    0x0809: "rsa_pss_pss_sha256", 0x080A: "rsa_pss_pss_sha384", 0x080B: "rsa_pss_pss_sha512",
    0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384", 0x0806: "rsa_pss_rsae_sha512",
    0x0401: "rsa_pkcs1_sha256", 0x0501: "rsa_pkcs1_sha384", 0x0601: "rsa_pkcs1_sha512",
    0x0303: "ecdsa_sha224", 0x0301: "rsa_pkcs1_sha224", 0x0302: "dsa_sha224",
    0x0402: "dsa_sha256", 0x0502: "dsa_sha384", 0x0602: "dsa_sha512",
    0x0201: "rsa_pkcs1_sha1", 0x0203: "ecdsa_sha1", 0x0202: "dsa_sha1",
}
VERSIONS = {0x0304: "TLS1.3", 0x0303: "TLS1.2", 0x0302: "TLS1.1", 0x0301: "TLS1.0", 0x0300: "SSL3"}
EXTS = {
    0x0000: "server_name", 0x0005: "status_request", 0x000A: "supported_groups",
    0x000B: "ec_point_formats", 0x000D: "signature_algorithms", 0x0010: "alpn",
    0x0012: "sct", 0x0015: "padding", 0x0016: "encrypt_then_mac",
    0x0017: "extended_master_secret", 0x001B: "compress_certificate",
    0x001C: "record_size_limit", 0x0023: "session_ticket", 0x0029: "pre_shared_key",
    0x002A: "early_data", 0x002B: "supported_versions", 0x002D: "psk_key_exchange_modes",
    0x0031: "post_handshake_auth", 0x0032: "signature_algorithms_cert", 0x0033: "key_share",
    0xFF01: "renegotiation_info",
}
ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 22: "record_overflow",
    40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate",
    44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
    47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied", 50: "decode_error",
    51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
    80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled",
    109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
    116: "certificate_required", 120: "no_application_protocol",
}


def name(table, value):
    if (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF):
        return "GREASE"
    return table.get(value, "0x%04x" % value)


def read_pcap(path):
    """Yield (timestamp, linktype, frame) from a classic pcap file."""
    with open(path, "rb") as handle:
        header = handle.read(24)
        if len(header) < 24:
            return
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise ValueError("not a classic pcap file: %s" % path)
        divisor = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        while True:
            record = handle.read(16)
            if len(record) < 16:
                return
            sec, frac, incl, _orig = struct.unpack(endian + "IIII", record)
            yield sec + frac / divisor, linktype, handle.read(incl)


def ip_payload(linktype, frame):
    """Return (version, ip_packet) or None."""
    if linktype == 1:  # Ethernet
        offset, ethertype = 14, struct.unpack(">H", frame[12:14])[0]
        while ethertype in (0x8100, 0x88A8):
            ethertype = struct.unpack(">H", frame[offset + 2:offset + 4])[0]
            offset += 4
    elif linktype == 113:  # Linux cooked v1
        offset, ethertype = 16, struct.unpack(">H", frame[14:16])[0]
    elif linktype == 276:  # Linux cooked v2
        offset, ethertype = 20, struct.unpack(">H", frame[0:2])[0]
    elif linktype in (12, 101, 228, 229):  # raw IP
        version = frame[0] >> 4
        return (version, frame) if version in (4, 6) else None
    else:
        return None
    packet = frame[offset:]
    if ethertype == 0x0800:
        return 4, packet
    if ethertype == 0x86DD:
        return 6, packet
    return None


def tcp_segment(version, packet):
    """Return (src, dst, sport, dport, seq, flags, payload) or None."""
    if version == 4:
        ihl = (packet[0] & 0x0F) * 4
        if packet[9] != 6:
            return None
        total = struct.unpack(">H", packet[2:4])[0]
        src, dst = ".".join(map(str, packet[12:16])), ".".join(map(str, packet[16:20]))
        tcp = packet[ihl:total]
    else:
        if packet[6] != 6:  # no extension-header walking: enough for this capture
            return None
        plen = struct.unpack(">H", packet[4:6])[0]
        src, dst = packet[8:24].hex(), packet[24:40].hex()
        tcp = packet[40:40 + plen]
    if len(tcp) < 20:
        return None
    sport, dport, seq = struct.unpack(">HHI", tcp[:8])
    doff = (tcp[12] >> 4) * 4
    return src, dst, sport, dport, seq, tcp[13], tcp[doff:]


def u16_list(data):
    return [struct.unpack(">H", data[i:i + 2])[0] for i in range(0, len(data) - 1, 2)]


def parse_client_hello(stream):
    if len(stream) < 9 or stream[0] != 22:
        return "first client bytes are not a TLS handshake record (%s)" % stream[:8].hex()
    body = bytearray()
    pos = 0
    while pos + 5 <= len(stream) and stream[pos] == 22:  # gather handshake records
        length = struct.unpack(">H", stream[pos + 3:pos + 5])[0]
        body += stream[pos + 5:pos + 5 + length]
        pos += 5 + length
        if len(body) >= 4 and len(body) >= 4 + int.from_bytes(body[1:4], "big"):
            break
    if not body or body[0] != 1:
        return "no ClientHello in the first handshake record"
    hello = bytes(body[4:4 + int.from_bytes(body[1:4], "big")])
    out = {"legacy_version": VERSIONS.get(struct.unpack(">H", hello[0:2])[0], hello[0:2].hex())}
    p = 34
    p += 1 + hello[p]  # session id
    cs_len = struct.unpack(">H", hello[p:p + 2])[0]
    ciphers = u16_list(hello[p + 2:p + 2 + cs_len])
    p += 2 + cs_len
    p += 1 + hello[p]  # compression methods
    out["ciphers"] = [name(CIPHERS, c) for c in ciphers]
    ext_end = p + 2 + struct.unpack(">H", hello[p:p + 2])[0] if p + 2 <= len(hello) else p
    p += 2
    order = []
    while p + 4 <= ext_end:
        etype, elen = struct.unpack(">HH", hello[p:p + 4])
        data = hello[p + 4:p + 4 + elen]
        order.append(name(EXTS, etype))
        if etype == 0x0000 and len(data) > 5:
            out["sni"] = data[5:5 + struct.unpack(">H", data[3:5])[0]].decode("ascii", "replace")
        elif etype == 0x000A:
            out["groups"] = [name(GROUPS, g) for g in u16_list(data[2:])]
        elif etype == 0x000D:
            out["sigalgs"] = [name(SIGALGS, s) for s in u16_list(data[2:])]
        elif etype == 0x0010:
            protos, q = [], 2
            while q < len(data):
                protos.append(data[q + 1:q + 1 + data[q]].decode("ascii", "replace"))
                q += 1 + data[q]
            out["alpn"] = protos
        elif etype == 0x002B:
            out["supported_versions"] = [name(VERSIONS, v) for v in u16_list(data[1:])]
        elif etype == 0x0033:
            shares, q = [], 2
            while q + 4 <= len(data):
                group, klen = struct.unpack(">HH", data[q:q + 4])
                shares.append(name(GROUPS, group))
                q += 4 + klen
            out["key_share"] = shares
        p += 4 + elen
    out["extensions"] = order
    return out


def parse_server_first(stream, flags):
    notes = []
    if stream:
        if stream[0] == 21 and len(stream) >= 7:
            level = "fatal" if stream[5] == 2 else "warning"
            notes.append("TLS alert %s %s" % (level, ALERTS.get(stream[6], stream[6])))
        elif stream[0] == 22 and len(stream) >= 9 and stream[5] == 2:
            hello = stream[9:]
            p = 34
            p += 1 + hello[p]
            cipher = struct.unpack(">H", hello[p:p + 2])[0]
            p += 3
            selected, group = None, None
            if p + 2 <= len(hello):
                ext_end = p + 2 + struct.unpack(">H", hello[p:p + 2])[0]
                p += 2
                while p + 4 <= ext_end:
                    etype, elen = struct.unpack(">HH", hello[p:p + 4])
                    data = hello[p + 4:p + 4 + elen]
                    if etype == 0x002B and len(data) >= 2:
                        selected = name(VERSIONS, struct.unpack(">H", data[:2])[0])
                    if etype == 0x0033 and len(data) >= 2:
                        group = name(GROUPS, struct.unpack(">H", data[:2])[0])
                    p += 4 + elen
            notes.append("ServerHello version=%s cipher=%s group=%s" % (
                selected or "TLS1.2-or-lower", name(CIPHERS, cipher), group))
        elif stream[:5] in (b"HTTP/",):
            notes.append("HTTP answer: " + stream.split(b"\r\n", 1)[0].decode("ascii", "replace"))
        else:
            notes.append("first server bytes: %s" % stream[:8].hex())
    else:
        notes.append("no data from server")
    if flags & 0x04:
        notes.append("server sent RST")
    if flags & 0x01:
        notes.append("server sent FIN")
    return "; ".join(notes)


def summarise(path):
    streams = {}
    for ts, linktype, frame in read_pcap(path):
        parsed = ip_payload(linktype, frame)
        if not parsed:
            continue
        seg = tcp_segment(*parsed)
        if not seg:
            continue
        src, dst, sport, dport, seq, flags, payload = seg
        if dport in (443, 80):
            key, to_server = (src, sport, dst, dport), True
        elif sport in (443, 80):
            key, to_server = (dst, dport, src, sport), False
        else:
            continue
        st = streams.setdefault(key, {"t0": ts, "c": {}, "s": {}, "sflags": 0, "cflags": 0})
        if to_server:
            st["cflags"] |= flags
            if payload:
                st["c"].setdefault(seq, payload)
        else:
            st["sflags"] |= flags
            if payload:
                st["s"].setdefault(seq, payload)
    print("=== %s : %d TCP stream(s) on ports 443/80" % (path, len(streams)))
    start = min((s["t0"] for s in streams.values()), default=0)
    for index, (key, st) in enumerate(sorted(streams.items(), key=lambda kv: kv[1]["t0"]), 1):
        client = b"".join(st["c"][k] for k in sorted(st["c"]))
        server = b"".join(st["s"][k] for k in sorted(st["s"]))
        print("--- stream %d  server %s:%d  t+%.3fs  bytes client=%d server=%d" % (
            index, key[2], key[3], st["t0"] - start, len(client), len(server)))
        if key[3] == 80:
            line = client.split(b"\r\n", 1)[0].decode("ascii", "replace") if client else "(no request)"
            print("  request: " + line)
        else:
            try:
                hello = parse_client_hello(client)
            except Exception as exc:  # keep going on odd captures
                hello = "ClientHello parse error: %r" % exc
            if isinstance(hello, dict):
                for field in ("sni", "legacy_version", "supported_versions", "alpn", "groups",
                              "key_share", "sigalgs", "ciphers", "extensions"):
                    if field in hello:
                        value = hello[field]
                        if isinstance(value, list):
                            value = "(%d) %s" % (len(value), ", ".join(value))
                        print("  %-18s %s" % (field, value))
            else:
                print("  " + hello)
        try:
            print("  server: " + parse_server_first(server, st["sflags"]))
        except Exception as exc:
            print("  server parse error: %r" % exc)
        if st["cflags"] & 0x04:
            print("  client sent RST")


if __name__ == "__main__":
    for pcap in sys.argv[1:]:
        try:
            summarise(pcap)
        except Exception as exc:
            print("=== %s : could not be read (%r)" % (pcap, exc))
