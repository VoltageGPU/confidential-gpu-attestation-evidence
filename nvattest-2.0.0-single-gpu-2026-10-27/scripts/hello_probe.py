#!/usr/bin/env python3
"""Send a hand-built TLS 1.3 ClientHello and report the server's first answer.

small: key_share x25519 only (about 250 bytes, like OpenSSL 3.0)
large: key_share X25519MLKEM768 + x25519 (about 1.5 KB, like OpenSSL >= 3.5 defaults)
The ML-KEM share is random bytes: a server that selects it may answer with an
alert, which still proves it received and parsed the whole ClientHello.
"""
import os, socket, struct, sys, time

def ext(t, body):
    return struct.pack(">HH", t, len(body)) + body

def client_hello(host, large):
    sni = host.encode()
    groups = [0x11EC, 0x001D, 0x0017, 0x0018] if large else [0x001D, 0x0017, 0x0018]
    shares = b""
    if large:
        shares += struct.pack(">HH", 0x11EC, 1216) + os.urandom(1216)
    shares += struct.pack(">HH", 0x001D, 32) + os.urandom(32)
    sigalgs = [0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601]
    exts = b"".join([
        ext(0x0000, struct.pack(">HBH", len(sni) + 3, 0, len(sni)) + sni),
        ext(0x000A, struct.pack(">H", 2 * len(groups)) + b"".join(struct.pack(">H", g) for g in groups)),
        ext(0x000D, struct.pack(">H", 2 * len(sigalgs)) + b"".join(struct.pack(">H", s) for s in sigalgs)),
        ext(0x0010, b"\x00\x0b\x08http/1.1" if False else b"\x00\x09\x08http/1.1"),
        ext(0x002B, b"\x04\x03\x04\x03\x03"),
        ext(0x002D, b"\x01\x01"),
        ext(0x0033, struct.pack(">H", len(shares)) + shares),
    ])
    suites = [0x1302, 0x1303, 0x1301, 0xC02C, 0xC030, 0xC02B, 0xC02F]
    body = (b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32)
            + struct.pack(">H", 2 * len(suites)) + b"".join(struct.pack(">H", s) for s in suites)
            + b"\x01\x00" + struct.pack(">H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs

ALERTS = {40: "handshake_failure", 47: "illegal_parameter", 50: "decode_error", 70: "protocol_version", 80: "internal_error", 112: "unrecognized_name"}

def probe(host, large):
    hello = client_hello(host, large)
    t0 = time.time()
    try:
        with socket.create_connection((host, 443), timeout=10) as s:
            peer = s.getpeername()[0]
            s.sendall(hello)
            s.settimeout(10)
            data = b""
            while len(data) < 6:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    except ConnectionResetError:
        return "%-28s %-5s hello=%4dB -> connection RESET by peer after %.2fs" % (host, "large" if large else "small", len(hello), time.time() - t0)
    except socket.timeout:
        return "%-28s %-5s hello=%4dB -> no answer within 10s" % (host, "large" if large else "small", len(hello))
    dt = time.time() - t0
    if not data:
        verdict = "server closed the connection (FIN) without answering"
    elif data[0] == 22 and data[5] == 2:
        verdict = "ServerHello (or HelloRetryRequest) received"
    elif data[0] == 21:
        verdict = "TLS alert %s" % ALERTS.get(data[6], data[6])
    else:
        verdict = "first bytes %s" % data[:8].hex()
    return "%-28s %-5s hello=%4dB -> %s in %.2fs" % (host, "large" if large else "small", len(hello), verdict, dt)

if __name__ == "__main__":
    hosts = sys.argv[1:] or ["ocsp.ndis.nvidia.com", "rim.attestation.nvidia.com", "nras.attestation.nvidia.com"]
    for h in hosts:
        for large in (False, True):
            print(probe(h, large), flush=True)
