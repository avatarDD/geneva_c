#!/usr/bin/env python3
"""Writes tests/golden/in.pcap: a small fixed capture for the golden tests.

Pure standard library (no scapy): a TCP connection to port 80 with an HTTP
request and answer, a TLS ClientHello to 443, a DNS query and answer over
UDP 53 and an IPv6 TCP SYN. Checksums are correct. Run from the repository
root: python3 tools/gen_golden_pcap.py > tests/golden/in.pcap
"""
import struct
import sys


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip4(src, dst, proto, payload, ttl=64, ident=1):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, ttl, proto, 0,
                      bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def l4sum4(src, dst, proto, seg):
    return csum(bytes(src) + bytes(dst) + struct.pack("!BBH", 0, proto, len(seg)) + seg)


def l4sum6(src, dst, proto, seg):
    return csum(bytes(src) + bytes(dst) + struct.pack("!IxxxB", len(seg), proto) + seg)


def tcp(sport, dport, seq, ack, flags, data=b"", win=64240, opts=b""):
    off = (20 + len(opts)) // 4
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off << 4, flags, win, 0, 0) + opts + data


def fix_tcp4(src, dst, seg):
    return seg[:16] + struct.pack("!H", l4sum4(src, dst, 6, seg)) + seg[18:]


def udp4(src, dst, sport, dport, data):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    return seg[:6] + struct.pack("!H", l4sum4(src, dst, 17, seg)) + seg[8:]


F, S, R, P, A = 1, 2, 4, 8, 16
cli, srv = [192, 168, 1, 10], [93, 184, 216, 34]
pkts = []


def t4(src, dst, *a, **k):
    pkts.append(ip4(src, dst, 6, fix_tcp4(src, dst, tcp(*a, **k)), ttl=64 if src == cli else 52))


mss = b"\x02\x04\x05\xb4\x01\x03\x03\x07\x04\x02\x00\x00"
t4(cli, srv, 40000, 80, 1000, 0, S, opts=mss)
t4(srv, cli, 80, 40000, 5000, 1001, S | A, opts=mss)
t4(cli, srv, 40000, 80, 1001, 5001, A)
req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n"
t4(cli, srv, 40000, 80, 1001, 5001, P | A, req)
resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
t4(srv, cli, 80, 40000, 5001, 1001 + len(req), P | A, resp)
t4(cli, srv, 40000, 80, 1001 + len(req), 5001 + len(resp), F | A)

# TLS 1.3 ClientHello with SNI example.com (minimal, well-formed)
sni = b"example.com"
ext_sni = struct.pack("!HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni
ext_ver = struct.pack("!HHBH", 43, 3, 2, 0x0304)
exts = ext_sni + ext_ver
body = b"\x03\x03" + bytes(range(32)) + b"\x20" + bytes(32) + b"\x00\x02\x13\x01\x01\x00" + \
    struct.pack("!H", len(exts)) + exts
hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
ch = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
t4(cli, srv, 40001, 443, 7000, 0, S, opts=mss)
t4(srv, cli, 443, 40001, 9000, 7001, S | A, opts=mss)
t4(cli, srv, 40001, 443, 7001, 9001, A)
t4(cli, srv, 40001, 443, 7001, 9001, P | A, ch)
t4(srv, cli, 443, 40001, 9001, 7001 + len(ch), R | A)

# DNS query and answer for example.com A
dns_q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
dns_a = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1) + \
    b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes(srv)
res = [8, 8, 8, 8]
pkts.append(ip4(cli, res, 17, udp4(cli, res, 50000, 53, dns_q)))
pkts.append(ip4(res, cli, 17, udp4(res, cli, 53, 50000, dns_a), ttl=118))

# IPv6 TCP SYN
c6 = bytes.fromhex("20010db8000000000000000000000010")
s6 = bytes.fromhex("20010db8000000000000000000000443")
seg = tcp(40002, 443, 11000, 0, S, opts=mss)
seg = seg[:16] + struct.pack("!H", l4sum6(c6, s6, 6, seg)) + seg[18:]
pkts.append(struct.pack("!IHBB", 6 << 28, len(seg), 6, 64) + c6 + s6 + seg)

out = sys.stdout.buffer
out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))  # LINKTYPE_RAW
for i, p in enumerate(pkts):
    out.write(struct.pack("<IIII", 1700000000, i * 1000, len(p), len(p)))
    out.write(p)
