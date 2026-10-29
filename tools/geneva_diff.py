#!/usr/bin/env python3
"""
Differential test of geneva_c against the Python Geneva.

    python3 tools/geneva_diff.py --geneva /path/to/geneva --bin build/geneva

1. Every strategy from Geneva's library.py and tests (plus EXTRA below) is
   parsed by Geneva and by "geneva check --json"; both must accept or reject
   it alike, and accepted strategies must print the same.
2. Every strategy Geneva can run deterministically is applied by Geneva's
   Strategy.act_on_packet() to a small capture (handshake, HTTP request,
   RST, DNS query, UDP datagram) and by "geneva apply"; the produced packets
   must be byte-identical and carry the same sleep delays. Random parts are
   pinned first: "corrupt" tampers become "replace" with a fixed value.

Needs scapy and anytree (Geneva's requirements). Geneva modules that only
matter for live traffic (netfilterqueue, netifaces) are stubbed if missing.
Exits non-zero on any unexplained difference.
"""
import argparse
import importlib
import json
import logging
import os
import re
import struct
import subprocess
import sys
import tempfile
import traceback
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import extract_strategies  # noqa: E402

SERVER_PORTS = (80, 53)

# Strategies beyond Geneva's own corpus, to cover every action and field kind.
EXTRA = [
    "[TCP:flags:PA]-tamper{TCP:options-mss:replace:1000}-|",
    "[TCP:flags:S]-tamper{TCP:options-wscale:replace:14}-|",
    "[TCP:flags:S]-tamper{TCP:options-timestamp:replace:777}-|",
    "[TCP:flags:S]-tamper{TCP:options-uto:replace:300}-|",
    "[TCP:flags:S]-tamper{TCP:options-sackok:replace:}-|",
    "[TCP:flags:PA]-tamper{TCP:window:add:-100}-|",
    "[TCP:flags:PA]-tamper{IP:ttl:add:5}-|",
    "[TCP:flags:PA]-tamper{IP:tos:replace:4}-|",
    "[TCP:flags:PA]-tamper{IP:id:replace:4242}-|",
    "[TCP:flags:PA]-tamper{IP:frag:replace:3}-|",
    "[TCP:flags:PA]-tamper{IP:len:replace:64}-|",
    "[TCP:flags:PA]-tamper{IP:flags:replace:MF}-|",
    "[TCP:flags:PA]-tamper{IP:src:replace:1.2.3.4}-|",
    "[TCP:flags:PA]-tamper{TCP:load:replace:hello%20world}-|",
    "[TCP:flags:PA]-tamper{TCP:load:replace:__HTTP_REQUEST__}-|",
    "[TCP:flags:PA]-tamper{IP:load:replace:xyz}-|",
    "[TCP:flags:PA]-tamper{TCP:urgptr:replace:7}-|",
    "[TCP:flags:PA]-tamper{TCP:reserved:replace:5}-|",
    "[TCP:flags:PA]-fragment{tcp:-1:True}-|",
    "[TCP:flags:PA]-fragment{tcp:5:False}-|",
    "[TCP:flags:PA]-fragment{tcp:5:True:3}-|",
    "[TCP:flags:PA]-fragment{tcp:200:True}-|",
    "[TCP:flags:PA]-fragment{tcp:0:True}-|",
    "[TCP:flags:PA]-fragment{ip:-1:True}-|",
    "[TCP:flags:PA]-fragment{ip:1:False}-|",
    "[TCP:flags:PA]-fragment{ip:3:True}-|",
    "[TCP:flags:PA]-fragment{ip:100:True}-|",
    "[TCP:flags:A]-fragment{ip:-1:True}-|",
    "[UDP:dport:9999]-fragment{ip:-1:True}-|",
    "[UDP:dport:9999]-fragment{ip:1:True}-|",
    "[TCP:flags:PA]-fragment{tcp:8:True}(tamper{TCP:flags:replace:R},tamper{IP:ttl:replace:3})-|",
    "[TCP:flags:PA]-fragment{ip:2:True}(tamper{IP:ttl:replace:3},drop)-|",
    "[TCP:flags:PA]-duplicate(sleep{0.5},)-|",
    "[TCP:flags:PA]-sleep{2}(duplicate,)-|",
    "[TCP:flags:PA]-tamper{TCP:dataofs:replace:10}(fragment{tcp:-1:True},)-|",
    "[TCP:flags:PA]-tamper{TCP:seq:replace:4294967290}(fragment{tcp:10:True},)-|",
    "[UDP:dport:53]-tamper{DNS:qd:compress}-|",
    "[UDP:dport:53]-tamper{DNS:id:replace:4242}-|",
    "[UDP:dport:53]-tamper{DNS:rd:replace:0}-|",
    "[UDP:dport:53]-tamper{DNSQR:qname:replace:example.org}-|",
    "[UDP:dport:53]-tamper{DNSQR:qtype:replace:28}-|",
    "[UDP:dport:53]-tamper{UDP:sport:replace:1111}-|",
    "[UDP:dport:53]-duplicate(tamper{UDP:chksum:replace:1},)-|",
    "[DNSQR:qname:example.com.]-drop-|",
    "[TCP:flags:A*]-tamper{IP:ttl:replace:7}-|",
    "[TCP:load:HTTP*]-tamper{IP:ttl:replace:7}-|",
    "[TCP:flags:A:1]-tamper{IP:ttl:replace:7}-|",
    "[TCP:flags:A:-1]-tamper{IP:ttl:replace:7}-|",
    "[TCP:flags:PA]-tamper{IP:ttl:replace:9}-| [TCP:flags:PA]-duplicate-|",
    "\\/ [TCP:flags:SA]-tamper{TCP:window:replace:1}-|",
    "\\/ [TCP:flags:R]-drop-|",
    "\\/ [TCP:flags:R]-tamper{IP:ttl:replace:1}-| [TCP:flags:R]-drop-|",
]

# Fixed values used in place of "corrupt" (by field name).
PINNED = {
    "sport": "1234", "dport": "4321", "seq": "123456", "ack": "654321", "dataofs": "7",
    "reserved": "3", "flags": "FRAPU", "window": "100", "chksum": "4321", "urgptr": "9",
    "load": "abc", "options-mss": "1000", "options-wscale": "5", "options-timestamp": "777",
    "options-uto": "300", "options-altchksum": "7", "ttl": "33", "id": "777", "tos": "4",
    "frag": "0", "len": "64", "ihl": "6", "src": "1.2.3.4", "dst": "5.6.7.8", "version": "6",
    "proto": "17", "qname": "a.example.", "qtype": "28", "qclass": "3", "qr": "1",
    "opcode": "2", "aa": "1", "tc": "1", "rd": "0", "ra": "1", "z": "1", "ad": "1", "cd": "1",
    "rcode": "3", "qdcount": "2", "ancount": "1", "nscount": "1", "arcount": "1",
}

# Inputs where geneva_c deliberately differs from Geneva (see docs/STRATEGY.md).
def deliberate_reject(s):
    # Geneva would pick a random tamper; geneva_c wants explicit parameters.
    return bool(re.search(r"tamper(?![{a-zA-Z])", s))


def patch_find_library():
    # scapy 2.4.3 calls find_library("libc"), which raises FileNotFoundError
    # on Python 3.8 with a current toolchain; None loads the process image,
    # whose symbols include libc.
    import ctypes.util
    orig = ctypes.util.find_library

    def find_library(name):
        try:
            return orig(name)
        except OSError:
            return None
    ctypes.util.find_library = find_library


class _Dummy(object):
    """Stands in for any attribute or call of a stubbed module."""
    def __getattr__(self, name):
        return _Dummy()

    def __call__(self, *a, **k):
        return _Dummy()


# Imported somewhere on Geneva's import path but only used for live traffic,
# remote workers or docker; nothing here touches them.
STUBBED = ("netfilterqueue", "netifaces", "psutil", "requests", "urllib3", "docker", "paramiko")


def stub_modules():
    for name in STUBBED:
        try:
            importlib.import_module(name)
        except ImportError:
            mod = types.ModuleType(name)
            mod.__getattr__ = lambda attr: _Dummy()  # PEP 562
            mod.interfaces = lambda: []
            mod.ifaddresses = lambda iface: {}
            mod.AF_INET = 2
            sys.modules[name] = mod
    import scapy.config
    # TraceAction opens a raw socket in its constructor, which Geneva runs
    # while listing actions; nothing here sends packets.
    scapy.config.conf.L3socket = lambda *a, **k: None


def load_geneva(path):
    sys.path.insert(0, path)
    os.chdir(path)
    patch_find_library()
    stub_modules()
    import actions.action  # noqa: F401
    import actions.utils  # noqa: F401
    import actions.strategy  # noqa: F401
    import actions.tree  # noqa: F401
    import layers.packet  # noqa: F401
    return sys.modules["actions.utils"], sys.modules["layers.packet"]


class ListHandler(logging.Handler):
    """Keeps what Geneva logs while parsing, to explain its rejections."""
    def __init__(self):
        logging.Handler.__init__(self)
        self.records = []

    def emit(self, record):
        msg = record.getMessage()
        if record.exc_info:
            msg += " | " + "".join(traceback.format_exception(*record.exc_info)).strip().splitlines()[-1]
        self.records.append(msg)


def geneva_print(gu, s, logger):
    handler = logger.handlers[0]
    handler.records = []
    try:
        st = gu.parse(s, logger)
        return True, str(st).strip()
    except BaseException as e:  # Geneva signals errors with assorted exceptions
        if isinstance(e, KeyboardInterrupt):
            raise
        why = "; ".join(handler.records[-3:])
        return False, "%s: %s%s" % (type(e).__name__, e, " [%s]" % why if why else "")


def run_check(binary, strategies):
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        for s in strategies:
            f.write(s + "\n")
        name = f.name
    try:
        r = subprocess.run([binary, "check", "--json", "-f", name], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True)
    finally:
        os.unlink(name)
    lines = [json.loads(x) for x in r.stdout.splitlines() if x.strip()]
    if len(lines) != len(strategies):
        raise SystemExit("geneva check printed %d results for %d strategies:\n%s"
                         % (len(lines), len(strategies), r.stderr))
    return lines


def pin(s):
    """Makes a strategy deterministic, or returns None if it cannot be."""
    def repl(m):
        proto, field = m.group(1), m.group(2)
        if field not in PINNED:
            raise KeyError(field)
        return "tamper{%s:%s:replace:%s}" % (proto, field, PINNED[field])
    if re.search(r"tamper(?!\{)|fragment(?!\{)|trace", s):
        return None  # random tamper or fragment order; trace needs sockets
    try:
        return re.sub(r"tamper\{([A-Za-z]+):([a-z-]+):corrupt(?::[^}]*)?\}", repl, s)
    except KeyError:
        return None


def make_packets():
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw
    c, s = "10.0.0.1", "10.0.0.2"
    opts = [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)), ("NOP", None), ("WScale", 7)]
    req = b"GET /?q=ultrasurf HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n"
    pkts = [
        IP(src=c, dst=s, id=1, flags="DF") / TCP(sport=40000, dport=80, flags="S", seq=1000, options=opts),
        IP(src=s, dst=c, id=2) / TCP(sport=80, dport=40000, flags="SA", seq=5000, ack=1001,
                                     options=[("MSS", 1400)]),
        IP(src=c, dst=s, id=3, flags="DF") / TCP(sport=40000, dport=80, flags="A", seq=1001, ack=5001),
        IP(src=c, dst=s, id=4, flags="DF") / TCP(sport=40000, dport=80, flags="PA", seq=1001,
                                                 ack=5001) / Raw(req),
        IP(src=s, dst=c, id=5) / TCP(sport=80, dport=40000, flags="R", seq=5001),
        IP(src=s, dst=c, id=6) / TCP(sport=80, dport=40000, flags="RA", seq=5001, ack=1001),
        IP(src=c, dst="8.8.8.8", id=7) / UDP(sport=33333, dport=53) /
        DNS(id=0x1234, rd=1, qd=DNSQR(qname="www.example.com")),
        IP(src=c, dst=s, id=8) / UDP(sport=1000, dport=9999) / Raw(b"x" * 50),
        IP(src=c, dst=s, id=9, flags="DF") / TCP(sport=40000, dport=80, flags="FA", seq=1068, ack=5001),
    ]
    return [bytes(p) for p in pkts]


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b23c4d, 2, 4, 0, 0, 65535, 101))
        for i, p in enumerate(packets):
            f.write(struct.pack("<IIII", i * 100, 0, len(p), len(p)))
            f.write(p)


def read_pcap(path):
    out = []
    with open(path, "rb") as f:
        hdr = f.read(24)
        magic = struct.unpack("<I", hdr[:4])[0]
        nsec = magic == 0xa1b23c4d
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            sec, frac, incl, _ = struct.unpack("<IIII", h)
            out.append((sec + frac / (1e9 if nsec else 1e6), f.read(incl)))
    return out


def direction(raw):
    from scapy.all import IP
    p = IP(raw)
    l4 = p.payload
    if not hasattr(l4, "dport"):
        return None
    if l4.dport in SERVER_PORTS:
        return "out"
    if l4.sport in SERVER_PORTS:
        return "in"
    return None


def geneva_apply(gu, gp, s, packets, logger):
    from scapy.all import IP
    st = gu.parse(s, logger)
    result = []
    for i, raw in enumerate(packets):
        d = direction(raw)
        if d is None:
            result.append((i, raw, 0))
            continue
        outs = st.act_on_packet(gp.Packet(IP(raw)), logger, direction=d)
        if d == "in":
            outs = outs[:1]
        for p in outs:
            result.append((i, bytes(p), p.sleep or 0))
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--geneva", required=True, help="Geneva checkout")
    ap.add_argument("--bin", required=True, help="geneva_c binary")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    binary = os.path.abspath(args.bin)
    geneva = os.path.abspath(args.geneva)

    corpus = [s for _, s in extract_strategies.collect(geneva)]
    strategies = corpus + [s for s in EXTRA if s not in corpus]

    gu, gp = load_geneva(geneva)
    logger = logging.getLogger("geneva-diff")
    logger.addHandler(ListHandler())
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # Geneva finds actions by instantiating every Action class; if that
    # breaks in this environment, nothing parses, so fail loudly here.
    action_mod = sys.modules["actions.action"]
    for d in ("out", "in"):
        try:
            found = sorted(name for name, _ in action_mod.Action.get_actions(d))
        except Exception:
            traceback.print_exc()
            raise SystemExit("Geneva cannot list its %s actions in this environment" % d)
        print("Geneva %s actions: %s" % (d, ", ".join(found)))
        if not found:
            raise SystemExit("Geneva found no %s actions" % d)

    failures = 0

    # 1. parse and print
    c_results = run_check(binary, strategies)
    n_same = 0
    for s, c in zip(strategies, c_results):
        ok, out = geneva_print(gu, s, logger)
        if ok and re.search(r"fragment(?!\{)", s):
            # random order: compare everything else
            out = re.sub(r"(fragment\{tcp:-1:)(True|False)", r"\1?", out)
            c_out = re.sub(r"(fragment\{tcp:-1:)(True|False)", r"\1?", c.get("strategy", ""))
        else:
            c_out = c.get("strategy")
        if c_out:
            # geneva_c keeps the wildcard "*" that Geneva drops when printing
            c_out = re.sub(r"\*(?=[\]:])", "", c_out)
        if ok and not c["ok"] and deliberate_reject(s):
            continue
        if ok != c["ok"] or (ok and out != c_out):
            failures += 1
            print("PARSE MISMATCH: %s\n  geneva:   %s\n  geneva_c: %s"
                  % (s, out if ok else "rejected (%s)" % out,
                     c_out if c["ok"] else "rejected (%s)" % c.get("error")))
        else:
            n_same += 1
    print("parse/print: %d of %d strategies agree" % (n_same, len(strategies)))

    # 2. apply
    packets = make_packets()
    tmp = tempfile.mkdtemp(prefix="geneva-diff-")
    inp = os.path.join(tmp, "in.pcap")
    outp = os.path.join(tmp, "out.pcap")
    write_pcap(inp, packets)
    n_run = n_skip = n_crash = 0
    for s in strategies:
        ps = pin(s)
        if ps is None or not geneva_print(gu, ps, logger)[0]:
            n_skip += 1
            continue
        try:
            expected = geneva_apply(gu, gp, ps, packets, logger)
        except BaseException as e:
            if isinstance(e, KeyboardInterrupt):
                raise
            # Geneva raises on some packets (e.g. "add" on a string field);
            # nothing to compare against.
            n_crash += 1
            if args.verbose:
                print("geneva raised %s on %s" % (type(e).__name__, ps))
            continue
        r = subprocess.run([binary, "apply", "-s", ps, "-i", inp, "-o", outp, "-p",
                            ",".join(str(p) for p in SERVER_PORTS)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if r.returncode != 0:
            failures += 1
            print("APPLY FAILED: %s\n%s" % (ps, r.stderr))
            continue
        got = read_pcap(outp)
        n_run += 1
        bad = len(got) != len(expected)
        for (i, eb, sleep), (ts, gb) in zip(expected, got):
            if eb != gb or abs(ts - (i * 100 + sleep)) > 1e-6:
                bad = True
        if bad:
            failures += 1
            print("APPLY MISMATCH: %s" % ps)
            for k in range(max(len(expected), len(got))):
                e = expected[k] if k < len(expected) else None
                g = got[k] if k < len(got) else None
                mark = "  " if e and g and e[1] == g[1] else "!!"
                print("  %s #%s geneva:   %s" % (mark, e[0] if e else "-",
                                                 e[1].hex() + (" sleep=%g" % e[2] if e[2] else "")
                                                 if e else "(none)"))
                print("  %s    geneva_c: %s" % (mark, g[1].hex() if g else "(none)"))
    print("apply: %d strategies compared, %d not deterministic, %d crash Geneva"
          % (n_run, n_skip, n_crash))
    if failures:
        print("%d differences" % failures)
        sys.exit(1)
    print("no differences")


if __name__ == "__main__":
    main()
