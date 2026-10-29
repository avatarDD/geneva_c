# Generates scapy reference bytes for geneva_c packet tests.
import copy, sys
from scapy.all import IP, IPv6, TCP, UDP, DNS, DNSQR, Raw, fragment

def h(b): return bytes(b).hex()
out = []
def emit(name, pkt):
    out.append((name, h(pkt)))

payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
base = IP(src="10.0.0.1", dst="10.0.0.2", id=1, ttl=64, flags="DF")/TCP(sport=40000, dport=80, flags="PA", seq=1000, ack=2000, window=502, options=[('MSS',1460),('NOP',None),('WScale',7)])/Raw(payload)
base = IP(bytes(base))  # wire form: all fields explicit, like a captured packet
emit("base", base)

def fresh(): return IP(bytes(base))

# Geneva Packet.set: del IP chksum, del TCP chksum, then setattr
p = fresh(); del p["IP"].chksum; del p["TCP"].chksum; p["IP"].ttl = 10; emit("ttl10", p)
p = fresh(); del p["IP"].chksum; del p["TCP"].chksum; p["TCP"].flags = "FRAPUN"; emit("flags_frapun", p)
p = fresh(); del p["IP"].chksum; del p["TCP"].chksum; p["TCP"].dataofs = 10; emit("dataofs10", p)
p = fresh(); del p["IP"].chksum; del p["TCP"].chksum; p["TCP"].chksum = 25776; emit("chksum25776", p)
p = fresh(); del p["IP"].chksum; del p["TCP"].chksum; p["IP"].flags = "MF+DF"; emit("ipflags_mfdf", p)

def set_opt(p, idx_name, fmt):
    found = False
    for i, o in enumerate(p["TCP"].options):
        if o[0] == idx_name[0] or o[0] == idx_name[1]:
            p["TCP"].options[i] = fmt; found = True; break
    if not found:
        opts = p["TCP"].options; opts.append(fmt); p["TCP"].options = opts
    del p["TCP"].chksum; del p["TCP"].dataofs; del p["IP"].chksum; del p["IP"].len

p = fresh(); del p["IP"].chksum; del p["TCP"].chksum; set_opt(p, ("WScale", 3), ("WScale", 200)); emit("opt_wscale200", p)
p = fresh(); del p["IP"].chksum; del p["TCP"].chksum; set_opt(p, ("Timestamp", 8), ("Timestamp", (12345, 0))); emit("opt_ts", p)
p = fresh(); del p["IP"].chksum; del p["TCP"].chksum; set_opt(p, ("MSS", 2), ("MSS", 0)); emit("opt_mss0", p)
p = fresh(); del p["IP"].chksum; del p["TCP"].chksum; set_opt(p, ("UTO", 28), ("UTO", 300)); emit("opt_uto", p)
p = fresh(); del p["IP"].chksum; del p["TCP"].chksum; set_opt(p, ("x", 19), (19, bytes.fromhex("00112233445566778899aabbccddeeff"))); emit("opt_md5", p)
p = fresh(); del p["IP"].chksum; del p["TCP"].chksum; set_opt(p, ("SAckOK", 4), ("SAckOK", b"")); emit("opt_sackok", p)
p = fresh(); del p["IP"].chksum; del p["TCP"].chksum; set_opt(p, ("NOP", 1), ("NOP", ())); emit("opt_nop_existing", p)
p = fresh(); del p["IP"].chksum; del p["TCP"].chksum; set_opt(p, ("AltChkSum", 14), ("AltChkSum", (7, 0))); emit("opt_altchksum", p)

# load replace (Layer.set_load): del IP len, payload = Raw
p = fresh(); del p["IP"].chksum; del p["TCP"].chksum; del p["IP"].len; p["TCP"].payload = Raw(b"hello world"); emit("load_hello", p)
p = fresh(); del p["IP"].chksum; del p["TCP"].chksum; del p["IP"].len; p["IP"].payload = Raw(b"xyz"); emit("ipload_xyz", p)

# tcp_segment(fragsize, overlap)
def seg(fragsize, overlap, ordered=True):
    packet = fresh()
    pl = packet["TCP"].load
    del packet["TCP"].load
    if fragsize == -1 or fragsize > len(pl) - 1:
        fragsize = int(len(pl)/2)
    ob = min(len(pl[fragsize:]), overlap)
    p1 = IP(bytes(packet["IP"]))/pl[:fragsize + ob]
    p2 = IP(bytes(packet["IP"]))/pl[fragsize:]
    p2["TCP"].seq += fragsize
    for q in (p1, p2):
        del q["IP"].chksum; del q["IP"].len; del q["TCP"].chksum; del q["TCP"].dataofs
    return p1, p2
a, b = seg(-1, 0); emit("seg_half_1", a); emit("seg_half_2", b)
a, b = seg(8, 5); emit("seg_8_5_1", a); emit("seg_8_5_2", b)

# ip_fragment with scapy fragment()
def ipfrag(fs):
    packet = fresh()
    load = bytes(packet["TCP"])
    if fs == -1 or (fs * 8) > len(load) or len(load) <= 8:
        fragsize = int(int(((int(len(load)/2))/8))*8)
    else:
        fragsize = fs * 8
    frags = fragment(packet.copy(), fragsize=fragsize)
    if len(frags) > 2:
        for frag in frags[2:]:
            frags[1]["IP"].load += frag["IP"].load
        frags[1]["IP"].flags = "DF"
    elif len(frags) == 1:
        frags.append(frags[0].copy())
    return frags[0], frags[1]
a, b = ipfrag(-1); emit("frag_half_1", a); emit("frag_half_2", b)
a, b = ipfrag(2); emit("frag_2_1", a); emit("frag_2_2", b)

# DNS
d = IP(src="10.0.0.1", dst="8.8.8.8", id=7)/UDP(sport=33333, dport=53)/DNS(id=0x1234, rd=1, qd=DNSQR(qname="www.example.com"))
d = IP(bytes(d)); emit("dns", d)
p = IP(bytes(d)); del p["IP"].chksum; p["DNS"].id = 0x4321; del p["UDP"].chksum; emit("dns_id", p)

# Geneva dns_decompress (fixed qtype/qclass A/IN like upstream)
def compress(packet):
    query = packet["DNSQR"].qname.decode()
    if query[-1] != '.': query += '.'
    labels = query.split(".")
    fhalf = labels[0]; shalf = ".".join(labels[1:])
    length = bytes([len(fhalf)]); label = fhalf.encode()
    off = 2*6 + 1 + len(label) + 2 + 2 + 2
    offset = (0xc000 | off).to_bytes(2, byteorder='big')
    qr1 = length + label + offset + b'\x00\x01\x00\x01'
    qr2 = b"".join([bytes([len(t)]) + t.encode() for t in shalf.split(".")]) + b"\x00\x01\x00\x01"
    packet["DNS"].qd = None
    packet["DNS"].qdcount = 2
    hdr = bytes(packet["DNS"])
    dp = DNS(hdr + qr1 + qr2)
    del packet["DNS"]
    packet = packet / dp
    del packet["IP"].chksum; del packet["IP"].len; del packet["UDP"].chksum; del packet["UDP"].len
    return packet
emit("dns_compressed", compress(IP(bytes(d))))

# IPv6
v6 = IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=64)/TCP(sport=40000, dport=443, flags="S", seq=1, window=64240, options=[('MSS',1440)])
v6 = IPv6(bytes(v6)); emit("v6syn", v6)
p = IPv6(bytes(v6)); del p["TCP"].chksum; p.hlim = 3; emit("v6_hlim3", p)
u6 = IPv6(src="2001:db8::1", dst="2001:db8::2")/UDP(sport=1000, dport=2000)/Raw(b"abc")
emit("v6udp", IPv6(bytes(u6)))

w = sys.stdout
w.write("/* Generated by scapy %s: reference bytes for packet tests. */\n" % __import__("scapy").VERSION)
w.write("static const struct { const char *name; const char *hex; } golden_pkts[] = {\n")
for n, x in out:
    w.write('    {"%s", "%s"},\n' % (n, x))
w.write("};\n")
