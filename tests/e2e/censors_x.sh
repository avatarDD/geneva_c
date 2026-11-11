#!/bin/sh
# End-to-end test of the lab censors 12-20 ("geneva censor --ext",
# docs/CENSOR.md): the same three namespaces as censors.sh (needs root,
# iproute2, python3, openssl, curl, and nft or iptables).
#
#   client ns 10.81.1.2 --- 10.81.1.1 censor ns 10.81.2.1 --- 10.81.2.2 server ns
#                           (geneva censor --ext)              (HTTP, HTTPS, UDP echo)
#
# For every censor: what it is made to see is blocked the way it says, and
# the same request without the word (or another address) gets through. For
# 19 and 20 also a Geneva strategy: a desync that a naive censor falls for
# does not fool 19, and IP fragments get past 20.
#
# With NFQWS2_DIR (an unpacked official zapret2 release: binaries/ and lua/,
# readable by everyone, as nfqws2 drops root) the section "nfqws2" runs
# nfqws2 in the client namespace with a reference strategy (nfqws2 syntax,
# --lua-desync) against each censor it can beat (docs/CENSOR.md). Usage:
# The section "posdebug" (also with NFQWS2_DIR) checks the conntrack of
# --ext against nfqws2's posdebug on the same packets (stage X3).
# The section "diff" (also with NFQWS2_DIR) checks x-actions against
# nfqws2 packet by packet.
# The section "xact" (or x14 ... x20 for one censor) runs geneva --ext with x-action strategies (the
# nfqws2 references as x-actions, and combinators) against 14, 15, 18-20.
#   tests/e2e/censors_x.sh [path/to/geneva] [censor ... | xact | nfqws2 | diff | posdebug]
set -u
GENEVA=$(readlink -f "${1:-build/geneva}")
[ $# -gt 0 ] && shift
ONLY="$*"
NC=gnx_c$$ NR=gnx_r$$ NS=gnx_s$$
WORK=$(mktemp -d)
fails=0

cleanup() {
    [ -n "${CPID:-}" ] && kill "$CPID" 2>/dev/null && wait "$CPID" 2>/dev/null
    # nfqws2, geneva run and tcpdump of the nfqws2 and diff sections: the
    # rules they need live in the client namespace and go with it
    for p in ${NPID:-} ${TPID:-}; do kill "$p" 2>/dev/null; done
    [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null
    for n in "$NC" "$NR" "$NS"; do ip netns del "$n" 2>/dev/null; done
    [ -n "${KEEP:-}" ] && cp -r "$WORK" "$KEEP"
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

for n in "$NC" "$NR" "$NS"; do
    ip netns add "$n" || { echo "cannot create namespaces"; exit 1; }
    ip -n "$n" link set lo up
done
ip link add vx_c netns "$NC" type veth peer name vx_rc netns "$NR"
ip link add vx_s netns "$NS" type veth peer name vx_rs netns "$NR"
ip -n "$NC" addr add 10.81.1.2/24 dev vx_c
ip -n "$NR" addr add 10.81.1.1/24 dev vx_rc
ip -n "$NR" addr add 10.81.2.1/24 dev vx_rs
ip -n "$NS" addr add 10.81.2.2/24 dev vx_s
ip -n "$NS" addr add 10.81.2.3/24 dev vx_s
for l in "$NC vx_c" "$NR vx_rc" "$NR vx_rs" "$NS vx_s"; do
    set -- $l
    ip -n "$1" link set "$2" up
    ip netns exec "$1" ethtool -K "$2" tso off gso off gro off >/dev/null 2>&1
done
ip -n "$NC" route add default via 10.81.1.1
ip -n "$NS" route add default via 10.81.2.1
ip netns exec "$NR" sysctl -qw net.ipv4.ip_forward=1

mkdir "$WORK/www"
echo "the page behind the censor" > "$WORK/www/secret.html"
head -c 300000 /dev/zero > "$WORK/www/big.bin"
head -c 4000000 /dev/zero > "$WORK/www/huge.bin"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=lab -keyout "$WORK/key.pem" \
    -out "$WORK/cert.pem" >/dev/null 2>&1 || { echo "openssl failed"; exit 1; }
# HTTP on 80, HTTPS on 443 (any name), and a UDP echo on 443 for QUIC
cat > "$WORK/srv.py" <<'EOF'
import http.server, os, socket, ssl, sys, threading
work = sys.argv[1]
os.chdir(work + "/www")
class H(http.server.SimpleHTTPRequestHandler):
    timeout = 10
    def log_message(self, *a):
        pass
def serve(port, tls):
    s = http.server.ThreadingHTTPServer(("0.0.0.0", port), H)
    if tls:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        c.load_cert_chain(work + "/cert.pem", work + "/key.pem")
        # the handshake in the request's thread: a ClientHello that a
        # censor dropped must not hold up accept() for the next clients
        s.socket = c.wrap_socket(s.socket, server_side=True, do_handshake_on_connect=False)
    s.serve_forever()
def echo():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("0.0.0.0", 443))
    while True:
        d, a = u.recvfrom(65535)
        u.sendto(d[:64], a)
threading.Thread(target=serve, args=(80, False), daemon=True).start()
def dns():
    # every A query: 10.81.2.80 (the names may be compressed)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("0.0.0.0", 53))
    while True:
        q, a = u.recvfrom(4096)
        if len(q) < 12:
            continue
        off = 12
        while off < len(q) and q[off] and not q[off] & 0xc0:
            off += 1 + q[off]
        end = off + (2 if off < len(q) and q[off] & 0xc0 else 1) + 4
        r = q[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:end]
        r += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([10, 81, 2, 80])
        u.sendto(r, a)
threading.Thread(target=echo, daemon=True).start()
threading.Thread(target=dns, daemon=True).start()
serve(443, True)
EOF
ip netns exec "$NS" python3 "$WORK/srv.py" "$WORK" > "$WORK/srv.log" 2>&1 &
SRV=$!
for _ in $(seq 50); do
    ip netns exec "$NS" curl -s -o /dev/null http://10.81.2.2/ && break
    sleep 0.1
done

# A QUIC client in miniature: sends a file as one datagram from a fixed port,
# twice, and prints how many echoes came back.
cat > "$WORK/udp.py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", int(sys.argv[3])))
s.settimeout(1)
d = open(sys.argv[2], "rb").read()
n = 0
for _ in range(2):
    s.sendto(d, (sys.argv[1], 443))
    try:
        s.recvfrom(65535)
        n += 1
    except socket.timeout:
        pass
print(n)
EOF
DATA=$(cd "$(dirname "$0")/../data/zapret2" && pwd)

ok() { echo "  ok   $1"; }
bad() { fails=$((fails + 1)); echo "  FAIL $1"; [ -n "${2:-}" ] && sed 's/^/       /' "$2" | tail -30; }
want() { if [ "$2" = "$3" ]; then ok "$1 ($2)"; else bad "$1: got $2, expected $3" "$WORK/cen.log"; fi; }
on() { [ -z "$ONLY" ] || echo " $ONLY " | grep -q " $1 "; }

# start_censor NAME [options]
start_censor() {
    : > "$WORK/cen.jsonl"
    : > "$WORK/cen.log"
    ip netns exec "$NR" "$GENEVA" censor --ext -c "$@" --events "$WORK/cen.jsonl" \
        --log-file "$WORK/cen.log" ${CENSOR_LOG:+--log-level $CENSOR_LOG} --quiet &
    CPID=$!
    for _ in $(seq 50); do
        grep -q '"ev":"ready"' "$WORK/cen.jsonl" 2>/dev/null && return 0
        sleep 0.1
    done
    bad "censor $1 did not start" "$WORK/cen.log"
    return 1
}

# stop_censor [none]: "none" when the censor must not have fired (a bypass)
stop_censor() {
    if [ "${1:-}" = none ]; then
        grep -q '"ev":"censorship"' "$WORK/cen.jsonl" && bad "the censor fired" "$WORK/cen.jsonl" || ok "the censor did not fire"
    else
        grep -q '"ev":"censorship"' "$WORK/cen.jsonl" && ok "censorship event" || bad "no censorship event"
    fi
    kill "$CPID" 2>/dev/null
    wait "$CPID" 2>/dev/null
    CPID=
    ip netns exec "$NR" sh -c 'iptables-save 2>/dev/null; nft list ruleset 2>/dev/null' | grep -qi geneva &&
        bad "censor rules left behind"
}

# HTTP status and size: "code bytes"
http() { # path [curl options]
    p=$1
    shift
    ip netns exec "$NC" curl --noproxy "*" -s -o "$WORK/body" -w '%{http_code}' --max-time 4 "$@" "http://10.81.2.2$p" > "$WORK/code"
    echo "$(cat "$WORK/code") $(wc -c < "$WORK/body" 2>/dev/null || echo 0)"
}
# HTTPS with a name for the SNI: the exit code of curl (0, 35 reset, 28 timeout)
https() { # name [address]
    ip netns exec "$NC" curl --noproxy "*" -sk -o /dev/null --max-time 4 --resolve "$1:443:${2:-10.81.2.2}" "https://$1/secret.html"
    echo $?
}
# eval with Geneva's http probe and a strategy: the fitness
PROBE="--probe http --host censored.example --ip 10.81.2.2 --path / --valid-contains secret --timeout 2"
fit() {
    if [ $# -gt 0 ]; then
        ip netns exec "$NC" "$GENEVA" eval $PROBE --bad-word ultrasurf --quiet -s "$1" > "$WORK/eval.txt"
    else
        ip netns exec "$NC" "$GENEVA" eval $PROBE --bad-word ultrasurf --quiet > "$WORK/eval.txt"
    fi
    cut -f1 "$WORK/eval.txt" | head -1
}
positive() { awk -v f="$1" 'BEGIN { exit !(f > 0) }'; }

echo "== baseline without a censor"
want "the page loads" "$(http /secret.html)" "200 27"
want "HTTPS loads" "$(https ultrasurf.example)" 0
want "UDP echoes" "$(ip netns exec "$NC" python3 "$WORK/udp.py" 10.81.2.2 "$DATA/quic_initial_www_google_com.bin" 40001)" 2

if on 12; then
    echo "== censor 12: freeze"
    start_censor 12 --freeze-bytes 20000 && {
        want "without the word" "$(http /big.bin)" "200 300000"
        r=$(http '/big.bin?ultrasurf')
        n=${r#* }
        [ "$n" -lt 300000 ] && [ "$n" -le 20000 ] && ok "frozen after $n bytes" || bad "not frozen: $r" "$WORK/cen.log"
        stop_censor
    }
fi

if on 13; then
    echo "== censor 13: policer"
    start_censor 13 --rate 60000 --burst 20000 && {
        t0=$(date +%s%N)
        ip netns exec "$NC" curl --noproxy "*" -s -o /dev/null --max-time 30 'http://10.81.2.2/big.bin?ultrasurf'
        rc=$?
        ms=$((($(date +%s%N) - t0) / 1000000))
        # 300 KB at 60 KB/s after a 20 KB burst: at least 4.5 s
        [ $rc -eq 0 ] && [ $ms -ge 3500 ] && ok "loads, slowly ($ms ms)" || bad "rc $rc in $ms ms" "$WORK/cen.log"
        t0=$(date +%s%N)
        ip netns exec "$NC" curl --noproxy "*" -s -o /dev/null --max-time 30 'http://10.81.2.2/big.bin'
        ms=$((($(date +%s%N) - t0) / 1000000))
        [ $ms -lt 2000 ] && ok "without the word: $ms ms" || bad "without the word: $ms ms"
        stop_censor
    }
fi

if on 14; then
    echo "== censor 14: RSTs on the SNI"
    start_censor 14 && {
        want "other name" "$(https lab.example)" 0
        r=$(https ultrasurf.example)
        [ "$r" != 0 ] && ok "reset (curl $r)" || bad "the name gets through" "$WORK/cen.log"
        stop_censor
    }
fi

if on 15; then
    echo "== censor 15: ClientHello reassembly"
    start_censor 15 && {
        want "other name" "$(https lab.example)" 0
        r=$(https ultrasurf.example)
        [ "$r" != 0 ] && ok "dropped (curl $r)" || bad "the name gets through" "$WORK/cen.log"
        stop_censor
    }
fi

if on 16; then
    echo "== censor 16: QUIC Initial"
    start_censor 16 --forbidden google && {
        want "other name" "$(ip netns exec "$NC" python3 "$WORK/udp.py" 10.81.2.2 "$DATA/quic_initial_vk_com.bin" 40002)" 2
        want "the name dropped" "$(ip netns exec "$NC" python3 "$WORK/udp.py" 10.81.2.2 "$DATA/quic_initial_www_google_com.bin" 40003)" 0
        stop_censor
    }
fi

if on 17; then
    echo "== censor 17: IP block"
    start_censor 17 --block-ip 10.81.2.3 --port 80,443 && {
        want "other address" "$(https lab.example 10.81.2.2)" 0
        r=$(https lab.example 10.81.2.3)
        [ "$r" != 0 ] && ok "blocked address (curl $r)" || bad "the address gets through" "$WORK/cen.log"
        stop_censor
    }
fi

if on 18; then
    echo "== censor 18: HTTP redirect"
    start_censor 18 --redirect http://block.example/ && {
        want "other host" "$(http /secret.html -H 'Host: lab.example')" "200 27"
        want "the host redirected" "$(http /secret.html -H 'Host: ultrasurf.example')" "302 0"
        ip netns exec "$NC" curl --noproxy "*" -s -D - -o /dev/null --max-time 4 -H 'Host: ultrasurf.example' \
            http://10.81.2.2/secret.html | grep -qi '^location: http://block.example/' &&
            ok "Location of the block page" || bad "no Location"
        stop_censor
    }
fi

# a desync that beats censor 1: RST and SYN with a bad checksum
DESYNC='[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:14239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:chksum:replace:14239},),))-| \/'
if on 19; then
    echo "== censor 19: strict"
    start_censor 19 && {
        f=$(fit)
        positive "${f:-0}" && bad "the word gets through ($f)" "$WORK/cen.log" || ok "blocked ($f)"
        f=$(fit "$DESYNC")
        positive "${f:-0}" && bad "fooled by bad checksums ($f)" "$WORK/cen.log" || ok "not fooled by bad checksums ($f)"
        stop_censor
    }
    echo "== censor 1 for comparison"
    : > "$WORK/cen.log"
    ip netns exec "$NR" "$GENEVA" censor -c 1 --events "$WORK/cen.jsonl" --log-file "$WORK/cen.log" --quiet &
    CPID=$!
    sleep 1
    f=$(fit "$DESYNC")
    positive "${f:-0}" && ok "the desync beats censor 1 ($f)" || bad "censor 1 blocks the desync ($f)" "$WORK/cen.log"
    kill "$CPID" 2>/dev/null
    wait "$CPID" 2>/dev/null
    CPID=
fi

if on 20; then
    echo "== censor 20: first fragments only"
    start_censor 20 && {
        f=$(fit)
        positive "${f:-0}" && bad "the word gets through ($f)" "$WORK/cen.log" || ok "blocked ($f)"
        f=$(fit '[TCP:flags:PA]-fragment{ip:3:True}-| \/')
        positive "${f:-0}" && ok "IP fragments get through ($f)" || bad "fragments blocked ($f)" "$WORK/cen.log"
        stop_censor
    }
fi

# x-actions (stage X5): geneva itself with the reference strategies of the
# nfqws2 section written as x-actions, and with combinators; "geneva eval
# --ext" runs the engine in the client namespace. XNAME censor-options
# probe-options strategy: blocked without, through with the strategy.
TLSPROBE="--probe tls --host ultrasurf.example --ip 10.81.2.2 --timeout 2"
HOSTPROBE="--probe http --host ultrasurf.example --ip 10.81.2.2 --path /secret.html --valid-contains behind --timeout 2"
WORDPROBE="$PROBE --bad-word ultrasurf"
xfit() { # probe-options [strategy]
    if [ $# -gt 1 ]; then
        ip netns exec "$NC" "$GENEVA" eval --ext $1 ${XLOG:---quiet} -s "$2" > "$WORK/eval.txt" 2> "$WORK/eval.log"
    else
        ip netns exec "$NC" "$GENEVA" eval --ext $1 --quiet > "$WORK/eval.txt" 2> "$WORK/eval.log"
    fi
    cut -f1 "$WORK/eval.txt" | head -1
}
xcase() {
    name=$1 copts=$2 probe=$3
    shift 3
    on xact || on "x$name" || return
    echo "== x-actions against censor $name"
    start_censor $name $copts || return
    f=$(xfit "$probe")
    positive "${f:-0}" && bad "the probe gets through without a strategy ($f)" "$WORK/cen.log" || ok "blocked ($f)"
    for s in "$@"; do
        f=$(xfit "$probe" "$s")
        positive "${f:-0}" && ok "gets through ($f): $s" || bad "blocked ($f): $s" "$WORK/eval.log"
    done
    kill "$CPID" 2>/dev/null
    wait "$CPID" 2>/dev/null
    CPID=
}
xcase 14 "" "$TLSPROBE" '[TCP:flags:PA]-xsplit{pos=1}-| \/' \
    '[TCP:dport:443]-xwhen{iff=L7:payload:tls_client_hello}(xsplit{pos=1},)-| \/'
xcase 15 "" "$TLSPROBE" '[TCP:flags:PA]-xdisorder{pos=1,midsld}-| \/' \
    '[TCP:flags:PA]-xrepeat{repeats=1}(xcutoff,xdisorder{pos=1,midsld})-| \/'
xcase 18 "" "$HOSTPROBE" '[TCP:flags:PA]-xsplit{pos=method+2}-| \/'
xcase 19 "" "$WORDPROBE" '[TCP:flags:PA]-xsplit{pos=9}-| \/' \
    '[TCP:flags:PA]-xstop{iff=cond_payload_str;pattern=ultrasurf;neg}(xsplit{pos=9},)-| \/'
xcase 20 "" "$WORDPROBE" '[TCP:flags:PA]-xsend{ipfrag;ipfrag_pos_tcp=24}(drop,)-| \/' \
    '[TCP:flags:PA]-xwhen{iff=L7:payload:http_req}(xsend{ipfrag;ipfrag_pos_tcp=24}(drop,),)-| \/'

# nfqws2 NAME "censor options" "check" nfqws2-options...: the check (a shell
# command printing "ok" when the request got through) with nfqws2 running
nfqws2_case() {
    name=$1 copts=$2 check=$3
    shift 3
    echo "== nfqws2 against censor $name"
    start_censor $name $copts || return
    ip netns exec "$NC" sh -c 'iptables -t mangle -N ZT 2>/dev/null
        iptables -t mangle -A ZT -m mark --mark 0x40000000/0x40000000 -j RETURN
        iptables -t mangle -A ZT -p tcp -m multiport --dports 80,443 -j NFQUEUE --queue-num 300 --queue-bypass
        iptables -t mangle -A ZT -p udp --dport 443 -j NFQUEUE --queue-num 300 --queue-bypass
        iptables -t mangle -I OUTPUT -j ZT'
    ip netns exec "$NC" "$NFQ" --qnum=300 --lua-init=@"$NFQWS2_DIR/lua/zapret-lib.lua" \
        --lua-init=@"$NFQWS2_DIR/lua/zapret-antidpi.lua" "$@" > "$WORK/nfq.log" 2>&1 &
    NPID=$!
    sleep 1.5
    if ! kill -0 $NPID 2>/dev/null; then
        bad "nfqws2 did not start" "$WORK/nfq.log"
    else
        r=$(eval "$check")
        [ "$r" = ok ] && ok "gets through: $*" || bad "blocked ($r): $*" "$WORK/cen.log"
        kill $NPID 2>/dev/null
        wait $NPID 2>/dev/null
    fi
    ip netns exec "$NC" sh -c 'iptables -t mangle -D OUTPUT -j ZT; iptables -t mangle -F ZT; iptables -t mangle -X ZT'
    stop_censor none
}
if [ -n "${NFQWS2_DIR:-}" ] && on nfqws2; then
    NFQ=$NFQWS2_DIR/binaries/linux-x86_64/nfqws2
    "$NFQ" --version 2>&1 | head -1
    # TLS: the first segment carries one byte, so 14 finds no ClientHello
    nfqws2_case 14 "" '[ "$(https ultrasurf.example)" = 0 ] && echo ok' \
        --filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=multisplit:pos=1
    # three segments sent last first: 15 reassembles only two in order
    nfqws2_case 15 "" '[ "$(https ultrasurf.example)" = 0 ] && echo ok' \
        --filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=multidisorder:pos=1,midsld
    # a fake Initial with another name first: 16 reads only the first one
    nfqws2_case 16 "--forbidden google" \
        '[ "$(ip netns exec "$NC" python3 "$WORK/udp.py" 10.81.2.2 "$DATA/quic_initial_www_google_com.bin" 40010)" != 0 ] && echo ok' \
        --blob=qvk:@"$NFQWS2_DIR/files/fake/quic_initial_vk_com.bin" \
        --filter-udp=443 --filter-l7=quic --payload=quic_initial --lua-desync=fake:blob=qvk
    # "GE" + the rest: no packet starts with a method and holds the Host
    nfqws2_case 18 "" '[ "$(http /secret.html -H "Host: ultrasurf.example")" = "200 27" ] && echo ok' \
        --filter-tcp=80 --filter-l7=http --payload=http_req --lua-desync=multisplit:pos=method+2
    # the word split between two segments (GET /?q=ul|trasurf)
    nfqws2_case 19 "" '[ "$(http "/?q=ultrasurf" | cut -d" " -f1)" = 200 ] && echo ok' \
        --filter-tcp=80 --filter-l7=http --payload=http_req --lua-desync=multisplit:pos=9
    # IP fragments, the word in the second one
    nfqws2_case 20 "" '[ "$(http "/?q=ultrasurf" | cut -d" " -f1)" = 200 ] && echo ok' \
        --filter-tcp=80 --filter-l7=http --payload=http_req \
        --lua-desync=send:ipfrag:ipfrag_pos_tcp=24 --lua-desync=drop
fi

# Differential (stage X5): the same desync from nfqws2 (zapret2's Lua) and
# from geneva's x-actions, on the same request without a censor; tcpdump on
# the client's interface and shape.py reduce each capture to the client's
# data packets and IP fragments (position from the SYN, length, flags,
# TTL, and a hash of the payload, but not of TLS, which curl makes anew
# every time, nor of fragments, which hold the TCP header). Both lists have
# to be the same.
cat > "$WORK/shape.py" <<'EOF'
import hashlib, struct, sys
d = open(sys.argv[1], "rb").read()
E = "<" if d[:4] == b"\xd4\xc3\xb2\xa1" else ">"
link = struct.unpack(E + "I", d[20:24])[0]
o, isn = 24, {}
while o + 16 <= len(d):
    cap = struct.unpack(E + "I", d[o + 8:o + 12])[0]
    p = d[o + 16:o + 16 + cap]
    o += 16 + cap
    if link == 1:
        p = p[14:]
    if len(p) < 20 or p[0] >> 4 != 4 or p[12:16] != bytes([10, 81, 1, 2]):
        continue
    ihl, tot, ttl = (p[0] & 15) * 4, struct.unpack(">H", p[2:4])[0], p[8]
    fo = struct.unpack(">H", p[6:8])[0]
    off, mf = (fo & 0x1fff) * 8, fo >> 13 & 1
    if off or mf:
        print("frag off=%d mf=%d len=%d ttl=%d" % (off, mf, tot - ihl, ttl))
        continue
    if p[9] != 6:
        continue
    t = p[ihl:tot]
    sport, dport = struct.unpack(">HH", t[0:4])
    seq, fl = struct.unpack(">I", t[4:8])[0], t[13]
    pl = t[(t[12] >> 4) * 4:]
    if fl & 2:
        isn[sport] = seq
    if not pl and not fl & 4:
        continue
    names = "".join(c for b, c in zip((1, 2, 4, 8, 16), "FSRPA") if fl & b)
    h = "tls" if dport == 443 else hashlib.md5(pl).hexdigest()[:8]
    print("seq=%d len=%d %s ttl=%d %s" % ((seq - isn.get(sport, seq)) & 0xffffffff, len(pl), names, ttl, h))
EOF
cap_start() {
    ip netns exec "$NC" tcpdump -i vx_c --immediate-mode -U -w "$WORK/$1.pcap" \
        'host 10.81.2.2 and (tcp port 80 or tcp port 443 or ip[6:2] & 0x1fff != 0)' > "$WORK/tcpdump.log" 2>&1 &
    TPID=$!
    for _ in $(seq 50); do grep -q "listening on" "$WORK/tcpdump.log" && break; sleep 0.1; done
}
cap_stop() {
    sleep 0.3
    kill -INT $TPID 2>/dev/null
    wait $TPID 2>/dev/null
}
# xdiff NAME "request" "geneva strategy" nfqws2-options...
xdiff() {
    name=$1 req=$2 strat=$3
    shift 3
    ip netns exec "$NC" sh -c 'iptables -t mangle -N ZT 2>/dev/null
        iptables -t mangle -A ZT -m mark --mark 0x40000000/0x40000000 -j RETURN
        iptables -t mangle -A ZT -p tcp -m multiport --dports 80,443 -j NFQUEUE --queue-num 302 --queue-bypass
        iptables -t mangle -I OUTPUT -j ZT'
    ip netns exec "$NC" "$NFQ" --qnum=302 --lua-init=@"$NFQWS2_DIR/lua/zapret-lib.lua" \
        --lua-init=@"$NFQWS2_DIR/lua/zapret-antidpi.lua" --lua-init=@"$NFQWS2_DIR/lua/zapret-auto.lua" \
        "$@" > "$WORK/nfq.log" 2>&1 &
    NPID=$!
    sleep 1.5
    cap_start z
    eval "$req" > /dev/null
    cap_stop
    kill $NPID 2>/dev/null
    wait $NPID 2>/dev/null
    ip netns exec "$NC" sh -c 'iptables -t mangle -D OUTPUT -j ZT; iptables -t mangle -F ZT; iptables -t mangle -X ZT'
    # a strategy, or geneva's options when it starts with "--" (profiles)
    case $strat in
    --*) gargs=$strat ;;
    *) gargs="-s '$strat' -p 80,443" ;;
    esac
    eval "ip netns exec \"\$NC\" \"\$GENEVA\" run --ext $gargs --log-file \"\$WORK/run.log\" --quiet &"
    NPID=$!
    sleep 1.5
    cap_start g
    eval "$req" > /dev/null
    cap_stop
    kill $NPID 2>/dev/null
    wait $NPID 2>/dev/null
    python3 "$WORK/shape.py" "$WORK/z.pcap" > "$WORK/z.txt"
    python3 "$WORK/shape.py" "$WORK/g.pcap" > "$WORK/g.txt"
    if [ ! -s "$WORK/z.txt" ]; then
        bad "$name: nothing captured" "$WORK/nfq.log"
    elif diff "$WORK/z.txt" "$WORK/g.txt" > "$WORK/x.diff"; then
        ok "$name: $(wc -l < "$WORK/z.txt") packets as nfqws2's"
    else
        bad "$name: differs from nfqws2 (< nfqws2, > geneva)" "$WORK/x.diff"
    fi
}
if [ -n "${NFQWS2_DIR:-}" ] && { on nfqws2 || on diff; }; then
    NFQ=$NFQWS2_DIR/binaries/linux-x86_64/nfqws2
    echo "== x-actions against nfqws2: the same packets"
    T='--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello'
    H='--filter-tcp=80 --filter-l7=http --payload=http_req'
    TR='https lab.example'
    HR='http /secret.html'
    xdiff multisplit "$TR" '[TCP:flags:PA]-xsplit{pos=1}-| \/' $T --lua-desync=multisplit:pos=1
    xdiff multisplit-http "$HR" '[TCP:flags:PA]-xsplit{pos=method+2,host}-| \/' \
        $H --lua-desync=multisplit:pos=method+2,host
    xdiff multidisorder "$TR" '[TCP:flags:PA]-xdisorder{pos=1,midsld}-| \/' \
        $T --lua-desync=multidisorder:pos=1,midsld
    xdiff fake "$HR" '[TCP:flags:PA]-xfake{blob=0x474554202f;ttl=1;seq=-10000}-| \/' \
        $H --lua-desync=fake:blob=0x474554202f:ip_ttl=1:tcp_seq=-10000
    xdiff fakedsplit "$HR" '[TCP:flags:PA]-xfakedsplit{pos=method+2;ttl=1}-| \/' \
        $H --lua-desync=fakedsplit:pos=method+2:ip_ttl=1
    xdiff seqovl "$HR" '[TCP:flags:PA]-xsplit{pos=host;seqovl=5;seqovl_pattern=0x41}-| \/' \
        $H --lua-desync=multisplit:pos=host:seqovl=5:seqovl_pattern=0x41
    xdiff fakeddisorder "$HR" '[TCP:flags:PA]-xfakeddisorder{pos=method+2;ttl=1}-| \/' \
        $H --lua-desync=fakeddisorder:pos=method+2:ip_ttl=1
    xdiff tcpseg "$HR" '[TCP:flags:PA]-xtcpseg{pos=2,10}-| \/' $H --lua-desync=tcpseg:pos=2,10
    xdiff ipfrag "$HR" '[TCP:flags:PA]-xsend{ipfrag;ipfrag_pos_tcp=24}(drop,)-| \/' \
        $H --lua-desync=send:ipfrag:ipfrag_pos_tcp=24 --lua-desync=drop
    xdiff repeater "$HR" '[TCP:flags:PA]-xrepeat{repeats=2}(xfake{blob=0x41;ttl=1},xsplit{pos=2})-| \/' \
        $H --lua-desync=repeater:repeats=2 --lua-desync=fake:blob=0x41:ip_ttl=1 --lua-desync=multisplit:pos=2
    xdiff condition "$HR" '[TCP:flags:PA]-xwhen{iff=cond_payload_str;pattern=secret}(xsplit{pos=5},)-| \/' \
        $H --lua-desync=condition:iff=cond_payload_str:pattern=secret --lua-desync=multisplit:pos=5
    xdiff condition-neg "$HR" '[TCP:flags:PA]-xwhen{iff=cond_payload_str;pattern=secret;neg}(xsplit{pos=5},)-| \/' \
        $H --lua-desync=condition:iff=cond_payload_str:pattern=secret:neg --lua-desync=multisplit:pos=5
    xdiff stopif "$HR" '[TCP:flags:PA]-xfake{blob=0x41;ttl=1}(xstop{iff=cond_payload_str;pattern=GET}(xsplit{pos=3},),)-| \/' \
        $H --lua-desync=fake:blob=0x41:ip_ttl=1 --lua-desync=stopif:iff=cond_payload_str:pattern=GET \
        --lua-desync=multisplit:pos=3
    # profiles (stage X6a): an HTTP and a TLS request, each with its own
    # profile; geneva takes the ports from the profiles (no -p)
    xdiff profiles "$HR; $TR" "--filter-tcp 80 --filter-l7 http -s '[TCP:flags:PA]-xsplit{pos=method+2}-| \\/' \
--new=tls --filter-tcp 443 --filter-l7 tls -s '[TCP:flags:PA]-xdisorder{pos=1,midsld}-| \\/'" \
        --filter-tcp=80 --filter-l7=http --payload=http_req --lua-desync=multisplit:pos=method+2 \
        --new --filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=multidisorder:pos=1,midsld
    # lists (stage X6b): TLS by the host name (a parent domain, an exclude),
    # HTTP by the server's subnet (its Host is the address)
    xdiff lists "$HR; $TR; https other.example" "--filter-tcp 443 --hostlist-domains example \
--hostlist-exclude-domains other.example -s '[TCP:flags:PA]-xdisorder{pos=1,midsld}-| \\/' \
--new=ip --filter-tcp 80 --ipset-ip 10.81.2.0/24 -s '[TCP:flags:PA]-xsplit{pos=method+2}-| \\/'" \
        --filter-tcp=443 --hostlist-domains=example --hostlist-exclude-domains=other.example \
        --payload=tls_client_hello --lua-desync=multidisorder:pos=1,midsld \
        --new --filter-tcp=80 --ipset-ip=10.81.2.0/24 --payload=http_req --lua-desync=multisplit:pos=method+2
fi

# Position parity (stage X3): nfqws2 runs zapret2's posdebug on every packet
# of a few flows in the client namespace while tcpdump captures them on its
# interface; "geneva apply --ext --ext-posdebug" over the capture has to see
# the same counters. The direct side of each line is compared strictly per
# direction (it depends only on the side's own packets); the whole lines are
# compared too, but the reverse side may differ where a reply crossed a
# packet held in the queue, so that only warns.
pd_lines() { # log direction: "posdebug: DIR ..." lines without the time
    # and without what nfqws2 adds after the payload ("reasm N", "decrypt N":
    # its reassembly and QUIC decryption buffers, not counters)
    grep -o "posdebug: $2 .*" "$1" | sed -e 's/ time +[^ ]*s direct/ direct/' -e 's/\( payload [0-9]*\) .*$/\1/'
}
if [ -n "${NFQWS2_DIR:-}" ] && { on nfqws2 || on posdebug; }; then
    NFQ=$NFQWS2_DIR/binaries/linux-x86_64/nfqws2
    echo "== posdebug parity with nfqws2"
    ip netns exec "$NC" sh -c 'iptables -t mangle -N ZT 2>/dev/null
        iptables -t mangle -A ZT -m mark --mark 0x40000000/0x40000000 -j RETURN
        iptables -t mangle -A ZT -p tcp -m multiport --dports 80,443 -j NFQUEUE --queue-num 301
        iptables -t mangle -A ZT -p udp --dport 443 -j NFQUEUE --queue-num 301
        iptables -t mangle -N ZTI 2>/dev/null
        iptables -t mangle -A ZTI -p tcp -m multiport --sports 80,443 -j NFQUEUE --queue-num 301
        iptables -t mangle -A ZTI -p udp --sport 443 -j NFQUEUE --queue-num 301
        iptables -t mangle -I OUTPUT -j ZT
        iptables -t mangle -I INPUT -j ZTI'
    # --immediate-mode: without it tcpdump loses its backlog when stopped
    ip netns exec "$NC" tcpdump -i vx_c --immediate-mode -U -w "$WORK/pd.pcap" \
        'tcp port 80 or tcp port 443 or udp port 443' > "$WORK/tcpdump.log" 2>&1 &
    TPID=$!
    for _ in $(seq 50); do grep -q "listening on" "$WORK/tcpdump.log" && break; sleep 0.1; done
    ip netns exec "$NC" "$NFQ" --qnum=301 --debug=1 --lua-init=@"$NFQWS2_DIR/lua/zapret-lib.lua" \
        --in-range=a --out-range=a --lua-desync=posdebug > "$WORK/nfq.log" 2>&1 &
    NPID=$!
    sleep 1.5
    if ! kill -0 $NPID 2>/dev/null; then
        bad "nfqws2 did not start" "$WORK/nfq.log"
    else
        http /secret.html > /dev/null
        http /big.bin > /dev/null
        https lab.example > /dev/null
        ip netns exec "$NC" python3 "$WORK/udp.py" 10.81.2.2 "$DATA/quic_initial_vk_com.bin" 40030 > /dev/null
        sleep 0.5
        kill $NPID 2>/dev/null
        wait $NPID 2>/dev/null
    fi
    kill -INT $TPID 2>/dev/null
    wait $TPID 2>/dev/null
    ip netns exec "$NC" sh -c 'iptables -t mangle -D OUTPUT -j ZT; iptables -t mangle -F ZT; iptables -t mangle -X ZT
        iptables -t mangle -D INPUT -j ZTI; iptables -t mangle -F ZTI; iptables -t mangle -X ZTI'
    "$GENEVA" apply --ext --ext-posdebug -s '\/' -i "$WORK/pd.pcap" -p 80,443 > /dev/null 2> "$WORK/pd.geneva"
    for d in out in; do
        pd_lines "$WORK/nfq.log" $d > "$WORK/pd.z.$d"
        pd_lines "$WORK/pd.geneva" $d > "$WORK/pd.g.$d"
        n=$(wc -l < "$WORK/pd.z.$d")
        sed 's/ reverse.* payload / payload /' "$WORK/pd.z.$d" > "$WORK/pd.zd.$d"
        sed 's/ reverse.* payload / payload /' "$WORK/pd.g.$d" > "$WORK/pd.gd.$d"
        if [ "$n" -lt 10 ]; then
            bad "$d: nfqws2 logged only $n posdebug lines" "$WORK/nfq.log"
        elif diff "$WORK/pd.zd.$d" "$WORK/pd.gd.$d" > "$WORK/pd.diff"; then
            ok "$d: $n packets, the same direct counters as nfqws2"
        else
            { echo "nfqws2 $n lines, geneva $(wc -l < "$WORK/pd.g.$d")"; cat "$WORK/tcpdump.log"
              grep -v '^posdebug' "$WORK/pd.geneva"; head -24 "$WORK/pd.diff"; } > "$WORK/pd.why"
            bad "$d: direct counters differ from nfqws2 (< nfqws2, > geneva)" "$WORK/pd.why"
        fi
        if ! diff "$WORK/pd.z.$d" "$WORK/pd.g.$d" > "$WORK/pd.diff"; then
            echo "  warn $d: reverse counters differ in $(grep -c '^<' "$WORK/pd.diff") line(s) (packets crossed in the queue)"
            head -6 "$WORK/pd.diff" | sed 's/^/       /'
        fi
    done
fi

# --ext-auto observe (stage X9): geneva run in the client namespace watches
# every flow through NFLOG and must give each censor's key its class within
# five flows, while flows that get through give no class at all. AUTO_FW
# picks the firewall (auto: nft, then iptables).
auto_impaired() { # class: the keys that went impaired with it
    grep '"ev":"ext_impaired"' "$WORK/auto.jsonl" | grep '"impaired":true' | grep "\"class\":\"$1\"" |
        sed 's/.*"key":"\([^"]*\)".*/\1/' | sort -u | tr '\n' ' '
}
auto_start() {
    : > "$WORK/auto.jsonl"
    ip netns exec "$NC" "$GENEVA" run --ext --ext-auto observe -s '\/' -p 1 --firewall "${AUTO_FW:-auto}" \
        --events "$WORK/auto.jsonl" --log-file "$WORK/auto.log" --log-level debug --quiet \
        --control "unix:$WORK/auto.sock" &
    APID=$!
    NPID=$APID
    for _ in $(seq 50); do
        grep -q '"ev":"ready"' "$WORK/auto.jsonl" 2>/dev/null && return 0
        sleep 0.1
    done
    bad "geneva run --ext-auto did not start" "$WORK/auto.log"
    return 1
}
auto_stop() {
    kill "$APID" 2>/dev/null
    wait "$APID" 2>/dev/null
    NPID=
    ip netns exec "$NC" sh -c 'iptables-save 2>/dev/null; nft list ruleset 2>/dev/null' | grep -qi geneva &&
        bad "--ext-auto rules left behind" || ok "the rules are gone"
}
# auto_case NAME "censor options" CLASS KEY "request": up to five requests
auto_case() {
    name=$1 copts=$2 cls=$3 key=$4 req=$5
    on auto || on "auto$name" || return
    echo "== --ext-auto observe against censor $name"
    start_censor $name $copts || return
    if auto_start; then
        n=0
        while [ $n -lt 5 ]; do
            n=$((n + 1))
            eval "$req" > /dev/null 2>&1
            sleep 0.3
            echo " $(auto_impaired "$cls")" | grep -q " $key " && break
        done
        if echo " $(auto_impaired "$cls")" | grep -q " $key "; then
            ok "$key impaired: $cls after $n flow(s)"
        else
            bad "no $cls for $key after $n flows" "$WORK/auto.jsonl"
            grep -E "rates of|detect|auto:" "$WORK/auto.log" | tail -20 | sed 's/^/       /'
        fi
        # no key of these flows got another class
        grep '"impaired":true' "$WORK/auto.jsonl" | grep -v "\"class\":\"$cls\"" > "$WORK/other"
        [ -s "$WORK/other" ] && bad "other classes" "$WORK/other" || ok "no other class"
        auto_stop
    fi
    kill "$CPID" 2>/dev/null
    wait "$CPID" 2>/dev/null
    CPID=
}
UDPN=40030
udp4() { # four datagrams on one flow
    UDPN=$((UDPN + 1))
    ip netns exec "$NC" python3 "$WORK/udp.py" 10.81.2.2 "$DATA/quic_initial_www_google_com.bin" $UDPN
    ip netns exec "$NC" python3 "$WORK/udp.py" 10.81.2.2 "$DATA/quic_initial_www_google_com.bin" $UDPN
}
cat > "$WORK/status.py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(b'{"cmd":"ext_status","id":1}\n')
print(s.makefile().readline().strip())
EOF
auto_case 14 "--rst-ttl 50" RST_INJECT ultrasurf.example 'https ultrasurf.example'
auto_case 15 "" RETRANS ultrasurf.example 'https ultrasurf.example'
auto_case 16 "--forbidden google" UDP_NOANSWER udp/443 udp4
auto_case 17 "--block-ip 10.81.2.3 --port 80,443" BLACKHOLE_SYN 10.81.2.3 'https lab.example 10.81.2.3'
auto_case 18 "" REDIRECT ultrasurf.example "http /secret.html -H 'Host: ultrasurf.example'"
# the volume classes (X9b): the conntrack's counters through ctnetlink
freeze() { # a download that stays open after the freeze
    ip netns exec "$NC" curl --noproxy "*" -s -o /dev/null --max-time 7 'http://10.81.2.2/big.bin?ultrasurf'
}
auto_case 12 "--freeze-bytes 20000" FREEZE_N 10.81.2.2 freeze
throttle() { # once a fast download (the capacity), then a policed one
    if [ -z "${THR_FAST:-}" ]; then
        THR_FAST=1
        ip netns exec "$NC" curl --noproxy "*" -s -o /dev/null --max-time 10 --limit-rate 1000k \
            http://10.81.2.2/huge.bin
    fi
    ip netns exec "$NC" curl --noproxy "*" -s -o /dev/null --max-time 9 'http://10.81.2.2/huge.bin?ultrasurf'
}
auto_case 13 "--rate 60000 --burst 20000" THROTTLE 10.81.2.2 throttle
# a query for a name: the forged answer comes first (another IP TTL)
cat > "$WORK/dnsq.py" <<'EOF'
import os, socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
name = b"".join(bytes([len(l)]) + l.encode() for l in sys.argv[2].split(".")) + b"\0"
s.sendto(os.urandom(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x01\x00\x01", (sys.argv[1], 53))
try:
    print(".".join(str(b) for b in s.recv(512)[-4:]))
except socket.timeout:
    print("timeout")
EOF
dnsq() { ip netns exec "$NC" python3 "$WORK/dnsq.py" 10.81.2.2 "$1"; }
auto_case dns "" DNS_POISON udp/53 'dnsq ultrasurf.example'
if on auto || on autonone; then
    echo "== --ext-auto observe without a censor: no class"
    if auto_start; then
        for i in 1 2 3; do
            http /big.bin > /dev/null
            https lab.example > /dev/null
            ip netns exec "$NC" python3 "$WORK/udp.py" 10.81.2.2 "$DATA/quic_initial_vk_com.bin" $((40050 + i)) > /dev/null
            dnsq lab.example > /dev/null
        done
        ip netns exec "$NC" curl --noproxy "*" -s -o /dev/null --max-time 10 --limit-rate 100k http://10.81.2.2/big.bin
        sleep 0.5
        grep -q '"ev":"ext_impaired"' "$WORK/auto.jsonl" && bad "a class without a censor" "$WORK/auto.jsonl" ||
            ok "no class"
        ip netns exec "$NC" python3 "$WORK/status.py" "$WORK/auto.sock" > "$WORK/status" 2>&1
        if grep -q '"flows_ok":[1-9]' "$WORK/status" && grep -q '"flows_failed":0' "$WORK/status"; then
            ok "ext_status: $(sed 's/.*"packets":\([0-9]*\).*"flows_ok":\([0-9]*\).*/\1 packets, \2 flows ok/' "$WORK/status")"
        else
            bad "ext_status" "$WORK/status"
        fi
        auto_stop
    fi
fi

if [ $fails -eq 0 ]; then echo "all passed"; else echo "$fails failure(s)"; fi
exit $fails
