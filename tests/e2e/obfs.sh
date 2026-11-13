#!/bin/sh
# The two-sided obfuscation (stage X13a of docs/EXT_ROADMAP.md, zapret2's
# zapret-obfs.lua): geneva run --ext with xwgobfs, xippxor, xudp2icmp and
# xsynhide in the client namespace, and on the server geneva too, or
# nfqws2 with the Lua functions (with NFQWS2_DIR: an unpacked official
# zapret2 release). The application on each end sees its own traffic, the
# wire (counted in the server's raw table, before the queue) only the
# obfuscated one. Needs root, iproute2, python3, iptables.
#
#   client ns 10.89.1.2 --- 10.89.1.1 server ns
#
#   [NFQWS2_DIR=...] tests/e2e/obfs.sh [path/to/geneva] [wgobfs|ippxor|udp2icmp|synhide ...]
set -u
GENEVA=$(readlink -f "${1:-build/geneva}")
[ $# -gt 0 ] && shift
ONLY="$*"
NC=gno_c$$ NS=gno_s$$
WORK=$(mktemp -d)
fails=0
APP= CPID= SPID=

cleanup() {
    for p in $APP $CPID $SPID; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    for n in "$NC" "$NS"; do ip netns del "$n" 2>/dev/null; done
    [ -n "${KEEP:-}" ] && cp -r "$WORK" "$KEEP"
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

ok() { echo "  ok   $1"; }
bad() { fails=$((fails + 1)); echo "  FAIL $1"; [ -n "${2:-}" ] && sed 's/^/       /' "$2" | tail -30; }
on() { [ -z "$ONLY" ] || case " $ONLY " in *" $1 "*) return 0 ;; esac; [ -z "$ONLY" ]; }

for n in "$NC" "$NS"; do
    ip netns add "$n" || { echo "cannot create namespaces"; exit 1; }
    ip -n "$n" link set lo up
done
ip link add vo_c netns "$NC" type veth peer name vo_s netns "$NS"
ip -n "$NC" addr add 10.89.1.2/24 dev vo_c
ip -n "$NS" addr add 10.89.1.1/24 dev vo_s
for l in "$NC vo_c" "$NS vo_s"; do
    set -- $l
    ip -n "$1" link set "$2" up
    ip netns exec "$1" ethtool -K "$2" tso off gso off gro off >/dev/null 2>&1
done

# the server: a UDP echo on 51820 and HTTP on 8080
cat > "$WORK/srv.py" <<'EOF'
import http.server, socket, threading
def echo():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("0.0.0.0", 51820))
    while True:
        d, a = u.recvfrom(65535)
        u.sendto(d, a)
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        b = b"hidden handshake\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
threading.Thread(target=echo, daemon=True).start()
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
EOF
ip netns exec "$NS" python3 "$WORK/srv.py" > "$WORK/srv.log" 2>&1 &
APP=$!

# the client: N WireGuard initiations (148 bytes, type 1) from port 40000,
# each echoed back unchanged; prints how many came back right
cat > "$WORK/cli.py" <<'EOF'
import os, socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 40000))
s.settimeout(1)
good = 0
for i in range(int(sys.argv[1])):
    m = b"\x01\x00\x00\x00" + os.urandom(144)
    s.sendto(m, ("10.89.1.1", 51820))
    try:
        d, _ = s.recvfrom(65535)
        good += d == m
    except socket.timeout:
        pass
print(good)
EOF
for _ in $(seq 50); do
    ip netns exec "$NC" python3 -c 'import socket; socket.create_connection(("10.89.1.1", 8080), 1)' 2>/dev/null && break
    sleep 0.1
done

# the wire as the server gets it: counters in its raw table
wire_on() { # iptables match ...
    ip netns exec "$NS" iptables -t raw -F PREROUTING
    for m in "$@"; do
        # shellcheck disable=SC2086
        ip netns exec "$NS" iptables -t raw -A PREROUTING $m
    done
}
wire_count() { # rule number: its packets
    ip netns exec "$NS" iptables -t raw -nvxL PREROUTING | awk -v n="$1" 'NR == n + 2 { print $1 }'
}

# geneva run --ext in namespace NS-or-NC; the rest are its options
gstart() { # var ns log options...
    var=$1 ns=$2 log=$3
    shift 3
    ip netns exec "$ns" "$GENEVA" run --ext --log-level info "$@" > "$log" 2>&1 &
    eval "$var=$!"
    for _ in $(seq 50); do
        grep -q '"event":"ready"\|ready' "$log" 2>/dev/null && break
        sleep 0.1
    done
    sleep 0.3
}

# nfqws2 on the server with the Lua functions; rules for its queue 200
NFQ=
[ -n "${NFQWS2_DIR:-}" ] && NFQ=$NFQWS2_DIR/binaries/linux-x86_64/nfqws2
nstart() { # "iptables rules" nfqws2-options...
    rules=$1
    shift
    ip netns exec "$NS" sh -c "$rules"
    ip netns exec "$NS" "$NFQ" --qnum=200 --lua-init=@"$NFQWS2_DIR/lua/zapret-lib.lua" \
        --lua-init=@"$NFQWS2_DIR/lua/zapret-obfs.lua" ${NFQ_DEBUG:+--debug} "$@" > "$WORK/nfq.log" 2>&1 &
    SPID=$!
    sleep 1.5
}
nstop() {
    kill "$SPID" 2>/dev/null
    wait "$SPID" 2>/dev/null
    SPID=
    ip netns exec "$NS" iptables -t mangle -F
}
gstop() { # var
    eval "p=\$$1"
    [ -n "$p" ] && kill "$p" 2>/dev/null && wait "$p" 2>/dev/null
    eval "$1="
}
Q='-m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass'

# udp_case NAME "wire rules" "rule: obfuscated" "rule: plain" client-options -- server(geneva)-options -- nfqws2 "rules" options
udp_check() { # name what
    r=$(ip netns exec "$NC" python3 "$WORK/cli.py" 5)
    [ "$r" = 5 ] && ok "$1: 5 of 5 echoed back as sent" || bad "$1: $r of 5 echoed back" "$WORK/c.log"
    o=$(wire_count 1)
    p=$(wire_count 2)
    [ "${o:-0}" -ge 5 ] && [ "${p:-1}" = 0 ] && ok "$1: the wire has $2 only ($o packets)" ||
        bad "$1: the wire: $o obfuscated, $p plain" "$WORK/s.log"
}

if on wgobfs; then
    echo "== xwgobfs"
    W='xwgobfs{secret=mycoolpassword}'
    # the plain initiation is IP length 176; the obfuscated one 206-222
    wire_on "-p udp --dport 51820 -m length --length 206:222" "-p udp --dport 51820 -m length --length 176"
    gstart CPID "$NC" "$WORK/c.log" -p 51820 --proto udp -s "[UDP:dport:51820]-$W-| \\/ [UDP:sport:51820]-$W-|"
    gstart SPID "$NS" "$WORK/s.log" --server-side -p 51820 --proto udp -s "[UDP:sport:51820]-$W-| \\/ [UDP:dport:51820]-$W-|"
    udp_check "geneva <-> geneva" "encrypted messages"
    gstop SPID
    if [ -n "$NFQ" ]; then
        wire_on "-p udp --dport 51820 -m length --length 206:222" "-p udp --dport 51820 -m length --length 176"
        nstart "iptables -t mangle -A OUTPUT -p udp --sport 51820 $Q; iptables -t mangle -A PREROUTING -p udp --dport 51820 $Q" \
            --in-range=a --out-range=a --lua-desync=wgobfs:secret=mycoolpassword
        udp_check "geneva <-> nfqws2 wgobfs" "encrypted messages"
        nstop
    fi
    gstop CPID
fi

if on ippxor; then
    echo "== xippxor"
    X='xippxor{ippxor=192;dataxor=0xABCD}'
    # UDP (17) goes as 17^192 = 209
    wire_on "-p 209" "-p udp --dport 51820"
    gstart CPID "$NC" "$WORK/c.log" -p 51820 --proto udp --filter-udp 51820 --filter-ipp 209 \
        -s "[UDP:dport:51820]-$X-| \\/ [IP:proto:209]-$X-|"
    gstart SPID "$NS" "$WORK/s.log" --server-side -p 51820 --proto udp --filter-udp 51820 --filter-ipp 209 \
        -s "[UDP:sport:51820]-$X-| \\/ [IP:proto:209]-$X-|"
    udp_check "geneva <-> geneva" "protocol 209"
    gstop SPID
    if [ -n "$NFQ" ]; then
        wire_on "-p 209" "-p udp --dport 51820"
        nstart "iptables -t mangle -A OUTPUT -p udp --sport 51820 $Q; iptables -t mangle -A PREROUTING -p 209 $Q" \
            --filter-ipp=209 --filter-udp=51820 --in-range=a --out-range=a --lua-desync=ippxor:ippxor=192:dataxor=0xABCD
        udp_check "geneva <-> nfqws2 ippxor" "protocol 209"
        nstop
    fi
    gstop CPID
fi

if on udp2icmp; then
    echo "== xudp2icmp"
    wire_on "-p icmp --icmp-type 8" "-p udp --dport 51820"
    gstart CPID "$NC" "$WORK/c.log" -p 51820 --proto udp --filter-udp 51820 --filter-icmp 0 \
        -s "[UDP:dport:51820]-xudp2icmp-| \\/ [IP:proto:1]-xudp2icmp-|"
    gstart SPID "$NS" "$WORK/s.log" --server-side -p 51820 --proto udp --filter-udp 51820 --filter-icmp 8 \
        -s "[UDP:sport:51820]-xudp2icmp{server=1}-| \\/ [IP:proto:1]-xudp2icmp{server=1}-|"
    udp_check "geneva <-> geneva" "ICMP echo requests"
    gstop SPID
    if [ -n "$NFQ" ]; then
        wire_on "-p icmp --icmp-type 8" "-p udp --dport 51820"
        nstart "iptables -t mangle -A OUTPUT -p udp --sport 51820 $Q; iptables -t mangle -A PREROUTING -p icmp --icmp-type 8 $Q" \
            --server --in-range=a --out-range=a --lua-desync=udp2icmp
        udp_check "geneva <-> nfqws2 udp2icmp --server" "ICMP echo requests"
        nstop
    fi
    gstop CPID
fi

if on synhide; then
    echo "== xsynhide"
    # no SYN without ACK on the wire, the page loads
    # the mark x2=1 is the bit before CWR (NS, the AccECN bit)
    M="-p tcp --dport 8080 --tcp-flags SYN,ACK,FIN,RST ACK -m u32 --u32 0>>22&0x3C@12>>16&0x100=0x100"
    wire_on "$M" "-p tcp --dport 8080 --tcp-flags SYN,ACK SYN"
    gstart CPID "$NC" "$WORK/c.log" -p 8080 -s "[TCP:flags:S]-xsynhide-| \\/"
    gstart SPID "$NS" "$WORK/s.log" --server-side -p 8080 -s "\\/ [TCP:dport:8080]-xsynhide-|"
    r=$(ip netns exec "$NC" curl --noproxy "*" -s --max-time 4 http://10.89.1.1:8080/)
    [ "$r" = "hidden handshake" ] && ok "geneva <-> geneva: the page loads" || bad "geneva <-> geneva: got '$r'" "$WORK/s.log"
    o=$(wire_count 1)
    p=$(wire_count 2)
    [ "${o:-0}" = 1 ] && [ "${p:-1}" = 0 ] && ok "the wire has no SYN, 1 marked ACK" ||
        bad "the wire: $o marked ACKs, $p SYNs" "$WORK/c.log"
    gstop SPID
    if [ -n "$NFQ" ]; then
        wire_on "$M" "-p tcp --dport 8080 --tcp-flags SYN,ACK SYN"
        # (the u32 expression quoted for the shell of nstart)
        nstart "iptables -t mangle -A PREROUTING ${M%%--u32*}--u32 '${M#*--u32 }' $Q" --in-range=a --lua-desync=synhide
        r=$(ip netns exec "$NC" curl --noproxy "*" -s --max-time 4 http://10.89.1.1:8080/)
        [ "$r" = "hidden handshake" ] && ok "geneva <-> nfqws2 synhide: the page loads" ||
            bad "geneva <-> nfqws2 synhide: got '$r'" "$WORK/nfq.log"
        o=$(wire_count 1)
        p=$(wire_count 2)
        [ "${o:-0}" = 1 ] && [ "${p:-1}" = 0 ] && ok "the wire has no SYN, 1 marked ACK" ||
            bad "the wire: $o marked ACKs, $p SYNs" "$WORK/c.log"
        nstop
    fi
    gstop CPID
fi

for n in "$NC" "$NS"; do
    ip netns exec "$n" sh -c 'iptables-save -t mangle 2>/dev/null; nft list ruleset 2>/dev/null' | grep -qi "NFQUEUE\|queue" &&
        { [ "$n" = "$NC" ] || [ -z "$NFQ" ]; } && bad "rules left in $n"
done
if [ $fails -eq 0 ]; then echo "all passed"; else echo "$fails failure(s)"; fi
exit $fails
