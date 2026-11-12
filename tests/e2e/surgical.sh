#!/bin/sh
# The surgical path (stage X10b of docs/EXT_ROADMAP.md): a connection the
# engine is done with gets the healthy mark in its conntrack entry and its
# later packets skip the queue. Checked with iptables and nft, one and four
# workers: the download arrives whole, the conntrack entry carries the
# mark, the engine saw only the first packets; a strategy that never lets
# go and a run without --ext-healthy-mark (off by default) keep every
# packet in the queue; the rules are gone afterwards. Needs root,
# iproute2, python3, curl, and nft or iptables.
#
#   client ns 10.88.1.2 --- 10.88.1.1 server ns
#
#   [FIREWALLS="iptables nft"] tests/e2e/surgical.sh [path/to/geneva]
set -u
GENEVA=$(readlink -f "${1:-build/geneva}")
FIREWALLS=${FIREWALLS:-"iptables nft"}
MB=20
NC=gns_c$$ NS=gns_s$$
WORK=$(mktemp -d)
fails=0
SRV=

cleanup() {
    [ -n "$SRV" ] && kill "$SRV" 2>/dev/null
    [ -n "${GPID:-}" ] && kill "$GPID" 2>/dev/null && wait "$GPID" 2>/dev/null
    for n in "$NC" "$NS"; do ip netns del "$n" 2>/dev/null; done
    [ -n "${KEEP:-}" ] && cp -r "$WORK" "$KEEP"
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

ok() { echo "  ok   $1"; }
bad() { fails=$((fails + 1)); echo "  FAIL $1"; [ -n "${2:-}" ] && sed 's/^/       /' "$2" | tail -30; }

for n in "$NC" "$NS"; do
    ip netns add "$n" || { echo "cannot create namespaces"; exit 1; }
    ip -n "$n" link set lo up
done
ip link add vs_c netns "$NC" type veth peer name vs_s netns "$NS"
ip -n "$NC" addr add 10.88.1.2/24 dev vs_c
ip -n "$NS" addr add 10.88.1.1/24 dev vs_s
for l in "$NC vs_c" "$NS vs_s"; do
    set -- $l
    ip -n "$1" link set "$2" up
    ip netns exec "$1" ethtool -K "$2" tso off gso off gro off >/dev/null 2>&1
done

# /N: N MB of zeros
cat > "$WORK/srv.py" <<'EOF'
import http.server
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a):
        pass
    def do_GET(self):
        n = int(self.path.strip("/") or "1") * 1000 * 1000
        self.send_response(200)
        self.send_header("Content-Length", str(n))
        self.end_headers()
        chunk = b"\0" * 65536
        while n > 0:
            self.wfile.write(chunk[:min(n, len(chunk))])
            n -= len(chunk)
http.server.ThreadingHTTPServer(("0.0.0.0", 80), H).serve_forever()
EOF
cat > "$WORK/ctl.py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(('{"cmd":"%s","id":1}\n' % sys.argv[2]).encode())
print(s.makefile().readline().strip())
EOF
ip netns exec "$NS" python3 "$WORK/srv.py" > "$WORK/srv.log" 2>&1 &
SRV=$!
for _ in $(seq 50); do
    ip netns exec "$NC" curl -s -o /dev/null http://10.88.1.1/1 && break
    sleep 0.1
done

# start STRATEGY [options]: geneva run with firewall $FW
start() {
    s=$1
    shift
    : > "$WORK/ev.jsonl"
    rm -f "$WORK/g.sock"
    ip netns exec "$NC" "$GENEVA" run --ext -p 80 --firewall "$FW" -s "$s" "$@" --events "$WORK/ev.jsonl" \
        --log-file "$WORK/g.log" --log-level info --quiet --control "unix:$WORK/g.sock" &
    GPID=$!
    for _ in $(seq 50); do
        grep -q '"ev":"ready"' "$WORK/ev.jsonl" 2>/dev/null && return 0
        sleep 0.1
    done
    bad "geneva run did not start" "$WORK/g.log"
    return 1
}

stop() {
    kill "$GPID" 2>/dev/null
    wait "$GPID" 2>/dev/null
    GPID=
}

# fetch: one download of $MB MB; 0 when it arrived whole
fetch() {
    n=$(ip netns exec "$NC" curl -s -o /dev/null -w '%{size_download}' --max-time 60 "http://10.88.1.1/$MB")
    [ "$n" = "$((MB * 1000000))" ]
}

# field NAME: the number NAME of the stats reply
field() {
    python3 "$WORK/ctl.py" "$WORK/g.sock" stats > "$WORK/stats"
    sed -n "s/.*\"$1\":\([0-9]*\).*/\1/p" "$WORK/stats" | head -1
}

# the conntrack mark of the connection to the server's port 80
ctmark() {
    ip netns exec "$NC" sh -c 'cat /proc/net/nf_conntrack 2>/dev/null; conntrack -L 2>/dev/null' |
        grep 'dport=80 ' | grep -o 'mark=[0-9]*' | head -1 | cut -d= -f2
}

# one 20 MB download is some 14000 packets each way; the engine of a cut
# strategy sees the first few dozen
FEW=500
CUT='[FLOW:n:1-3]-duplicate-| \/'

for FW in $FIREWALLS; do
    for W in 1 4; do
        echo "== $FW, $W worker(s), a strategy cut off after 3 packets"
        start "$CUT" --ext-healthy-mark on --ext-workers "$W" || continue
        ip netns exec "$NC" conntrack -F >/dev/null 2>&1
        fetch && ok "$MB MB arrived whole" || bad "the download was cut short" "$WORK/g.log"
        m=$(ctmark)
        [ -n "$m" ] && [ $((m & 0x10000000)) -ne 0 ] && ok "the connection has the healthy mark ($m)" ||
            bad "no healthy mark in conntrack: '${m:-none}'"
        pk=$(($(field pkts_out) + $(field pkts_in)))
        h=$(field healthy)
        [ "$pk" -lt $FEW ] && ok "the engine saw $pk packets" || bad "the engine saw $pk packets (less than $FEW expected)"
        [ "${h:-0}" -ge 1 ] && ok "stats: healthy $h" || bad "stats: healthy ${h:-none}" "$WORK/stats"
        grep -q '"verdict_errors":0,' "$WORK/stats" && ok "no verdict errors" || bad "verdict errors" "$WORK/stats"
        python3 "$WORK/ctl.py" "$WORK/g.sock" ext_status | grep -q '"surgical":true' &&
            ok "ext_status: surgical" || bad "ext_status without surgical"
        stop
    done

    echo "== $FW, a strategy that never lets go"
    if start '[TCP:flags:PA]-duplicate-| \/' --ext-healthy-mark on; then
        fetch && ok "$MB MB arrived whole" || bad "the download was cut short" "$WORK/g.log"
        pk=$(($(field pkts_out) + $(field pkts_in)))
        [ "$pk" -ge $FEW ] && ok "every packet in the queue ($pk)" || bad "only $pk packets in the queue"
        [ "$(field healthy)" = 0 ] && ok "stats: healthy 0" || bad "healthy connections" "$WORK/stats"
        stop
    fi

    echo "== $FW, without --ext-healthy-mark (off)"
    if start "$CUT"; then
        rules=$(ip netns exec "$NC" sh -c 'iptables-save 2>/dev/null; nft list ruleset 2>/dev/null')
        echo "$rules" | grep -qi '0x10000000' && bad "a healthy-mark rule without the mark" || ok "no healthy-mark rules"
        python3 "$WORK/ctl.py" "$WORK/g.sock" ext_status | grep -q '"surgical":false' &&
            ok "ext_status: surgical off" || bad "surgical without --ext-healthy-mark"
        fetch && ok "$MB MB arrived whole" || bad "the download was cut short" "$WORK/g.log"
        pk=$(($(field pkts_out) + $(field pkts_in)))
        [ "$pk" -ge $FEW ] && ok "every packet in the queue ($pk)" || bad "only $pk packets in the queue"
        stop
    fi
    ip netns exec "$NC" sh -c 'iptables-save 2>/dev/null; nft list ruleset 2>/dev/null' | grep -qi geneva &&
        bad "rules left behind" || ok "the rules are gone"
done

[ $fails -eq 0 ] && echo "surgical: all passed" || echo "surgical: $fails failed"
[ $fails -eq 0 ]
