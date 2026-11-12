#!/bin/sh
# --ext-workers (stage X10a of docs/EXT_ROADMAP.md): geneva run with four
# workers in two namespaces. The rules spread the flows over the queues
# (iptables --queue-balance, nft "queue num A-B"), every worker gets
# packets, every download arrives whole and the rules are gone afterwards.
# BENCH=1 also measures the throughput of 1 and of 4 workers (the
# criterion: at least 3 times). Needs root, iproute2, python3, curl, and
# nft or iptables.
#
#   client ns 10.86.1.2 --- 10.86.1.1 server ns (10.86.2.1-32 on lo)
#
#   [FIREWALLS="iptables nft"] [BENCH=1] tests/e2e/workers.sh [path/to/geneva]
set -u
GENEVA=$(readlink -f "${1:-build/geneva}")
FIREWALLS=${FIREWALLS:-"iptables nft"}
NADDR=32
NC=gnw_c$$ NS=gnw_s$$
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
ip link add vw_c netns "$NC" type veth peer name vw_s netns "$NS"
ip -n "$NC" addr add 10.86.1.2/24 dev vw_c
ip -n "$NS" addr add 10.86.1.1/24 dev vw_s
for i in $(seq $NADDR); do ip -n "$NS" addr add "10.86.2.$i/32" dev lo; done
for l in "$NC vw_c" "$NS vw_s"; do
    set -- $l
    ip -n "$1" link set "$2" up
    # every segment through the queue as it is, not merged
    ip netns exec "$1" ethtool -K "$2" tso off gso off gro off >/dev/null 2>&1
done
ip -n "$NC" route add default via 10.86.1.1

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
    ip netns exec "$NC" curl -s -o /dev/null http://10.86.1.1/1 && break
    sleep 0.1
done

# start N: geneva run with N workers and firewall $FW
start() {
    : > "$WORK/ev.jsonl"
    rm -f "$WORK/g.sock"
    ip netns exec "$NC" "$GENEVA" run --ext --ext-workers "$1" -p 80 --firewall "$FW" \
        -s '[TCP:flags:PA]-duplicate-| \/' --events "$WORK/ev.jsonl" --log-file "$WORK/g.log" \
        --log-level info --quiet --control "unix:$WORK/g.sock" &
    GPID=$!
    for _ in $(seq 50); do
        grep -q '"ev":"ready"' "$WORK/ev.jsonl" 2>/dev/null && return 0
        sleep 0.1
    done
    bad "geneva run --ext-workers $1 did not start" "$WORK/g.log"
    return 1
}

stop() {
    kill "$GPID" 2>/dev/null
    wait "$GPID" 2>/dev/null
    GPID=
}

# fetch MB: one download of MB from each address at once; prints the
# seconds and counts the short ones in $WORK/short
fetch() {
    : > "$WORK/short"
    t0=$(date +%s.%N)
    pids=
    for i in $(seq $NADDR); do
        ( n=$(ip netns exec "$NC" curl -s -o /dev/null -w '%{size_download}' --max-time 120 "http://10.86.2.$i/$1")
          [ "$n" = "$(($1 * 1000000))" ] || echo "10.86.2.$i: $n" >> "$WORK/short" ) &
        pids="$pids $!"
    done
    wait $pids # not the server's or the engine's
    python3 -c "print($(date +%s.%N) - $t0)"
}

# the engine's CPU seconds (user and system)
cpu() {
    awk -v hz="$(getconf CLK_TCK)" '{ print ($14 + $15) / hz }' "/proc/$GPID/stat"
}

for FW in $FIREWALLS; do
    echo "== --ext-workers 4, $FW"
    start 4 || continue
    rules=$(ip netns exec "$NC" sh -c 'iptables-save 2>/dev/null; nft list ruleset 2>/dev/null')
    echo "$rules" | grep -Eq -- '--queue-balance 310:313|queue (flags bypass )?(num|to) 310-313' &&
        ok "the rules balance over the queues 310-313" || { echo "$rules" > "$WORK/rules"; bad "no balanced queue rule" "$WORK/rules"; }
    grep -q "4 workers on queues 310-313" "$WORK/g.log" && ok "4 workers started" || bad "no workers" "$WORK/g.log"
    fetch 5 > /dev/null
    [ -s "$WORK/short" ] && bad "downloads cut short" "$WORK/short" || ok "$NADDR downloads of 5 MB at once"
    st=$(python3 "$WORK/ctl.py" "$WORK/g.sock" stats)
    echo "$st" | grep -q '"workers":4' && ok "stats: 4 workers" || bad "stats without workers: $st"
    wp=$(echo "$st" | sed -n 's/.*"worker_pkts":\[\([0-9,]*\)\].*/\1/p')
    echo "  worker packets: $wp"
    echo "$wp" | awk -F, 'NF == 4 { for (i = 1; i <= 4; i++) if ($i < 100) exit 1; exit 0 } { exit 1 }' &&
        ok "every worker had packets" || bad "the flows did not spread: $wp"
    echo "$st" | grep -Eq '"verdict_errors":0,' && ok "no verdict errors" || bad "verdict errors: $st"
    stop
    ip netns exec "$NC" sh -c 'iptables-save 2>/dev/null; nft list ruleset 2>/dev/null' | grep -qi geneva &&
        bad "rules left behind" || ok "the rules are gone"
done

if [ -n "${BENCH:-}" ]; then
    FW=${FIREWALLS%% *}
    echo "== throughput, 1 and 4 workers ($FW, $NADDR flows of 20 MB)"
    for n in 1 4; do
        start "$n" || continue
        fetch 20 > /dev/null # warm up
        c0=$(cpu)
        t=$(fetch 20)
        c1=$(cpu)
        [ -s "$WORK/short" ] && bad "$n workers: downloads cut short" "$WORK/short"
        mbit=$(python3 -c "print(round($NADDR * 20 * 8 / $t))")
        echo "  $n worker(s): $mbit Mbit/s ($t s), the engine used $(python3 -c "print(round(($c1 - $c0) / $t, 2))") CPUs"
        eval "rate_$n=$mbit cpu_$n=$(python3 -c "print(($c1 - $c0) / $t)")"
        stop
    done
    # 3 times needs CPUs for the 4 workers besides the downloads, the
    # server and the kernel's part (which the engine's CPU time partly
    # includes: a verdict sends the packet on in its system call). With
    # fewer than 8 the CPUs run out before the engine does: the numbers
    # are only shown.
    if [ "$(nproc)" -ge 8 ]; then
        python3 -c "import sys; sys.exit(0 if ${rate_4:-0} >= 3 * ${rate_1:-1} else 1)" &&
            ok "4 workers: at least 3 times 1 worker" ||
            bad "4 workers: ${rate_4:-0} Mbit/s, 1 worker: ${rate_1:-0} Mbit/s"
    else
        echo "  $(nproc) CPUs: too few to measure (8 or more needed), not checked"
    fi
fi

[ $fails -eq 0 ] && echo "workers: all passed" || echo "workers: $fails failed"
[ $fails -eq 0 ]
