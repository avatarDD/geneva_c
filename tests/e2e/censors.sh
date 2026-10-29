#!/bin/sh
# End-to-end test of "geneva censor": Geneva's lab censors on a router
# namespace between a client and a server (needs root, iproute2, python3,
# curl, and nft or iptables).
#
#   client ns 10.80.1.2 --- 10.80.1.1 censor ns 10.80.2.1 --- 10.80.2.2 server ns
#                           (geneva censor)                    (HTTP and DNS servers)
#
# For every censor: the request with the forbidden word is blocked without a
# strategy, and every strategy of Geneva's library (LAB_STRATEGIES) that is
# listed against this censor gets through. Then "geneva evolve" finds a
# strategy against censor 2 by itself, and the DNS censor is checked with
# Geneva's DNS compression. SIGHUP resets the censor before every run, as
# Geneva starts a fresh censor for every strategy. Usage:
#   tests/e2e/censors.sh [path/to/geneva] [censor ...]
set -u
GENEVA=$(readlink -f "${1:-build/geneva}")
[ $# -gt 0 ] && shift
ONLY="$*"
NC=gnc_c$$ NR=gnc_r$$ NS=gnc_s$$
WORK=$(mktemp -d)
fails=0

cleanup() {
    [ -n "${CPID:-}" ] && kill "$CPID" 2>/dev/null && wait "$CPID" 2>/dev/null
    [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null
    [ -n "${DNS:-}" ] && kill "$DNS" 2>/dev/null
    for n in "$NC" "$NR" "$NS"; do ip netns del "$n" 2>/dev/null; done
    [ -n "${KEEP:-}" ] && cp -r "$WORK" "$KEEP"
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

for n in "$NC" "$NR" "$NS"; do
    ip netns add "$n" || { echo "cannot create namespaces"; exit 1; }
    ip -n "$n" link set lo up
done
ip link add veth_c netns "$NC" type veth peer name veth_rc netns "$NR"
ip link add veth_s netns "$NS" type veth peer name veth_rs netns "$NR"
ip -n "$NC" addr add 10.80.1.2/24 dev veth_c
ip -n "$NR" addr add 10.80.1.1/24 dev veth_rc
ip -n "$NR" addr add 10.80.2.1/24 dev veth_rs
ip -n "$NS" addr add 10.80.2.2/24 dev veth_s
for l in "$NC veth_c" "$NR veth_rc" "$NR veth_rs" "$NS veth_s"; do
    set -- $l
    ip -n "$1" link set "$2" up
    ip netns exec "$1" ethtool -K "$2" tso off gso off gro off >/dev/null 2>&1
done
ip -n "$NC" route add default via 10.80.1.1
ip -n "$NS" route add default via 10.80.2.1
ip netns exec "$NR" sysctl -qw net.ipv4.ip_forward=1

mkdir "$WORK/www"
echo "the page behind the censor" > "$WORK/www/secret.html"
ip netns exec "$NS" python3 -m http.server 80 --bind 10.80.2.2 -d "$WORK/www" >/dev/null 2>&1 &
SRV=$!
# A resolver that answers every A query with 10.80.2.80 and reads compressed
# names, as real resolvers do.
cat > "$WORK/dns.py" <<'EOF'
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.80.2.2", 53))
def name_end(p, off):
    while True:
        l = p[off]
        if l == 0:
            return off + 1
        if l & 0xc0:
            return off + 2
        off += 1 + l
while True:
    q, a = s.recvfrom(4096)
    if len(q) < 12:
        continue
    end = name_end(q, 12) + 4
    r = q[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:end]
    r += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([10, 80, 2, 80])
    s.sendto(r, a)
EOF
ip netns exec "$NS" python3 "$WORK/dns.py" >/dev/null 2>&1 &
DNS=$!
for _ in $(seq 50); do
    ip netns exec "$NS" curl -s -o /dev/null http://10.80.2.2/ && break
    sleep 0.1
done

ok() { echo "  ok   $1"; }
bad() { fails=$((fails + 1)); echo "  FAIL $1"; [ -n "${2:-}" ] && sed 's/^/       /' "$2" | tail -30; }

# start_censor NAME [options]: runs it on the router and waits until it is ready
start_censor() {
    : > "$WORK/cen.jsonl"
    ip netns exec "$NR" "$GENEVA" censor -c "$@" --events "$WORK/cen.jsonl" \
        --log-file "$WORK/cen.log" ${CENSOR_LOG:+--log-level $CENSOR_LOG} --quiet &
    CPID=$!
    for _ in $(seq 50); do
        grep -q '"ev":"ready"' "$WORK/cen.jsonl" 2>/dev/null && return 0
        sleep 0.1
    done
    bad "censor $1 did not start" "$WORK/cen.log"
    return 1
}

stop_censor() {
    kill "$CPID" 2>/dev/null
    wait "$CPID" 2>/dev/null
    CPID=
    ip netns exec "$NR" sh -c 'iptables-save 2>/dev/null; nft list ruleset 2>/dev/null' | grep -qi geneva &&
        bad "censor rules left behind"
}

reset_censor() {
    kill -HUP "$CPID"
    sleep 0.2
}

PROBE="--probe http --host censored.example --ip 10.80.2.2 --path / --valid-contains secret --timeout 2"

# run_eval [strategy]: prints the fitness
run_eval() {
    reset_censor
    if [ $# -gt 0 ]; then
        ip netns exec "$NC" "$GENEVA" eval $PROBE --bad-word ultrasurf --quiet -s "$1" > "$WORK/eval.txt"
    else
        ip netns exec "$NC" "$GENEVA" eval $PROBE --bad-word ultrasurf --quiet > "$WORK/eval.txt"
    fi
    cut -f1 "$WORK/eval.txt" | head -1
}

positive() { awk -v f="$1" 'BEGIN { exit !(f > 0) }'; }

# Geneva's library.py LAB_STRATEGIES: strategy and the censors it beats
cat > "$WORK/lab.txt" <<'EOF'
6 7 8|[TCP:flags:A]-tamper{TCP:flags:replace:F}-| \/
6 7|[TCP:flags:A]-duplicate(tamper{TCP:seq:corrupt}(tamper{TCP:flags:replace:R},),)-| \/
6 7 8 8b|[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \/
2|\/ [TCP:dataofs:5]-drop-|
2|\/ [TCP:flags:R]-drop-|
2|\/ [TCP:window:8192]-drop-|
1 2 3 5 6 7 8 8b 9|[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:14239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:chksum:replace:14239},),))-| \/
1 2 3 5 6 7 8 8b 9|[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:15239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:seq:corrupt}(tamper{TCP:chksum:corrupt},),),))-| \/
1 2 3 5 9 10|[TCP:flags:A]-tamper{TCP:dataofs:replace:0}-| \/
1 2 3 5 9 10|[TCP:flags:A]-duplicate(tamper{TCP:dataofs:replace:0},)-| \/
EOF
# more lines in the same format, for debugging
[ -n "${EXTRA:-}" ] && printf '%s\n' "$EXTRA" >> "$WORK/lab.txt"

echo "== baseline without a censor"
ip netns exec "$NC" "$GENEVA" eval $PROBE --bad-word ultrasurf --quiet > "$WORK/eval.txt" &&
    ok "the page loads through the router" || bad "the page does not load" "$WORK/eval.txt"

for c in 1 2 3 4 5 6 7 8 8b 9 10 11; do
    if [ -n "$ONLY" ] && ! echo " $ONLY " | grep -q " $c "; then continue; fi
    echo "== censor $c"
    start_censor "$c" || continue
    f=$(run_eval)
    positive "${f:-0}" && bad "censor $c: the word gets through without a strategy" "$WORK/cen.log" ||
        ok "blocked without a strategy ($f)"
    grep -q '"ev":"censorship"' "$WORK/cen.jsonl" && ok "censorship event" || bad "no censorship event"
    while IFS='|' read -r list strategy; do
        echo " $list " | grep -q " $c " || continue
        f=$(run_eval "$strategy")
        positive "${f:-0}" && ok "gets through ($f): $strategy" || bad "blocked ($f): $strategy" "$WORK/cen.log"
    done < "$WORK/lab.txt"
    stop_censor
done

if [ -z "$ONLY" ] || echo " $ONLY " | grep -q " evolve "; then
    echo "== geneva evolve against censor 2"
    # Censor 2 keeps no state between connections (it synchronizes on every
    # SYN and blocks no host), so runs need no reset and the http probe can
    # be used directly; its RSTs fail a run quickly. Inbound trees let the
    # search drop the RSTs too.
    start_censor 2 && {
        ip netns exec "$NC" "$GENEVA" evolve $PROBE --bad-word ultrasurf --timeout 1 --in-trees 1 \
            --population 40 --generations 15 --rng-seed ${SEED:-3} --runs 2 --fitness-by min \
            --log-file "$WORK/evolve.log" --quiet > "$WORK/best.txt"
        rc=$?
        head -3 "$WORK/best.txt"
        BEST=$(head -1 "$WORK/best.txt" | cut -f3)
        FIT=$(head -1 "$WORK/best.txt" | cut -f1)
        [ $rc -eq 0 ] && positive "${FIT:-0}" && ok "found: $BEST ($FIT)" || bad "evolve found nothing (exit $rc)" "$WORK/evolve.log"
        if positive "${FIT:-0}"; then
            ip netns exec "$NC" "$GENEVA" eval $PROBE --bad-word ultrasurf --runs 3 --fitness-by min --quiet \
                -s "$BEST" > "$WORK/eval.txt" && ok "it works again (3 of 3)" || bad "the strategy does not hold" "$WORK/eval.txt"
        fi
        stop_censor
    }
fi

if [ -z "$ONLY" ] || echo " $ONLY " | grep -q " dns "; then
    echo "== DNS censor"
    DPROBE="--probe dns --host ultrasurf.example --ip 10.80.2.2 --dns-expect 10.80.2.80 --timeout 2"
    ip netns exec "$NC" "$GENEVA" eval $DPROBE --quiet > "$WORK/eval.txt" &&
        ok "the name resolves without the censor" || bad "no answer without the censor" "$WORK/eval.txt"
    start_censor dns && {
        ip netns exec "$NC" "$GENEVA" eval $DPROBE --quiet --log-level debug --log-file "$WORK/dns.log" > "$WORK/eval.txt" &&
            bad "the forged answer was not first" "$WORK/dns.log" || ok "forged answer first: $(cut -f1 "$WORK/eval.txt")"
        grep -q '"action":"dns"' "$WORK/cen.jsonl" && ok "censorship event" || bad "no censorship event"
        ip netns exec "$NC" "$GENEVA" eval $DPROBE --quiet -s '[UDP:dport:53]-tamper{DNS:qd:compress}-| \/' > "$WORK/eval.txt" &&
            ok "DNS compression gets through: $(cut -f1 "$WORK/eval.txt")" || bad "DNS compression is censored" "$WORK/cen.log"
        stop_censor
    }
fi

if [ $fails -eq 0 ]; then echo "all passed"; else echo "$fails failure(s)"; fi
exit $fails
