#!/bin/sh
# End-to-end test of "geneva run" in two network namespaces (needs root,
# iproute2, iptables and/or nft, tcpdump, python3).
#
#   client ns (geneva run) 10.77.0.1 ---veth--- 10.77.0.2 server ns (echo server)
#
# Every case starts the engine with a strategy, makes one TCP exchange and
# checks the server-side capture for the packets the strategy should make.
# Usage: tests/e2e/run.sh [path/to/geneva]   FIREWALLS="auto iptables nft"
set -u
GENEVA=$(readlink -f "${1:-build/geneva}")
FIREWALLS=${FIREWALLS:-"auto iptables"}
NC=gnv_c$$ NS=gnv_s$$
WORK=$(mktemp -d)
PORT=8080
fails=0 passes=0

cleanup() {
    [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null
    ip netns del "$NC" 2>/dev/null
    ip netns del "$NS" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

ip netns add "$NC" && ip netns add "$NS" || { echo "cannot create namespaces"; exit 1; }
ip link add veth_c netns "$NC" type veth peer name veth_s netns "$NS"
ip -n "$NC" addr add 10.77.0.1/24 dev veth_c
ip -n "$NS" addr add 10.77.0.2/24 dev veth_s
ip -n "$NC" addr add fd77::1/64 dev veth_c nodad
ip -n "$NS" addr add fd77::2/64 dev veth_s nodad
for n in "$NC" "$NS"; do ip -n "$n" link set lo up; done
ip -n "$NC" link set veth_c up
ip -n "$NS" link set veth_s up
# no offloads: the capture must show packets as sent, not merged
ip netns exec "$NC" ethtool -K veth_c tso off gso off gro off >/dev/null 2>&1
ip netns exec "$NS" ethtool -K veth_s tso off gso off gro off >/dev/null 2>&1

cat > "$WORK/srv.py" <<'PY'
import socket, sys, threading
def serve(fam, addr):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if fam == socket.AF_INET6:  # "::" would take the IPv4 port as well
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, int(sys.argv[1]))); s.listen(16)
    while True:
        c, _ = s.accept()
        c.settimeout(5)
        data = b""
        try:
            while not data.endswith(b"\n"):
                d = c.recv(4096)
                if not d: break
                data += d
            c.sendall(b"echo:" + data)
        except Exception:
            pass
        c.close()
if socket.has_ipv6:
    try: socket.socket(socket.AF_INET6).close(); threading.Thread(target=serve, args=(socket.AF_INET6, "::"), daemon=True).start()
    except OSError: pass
serve(socket.AF_INET, "0.0.0.0")
PY
cat > "$WORK/cli.py" <<'PY'
import socket, sys
fam = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
s = socket.socket(fam, socket.SOCK_STREAM); s.settimeout(8)
s.connect((sys.argv[1], int(sys.argv[2])))
msg = b"hello geneva 0123456789 abcdefghijklmnopqrstuvwxyz\n"
s.sendall(msg)
got = b""
while True:
    d = s.recv(4096)
    if not d: break
    got += d
sys.exit(0 if got == b"echo:" + msg else 1)
PY
HAVE6=0
ip netns exec "$NC" python3 -c 'import socket; socket.socket(socket.AF_INET6)' 2>/dev/null && HAVE6=1
ip netns exec "$NS" python3 "$WORK/srv.py" $PORT &
SRV=$!
sleep 0.5
kill -0 $SRV 2>/dev/null || { echo "echo server failed to start"; exit 1; }

# run_case NAME FIREWALL STRATEGY [DST] -- then checks via helpers below
start_case() {
    CASE=$1 FW=$2 STRAT=$3 DST=${4:-10.77.0.2}
    rm -f "$WORK/cap.pcap" "$WORK/ev.jsonl"
    ip netns exec "$NS" tcpdump -i veth_s -U -s 0 -w "$WORK/cap.pcap" "tcp port $PORT or ip[6:2] & 0x1fff != 0 or ip6[6] = 44" >/dev/null 2>&1 &
    TCPD=$!
    printf '%s\n' "$STRAT" > "$WORK/strategy"
    ip netns exec "$NC" "$GENEVA" run -f "$WORK/strategy" -p $PORT --firewall "$FW" \
        --events "$WORK/ev.jsonl" --stats-interval 0.2 --quiet &
    ENG=$!
    i=0
    while ! grep -q '"ev":"ready"' "$WORK/ev.jsonl" 2>/dev/null; do
        i=$((i + 1)); sleep 0.1
        if [ $i -gt 50 ] || ! kill -0 $ENG 2>/dev/null; then
            echo "  engine did not start"; cat "$WORK/ev.jsonl" 2>/dev/null; break
        fi
    done
    sleep 0.3
}

stop_case() {
    kill -TERM $ENG 2>/dev/null
    wait $ENG; ENG_RC=$?
    sleep 0.3
    kill $TCPD 2>/dev/null; wait $TCPD 2>/dev/null
    tcpdump -nn -v -r "$WORK/cap.pcap" 2>/dev/null > "$WORK/cap.txt"
}

ok() { passes=$((passes + 1)); echo "  ok   $CASE [$FW]: $1"; }
bad() { fails=$((fails + 1)); echo "  FAIL $CASE [$FW]: $1"; [ -n "${2:-}" ] && sed 's/^/       /' "$2" | head -40; }
check() { if eval "$2"; then ok "$1"; else bad "$1" "$WORK/cap.txt"; fi; }

exchange() { ip netns exec "$NC" timeout 15 python3 "$WORK/cli.py" "${DST}" $PORT; }

rules_gone() {
    ! ip netns exec "$NC" iptables-save 2>/dev/null | grep -q GENEVA &&
    ! ip netns exec "$NC" ip6tables-save 2>/dev/null | grep -q GENEVA &&
    ! ip netns exec "$NC" nft list tables 2>/dev/null | grep -q geneva
}

cnt() { grep -c -- "$1" "$WORK/cap.txt"; }

for FW in $FIREWALLS; do
    echo "== firewall: $FW"

    start_case "no-op" "$FW" '\/'
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case
    check "engine exit code 0" '[ $ENG_RC -eq 0 ]'
    check "exit event" 'grep -q "\"ev\":\"exit\"" "$WORK/ev.jsonl"'
    check "rules removed" rules_gone

    start_case "duplicate+tamper SYN" "$FW" '[TCP:flags:S]-duplicate(tamper{TCP:window:replace:7},)-| \/'
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case
    check "SYN with win 7 (verdict path)" '[ $(grep "Flags \[S\]" "$WORK/cap.txt" | grep -c "win 7,") -ge 1 ]'
    check "plain SYN too (raw path)" '[ $(grep "Flags \[S\]" "$WORK/cap.txt" | grep -vc "win 7,") -ge 1 ]'

    start_case "tcp segmentation" "$FW" '[TCP:flags:PA]-fragment{tcp:8:True}-| \/'
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case
    check "first segment has 8 bytes" '[ $(grep "10.77.0.1.*> 10.77.0.2.$PORT: Flags \[P.\]" "$WORK/cap.txt" | grep -Ec "length 8(:|$)") -ge 1 ]'

    start_case "tcp segments out of order" "$FW" '[TCP:flags:PA]-fragment{tcp:8:False}-| \/'
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case

    start_case "ip fragmentation" "$FW" '[TCP:flags:PA]-fragment{ip:16:True}-| \/'
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case
    check "IP fragments on the wire" '[ $(cnt "flags \[+") -ge 1 ]'

    start_case "corrupt IP checksum (exact bytes)" "$FW" '[TCP:flags:S]-tamper{IP:chksum:corrupt}-| \/'
    exchange && bad "exchange worked although every SYN is broken" || ok "exchange fails (bad SYNs are ignored)"
    stop_case
    check "bad IP checksum on the wire" '[ $(cnt "bad cksum") -ge 1 ]'

    start_case "sleep" "$FW" '[TCP:flags:PA]-duplicate(,sleep{0.6})-| \/'
    exchange && ok "exchange works" || bad "exchange failed"
    sleep 1
    stop_case
    check "payload sent twice" '[ $(grep "10.77.0.1.*> 10.77.0.2.$PORT: Flags \[P.\]" "$WORK/cap.txt" | wc -l) -ge 2 ]'
    check "delay counted" 'grep "\"ev\":\"stats\"" "$WORK/ev.jsonl" | tail -1 | grep -q "\"delayed\":1"'

    start_case "drop" "$FW" '[TCP:flags:S]-drop-| \/'
    exchange && bad "exchange worked although SYNs are dropped" || ok "exchange fails"
    stop_case
    check "no SYN reached the server" '[ $(cnt "Flags \[S\]") -eq 0 ]'

    start_case "inbound tamper" "$FW" '\/ [TCP:flags:SA]-tamper{TCP:window:replace:9}-|'
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case
    check "in-tree fired" 'grep "\"ev\":\"stats\"" "$WORK/ev.jsonl" | tail -1 | grep -q "\"in_trees\":\[{\"tree\":\"\[TCP:flags:SA\]-tamper{TCP:window:replace:9}-|\",\"fired\":[1-9]"'

    if [ $HAVE6 -eq 0 ]; then echo "  skip IPv6 cases: no IPv6 in this kernel"; else
    start_case "IPv6 duplicate" "$FW" '[TCP:flags:S]-duplicate(tamper{TCP:window:replace:7},)-| \/' fd77::2
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case
    check "IPv6 SYN with win 7" '[ $(grep "fd77::1" "$WORK/cap.txt" | grep "Flags \[S\]" | grep -c "win 7,") -ge 1 ]'

    start_case "IPv6 fragmentation" "$FW" '[TCP:flags:PA]-fragment{ip:16:True}-| \/' fd77::2
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case
    check "IPv6 fragments on the wire" '[ $(cnt "frag (") -ge 1 ]'
    fi

    start_case "SIGHUP reload" "$FW" '\/'
    printf '%s\n' '[TCP:flags:S]-tamper{TCP:window:replace:7}-| \/' > "$WORK/strategy"
    kill -HUP $ENG; sleep 0.3
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case
    check "new strategy announced" '[ $(grep -c "\"ev\":\"strategy\"" "$WORK/ev.jsonl") -eq 2 ]'
    check "new strategy applied" '[ $(grep "Flags \[S\]" "$WORK/cap.txt" | grep -c "win 7,") -ge 1 ]'
    check "rules removed" rules_gone
done

echo "e2e: $passes passed, $fails failed"
[ $fails -eq 0 ]
