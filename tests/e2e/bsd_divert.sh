#!/bin/sh
# End-to-end test of "geneva run" on FreeBSD with ipfw and divert sockets
# (docs/EXT.md, X13b). Needs root, a kernel with VIMAGE (GENERIC) and the
# base system only (ipfw, jail, epair, inetd, nc, tcpdump):
#
#   host (geneva run) 10.77.0.1 ---epair--- 10.77.0.2 vnet jail (inetd echo)
#
# Every case starts the engine with a strategy, makes one exchange with the
# echo service (TCP port 7) and checks the jail's capture for the packets the
# strategy should make, like tests/e2e/run.sh does on Linux.
# Usage: tests/e2e/bsd_divert.sh [path/to/geneva]
set -u
GENEVA=$(realpath "${1:-build/geneva}")
WORK=$(mktemp -d /tmp/gbsd.XXXXXX)
PORT=7
JAIL=gbsd$$
fails=0 passes=0

cleanup() {
    [ -n "${ENG:-}" ] && kill "$ENG" 2>/dev/null
    jail -r "$JAIL" 2>/dev/null
    [ -n "${EPA:-}" ] && ifconfig "$EPA" destroy 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# ipfw lets everything through until a rule says otherwise; divert sockets
kenv net.inet.ip.fw.default_to_accept=1 >/dev/null 2>&1
kldload -n ipfw ipdivert || { echo "cannot load ipfw and ipdivert"; exit 1; }

EPA=$(ifconfig epair create) || { echo "cannot create an epair"; exit 1; }
EPB=${EPA%a}b
jail -c name="$JAIL" path=/ vnet persist vnet.interface="$EPB" || { echo "cannot create a vnet jail"; exit 1; }
ifconfig "$EPA" inet 10.77.0.1/24 up
ifconfig "$EPA" inet6 fd77::1/64 no_dad
jexec "$JAIL" ifconfig lo0 up
jexec "$JAIL" ifconfig "$EPB" inet 10.77.0.2/24 up
jexec "$JAIL" ifconfig "$EPB" inet6 fd77::2/64 no_dad
# no offloads: the capture must show packets as sent
for i in "$EPA" "$EPB"; do
    j=; [ "$i" = "$EPB" ] && j="jexec $JAIL"
    $j ifconfig "$i" -txcsum -rxcsum -txcsum6 -rxcsum6 -tso -lro 2>/dev/null
done
printf 'echo stream tcp nowait root internal\necho stream tcp6 nowait root internal\n' > "$WORK/inetd.conf"
jexec "$JAIL" inetd -p "$WORK/inetd.pid" "$WORK/inetd.conf" || { echo "inetd failed"; exit 1; }
sleep 0.5

printf 'hello geneva 0123456789 abcdefghijklmnopqrstuvwxyz\n' > "$WORK/msg"
dd if=/dev/random of="$WORK/big" bs=1k count=200 2>/dev/null

# exchange [DST [FILE]]: FILE through the echo service, back unchanged
exchange() {
    f=${2:-$WORK/msg}
    timeout 20 nc -N -w 5 "${1:-10.77.0.2}" $PORT < "$f" > "$WORK/got" 2>/dev/null && cmp -s "$f" "$WORK/got"
}

ipfw_ours() { ipfw list 2>/dev/null | grep -c "// geneva 310$"; }

start_case() {
    CASE=$1 STRAT=$2 EXTRA=${3:-}
    rm -f "$WORK/cap.pcap" "$WORK/ev.jsonl" "$WORK/eng.log" "$WORK/tcpdump.err"
    # immediate mode: without it the packets wait in BPF's buffer for up to a
    # second and the ones still there when tcpdump is stopped are lost
    jexec "$JAIL" tcpdump -i "$EPB" --immediate-mode -U -s 0 -w "$WORK/cap.pcap" \
        "tcp port $PORT or (ip[6:2] & 0x1fff != 0) or (ip6 and ip6[6] = 44)" >/dev/null 2>"$WORK/tcpdump.err" &
    TCPD=$!
    i=0
    while ! grep -q "listening on" "$WORK/tcpdump.err" 2>/dev/null; do
        i=$((i + 1)); sleep 0.1
        if [ $i -gt 50 ]; then echo "  tcpdump did not start"; cat "$WORK/tcpdump.err"; break; fi
    done
    printf '%s\n' "$STRAT" > "$WORK/strategy"
    # shellcheck disable=SC2086
    "$GENEVA" run -f "$WORK/strategy" -p $PORT --events "$WORK/ev.jsonl" --stats-interval 0.2 --quiet -v \
        --log-file "$WORK/eng.log" $EXTRA &
    ENG=$!
    i=0
    while ! grep -q '"ev":"ready"' "$WORK/ev.jsonl" 2>/dev/null; do
        i=$((i + 1)); sleep 0.1
        if [ $i -gt 50 ] || ! kill -0 $ENG 2>/dev/null; then
            echo "  engine did not start"; cat "$WORK/ev.jsonl" "$WORK/eng.log" 2>/dev/null; break
        fi
    done
    sleep 0.3
}

stop_case() {
    kill -TERM $ENG 2>/dev/null
    wait $ENG; ENG_RC=$?
    ENG=
    sleep 0.3
    kill -INT $TCPD 2>/dev/null; wait $TCPD 2>/dev/null
    tcpdump -nn -v -r "$WORK/cap.pcap" 2>/dev/null > "$WORK/cap.txt"
}

ok() { passes=$((passes + 1)); echo "  ok   $CASE: $1"; }
bad() {
    fails=$((fails + 1)); echo "  FAIL $CASE: $1"
    [ -n "${2:-}" ] && sed 's/^/       /' "$2" | head -40
    if [ -f "$WORK/eng.log" ]; then echo "       -- engine log:"; sed 's/^/       /' "$WORK/eng.log" | head -60; fi
}
check() { if eval "$2"; then ok "$1"; else bad "$1" "$WORK/cap.txt"; fi; }
cnt() { grep -c -- "$1" "$WORK/cap.txt"; }
client() { grep "10.77.0.1.* > 10.77.0.2.$PORT:" "$WORK/cap.txt"; }

echo "== divert ($(uname -sr))"
CASE=baseline
exchange && ok "exchange works without geneva" || bad "the echo service does not answer"

start_case "no-op" '\/'
exchange && ok "exchange works" || bad "exchange failed"
check "the rules are in place" '[ $(ipfw_ours) -ge 2 ]'
stop_case
check "engine exit code 0" '[ $ENG_RC -eq 0 ]'
check "exit event" 'grep -q "\"ev\":\"exit\"" "$WORK/ev.jsonl"'
check "ready event names the backend" 'grep "\"ev\":\"ready\"" "$WORK/ev.jsonl" | grep -q "\"backend\":\"divert\""'
check "rules removed" '[ $(ipfw_ours) -eq 0 ]'

start_case "duplicate+tamper SYN" '[TCP:flags:S]-duplicate(tamper{TCP:window:replace:7},)-| \/'
exchange && ok "exchange works" || bad "exchange failed"
stop_case
check "SYN with win 7 (verdict path)" '[ $(grep "Flags \[S\]" "$WORK/cap.txt" | grep -c "win 7,") -ge 1 ]'
check "plain SYN too (inject path)" '[ $(grep "Flags \[S\]" "$WORK/cap.txt" | grep -vc "win 7,") -ge 1 ]'

start_case "tcp segmentation" '[TCP:flags:PA]-fragment{tcp:8:True}-| \/'
exchange && ok "exchange works" || bad "exchange failed"
stop_case
check "first segment has 8 bytes" '[ $(client | grep "Flags \[P.\]" | grep -Ec "length 8(:|$)") -ge 1 ]'

start_case "200 KB both ways, every data packet split" '[TCP:flags:PA]-fragment{tcp:8:False}-| \/'
exchange 10.77.0.2 "$WORK/big" && ok "the echo is intact" || bad "the echo differs or failed"
stop_case

start_case "ip fragmentation" '[TCP:flags:PA]-fragment{ip:16:True}-| \/'
exchange && ok "exchange works" || bad "exchange failed"
stop_case
check "IP fragments on the wire" '[ $(cnt "flags \[+") -ge 1 ]'

start_case "sleep" '[TCP:flags:PA]-duplicate(,sleep{0.6})-| \/'
exchange && ok "exchange works" || bad "exchange failed"
sleep 1
stop_case
check "payload sent twice" '[ $(client | grep -c "Flags \[P.\]") -ge 2 ]'
check "delay counted" 'grep "\"ev\":\"stats\"" "$WORK/ev.jsonl" | tail -1 | grep -q "\"delayed\":1"'

start_case "drop" '[TCP:flags:S]-drop-| \/'
exchange && bad "exchange worked although SYNs are dropped" || ok "exchange fails"
stop_case
check "no SYN reached the server" '[ $(cnt "Flags \[S\]") -eq 0 ]'

start_case "inbound tamper" '\/ [TCP:flags:SA]-tamper{TCP:window:replace:9}-|'
exchange && ok "exchange works" || bad "exchange failed"
stop_case
check "in-tree fired" 'grep "\"ev\":\"stats\"" "$WORK/ev.jsonl" | tail -1 | grep -q "\"in_trees\":\[{\"tree\":\"\[TCP:flags:SA\]-tamper{TCP:window:replace:9}-|\",\"fired\":[1-9]"'

start_case "IPv6 duplicate" '[TCP:flags:S]-duplicate(tamper{TCP:window:replace:7},)-| \/'
exchange fd77::2 && ok "exchange works" || bad "exchange failed"
stop_case
check "IPv6 SYN with win 7" '[ $(grep "fd77::1" "$WORK/cap.txt" | grep "Flags \[S\]" | grep -c "win 7,") -ge 1 ]'

start_case "IPv6 fragmentation" '[TCP:flags:PA]-fragment{ip:16:True}-| \/'
exchange fd77::2 && ok "exchange works" || bad "exchange failed"
stop_case
check "IPv6 fragments on the wire" '[ $(cnt "frag (") -ge 1 ]'

if "$GENEVA" version --json | grep -q '"ext_xact"'; then
    start_case "--ext: FLOW:n second packet" '[FLOW:n:2-2]-tamper{TCP:window:replace:7}-| \/' --ext
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case
    check "only the handshake ACK has win 7" '[ $(client | grep -c "win 7,") -eq 1 ] && client | grep "win 7," | grep -q "Flags \[\.\]"'

    start_case "--ext: META:ifin of the inbound packets" '\/ [META:ifin:'"$EPA"']-tamper{TCP:window:replace:9}-| [META:ifin:nosuch]-drop-|' --ext
    exchange && ok "exchange works (no inbound packet dropped)" || bad "exchange failed"
    stop_case
    check "the interface's tree fired" 'grep "\"ev\":\"stats\"" "$WORK/ev.jsonl" | tail -1 | grep -q "\"tree\":\"\[META:ifin:'"$EPA"'\][^\"]*\",\"fired\":[1-9]"'

    start_case "--ext: xsplit + xfake" '[TCP:flags:PA]-xfake{blob=0x41;badsum;payload=all}(xsplit{pos=5;payload=all},)-| \/' --ext
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case
    check "a 1-byte fake with a bad checksum" '[ $(grep -A1 "incorrect" "$WORK/cap.txt" | grep -Ec "length 1(:|$)") -ge 1 ] || [ $(grep "incorrect" "$WORK/cap.txt" | grep -Ec "length 1(:|$)") -ge 1 ]'
    check "the 5-byte first part" '[ $(client | grep "Flags \[P.\]" | grep -Ec "length 5(:|$)") -ge 1 ]'
fi

# a killed engine leaves its rules; the next start removes them first
CASE="SIGKILL"
start_case "SIGKILL" '\/'
kill -KILL $ENG; wait $ENG 2>/dev/null; ENG=
kill -INT $TCPD 2>/dev/null; wait $TCPD 2>/dev/null
check "rules left behind" '[ $(ipfw_ours) -ge 2 ]'
start_case "restart after SIGKILL" '\/'
check "one set of rules" '[ $(ipfw_ours) -eq 2 ] && [ $(ipfw list | grep "// geneva 310$" | cut -c1-5 | sort -u | wc -l) -eq 1 ]'
exchange && ok "exchange works" || bad "exchange failed"
stop_case
check "rules removed" '[ $(ipfw_ours) -eq 0 ]'

CASE="geneva fw"
out=$("$GENEVA" fw up -p $PORT 2>&1)
check "fw up applies ipfw rules" '[ "$out" = ipfw ] && [ $(ipfw_ours) -eq 2 ]'
"$GENEVA" fw down -p $PORT
check "fw down removes them" '[ $(ipfw_ours) -eq 0 ]'
"$GENEVA" fw print -p $PORT > "$WORK/cap.txt"
check "fw print shows ipfw by default" 'grep -q "^ipfw -q add \$R divert 310 tcp from any to any 7 out not diverted // geneva 310$" "$WORK/cap.txt"'

echo "divert e2e: $passes passed, $fails failed"
[ $fails -eq 0 ]
