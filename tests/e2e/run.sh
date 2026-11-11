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
        # a thread per connection: one a censor cut off waits for its
        # timeout without holding up the next
        threading.Thread(target=handle, args=(c,), daemon=True).start()
def handle(c):
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
# a TLS ClientHello (Chromium, SNI example.com at its end) in two segments,
# then the newline the echo server waits for
CH_FILE=$(readlink -f "$(dirname "$0")/../data/ext/tls_clienthello_chromium_mlkem.bin")
cat > "$WORK/cli_ch.py" <<'PY'
import socket, sys, time
ch = open(sys.argv[3], "rb").read()
s = socket.socket(); s.settimeout(8)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.connect((sys.argv[1], int(sys.argv[2])))
for part in (ch[:1000], ch[1000:], b"\n"):
    s.sendall(part)
    time.sleep(0.2)
got = b""
while True:
    d = s.recv(65536)
    if not d: break
    got += d
sys.exit(0 if got == b"echo:" + ch + b"\n" else 1)
PY
HAVE6=0
ip netns exec "$NC" python3 -c 'import socket; socket.socket(socket.AF_INET6)' 2>/dev/null && HAVE6=1
ip netns exec "$NS" python3 "$WORK/srv.py" $PORT &
SRV=$!
sleep 0.5
kill -0 $SRV 2>/dev/null || { echo "echo server failed to start"; exit 1; }

# run_case NAME FIREWALL STRATEGY [DST] -- then checks via helpers below
start_case() {
    CASE=$1 FW=$2 STRAT=$3 DST=${4:-10.77.0.2} EXTRA=${5:-}
    rm -f "$WORK/cap.pcap" "$WORK/ev.jsonl" "$WORK/eng.log"
    rm -f "$WORK/tcpdump.err"
    ip netns exec "$NS" tcpdump -i veth_s --immediate-mode -U -s 0 -w "$WORK/cap.pcap" "tcp port $PORT or ip[6:2] & 0x1fff != 0 or ip6[6] = 44" >/dev/null 2>"$WORK/tcpdump.err" &
    TCPD=$!
    # the capture must be running before the first packet
    i=0
    while ! grep -q "listening on" "$WORK/tcpdump.err" 2>/dev/null; do
        i=$((i + 1)); sleep 0.1
        if [ $i -gt 50 ]; then echo "  tcpdump did not start"; cat "$WORK/tcpdump.err"; break; fi
    done
    printf '%s\n' "$STRAT" > "$WORK/strategy"
    ip netns exec "$NC" "$GENEVA" run -f "$WORK/strategy" -p $PORT --firewall "$FW" \
        --events "$WORK/ev.jsonl" --stats-interval 0.2 --quiet -v --log-file "$WORK/eng.log" $EXTRA &
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
    kill -INT $TCPD 2>/dev/null; wait $TCPD 2>/dev/null
    tcpdump -nn -v -r "$WORK/cap.pcap" 2>/dev/null > "$WORK/cap.txt"
}

ok() { passes=$((passes + 1)); echo "  ok   $CASE [$FW]: $1"; }
bad() {
    fails=$((fails + 1)); echo "  FAIL $CASE [$FW]: $1"
    [ -n "${2:-}" ] && sed 's/^/       /' "$2" | head -40
    if [ -n "${2:-}" ] && [ -f "$WORK/eng.log" ]; then
        echo "       -- engine log:"; sed 's/^/       /' "$WORK/eng.log" | head -60
    fi
}
check() { if eval "$2"; then ok "$1"; else bad "$1" "$WORK/cap.txt"; fi; }

exchange() { ip netns exec "$NC" timeout 15 python3 "$WORK/cli.py" "${DST}" $PORT; }
exchange_ch() { ip netns exec "$NC" timeout 15 python3 "$WORK/cli_ch.py" "${DST}" $PORT "$CH_FILE"; }

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

    # the conntrack of --ext (stage X3): a FLOW range picks one packet of the
    # flow, META:ifout the interface; the window marks what the trees hit
    if "$GENEVA" version --json | grep -q '"ext_ctrack"'; then
    start_case "FLOW:n second packet" "$FW" '[FLOW:n:2-2]-tamper{TCP:window:replace:7}-| \/' 10.77.0.2 --ext
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case
    check "only the handshake ACK has win 7" '[ $(grep "10.77.0.1.* > 10.77.0.2.$PORT:" "$WORK/cap.txt" | grep -c "win 7,") -eq 1 ] && grep "10.77.0.1.* > 10.77.0.2.$PORT:" "$WORK/cap.txt" | grep "win 7," | grep "Flags \[\.\]" | grep -q "ack 1,"'
    check "the tree was cut off after it" 'grep "\"ev\":\"stats\"" "$WORK/ev.jsonl" | tail -1 | grep -q "\"fired\":1}"'

    start_case "META:ifout" "$FW" '[META:ifout:veth_c]-tamper{TCP:window:replace:7}-| [META:ifout:nosuch]-drop-| \/' 10.77.0.2 --ext
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case
    check "every client packet has win 7" '[ $(grep "10.77.0.1.* > 10.77.0.2.$PORT:" "$WORK/cap.txt" | grep -vc "win 7,") -eq 0 ] && [ $(cnt "win 7,") -ge 3 ]'
    fi

    # L7 of --ext (stage X4): the hello in two segments is reassembled, the
    # held segments go on through the strategy with its host name
    if "$GENEVA" version --json | grep -q '"ext_l7"'; then
    start_case "L7:host over a split ClientHello" "$FW" '[L7:host:example.com]-tamper{TCP:window:replace:7}-| \/' 10.77.0.2 --ext
    exchange_ch && ok "exchange works" || bad "exchange failed"
    stop_case
    check "the first piece has win 7 (the SNI is in the second)" 'grep "10.77.0.1.* > 10.77.0.2.$PORT: Flags \[P.\]" "$WORK/cap.txt" | grep -E "length 1000(:|$)" | grep -q "win 7,"'
    check "the second piece too, not the SYN" 'grep "10.77.0.1.* > 10.77.0.2.$PORT: Flags \[P.\]" "$WORK/cap.txt" | grep -E "length 825(:|$)" | grep -q "win 7," && ! grep "Flags \[S\]" "$WORK/cap.txt" | grep -q "win 7,"'
    check "two packets held" 'grep "\"ev\":\"stats\"" "$WORK/ev.jsonl" | tail -1 | grep -q "\"held\":2"'

    start_case "L7:host without reassembly" "$FW" '[L7:host:example.com]-tamper{TCP:window:replace:7}-| \/' 10.77.0.2 "--ext --ext-reasm-disable all"
    exchange_ch && ok "exchange works" || bad "exchange failed"
    stop_case
    check "no piece knows the host (the SNI is in the second)" '[ $(cnt "win 7,") -eq 0 ]'
    fi

    # x-actions of --ext (stage X5a): a fake with a bad checksum the server
    # ignores, then the reassembled hello in parts from the last to the first;
    # parts in IP fragments
    if "$GENEVA" version --json | grep -q '"ext_xact"'; then
    start_case "xfake + xdisorder over a split ClientHello" "$FW" '[TCP:flags:PA]-xfake{blob=fake_default_tls;badsum;repeats=2}(xdisorder{pos=1,midsld},)-| \/' 10.77.0.2 --ext
    exchange_ch && ok "exchange works" || bad "exchange failed"
    stop_case
    check "two fakes of 680 bytes with a bad checksum" '[ $(grep -A1 "incorrect" "$WORK/cap.txt" | grep -Ec "length 680(:|$)") -ge 2 ] || [ $(grep "incorrect" "$WORK/cap.txt" | grep -Ec "length 680(:|$)") -ge 2 ]'
    check "the 1-byte first part" '[ $(grep "10.77.0.1.* > 10.77.0.2.$PORT: Flags \[P.\]" "$WORK/cap.txt" | grep -Ec "length 1(:|$)") -ge 1 ]'
    check "no piece went as it was" '[ $(grep "10.77.0.1.* > 10.77.0.2.$PORT: Flags \[P.\]" "$WORK/cap.txt" | grep -Ec "length (1000|825)(:|$)") -eq 0 ]'

    start_case "xsplit in IP fragments" "$FW" '[TCP:flags:PA]-xsplit{pos=5;payload=all;ipfrag;ipfrag_pos_tcp=16}-| \/' 10.77.0.2 --ext
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case
    check "IP fragments on the wire" '[ $(cnt "flags \[+") -ge 2 ]'

    start_case "xtlsclone: a fake ClientHello with another SNI" "$FW" '[TCP:flags:PA]-xtlsclone{blob=c;sni_first=clone.example}(xfake{blob=c;optional;badsum},)-| \/' 10.77.0.2 --ext
    exchange_ch && ok "exchange works" || bad "exchange failed"
    stop_case
    check "the clone went with a bad checksum" '[ $(grep -c "incorrect" "$WORK/cap.txt") -ge 1 ]'
    check "the clone carries the new name" 'grep -aq clone.example "$WORK/cap.pcap"'

    start_case "xsyndata + xwssize" "$FW" '[TCP:flags:S]-xsyndata{blob=0x0102}-| [TCP:dport:'"$PORT"']-xwssize{wsize=1000}-| \/' 10.77.0.2 --ext
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case
    check "a SYN with 2 bytes of data" '[ $(grep "10.77.0.1.* > 10.77.0.2.$PORT: Flags \[S\]" "$WORK/cap.txt" | grep -Ec "length 2(:|$)") -ge 1 ]'
    check "the SYN window rewritten" '[ $(grep "10.77.0.1.* > 10.77.0.2.$PORT: Flags \[S\]" "$WORK/cap.txt" | grep -c "win 1000,") -ge 1 ]'

    start_case "xlog + xrst" "$FW" '[TCP:flags:PA]-xlog{msg=seen}(xrst{payload=all;badsum},)-| \/' 10.77.0.2 --ext
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case
    check "an ext_pkt event" 'grep -q "\"ev\":\"ext_pkt\".*\"msg\":\"seen\"" "$WORK/ev.jsonl"'
    check "an RST with a bad checksum" '[ $(grep "Flags \[R\]" "$WORK/cap.txt" | grep -c "incorrect") -ge 1 ]'

    # combinators (stage X5c): three RSTs on the first data packet, then the
    # tree is cut off for the flow; a condition on the payload
    start_case "xrepeat + xcutoff" "$FW" '[TCP:flags:PA]-xrepeat{repeats=3}(xrst{payload=all;badsum},xcutoff)-| \/' 10.77.0.2 --ext
    exchange_ch && ok "exchange works" || bad "exchange failed"
    stop_case
    check "three RSTs, on the first packet only" '[ $(grep "Flags \[R\]" "$WORK/cap.txt" | grep -c "incorrect") -eq 3 ]'

    start_case "xwhen on the payload" "$FW" '[TCP:flags:PA]-xwhen{iff=cond_payload_str;pattern=geneva}(xrst{payload=all;badsum},xrst{payload=all;badsum;repeats=2})-| \/' 10.77.0.2 --ext
    exchange && ok "exchange works" || bad "exchange failed"
    stop_case
    check "one RST from the then branch" '[ $(grep "Flags \[R\]" "$WORK/cap.txt" | grep -c "incorrect") -eq 1 ]'

    # profiles (stage X6a): the TLS flow gets profile 1 once its ClientHello
    # is seen, the plain one stays with profile 2
    printf '%s\n' '[TCP:flags:PA]-tamper{TCP:window:replace:9}-| \/' > "$WORK/strategy2"
    start_case "profiles by L7" "$FW" '[TCP:flags:PA]-tamper{TCP:window:replace:7}-| \/' 10.77.0.2 \
        "--ext --filter-l7 tls --new=rest --filter-tcp $PORT -f $WORK/strategy2"
    exchange_ch && ok "TLS exchange works" || bad "TLS exchange failed"
    exchange && ok "plain exchange works" || bad "plain exchange failed"
    stop_case
    check "the ClientHello with profile 1" '[ $(grep "Flags \[P.\]" "$WORK/cap.txt" | grep -c "win 7,") -ge 2 ]'
    check "the plain data with profile 2" '[ $(grep "Flags \[P.\]" "$WORK/cap.txt" | grep -c "win 9,") -eq 1 ]'

    # host lists (stage X6b): the ClientHello names example.com, in the
    # list (gzip, a subdomain entry and a parent): profile 1; the list
    # changed and SIGHUP: profile 2
    printf '# hosts\nwww.example.com\n^com\n' | gzip > "$WORK/hosts.gz"
    start_case "profiles by host list" "$FW" '[TCP:flags:PA]-tamper{TCP:window:replace:7}-| \/' 10.77.0.2 \
        "--ext --hostlist-domains example.com --hostlist-exclude $WORK/hosts.gz --new=rest --filter-tcp $PORT -f $WORK/strategy2 --control unix:$WORK/ctl.sock"
    exchange_ch && ok "TLS exchange works" || bad "TLS exchange failed"
    printf 'example.com\n' | gzip > "$WORK/hosts.gz"
    kill -HUP $ENG; sleep 0.3
    exchange_ch && ok "TLS exchange works after SIGHUP" || bad "TLS exchange failed after SIGHUP"
    check "ctl reload_lists" 'ip netns exec $NC $GENEVA ctl -c unix:$WORK/ctl.sock reload_lists | grep -q "\"files\":1"'
    stop_case
    check "the first ClientHello with profile 1" '[ $(grep "Flags \[P.\]" "$WORK/cap.txt" | grep -c "win 7,") -ge 2 ]'
    check "the second with profile 2 (excluded)" '[ $(grep "Flags \[P.\]" "$WORK/cap.txt" | grep -c "win 9,") -ge 2 ]'
    check "the list was read again" 'grep -q "loaded 1 hosts" "$WORK/eng.log"'
    fi

    # the autolist (stage X6c): a censor resets the ClientHello naming
    # example.com; two failures add it, then the strategy runs for it. A
    # censor that drops it: the retransmissions are the failure, and the
    # client gets a RST at once
    if "$GENEVA" version --json | grep -q '"ext_autolist"' &&
        ip netns exec "$NS" iptables -I INPUT -p tcp --dport $PORT -m string --string example.com --algo bm \
            -j REJECT --reject-with tcp-reset 2>/dev/null; then
    rm -f "$WORK/auto.txt" "$WORK/auto.log"
    start_case "autolist" "$FW" '[TCP:flags:PA]-tamper{TCP:window:replace:7}-| \/' 10.77.0.2 \
        "--ext --filter-tcp $PORT --hostlist-auto $WORK/auto.txt --hostlist-auto-fail-threshold 2 --hostlist-auto-debug $WORK/auto.log"
    exchange_ch && bad "the censor let the first through" || ok "the censor resets the first"
    check "one failure is not enough" '[ ! -s "$WORK/auto.txt" ]'
    exchange_ch && bad "the censor let the second through" || ok "the censor resets the second"
    check "example.com is in the autolist" 'grep -qx example.com "$WORK/auto.txt"'
    exchange_ch
    stop_case
    check "then the strategy runs for it" '[ $(grep "Flags \[P.\]" "$WORK/cap.txt" | grep -c "win 7,") -ge 1 ]'
    check "the debug log" 'grep -q "example.com : profile 1 (noname) : client 10.77.0.1:[0-9]* : proto tls : rseq 1 : incoming RST" "$WORK/auto.log" && grep -q "adding to $WORK/auto.txt" "$WORK/auto.log"'
    ip netns exec "$NS" iptables -D INPUT -p tcp --dport $PORT -m string --string example.com --algo bm \
        -j REJECT --reject-with tcp-reset
    ip netns exec "$NS" iptables -I INPUT -p tcp --dport $PORT -m string --string example.com --algo bm -j DROP
    rm -f "$WORK/auto.txt" "$WORK/auto.log"
    start_case "autolist by retransmissions" "$FW" '[TCP:flags:PA]-tamper{TCP:window:replace:7}-| \/' 10.77.0.2 \
        "--ext --filter-tcp $PORT --hostlist-auto $WORK/auto.txt --hostlist-auto-fail-threshold 1 --hostlist-auto-debug $WORK/auto.log"
    t0=$(date +%s)
    exchange_ch && bad "the censor let it through" || ok "the exchange fails"
    t1=$(date +%s)
    stop_case
    check "the client got a RST before its timeout ($((t1 - t0)) s)" '[ $((t1 - t0)) -lt 7 ]'
    check "retransmissions are the failure" 'grep -q "retrans threshold reached" "$WORK/auto.log" && grep -qx example.com "$WORK/auto.txt"'
    ip netns exec "$NS" iptables -D INPUT -p tcp --dport $PORT -m string --string example.com --algo bm -j DROP
    fi

    # running as a service (stage X7a): as nobody with two capabilities and
    # seccomp; a SIGKILL of the engine leaves the root helper to take the
    # rules down; --daemon returns once packets flow
    if "$GENEVA" version --json | grep -q '"ext_service"'; then
    start_case "service" "$FW" '[TCP:flags:PA]-tamper{TCP:window:replace:7}-| \/' 10.77.0.2 \
        "--ext --user nobody --pidfile $WORK/geneva.pid --control unix:$WORK/ctl.sock"
    exchange && ok "exchange works" || bad "exchange failed" "$WORK/eng.log"
    check "running as nobody" '[ "$(ps -o user= -p $ENG)" = nobody ]'
    check "only CAP_NET_ADMIN and CAP_NET_RAW" 'grep -q "^CapEff:.*0000000000003000$" /proc/$ENG/status'
    check "seccomp on" 'grep -q "^Seccomp:.*2$" /proc/$ENG/status'
    check "the pidfile" '[ "$(cat $WORK/geneva.pid)" = $ENG ]'
    check "ctl ext_flows" 'ip netns exec $NC $GENEVA ctl -c unix:$WORK/ctl.sock ext_flows | grep -q "\"sport\":$PORT"'
    check "ctl ext_keys" 'ip netns exec $NC $GENEVA ctl -c unix:$WORK/ctl.sock ext_keys | grep -q "\"autolist\":\[\]"'
    kill -KILL $ENG
    wait $ENG 2>/dev/null
    sleep 0.5
    check "SIGKILL: rules removed by the helper" rules_gone
    check "SIGKILL: the pidfile removed" '[ ! -e $WORK/geneva.pid ]'
    kill -INT $TCPD 2>/dev/null; wait $TCPD 2>/dev/null
    CASE=daemon
    ip netns exec "$NC" "$GENEVA" run --ext -s '\/' -p $PORT --firewall "$FW" --daemon --pidfile $WORK/geneva.pid \
        --log-file "$WORK/eng.log" --quiet
    check "--daemon returns 0 once running" '[ $? -eq 0 ] && [ -s $WORK/geneva.pid ] && ! rules_gone'
    DPID=$(cat $WORK/geneva.pid 2>/dev/null)
    check "the daemon has its own session" '[ "$(ps -o sid= -p $DPID | tr -d " ")" = "$DPID" ]'
    exchange && ok "exchange works" || bad "exchange failed" "$WORK/eng.log"
    kill -TERM $DPID 2>/dev/null
    i=0; while kill -0 $DPID 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
    check "SIGTERM: rules removed" rules_gone
    check "SIGTERM: the pidfile removed" '[ ! -e $WORK/geneva.pid ]'
    ip netns exec "$NC" "$GENEVA" run --ext -s '[x' -p $PORT --firewall "$FW" --daemon 2>/dev/null
    check "a failed start: exit code 3" '[ $? -eq 3 ]'
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

# control socket (once, with the default firewall)
CTL="ip netns exec $NC $GENEVA ctl -c unix:$WORK/ctl.sock"
FW=auto
start_case "control socket" auto '\/' 10.77.0.2 "--control unix:$WORK/ctl.sock"
check "status says running" '$CTL status | grep -q "\"state\":\"running\""'
$CTL subscribe --until exit > "$WORK/sub.jsonl" 2>&1 &
SUB=$!
sleep 0.2
check "set_strategy" '$CTL set_strategy strategy="[TCP:flags:S]-tamper{TCP:window:replace:7}-| \\/" | grep -q "\"ok\":true"'
check "bad strategy is refused" '! $CTL set_strategy strategy="[TCP:flags:S]-nonsense-|" >/dev/null'
exchange && ok "exchange works" || bad "exchange failed"
check "pause" '$CTL pause | grep -q "\"ok\":true"'
exchange && ok "exchange works while paused" || bad "exchange failed while paused"
check "stats while paused" '$CTL stats | grep -q "\"paused\":true"'
check "resume" '$CTL resume >/dev/null && $CTL status | grep -q "\"state\":\"running\""'
check "log_level" '$CTL log_level level=debug | grep -q "\"level\":\"debug\""'
check "stop" '$CTL stop | grep -q "\"ok\":true"'
wait $SUB
stop_case
check "engine exit code 0" '[ $ENG_RC -eq 0 ]'
check "exit reason control" 'grep -q "\"reason\":\"control\"" "$WORK/ev.jsonl"'
check "subscriber saw strategy, state and exit" 'grep -q "\"ev\":\"strategy\"" "$WORK/sub.jsonl" && grep -q "\"ev\":\"state\"" "$WORK/sub.jsonl" && grep -q "\"ev\":\"exit\"" "$WORK/sub.jsonl"'
check "new strategy applied before pause only" '[ $(grep "Flags \[S\]" "$WORK/cap.txt" | grep -c "win 7,") -eq 1 ] && [ $(grep -c "Flags \[S\]" "$WORK/cap.txt") -eq 2 ]'
check "socket file removed" '[ ! -e "$WORK/ctl.sock" ]'
check "rules removed" rules_gone

start_case "control token" auto '\/' 10.77.0.2 "--control tcp:127.0.0.1:47123 --control-token t0k"
check "no token: refused" '! ip netns exec $NC $GENEVA ctl -c tcp:127.0.0.1:47123 status >/dev/null'
check "wrong token: refused" '! ip netns exec $NC $GENEVA ctl -c tcp:127.0.0.1:47123 -t nope status >/dev/null'
check "right token: status" 'ip netns exec $NC $GENEVA ctl -c tcp:127.0.0.1:47123 -t t0k status | grep -q "\"ok\":true"'
stop_case

# the evaluator with --firewall none: the rules come from "geneva fw print"
# (as an integrator installs them) and the search gets past its baseline
echo "== evaluator with --firewall none"
FW=iptables
case " $FIREWALLS " in *" nft "*) FW=nft ;; esac
CASE="eval/evolve --firewall none"
EVPROBE="--probe tcp --ip 10.77.0.2 --port $PORT --valid-contains echo --timeout 1 --local-ports 30000 -q 311"
"$GENEVA" fw print --local-ports 30000 --workers 1 -q 311 --firewall $FW > "$WORK/fw.txt"
awk -v h="# $FW: apply" '$0 == h {on=1; next} /^# /{on=0} on' "$WORK/fw.txt" > "$WORK/fw-up.sh"
awk -v h="# $FW: remove" '$0 == h {on=1; next} /^# /{on=0} on' "$WORK/fw.txt" > "$WORK/fw-down.sh"
check "fw print has the slots' rules" 'grep -Eq "30000(-|:)30063" "$WORK/fw-up.sh" && grep -Eq "queue.num 311" "$WORK/fw-up.sh"'
ip netns exec "$NC" "$GENEVA" eval $EVPROBE --payload 'hi\n' --firewall none \
    -s '[TCP:flags:S]-drop-| \/' --quiet > "$WORK/noop.txt" 2>&1
check "without rules the strategy sees nothing" '[ $? -eq 0 ]'
ip netns exec "$NC" sh "$WORK/fw-up.sh"
check "rules installed by hand" '! rules_gone'
ip netns exec "$NC" "$GENEVA" eval $EVPROBE --payload 'hi\n' --firewall none \
    -s '[TCP:flags:S]-drop-| \/' --quiet > "$WORK/drop.txt" 2>&1
check "with them it applies (dropped SYNs fail)" '[ $? -eq 1 ]'
# a keyword censor on the server side makes the target blocked
ip netns exec "$NS" iptables -I INPUT -p tcp --dport $PORT -m string --string forbidden --algo bm \
    -j REJECT --reject-with tcp-reset 2>/dev/null && HAVE_STRING=1 || HAVE_STRING=0
if [ $HAVE_STRING -eq 1 ]; then
    ip netns exec "$NC" timeout 120 "$GENEVA" evolve $EVPROBE --payload 'forbidden\n' --firewall none \
        --population 4 --generations 1 --no-canary --rng-seed 7 --events "$WORK/evo.jsonl" --quiet \
        > "$WORK/evo.txt" 2>&1
    EVO_RC=$?
    check "evolve: the baseline is blocked" 'grep "\"ev\":\"baseline\"" "$WORK/evo.jsonl" | grep -q "\"blocked\":true"'
    check "evolve: got past the baseline (exit $EVO_RC)" '[ $EVO_RC -eq 0 -o $EVO_RC -eq 1 ] && grep -q "\"ev\":\"generation\"" "$WORK/evo.jsonl"'
    check "evolve left the rules alone" '! rules_gone'
    ip netns exec "$NS" iptables -D INPUT -p tcp --dport $PORT -m string --string forbidden --algo bm \
        -j REJECT --reject-with tcp-reset
else
    echo "  skip evolve --firewall none: no iptables string match"
fi
ip netns exec "$NC" sh "$WORK/fw-down.sh"
check "rules removed by hand" rules_gone

echo "e2e: $passes passed, $fails failed"
[ $fails -eq 0 ]
