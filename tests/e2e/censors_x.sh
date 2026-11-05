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
#   tests/e2e/censors_x.sh [path/to/geneva] [censor ... | nfqws2 | posdebug]
set -u
GENEVA=$(readlink -f "${1:-build/geneva}")
[ $# -gt 0 ] && shift
ONLY="$*"
NC=gnx_c$$ NR=gnx_r$$ NS=gnx_s$$
WORK=$(mktemp -d)
fails=0

cleanup() {
    [ -n "${CPID:-}" ] && kill "$CPID" 2>/dev/null && wait "$CPID" 2>/dev/null
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
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=lab -keyout "$WORK/key.pem" \
    -out "$WORK/cert.pem" >/dev/null 2>&1 || { echo "openssl failed"; exit 1; }
# HTTP on 80, HTTPS on 443 (any name), and a UDP echo on 443 for QUIC
cat > "$WORK/srv.py" <<'EOF'
import http.server, os, socket, ssl, sys, threading
work = sys.argv[1]
os.chdir(work + "/www")
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass
def serve(port, tls):
    s = http.server.ThreadingHTTPServer(("0.0.0.0", port), H)
    if tls:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        c.load_cert_chain(work + "/cert.pem", work + "/key.pem")
        s.socket = c.wrap_socket(s.socket, server_side=True)
    s.serve_forever()
def echo():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("0.0.0.0", 443))
    while True:
        d, a = u.recvfrom(65535)
        u.sendto(d[:64], a)
threading.Thread(target=serve, args=(80, False), daemon=True).start()
threading.Thread(target=echo, daemon=True).start()
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

# Position parity (stage X3): nfqws2 runs zapret2's posdebug on every packet
# of a few flows in the client namespace while tcpdump captures them on its
# interface; "geneva apply --ext --ext-posdebug" over the capture has to see
# the same counters. The direct side of each line is compared strictly per
# direction (it depends only on the side's own packets); the whole lines are
# compared too, but the reverse side may differ where a reply crossed a
# packet held in the queue, so that only warns.
pd_lines() { # log direction: "posdebug: DIR ..." lines without the time
    grep -o "posdebug: $2 .*" "$1" | sed 's/ time +[^ ]*s direct/ direct/'
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
    ip netns exec "$NC" tcpdump -i vx_c -U -w "$WORK/pd.pcap" 'tcp port 80 or tcp port 443 or udp port 443' \
        > "$WORK/tcpdump.log" 2>&1 &
    TPID=$!
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
            bad "$d: direct counters differ from nfqws2 (< nfqws2, > geneva)" "$WORK/pd.diff"
        fi
        if ! diff "$WORK/pd.z.$d" "$WORK/pd.g.$d" > "$WORK/pd.diff"; then
            echo "  warn $d: reverse counters differ in $(grep -c '^<' "$WORK/pd.diff") line(s) (packets crossed in the queue)"
            head -6 "$WORK/pd.diff" | sed 's/^/       /'
        fi
    done
fi

if [ $fails -eq 0 ]; then echo "all passed"; else echo "$fails failure(s)"; fi
exit $fails
