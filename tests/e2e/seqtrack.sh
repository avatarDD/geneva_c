#!/bin/sh
# End-to-end test of seqtrack (stage X8): xoob and xtlsrec make the client's
# first message longer and shift the flow's numbering on the SYN; a 100 MB
# download must arrive whole after it (its SHA-256 is checked), and with
# packets lost on the way the first message's retransmissions must still
# reach the server changed. xdrip is checked the same way (no shift). Needs
# root, iproute2, iptables (with the statistic match) and python3.
#
#   client ns (geneva run) 10.78.0.1 ---veth--- 10.78.0.2 server ns
#
# Usage: tests/e2e/seqtrack.sh [path/to/geneva]   SIZE=bytes (104857600)
set -u
GENEVA=$(readlink -f "${1:-build/geneva}")
SIZE=${SIZE:-104857600}
NC=gsq_c$$ NS=gsq_s$$
WORK=$(mktemp -d)
PORT=8443
CH_FILE=${CH_FILE:-$(readlink -f "$(dirname "$0")/../data/ext/tls_clienthello_chromium_mlkem.bin")}
fails=0 passes=0

cleanup() {
    [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null
    [ -n "${ENG:-}" ] && kill "$ENG" 2>/dev/null
    ip netns del "$NC" 2>/dev/null
    ip netns del "$NS" 2>/dev/null
    [ -n "${KEEP:-}" ] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

ip netns add "$NC" && ip netns add "$NS" || { echo "cannot create namespaces"; exit 1; }
ip link add veth_c netns "$NC" type veth peer name veth_s netns "$NS"
ip -n "$NC" addr add 10.78.0.1/24 dev veth_c
ip -n "$NS" addr add 10.78.0.2/24 dev veth_s
for n in "$NC" "$NS"; do ip -n "$n" link set lo up; done
ip -n "$NC" link set veth_c up
ip -n "$NS" link set veth_s up

# The server: TLS records (their bodies put together) or "L" and a line,
# then "N\n"; it answers with the SHA-256 of what it read (the record
# bodies, or the line) and N bytes of a known stream.
cat > "$WORK/srv.py" <<'PY'
import hashlib, socket, sys, threading
def stream(n):
    blk = hashlib.sha256(b"geneva").digest() * 2048  # 64 KiB
    while n > 0:
        k = min(n, len(blk)); yield blk[:k]; n -= k
def readn(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d: raise EOFError
        b += d
    return b
def readline(c):
    b = b""
    while not b.endswith(b"\n"):
        d = c.recv(1)
        if not d: raise EOFError
        b += d
    return b
def handle(c):
    c.settimeout(30)
    try:
        b = readn(c, 1)
        if b == b"\x16":  # TLS records, then N
            body = b""
            while b == b"\x16":
                h = b + readn(c, 4)
                body += readn(c, h[3] << 8 | h[4])
                b = readn(c, 1)
            got, n = body, int(b + readline(c))
        else:              # L<line>, then N
            got = readline(c)
            n = int(readline(c))
        c.sendall(hashlib.sha256(got).hexdigest().encode() + b"\n")
        for d in stream(n): c.sendall(d)
    except Exception as e:
        print("server:", e, file=sys.stderr)
    c.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1]))); s.listen(64)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PY
# The client: the request, its hash back, then N bytes hashed as they come
cat > "$WORK/cli.py" <<'PY'
import hashlib, socket, sys, time
host, port, mode, n = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
s = socket.socket(); s.settimeout(30)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.connect((host, port))
if mode == "tls":
    ch = open(sys.argv[5], "rb").read()
    body = ch[5:]
    # the hello first: the action works on the first message
    s.sendall(ch)
    s.sendall(b"%d\n" % n)
    want = hashlib.sha256(body).hexdigest()
else:
    line = b"GET /seqtrack HTTP/1.1 0123456789\n"
    # N in a segment of its own after the message: with urp=e the urgent
    # byte ends the message, and a server that closes with it unread
    # (nothing read past it) answers with a RST
    s.sendall(b"L" + line)
    time.sleep(0.05)
    s.sendall(b"%d\n" % n)
    want = hashlib.sha256(line).hexdigest()
f = s.makefile("rb")
got = f.readline().strip().decode()
if got != want:
    print("request hash %s, expected %s" % (got, want)); sys.exit(1)
h, k = hashlib.sha256(), 0
blk = hashlib.sha256(b"geneva").digest() * 2048
exp = hashlib.sha256()
left = n
while left > 0:
    d = f.read(min(left, 1 << 20))
    if not d: break
    h.update(d); k += len(d); left -= len(d)
while n > 0:
    t = min(n, len(blk)); exp.update(blk[:t]); n -= t
if k != int(sys.argv[4]) or h.hexdigest() != exp.hexdigest():
    print("got %d bytes, sha256 %s, expected %s" % (k, h.hexdigest(), exp.hexdigest())); sys.exit(1)
PY

ip netns exec "$NS" python3 "$WORK/srv.py" $PORT 2>"$WORK/srv.err" &
SRV=$!
sleep 0.5
kill -0 $SRV 2>/dev/null || { echo "server failed to start"; exit 1; }

ok() { passes=$((passes + 1)); echo "  ok   $1"; }
bad() {
    fails=$((fails + 1)); echo "  FAIL $1"
    [ -f "$WORK/out.txt" ] && sed 's/^/       /' "$WORK/out.txt" | head -10
    [ -f "$WORK/eng.log" ] && { echo "       -- engine log:"; tail -30 "$WORK/eng.log" | sed 's/^/       /'; }
    sed 's/^/       /' "$WORK/srv.err" | tail -5
}

start() {
    printf '%s\n' "$1" > "$WORK/strategy"
    rm -f "$WORK/ev.jsonl" "$WORK/eng.log"
    ip netns exec "$NC" "$GENEVA" run --ext -f "$WORK/strategy" -p $PORT --events "$WORK/ev.jsonl" \
        --quiet -v --log-file "$WORK/eng.log" &
    ENG=$!
    i=0
    while ! grep -q '"ev":"ready"' "$WORK/ev.jsonl" 2>/dev/null; do
        i=$((i + 1)); sleep 0.1
        if [ $i -gt 50 ] || ! kill -0 $ENG 2>/dev/null; then echo "  engine did not start"; break; fi
    done
}

stop() {
    kill -TERM $ENG 2>/dev/null
    wait $ENG
    ENG=
}

# get NAME MODE BYTES: one download, checked
get() {
    if ip netns exec "$NC" timeout 120 python3 "$WORK/cli.py" 10.78.0.2 $PORT "$2" "$3" "$CH_FILE" >"$WORK/out.txt" 2>&1; then
        ok "$1"
    else
        bad "$1"
    fi
}

# the first message is lost a few times (30% of what reaches the server
# is dropped there): it goes again changed
lossy() {
    ip netns exec "$NS" iptables -I INPUT -p tcp --dport $PORT -m statistic --mode random --probability 0.3 \
        -j DROP 2>/dev/null || {
        echo "  skip $1: no iptables statistic match"
        return
    }
    n=0
    for i in 1 2 3 4 5 6 7 8 9 10; do
        ip netns exec "$NC" timeout 60 python3 "$WORK/cli.py" 10.78.0.2 $PORT "$2" 2048 "$CH_FILE" >"$WORK/out.txt" 2>&1 && n=$((n + 1))
    done
    ip netns exec "$NS" iptables -D INPUT -p tcp --dport $PORT -m statistic --mode random --probability 0.3 -j DROP
    # (how many first messages went again: by chance, so only shown)
    echo "       first messages sent again: $(grep -c 'retransmission of the first message' "$WORK/eng.log")"
    if [ $n -eq 10 ]; then ok "$1: 10 of 10"; else bad "$1: $n of 10"; fi
}

echo "== seqtrack e2e ($SIZE bytes)"
start '\/'
get "no strategy: line" line "$SIZE"
stop

start '[FLOW:n:1-]-xoob-| \/'
get "xoob (urp=b): 100 MB after the urgent byte" line "$SIZE"
get "xoob (urp=b) over a TLS hello" tls 65536
lossy "xoob with 30% loss" line
stop
grep -q "decreasing outgoing seq" "$WORK/eng.log" && ok "xoob shifted the SYN" || bad "xoob shifted the SYN"

start '[FLOW:n:1-]-xoob{urp=e;char=Z}-| \/'
get "xoob (urp=e)" line "$SIZE"
stop

start '[FLOW:n:1-]-xtlsrec{pos=sniext+1}-| \/'
get "xtlsrec: 100 MB after the hello cut in two records" tls "$SIZE"
lossy "xtlsrec with 30% loss" tls
stop
grep -q "TLS record of" "$WORK/eng.log" && ok "xtlsrec cut the record" || bad "xtlsrec cut the record"

start '[TCP:flags:PA]-xdrip{n=4;delay=30;payload=all}-| \/'
get "xdrip" tls 1048576
stop

echo "seqtrack e2e: $passes passed, $fails failed"
[ $fails -eq 0 ]
