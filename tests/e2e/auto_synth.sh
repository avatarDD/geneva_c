#!/bin/sh
# --ext-auto observe on traffic without a censor (stage X9c, the criterion of
# docs/EXT_ROADMAP.md, section 10): long-polls, WebSocket-style connections
# and 50 MB downloads for DURATION seconds (default 1800) must give no key a
# class and the link no LINK_DEGRADED. Needs root, iproute2, python3, curl,
# tc, and nft or iptables.
#
#   client ns 10.83.1.2 --- 10.83.1.1 server ns (also 10.83.2.1)
#
#   [DURATION=300] [AUTO_FW=iptables] tests/e2e/auto_synth.sh [path/to/geneva]
set -u
GENEVA=$(readlink -f "${1:-build/geneva}")
DURATION=${DURATION:-1800}
NC=gns_c$$ NS=gns_s$$
WORK=$(mktemp -d)
fails=0
PIDS=

cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null; done
    [ -n "${APID:-}" ] && kill "$APID" 2>/dev/null && wait "$APID" 2>/dev/null
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
ip -n "$NC" addr add 10.83.1.2/24 dev vs_c
ip -n "$NS" addr add 10.83.1.1/24 dev vs_s
ip -n "$NS" addr add 10.83.2.1/32 dev lo
for l in "$NC vs_c" "$NS vs_s"; do
    set -- $l
    ip -n "$1" link set "$2" up
    ip netns exec "$1" ethtool -K "$2" tso off gso off gro off >/dev/null 2>&1
done
ip -n "$NC" route add default via 10.83.1.1
# a 50 Mbit/s link: a 50 MB download takes seconds, long enough for the
# capacity C and the rate windows
ip netns exec "$NS" tc qdisc add dev vs_s root tbf rate 50mbit burst 256kb latency 50ms ||
    { echo "tc tbf failed"; exit 1; }

# HTTP on 80: /big is 50 MB, /poll answers after 20 s (a long-poll), the
# rest a small page. 8080: a WebSocket-style connection, an upgrade and then
# a small message both ways every few seconds for a minute.
cat > "$WORK/srv.py" <<'EOF'
import http.server, socket, threading, time
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a):
        pass
    def do_GET(self):
        if self.path == "/big":
            n = 50 * 1000 * 1000
            self.send_response(200)
            self.send_header("Content-Length", str(n))
            self.end_headers()
            chunk = b"\0" * 65536
            while n > 0:
                self.wfile.write(chunk[:min(n, len(chunk))])
                n -= len(chunk)
            return
        body = b"{}\n" if self.path == "/poll" else b"<html>small page</html>\n" * 20
        if self.path == "/poll":
            time.sleep(20)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
def ws(c):
    try:
        c.recv(4096)
        c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        c.settimeout(0.5)
        t0 = time.time()
        while time.time() - t0 < 60:
            c.sendall(b"\x81\x20" + b"n" * 32)
            end = time.time() + 4
            while time.time() < end:
                try:
                    if not c.recv(4096):
                        return
                except socket.timeout:
                    pass
    except OSError:
        pass
    finally:
        c.close()
def ws_server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 8080))
    s.listen(64)
    while True:
        c, _ = s.accept()
        threading.Thread(target=ws, args=(c,), daemon=True).start()
threading.Thread(target=ws_server, daemon=True).start()
http.server.ThreadingHTTPServer(("0.0.0.0", 80), H).serve_forever()
EOF
cat > "$WORK/wsc.py" <<'EOF'
import socket, sys, time
s = socket.create_connection((sys.argv[1], 8080), timeout=10)
s.sendall(b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
s.settimeout(0.5)
t0 = time.time()
while time.time() - t0 < 70:
    s.sendall(b"\x81\xa0" + b"\0" * 4 + b"c" * 32)
    end = time.time() + 7
    while time.time() < end:
        try:
            if not s.recv(4096):
                sys.exit(0)
        except socket.timeout:
            pass
EOF
ip netns exec "$NS" python3 "$WORK/srv.py" > "$WORK/srv.log" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 50); do
    ip netns exec "$NC" curl -s -o /dev/null http://10.83.1.1/ && break
    sleep 0.1
done

: > "$WORK/auto.jsonl"
ip netns exec "$NC" "$GENEVA" run --ext --ext-auto observe -s '\/' -p 1 --firewall "${AUTO_FW:-auto}" \
    --events "$WORK/auto.jsonl" --log-file "$WORK/auto.log" --log-level debug --quiet \
    --control "unix:$WORK/auto.sock" &
APID=$!
for _ in $(seq 50); do
    grep -q '"ev":"ready"' "$WORK/auto.jsonl" 2>/dev/null && break
    sleep 0.1
done
grep -q '"ev":"ready"' "$WORK/auto.jsonl" || { bad "geneva run --ext-auto did not start" "$WORK/auto.log"; exit 1; }

echo "== $DURATION s of traffic without a censor"
END=$(( $(date +%s) + DURATION ))
# long-polls to both addresses, one after another
for a in 10.83.1.1 10.83.2.1; do
    ip netns exec "$NC" sh -c "while [ \$(date +%s) -lt $END ]; do curl -s -o /dev/null --max-time 30 http://$a/poll; done" &
    PIDS="$PIDS $!"
done
# WebSocket-style connections, a new one after each minute
ip netns exec "$NC" sh -c "while [ \$(date +%s) -lt $END ]; do python3 $WORK/wsc.py 10.83.1.1; sleep 1; done" \
    > /dev/null 2>&1 &
PIDS="$PIDS $!"
# a 50 MB download every minute, small pages in between
downloads=0 pages=0 dl_bad=0
while [ "$(date +%s)" -lt "$END" ]; do
    if [ $((pages % 30)) -eq 0 ]; then
        n=$(ip netns exec "$NC" curl -s -o /dev/null -w '%{size_download}' --max-time 60 http://10.83.2.1/big)
        downloads=$((downloads + 1))
        [ "$n" = 50000000 ] || dl_bad=$((dl_bad + 1))
    fi
    ip netns exec "$NC" curl -s -o /dev/null --max-time 5 "http://10.83.1.1/p$pages"
    pages=$((pages + 1))
    sleep 2
done
[ "$dl_bad" = 0 ] && ok "$downloads downloads of 50 MB, $pages pages" || bad "$dl_bad of $downloads downloads cut short"

cat > "$WORK/status.py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(b'{"cmd":"ext_status","id":1}\n')
print(s.makefile().readline().strip())
EOF
st=$(python3 "$WORK/status.py" "$WORK/auto.sock")
echo "  $st" | cut -c1-300
echo "$st" | grep -q '"counters":true' && ok "the conntrack's counters were read" || bad "no counters"
echo "$st" | grep -q '"flows_failed":0,' && ok "no flow failed" || bad "flows failed" "$WORK/auto.jsonl"
grep '"ev":"ext_impaired"' "$WORK/auto.jsonl" > "$WORK/impaired"
[ -s "$WORK/impaired" ] && bad "keys got a class" "$WORK/impaired" || ok "no key got a class"
grep '"ev":"ext_link"' "$WORK/auto.jsonl" > "$WORK/link"
[ -s "$WORK/link" ] && bad "LINK_DEGRADED" "$WORK/link" || ok "the link was never degraded"
n=$(grep -c "rates of a flow" "$WORK/auto.log")
[ "$n" -gt 0 ] && ok "$n rate checks" || bad "no rate checks: THROTTLE was never tried"
echo "$st" | grep -Eq '"capacity":[0-9]{7}' && ok "C is the link's (over 1 MB/s)" || bad "C is too small"


kill "$APID" 2>/dev/null
wait "$APID" 2>/dev/null
APID=
ip netns exec "$NC" sh -c 'iptables-save 2>/dev/null; nft list ruleset 2>/dev/null' | grep -qi geneva &&
    bad "--ext-auto rules left behind" || ok "the rules are gone"

[ $fails -eq 0 ] && echo "auto_synth: all passed" || echo "auto_synth: $fails failed"
[ $fails -eq 0 ]
