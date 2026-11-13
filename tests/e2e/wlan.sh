#!/bin/sh
# --filter-ssid on a real Wi-Fi link (stage X13c of docs/EXT_ROADMAP.md):
# two radios of mac80211_hwsim, an open access point (hostapd) in one
# namespace and a station connected to it (iw) in the other, where geneva
# run --ext reads the SSID over nl80211. The SYN of a profile that takes
# the network gets window 7, counted at the access point. Needs root, the
# module mac80211_hwsim, iw, hostapd, python3, iptables.
#
#   sta ns (geneva) 10.88.0.2 ~~ Wi-Fi "geneva-e2e" ~~ 10.88.0.1 ap ns (HTTP)
#
#   tests/e2e/wlan.sh [path/to/geneva]
set -u
GENEVA=$(readlink -f "${1:-build/geneva}")
NA=gwl_a$$ NS=gwl_s$$
SSID=geneva-e2e
WORK=$(mktemp -d)
fails=0
APP= HAP= ENG=

cleanup() {
    for p in $ENG $APP $HAP; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    for n in "$NA" "$NS"; do ip netns del "$n" 2>/dev/null; done
    rmmod mac80211_hwsim 2>/dev/null
    [ -n "${KEEP:-}" ] && cp -r "$WORK" "$KEEP"
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

ok() { echo "  ok   $1"; }
bad() { fails=$((fails + 1)); echo "  FAIL $1"; [ -n "${2:-}" ] && sed 's/^/       /' "$2" | tail -30; }

before=$(ls /sys/class/ieee80211 2>/dev/null)
modprobe mac80211_hwsim radios=2 || { echo "no mac80211_hwsim"; exit 1; }
sleep 1
phys=
for p in $(ls /sys/class/ieee80211); do
    case " $(echo $before) " in *" $p "*) ;; *) phys="$phys $p" ;; esac
done
set -- $phys
[ $# -eq 2 ] || { echo "expected two new radios, got:$phys"; exit 1; }
PA=$1 PS=$2
dev() { ls "/sys/class/ieee80211/$1/device/net" | head -1; }
DA=$(dev "$PA") DS=$(dev "$PS")
for n in "$NA" "$NS"; do
    ip netns add "$n" || { echo "cannot create namespaces"; exit 1; }
    ip -n "$n" link set lo up
done
iw phy "$PA" set netns name "$NA"
iw phy "$PS" set netns name "$NS"
ip -n "$NA" addr add 10.88.0.1/24 dev "$DA"
ip -n "$NS" addr add 10.88.0.2/24 dev "$DS"
ip -n "$NA" link set "$DA" up
ip -n "$NS" link set "$DS" up

cat > "$WORK/hostapd.conf" <<EOF
interface=$DA
driver=nl80211
ssid=$SSID
hw_mode=g
channel=1
EOF
ip netns exec "$NA" hostapd "$WORK/hostapd.conf" > "$WORK/hostapd.log" 2>&1 &
HAP=$!
connected=0
for _ in $(seq 100); do
    ip netns exec "$NS" iw dev "$DS" connect "$SSID" 2>/dev/null
    sleep 0.3
    if ip netns exec "$NS" iw dev "$DS" link | grep -q "SSID: $SSID"; then connected=1; break; fi
done
[ $connected = 1 ] || { echo "the station did not connect"; cat "$WORK/hostapd.log"; exit 1; }

cat > "$WORK/srv.py" <<'EOF'
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        b = b"over the air\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
EOF
ip netns exec "$NA" python3 "$WORK/srv.py" &
APP=$!
up=0
for _ in $(seq 100); do
    ip netns exec "$NS" python3 -c 'import socket; socket.create_connection(("10.88.0.1", 8080), 1)' 2>/dev/null && { up=1; break; }
    sleep 0.2
done
[ $up = 1 ] || { echo "no traffic over the Wi-Fi link"; exit 1; }

# SYNs with window 7 that reach the access point
ip netns exec "$NA" iptables -t raw -A PREROUTING -p tcp --dport 8080 --syn -m u32 --u32 "0>>22&0x3C@12&0xFFFF=7"
win7() { ip netns exec "$NA" iptables -t raw -nvxL PREROUTING | awk 'NR == 3 { print $1 }'; }
fetch() {
    ip netns exec "$NS" python3 -c 'import urllib.request; print(urllib.request.urlopen("http://10.88.0.1:8080/", timeout=5).read().decode(), end="")' 2>/dev/null
}

# case NAME EXPECT_WIN7 profile-options...: a fetch through the profiles
case_() {
    name=$1 want=$2
    shift 2
    ip netns exec "$NA" iptables -t raw -Z PREROUTING
    ip netns exec "$NS" "$GENEVA" run --ext -p 8080 --log-level info "$@" > "$WORK/eng.log" 2>&1 &
    ENG=$!
    for _ in $(seq 50); do grep -q "ready\|listening\|applied" "$WORK/eng.log" 2>/dev/null && break; sleep 0.1; done
    sleep 0.5
    got=$(fetch)
    kill "$ENG" 2>/dev/null; wait "$ENG" 2>/dev/null; ENG=
    [ "$got" = "over the air" ] && ok "$name: the page loads" || bad "$name: the page does not load" "$WORK/eng.log"
    n=$(win7)
    if [ "$want" = 1 ] && [ "${n:-0}" -ge 1 ]; then ok "$name: SYN with window 7 at the access point"
    elif [ "$want" = 0 ] && [ "${n:-0}" -eq 0 ]; then ok "$name: no SYN changed"
    else bad "$name: $n SYN(s) with window 7, expected $([ "$want" = 1 ] && echo some || echo none)" "$WORK/eng.log"
    fi
}

T='[TCP:flags:S]-tamper{TCP:window:replace:7}-| \/'
echo "== --filter-ssid over $DS (mac80211_hwsim)"
case_ "the network's profile" 1 --filter-ssid "$SSID" -s "$T" --new -s '\/'
grep -q "wlan: $DS: SSID \"$SSID\"" "$WORK/eng.log" && ok "the log names the network" ||
    bad "the log does not name the network" "$WORK/eng.log"
case_ "another network's profile" 0 --filter-ssid other,cafe -s "$T" --new -s '\/'
case_ "--filter-ssid-neg of another network" 1 --filter-ssid other --filter-ssid-neg -s "$T"
case_ "--filter-ssid-neg of this network" 0 --filter-ssid "$SSID" --filter-ssid-neg -s "$T"
case_ "a template's network" 1 --new=wifi --template --filter-ssid "$SSID" --new --import wifi -s "$T"

echo "wlan e2e: $fails failure(s)"
[ $fails -eq 0 ]
