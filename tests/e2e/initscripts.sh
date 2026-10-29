#!/bin/sh
# Checks the service scripts of packaging/: the Entware S-script for real in
# a network namespace (start, status, reload of the strategy, agent, stop
# that removes the rules), and the OpenWrt procd script against stubs of
# rc.common that print the command line procd would run. Needs root,
# iproute2, and nft or iptables. Usage:
#   tests/e2e/initscripts.sh [path/to/geneva]
set -u
GENEVA=$(readlink -f "${1:-build/geneva}")
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NS=gnc_init$$
WORK=$(mktemp -d)
fails=0
ok() { echo "  ok   $1"; }
bad() { fails=$((fails + 1)); echo "  FAIL $1"; [ -n "${2:-}" ] && sed 's/^/       /' "$2" | tail -20; }
cleanup() {
    ip netns exec "$NS" env GENEVA="$GENEVA" GENEVA_CONF="$WORK/geneva.conf" GENEVA_RUN_DIR="$WORK/run" \
        sh "$ROOT/packaging/entware/S51geneva" stop >/dev/null 2>&1
    ip netns del "$NS" 2>/dev/null
    [ -n "${KEEP:-}" ] && cp -r "$WORK" "$KEEP"
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

echo "== Entware: S51geneva"
ip netns add "$NS" || { echo "cannot create a namespace"; exit 1; }
ip -n "$NS" link set lo up
echo '[TCP:flags:PA]-fragment{tcp:8:False}-| \/' > "$WORK/strategy.txt"
cat > "$WORK/geneva.conf" <<CONF
ENABLED=yes
STRATEGY_FILE=$WORK/strategy.txt
PORTS=80,443
LOG_FILE=$WORK/geneva.log
CONTROL=unix:$WORK/geneva.sock
EXTRA="--stats-interval 60"
AGENT_ENABLED=yes
AGENT_LISTEN=tcp:127.0.0.1:7199
AGENT_TOKEN=init-secret
AGENT_LOG_FILE=$WORK/agent.log
CONF
S() {
    ip netns exec "$NS" env GENEVA="$GENEVA" GENEVA_CONF="$WORK/geneva.conf" GENEVA_RUN_DIR="$WORK/run" \
        sh "$ROOT/packaging/entware/S51geneva" "$@"
}
rules() { ip netns exec "$NS" sh -c 'iptables-save 2>/dev/null; nft list ruleset 2>/dev/null' | grep -ci geneva; }

S start && ok "start" || bad "start" "$WORK/geneva.log"
S status > "$WORK/status.txt" && grep -q "agent: running" "$WORK/status.txt" && ok "status: run and agent" ||
    bad "status" "$WORK/status.txt"
[ "$(rules)" -gt 0 ] && ok "firewall rules are up" || bad "no firewall rules" "$WORK/geneva.log"
ip netns exec "$NS" "$GENEVA" ctl -c "unix:$WORK/geneva.sock" status > "$WORK/st.json" &&
    grep -q 'fragment{tcp:8:False}' "$WORK/st.json" && ok "control socket: the strategy" || bad "ctl status" "$WORK/st.json"
echo '[TCP:flags:S]-duplicate-| \/' > "$WORK/strategy.txt"
S reload
sleep 0.5
ip netns exec "$NS" "$GENEVA" ctl -c "unix:$WORK/geneva.sock" status > "$WORK/st.json"
grep -q 'flags:S' "$WORK/st.json" && ok "reload re-reads the strategy" || bad "reload" "$WORK/st.json"
S start && [ "$(wc -l < "$WORK/run/geneva.pid")" -eq 1 ] && ok "a second start keeps the running one" || bad "second start"
S stop
S status > /dev/null && bad "still running after stop" || ok "stop"
[ "$(rules)" -eq 0 ] && ok "firewall rules removed" || bad "rules left behind"
: > "$WORK/strategy.txt"
S start 2> "$WORK/err.txt" && bad "started without a strategy" || ok "refuses an empty strategy file"

echo "== OpenWrt: geneva.init with stubs of procd"
cat > "$WORK/stubs.sh" <<'STUBS'
# minimal rc.common and procd helpers: print what procd would run
config_load() { :; }
config_get() { eval "v=\${UCI_$2_$3-}"; [ -z "$v" ] && v=${4-}; eval "$1=\$v"; }
config_get_bool() { config_get "$@"; case "$(eval echo \$$1)" in 1|yes|on|true) eval "$1=1";; *) eval "$1=0";; esac; }
procd_open_instance() { echo "instance $1"; }
procd_set_param() { k=$1; shift; printf '%s' "$k"; for a in "$@"; do printf ' [%s]' "$a"; done; echo; }
procd_append_param() { procd_set_param "+$@"; }
procd_close_instance() { echo end; }
logger() { echo "log: $*"; }
STUBS
runwrt() {
    (. "$WORK/stubs.sh"; eval "$1"; . "$ROOT/packaging/openwrt/geneva.init"; start_service) 2>&1
}
echo 'x' > "$WORK/s.txt"
out=$(runwrt "UCI_main_enabled=1 UCI_main_strategy_file=$WORK/s.txt UCI_main_iface=wan UCI_main_extra='--dir out --first 8' UCI_agent_enabled=1 UCI_agent_token=t")
echo "$out" > "$WORK/wrt.txt"
grep -q "^command \[/usr/bin/geneva\] \[run\] \[-f\] \[$WORK/s.txt\] \[-p\] \[80,443\]" "$WORK/wrt.txt" &&
    ok "run: command line" || bad "run: command line" "$WORK/wrt.txt"
grep -q '^+command \[-i\] \[wan\]' "$WORK/wrt.txt" && grep -q '^+command \[--dir\] \[out\] \[--first\] \[8\]' "$WORK/wrt.txt" &&
    ok "run: interface and extra options" || bad "run: options" "$WORK/wrt.txt"
grep -q '^command \[/usr/bin/geneva\] \[agent\] \[--listen\] \[tcp:0.0.0.0:7110\]' "$WORK/wrt.txt" &&
    grep -q '^env \[GENEVA_AGENT_TOKEN=t\]' "$WORK/wrt.txt" && ok "agent: token in the environment" ||
    bad "agent" "$WORK/wrt.txt"
out=$(runwrt "UCI_main_enabled=1 UCI_main_strategy_file=$WORK/none.txt")
echo "$out" | grep -q "instance" && bad "started without a strategy" || ok "refuses a missing strategy file"
out=$(runwrt "UCI_main_enabled=0 UCI_agent_enabled=1")
echo "$out" | grep -q "instance" && bad "agent started without a token" || ok "agent refuses an empty token"

for f in packaging/openwrt/geneva.init packaging/entware/S51geneva packaging/entware/010-geneva.sh; do
    sh -n "$ROOT/$f" && ok "syntax: $f" || bad "syntax: $f"
done

if [ $fails -eq 0 ]; then echo "all passed"; else echo "$fails failure(s)"; fi
exit $fails
