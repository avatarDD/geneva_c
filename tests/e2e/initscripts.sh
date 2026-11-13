#!/bin/sh
# Checks the service scripts of packaging/: the Entware S-script and the
# SysV script for real in a network namespace (start, status, reload of the
# strategy, agent, stop that removes the rules), the runit and s6 service
# directories under the real runsv and s6-supervise (skipped when missing,
# a failure with NEED_SUPERVISORS=1; RUNIT_BIN and S6_BIN may name their
# directories), the OpenRC script with stubs of
# openrc-run and its command run for real, and the OpenWrt procd script
# against stubs of rc.common that print the command line procd would run.
# Needs root, iproute2, and nft or iptables. Usage:
#   tests/e2e/initscripts.sh [path/to/geneva]
set -u
GENEVA=$(readlink -f "${1:-build/geneva}")
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NS=gnc_init$$
WORK=$(mktemp -d)
fails=0
ok() { echo "  ok   $1"; }
bad() { fails=$((fails + 1)); echo "  FAIL $1"; [ -n "${2:-}" ] && sed 's/^/       /' "$2" | tail -20; }
SUP=
cleanup() {
    ip netns exec "$NS" env GENEVA="$GENEVA" GENEVA_CONF="$WORK/geneva.conf" GENEVA_RUN_DIR="$WORK/run" \
        sh "$ROOT/packaging/entware/S51geneva" stop >/dev/null 2>&1
    ip netns exec "$NS" env GENEVA="$GENEVA" GENEVA_CONF="$WORK/sysv.conf" GENEVA_RUN_DIR="$WORK/run" \
        sh "$ROOT/packaging/sysv/geneva" stop >/dev/null 2>&1
    for p in $SUP; do kill "$p" 2>/dev/null; done
    pkill -f "$WORK/" 2>/dev/null
    sleep 0.5
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

# ctlst SOCK: the strategy of the running instance (empty: none answers)
ctlst() { ip netns exec "$NS" "$GENEVA" ctl -c "unix:$1" status 2>/dev/null; }
# waitfor N CMD...: up to N tenths of a second for CMD to succeed
waitfor() {
    n=$1
    shift
    while [ "$n" -gt 0 ]; do
        "$@" && return 0
        sleep 0.1
        n=$((n - 1))
    done
    return 1
}
norules() { [ "$(rules)" -eq 0 ]; }
has() { ctlst "$1" | grep -q "$2"; }

echo "== SysV: /etc/init.d/geneva"
echo '[TCP:flags:PA]-fragment{tcp:8:False}-| \/' > "$WORK/strategy.txt"
cat > "$WORK/sysv.conf" <<CONF
ENABLED=yes
STRATEGY_FILE=$WORK/strategy.txt
LOG_FILE=$WORK/sysv.log
CONTROL=unix:$WORK/sysv.sock
EXTRA="--stats-interval 60"
CONF
V() {
    ip netns exec "$NS" env GENEVA="$GENEVA" GENEVA_CONF="$WORK/sysv.conf" GENEVA_RUN_DIR="$WORK/run" \
        sh "$ROOT/packaging/sysv/geneva" "$@"
}
V start && ok "sysv: start" || bad "sysv: start" "$WORK/sysv.log"
V status > /dev/null && ok "sysv: status running" || bad "sysv: status"
[ "$(rules)" -gt 0 ] && ok "sysv: firewall rules are up" || bad "sysv: no firewall rules" "$WORK/sysv.log"
has "$WORK/sysv.sock" 'fragment{tcp:8:False}' && ok "sysv: control socket" || bad "sysv: ctl status"
echo '[TCP:flags:S]-duplicate-| \/' > "$WORK/strategy.txt"
V reload
waitfor 20 has "$WORK/sysv.sock" 'flags:S' && ok "sysv: reload re-reads the strategy" || bad "sysv: reload"
V stop
V status > /dev/null; [ $? -eq 3 ] && ok "sysv: stop (status 3)" || bad "sysv: still running"
norules && ok "sysv: firewall rules removed" || bad "sysv: rules left behind"
: > "$WORK/strategy.txt"
V start 2> /dev/null && bad "sysv: started without a strategy" || ok "sysv: refuses an empty strategy file"
sed -i 's/^ENABLED=yes/ENABLED=no/' "$WORK/sysv.conf"
V start > "$WORK/out.txt" && grep -q disabled "$WORK/out.txt" && ok "sysv: ENABLED=no starts nothing" ||
    bad "sysv: ENABLED=no" "$WORK/out.txt"

# svconf DIR SOCK: the conf of a runit or s6 service directory
svconf() {
    cat > "$1/conf" <<CONF
GENEVA=$GENEVA
STRATEGY_FILE=$WORK/strategy.txt
CONTROL=unix:$2
EXTRA="--stats-interval 60 --log-file $1.log"
CONF
}
# supervised NAME DIR SOCK UP HUP DOWN EXIT: a service directory under its
# supervisor (started by the caller), driven with its own commands
supervised() {
    name=$1 dir=$2 sock=$3
    echo '[TCP:flags:PA]-fragment{tcp:8:False}-| \/' > "$WORK/strategy.txt"
    waitfor 100 has "$sock" 'fragment{tcp:8:False}' && ok "$name: running, control socket" ||
        bad "$name: not running" "$dir.log"
    [ "$(rules)" -gt 0 ] && ok "$name: firewall rules are up" || bad "$name: no firewall rules" "$dir.log"
    echo '[TCP:flags:S]-duplicate-| \/' > "$WORK/strategy.txt"
    eval "$5"
    waitfor 20 has "$sock" 'flags:S' && ok "$name: hup re-reads the strategy" || bad "$name: hup" "$dir.log"
    eval "$6"
    waitfor 150 norules && ok "$name: down removes the rules" || bad "$name: rules left behind" "$dir.log"
    has "$sock" . && bad "$name: still answers after down" || ok "$name: down stops geneva"
    : > "$WORK/strategy.txt"
    eval "$4"
    sleep 1.5
    grep -q "no strategy in $WORK/strategy.txt" "$dir.out" && norules && ok "$name: waits for a strategy" ||
        bad "$name: an empty strategy file" "$dir.out"
    eval "$7"
}

RUNSV=$(command -v runsv || ls "${RUNIT_BIN:-/opt/runit/usr/bin}/runsv" 2>/dev/null)
if [ -n "$RUNSV" ]; then
    echo "== runit: packaging/runit/geneva"
    R=$(dirname "$RUNSV")
    mkdir -p "$WORK/sv"
    cp -r "$ROOT/packaging/runit/geneva" "$WORK/sv/"
    rm -rf "$WORK/sv/geneva/log" # svlogd would write to /var/log
    svconf "$WORK/sv/geneva" "$WORK/runit.sock"
    ip netns exec "$NS" "$R/runsv" "$WORK/sv/geneva" > "$WORK/sv/geneva.out" 2>&1 &
    SUP="$SUP $!"
    supervised runit "$WORK/sv/geneva" "$WORK/runit.sock" \
        "$R/sv up $WORK/sv/geneva >/dev/null" "$R/sv hup $WORK/sv/geneva >/dev/null" \
        "$R/sv down $WORK/sv/geneva >/dev/null" "$R/sv exit $WORK/sv/geneva >/dev/null"
else
    [ -n "${NEED_SUPERVISORS:-}" ] && bad "runit: no runsv" || echo "== runit: no runsv, skipped"
fi

S6=$(command -v s6-supervise || ls "${S6_BIN:-/nonexistent}/s6-supervise" 2>/dev/null)
if [ -n "$S6" ]; then
    echo "== s6: packaging/s6/geneva"
    B=$(dirname "$S6")
    mkdir -p "$WORK/s6"
    cp -r "$ROOT/packaging/s6/geneva" "$WORK/s6/"
    svconf "$WORK/s6/geneva" "$WORK/s6.sock"
    ip netns exec "$NS" "$B/s6-supervise" "$WORK/s6/geneva" > "$WORK/s6/geneva.out" 2>&1 &
    SUP="$SUP $!"
    supervised s6 "$WORK/s6/geneva" "$WORK/s6.sock" \
        "$B/s6-svc -u $WORK/s6/geneva" "$B/s6-svc -h $WORK/s6/geneva" \
        "$B/s6-svc -d $WORK/s6/geneva" "$B/s6-svc -dx $WORK/s6/geneva"
else
    [ -n "${NEED_SUPERVISORS:-}" ] && bad "s6: no s6-supervise" || echo "== s6: no s6-supervise, skipped"
fi
cmp -s "$ROOT/packaging/runit/geneva/run" "$ROOT/packaging/s6/geneva/run" && ok "runit and s6: the same run script" ||
    bad "runit and s6 run scripts differ"

echo "== OpenRC: packaging/openrc/geneva with stubs of openrc-run"
cat > "$WORK/openrc-stubs.sh" <<'STUBS'
RC_SVCNAME=geneva
eerror() { echo "eerror: $*"; }
ebegin() { echo "ebegin: $*"; }
eend() { return "$1"; }
checkpath() { :; }
STUBS
echo '[TCP:flags:PA]-fragment{tcp:8:False}-| \/' > "$WORK/strategy.txt"
sed "s|^STRATEGY_FILE=.*|STRATEGY_FILE=$WORK/strategy.txt|; s|^CONTROL=.*|CONTROL=unix:$WORK/openrc.sock|; s|^LOG_FILE=.*|LOG_FILE=$WORK/openrc.log|; s|^EXTRA=.*|EXTRA=\"--stats-interval 60\"|; s|^CONTROL_TOKEN=.*|CONTROL_TOKEN=|; s|^#GENEVA=.*|GENEVA=$GENEVA|" \
    "$ROOT/packaging/openrc/geneva.confd" > "$WORK/confd"
# what start-stop-daemon would start, then that command for real
(. "$WORK/openrc-stubs.sh"; . "$WORK/confd"; . "$ROOT/packaging/openrc/geneva"; start_pre && echo "$command $command_args" &&
    echo "$pidfile $retry $command_background") > "$WORK/openrc.txt" 2>&1
grep -q "^$GENEVA run -f $WORK/strategy.txt -p 80,443 --proto tcp -q 310 --firewall auto -l info --log-file $WORK/openrc.log --quiet -c unix:$WORK/openrc.sock --stats-interval 60\$" "$WORK/openrc.txt" &&
    ok "openrc: command line" || bad "openrc: command line" "$WORK/openrc.txt"
grep -q '^/run/geneva.pid TERM/15/KILL/5 yes$' "$WORK/openrc.txt" && ok "openrc: pidfile, retry, background" ||
    bad "openrc: pidfile, retry, background" "$WORK/openrc.txt"
# shellcheck disable=SC2046
ip netns exec "$NS" $(head -1 "$WORK/openrc.txt") &
OPID=$!
waitfor 100 has "$WORK/openrc.sock" 'fragment{tcp:8:False}' && ok "openrc: the command runs" || bad "openrc: the command" "$WORK/openrc.log"
kill -TERM $OPID
wait $OPID
waitfor 50 norules && ok "openrc: SIGTERM removes the rules" || bad "openrc: rules left behind"
: > "$WORK/strategy.txt"
(. "$WORK/openrc-stubs.sh"; . "$WORK/confd"; . "$ROOT/packaging/openrc/geneva"; start_pre) > "$WORK/openrc.txt" 2>&1 &&
    bad "openrc: start_pre without a strategy" || {
    grep -q "eerror: no strategy in $WORK/strategy.txt" "$WORK/openrc.txt" && ok "openrc: refuses an empty strategy file" ||
        bad "openrc: empty strategy" "$WORK/openrc.txt"
}

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

for f in packaging/openwrt/geneva.init packaging/entware/S51geneva packaging/entware/010-geneva.sh \
    packaging/sysv/geneva packaging/sysv/geneva.default packaging/openrc/geneva packaging/openrc/geneva.confd \
    packaging/runit/geneva/run packaging/runit/geneva/finish packaging/runit/geneva/log/run packaging/runit/geneva/conf \
    packaging/s6/geneva/run packaging/s6/geneva/finish packaging/s6/geneva/conf; do
    sh -n "$ROOT/$f" && ok "syntax: $f" || bad "syntax: $f"
done

if [ $fails -eq 0 ]; then echo "all passed"; else echo "$fails failure(s)"; fi
exit $fails
