#!/bin/sh
# Geneva on pfSense (FreeBSD): "geneva run" through divert sockets and ipfw
# next to pfSense's pf, as zapret2's init.d/pfsense does. Put it into
# /usr/local/etc/rc.d/ (chmod 755: pfSense runs *.sh there at boot) and the
# binary into /usr/local/bin/geneva; settings in /usr/local/etc/geneva/geneva.conf.
#   geneva.sh start|stop|restart|reload|status
# geneva adds its own ipfw rule (comment "geneva PORT") and removes it on
# stop; reload re-reads the strategy file.

GENEVA=${GENEVA:-/usr/local/bin/geneva}
CONF=${GENEVA_CONF:-/usr/local/etc/geneva/geneva.conf}
PIDFILE=${GENEVA_PIDFILE:-/var/run/geneva.pid}

STRATEGY_FILE=/usr/local/etc/geneva/strategy.txt
PORTS=80,443
PROTO=tcp
# the divert port (geneva's -q)
QUEUE=310
CONTROL=unix:/var/run/geneva.sock
CONTROL_TOKEN=
LOG_LEVEL=info
LOG_FILE=/var/log/geneva.log
EVENTS=
EXTRA=
# shellcheck disable=SC1090
[ -r "$CONF" ] && . "$CONF"

alive() {
	[ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

prepare() {
	kldload -n ipfw ipdivert
	# older pfSense: ipfw before pf in pfil; newer ones lack these sysctls
	for d in net.inet.ip.pfil net.inet6.ip6.pfil; do
		sysctl -q "$d.outbound=ipfw,pf" "$d.inbound=ipfw,pf" >/dev/null 2>&1
	done
	# pfSense 2.6+: re-enabling pf puts ipfw back to work
	pfctl -d >/dev/null 2>&1
	pfctl -e >/dev/null 2>&1
}

do_start() {
	alive && return 0
	if ! grep -q '[^[:space:]]' "$STRATEGY_FILE" 2>/dev/null; then
		echo "geneva: no strategy in $STRATEGY_FILE" >&2
		return 1
	fi
	prepare
	set -- run -f "$STRATEGY_FILE" -p "$PORTS" --proto "$PROTO" -q "$QUEUE" --firewall ipfw \
		-l "$LOG_LEVEL" --log-file "$LOG_FILE" --quiet
	[ -n "$CONTROL" ] && set -- "$@" -c "$CONTROL"
	[ -n "$EVENTS" ] && set -- "$@" -e "$EVENTS"
	# shellcheck disable=SC2086 # EXTRA holds several options
	[ -n "$EXTRA" ] && set -- "$@" $EXTRA
	GENEVA_CONTROL_TOKEN=$CONTROL_TOKEN "$GENEVA" "$@" </dev/null >/dev/null 2>&1 &
	echo $! > "$PIDFILE"
	sleep 1
	if ! alive; then
		echo "geneva: failed to start, see $LOG_FILE" >&2
		rm -f "$PIDFILE"
		return 1
	fi
}

# SIGTERM, then up to 15 s for the rule to go
do_stop() {
	alive || { rm -f "$PIDFILE"; return 0; }
	pid=$(cat "$PIDFILE")
	kill "$pid" 2>/dev/null
	i=0
	while kill -0 "$pid" 2>/dev/null && [ $i -lt 15 ]; do
		sleep 1
		i=$((i + 1))
	done
	if kill -0 "$pid" 2>/dev/null; then
		kill -9 "$pid" 2>/dev/null
		# a divert rule without its listener drops the packets: remove it
		"$GENEVA" fw down -p "$PORTS" --proto "$PROTO" -q "$QUEUE" --firewall ipfw >/dev/null 2>&1
	fi
	rm -f "$PIDFILE"
}

case "$1" in
start) do_start ;;
stop) do_stop ;;
restart)
	do_stop
	do_start
	;;
reload) alive && kill -HUP "$(cat "$PIDFILE")" ;;
status)
	if alive; then
		echo "geneva: running ($(cat "$PIDFILE"))"
	else
		echo "geneva: stopped"
		exit 3
	fi
	;;
*)
	echo "Usage: $0 start|stop|restart|reload|status" >&2
	exit 2
	;;
esac
