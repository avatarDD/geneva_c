#!/bin/sh
# /opt/etc/ndm/netfilter.d/010-geneva.sh: Keenetic rebuilds its firewall
# now and then and drops foreign rules; put the rules of geneva back by
# restarting it (it is quick, but connections in flight lose the strategy).
[ "$type" = ip6tables ] && exit 0
[ "$table" = mangle ] || exit 0
/opt/etc/init.d/S51geneva status >/dev/null 2>&1 || exit 0
/opt/etc/init.d/S51geneva restart >/dev/null 2>&1 &
exit 0
