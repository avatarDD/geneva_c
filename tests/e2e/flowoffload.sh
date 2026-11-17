#!/bin/sh
# --ext-flowoffload on a real kernel (docs/EXT.md, X7b; zapret2 1.0.7's
# resolve_hw_offload): in a namespace with a bridge of two veth ports, a
# VLAN over a third and a plain WAN veth,
#   - software: one flowtable over the WAN and the bridge;
#   - hardware: the flowtable is made without devices and flags offload,
#     then the bridge is resolved to its ports and the VLAN to its lower
#     device, each added on its own (veth cannot offload: every add fails,
#     the rules still go up, the log names the resolved ports);
#   - fw print resolves the same way;
#   - fw down removes the table with its flowtable.
# Needs root, iproute2 and nft with flowtable support (else SKIP).
#
#   tests/e2e/flowoffload.sh [path/to/geneva]
set -u
GENEVA=$(readlink -f "${1:-build/geneva}")
NN=gfo$$
Q=377
WORK=$(mktemp -d)
fails=0

cleanup() {
    ip netns del "$NN" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

ok() { echo "  ok   $1"; }
bad() { fails=$((fails + 1)); echo "  FAIL $1"; [ -n "${2:-}" ] && sed 's/^/       /' "$2" | tail -30; }
inns() { ip netns exec "$NN" "$@"; }

ip netns add "$NN" || { echo "cannot create a namespace"; exit 1; }
ip -n "$NN" link set lo up
ip -n "$NN" link add wan0 type veth peer name wan1
ip -n "$NN" link add br-lan type bridge
for i in 1 2 3; do
    ip -n "$NN" link add lan$i type veth peer name peer$i
done
ip -n "$NN" link set lan1 master br-lan
ip -n "$NN" link set lan2 master br-lan
ip -n "$NN" link add link lan3 name vl5 type vlan id 5 2>/dev/null || {
    echo "SKIP: no VLAN support"
    exit 0
}
for d in wan0 wan1 br-lan lan1 lan2 lan3 peer1 peer2 peer3 vl5; do
    ip -n "$NN" link set "$d" up
done

# a flowtable at all?
if ! printf 'table inet gfo_probe {\n\tflowtable ft {\n\t\thook ingress priority 0; devices = { "wan0" };\n\t}\n}\n' |
    inns nft -f - 2>"$WORK/probe.err"; then
    echo "SKIP: nft flowtables do not work here: $(cat "$WORK/probe.err")"
    exit 0
fi
inns nft delete table inet gfo_probe

OPTS="--ext -p 443 -q $Q --firewall nft --iface wan0 --ext-lan br-lan,vl5"
table() { inns nft list table inet geneva_$Q 2>&1; }

echo "== software"
inns "$GENEVA" fw up $OPTS --ext-flowoffload software >"$WORK/sw.log" 2>&1 || bad "software: fw up" "$WORK/sw.log"
table >"$WORK/sw.nft"
if grep -q 'flowtable ft' "$WORK/sw.nft" && grep -q '"wan0"\|wan0' "$WORK/sw.nft" &&
    grep -q 'br-lan' "$WORK/sw.nft" && ! grep -q 'flags offload' "$WORK/sw.nft"; then
    ok "software: one flowtable over wan0, br-lan, vl5"
else
    bad "software: flowtable" "$WORK/sw.nft"
fi
inns "$GENEVA" fw down $OPTS --ext-flowoffload software >/dev/null 2>&1
table >/dev/null 2>&1 && bad "software: the table stays after fw down" || ok "software: fw down removes the table"

echo "== hardware"
inns "$GENEVA" fw up $OPTS --ext-flowoffload hardware -l debug >"$WORK/hw.log" 2>&1
rc=$?
table >"$WORK/hw.nft"
if [ $rc -eq 0 ] && grep -q 'flags offload' "$WORK/hw.nft" && grep -q 'flow add @ft' "$WORK/hw.nft"; then
    ok "hardware: the rules are up, the flowtable has flags offload"
else
    bad "hardware: fw up ($rc)" "$WORK/hw.log"
    cat "$WORK/hw.nft"
fi
# the bridge became its ports, the VLAN its lower device, each tried alone
for d in "lan1 (br-lan)" "lan2 (br-lan)" "lan3 (vl5)" "wan0 (wan0)"; do
    if grep -qF "flowtable: $d" "$WORK/hw.log"; then
        ok "hardware: tried $d"
    else
        bad "hardware: $d not tried" "$WORK/hw.log"
    fi
done
# veth cannot offload: the bridge itself is the fallback, the warning says so
if grep -qF "flowtable: br-lan (br-lan)" "$WORK/hw.log" || grep -qF "flowtable: lan1 (br-lan) offloads" "$WORK/hw.log"; then
    ok "hardware: fallback to the bridge itself when its ports cannot"
else
    bad "hardware: no fallback to br-lan" "$WORK/hw.log"
fi
if grep -q 'flowtable: lan2 (br-lan) offloads' "$WORK/hw.log" || grep -q 'nothing is offloaded\|is not offloaded' "$WORK/hw.log"; then
    ok "hardware: devices that cannot offload are reported, not fatal"
else
    bad "hardware: no report of the devices" "$WORK/hw.log"
fi

echo "== print"
inns "$GENEVA" fw print $OPTS --ext-flowoffload hardware >"$WORK/print.txt" 2>&1
if grep -q "devices = { \"lan1\" }; }' 2>/dev/null && b=1" "$WORK/print.txt" &&
    grep -q "devices = { \"lan3\" }; }' 2>/dev/null && b=1" "$WORK/print.txt" &&
    grep -q "\[ -n \"\$b\" \] || nft 'add flowtable inet geneva_$Q ft { hook ingress priority 0; flags offload; devices = { \"br-lan\" }; }'" "$WORK/print.txt"; then
    ok "print: the bridge and the VLAN resolved, the fallbacks printed"
else
    bad "print" "$WORK/print.txt"
fi

inns "$GENEVA" fw down $OPTS --ext-flowoffload hardware >/dev/null 2>&1
table >/dev/null 2>&1 && bad "hardware: the table stays after fw down" || ok "hardware: fw down removes the table"

if [ $fails -eq 0 ]; then
    echo "flowoffload: all ok"
    exit 0
fi
echo "flowoffload: $fails failure(s)"
exit 1
