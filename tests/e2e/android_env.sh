#!/bin/sh
# The static Linux build on Android (stage X13c of docs/EXT_ROADMAP.md, A6):
# a chroot shaped like Android's root (/system/build.prop, /data/local/tmp,
# no /etc/resolv.conf, no /tmp, no /var/run) runs the binary as it is. Needs
# root and a static build (make STATIC=1, e.g. with musl-gcc).
#
#   sudo tests/e2e/android_env.sh build/geneva
set -u
GENEVA=$(readlink -f "${1:-build/geneva}")
R=$(mktemp -d)
fails=0
trap 'umount "$R/proc" 2>/dev/null; rm -rf "$R"' EXIT INT TERM

ok() { echo "  ok   $1"; }
bad() { fails=$((fails + 1)); echo "  FAIL $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/       /' | tail -20; }

file "$GENEVA" | grep -q "statically linked" || { echo "$GENEVA is not a static build"; exit 1; }
mkdir -p "$R/system/bin" "$R/data/local/tmp" "$R/proc" "$R/dev"
printf 'ro.build.version.sdk=34\n' > "$R/system/build.prop"
cp "$GENEVA" "$R/system/bin/geneva"
mount -t proc proc "$R/proc"
: > "$R/dev/null"
run() { chroot "$R" /system/bin/geneva "$@"; }

echo "== geneva on an Android-shaped root"
out=$(run version --json 2>&1)
printf '%s' "$out" | grep -q '"os":"android"' && ok "version --json: os android" || bad "version --json" "$out"
out=$(run eval --host example.com -s '\/' --timeout 1 2>&1)
printf '%s' "$out" | grep -q "Android has no /etc/resolv.conf for this static build: give the address with --ip" &&
    ok "a name without /etc/resolv.conf: the hint" || bad "the resolver hint" "$out"
out=$(run check '[TCP:flags:S]-duplicate-| \/' 2>&1)
[ $? -eq 0 ] && ok "check parses a strategy" || bad "check" "$out"
out=$(run selftest --ext --fuzz 200 --seed 1 2>&1)
[ $? -eq 0 ] && ok "selftest --ext (fuzz targets, fmemopen)" || bad "selftest" "$out"
out=$(run run --ext -s '\/' --filter-tcp 443 -p 443 --dry-run 2>&1)
[ $? -eq 0 ] && ok "run --ext --dry-run" || bad "run --dry-run" "$out"

echo "android env: $fails failure(s)"
[ $fails -eq 0 ]
