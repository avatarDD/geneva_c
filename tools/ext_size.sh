#!/bin/sh
# Size budget of the --ext extensions (docs/EXT_ROADMAP.md, 6.1): builds the
# router binary with and without src/ext/ and fails when the stripped
# difference is above LIMIT bytes. There is no fixed cap: the limit only
# catches unexpected growth and is raised as each stage lands.
#   tools/ext_size.sh LIMIT [make variables...]
#   tools/ext_size.sh 2048 CC=musl-gcc
#   STRIP=llvm-strip tools/ext_size.sh 2048 CC="zig cc -target mipsel-linux-musleabi"
# (a cross build needs a strip that knows the target: STRIP=...)
set -eu
limit=$1
shift
out=${TMPDIR:-/tmp}/geneva-size.$$
trap 'rm -rf "$out"' EXIT INT TERM
make -s -j"$(nproc 2>/dev/null || echo 2)" STATIC=1 SMALL=1 O="$out/ext" EXT=1 "$@" >/dev/null
make -s -j"$(nproc 2>/dev/null || echo 2)" STATIC=1 SMALL=1 O="$out/noext" EXT=0 "$@" >/dev/null
strip=${STRIP:-strip}
"$strip" -o "$out/a" "$out/ext/geneva" && "$strip" -o "$out/b" "$out/noext/geneva"
a=$(wc -c < "$out/a")
b=$(wc -c < "$out/b")
d=$((a - b))
echo "ext size: $a bytes with --ext, $b without, +$d (limit $limit)"
[ "$d" -le "$limit" ] || { echo "ext size: over the budget" >&2; exit 1; }
