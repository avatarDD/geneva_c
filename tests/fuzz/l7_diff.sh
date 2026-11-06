#!/bin/sh
# Differential fuzzing of geneva's L7 code (src/ext/l7.c, markers.c,
# quic.c) against zapret2's own (nfq2/protocol.c): both read the same
# mutated payloads and must print the same line for each.
#
#   tests/fuzz/l7_diff.sh ZAPRET2_DIR [SECONDS] [SEED]
#
# Needs cc, python3 and a built build/libgeneva.a (make; LIB=... for
# another, FCFLAGS=... for its flags, e.g. with ASan:
#   make O=build-asan CFLAGS="-O1 -g -fsanitize=address,undefined"
#   LIB=build-asan/libgeneva.a FCFLAGS="-fsanitize=address,undefined" tests/fuzz/l7_diff.sh ...).
# Stops at the first difference and keeps the input in the work directory.
set -eu
Z=${1:?usage: $0 ZAPRET2_DIR [SECONDS] [SEED]}
T=${2:-60}
SEED=${3:-1}
CC=${CC:-cc}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
W=$(mktemp -d)
mkdir "$W/ref" "$W/in"
cp "$Z"/nfq2/protocol.c "$Z"/nfq2/protocol.h "$Z"/nfq2/helpers.c "$Z"/nfq2/helpers.h "$Z"/nfq2/random.c \
    "$Z"/nfq2/random.h "$W/ref/"
cp -r "$Z"/nfq2/crypto "$W/ref/"
cp "$here/zapret2_params.h" "$W/ref/params.h"
(cd "$W/ref" && for f in *.c crypto/*.c; do $CC -std=gnu99 -O1 -w -I. -c "$f" -o "$(basename "$f" .c).o"; done &&
    $CC -std=gnu99 -O1 -w -I. "$here/zapret2_ref.c" *.o -o ref)
$CC -std=c11 -O1 ${FCFLAGS:-} -DL7_LINE_MAIN -I"$root/src" "$here/l7_line.c" "${LIB:-$root/build/libgeneva.a}" \
    -o "$W/l7line"
end=$(($(date +%s) + T))
round=0
total=0
while [ "$(date +%s)" -lt "$end" ]; do
    rm -f "$W"/in/*
    python3 "$here/l7_mutate.py" "$W/in" 2000 $((SEED * 100000 + round)) "$root"/tests/data/zapret2/*.bin \
        "$root"/tests/data/ext/*.bin
    "$W/ref/ref" "$W"/in/*.bin >"$W/a.txt"
    "$W/l7line" "$W"/in/*.bin >"$W/b.txt"
    if ! cmp -s "$W/a.txt" "$W/b.txt"; then
        diff "$W/a.txt" "$W/b.txt" | head -6
        echo "l7_diff: differs (round $round, inputs in $W/in)" >&2
        exit 1
    fi
    round=$((round + 1))
    total=$((total + 2000))
done
echo "l7_diff: $total inputs, no difference"
rm -rf "$W"
