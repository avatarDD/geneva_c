#!/bin/sh
# Coverage-guided fuzzing of geneva's readers (docs/EXT_ROADMAP.md, 7.2):
# the targets of src/ext/fuzz.c ("geneva selftest --ext --list") under
# libFuzzer (default) or AFL++, with ASan and UBSan.
#
#   tests/fuzz/run.sh [SECONDS] [TARGET...]
#
# SECONDS per target (default 60); every target when none is named.
# Environment:
#   FUZZER=libfuzzer|afl   the fuzzer (afl: AFL++'s afl-clang-fast and afl-fuzz)
#   CC                     clang (libfuzzer) or afl-clang-fast (afl)
#   WORK=DIR               corpus and crashes (default: a new temporary
#                          directory, kept when something crashed)
#   O=DIR                  the instrumented build (default build-fuzz)
# The corpus starts from the targets' own seeds ("selftest --seeds-out")
# and the samples in tests/data and tests/golden. Exit 1 when a target
# crashed: its input is in WORK/TARGET/ (libFuzzer: crash-*, leak-*,
# timeout-*; AFL++: out/default/crashes/), and
#   O/fuzz-TARGET FILE
# runs it again.
set -eu
T=${1:-60}
[ $# -gt 0 ] && shift
FUZZER=${FUZZER:-libfuzzer}
O=${O:-build-fuzz}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
cd "$root"

case $FUZZER in
libfuzzer)
    CC=${CC:-clang}
    SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
    LIBCFLAGS="-O1 -g -fsanitize=fuzzer-no-link $SAN"
    LINK="-fsanitize=fuzzer $SAN"
    ;;
afl)
    CC=${CC:-afl-clang-fast}
    SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
    LIBCFLAGS="-O1 -g $SAN"
    LINK="-fsanitize=fuzzer $SAN" # AFL++'s own libFuzzer driver
    ;;
*)
    echo "FUZZER is libfuzzer or afl" >&2
    exit 2
    ;;
esac

make -j"$(nproc 2>/dev/null || echo 2)" O="$O" CC="$CC" CFLAGS="$LIBCFLAGS" LDFLAGS="$SAN" "$O/geneva" >/dev/null
targets=${*:-$("$O/geneva" selftest --ext --list | cut -d' ' -f1)}
for t in $targets; do
    "$CC" -std=c11 $LIBCFLAGS -Isrc -DFUZZ_TARGET="\"$t\"" -c tests/fuzz/fuzz_target.c -o "$O/fuzz_target-$t.o"
    "$CC" $LINK "$O/fuzz_target-$t.o" "$O/libgeneva.a" -lpthread -lm -o "$O/fuzz-$t"
done

keep=0
if [ -z "${WORK:-}" ]; then
    WORK=$(mktemp -d)
else
    mkdir -p "$WORK"
    keep=1
fi
WORK=$(cd "$WORK" && pwd) # the targets run inside it
"$O/geneva" selftest --ext --seeds-out "$WORK/seeds" >/dev/null

# the samples of the repository for the targets that read them
extra() {
    case $1 in
    l7 | tls | quic) ls tests/data/ext/*.bin tests/data/zapret2/*.bin 2>/dev/null ;;
    pcap | apply) ls tests/golden/*.pcap 2>/dev/null ;;
    lists) ls tests/data/lists/*.txt 2>/dev/null ;;
    inflate) ls tests/data/lists/*.gz tests/data/lists/*.z 2>/dev/null ;;
    profile) ls tests/golden/profiles.ini 2>/dev/null ;;
    esac
}

failed=""
for t in $targets; do
    d="$WORK/$t"
    mkdir -p "$d/corpus"
    cp "$WORK/seeds/$t"/* "$d/corpus/" 2>/dev/null || true
    for f in $(extra "$t"); do
        cp "$f" "$d/corpus/"
    done
    # the strategy target: one strategy per file, as in the golden corpus
    if [ "$t" = strategy ]; then
        i=0
        grep -v '^#' tests/golden/ok.txt | while IFS= read -r line; do
            [ -n "$line" ] && printf '%s' "$line" >"$d/corpus/ok-$i" && i=$((i + 1))
        done
    fi
    echo "== $t: $T s"
    if [ "$FUZZER" = libfuzzer ]; then
        if ! (cd "$d" && "$root/$O/fuzz-$t" -max_total_time="$T" -max_len=65536 -timeout=10 -rss_limit_mb=2048 \
            -print_final_stats=1 corpus >"$d/log.txt" 2>&1); then
            tail -40 "$d/log.txt"
            failed="$failed $t"
            continue
        fi
        grep -E "^stat::(number_of_executed_units|new_units_added)" "$d/log.txt" | tr '\n' ' '
        echo
    else
        AFL_SKIP_CPUFREQ=1 AFL_NO_UI=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
            afl-fuzz -V "$T" -i "$d/corpus" -o "$d/out" -- "$root/$O/fuzz-$t" >"$d/log.txt" 2>&1 || true
        if [ -n "$(ls "$d/out/default/crashes" 2>/dev/null | grep -v README)" ]; then
            failed="$failed $t"
        fi
    fi
done

if [ -n "$failed" ]; then
    echo "crashed:$failed (inputs in $WORK)" >&2
    exit 1
fi
[ "$keep" = 1 ] || rm -rf "$WORK"
echo "all targets ok"
