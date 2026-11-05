#!/bin/sh
# Golden snapshots of geneva's output: every command in cases.txt must print
# (stdout, stderr and exit code) exactly what expected.txt holds. They pin the
# behaviour of the build without --ext (docs/EXT_ROADMAP.md, stage X0); in a
# build with --ext the cases tagged "ext" are run again with --ext and must
# match too, because --ext changes nothing for strategies without x-actions.
#
#   tests/golden/run.sh build/geneva            compare
#   tests/golden/run.sh --update build/geneva   rewrite expected.txt
#
# Portable output only: the version string, the OS and the architecture are
# replaced with placeholders, and the "ext*" features are cut from version --json.
set -u
update=0
if [ "${1:-}" = "--update" ]; then
    update=1
    shift
fi
[ $# -eq 1 ] || { echo "usage: $0 [--update] BIN" >&2; exit 2; }
G=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
D=$(cd "$(dirname "$0")" && pwd)
TBASE=$(mktemp -d)
export G D
LC_ALL=C
export LC_ALL

# literal strings for sed: escape the characters a regex would read
lit() { printf '%s\n' "$1" | sed 's/[].[*^$\\|]/\\&/g'; }
ver=$(lit "$("$G" version | awk '{print $2}')")
osarch=$(lit "$("$G" version | sed -n 's/.*(\(.*\)).*/\1/p')")
has_ext=0
"$G" version --json | grep -q '"ext"' && has_ext=1

# one case: header, command, its output and exit code, version normalized
run_case() { # name shown-command [command to run, default the shown one]
    printf '### %s\n$ %s\n' "$1" "$2"
    # a fresh $T per run: no case sees the files of another
    out=$(T=$(mktemp -d "$TBASE/case.XXXXXX") && export T && cd "$D" && sh -c "${3:-$2}" 2>&1; echo "[exit $?]")
    printf '%s\n' "$out" | sed -e "s|$ver|VERSION|g" -e "s|$osarch|OS/ARCH|g" \
        -e 's|"os":"[^"]*","arch":"[^"]*"|"os":"OS","arch":"ARCH"|' -e '/^{"version"/s/,"ext\(_[a-z0-9_]*\)\{0,1\}"//g'
}

# "check --nosuch" -> "check --ext --nosuch": --ext right after the subcommand
with_ext() {
    printf '%s\n' "$1" | sed 's/\$G \([a-z][a-z]*\)/$G \1 --ext/'
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp" "$TBASE"' EXIT INT TERM
fail=0
grep -v '^#' "$D/cases.txt" | grep -v '^$' > "$tmp/cases"
while IFS='|' read -r name tags cmd; do
    run_case "$name" "$cmd" > "$tmp/plain"
    cat "$tmp/plain" >> "$tmp/actual"
    if [ $has_ext = 1 ] && [ "$tags" = ext ]; then
        run_case "$name" "$cmd" "$(with_ext "$cmd")" > "$tmp/ext"
        if ! cmp -s "$tmp/plain" "$tmp/ext"; then
            echo "golden: $name differs with --ext:" >&2
            diff -u "$tmp/plain" "$tmp/ext" >&2
            fail=1
        fi
    fi
done < "$tmp/cases"

if [ $update = 1 ]; then
    cp "$tmp/actual" "$D/expected.txt"
    echo "golden: wrote $D/expected.txt ($(grep -c '^### ' "$D/expected.txt") cases)"
    exit $fail
fi
if ! diff -u "$D/expected.txt" "$tmp/actual"; then
    echo "golden: output differs from tests/golden/expected.txt" >&2
    fail=1
fi
[ $fail = 0 ] && echo "golden: $(grep -c '^### ' "$tmp/actual") cases ok (ext: $has_ext)"
exit $fail
