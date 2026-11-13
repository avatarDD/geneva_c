#!/bin/sh
# geneva ip2net and resolve (X12a) against zapret2's own ip2net and mdig:
# the same random lists, the same output. Needs NFQWS2_DIR (an unpacked
# official zapret2 release); no root.
#   NFQWS2_DIR=/opt/zapret2/zapret2-v1.0.6 tests/e2e/tools.sh build/geneva [ROUNDS]
set -u
G=${1:-build/geneva}
ROUNDS=${2:-100}
[ -n "${NFQWS2_DIR:-}" ] || { echo "tools.sh: NFQWS2_DIR is not set" >&2; exit 2; }
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
# copies: the release's files may have no x bit
ZB=$W/bin
mkdir "$ZB"
for b in ip2net mdig; do
    cp "$NFQWS2_DIR/binaries/linux-x86_64/$b" "$ZB/" && chmod +x "$ZB/$b" ||
        { echo "tools.sh: no $NFQWS2_DIR/binaries/linux-x86_64/$b" >&2; exit 2; }
done
fail=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }

# a list: addresses near a few bases, some subnets, ranges and junk
gen() { # SEED FAMILY
    awk -v seed="$1" -v fam="$2" 'BEGIN {
        srand(seed); n = 1 + int(rand() * 3000)
        for (i = 0; i < n; i++) {
            r = rand()
            if (fam == 4) {
                b = int(rand() * 4)
                a1 = b == 0 ? 10 : b == 1 ? 192 : b == 2 ? 93 : int(rand() * 256)
                a2 = b == 1 ? 168 : int(rand() * 4); a3 = int(rand() * (b == 3 ? 256 : 8)); a4 = int(rand() * 256)
                s = a1 "." a2 "." a3 "." a4
                if (r < 0.05) s = s "/" int(rand() * 40)
                else if (r < 0.08) s = s "-" s
                else if (r < 0.10) s = " " s " junk"
                else if (r < 0.11) s = "300.1.1.1"
            } else {
                b = int(rand() * 3)
                p = b == 0 ? "2001:db8" : b == 1 ? "2a02:4e8" : sprintf("%x:%x", int(rand() * 65536), int(rand() * 65536))
                s = sprintf("%s:%x:%x::%x", p, int(rand() * 2), int(rand() * 4), int(rand() * 65536))
                if (r < 0.05) s = s "/" int(rand() * 140)
                else if (r < 0.08) s = s "-" s
                else if (r < 0.10) s = s "\r"
                else if (r < 0.11) s = "zz::1"
            }
            print s
        }
    }'
}

echo "== ip2net: $ROUNDS random lists of each family"
i=0
while [ $i -lt "$ROUNDS" ]; do
    i=$((i + 1))
    for fam in 4 6; do
        gen $i $fam > "$W/in"
        case $((i % 5)) in
        0) o= ;;
        1) [ $fam = 4 ] && o=--prefix-length=20-28 || o=--prefix-length=48-64 ;;
        2) o=--v4-threshold=1/2 ;;
        3) o=--v6-threshold=2 ;;
        *) [ $fam = 4 ] && o=--prefix-length=24 || o=--prefix-length=60 ;;
        esac
        # shellcheck disable=SC2086
        "$ZB/ip2net" -$fam $o < "$W/in" > "$W/z"
        # shellcheck disable=SC2086
        "$G" ip2net --ext -$fam $o < "$W/in" > "$W/g"
        cmp -s "$W/z" "$W/g" || { bad "ip2net -$fam $o, list $i"; diff "$W/z" "$W/g" | head -5; }
    done
done
[ $fail = 0 ] && ok "the same subnets"

echo "== resolve: the list's addresses, names, logs"
# no names: they go to the libc's resolver, and the release's static libc
# (musl) and the runner's glibc answer them differently (localhost, with or
# without the dot); names are checked below on geneva's own
printf 'example.invalid\n1.2.3.4\n1.2.3.4/24\n1.2.3.4/32\n1.2.3.4/40\n::1\n::1/64\nbad..name!\n\n' > "$W/names"
for fam in 4 6 46; do
    "$ZB/mdig" --family=$fam --threads=3 --log-failed="$W/zf" --log-resolved="$W/zr" < "$W/names" | sort > "$W/z"
    "$G" resolve --ext --family=$fam --threads=3 --log-failed="$W/gf" --log-resolved="$W/gr" < "$W/names" | sort > "$W/g"
    sort -o "$W/zf" "$W/zf"; sort -o "$W/gf" "$W/gf"; sort -o "$W/zr" "$W/zr"; sort -o "$W/gr" "$W/gr"
    if cmp -s "$W/z" "$W/g" && cmp -s "$W/zf" "$W/gf" && cmp -s "$W/zr" "$W/gr"; then
        ok "--family $fam"
    else
        bad "--family $fam"
        diff "$W/z" "$W/g" | head -5
    fi
done
if printf 'localhost\n' | "$G" resolve --ext --family=4 | grep -qx 127.0.0.1; then
    ok "localhost resolves (the system resolver)"
else
    bad "localhost does not resolve"
fi
for d in example.com a.b. a.b.. x..y; do
    for fam in 4 6; do
        z=$("$ZB/mdig" --dns-make-query="$d" --family=$fam < /dev/null 2> /dev/null | tail -c +3 | od -An -tx1 | tr -d ' \n')
        g=$("$G" resolve --ext --dns-make-query="$d" --family=$fam < /dev/null 2> /dev/null | tail -c +3 | od -An -tx1 | tr -d ' \n')
        [ "$z" = "$g" ] || bad "--dns-make-query $d --family $fam: $z / $g"
    done
done
"$G" resolve --ext --dns-make-query=example.com < /dev/null > "$W/q"
if [ "$("$ZB/mdig" --dns-parse-query < "$W/q" 2>&1)" = "$("$G" resolve --ext --dns-parse-query < "$W/q" 2>&1 | sed 's/^geneva resolve: //')" ]; then
    ok "--dns-make-query, --dns-parse-query"
else
    bad "--dns-parse-query of a query"
fi

[ $fail = 0 ] || { echo "$fail failure(s)"; exit 1; }
echo "tools: all ok"
