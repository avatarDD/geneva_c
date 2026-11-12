#!/bin/sh
# geneva blockcheck's grid (X12b) against zapret2's own blockcheck2.d/standard:
# the scripts of the release run with a stub of pktws_curl_test_update that
# prints its nfqws2 options and says "works" for the lines of an oracle; the
# lines and their order must be those of geneva blockcheck --print-grid with
# the same oracle, at every scan level, IPv4 and IPv6. Needs NFQWS2_DIR (an
# unpacked official zapret2 release) and sh; no root.
#   NFQWS2_DIR=/opt/zapret2/zapret2-v1.0.6 tests/e2e/blockcheck_grid.sh build/geneva
set -u
G=${1:-build/geneva}
[ -n "${NFQWS2_DIR:-}" ] || { echo "blockcheck_grid.sh: NFQWS2_DIR is not set" >&2; exit 2; }
[ -d "$NFQWS2_DIR/blockcheck2.d/standard" ] || { echo "blockcheck_grid.sh: no $NFQWS2_DIR/blockcheck2.d" >&2; exit 2; }
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fail=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }

# blockcheck2.sh's main loop for one IP version: the scripts of each test
# in one shell, so that the need_ variables carry over as they do there
sim() { # LEVEL IPV "TESTS" ORACLE
    (
        set +u
        . "$NFQWS2_DIR/common/base.sh"
        SCANLEVEL=$1
        IPV=$2
        IPVV=
        [ "$IPV" = 6 ] && IPVV=6
        UNAME=Linux
        TESTDIR=$NFQWS2_DIR/blockcheck2.d/standard
        NL='
'
        ORACLE="$NL$(cat "$4")$NL"
        pktws_curl_test_update() {
            shift 2
            set -f
            set -- $*
            set +f
            printf '%s\n' "$*"
            case $ORACLE in
            *"$NL$*$NL"*) strategy="${strategy:-$*}"; return 0 ;;
            esac
            return 1
        }
        for t in $3; do
            case $t in
            http) f=pktws_check_http ;;
            tls12) f=pktws_check_https_tls12 ;;
            tls13) f=pktws_check_https_tls13 ;;
            http3) f=pktws_check_http3 ;;
            esac
            for script in "$TESTDIR"/*.sh; do
                unset -f $f
                . "$script"
                existf $f && $f curl_test example.com
            done
        done
    )
}

check() { # LEVEL IPV ORACLE NAME
    sim "$1" "$2" "http tls12 tls13 http3" "$3" > "$W/z"
    "$G" blockcheck --ext --print-grid --level "$1" --ipv "$2" --test http,tls12,tls13,http3 --grid-ok "$3" |
        cut -f1 > "$W/g"
    if cmp -s "$W/z" "$W/g"; then
        ok "$1 ipv$2 $4: $(wc -l < "$W/g") lines"
    else
        bad "$1 ipv$2 $4: $(wc -l < "$W/z") lines of zapret2, $(wc -l < "$W/g") of geneva"
        diff "$W/z" "$W/g" | head -6
    fi
}

echo "== the grid of blockcheck2.d/standard"
: > "$W/none"
for level in veryquick quick standard force; do
    for ipv in 4 6; do
        check $level $ipv "$W/none" "all fail"
        # some lines work: the scripts' shortcuts (need_, breaks, the wssize pass)
        for step in 7 61 397; do
            sim $level $ipv "http tls12 tls13 http3" "$W/none" | awk -v s=$step 'NR % s == 0' | grep -v luaexec > "$W/some"
            check $level $ipv "$W/some" "every ${step}th works"
        done
    done
done

echo "== every line has a geneva strategy, except zapret2's Lua code"
"$G" blockcheck --ext --print-grid --level force --ipv 6 --test http,tls12,tls13,http3 > "$W/g"
n=$(awk -F '\t' '$2 == "-" && $1 !~ /luaexec/' "$W/g" | wc -l)
[ "$n" = 0 ] && ok "$(wc -l < "$W/g") lines translated" || {
    bad "$n lines without a strategy"
    awk -F '\t' '$2 == "-" && $1 !~ /luaexec/' "$W/g" | head -3
}

[ $fail = 0 ] || { echo "$fail failure(s)"; exit 1; }
echo "blockcheck grid: all ok"
