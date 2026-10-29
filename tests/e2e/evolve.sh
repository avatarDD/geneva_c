#!/bin/sh
# End-to-end test of the evaluator: "geneva evolve" against a censor in a
# network namespace must find a strategy that gets through (needs root,
# iproute2, iptables with the string match, python3).
#
#   client ns (geneva) 10.79.0.1 ---veth--- 10.79.0.2 server ns (HTTP server + censor)
#
# The censor answers every packet that carries the forbidden word with a
# reset, like a stateless keyword filter. Splitting the request inside the
# word gets through. The path is padded so that the word sits in the middle
# of the request (bytes 95-103 of 198): Geneva's fragment{tcp:-1:...} splits
# in half, so the search does not have to hit an exact offset. Usage:
#   tests/e2e/evolve.sh [path/to/geneva]
set -u
GENEVA=$(readlink -f "${1:-build/geneva}")
NC=gne_c$$ NS=gne_s$$
WORK=$(mktemp -d)
WORD=ultrasurf
fails=0

cleanup() {
    [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null
    ip netns del "$NC" 2>/dev/null
    ip netns del "$NS" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

ip netns add "$NC" && ip netns add "$NS" || { echo "cannot create namespaces"; exit 1; }
ip link add veth_c netns "$NC" type veth peer name veth_s netns "$NS"
ip -n "$NC" addr add 10.79.0.1/24 dev veth_c
ip -n "$NS" addr add 10.79.0.2/24 dev veth_s
for n in "$NC" "$NS"; do ip -n "$n" link set lo up; done
ip -n "$NC" link set veth_c up
ip -n "$NS" link set veth_s up
ip netns exec "$NC" ethtool -K veth_c tso off gso off gro off >/dev/null 2>&1
ip netns exec "$NS" ethtool -K veth_s tso off gso off gro off >/dev/null 2>&1

# no index.html: "/" is a listing, so a strategy that sends its own
# "GET /" (tamper{TCP:load:corrupt} can) does not count as success
mkdir "$WORK/www"
echo "the page behind the censor" > "$WORK/www/secret.html"
ip netns exec "$NS" python3 -m http.server 80 --bind 10.79.0.2 -d "$WORK/www" >/dev/null 2>&1 &
SRV=$!
sleep 1
ip netns exec "$NS" iptables -A INPUT -p tcp --dport 80 -m string --string "$WORD" --algo bm \
    -j REJECT --reject-with tcp-reset || { echo "no iptables string match"; exit 1; }

ok() { echo "  ok   $1"; }
bad() { fails=$((fails + 1)); echo "  FAIL $1"; [ -n "${2:-}" ] && sed 's/^/       /' "$2" | tail -40; }

PAD=$(printf "%071d" 0 | tr 0 a)
PROBE="--probe http --host censored.example --ip 10.79.0.2 --path /secret.html?pad=$PAD --valid-contains behind --timeout 1"

echo "== baseline"
ip netns exec "$NC" "$GENEVA" eval $PROBE --quiet > "$WORK/plain.txt"
[ $? -eq 0 ] && ok "the page loads without the word" || bad "the page does not load" "$WORK/plain.txt"
ip netns exec "$NC" "$GENEVA" eval $PROBE --bad-word $WORD --quiet > "$WORK/base.txt"
[ $? -eq 1 ] && ok "the word is censored" || bad "the word is not censored" "$WORK/base.txt"

echo "== geneva eval with strategies"
ip netns exec "$NC" "$GENEVA" eval $PROBE --bad-word $WORD --log-file "$WORK/eval.log" --quiet \
    -s '[TCP:flags:PA]-fragment{tcp:98:True}-| \/' -s '[TCP:flags:S]-duplicate-| \/' > "$WORK/eval.txt"
rc=$?
cat "$WORK/eval.txt"
[ $rc -eq 0 ] && ok "eval exit code 0" || bad "eval exit code $rc" "$WORK/eval.log"
awk -F'\t' '/fragment/ { exit !($1 > 0) }' "$WORK/eval.txt" && ok "segmentation gets through" ||
    bad "segmentation does not get through" "$WORK/eval.log"
awk -F'\t' '/duplicate/ { exit !($1 < 0) }' "$WORK/eval.txt" && ok "a SYN duplicate does not" ||
    bad "a SYN duplicate got through" "$WORK/eval.log"
ip netns exec "$NC" iptables-save 2>/dev/null | grep -q GENEVA && bad "rules left behind" || ok "rules removed"

echo "== geneva evolve"
ip netns exec "$NC" "$GENEVA" evolve $PROBE --bad-word $WORD --population 40 --generations 12 \
    --workers 8 --runs 2 --fitness-by min --rng-seed 7 --events "$WORK/ev.jsonl" --log-file "$WORK/evolve.log" --quiet \
    --db "$WORK/db.jsonl" --checkpoint "$WORK/search.ckpt" > "$WORK/best.txt"
rc=$?
cat "$WORK/best.txt"
[ $rc -eq 0 ] && ok "evolve exit code 0" || bad "evolve exit code $rc" "$WORK/evolve.log"
grep -q '"ev":"baseline","blocked":true' "$WORK/ev.jsonl" 2>/dev/null ||
    grep '"ev":"baseline"' "$WORK/ev.jsonl" | grep -q '"blocked":true' && ok "baseline: blocked" ||
    bad "no blocked baseline" "$WORK/ev.jsonl"
BEST=$(head -1 "$WORK/best.txt" | cut -f3)
FIT=$(head -1 "$WORK/best.txt" | cut -f1)
awk -v f="$FIT" 'BEGIN { exit !(f > 0) }' && ok "found: $BEST (fitness $FIT)" ||
    bad "no working strategy found" "$WORK/evolve.log"
# Two runs during the search can be lucky for a strategy that depends on
# timing (a corrupted segment and the kernel's retransmission), so the
# recheck accepts any of the top five that holds 3 of 3.
if [ -n "$BEST" ]; then
    : > "$WORK/check.txt"
    held=
    awk -F'\t' '$1 > 0 { print $3 }' "$WORK/best.txt" | head -5 > "$WORK/top.txt"
    while IFS= read -r s; do
        if ip netns exec "$NC" "$GENEVA" eval $PROBE --bad-word $WORD --runs 3 --fitness-by min --quiet -s "$s" \
            >> "$WORK/check.txt"; then held=$s; break; fi
    done < "$WORK/top.txt"
    [ -n "$held" ] && ok "a found strategy works again (3 of 3): $held" ||
        bad "none of the found strategies holds" "$WORK/check.txt"
fi
grep -q '"ev":"eval"' "$WORK/ev.jsonl" && ok "eval events" || bad "no eval events"
[ -s "$WORK/db.jsonl" ] && ok "database written" || bad "no database"
ip netns exec "$NC" iptables-save 2>/dev/null | grep -q GENEVA && bad "rules left behind" || ok "rules removed"

echo "== evolve on an unblocked target"
ip netns exec "$NC" "$GENEVA" evolve $PROBE --population 4 --generations 1 --quiet
rc=$?
[ $rc -eq 7 ] && ok "exit code 7 (not blocked)" || bad "exit code $rc, expected 7"

if [ $fails -eq 0 ]; then echo "all passed"; else echo "$fails failure(s)"; fi
exit $fails
