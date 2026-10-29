/* Strategy language tests: parsing/printing against Geneva's own strategy
 * corpus, run-time semantics, and action results against scapy goldens. */
#include <stdlib.h>
#include <string.h>

#include "geneva_strategies.h"
#include "golden_pkt.h"
#include "pcap.h"
#include "pkt.h"
#include "rng.h"
#include "strategy.h"
#include "test.h"

static gpkt *golden(const char *name)
{
    uint8_t buf[2048];
    for (size_t i = 0; i < sizeof(golden_pkts) / sizeof(golden_pkts[0]); i++) {
        if (strcmp(golden_pkts[i].name, name) == 0) {
            long n = hex_decode(golden_pkts[i].hex, buf, sizeof(buf));
            return pkt_parse(buf, (size_t)n);
        }
    }
    fprintf(stderr, "no golden %s\n", name);
    return NULL;
}

static size_t golden_bytes(const char *name, uint8_t *buf, size_t cap)
{
    for (size_t i = 0; i < sizeof(golden_pkts) / sizeof(golden_pkts[0]); i++)
        if (strcmp(golden_pkts[i].name, name) == 0)
            return (size_t)hex_decode(golden_pkts[i].hex, buf, cap);
    return 0;
}

static strategy *parse_ok(const char *text)
{
    sbuf err;
    strategy *s;
    sb_init(&err);
    s = strategy_parse(text, &err);
    if (!s)
        fprintf(stderr, "  parse failed: %s: %s\n", text, err.data);
    CHECK(s != NULL);
    sb_free(&err);
    return s;
}

static int parses(const char *text)
{
    sbuf err;
    strategy *s;
    sb_init(&err);
    s = strategy_parse(text, &err);
    if (!s)
        CHECK(err.len > 0); /* every failure explains itself */
    strategy_free(s);
    sb_free(&err);
    return s != NULL;
}

static char *printed(const strategy *s)
{
    sbuf b;
    sb_init(&b);
    strategy_print(s, &b);
    return sb_take(&b);
}

/* What Geneva prints for an already-canonical strategy text: every tree
 * closed by "-|", forests joined with " \/ ", outer whitespace stripped. */
static char *canonical(const char *text)
{
    sbuf out;
    const char *sl = strstr(text, "\\/");
    sb_init(&out);
    for (int d = 0; d < 2; d++) {
        const char *b = d ? (sl ? sl + 2 : "") : text;
        size_t n = d ? strlen(b) : (sl ? (size_t)(sl - text) : strlen(text));
        char *forest = xstrndup(b, n), *save = forest, *tok;
        int first = 1;
        if (d)
            sb_puts(&out, out.len ? " \\/" : "\\/");
        for (tok = strtok(forest, "|"); tok; tok = strtok(NULL, "|")) {
            while (*tok == ' ')
                tok++;
            size_t tl = strlen(tok);
            while (tl && tok[tl - 1] == ' ')
                tok[--tl] = 0;
            if (!tl)
                continue;
            if (d || !first)
                sb_putc(&out, ' ');
            while (tl && tok[tl - 1] == '-') /* "[t]--|" is an empty tree */
                tok[--tl] = 0;
            sb_printf(&out, "%s-|", tok);
            first = 0;
        }
        free(save);
    }
    return sb_take(&out);
}

TEST(test_geneva_corpus)
{
    for (size_t i = 0; i < ARRAY_LEN(geneva_strategies); i++) {
        const char *in = geneva_strategies[i].s;
        sbuf err;
        strategy *s;
        sb_init(&err);
        s = strategy_parse(in, &err);
        if (!geneva_strategies[i].ok) {
            if (s)
                fprintf(stderr, "  accepted, Geneva rejects: %s\n", in);
            CHECK(s == NULL);
        } else if (!s) {
            fprintf(stderr, "  rejected: %s: %s\n", in, err.data);
            CHECK(s != NULL);
        } else {
            char *out = printed(s), *exp = canonical(in), *again;
            strategy *s2 = parse_ok(out);
            CHECK_STR(out, exp);
            again = s2 ? printed(s2) : NULL;
            CHECK_STR(again, out);
            free(out);
            free(exp);
            free(again);
            strategy_free(s2);
        }
        strategy_free(s);
        sb_free(&err);
    }
}

TEST(test_print_exact)
{
    /* Geneva's test_parse.py EDGE_CASES print back unchanged */
    static const char *same[] = {
        "[TCP:flags:A]-| \\/",
        "\\/ [TCP:flags:A]-|",
        "[TCP:flags:A]-duplicate(duplicate(duplicate(duplicate,),),)-| \\/",
        "[IP:version:4]-| \\/",
        "[TCP:flags:A]-duplicate(tamper{TCP:flags:corrupt}(duplicate(duplicate,),),)-| \\/",
        "[TCP:flags:A]-tamper{TCP:flags:replace:S}(duplicate,)-| \\/",
        "[IP:frag:0]-fragment{tcp:-1:False}(drop,tamper{TCP:options-altchksum:replace:})-| \\/",
        "[IP:ihl:0]-fragment{tcp:-1:True}(duplicate,tamper{IP:load:replace:074})-| \\/",
        "[TCP:flags:0]-tamper{TCP:flags:replace:S}(duplicate(,drop),)-| \\/",
        "[TCP:flags:SA:1]-drop-| [UDP:dport:53:-2]-sleep{0.25}-| \\/ [TCP:flags:R]-drop-|",
        "[TCP:load:GET*]-trace{2:10}-| \\/",
        "[UDP:dport:53]-tamper{DNS:qd:compress}-| \\/",
        "[TCP:flags:PA]-fragment{ip:2:True:4}-| \\/",
        "[IPv6:hlim:64]-tamper{IP:ttl:add:-3}-| \\/",
        "\\/",
    };
    static const struct { const char *in, *out; } norm[] = {
        {"", "\\/"},
        {"\"\\/\"", "\\/"},
        {"\"\\/ [TCP:flags:A]-drop-|\"", "\\/ [TCP:flags:A]-drop-|"},
        {"[TCP:flags:0]--|", "[TCP:flags:0]-| \\/"},
        {"[TCP:flags:A]-drop|", "[TCP:flags:A]-drop-| \\/"},
        {"[[TCP:flags:A]]-drop-|", "[TCP:flags:A]-drop-| \\/"},
        /* int() normalizes numbers, except in loads */
        {"[TCP:dport:080]-tamper{TCP:window:replace:+1_000}-|",
         "[TCP:dport:80]-tamper{TCP:window:replace:1000}-| \\/"},
        {"[TCP:flags:PA]-tamper{TCP:load:replace:007}-|", "[TCP:flags:PA]-tamper{TCP:load:replace:007}-| \\/"},
        /* corrupt drops a value; compress always prints DNS:qd */
        {"[TCP:flags:A]-tamper{TCP:seq:corrupt:5}-|", "[TCP:flags:A]-tamper{TCP:seq:corrupt}-| \\/"},
        {"[UDP:dport:53]-tamper{UDP:sport:compress}-|", "[UDP:dport:53]-tamper{DNS:qd:compress}-| \\/"},
        /* fragment and sleep parameter forms */
        {"[TCP:flags:PA]-fragment{tcp:8:true:0}-|", "[TCP:flags:PA]-fragment{tcp:8:False}-| \\/"},
        {"[TCP:flags:PA]-fragment{xx:8:True}-|", "[TCP:flags:PA]-fragment{ip:8:True}-| \\/"},
        {"[TCP:flags:PA]-sleep{1.50}-|", "[TCP:flags:PA]-sleep{1.5}-| \\/"},
        {"[TCP:flags:PA]-sleep-|", "[TCP:flags:PA]-sleep{1}-| \\/"},
        {"[TCP:flags:PA]-trace-|", "[TCP:flags:PA]-trace{1:64}-| \\/"},
        {"[TCP:flags:PA]-DUPLICATE-|", "[TCP:flags:PA]-duplicate-| \\/"},
        /* several "\/": everything after the first is inbound */
        {"[TCP:flags:S]-drop-| \\/ [TCP:flags:R]-drop-| \\/ [TCP:flags:F]-drop-|",
         "[TCP:flags:S]-drop-| \\/ [TCP:flags:R]-drop-| [TCP:flags:F]-drop-|"},
    };
    for (size_t i = 0; i < ARRAY_LEN(same); i++) {
        strategy *s = parse_ok(same[i]);
        char *out = s ? printed(s) : NULL;
        CHECK_STR(out, same[i]);
        free(out);
        strategy_free(s);
    }
    for (size_t i = 0; i < ARRAY_LEN(norm); i++) {
        strategy *s = parse_ok(norm[i].in);
        char *out = s ? printed(s) : NULL;
        CHECK_STR(out, norm[i].out);
        free(out);
        strategy_free(s);
    }
}

TEST(test_parse_errors)
{
    static const char *bad[] = {
        "asdfasdf",
        "[TCP:flags:0]-duplicate{x}-|",
        "[TCP:flags:0]-tamper-|",                       /* Geneva: random tamper */
        "[TCP:flags:0]-tamper{TCP:flags:replace}-|",    /* no value */
        "[TCP:flags:0]-tamper{TCP:flags:frob:1}-|",     /* unknown primitive */
        "[TCP:flags:0]-tamper{TCP:nosuch:replace:1}-|", /* unknown field */
        "[TCP:flags:0]-tamper{XYZ:ttl:replace:1}-|",    /* unknown protocol */
        "[TCP:flags:0]-tamper{IP:ttl:add:x}-|",
        "[TCP:flags:0]-tamper{TCP:flags:replace:XYZ}-|",     /* not TCP flags */
        "[TCP:flags:0]-tamper{IP:flags:replace:QQ}-|",
        "[TCP:flags:0]-tamper{TCP:window:replace:abc}-|",
        "[TCP:flags:0]-tamper{TCP:options-md5header:replace:zz}-|",
        "[TCP:flags:0]-tamper{IP:ttl:replace:1:2}-|",
        "[TCP:flags:0]-tamper{{IP:ttl:replace:1}-|",
        "[TCP:flags:0]-fragment{tcp:x:True}-|",
        "[TCP:flags:0]-fragment{tcp}-|",
        "[TCP:flags:0]-sleep{-1}-|",
        "[TCP:flags:0]-sleep{nan}-|",
        "[TCP:flags:0]-sleep{abc}-|",
        "[TCP:flags:0]-trace{5:1}-|",
        "[TCP:flags:0]-trace{5}-|",
        "[TCP:flags:0:x]-drop-|",
        "[TCP:flags]-drop-|",
        "[TCP:flags:0:1:2]-drop-|",
        "[FOO:flags:0]-drop-|",
        "\\/ [TCP:flags:R]-duplicate-|", /* branching is outbound-only */
        "\\/ [TCP:flags:R]-fragment{tcp:-1:True}-|",
        "\\/ [TCP:flags:R]-trace{1:2}-|",
        "[TCP:flags:A]-drop-| x",
    };
    char deep[8192];
    size_t n = 0;
    for (size_t i = 0; i < ARRAY_LEN(bad); i++) {
        if (parses(bad[i]))
            fprintf(stderr, "  accepted: %s\n", bad[i]);
        CHECK(!parses(bad[i]));
    }
    /* nesting is bounded instead of exhausting the stack */
    n += (size_t)snprintf(deep, sizeof(deep), "[TCP:flags:A]-");
    for (int i = 0; i < 1000 && n + 20 < sizeof(deep); i++)
        n += (size_t)snprintf(deep + n, sizeof(deep) - n, "duplicate(");
    snprintf(deep + n, sizeof(deep) - n, ",)-|");
    CHECK(!parses(deep));
}

TEST(test_fragment_random_order)
{
    /* without parameters Geneva picks the order at random */
    int seen[2] = {0, 0};
    for (int i = 0; i < 64; i++) {
        strategy *s = parse_ok("[TCP:flags:PA]-fragment-|");
        if (!s)
            return;
        seen[s->out[0]->root->in_order]++;
        CHECK_INT(s->out[0]->root->fragsize, -1);
        CHECK(s->out[0]->root->segment);
        strategy_free(s);
    }
    CHECK(seen[0] > 0 && seen[1] > 0);
}

/* Runs base packet through a strategy; compares to goldens (NULL-ended). */
static void check_run(const char *strat, const char *pkt, const char *const *exp)
{
    strategy *s = parse_ok(strat);
    gpkt *p = golden(pkt);
    pktlist out = {0};
    size_t n = 0;
    if (!s || !p) {
        strategy_free(s);
        pkt_free(p);
        return;
    }
    strategy_apply(s, p, DIR_OUT, &out);
    while (exp[n])
        n++;
    if (out.n != n)
        fprintf(stderr, "  %s: %zu packets, expected %zu\n", strat, out.n, n);
    CHECK_INT(out.n, n);
    for (size_t i = 0; i < out.n && i < n; i++) {
        uint8_t e[2048];
        size_t el = golden_bytes(exp[i], e, sizeof(e)), len;
        uint8_t *b = pkt_bytes(out.v[i], &len);
        if (len != el || memcmp(b, e, el))
            fprintf(stderr, "  %s: packet %zu differs from %s\n", strat, i, exp[i]);
        CHECK_MEM(b, len, e, el);
        free(b);
    }
    pktlist_free(&out);
    strategy_free(s);
}

#define L(...) ((const char *const[]){__VA_ARGS__, NULL})

TEST(test_actions_vs_scapy)
{
    check_run("[TCP:flags:PA]-tamper{IP:ttl:replace:10}-|", "base", L("ttl10"));
    check_run("[TCP:flags:PA]-tamper{TCP:flags:replace:FRAPUN}-|", "base", L("flags_frapun"));
    check_run("[TCP:flags:PA]-tamper{TCP:dataofs:replace:10}-|", "base", L("dataofs10"));
    check_run("[TCP:flags:PA]-tamper{TCP:chksum:replace:25776}-|", "base", L("chksum25776"));
    check_run("[TCP:flags:PA]-tamper{IP:flags:replace:MF+DF}-|", "base", L("ipflags_mfdf"));
    check_run("[TCP:flags:PA]-tamper{TCP:options-wscale:replace:200}-|", "base", L("opt_wscale200"));
    check_run("[TCP:flags:PA]-tamper{TCP:options-mss:replace:}-|", "base", L("opt_mss0"));
    check_run("[TCP:flags:PA]-tamper{TCP:load:replace:hello%20world}-|", "base", L("load_hello"));
    check_run("[TCP:flags:PA]-tamper{IP:load:replace:xyz}-|", "base", L("ipload_xyz"));
    check_run("[IP:ttl:54]-tamper{IP:ttl:add:10}-|", "ttl10", L("ttl10")); /* no match */
    check_run("[IP:ttl:10]-tamper{IP:ttl:add:54}-|", "ttl10", L("base"));
    check_run("[TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:10},)-|", "base", L("ttl10", "base"));
    check_run("[TCP:flags:PA]-duplicate(,tamper{IP:ttl:replace:10})-|", "base", L("base", "ttl10"));
    check_run("[TCP:flags:PA]-fragment{tcp:-1:True}-|", "base", L("seg_half_1", "seg_half_2"));
    check_run("[TCP:flags:PA]-fragment{tcp:-1:False}-|", "base", L("seg_half_2", "seg_half_1"));
    check_run("[TCP:flags:PA]-fragment{tcp:8:True:5}-|", "base", L("seg_8_5_1", "seg_8_5_2"));
    check_run("[TCP:flags:PA]-fragment{ip:-1:True}-|", "base", L("frag_half_1", "frag_half_2"));
    check_run("[TCP:flags:PA]-fragment{ip:2:True}-|", "base", L("frag_2_1", "frag_2_2"));
    check_run("[TCP:flags:PA]-fragment{ip:2:False}-|", "base", L("frag_2_2", "frag_2_1"));
    check_run("[UDP:dport:53]-tamper{DNS:qd:compress}-|", "dns", L("dns_compressed"));
    check_run("[DNS:id:4660]-tamper{DNS:id:replace:17185}-|", "dns", L("dns_id"));
    check_run("[DNSQR:qname:www.example.com.]-drop-|", "dns", (const char *const[]){NULL});
    check_run("[DNSQR:qname:example.com.]-drop-|", "dns", L("dns"));
    check_run("[IPv6:hlim:64]-tamper{IP:ttl:replace:3}-|", "v6syn", L("v6_hlim3"));
    /* trees: none fires -> unchanged; an empty tree swallows the packet */
    check_run("[TCP:flags:S]-drop-|", "base", L("base"));
    check_run("[TCP:flags:PA]-|", "base", (const char *const[]){NULL});
    check_run("[TCP:flags:PA]-drop-|", "base", (const char *const[]){NULL});
    check_run("\\/ [TCP:flags:PA]-drop-|", "base", L("base")); /* inbound forest only */
    /* every matching tree runs on a fresh copy of the original */
    check_run("[TCP:flags:PA]-tamper{IP:ttl:replace:10}-| [IP:ttl:64]-duplicate(drop,)-|", "base",
              L("ttl10", "base"));
    /* the trigger always sees the original, not an earlier tree's result */
    check_run("[TCP:flags:PA]-tamper{IP:ttl:replace:10}-| [IP:ttl:10]-drop-|", "base", L("ttl10"));
}

static int run_count(strategy *s, const char *pkt)
{
    pktlist out = {0};
    int n;
    strategy_apply(s, golden(pkt), DIR_OUT, &out);
    n = (int)out.n;
    pktlist_free(&out);
    return n;
}

TEST(test_gas)
{
    strategy *s = parse_ok("[TCP:flags:PA:2]-duplicate-|");
    if (!s)
        return;
    CHECK_INT(run_count(s, "base"), 2);
    CHECK_INT(run_count(s, "base"), 2);
    CHECK_INT(run_count(s, "base"), 1); /* out of gas */
    CHECK_INT(s->out[0]->fired, 2);
    strategy_reset(s);
    CHECK_INT(run_count(s, "base"), 2);
    strategy_free(s);

    /* bomb trigger: waits for 2 matches, then fires every time */
    s = parse_ok("[TCP:flags:PA:-2]-duplicate-|");
    if (!s)
        return;
    CHECK_INT(run_count(s, "base"), 1);
    CHECK_INT(run_count(s, "base"), 1);
    CHECK_INT(run_count(s, "base"), 2);
    CHECK_INT(run_count(s, "base"), 2);
    CHECK_INT(run_count(s, "dns"), 1); /* no match */
    strategy_free(s);

    /* gas 0 never fires */
    s = parse_ok("[TCP:flags:PA:0]-drop-|");
    if (!s)
        return;
    CHECK_INT(run_count(s, "base"), 1);
    strategy_free(s);
}

TEST(test_trigger_values)
{
    strategy *s;
    /* wildcard: substring match on strings, and on the decimal form of ints */
    s = parse_ok("[TCP:flags:A*]-drop-| [TCP:load:HTTP/1.1*]-duplicate-|");
    if (s) {
        CHECK_INT(run_count(s, "base"), 2); /* PA matches A*, load has HTTP/1.1 */
        CHECK_INT(run_count(s, "v6syn"), 1);
        strategy_free(s);
    }
    s = parse_ok("[TCP:dport:8*]-drop-|");
    if (s) {
        CHECK_INT(run_count(s, "base"), 0);
        strategy_free(s);
    }
    /* an int never equals a string: flags:0 does not match "" */
    s = parse_ok("[TCP:flags:0]-drop-|");
    if (s) {
        CHECK_INT(run_count(s, "base"), 1);
        strategy_free(s);
    }
    /* lower-case protocol names work and print back as written */
    s = parse_ok("[tcp:flags:PA]-tamper{ip:ttl:replace:10}-|");
    if (s) {
        char *o = printed(s);
        CHECK_STR(o, "[tcp:flags:PA]-tamper{ip:ttl:replace:10}-| \\/");
        free(o);
        check_run("[tcp:flags:PA]-tamper{ip:ttl:replace:10}-|", "base", L("ttl10"));
        strategy_free(s);
    }
}

TEST(test_sleep_trace)
{
    strategy *s = parse_ok("[TCP:flags:PA]-duplicate(sleep{0.5},)-| [TCP:flags:PA]-trace{3:6}-|");
    pktlist out = {0};
    gval v;
    if (!s)
        return;
    strategy_apply(s, golden("base"), DIR_OUT, &out);
    CHECK_INT(out.n, 5);
    if (out.n == 5) {
        CHECK(out.v[0]->sleep == 0.5);
        CHECK(out.v[1]->sleep == 0); /* duplicate's copy has no delay */
        for (int i = 0; i < 3; i++) {
            pkt_get(out.v[2 + i], LAYER_IP, "ttl", &v);
            CHECK_INT(v.i, 3 + i);
            CHECK(out.v[2 + i]->sleep == (double)i);
        }
    }
    pktlist_free(&out);
    /* trace runs once; later packets are dropped by it */
    strategy_apply(s, golden("base"), DIR_OUT, &out);
    CHECK_INT(out.n, 2);
    pktlist_free(&out);
    strategy_free(s);
}

TEST(test_segment_edges)
{
    strategy *s;
    pktlist out = {0};
    gval v;
    /* no payload: segmentation duplicates the packet */
    s = parse_ok("[TCP:flags:S]-fragment{tcp:4:True}-|");
    if (s) {
        strategy_apply(s, golden("v6syn"), DIR_OUT, &out);
        CHECK_INT(out.n, 2);
        pktlist_free(&out);
        strategy_free(s);
    }
    /* sequence numbers wrap; IPv6 segments get a fresh payload length */
    s = parse_ok("[TCP:flags:PA]-tamper{TCP:seq:replace:4294967290}(fragment{tcp:10:True},)-|");
    if (s) {
        strategy_apply(s, golden("base"), DIR_OUT, &out);
        CHECK_INT(out.n, 2);
        if (out.n == 2) {
            pkt_get(out.v[1], LAYER_TCP, "seq", &v);
            CHECK_INT(v.i, 4);
            CHECK_INT(out.v[0]->payload_len, 10);
            CHECK_INT(out.v[1]->payload_len, 37 - 10);
        }
        pktlist_free(&out);
        strategy_free(s);
    }
    /* overlap larger than the rest is clamped */
    s = parse_ok("[TCP:flags:PA]-fragment{tcp:30:True:100}-|");
    if (s) {
        strategy_apply(s, golden("base"), DIR_OUT, &out);
        CHECK_INT(out.n, 2);
        if (out.n == 2) {
            CHECK_INT(out.v[0]->payload_len, 37);
            CHECK_INT(out.v[1]->payload_len, 7);
        }
        pktlist_free(&out);
        strategy_free(s);
    }
}

TEST(test_ipv6_fragment)
{
    strategy *s = parse_ok("[UDP:dport:2000]-fragment{ip:1:True}-|");
    pktlist out = {0};
    uint8_t v6big[200];
    gpkt *p;
    if (!s)
        return;
    /* IPv6/UDP with 100 bytes of payload */
    memset(v6big, 0, sizeof(v6big));
    v6big[0] = 0x60;
    v6big[5] = 108;
    v6big[6] = 17;
    v6big[7] = 64;
    v6big[23] = 1;
    v6big[39] = 2;
    v6big[40] = 0x03;
    v6big[41] = 0xe8;
    v6big[42] = 0x07;
    v6big[43] = 0xd0;
    v6big[45] = 108;
    p = pkt_parse(v6big, 148);
    CHECK(p != NULL);
    if (!p) {
        strategy_free(s);
        return;
    }
    strategy_apply(s, p, DIR_OUT, &out);
    CHECK_INT(out.n, 2);
    if (out.n == 2) {
        size_t l1, l2;
        uint8_t *a = pkt_bytes(out.v[0], &l1), *b = pkt_bytes(out.v[1], &l2);
        CHECK_INT(a[6], 44); /* fragment header */
        CHECK_INT(a[40], 17);
        CHECK_INT(a[43] & 1, 1); /* M flag */
        CHECK_INT(l1, 40 + 8 + 8);
        CHECK_INT(b[6], 44);
        CHECK_INT(((b[42] << 8) | b[43]) >> 3, 1); /* offset 8 bytes */
        CHECK_INT(b[43] & 1, 0);
        CHECK_INT(l2, 40 + 8 + 100);
        CHECK(memcmp(a + 44, b + 44, 4) == 0); /* same identification */
        free(a);
        free(b);
    }
    pktlist_free(&out);
    strategy_free(s);
}

TEST(test_pretty_json)
{
    strategy *s = parse_ok("[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:corrupt},),)-| \\/");
    sbuf b;
    jw w;
    if (!s)
        return;
    sb_init(&b);
    strategy_pretty(s, &b);
    CHECK_STR(b.data, "TCP:flags:PA\n"
                      "duplicate\n"
                      "\xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80 tamper{TCP:dataofs:replace:10}\n"
                      "\xe2\x94\x82   \xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 tamper{TCP:chksum:corrupt}\n"
                      "\xe2\x94\x82       \xe2\x94\x94\xe2\x94\x80\xe2\x94\x80  ===> \n"
                      "\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80  ===> \n"
                      " \n \\/ \n ");
    sb_reset(&b);
    jw_init(&w, &b);
    strategy_json(s, &w);
    CHECK(strstr(b.data, "\"actions\":3") != NULL);
    CHECK(strstr(b.data, "\"primitive\":\"replace\",\"value\":10") != NULL);
    CHECK(strstr(b.data, "\"in\":[]") != NULL);
    CHECK_INT(strategy_len(s), 3);
    sb_free(&b);
    strategy_free(s);
}

/* ---- pcap ---------------------------------------------------------------- */

TEST(test_pcap_roundtrip)
{
    FILE *f = tmpfile();
    sbuf err;
    pcap_writer *w;
    pcap_reader *r;
    pcap_rec rec;
    uint8_t a[2048], b[2048];
    size_t al = golden_bytes("base", a, sizeof(a)), bl = golden_bytes("v6udp", b, sizeof(b));
    sb_init(&err);
    CHECK(f != NULL);
    if (!f)
        return;
    w = pcap_write_fp(f, &err);
    CHECK_INT(pcap_write(w, 1500000000123456789ull, a, al), 0);
    CHECK_INT(pcap_write(w, 1500000001000000000ull, b, bl), 0);
    fflush(f);
    rewind(f);
    r = pcap_read_fp(f, &err);
    CHECK(r != NULL);
    if (r) {
        CHECK_INT(pcap_next(r, &rec, &err), 1);
        CHECK_INT(rec.linktype, LINKTYPE_RAW);
        CHECK(rec.ts_ns == 1500000000123456789ull);
        CHECK_MEM(rec.ip, rec.ip_len, a, al);
        CHECK_INT(pcap_next(r, &rec, &err), 1);
        CHECK_MEM(rec.ip, rec.ip_len, b, bl);
        CHECK_INT(pcap_next(r, &rec, &err), 0);
        pcap_close_read(r); /* also closes f */
    }
    /* the writer does not own anything else */
    free(w);
    sb_free(&err);
}

static void put32(uint8_t *p, uint32_t v, int be)
{
    for (int i = 0; i < 4; i++)
        p[be ? i : 3 - i] = (uint8_t)(v >> (8 * (3 - i)));
}

static void put16(uint8_t *p, uint16_t v, int be)
{
    p[be ? 0 : 1] = (uint8_t)(v >> 8);
    p[be ? 1 : 0] = (uint8_t)v;
}

TEST(test_pcap_ethernet_be_us)
{
    /* big-endian microsecond pcap, Ethernet + 802.1Q, padded frame */
    uint8_t ip[2048], file[4096];
    size_t il = golden_bytes("base", ip, sizeof(ip)), n = 0;
    FILE *f = tmpfile();
    sbuf err;
    pcap_reader *r;
    pcap_rec rec;
    sb_init(&err);
    put32(file, 0xa1b2c3d4, 1);
    put16(file + 4, 2, 1);
    put16(file + 6, 4, 1);
    memset(file + 8, 0, 8);
    put32(file + 16, 65535, 1);
    put32(file + 20, LINKTYPE_ETHERNET, 1);
    n = 24;
    put32(file + n, 7, 1);
    put32(file + n + 4, 250000, 1);
    put32(file + n + 8, (uint32_t)(18 + il + 4), 1);
    put32(file + n + 12, (uint32_t)(18 + il + 4), 1);
    n += 16;
    memset(file + n, 0xaa, 12);
    put16(file + n + 12, 0x8100, 1);
    put16(file + n + 14, 5, 1);
    put16(file + n + 16, 0x0800, 1);
    memcpy(file + n + 18, ip, il);
    memset(file + n + 18 + il, 0, 4); /* padding */
    n += 18 + il + 4;
    /* an ARP frame: not IP */
    put32(file + n, 8, 1);
    put32(file + n + 4, 0, 1);
    put32(file + n + 8, 42, 1);
    put32(file + n + 12, 42, 1);
    n += 16;
    memset(file + n, 0, 42);
    put16(file + n + 12, 0x0806, 1);
    n += 42;
    fwrite(file, 1, n, f);
    rewind(f);
    r = pcap_read_fp(f, &err);
    CHECK(r != NULL);
    if (!r)
        return;
    CHECK_INT(pcap_next(r, &rec, &err), 1);
    CHECK(rec.ts_ns == 7250000000ull);
    CHECK_MEM(rec.ip, rec.ip_len, ip, il);
    CHECK_INT(pcap_next(r, &rec, &err), 1);
    CHECK(rec.ip == NULL);
    CHECK_INT(pcap_next(r, &rec, &err), 0);
    pcap_close_read(r);
    sb_free(&err);
}

TEST(test_pcapng)
{
    /* SHB, IDB (raw IP, tsresol 10^-9), EPB, SPB, truncated block */
    uint8_t ip[2048], file[4096];
    size_t il = golden_bytes("v6udp", ip, sizeof(ip)), n = 0, pad = (4 - il % 4) % 4;
    FILE *f = tmpfile();
    sbuf err;
    pcap_reader *r;
    pcap_rec rec;
    sb_init(&err);
    put32(file, 0x0a0d0d0a, 0);
    put32(file + 4, 28, 0);
    put32(file + 8, 0x1a2b3c4d, 0);
    put16(file + 12, 1, 0);
    put16(file + 14, 0, 0);
    memset(file + 16, 0xff, 8);
    put32(file + 24, 28, 0);
    n = 28;
    put32(file + n, 1, 0);
    put32(file + n + 4, 28, 0);
    put16(file + n + 8, LINKTYPE_RAW, 0);
    put16(file + n + 10, 0, 0);
    put32(file + n + 12, 0, 0);
    put16(file + n + 16, 9, 0); /* if_tsresol */
    put16(file + n + 18, 1, 0);
    file[n + 20] = 9;
    memset(file + n + 21, 0, 3);
    put32(file + n + 24, 28, 0);
    n += 28;
    put32(file + n, 6, 0);
    put32(file + n + 4, (uint32_t)(32 + il + pad), 0);
    put32(file + n + 8, 0, 0);
    put32(file + n + 12, 1, 0); /* ts high */
    put32(file + n + 16, 5, 0);
    put32(file + n + 20, (uint32_t)il, 0);
    put32(file + n + 24, (uint32_t)il, 0);
    memcpy(file + n + 28, ip, il);
    memset(file + n + 28 + il, 0, pad);
    put32(file + n + 28 + il + pad, (uint32_t)(32 + il + pad), 0);
    n += 32 + il + pad;
    put32(file + n, 3, 0);
    put32(file + n + 4, (uint32_t)(16 + il + pad), 0);
    put32(file + n + 8, (uint32_t)il, 0);
    memcpy(file + n + 12, ip, il);
    memset(file + n + 12 + il, 0, pad);
    put32(file + n + 12 + il + pad, (uint32_t)(16 + il + pad), 0);
    n += 16 + il + pad;
    put32(file + n, 6, 0);
    put32(file + n + 4, 200, 0);
    n += 8;
    fwrite(file, 1, n, f);
    rewind(f);
    r = pcap_read_fp(f, &err);
    CHECK(r != NULL);
    if (!r)
        return;
    CHECK_INT(pcap_next(r, &rec, &err), 1);
    CHECK(rec.ts_ns == ((1ull << 32) | 5));
    CHECK_MEM(rec.ip, rec.ip_len, ip, il);
    CHECK_INT(pcap_next(r, &rec, &err), 1);
    CHECK_MEM(rec.ip, rec.ip_len, ip, il);
    CHECK_INT(pcap_next(r, &rec, &err), -1);
    CHECK(err.len > 0);
    pcap_close_read(r);
    sb_free(&err);
}

TEST(test_pcap_garbage)
{
    FILE *f = tmpfile();
    sbuf err;
    sb_init(&err);
    fwrite("hello world, not a capture", 1, 26, f);
    rewind(f);
    CHECK(pcap_read_fp(f, &err) == NULL);
    CHECK(err.len > 0);
    sb_free(&err);
}

void suite_strategy(void);
void suite_strategy(void)
{
    RUN(test_geneva_corpus);
    RUN(test_print_exact);
    RUN(test_parse_errors);
    RUN(test_fragment_random_order);
    RUN(test_actions_vs_scapy);
    RUN(test_gas);
    RUN(test_trigger_values);
    RUN(test_sleep_trace);
    RUN(test_segment_edges);
    RUN(test_ipv6_fragment);
    RUN(test_pretty_json);
    RUN(test_pcap_roundtrip);
    RUN(test_pcap_ethernet_be_us);
    RUN(test_pcapng);
    RUN(test_pcap_garbage);
}
