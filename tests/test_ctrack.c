/* Stage X3: ranges (src/ext/range.c), the conntrack (src/ext/ctrack.c) and
 * the FLOW:/META: triggers (src/ext/xtrig.c), with zapret2's semantics. */
#include <stdlib.h>
#include <string.h>

#include "ext/ext.h"
#include "ext_opt.h"
#include "pkt.h"
#include "strategy.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/ctrack.h"
#  include "ext/range.h"
#  include "ext/xtrig.h"

enum { F = 1, S = 2, R = 4, P = 8, A = 16 };

typedef struct {
    int v6, udp, ttl;
    uint16_t win;
    int mss, wscale; /* -1: no option */
    uint16_t cport, sport;
} popt;

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8), p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, v >> 16), put16(p + 2, v & 0xffff); }

/* Raw bytes of a packet from the client (c2s) or the server; returns the length */
static size_t raw(uint8_t *b, int c2s, unsigned flags, uint32_t seq, uint32_t ack, size_t dl, const popt *o)
{
    static const popt none = {0, 0, 64, 1000, -1, -1, 40000, 443};
    size_t hl, optl = 0, l4h, l4;
    uint8_t *t, opts[8];
    if (!o)
        o = &none;
    if (!o->udp && o->mss >= 0) {
        opts[optl++] = 2, opts[optl++] = 4;
        put16(opts + optl, (unsigned)o->mss), optl += 2;
    }
    if (!o->udp && o->wscale >= 0) {
        opts[optl++] = 1, opts[optl++] = 3, opts[optl++] = 3, opts[optl++] = (uint8_t)o->wscale;
    }
    l4h = o->udp ? 8 : 20 + optl;
    l4 = l4h + dl;
    hl = o->v6 ? 40 : 20;
    memset(b, 0, hl + l4);
    if (o->v6) {
        b[0] = 0x60;
        put16(b + 4, (unsigned)l4);
        b[6] = o->udp ? 17 : 6;
        b[7] = (uint8_t)o->ttl;
        b[8] = 0x20, b[9] = 0x01, b[23] = c2s ? 1 : 2;
        b[24] = 0x20, b[25] = 0x01, b[39] = c2s ? 2 : 1;
    } else {
        b[0] = 0x45;
        put16(b + 2, (unsigned)(hl + l4));
        b[8] = (uint8_t)o->ttl;
        b[9] = o->udp ? 17 : 6;
        b[12] = 10, b[15] = c2s ? 1 : 2;
        b[16] = 10, b[19] = c2s ? 2 : 1;
    }
    t = b + hl;
    put16(t, c2s ? o->cport : o->sport);
    put16(t + 2, c2s ? o->sport : o->cport);
    if (o->udp) {
        put16(t + 4, (unsigned)l4);
    } else {
        put32(t + 4, seq);
        put32(t + 8, ack);
        t[12] = (uint8_t)(l4h / 4 << 4);
        t[13] = (uint8_t)flags;
        put16(t + 14, o->win);
        memcpy(t + 20, opts, optl);
    }
    memset(t + l4h, 'x', dl);
    return hl + l4;
}

static gpkt *mk(int c2s, unsigned flags, uint32_t seq, uint32_t ack, size_t dl, const popt *o)
{
    uint8_t b[2000];
    size_t n = raw(b, c2s, flags, seq, ack, dl, o);
    return pkt_parse(b, n);
}

/* Feeds a packet, frees it, returns the flow */
static ct_flow *feed(ctrack *t, int c2s, unsigned flags, uint32_t seq, uint32_t ack, size_t dl, const popt *o,
                     uint64_t now, int *rev)
{
    gpkt *p = mk(c2s, flags, seq, ack, dl, o);
    ct_flow *f;
    int r = -1;
    if (!p)
        return NULL;
    f = ctrack_feed(t, p, now, &r);
    if (rev)
        *rev = r;
    pkt_free(p);
    return f;
}

/* ---- ranges ---------------------------------------------------------------- */

static int rin(const char *s, char def, const xside_view *v)
{
    xrange r;
    sbuf e;
    int k;
    sb_init(&e);
    k = xrange_parse(s, def, &r, &e) < 0 ? -1 : xrange_in(v, &r);
    sb_free(&e);
    return k;
}

static int rcut(const char *s, const xside_view *v)
{
    xrange r;
    sbuf e;
    int k;
    sb_init(&e);
    k = xrange_parse(s, 'n', &r, &e) < 0 ? -1 : xrange_cutoff(v, &r);
    sb_free(&e);
    return k;
}

static const char *rprint(const char *s, char def)
{
    static char buf[64];
    xrange r;
    sbuf e, o;
    sb_init(&e);
    sb_init(&o);
    if (xrange_parse(s, def, &r, &e) < 0)
        snprintf(buf, sizeof(buf), "ERR");
    else {
        xrange_print(&r, &o);
        snprintf(buf, sizeof(buf), "%s", o.data);
    }
    sb_free(&e);
    sb_free(&o);
    return buf;
}

TEST(range_parse_print)
{
    CHECK_STR(rprint("n2-n5", 0), "n2-n5");
    CHECK_STR(rprint("d1<d3", 0), "d1<d3");
    CHECK_STR(rprint("-s100", 0), "-s100");
    CHECK_STR(rprint("<p1000", 0), "<p1000");
    CHECK_STR(rprint("b10-", 0), "b10-");
    CHECK_STR(rprint("a", 0), "a");
    CHECK_STR(rprint("x", 0), "x");
    CHECK_STR(rprint("1-5", 'n'), "n1-n5");
    CHECK_STR(rprint("5", 'd'), "d5-d5");
    CHECK_STR(rprint("3-", 'b'), "b3-");
    CHECK_STR(rprint("<10", 'n'), "<n10");
    CHECK_STR(rprint("n1-s9", 'n'), "n1-s9");
    /* zapret2 wants the letters and a range */
    CHECK_STR(rprint("1-5", 0), "ERR");
    CHECK_STR(rprint("n5", 0), "ERR");
    CHECK_STR(rprint("", 'n'), "ERR");
    CHECK_STR(rprint("q1-q2", 'n'), "ERR");
    CHECK_STR(rprint("n1-n2x", 'n'), "ERR");
    CHECK_STR(rprint("n1~n2", 'n'), "ERR");
    CHECK_STR(rprint("n4294967296", 'n'), "ERR");
    CHECK_STR(rprint("n4294967295-", 'n'), "n4294967295-");
}

TEST(range_check)
{
    xside_view v = {3, 1, 100, 50, 150, 0};
    CHECK_INT(rin("n1-n3", 0, &v), 1);
    CHECK_INT(rin("n1<n3", 0, &v), 0); /* exclusive */
    CHECK_INT(rin("n4-", 0, &v), 0);
    CHECK_INT(rin("-n3", 0, &v), 1);
    CHECK_INT(rin("d1-d1", 0, &v), 1);
    CHECK_INT(rin("b101-", 0, &v), 0);
    CHECK_INT(rin("s50-p150", 0, &v), 1);
    CHECK_INT(rin("a", 0, &v), 1);
    CHECK_INT(rin("x", 0, &v), 0);
    /* without a flow only "a" (and a "-" lower bound with "a" upper) matches */
    CHECK_INT(rin("a", 0, NULL), 1);
    CHECK_INT(rin("n1-", 0, NULL), 0);
    CHECK_INT(rin("-n5", 0, NULL), 0);
    CHECK_INT(rin("x", 0, NULL), 0);
    /* past 2 GB, s and p no longer count, n d b still do */
    v.over2g = 1;
    CHECK_INT(rin("s1-", 0, &v), 0);
    CHECK_INT(rin("-p999999", 0, &v), 0);
    CHECK_INT(rin("n1-", 0, &v), 1);
}

TEST(range_cutoff)
{
    xside_view v = {3, 1, 100, 50, 150, 0};
    CHECK_INT(rcut("1-2", &v), 1);
    CHECK_INT(rcut("1-3", &v), 0);
    CHECK_INT(rcut("<3", &v), 1);
    CHECK_INT(rcut("<4", &v), 0);
    CHECK_INT(rcut("5-", &v), 0); /* not yet */
    CHECK_INT(rcut("a", &v), 0);
    CHECK_INT(rcut("x", &v), 1);
    /* without a flow: cut unless the range is "a" both ways */
    CHECK_INT(rcut("a", NULL), 0);
    CHECK_INT(rcut("1-", NULL), 1);
    CHECK_INT(rcut("-5", NULL), 1);
    v.over2g = 1;
    {
        xrange r;
        sbuf e;
        sb_init(&e);
        xrange_parse("-s100", 0, &r, &e);
        CHECK_INT(xrange_cutoff(&v, &r), 1);
        sb_free(&e);
    }
}

/* ---- conntrack ------------------------------------------------------------- */

static ctrack *ct_new(size_t max)
{
    ct_config c;
    ct_config_default(&c);
    if (max)
        c.max = max;
    return ctrack_new(&c);
}

TEST(ctrack_timeouts_parse)
{
    ct_config c;
    ct_config_default(&c);
    CHECK_INT(ct_timeouts_parse("1:2:3", &c), 0);
    CHECK_INT(c.t_syn, 1);
    CHECK_INT(c.t_est, 2);
    CHECK_INT(c.t_fin, 3);
    CHECK_INT(c.t_udp, 60);
    CHECK_INT(ct_timeouts_parse("5:6:7:8", &c), 0);
    CHECK_INT(c.t_udp, 8);
    CHECK_INT(ct_timeouts_parse("1:2", &c), -1);
    CHECK_INT(ct_timeouts_parse("1:2:3:4:5", &c), -1);
    CHECK_INT(ct_timeouts_parse("1:x:3", &c), -1);
    CHECK_INT(ct_timeouts_parse("1:2:3:", &c), -1);
    CHECK_INT(ct_timeouts_parse("", &c), -1);
}

TEST(ctrack_handshake)
{
    ctrack *t = ct_new(0);
    popt syn = {0, 0, 64, 64240, 1460, 7, 40000, 443};
    popt sa = {0, 0, 52, 65535, 1400, 8, 40000, 443};
    popt o = {0, 0, 64, 502, -1, -1, 40000, 443};
    ct_flow *f;
    xside_view v;
    int rev = -1;

    /* a lone ACK of an unknown flow is not tracked */
    CHECK(!feed(t, 1, A, 1, 1, 0, &o, 1000, &rev));
    CHECK_INT(ctrack_count(t), 0);

    f = feed(t, 1, S, 1000, 0, 0, &syn, 1000, &rev);
    CHECK(f != NULL);
    CHECK_INT(rev, 0);
    CHECK_INT(f->state, CT_SYN);
    CHECK_INT(f->client.seq0, 1000);
    CHECK_INT(f->client.mss, 1460);
    CHECK_INT(f->client.scale, 7);
    CHECK_INT(f->incoming_ttl, 0);

    CHECK(feed(t, 0, S | A, 5000, 1001, 0, &sa, 1010, &rev) == f);
    CHECK_INT(rev, 1);
    CHECK_INT(f->server.seq0, 5000);
    CHECK_INT(f->server.mss, 1400);
    CHECK_INT(f->incoming_ttl, 52);
    CHECK_INT(ct_mss(f), 1400);

    CHECK(feed(t, 1, A, 1001, 5001, 0, &o, 1020, &rev) == f);
    CHECK_INT(f->state, CT_EST);
    CHECK_INT(f->client.winsize_calc, 502 << 7);

    CHECK(feed(t, 1, P | A, 1001, 5001, 100, &o, 1030, &rev) == f);
    ct_view(&f->client, &v);
    CHECK_INT(v.n, 4 - 1); /* the lone ACK before the SYN was not counted */
    CHECK_INT(v.d, 1);
    CHECK_INT(v.b, 100);
    CHECK_INT(v.s, 1);
    CHECK_INT(v.p, 101);
    CHECK_INT(ct_is_retrans(&f->client), 0);

    /* the server's reply moves the client's position to its ack */
    CHECK(feed(t, 0, P | A, 5001, 1101, 40, &o, 1040, &rev) == f);
    ct_view(&f->server, &v);
    CHECK_INT(v.n, 2);
    CHECK_INT(v.d, 1);
    CHECK_INT(v.b, 40);
    CHECK_INT(v.s, 1);
    CHECK_INT(v.p, 41);
    ct_view(&f->client, &v);
    CHECK_INT(v.s, 101);
    CHECK_INT(v.p, 101);
    CHECK_INT(f->incoming_ttl, 52); /* the first reply's */

    /* a retransmission: counted in b, recognized by uppos */
    CHECK(feed(t, 1, P | A, 1001, 5041, 100, &o, 1050, &rev) == f);
    CHECK_INT(ct_is_retrans(&f->client), 1);
    ct_view(&f->client, &v);
    CHECK_INT(v.b, 200);
    CHECK(feed(t, 1, P | A, 1101, 5041, 10, &o, 1060, &rev) == f);
    CHECK_INT(ct_is_retrans(&f->client), 0);

    CHECK(feed(t, 1, F | A, 1111, 5041, 0, &o, 1070, &rev) == f);
    CHECK_INT(f->state, CT_FIN);
    {
        gpkt *p = mk(0, A, 0, 0, 0, &o);
        rev = -1;
        CHECK(ctrack_find(t, p, &rev) == f);
        CHECK_INT(rev, 1);
        pkt_free(p);
    }
    ctrack_free(t);
}

TEST(ctrack_syn_reinit)
{
    ctrack *t = ct_new(0);
    popt o = {0, 0, 64, 1000, -1, -1, 40001, 80};
    ct_flow *f;
    xside_view v;
    f = feed(t, 1, S, 100, 0, 0, &o, 1000, NULL);
    feed(t, 0, S | A, 900, 101, 0, &o, 1000, NULL);
    feed(t, 1, A, 101, 901, 0, &o, 1000, NULL);
    feed(t, 1, P | A, 101, 901, 10, &o, 1000, NULL);
    f->xstate[0] = 7;
    f->tree_cut[0] = 1;
    /* a retransmitted SYN in the SYN state is just counted */
    /* a new SYN past it starts the flow over, erasing itself too */
    CHECK(feed(t, 1, S, 7777, 0, 0, &o, 2000, NULL) == f);
    CHECK_INT(f->state, CT_SYN);
    CHECK_INT(f->client.seq0, 7777);
    CHECK_INT(f->xstate[0], 0);
    CHECK_INT(f->tree_cut[0], 0);
    ct_view(&f->client, &v);
    CHECK_INT(v.n, 0);
    CHECK_INT(v.s, 0);
    /* a SYN+ACK with another ISN past SYN starts over too */
    feed(t, 0, S | A, 300, 7778, 0, &o, 2000, NULL);
    feed(t, 1, A, 7778, 301, 0, &o, 2000, NULL);
    CHECK_INT(f->state, CT_EST);
    CHECK(feed(t, 0, S | A, 300, 9999, 0, &o, 2000, NULL) == f);
    CHECK_INT(f->state, CT_SYN);
    CHECK_INT(f->client.seq0, 9998);
    ct_view(&f->client, &v);
    CHECK_INT(v.n, 0);
    /* a duplicate SYN+ACK changes nothing of the state */
    feed(t, 1, A, 9999, 301, 0, &o, 2000, NULL);
    CHECK(feed(t, 0, S | A, 300, 9999, 0, &o, 2000, NULL) == f);
    CHECK_INT(f->state, CT_EST);
    ctrack_free(t);
}

TEST(ctrack_synack_first)
{
    ctrack *t = ct_new(0);
    popt o = {0, 0, 60, 1000, -1, -1, 40002, 443};
    int rev = -1;
    ct_flow *f = feed(t, 0, S | A, 50, 11, 0, &o, 1000, &rev);
    CHECK(f != NULL);
    CHECK_INT(rev, 1);
    CHECK_INT(f->cport, 40002);
    CHECK_INT(f->sport, 443);
    CHECK_INT(f->client.seq0, 10);
    CHECK_INT(f->server.seq0, 50);
    CHECK(feed(t, 1, A, 11, 51, 0, &o, 1000, &rev) == f);
    CHECK_INT(rev, 0);
    ctrack_free(t);
}

TEST(ctrack_udp_v6)
{
    ctrack *t = ct_new(0);
    popt o = {1, 1, 33, 0, -1, -1, 5353, 53};
    int rev = -1;
    xside_view v;
    ct_flow *f = feed(t, 1, 0, 0, 0, 30, &o, 1000, &rev);
    CHECK(f != NULL);
    CHECK_INT(f->proto, 17);
    CHECK_INT(f->ver, 6);
    CHECK(feed(t, 0, 0, 0, 0, 70, &o, 1000, &rev) == f);
    CHECK_INT(rev, 1);
    CHECK_INT(f->incoming_ttl, 33);
    ct_view(&f->server, &v);
    CHECK_INT(v.n, 1);
    CHECK_INT(v.b, 70);
    CHECK_INT(ct_mss(f), CT_DEFAULT_MSS);
    ctrack_free(t);
}

TEST(ctrack_2g_wrap)
{
    ctrack *t = ct_new(0);
    popt o = {0, 0, 64, 1000, -1, -1, 40003, 443};
    xside_view v;
    ct_flow *f = feed(t, 1, S, 10, 0, 0, &o, 1000, NULL);
    feed(t, 0, S | A, 20, 11, 0, &o, 1000, NULL);
    feed(t, 1, P | A, 11 + 0x7fffffffu, 21, 1, &o, 1000, NULL);
    ct_view(&f->client, &v);
    CHECK_INT(v.over2g, 1);
    ct_view(&f->server, &v);
    CHECK_INT(v.over2g, 0);
    ctrack_free(t);
}

TEST(ctrack_icmp)
{
    ctrack *t = ct_new(0);
    popt o = {0, 0, 64, 1000, -1, -1, 40004, 443};
    uint8_t b[200], inner[100];
    size_t in = raw(inner, 1, S, 10, 0, 0, &o);
    ct_flow *f = feed(t, 1, S, 10, 0, 0, &o, 1000, NULL), *g;
    gpkt *p;
    int rev = -1;
    xside_view v;
    /* an ICMP unreachable from a router about the client's SYN */
    memset(b, 0, sizeof(b));
    b[0] = 0x45, b[8] = 250, b[9] = 1;
    put16(b + 2, (unsigned)(20 + 8 + 28));
    b[12] = 10, b[13] = 9, b[16] = 10, b[19] = 1;
    b[20] = 3, b[21] = 1;
    memcpy(b + 28, inner, 28);
    p = pkt_parse(b, 20 + 8 + 28);
    CHECK(p != NULL);
    if (p) {
        g = ctrack_feed(t, p, 1000, &rev);
        CHECK(g == f);
        CHECK_INT(rev, 1);
        ct_view(&f->client, &v);
        CHECK_INT(v.n, 1); /* not counted */
        ct_view(&f->server, &v);
        CHECK_INT(v.n, 0);
        /* an echo request is not an error */
        p->payload[0] = 8;
        CHECK(ctrack_feed(t, p, 1000, &rev) == NULL);
        pkt_free(p);
    }
    (void)in;
    ctrack_free(t);
}

TEST(ctrack_timeouts_lru)
{
    ctrack *t;
    ct_config c;
    popt o = {0, 0, 64, 1000, -1, -1, 41000, 443};
    ct_config_default(&c);
    c.t_syn = 5, c.t_est = 100, c.t_fin = 5, c.t_udp = 20;
    t = ctrack_new(&c);
    feed(t, 1, S, 1, 0, 0, &o, 1000, NULL); /* SYN: 5 s */
    o.cport = 41001;
    feed(t, 1, S, 1, 0, 0, &o, 1000, NULL);
    feed(t, 0, S | A, 1, 2, 0, &o, 1000, NULL);
    feed(t, 1, A, 2, 2, 0, &o, 1000, NULL); /* EST: 100 s */
    CHECK_INT(ctrack_count(t), 2);
    ctrack_purge(t, 1000 + 6000);
    CHECK_INT(ctrack_count(t), 1);
    ctrack_purge(t, 1000 + 99000);
    CHECK_INT(ctrack_count(t), 1);
    ctrack_purge(t, 1000 + 100000);
    CHECK_INT(ctrack_count(t), 0);
    /* feed purges every 10 s of packet time */
    o.cport = 41002;
    feed(t, 1, S, 1, 0, 0, &o, 200000, NULL);
    o.cport = 41003;
    feed(t, 1, S, 1, 0, 0, &o, 209000, NULL);
    CHECK_INT(ctrack_count(t), 2);
    o.cport = 41004;
    feed(t, 1, S, 1, 0, 0, &o, 210001, NULL);
    CHECK_INT(ctrack_count(t), 2); /* 41002 gone */
    /* time going back (a merged capture) is taken as no time passing */
    o.cport = 41005;
    feed(t, 1, S, 1, 0, 0, &o, 5000, NULL);
    CHECK_INT(ctrack_count(t), 3);
    ctrack_free(t);

    /* full: the least recently active one goes */
    c.max = 16;
    t = ctrack_new(&c);
    for (unsigned i = 0; i < 16; i++) {
        o.cport = (uint16_t)(42000 + i);
        feed(t, 1, S, 1, 0, 0, &o, 1000, NULL);
    }
    o.cport = 42000;
    feed(t, 1, S, 1, 0, 0, &o, 1001, NULL); /* 42000 is active again */
    o.cport = 42100;
    feed(t, 1, S, 1, 0, 0, &o, 1002, NULL);
    CHECK_INT(ctrack_count(t), 16);
    CHECK_INT(ctrack_evictions(t), 1);
    {
        gpkt *p;
        int r;
        o.cport = 42000;
        p = mk(1, A, 2, 2, 0, &o);
        CHECK(ctrack_find(t, p, &r) != NULL);
        pkt_free(p);
        o.cport = 42001;
        p = mk(1, A, 2, 2, 0, &o);
        CHECK(ctrack_find(t, p, &r) == NULL);
        pkt_free(p);
    }
    ctrack_free(t);
}

/* ---- FLOW: and META: triggers ---------------------------------------------- */

static strategy *sparse(const char *s)
{
    sbuf e;
    strategy *st;
    sb_init(&e);
    st = strategy_parse(s, &e);
    if (!st)
        fprintf(stderr, "    %s: %s\n", s, e.data);
    sb_free(&e);
    return st;
}

static const char *parse_err(const char *s)
{
    static char buf[300];
    sbuf e;
    strategy *st;
    sb_init(&e);
    st = strategy_parse(s, &e);
    snprintf(buf, sizeof(buf), "%s", st ? "OK" : e.data);
    strategy_free(st);
    sb_free(&e);
    return buf;
}

/* Feeds the packet, then runs it through st; returns the trees fired, or
 * -1 when every tree is cut off (the packet passes by) */
static int run1(ctrack *t, strategy *st, xpkt_ctx *c, int c2s, unsigned flags, uint32_t seq, uint32_t ack,
                size_t dl, const popt *o)
{
    gpkt *p = mk(c2s, flags, seq, ack, dl, o);
    pktlist out = {0};
    int k;
    strat_dir dir = c2s ? DIR_OUT : DIR_IN;
    c->f = ctrack_feed(t, p, 1000, &c->reverse);
    c->st = st;
    if (c->f && xtrig_all_cut(st, dir, c->f)) {
        pkt_free(p);
        return -1;
    }
    k = strategy_apply_x(st, p, dir, &out, c);
    pktlist_free(&out);
    return k;
}

TEST(xtrig_parse)
{
    strategy_set_xtrig(&xtrig_ops);
    CHECK_STR(parse_err("[FLOW:n:1-3]-drop-| \\/"), "OK");
    CHECK_STR(parse_err("[FLOW:rd:d2-]-drop-| \\/"), "OK");
    CHECK_STR(parse_err("[FLOW:state:est]-drop-| \\/"), "OK");
    CHECK_STR(parse_err("[FLOW:retrans:1]-drop-| \\/"), "OK");
    CHECK_STR(parse_err("[META:ifin:eth0]-drop-| \\/"), "OK");
    CHECK_STR(parse_err("[META:mark:0x40000000/0x40000000]-drop-| \\/"), "OK");
    CHECK(strstr(parse_err("[FLOW:q:1]-drop-| \\/"), "unknown field \"q\" for FLOW"));
    CHECK(strstr(parse_err("[FLOW:n:1~2]-drop-| \\/"), "bad range"));
    CHECK(strstr(parse_err("[FLOW:state:open]-drop-| \\/"), "syn, est or fin"));
    CHECK(strstr(parse_err("[FLOW:retrans:2]-drop-| \\/"), "0 or 1"));
    CHECK(strstr(parse_err("[META:mark:x]-drop-| \\/"), "N or N/MASK"));
    CHECK(strstr(parse_err("[META:mark:0x100000000]-drop-| \\/"), "N or N/MASK"));
    CHECK(strstr(parse_err("[META:ifin:]-drop-| \\/"), "interface"));
    CHECK(strstr(parse_err("[META:mark:0x5f/0xf0]-drop-| \\/"), "outside the mask"));
    CHECK(strstr(parse_err("[META:nosuch:1]-drop-| \\/"), "unknown field"));
    /* round trip through print */
    {
        strategy *st = sparse("[FLOW:n:1-3]-drop-| [META:mark:5]-drop-| \\/");
        sbuf o;
        sb_init(&o);
        CHECK(st != NULL);
        if (st) {
            strategy_print(st, &o);
            CHECK_STR(o.data, "[FLOW:n:1-3]-drop-| [META:mark:5]-drop-| \\/");
        }
        strategy_free(st);
        sb_free(&o);
    }
    strategy_set_xtrig(NULL);
    /* without --ext, FLOW is an unknown protocol as in Geneva */
    CHECK(strcmp(parse_err("[FLOW:n:1-3]-drop-| \\/"), "OK") != 0);
}

TEST(xtrig_match_cutoff)
{
    ctrack *t = ct_new(0);
    popt o = {0, 0, 64, 1000, -1, -1, 43000, 443};
    xpkt_ctx c;
    strategy *st;
    strategy_set_xtrig(&xtrig_ops);
    memset(&c, 0, sizeof(c));
    st = sparse("[FLOW:n:2-3]-drop-| \\/");
    CHECK(st != NULL);
    if (!st)
        goto out;
    CHECK_INT(run1(t, st, &c, 1, S, 1, 0, 0, &o), 0);         /* n1 */
    CHECK_INT(run1(t, st, &c, 0, S | A, 1, 2, 0, &o), 0);     /* in: no in-trees */
    CHECK_INT(run1(t, st, &c, 1, A, 2, 2, 0, &o), 1);         /* n2 */
    CHECK_INT(run1(t, st, &c, 1, P | A, 2, 2, 10, &o), 1);    /* n3 */
    CHECK_INT(run1(t, st, &c, 1, P | A, 12, 2, 10, &o), 0);   /* n4: cut off while looked at */
    CHECK_INT(c.f->tree_cut[DIR_OUT], 1);
    CHECK_INT(run1(t, st, &c, 1, P | A, 22, 2, 10, &o), -1); /* n5: passes by */
    /* the same strategy changed (mutated) is another one */
    strategy_new_serial(st);
    CHECK_INT(run1(t, st, &c, 1, P | A, 22, 2, 10, &o), 0);
    CHECK_INT(run1(t, st, &c, 1, P | A, 22, 2, 10, &o), -1);
    /* another strategy on the same flow starts with no cuts */
    {
        strategy *s2 = sparse("[FLOW:n:2-]-drop-| \\/");
        CHECK_INT(run1(t, s2, &c, 1, P | A, 32, 2, 10, &o), 1);
        CHECK_INT(c.f->tree_cut[DIR_OUT], 0);
        strategy_free(s2);
    }
    strategy_free(st);

    /* the other side's counters are never cut */
    st = sparse("[FLOW:rn:1-1]-drop-| \\/");
    o.cport = 43001;
    CHECK_INT(run1(t, st, &c, 1, S, 1, 0, 0, &o), 0);     /* server n0 */
    CHECK_INT(run1(t, st, &c, 0, S | A, 1, 2, 0, &o), 0); /* in: no in-trees */
    CHECK_INT(run1(t, st, &c, 1, A, 2, 2, 0, &o), 1);     /* server n1 */
    run1(t, st, &c, 0, A, 2, 2, 0, &o);
    CHECK_INT(run1(t, st, &c, 1, A, 2, 2, 0, &o), 0);     /* server n2 */
    CHECK_INT(c.f->tree_cut[DIR_OUT], 0);
    strategy_free(st);

    /* state and retrans; two trees, only one of them cut */
    st = sparse("[FLOW:state:est]-drop-| [FLOW:retrans:1]-drop-| [FLOW:d:<1]-drop-| \\/");
    o.cport = 43002;
    CHECK_INT(run1(t, st, &c, 1, S, 1, 0, 0, &o), 1);  /* d:<1 */
    run1(t, st, &c, 0, S | A, 1, 2, 0, &o);
    CHECK_INT(run1(t, st, &c, 1, P | A, 2, 2, 10, &o), 1); /* est; d1: cut */
    CHECK_INT(c.f->tree_cut[DIR_OUT], 4);
    CHECK_INT(run1(t, st, &c, 1, P | A, 2, 2, 10, &o), 2); /* est + retrans */
    CHECK_INT(run1(t, st, &c, 1, F | A, 12, 2, 0, &o), 0); /* fin, no data */
    strategy_free(st);

    /* no flow: only "a" */
    st = sparse("[FLOW:n:a]-drop-| [FLOW:n:1-]-drop-| \\/");
    {
        gpkt *p = mk(1, A, 1, 1, 0, &o);
        pktlist out = {0};
        CHECK_INT(strategy_apply_x(st, p, DIR_OUT, &out, NULL), 1);
        pktlist_free(&out);
    }
    strategy_free(st);
out:
    strategy_set_xtrig(NULL);
    ctrack_free(t);
}

TEST(xtrig_meta)
{
    xpkt_ctx c;
    strategy *st;
    popt o = {0, 0, 64, 1000, -1, -1, 44000, 443};
    strategy_set_xtrig(&xtrig_ops);
    memset(&c, 0, sizeof(c));
    st = sparse("[META:mark:0x40/0xf0]-drop-| [META:ifin:eth0]-drop-| [META:ifout:wan]-drop-| \\/");
    CHECK(st != NULL);
    if (st) {
        pktlist out = {0};
        c.has_meta = 1;
        c.mark = 0x4f;
        c.ifin = "eth0";
        c.ifout = "lan";
        CHECK_INT(strategy_apply_x(st, mk(1, A, 1, 1, 0, &o), DIR_OUT, &out, &c), 2);
        pktlist_free(&out);
        c.mark = 0x8f;
        c.ifin = NULL;
        c.ifout = "wan";
        CHECK_INT(strategy_apply_x(st, mk(1, A, 1, 1, 0, &o), DIR_OUT, &out, &c), 1);
        pktlist_free(&out);
        c.has_meta = 0;
        c.mark = 0;
        CHECK_INT(strategy_apply_x(st, mk(1, A, 1, 1, 0, &o), DIR_OUT, &out, &c), 1);
        pktlist_free(&out);
        /* mark 0 with no metadata (WinDivert) does not match "0" */
        strategy_free(st);
        st = sparse("[META:mark:0]-drop-| \\/");
        CHECK_INT(strategy_apply_x(st, mk(1, A, 1, 1, 0, &o), DIR_OUT, &out, &c), 0);
        pktlist_free(&out);
    }
    strategy_free(st);
    strategy_set_xtrig(NULL);
}

void suite_ctrack(void)
{
    RUN(range_parse_print);
    RUN(range_check);
    RUN(range_cutoff);
    RUN(ctrack_timeouts_parse);
    RUN(ctrack_handshake);
    RUN(ctrack_syn_reinit);
    RUN(ctrack_synack_first);
    RUN(ctrack_udp_v6);
    RUN(ctrack_2g_wrap);
    RUN(ctrack_icmp);
    RUN(ctrack_timeouts_lru);
    RUN(xtrig_parse);
    RUN(xtrig_match_cutoff);
    RUN(xtrig_meta);
}

#else
void suite_ctrack(void) {}
#endif
