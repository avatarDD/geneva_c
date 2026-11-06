/* Stage X5c: the combinators (src/ext/xact_comb.c): xwhen, xstop, xrepeat
 * and xcutoff, as zapret-auto.lua's condition, stopif, repeater and
 * instance_cutoff, with zapret2's conditions and trigger expressions. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkt.h"
#include "strategy.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/blob.h"
#  include "ext/ctrack.h"
#  include "ext/l7.h"
#  include "ext/xact.h"
#  include "ext/xl7.h"
#  include "ext/xtrig.h"

enum { S = 2, P = 8, A = 16 };

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8), p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, v >> 16), put16(p + 2, v & 0xffff); }

/* 10.0.0.1:40000 -> 10.0.0.2:443, TCP with options */
static size_t mk(uint8_t *b, unsigned flags, const uint8_t *opt, size_t olen, const char *d)
{
    size_t dl = strlen(d), l4h = 20 + olen, l4 = l4h + dl;
    uint8_t *t = b + 20;
    memset(b, 0, 20 + l4h);
    b[0] = 0x45;
    put16(b + 2, (unsigned)(20 + l4));
    b[8] = 64;
    b[9] = 6;
    b[12] = 10, b[15] = 1;
    b[16] = 10, b[19] = 2;
    put16(t, 40000);
    put16(t + 2, 443);
    put32(t + 4, 1000);
    put32(t + 8, 7777);
    t[12] = (uint8_t)((5 + olen / 4) << 4);
    t[13] = (uint8_t)flags;
    put16(t + 14, 64000);
    if (olen)
        memcpy(t + 20, opt, olen);
    memcpy(t + l4h, d, dl);
    return 20 + l4;
}

static const char *perr(const char *s)
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

typedef struct {
    strategy *st;
    xpkt_ctx c;
    ct_flow f;
    pktlist out;
} run_t;

static void r_open(run_t *r, const char *s, int flow)
{
    sbuf e;
    memset(r, 0, sizeof(*r));
    sb_init(&e);
    r->st = strategy_parse(s, &e);
    if (!r->st)
        fprintf(stderr, "  %s: %s\n", s, e.data);
    CHECK(r->st != NULL);
    sb_free(&e);
    r->c.st = r->st;
    r->c.f = flow ? &r->f : NULL;
}

static int r_pkt(run_t *r, strat_dir dir, const uint8_t *b, size_t n, const xl7_view *v)
{
    pktlist_free(&r->out);
    r->c.l7 = v;
    return r->st ? strategy_apply_x(r->st, pkt_parse(b, n), dir, &r->out, &r->c) : 0;
}

static void r_close(run_t *r)
{
    pktlist_free(&r->out);
    xact_flow_clear(&r->f);
    strategy_free(r->st);
}

/* the TTLs of the results, "64,5" */
static const char *ttls(const pktlist *l)
{
    static char b[200];
    size_t k = 0;
    b[0] = 0;
    for (size_t i = 0; i < l->n && k < sizeof(b) - 8; i++)
        k += (size_t)snprintf(b + k, sizeof(b) - k, "%s%s%d", i ? "," : "", l->v[i]->xgen ? "g" : "",
                              l->v[i]->ttl);
    return b;
}

static const xl7_view *http(void)
{
    static xl7_view h;
    memset(&h, 0, sizeof(h));
    h.l7p = L7P_HTTP_REQ;
    return &h;
}

/* one packet through s (an HTTP request without v): the TTLs of the results */
static const char *one(const char *s, const uint8_t *b, size_t n, const xl7_view *v)
{
    static char res[200];
    run_t r;
    if (!v)
        v = http();
    r_open(&r, s, 1);
    r_pkt(&r, DIR_OUT, b, n, v);
    snprintf(res, sizeof(res), "%s", ttls(&r.out));
    r_close(&r);
    return res;
}

#  define T5 "tamper{IP:ttl:replace:5}"
#  define T9 "tamper{IP:ttl:replace:9}"

TEST(xc_parse)
{
    CHECK_STR(perr("[TCP:flags:PA]-xwhen{iff=cond_random;percent=30;neg}(" T5 "," T9 ")-| \\/"), "OK");
    CHECK_STR(perr("[TCP:flags:PA]-xwhen{iff=FLOW:n:<5}(xsplit{pos=1},)-| \\/"), "OK");
    CHECK_STR(perr("[TCP:flags:PA]-xwhen{iff=L7:payload:http_req,tls_client_hello}(,xsplit{pos=1})-| \\/"), "OK");
    CHECK_STR(perr("[TCP:flags:PA]-xstop{iff=cond_payload_str;pattern=%fake_default_http}(xsplit{pos=1},)-| \\/"),
              "OK");
    CHECK_STR(perr("[TCP:flags:PA]-xrepeat{repeats=2}(xfake{blob=0x41},xsplit{pos=1})-| \\/"), "OK");
    CHECK_STR(perr("[TCP:flags:PA]-xrepeat{repeats=3;iff=cond_tcp_has_ts;neg;stop;clear}-| \\/"), "OK");
    CHECK_STR(perr("[TCP:flags:PA]-xcutoff-| \\/ [TCP:flags:SA]-xcutoff{dir=both}-|"), "OK");
    CHECK(strstr(perr("[TCP:flags:PA]-xwhen-| \\/"), "missing iff"));
    CHECK(strstr(perr("[TCP:flags:PA]-xstop{neg}-| \\/"), "missing iff"));
    CHECK(strstr(perr("[TCP:flags:PA]-xwhen{iff}-| \\/"), "iff needs a condition"));
    CHECK(strstr(perr("[TCP:flags:PA]-xwhen{iff=cond_lua}-| \\/"), "cond_lua is not supported"));
    CHECK(strstr(perr("[TCP:flags:PA]-xwhen{iff=nope}-| \\/"), "unknown condition"));
    CHECK(strstr(perr("[TCP:flags:PA]-xwhen{iff=cond_payload_str}-| \\/"), "needs pattern"));
    CHECK(strstr(perr("[TCP:flags:PA]-xwhen{iff=cond_true;pattern=a}-| \\/"), "pattern is for cond_payload_str"));
    CHECK(strstr(perr("[TCP:flags:PA]-xwhen{iff=cond_random;percent=101}-| \\/"), "percent"));
    CHECK(strstr(perr("[TCP:flags:PA]-xwhen{iff=cond_random;percent=30;pattern=x}-| \\/"),
                 "pattern is for cond_payload_str"));
    CHECK(strstr(perr("[TCP:flags:PA]-xwhen{iff=cond_payload_str;pattern=x;percent=3}-| \\/"),
                 "percent is for cond_random"));
    CHECK(strstr(perr("[TCP:flags:PA]-xwhen{iff=cond_true;neg=1}-| \\/"), "takes no value"));
    CHECK(strstr(perr("[TCP:flags:PA]-xwhen{iff=FLOW:n:<5:2}-| \\/"), "no gas"));
    CHECK(strstr(perr("[TCP:flags:PA]-xwhen{iff=FOO:a:b}-| \\/"), "xwhen: unknown protocol"));
    CHECK(strstr(perr("[TCP:flags:PA]-xwhen{iff=FLOW:x:1}-| \\/"), "unknown field"));
    CHECK(strstr(perr("[TCP:flags:PA]-xrepeat-| \\/"), "missing repeats"));
    CHECK(strstr(perr("[TCP:flags:PA]-xrepeat{repeats=1000}-| \\/"), "repeats"));
    CHECK(strstr(perr("[TCP:flags:PA]-xrepeat{repeats=1;stop=1}-| \\/"), "takes no value"));
    CHECK(strstr(perr("[TCP:flags:PA]-xcutoff{dir=up}-| \\/"), "dir is in, out or both"));
    CHECK(strstr(perr("[TCP:flags:PA]-xcutoff{iff=cond_true}-| \\/"), "unknown parameter"));
    /* the inbound forest takes them all */
    CHECK_STR(perr("\\/ [TCP:flags:SA]-xwhen{iff=cond_true}(xcutoff,)-| [TCP:flags:SA]-xrepeat{repeats=1}-|"), "OK");
    /* printed back as written */
    {
        static const char s[] = "[TCP:flags:PA]-xwhen{iff=TCP:flags:PA;neg}(xstop{iff=cond_false}(xcutoff{dir=in},),)-| \\/";
        sbuf e, o;
        strategy *st;
        sb_init(&e);
        sb_init(&o);
        st = strategy_parse(s, &e);
        CHECK(st != NULL);
        if (st)
            strategy_print(st, &o);
        CHECK_STR(o.data ? o.data : "", s);
        strategy_free(st);
        sb_free(&e);
        sb_free(&o);
    }
}

TEST(xc_when)
{
    static const uint8_t ts[] = {1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0};
    uint8_t b[300], bt[300];
    size_t n = mk(b, P | A, NULL, 0, "GET / HTTP/1.1\r\n\r\n");
    size_t nt = mk(bt, P | A, ts, sizeof(ts), "hello");
    xl7_view h;
    memset(&h, 0, sizeof(h));
    h.l7p = L7P_HTTP_REQ;
    CHECK_STR(one("[TCP:flags:PA]-xwhen{iff=cond_true}(" T5 "," T9 ")-| \\/", b, n, NULL), "5");
    CHECK_STR(one("[TCP:flags:PA]-xwhen{iff=cond_true;neg}(" T5 "," T9 ")-| \\/", b, n, NULL), "9");
    CHECK_STR(one("[TCP:flags:PA]-xwhen{iff=cond_false}(" T5 ",)-| \\/", b, n, NULL), "64");
    CHECK_STR(one("[TCP:flags:PA]-xwhen{iff=cond_payload_str;pattern=HTTP/1.1}(" T5 "," T9 ")-| \\/", b, n, NULL),
              "5");
    CHECK_STR(one("[TCP:flags:PA]-xwhen{iff=cond_payload_str;pattern=HTTP/2}(" T5 "," T9 ")-| \\/", b, n, NULL), "9");
    CHECK_STR(one("[TCP:flags:PA]-xwhen{iff=cond_tcp_has_ts}(" T5 "," T9 ")-| \\/", b, n, NULL), "9");
    CHECK_STR(one("[TCP:flags:PA]-xwhen{iff=cond_tcp_has_ts}(" T5 "," T9 ")-| \\/", bt, nt, NULL), "5");
    CHECK_STR(one("[TCP:flags:PA]-xwhen{iff=cond_random;percent=0}(" T5 "," T9 ")-| \\/", b, n, NULL), "9");
    CHECK_STR(one("[TCP:flags:PA]-xwhen{iff=cond_random;percent=100}(" T5 "," T9 ")-| \\/", b, n, NULL), "5");
    /* triggers: the packet's fields, its payload type */
    CHECK_STR(one("[TCP:flags:PA]-xwhen{iff=TCP:flags:S}(" T5 "," T9 ")-| \\/", b, n, NULL), "9");
    CHECK_STR(one("[TCP:flags:PA]-xwhen{iff=TCP:dport:443}(" T5 "," T9 ")-| \\/", b, n, NULL), "5");
    CHECK_STR(one("[TCP:flags:PA]-xwhen{iff=L7:payload:http_req}(" T5 "," T9 ")-| \\/", b, n, &h), "5");
    CHECK_STR(one("[TCP:flags:PA]-xwhen{iff=L7:payload:tls_client_hello}(" T5 "," T9 ")-| \\/", b, n, &h), "9");
    /* nested: per_instance_condition is an xwhen before each action */
    CHECK_STR(one("[TCP:flags:PA]-xwhen{iff=cond_true}(xwhen{iff=cond_false}(" T5 "," T9 "),)-| \\/", b, n, NULL),
              "9");
    /* the condition comes before the action's own packets */
    CHECK_STR(one("[TCP:flags:PA]-xwhen{iff=cond_true}(xfake{blob=0x41;ttl=3}(" T5 ",),)-| \\/", b, n, NULL), "g3,5");
}

TEST(xc_stop)
{
    uint8_t b[300];
    size_t n = mk(b, P | A, NULL, 0, "GET / HTTP/1.1\r\n\r\n");
    CHECK_STR(one("[TCP:flags:PA]-xstop{iff=cond_true}(" T5 ",)-| \\/", b, n, NULL), "64");
    CHECK_STR(one("[TCP:flags:PA]-xstop{iff=cond_false}(" T5 ",)-| \\/", b, n, NULL), "5");
    CHECK_STR(one("[TCP:flags:PA]-xstop{iff=cond_payload_str;pattern=GET}(" T5 ",)-| \\/", b, n, NULL), "64");
    CHECK_STR(one("[TCP:flags:PA]-xstop{iff=cond_payload_str;pattern=GET;neg}(" T5 ",)-| \\/", b, n, NULL), "5");
    /* the packet as an action before changed it */
    CHECK_STR(one("[TCP:flags:PA]-" T9 "(xstop{iff=IP:ttl:9}(" T5 ",),)-| \\/", b, n, NULL), "9");
    /* a dropped packet stays dropped */
    CHECK_STR(one("[TCP:flags:PA]-xsplit{pos=4}(xstop{iff=cond_true}(" T5 ",),)-| \\/", b, n, NULL), "g64,g64");
}

TEST(xc_repeat)
{
    uint8_t b[300];
    size_t n = mk(b, P | A, NULL, 0, "GET / HTTP/1.1\r\n\r\n");
    CHECK_STR(one("[TCP:flags:PA]-xrepeat{repeats=3}(xfake{blob=0x41;ttl=3}," T5 ")-| \\/", b, n, NULL),
              "g3,g3,g3,5");
    CHECK_STR(one("[TCP:flags:PA]-xrepeat{repeats=0}(xfake{blob=0x41;ttl=3}," T5 ")-| \\/", b, n, NULL), "5");
    CHECK_STR(one("[TCP:flags:PA]-xrepeat{repeats=3;iff=cond_false}(xfake{blob=0x41;ttl=3}," T5 ")-| \\/", b, n,
                  NULL),
              "5");
    CHECK_STR(one("[TCP:flags:PA]-xrepeat{repeats=2;stop}(xfake{blob=0x41;ttl=3}," T5 ")-| \\/", b, n, NULL),
              "g3,g3,64");
    CHECK_STR(one("[TCP:flags:PA]-xrepeat{repeats=2;clear}(xfake{blob=0x41;ttl=3}," T5 ")-| \\/", b, n, NULL),
              "g3,g3,64");
    /* each repeat sees what the one before made of the packet: the condition
     * breaks the loop once the body changed the TTL */
    CHECK_STR(one("[TCP:flags:PA]-xrepeat{repeats=5;iff=IP:ttl:64}(xfake{blob=0x41;ttl=3}(" T9 ",),)-| \\/", b, n,
                  NULL),
              "g3,9");
    /* a body that splits: the parts again on every repeat, the original dropped */
    CHECK_STR(one("[TCP:flags:PA]-xrepeat{repeats=2}(xsplit{pos=4},)-| \\/", b, n, NULL), "g64,g64,g64,g64");
    /* duplicate in the body: the copy is a result, the original goes on */
    CHECK_STR(one("[TCP:flags:PA]-xrepeat{repeats=2}(duplicate(" T9 ",)," T5 ")-| \\/", b, n, NULL), "9,9,5");
    /* the body absorbs it */
    CHECK_STR(one("[TCP:flags:PA]-xrepeat{repeats=2}(drop," T5 ")-| \\/", b, n, NULL), "");
    /* no body: the rest only */
    CHECK_STR(one("[TCP:flags:PA]-xrepeat{repeats=2}(," T5 ")-| \\/", b, n, NULL), "5");
    /* cond_random draws on every repeat (seeded) */
    {
        int fakes = 0;
        for (int i = 0; i < 200; i++) {
            run_t r;
            r_open(&r, "[TCP:flags:PA]-xrepeat{repeats=4;iff=cond_random;percent=50}(xfake{blob=0x41},)-| \\/", 1);
            r_pkt(&r, DIR_OUT, b, n, http());
            fakes += (int)r.out.n - 1;
            r_close(&r);
        }
        /* 0.5+0.25+0.125+0.0625 = 0.9375 per packet */
        CHECK(fakes > 140 && fakes < 240);
    }
}

TEST(xc_cutoff)
{
    uint8_t b[300], bs[100];
    size_t n = mk(b, P | A, NULL, 0, "GET / HTTP/1.1\r\n\r\n");
    size_t ns = mk(bs, S | A, NULL, 0, "");
    run_t r;
    /* the tree of xcutoff is not looked at again on the flow; others are */
    r_open(&r, "[TCP:flags:PA]-xcutoff(" T5 ",)-| [TCP:flags:PA]-" T9 "-| \\/", 1);
    r_pkt(&r, DIR_OUT, b, n, NULL);
    CHECK_STR(ttls(&r.out), "5,9");
    CHECK_INT(r_pkt(&r, DIR_OUT, b, n, NULL), 1);
    CHECK_STR(ttls(&r.out), "9");
    CHECK(!xtrig_all_cut(r.st, DIR_OUT, &r.f));
    r_close(&r);
    /* the last tree: the flow then passes by the forest */
    r_open(&r, "[TCP:flags:PA]-xcutoff(" T5 ",)-| \\/", 1);
    r_pkt(&r, DIR_OUT, b, n, NULL);
    CHECK_INT(r_pkt(&r, DIR_OUT, b, n, NULL), 0);
    CHECK_STR(ttls(&r.out), "64");
    CHECK(xtrig_all_cut(r.st, DIR_OUT, &r.f));
    CHECK(!xtrig_all_cut(r.st, DIR_IN, &r.f));
    r_close(&r);
    /* dir: every tree of a forest, here the inbound one from the outbound */
    r_open(&r, "[TCP:flags:PA]-xcutoff{dir=in}(" T5 ",)-| \\/ [TCP:flags:SA]-" T9 "-|", 1);
    r_pkt(&r, DIR_IN, bs, ns, NULL);
    CHECK_STR(ttls(&r.out), "9");
    r_pkt(&r, DIR_OUT, b, n, NULL);
    r_pkt(&r, DIR_OUT, b, n, NULL);
    CHECK_STR(ttls(&r.out), "5");
    CHECK_INT(r_pkt(&r, DIR_IN, bs, ns, NULL), 0);
    CHECK(xtrig_all_cut(r.st, DIR_IN, &r.f));
    r_close(&r);
    r_open(&r, "[TCP:flags:PA]-xcutoff{dir=both}-| [TCP:flags:PA]-" T9 "-| \\/ [TCP:flags:SA]-" T9 "-|", 1);
    r_pkt(&r, DIR_OUT, b, n, NULL);
    CHECK_INT(r_pkt(&r, DIR_OUT, b, n, NULL), 0);
    CHECK_INT(r_pkt(&r, DIR_IN, bs, ns, NULL), 0);
    r_close(&r);
    /* without a flow nothing is cut */
    r_open(&r, "[TCP:flags:PA]-xcutoff(" T5 ",)-| \\/", 0);
    r_pkt(&r, DIR_OUT, b, n, NULL);
    r_pkt(&r, DIR_OUT, b, n, NULL);
    CHECK_STR(ttls(&r.out), "5");
    r_close(&r);
    /* the cut is about the strategy: another one starts afresh on the flow */
    {
        run_t r2;
        r_open(&r, "[TCP:flags:PA]-xcutoff(" T5 ",)-| \\/", 1);
        r_open(&r2, "[TCP:flags:PA]-xcutoff(" T9 ",)-| \\/", 1);
        r_pkt(&r, DIR_OUT, b, n, NULL);
        r2.f = r.f;
        r.f.xa = NULL;
        r2.c.f = &r2.f;
        CHECK_INT(r_pkt(&r2, DIR_OUT, b, n, NULL), 1);
        CHECK_STR(ttls(&r2.out), "9");
        r_close(&r2);
        r_close(&r);
    }
    /* a reassembled message: cut once its last piece went through, so the
     * second piece still meets xsplit, which drops it (replay_drop) */
    {
        xl7_view v = *http();
        v.data = (const uint8_t *)"GET / HTTP/1.1\r\n\r\n";
        v.len = 18;
        v.pieces = 2;
        v.piece = 1;
        r_open(&r, "[TCP:flags:PA]-xcutoff(xsplit{pos=4},)-| \\/", 1);
        r_pkt(&r, DIR_OUT, b, n, &v);
        CHECK_STR(ttls(&r.out), "g64,g64");
        v.piece = 2;
        CHECK_INT(r_pkt(&r, DIR_OUT, b, n, &v), 1);
        CHECK_STR(ttls(&r.out), "");
        CHECK(xtrig_all_cut(r.st, DIR_OUT, &r.f));
        r_close(&r);
    }
    /* more trees than the cut bits hold: dir= still lets the flow pass by */
    {
        sbuf big;
        sb_init(&big);
        sb_puts(&big, "[TCP:flags:PA]-xcutoff{dir=out}-|");
        for (int i = 0; i < CT_MAX_TREES + 2; i++)
            sb_puts(&big, " [TCP:flags:S]-drop-|");
        sb_puts(&big, " \\/");
        r_open(&r, big.data, 1);
        r_pkt(&r, DIR_OUT, b, n, NULL);
        CHECK(xtrig_all_cut(r.st, DIR_OUT, &r.f));
        r_close(&r);
        sb_free(&big);
    }
    /* a condition never cuts a tree off: FLOW:n behind for good */
    r_open(&r, "[TCP:flags:PA]-xwhen{iff=FLOW:n:<1}(" T5 "," T9 ")-| \\/", 1);
    r.f.client.pcounter = 5;
    r_pkt(&r, DIR_OUT, b, n, NULL);
    CHECK_STR(ttls(&r.out), "9");
    r_pkt(&r, DIR_OUT, b, n, NULL);
    CHECK_STR(ttls(&r.out), "9");
    r_close(&r);
}

void suite_xcomb(void)
{
    strategy_set_xact(&xact_ops);
    strategy_set_xtrig(&xtrig_ops);
    blob_reset();
    RUN(xc_parse);
    RUN(xc_when);
    RUN(xc_stop);
    RUN(xc_repeat);
    RUN(xc_cutoff);
    strategy_set_xtrig(NULL);
    strategy_set_xact(NULL);
    blob_free_all();
}

#else
void suite_xcomb(void) {}
#endif
