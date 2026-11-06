/* Stage X5a: the x-actions (src/ext/xact.c, xact_tcp.c), the blobs
 * (blob.c), tls_mod and genhost (tls.c) and the engine's ordering of the
 * packets they make. The expectations follow zapret2's Lua functions
 * (zapret-antidpi.lua, zapret-lib.lua) step by step. */
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "engine_int.h"
#include "ext/ext.h"
#include "ext_opt.h"
#include "pkt.h"
#include "rng.h"
#include "strategy.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/blob.h"
#  include "ext/ctrack.h"
#  include "ext/l7.h"
#  include "ext/quic.h"
#  include "ext/tls.h"
#  include "ext/xact.h"
#  include "ext/xl7.h"
#  include "ext/xtrig.h"

enum { F = 1, S = 2, R = 4, P = 8, A = 16, U = 32 };

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8), p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, v >> 16), put16(p + 2, v & 0xffff); }
static unsigned get16(const uint8_t *p) { return (unsigned)p[0] << 8 | p[1]; }

/* 10.0.0.1:40000 -> 10.0.0.2:443 (or [fd00::1] -> [fd00::2] with v6), TCP
 * with options opt (olen, a multiple of 4) or UDP */
static size_t mkpkt(uint8_t *b, int v6, int udp, unsigned flags, uint32_t seq, const uint8_t *opt, size_t olen,
                    const uint8_t *d, size_t dl)
{
    size_t l3 = v6 ? 40 : 20, l4h = udp ? 8 : 20 + olen, l4 = l4h + dl;
    uint8_t *t = b + l3;
    memset(b, 0, l3 + l4h);
    if (v6) {
        b[0] = 0x60;
        put16(b + 4, (unsigned)l4);
        b[6] = udp ? 17 : 6;
        b[7] = 64;
        b[8] = 0xfd, b[23] = 1;
        b[24] = 0xfd, b[39] = 2;
    } else {
        b[0] = 0x45;
        put16(b + 2, (unsigned)(20 + l4));
        put16(b + 4, 0x1234);
        b[6] = 0x40; /* DF */
        b[8] = 64;
        b[9] = udp ? 17 : 6;
        b[12] = 10, b[15] = 1;
        b[16] = 10, b[19] = 2;
    }
    put16(t, 40000);
    put16(t + 2, 443);
    if (udp) {
        put16(t + 4, (unsigned)l4);
    } else {
        put32(t + 4, seq);
        put32(t + 8, 7777);
        t[12] = (uint8_t)((5 + olen / 4) << 4);
        t[13] = (uint8_t)flags;
        put16(t + 14, 64000);
        if (olen)
            memcpy(t + 20, opt, olen);
    }
    if (dl)
        memcpy(t + l4h, d, dl);
    return l3 + l4;
}

static const char http_req[] = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n";
#  define HTTP_LEN (sizeof(http_req) - 1)
#  define SEQ 100000u

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

static const char *round_trip(const char *s)
{
    static char buf[600];
    sbuf e, o;
    strategy *st;
    sb_init(&e);
    sb_init(&o);
    st = strategy_parse(s, &e);
    if (st)
        strategy_print(st, &o);
    snprintf(buf, sizeof(buf), "%s", st ? o.data : e.data);
    strategy_free(st);
    sb_free(&e);
    sb_free(&o);
    return buf;
}

/* runs raw through the outbound forest of s with a context (view v, flow
 * f); the results in out */
static void runx(const char *s, const uint8_t *raw, size_t n, const xl7_view *v, ct_flow *f, xpkt_ctx *cx,
                 pktlist *out)
{
    sbuf e;
    strategy *st;
    xpkt_ctx c0;
    xpkt_ctx *c = cx ? cx : &c0;
    out->n = 0;
    sb_init(&e);
    st = strategy_parse(s, &e);
    if (!st)
        fprintf(stderr, "  %s: %s\n", s, e.data);
    CHECK(st != NULL);
    if (st) {
        if (!cx)
            memset(c, 0, sizeof(*c));
        c->st = st;
        c->f = f;
        c->l7 = v;
        strategy_apply_x(st, pkt_parse(raw, n), DIR_OUT, out, c);
        c->st = NULL;
    }
    strategy_free(st);
    sb_free(&e);
}

static xl7_view http_view(void)
{
    xl7_view v;
    memset(&v, 0, sizeof(v));
    v.l7 = L7_HTTP;
    v.l7p = L7P_HTTP_REQ;
    v.data = (const uint8_t *)http_req;
    v.len = HTTP_LEN;
    v.host = "example.com";
    return v;
}

static size_t http_pkt(uint8_t *b) { return mkpkt(b, 0, 0, P | A, SEQ, NULL, 0, (const uint8_t *)http_req, HTTP_LEN); }

/* the packet i of out rebuilt and parsed again: what goes on the wire */
static gpkt *wire(pktlist *out, size_t i)
{
    size_t n;
    uint8_t *b = pkt_bytes(out->v[i], &n);
    gpkt *p = pkt_parse(b, n);
    free(b);
    return p;
}

/* the TCP checksum of the bytes is right */
static int l4sum_ok(gpkt *p)
{
    size_t n;
    uint8_t *b = pkt_bytes(p, &n);
    size_t l3 = (size_t)(b[0] & 15) * 4, l4 = n - l3;
    uint32_t s = 0;
    s += get16(b + 12) + get16(b + 14) + get16(b + 16) + get16(b + 18);
    s += 6 + (uint32_t)l4;
    {
        uint16_t c = inet_csum(b + l3, l4, s);
        free(b);
        return c == 0;
    }
}

/* ---- parsing ---------------------------------------------------------------------- */

TEST(xact_parse)
{
    strategy_set_xact(&xact_ops);
    blob_reset();
    CHECK_STR(parse_err("[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=auto:-2:3-20;repeats=2}-| \\/"), "OK");
    CHECK_STR(parse_err("[TCP:flags:PA]-xfake{blob=fake_default_tls;tlsmod=rnd,dupsid;ip_ttl=3;tcp_md5}-| \\/"),
              "OK");
    CHECK_STR(parse_err("[TCP:flags:PA]-xsplit{pos=1,midsld;seqovl=5;seqovl_pattern=0x1603}-| \\/"), "OK");
    CHECK_STR(parse_err("[TCP:flags:PA]-xdisorder{pos=host,endhost;seqovl=1}-| \\/"), "OK");
    CHECK_STR(parse_err("[TCP:flags:PA]-xtcpseg{pos=0,-1;seqovl=#fake_default_tls}-| \\/"), "OK");
    CHECK_STR(parse_err("[TCP:flags:PA]-xhostfake{midhost=midsld;disorder_after=-5;nofake1}-| \\/"), "OK");
    CHECK_STR(parse_err("[TCP:flags:PA]-xfakedsplit{pos=method+2;pattern=0x00ff;nofake3}-| \\/"), "OK");
    CHECK_STR(parse_err("[TCP:flags:PA]-xfakeddisorder{pos=midsld;seqovl=1}-| \\/"), "OK");
    CHECK_STR(parse_err("[TCP:flags:PA]-xsend{ipfrag;ipfrag_pos_tcp=16;ipfrag_disorder;delay=10}-| \\/"), "OK");
    CHECK_STR(parse_err("[TCP:flags:PA]-xmod{flags+=SYN,ack;flags-=PSH;seq=-5;ipid=zero}-| \\/"), "OK");
    CHECK_STR(parse_err("[TCP:flags:PA]-xsplit-| \\/"), "OK");
    CHECK_STR(parse_err("\\/ [TCP:flags:SA]-xmod{ttl=5}-|"), "OK");
    CHECK_STR(parse_err("[IP:version:6]-xmod{ip6ext=hopbyhop,destopt:0x000000000000,ah}-| \\/"), "OK");
    CHECK_STR(parse_err("[TCP:flags:PA]-xmod{ip6_hopbyhop;ip6_ah=0x0102030405060708090a}-| \\/"), "OK");

    CHECK(strstr(parse_err("\\/ [TCP:flags:SA]-xfake{blob=x}-|"), "cannot be used in the inbound forest"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{ttl=3}-| \\/"), "'blob' arg required"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;nosuch=1}-| \\/"), "unknown parameter \"nosuch\""));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;ttl=1;ip_ttl=2;ttl=3}-| \\/"), "given twice"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;tcp_seq=1;seq=2}-| \\/"), "given twice"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;;ttl=1}-| \\/"), "empty parameter"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;ttl=300}-| \\/"), "bad ttl"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;ttl=auto:-2:20-3}-| \\/"), "bad ttl"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;ttl}-| \\/"), "ttl needs a value"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;ip6_ttl}-| \\/"), "ip6_ttl needs a value"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;ip6_autottl}-| \\/"), "ip6_autottl needs a value"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;badsum=1}-| \\/"), "badsum takes no value"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;md5=0x01}-| \\/"), "bad md5"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;flags+=SYN,XYZ}-| \\/"), "bad TCP flags"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;ipid=inc}-| \\/"), "bad ipid"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;repeats=1001}-| \\/"), "bad repeats"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;ifout=0123456789abcdef}-| \\/"), "bad ifout"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;payload=nosuch}-| \\/"), "unknown payload"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=x;tlsmod=bogus}-| \\/"), "invalid tls mod list"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=0x123}-| \\/"), "bad hex"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfake{blob=1abc}-| \\/"), "bad blob name"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xsend{ipfrag=ipfrag3}-| \\/"), "unknown ipfrag function"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xsend{ipfrag_pos_tcp=12}-| \\/"), "multiple of 8"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xsend{delay=-1}-| \\/"), "bad delay"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xsend{payload=all}-| \\/"), "unknown parameter"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xhostfake{ipfrag}-| \\/"), "unknown parameter"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xmod{ip6ext=hopbyhop:0x00}-| \\/"), "bad ip6ext"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xmod{ip6_ah=0x0001020304050607}-| \\/"), "bad ip6_ah"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xsplit{pos=nosuch}-| \\/"), "nosuch"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xsplit{nodrop=1}-| \\/"), "nodrop takes no value"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xtcpseg{seqovl=1}-| \\/"), "no pos specified"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xtcpseg{pos=1}-| \\/"), "two markers"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xdisorder{legacy;nodrop}-| \\/"), "legacy takes no"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xdisorder{seqovl=bad}-| \\/"), "bad seqovl marker"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfakedsplit{pos=1,2}-| \\/"), "one marker"));
    CHECK(strstr(parse_err("[TCP:flags:PA]-xfakedsplit{seqovl=midsld}-| \\/"), "bad seqovl"));

    /* printed as written; commas inside braces do not split subtrees */
    CHECK_STR(round_trip("[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=3;md5}(xdisorder{pos=1,midsld},)-| \\/"),
              "[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=3;md5}(xdisorder{pos=1,midsld},)-| \\/");
    CHECK_STR(round_trip("[TCP:flags:PA]-xsplit(xmod{ttl=1},)-| \\/"), "[TCP:flags:PA]-xsplit(xmod{ttl=1},)-| \\/");
    CHECK_STR(round_trip("[TCP:flags:PA]-xsplit{pos=1}(duplicate(,drop),)-| \\/"),
              "[TCP:flags:PA]-xsplit{pos=1}(duplicate(,drop),)-| \\/");
    /* an x-action takes one subtree */
    CHECK(strcmp(parse_err("[TCP:flags:PA]-xsplit(drop,drop)-| \\/"), "OK") != 0);

    /* not known without --ext */
    strategy_set_xact(NULL);
    CHECK(strstr(parse_err("[TCP:flags:PA]-xsplit-| \\/"), "xsplit"));
    strategy_set_xact(&xact_ops);
}

/* ---- the actions ---------------------------------------------------------------------- */

TEST(xact_fake)
{
    uint8_t b[2000];
    size_t n = http_pkt(b);
    xl7_view v = http_view();
    pktlist out = {0};
    const xblob *fh = blob_find("fake_default_http");
    gpkt *q;
    CHECK(fh != NULL);
    if (!fh)
        return;
    rng_global_seed(1);
    runx("[TCP:flags:PA]-xfake{blob=fake_default_http;ttl=3;md5;repeats=2;fwmark=0x40;ifout=eth1}-| \\/", b, n, &v,
         NULL, NULL, &out);
    CHECK_INT(out.n, 3);
    for (size_t i = 0; i < 2 && out.n == 3; i++) {
        q = wire(&out, i);
        CHECK(out.v[i]->xgen && !out.v[i]->xdrop);
        CHECK_INT(out.v[i]->xmark, 0x40);
        CHECK_STR(out.v[i]->xifout, "eth1");
        CHECK_INT(q->ttl, 3);
        CHECK_INT(q->seq, SEQ);
        CHECK(q->nopts >= 1 && q->opts[0].kind == 19 && q->opts[0].len == 16);
        CHECK_MEM(q->payload, q->payload_len, fh->data, fh->len);
        CHECK(l4sum_ok(q));
        pkt_free(q);
    }
    if (out.n == 3) {
        CHECK(!out.v[2]->xgen);
        CHECK_INT(out.v[2]->ttl, 64);
        CHECK_INT(out.v[2]->payload_len, HTTP_LEN);
    }
    pktlist_free(&out);

    /* the default payload filter is "known": nothing on unknown data */
    runx("[TCP:flags:PA]-xfake{blob=fake_default_http}-| \\/", b, n, NULL, NULL, NULL, &out);
    CHECK_INT(out.n, 1);
    pktlist_free(&out);
    runx("[TCP:flags:PA]-xfake{blob=fake_default_http;payload=all}-| \\/", b, n, NULL, NULL, NULL, &out);
    CHECK_INT(out.n, 2);
    pktlist_free(&out);
    runx("[TCP:flags:PA]-xfake{blob=fake_default_http;payload=tls_client_hello}-| \\/", b, n, &v, NULL, NULL, &out);
    CHECK_INT(out.n, 1);
    pktlist_free(&out);
    /* an absent optional blob: skipped; a hex blob */
    runx("[TCP:flags:PA]-xfake{blob=nosuch;optional}-| \\/", b, n, &v, NULL, NULL, &out);
    CHECK_INT(out.n, 1);
    pktlist_free(&out);
    runx("[TCP:flags:PA]-xfake{blob=0x16030100}-| \\/", b, n, &v, NULL, NULL, &out);
    CHECK_INT(out.n, 2);
    if (out.n == 2)
        CHECK_MEM(out.v[0]->payload, out.v[0]->payload_len, "\x16\x03\x01\x00", 4);
    pktlist_free(&out);
    /* only the first piece of a replay */
    v.piece = 2, v.pieces = 2;
    runx("[TCP:flags:PA]-xfake{blob=fake_default_http}-| \\/", b, n, &v, NULL, NULL, &out);
    CHECK_INT(out.n, 1);
    pktlist_free(&out);
    /* UDP */
    n = mkpkt(b, 0, 1, 0, 0, NULL, 0, (const uint8_t *)"xyz", 3);
    runx("[UDP:dport:443]-xfake{blob=fake_default_quic;payload=all;ip_ttl=1}-| \\/", b, n, NULL, NULL, NULL, &out);
    CHECK_INT(out.n, 2);
    if (out.n == 2) {
        q = wire(&out, 0);
        CHECK_INT(q->payload_len, 620);
        CHECK_INT(q->ttl, 1);
        CHECK_INT(q->udplen, 628);
        pkt_free(q);
    }
    pktlist_free(&out);
}

/* the seq offsets from SEQ and the lengths of out, as "off:len,..."; "D"
 * marks a dropped packet (never a result), "o" the original */
static const char *layout(pktlist *out)
{
    static char buf[400];
    size_t k = 0;
    buf[0] = 0;
    for (size_t i = 0; i < out->n && k < sizeof(buf) - 40; i++) {
        gpkt *p = out->v[i];
        k += (size_t)snprintf(buf + k, sizeof(buf) - k, "%s%s%ld:%zu", i ? "," : "", p->xgen ? "" : "o",
                              (long)(int32_t)(p->seq - SEQ), p->payload_len);
    }
    return buf;
}

/* the parts put together by seq give the request back */
static int covers(pktlist *out, int with_orig)
{
    char got[sizeof(http_req)];
    memset(got, '?', HTTP_LEN);
    for (size_t i = 0; i < out->n; i++) {
        const gpkt *p = out->v[i];
        long off = (long)(int32_t)(p->seq - SEQ);
        if (!p->xgen && !with_orig)
            continue;
        if (p->ttl != 64)
            continue; /* a fake */
        for (size_t j = 0; j < p->payload_len; j++)
            if (off + (long)j >= 0 && off + (long)j < (long)HTTP_LEN)
                got[off + (long)j] = (char)p->payload[j];
    }
    return !memcmp(got, http_req, HTTP_LEN);
}

TEST(xact_split_disorder)
{
    uint8_t b[2000];
    size_t n = http_pkt(b);
    xl7_view v = http_view();
    pktlist out = {0};
    char exp[100];

    runx("[TCP:flags:PA]-xsplit{pos=5,host}-| \\/", b, n, &v, NULL, NULL, &out);
    snprintf(exp, sizeof(exp), "0:5,5:17,22:%zu", HTTP_LEN - 22);
    CHECK_STR(layout(&out), exp);
    CHECK(covers(&out, 0));
    pktlist_free(&out);
    /* default pos 2; nodrop keeps the original */
    runx("[TCP:flags:PA]-xsplit{nodrop}-| \\/", b, n, &v, NULL, NULL, &out);
    snprintf(exp, sizeof(exp), "0:2,2:%zu,o0:%zu", HTTP_LEN - 2, HTTP_LEN);
    CHECK_STR(layout(&out), exp);
    pktlist_free(&out);
    /* seqovl: the first part starts earlier with the pattern */
    runx("[TCP:flags:PA]-xsplit{pos=5;seqovl=3;seqovl_pattern=0x41}-| \\/", b, n, &v, NULL, NULL, &out);
    snprintf(exp, sizeof(exp), "-3:8,5:%zu", HTTP_LEN - 5);
    CHECK_STR(layout(&out), exp);
    if (out.n == 2)
        CHECK_MEM(out.v[0]->payload, 8, "AAAGET /", 8);
    pktlist_free(&out);
    /* seqovl through a "#" prefix: the length of a blob */
    CHECK_INT(blob_opt("three:0x010203", NULL), 0);
    runx("[TCP:flags:PA]-xsplit{pos=5;seqovl=#three}-| \\/", b, n, &v, NULL, NULL, &out);
    snprintf(exp, sizeof(exp), "-3:8,5:%zu", HTTP_LEN - 5);
    CHECK_STR(layout(&out), exp);
    if (out.n == 2)
        CHECK_MEM(out.v[0]->payload, 3, "\0\0\0", 3);
    pktlist_free(&out);
    /* positions at 0 or out of the data do not split */
    runx("[TCP:flags:PA]-xsplit{pos=0,5000}-| \\/", b, n, &v, NULL, NULL, &out);
    snprintf(exp, sizeof(exp), "o0:%zu", HTTP_LEN);
    CHECK_STR(layout(&out), exp);
    pktlist_free(&out);
    /* the parts of a blob instead of the payload */
    runx("[TCP:flags:PA]-xsplit{pos=2;blob=0x41424344}-| \\/", b, n, &v, NULL, NULL, &out);
    CHECK_STR(layout(&out), "0:2,2:2");
    pktlist_free(&out);
    /* a replay: the first piece splits the whole message, the rest go */
    v.pieces = 2, v.piece = 1;
    {
        ct_flow f;
        memset(&f, 0, sizeof(f));
        runx("[TCP:flags:PA]-xsplit{pos=5}-| \\/", b, n, &v, &f, NULL, &out);
        snprintf(exp, sizeof(exp), "0:5,5:%zu", HTTP_LEN - 5);
        CHECK_STR(layout(&out), exp);
        pktlist_free(&out);
        v.piece = 2;
        /* runx parses anew: the slot is per x-action, so keep one strategy */
        {
            sbuf e;
            strategy *st;
            xpkt_ctx c;
            sb_init(&e);
            st = strategy_parse("[TCP:flags:PA]-xsplit{pos=5}-| \\/", &e);
            memset(&c, 0, sizeof(c));
            c.st = st, c.f = &f, c.l7 = &v;
            v.piece = 1;
            strategy_apply_x(st, pkt_parse(b, n), DIR_OUT, &out, &c);
            CHECK_INT(out.n, 2);
            pktlist_free(&out);
            v.piece = 2;
            strategy_apply_x(st, pkt_parse(b, n), DIR_OUT, &out, &c);
            CHECK_INT(out.n, 0); /* replay_drop */
            pktlist_free(&out);
            v.piece = 0, v.pieces = 0;
            strategy_apply_x(st, pkt_parse(b, n), DIR_OUT, &out, &c);
            CHECK_INT(out.n, 2);
            pktlist_free(&out);
            strategy_free(st);
            sb_free(&e);
        }
        xact_flow_clear(&f);
    }
    v.pieces = v.piece = 0;

    /* disorder: from the last part to the first */
    runx("[TCP:flags:PA]-xdisorder{pos=5,host}-| \\/", b, n, &v, NULL, NULL, &out);
    snprintf(exp, sizeof(exp), "22:%zu,5:17,0:5", HTTP_LEN - 22);
    CHECK_STR(layout(&out), exp);
    CHECK(covers(&out, 0));
    pktlist_free(&out);
    /* seqovl (a marker) goes into the second part, when before pos[0] */
    runx("[TCP:flags:PA]-xdisorder{pos=5,host;seqovl=2}-| \\/", b, n, &v, NULL, NULL, &out);
    snprintf(exp, sizeof(exp), "22:%zu,3:19,0:5", HTTP_LEN - 22);
    CHECK_STR(layout(&out), exp);
    pktlist_free(&out);
    runx("[TCP:flags:PA]-xdisorder{pos=5,host;seqovl=7}-| \\/", b, n, &v, NULL, NULL, &out);
    snprintf(exp, sizeof(exp), "22:%zu,5:17,0:5", HTTP_LEN - 22);
    CHECK_STR(layout(&out), exp);
    pktlist_free(&out);
    /* legacy: the same on a whole packet */
    runx("[TCP:flags:PA]-xdisorder{pos=5,host;legacy}-| \\/", b, n, &v, NULL, NULL, &out);
    snprintf(exp, sizeof(exp), "22:%zu,5:17,0:5", HTTP_LEN - 22);
    CHECK_STR(layout(&out), exp);
    pktlist_free(&out);
    /* legacy on a later piece: positions inside it, relative to it */
    {
        size_t n2 = mkpkt(b, 0, 0, P | A, SEQ, NULL, 0, (const uint8_t *)http_req + 20, HTTP_LEN - 20);
        v.pieces = 2, v.piece = 2, v.offset = 20;
        runx("[TCP:flags:PA]-xdisorder{pos=5,host;legacy}-| \\/", b, n2, &v, NULL, NULL, &out);
        snprintf(exp, sizeof(exp), "2:%zu,0:2", HTTP_LEN - 22);
        CHECK_STR(layout(&out), exp);
        pktlist_free(&out);
        v.pieces = v.piece = 0, v.offset = 0;
    }
    /* UDP passes */
    n = mkpkt(b, 0, 1, 0, 0, NULL, 0, (const uint8_t *)"xyz", 3);
    runx("[UDP:dport:443]-xdisorder{payload=all}-| \\/", b, n, NULL, NULL, NULL, &out);
    CHECK_INT(out.n, 1);
    pktlist_free(&out);
}

TEST(xact_tcpseg_hostfake)
{
    uint8_t b[2000];
    size_t n = http_pkt(b);
    xl7_view v = http_view();
    pktlist out = {0};
    char exp[200];

    /* tcpseg sends the range and lets the packet go */
    runx("[TCP:flags:PA]-xtcpseg{pos=method+2,host}-| \\/", b, n, &v, NULL, NULL, &out);
    snprintf(exp, sizeof(exp), "2:21,o0:%zu", HTTP_LEN); /* both ends included */
    CHECK_STR(layout(&out), exp);
    if (out.n == 2)
        CHECK_MEM(out.v[0]->payload, 21, http_req + 2, 21);
    pktlist_free(&out);
    runx("[TCP:flags:PA]-xtcpseg{pos=0,-1;seqovl=4}-| \\/", b, n, &v, NULL, NULL, &out);
    snprintf(exp, sizeof(exp), "-4:%zu,o0:%zu", HTTP_LEN + 4, HTTP_LEN);
    CHECK_STR(layout(&out), exp);
    pktlist_free(&out);

    /* hostfakesplit: before the host, fake, host, fake, after */
    rng_global_seed(5);
    runx("[TCP:flags:PA]-xhostfake{ttl=4;host=cdn.org}-| \\/", b, n, &v, NULL, NULL, &out);
    snprintf(exp, sizeof(exp), "0:22,22:11,22:11,22:11,33:%zu", HTTP_LEN - 33);
    CHECK_STR(layout(&out), exp);
    if (out.n == 5) {
        CHECK_INT(out.v[0]->ttl, 64);
        CHECK_INT(out.v[1]->ttl, 4);
        CHECK_INT(out.v[2]->ttl, 64);
        CHECK_INT(out.v[3]->ttl, 4);
        CHECK_INT(out.v[4]->ttl, 64);
        CHECK_MEM(out.v[2]->payload, 11, "example.com", 11);
        CHECK(!memcmp(out.v[1]->payload + 3, ".cdn.org", 8));
        CHECK(memcmp(out.v[1]->payload, "example.com", 11) != 0);
        CHECK_MEM(out.v[1]->payload, 11, out.v[3]->payload, 11);
    }
    CHECK(covers(&out, 0));
    pktlist_free(&out);
    /* midhost, no fakes, disorder after */
    runx("[TCP:flags:PA]-xhostfake{midhost=midsld;nofake1;nofake2;disorder_after=-3}-| \\/", b, n, &v, NULL, NULL,
         &out);
    snprintf(exp, sizeof(exp), "0:22,22:3,25:8,%zu:3,33:%zu", HTTP_LEN - 3, HTTP_LEN - 36);
    CHECK_STR(layout(&out), exp);
    CHECK(covers(&out, 0));
    pktlist_free(&out);
    /* no host: the packet goes */
    {
        static const char d[] = "GET / HTTP/1.1\r\n\r\n";
        size_t n2 = mkpkt(b, 0, 0, P | A, SEQ, NULL, 0, (const uint8_t *)d, sizeof(d) - 1);
        xl7_view v2 = v;
        v2.data = (const uint8_t *)d, v2.len = sizeof(d) - 1;
        runx("[TCP:flags:PA]-xhostfake-| \\/", b, n2, &v2, NULL, NULL, &out);
        CHECK_INT(out.n, 1);
        CHECK(out.n == 1 && !out.v[0]->xgen);
        pktlist_free(&out);
    }
}

TEST(xact_faked)
{
    uint8_t b[2000];
    size_t n = http_pkt(b);
    xl7_view v = http_view();
    pktlist out = {0};
    char exp[200];
    size_t r = HTTP_LEN - 10;

    runx("[TCP:flags:PA]-xfakedsplit{pos=10;ttl=2;pattern=0x5a}-| \\/", b, n, &v, NULL, NULL, &out);
    snprintf(exp, sizeof(exp), "0:10,0:10,0:10,10:%zu,10:%zu,10:%zu", r, r, r);
    CHECK_STR(layout(&out), exp);
    if (out.n == 6) {
        static const int fake[] = {1, 0, 1, 1, 0, 1};
        for (int i = 0; i < 6; i++) {
            CHECK_INT(out.v[i]->ttl, fake[i] ? 2 : 64);
            if (fake[i])
                CHECK(out.v[i]->payload[0] == 0x5a && out.v[i]->payload[out.v[i]->payload_len - 1] == 0x5a);
        }
    }
    CHECK(covers(&out, 0));
    pktlist_free(&out);
    runx("[TCP:flags:PA]-xfakedsplit{pos=10;ttl=2;nofake1;nofake2;nofake3;nofake4;seqovl=2}-| \\/", b, n, &v, NULL,
         NULL, &out);
    snprintf(exp, sizeof(exp), "-2:12,10:%zu", r);
    CHECK_STR(layout(&out), exp);
    pktlist_free(&out);
    runx("[TCP:flags:PA]-xfakeddisorder{pos=10;ttl=2}-| \\/", b, n, &v, NULL, NULL, &out);
    snprintf(exp, sizeof(exp), "10:%zu,10:%zu,10:%zu,0:10,0:10,0:10", r, r, r);
    CHECK_STR(layout(&out), exp);
    if (out.n == 6) {
        static const int fake[] = {1, 0, 1, 1, 0, 1};
        for (int i = 0; i < 6; i++)
            CHECK_INT(out.v[i]->ttl, fake[i] ? 2 : 64);
        /* the default pattern: zeros */
        CHECK(out.v[0]->payload[0] == 0 && out.v[3]->payload[9] == 0);
    }
    CHECK(covers(&out, 0));
    pktlist_free(&out);
    /* seqovl of fakeddisorder: a marker before pos, into the second part */
    runx("[TCP:flags:PA]-xfakeddisorder{pos=10;seqovl=4;nofake1;nofake2;nofake3;nofake4;nodrop}-| \\/", b, n, &v,
         NULL, NULL, &out);
    snprintf(exp, sizeof(exp), "6:%zu,0:10,o0:%zu", r + 4, HTTP_LEN);
    CHECK_STR(layout(&out), exp);
    pktlist_free(&out);
    /* pos 0: nothing */
    runx("[TCP:flags:PA]-xfakedsplit{pos=0}-| \\/", b, n, &v, NULL, NULL, &out);
    CHECK_INT(out.n, 1);
    pktlist_free(&out);
}

/* ---- fooling, sending ------------------------------------------------------------------- */

TEST(xact_fooling)
{
    uint8_t b[2000];
    /* NOP NOP timestamp(10) */
    static const uint8_t ts[12] = {1, 1, 8, 10, 0, 0, 0, 100, 0, 0, 0, 9};
    size_t n = mkpkt(b, 0, 0, P | A, SEQ, ts, sizeof(ts), (const uint8_t *)"abc", 3);
    pktlist out = {0};
    gpkt *q;

    runx("[TCP:flags:PA]-xmod{seq=-5;ack=0x10;ts=-50;flags+=SYN,urg;flags-=PSH}-| \\/", b, n, NULL, NULL, NULL,
         &out);
    CHECK_INT(out.n, 1);
    if (out.n == 1) {
        q = wire(&out, 0);
        CHECK_INT(q->seq, SEQ - 5);
        CHECK_INT(q->ack, 7777 + 16);
        CHECK_INT(q->tcpflags, S | A | U);
        CHECK_INT(q->nopts, 3);
        CHECK_INT(q->opts[2].kind, 8);
        CHECK_MEM(q->opts[2].data, 4, "\0\0\0\x32", 4);
        CHECK(l4sum_ok(q));
        pkt_free(q);
    }
    pktlist_free(&out);
    /* nopdel removes the NOPs, tsup puts the timestamp first */
    runx("[TCP:flags:PA]-xmod{nopdel}-| \\/", b, n, NULL, NULL, NULL, &out);
    CHECK(out.n == 1 && out.v[0]->nopts == 1 && out.v[0]->opts[0].kind == 8);
    pktlist_free(&out);
    runx("[TCP:flags:PA]-xmod{tsup}-| \\/", b, n, NULL, NULL, NULL, &out);
    CHECK(out.n == 1 && out.v[0]->nopts == 3 && out.v[0]->opts[0].kind == 8 && out.v[0]->opts[1].kind == 1);
    pktlist_free(&out);
    /* md5 with given bytes */
    runx("[TCP:flags:PA]-xmod{md5=0x000102030405060708090a0b0c0d0e0f}-| \\/", b, n, NULL, NULL, NULL, &out);
    if (out.n == 1) {
        q = wire(&out, 0);
        CHECK(q->nopts >= 4 && q->opts[3].kind == 19 && q->opts[3].data[15] == 15);
        CHECK_INT(q->dataofs, 5 + 8); /* 12 + 18 bytes padded to 32 */
        pkt_free(q);
    }
    pktlist_free(&out);

    /* ipid: zero, none, seq (consecutive in a packet's context) */
    runx("[TCP:flags:PA]-xmod{ipid=zero}-| \\/", b, n, NULL, NULL, NULL, &out);
    CHECK(out.n == 1 && out.v[0]->id == 0);
    pktlist_free(&out);
    runx("[TCP:flags:PA]-xmod-| \\/", b, n, NULL, NULL, NULL, &out);
    CHECK(out.n == 1 && out.v[0]->id == 0x1234);
    pktlist_free(&out);
    {
        xl7_view v = http_view();
        size_t hn = http_pkt(b);
        runx("[TCP:flags:PA]-xsplit{pos=5,10}-| \\/", b, hn, &v, NULL, NULL, &out);
        CHECK_INT(out.n, 3);
        if (out.n == 3) {
            CHECK_INT(out.v[0]->id, 0x1234);
            CHECK_INT(out.v[1]->id, 0x1235);
            CHECK_INT(out.v[2]->id, 0x1236);
        }
        pktlist_free(&out);
        /* ipid_conn: kept on the flow from packet to packet */
        {
            ct_flow f;
            memset(&f, 0, sizeof(f));
            runx("[TCP:flags:PA]-xsplit{pos=5;ipid_conn}-| \\/", b, hn, &v, &f, NULL, &out);
            CHECK(out.n == 2 && out.v[1]->id == 0x1235);
            pktlist_free(&out);
            runx("[TCP:flags:PA]-xsplit{pos=5;ipid_conn}-| \\/", b, hn, &v, &f, NULL, &out);
            /* a new strategy (a new serial) starts again */
            CHECK(out.n == 2 && out.v[0]->id == 0x1234);
            pktlist_free(&out);
            xact_flow_clear(&f);
        }
        /* badsum: the fakes' checksums are wrong, the parts' right */
        runx("[TCP:flags:PA]-xfake{blob=fake_default_http;badsum}(xsplit{pos=5},)-| \\/", b, hn, &v, NULL, NULL,
             &out);
        CHECK_INT(out.n, 3);
        if (out.n == 3) {
            CHECK(!l4sum_ok(out.v[0]));
            CHECK(l4sum_ok(out.v[1]));
            CHECK(l4sum_ok(out.v[2]));
        }
        pktlist_free(&out);
        /* rnd */
        runx("[TCP:flags:PA]-xsplit{pos=5;ipid=rnd}-| \\/", b, hn, &v, NULL, NULL, &out);
        CHECK(out.n == 2 && out.v[0]->id != 0);
        pktlist_free(&out);
    }

    /* autottl from the flow's incoming TTL: 64 - 57 = 7 hops, minus 2 */
    {
        ct_flow f;
        xl7_view v = http_view();
        size_t hn = http_pkt(b);
        memset(&f, 0, sizeof(f));
        f.incoming_ttl = 57;
        runx("[TCP:flags:PA]-xfake{blob=fake_default_http;ttl=auto:-2:3-20}-| \\/", b, hn, &v, &f, NULL, &out);
        CHECK(out.n == 2 && out.v[0]->ttl == 5);
        pktlist_free(&out);
        xact_flow_clear(&f);
        /* clamped to the minimum, then too far: the fixed ttl stays */
        f.incoming_ttl = 62;
        runx("[TCP:flags:PA]-xfake{blob=fake_default_http;ttl=auto:-2:3-20}-| \\/", b, hn, &v, &f, NULL, &out);
        CHECK(out.n == 2 && out.v[0]->ttl == 64);
        pktlist_free(&out);
        xact_flow_clear(&f);
        f.incoming_ttl = 0;
        runx("[TCP:flags:PA]-xfake{blob=fake_default_http;ip_autottl=-1,3-20}-| \\/", b, hn, &v, &f, NULL, &out);
        CHECK(out.n == 2 && out.v[0]->ttl == 64);
        pktlist_free(&out);
        xact_flow_clear(&f);
        f.incoming_ttl = 116; /* 128: 12 hops */
        runx("[TCP:flags:PA]-xfake{blob=fake_default_http;ip_autottl=-1,3-20;ip_ttl=9}-| \\/", b, hn, &v, &f, NULL,
             &out);
        CHECK(out.n == 2 && out.v[0]->ttl == 11);
        pktlist_free(&out);
        xact_flow_clear(&f);
    }
}

TEST(xact_ipv6)
{
    uint8_t b[2000];
    size_t n = mkpkt(b, 1, 0, P | A, SEQ, NULL, 0, (const uint8_t *)http_req, HTTP_LEN);
    xl7_view v = http_view();
    pktlist out = {0};
    gpkt *q;

    runx("[TCP:flags:PA]-xmod{ip6ext=hopbyhop,destopt,routing,destopt2,ah;ttl=7}-| \\/", b, n, NULL, NULL, NULL,
         &out);
    CHECK_INT(out.n, 1);
    if (out.n == 1) {
        size_t offs[8];
        int k = 0;
        uint8_t nh;
        q = wire(&out, 0);
        CHECK_INT(q->hlim, 7);
        /* hop-by-hop, destopt, routing, destopt, AH, then TCP */
        nh = q->nh;
        for (size_t o = 0; o + 2 <= q->ext_len && k < 8; k++) {
            offs[k] = nh;
            nh = q->ext[o];
            o += offs[k] == 51 ? ((size_t)q->ext[o + 1] + 2) * 4 : ((size_t)q->ext[o + 1] + 1) * 8;
        }
        CHECK_INT(k, 5);
        if (k == 5) {
            CHECK_INT(offs[0], 0);
            CHECK_INT(offs[1], 60);
            CHECK_INT(offs[2], 43);
            CHECK_INT(offs[3], 60);
            CHECK_INT(offs[4], 51);
        }
        CHECK_INT(nh, 6);
        CHECK_INT(q->ext_len, 8 * 5); /* AH: 0000 and 4 random bytes */
        CHECK_INT(q->l4, LAYER_TCP);
        CHECK_INT(q->payload_len, HTTP_LEN);
        pkt_free(q);
    }
    pktlist_free(&out);

    /* ipfrag2 over IPv6: the fragment header after hop-by-hop */
    runx("[TCP:flags:PA]-xsend{ip6_hopbyhop;ipfrag;ipfrag_pos_tcp=24}-| \\/", b, n, &v, NULL, NULL, &out);
    CHECK_INT(out.n, 3);
    if (out.n == 3) {
        size_t n1, n2;
        uint8_t *b1 = pkt_bytes(out.v[0], &n1), *b2 = pkt_bytes(out.v[1], &n2);
        CHECK_INT(b1[6], 0);       /* hop-by-hop */
        CHECK_INT(b1[40], 44);     /* then the fragment header */
        CHECK_INT(b1[48], 6);      /* for TCP */
        CHECK_INT(get16(b1 + 50), 1); /* offset 0, more */
        CHECK_INT(n1, 40 + 8 + 8 + 24);
        CHECK_INT(get16(b2 + 50), 24);
        CHECK_INT(n2, 40 + 8 + 8 + 20 + HTTP_LEN - 24);
        CHECK(!memcmp(b1 + 52, b2 + 52, 4)); /* one identification */
        CHECK_INT(get16(b1 + 4), n1 - 40);
        CHECK_INT(get16(b2 + 4), n2 - 40);
        free(b1);
        free(b2);
        CHECK(!out.v[2]->xgen);
    }
    pktlist_free(&out);
    /* ipfrag_next changes the second fragment's next header */
    runx("[TCP:flags:PA]-xsend{ipfrag;ipfrag_next=59}-| \\/", b, n, &v, NULL, NULL, &out);
    if (out.n == 3) {
        size_t n1, n2;
        uint8_t *b1 = pkt_bytes(out.v[0], &n1), *b2 = pkt_bytes(out.v[1], &n2);
        CHECK_INT(b1[6], 44);
        CHECK_INT(b1[40], 6);
        CHECK_INT(b2[40], 59);
        CHECK_INT(get16(b2 + 42), 32);
        free(b1);
        free(b2);
    }
    pktlist_free(&out);
}

TEST(xact_ipfrag_mss)
{
    uint8_t b[4000], big[3000];
    size_t n = http_pkt(b);
    xl7_view v = http_view();
    pktlist out = {0};

    runx("[TCP:flags:PA]-xsend{ipfrag;ipfrag_pos_tcp=16}-| \\/", b, n, &v, NULL, NULL, &out);
    CHECK_INT(out.n, 3);
    if (out.n == 3) {
        gpkt *f1 = out.v[0], *f2 = out.v[1];
        CHECK_INT(f1->iplen, 20 + 16);
        CHECK_INT(f1->ipflags, 1); /* MF, no DF */
        CHECK_INT(f1->frag, 0);
        CHECK_INT(f2->iplen, 20 + 20 + HTTP_LEN - 16);
        CHECK_INT(f2->frag, 2);
        CHECK_INT(f2->ipflags, 0);
        CHECK_INT(f1->id, f2->id);
        CHECK(out.v[0]->xgen && out.v[1]->xgen && !out.v[2]->xgen);
    }
    pktlist_free(&out);
    runx("[TCP:flags:PA]-xsend{ipfrag;ipfrag_disorder;repeats=2}-| \\/", b, n, &v, NULL, NULL, &out);
    CHECK_INT(out.n, 5);
    if (out.n == 5)
        CHECK(out.v[0]->frag == 4 && out.v[1]->frag == 4 && out.v[2]->frag == 0 && out.v[3]->frag == 0);
    pktlist_free(&out);
    /* too short to fragment at 32: sent whole */
    {
        size_t n2 = mkpkt(b, 0, 0, P | A, SEQ, NULL, 0, (const uint8_t *)"abc", 3);
        runx("[TCP:flags:PA]-xsend{ipfrag}-| \\/", b, n2, NULL, NULL, NULL, &out);
        CHECK(out.n == 2 && out.v[0]->frag == 0 && out.v[0]->payload_len == 3);
        pktlist_free(&out);
    }
    /* delay: the copy waits */
    n = http_pkt(b);
    runx("[TCP:flags:PA]-xsend{delay=250;ttl=1}-| \\/", b, n, &v, NULL, NULL, &out);
    CHECK(out.n == 2 && out.v[0]->sleep > 0.24 && out.v[0]->sleep < 0.26 && out.v[0]->ttl == 1 &&
          out.v[1]->sleep == 0);
    pktlist_free(&out);

    /* MSS: parts longer than the MSS less the options go in segments */
    for (size_t i = 0; i < sizeof(big); i++)
        big[i] = (uint8_t)('a' + i % 26);
    memcpy(big, "GET / HTTP/1.1\r\nHost: example.com\r\n", 35);
    n = mkpkt(b, 0, 0, P | A, SEQ, NULL, 0, big, sizeof(big));
    v.data = big, v.len = sizeof(big);
    runx("[TCP:flags:PA]-xsplit{pos=2;md5}-| \\/", b, n, &v, NULL, NULL, &out);
    /* 2, then 2998 in 1200 (1220 less 20 of MD5) */
    CHECK_STR(layout(&out), "0:2,2:1200,1202:1200,2402:598");
    pktlist_free(&out);
    {
        ct_flow f;
        memset(&f, 0, sizeof(f));
        f.client.mss = 1460, f.server.mss = 1000;
        runx("[TCP:flags:PA]-xsplit{pos=2}-| \\/", b, n, &v, &f, NULL, &out);
        CHECK_STR(layout(&out), "0:2,2:1000,1002:1000,2002:998");
        pktlist_free(&out);
        xact_flow_clear(&f);
    }
    /* URG: the pointer goes with its segment */
    n = mkpkt(b, 0, 0, P | A | U, SEQ, NULL, 0, big, sizeof(big));
    put16(b + 20 + 18, 1500);
    runx("[TCP:flags:PAU]-xsplit{pos=2}-| \\/", b, n, &v, NULL, NULL, &out);
    CHECK_INT(out.n, 4);
    if (out.n == 4) {
        CHECK(out.v[0]->tcpflags & U);
        CHECK_INT(out.v[0]->urgptr, 1500); /* the first part: as it was */
        CHECK(!(out.v[1]->tcpflags & U));
        CHECK(out.v[2]->tcpflags & U);
        CHECK_INT(out.v[2]->urgptr, 1500 - 1220); /* relative to the part */
        CHECK(!(out.v[3]->tcpflags & U));
    }
    pktlist_free(&out);
}

TEST(xact_meta)
{
    uint8_t b[2000];
    size_t n = http_pkt(b);
    xl7_view v = http_view();
    pktlist out = {0};
    xpkt_ctx c;
    memset(&c, 0, sizeof(c));
    c.has_meta = 1;
    c.mark = 0x100;
    c.ifout = "wan0";
    runx("[TCP:flags:PA]-xfake{blob=fake_default_http}-| \\/", b, n, &v, NULL, &c, &out);
    CHECK(out.n == 2 && out.v[0]->xmark == 0x100 && !strcmp(out.v[0]->xifout, "wan0"));
    pktlist_free(&out);
    memset(&c, 0, sizeof(c));
    c.has_meta = 1;
    c.mark = 0x100;
    runx("[TCP:flags:PA]-xfake{blob=fake_default_http;fwmark=0x20000000;ifout=ppp1}-| \\/", b, n, &v, NULL, &c, &out);
    CHECK(out.n == 2 && out.v[0]->xmark == 0x20000000 && !strcmp(out.v[0]->xifout, "ppp1"));
    pktlist_free(&out);
    /* a dropped packet goes on down the tree, then is no result */
    runx("[TCP:flags:PA]-xsplit{pos=5}(xfake{blob=fake_default_http},)-| \\/", b, n, &v, NULL, NULL, &out);
    CHECK_INT(out.n, 3);
    if (out.n == 3)
        CHECK(out.v[2]->payload_len == blob_find("fake_default_http")->len);
    pktlist_free(&out);
    /* Geneva actions under an x-action */
    runx("[TCP:flags:PA]-xmod{ttl=9}(duplicate,)-| \\/", b, n, &v, NULL, NULL, &out);
    CHECK(out.n == 2 && out.v[0]->ttl == 9 && out.v[1]->ttl == 9);
    pktlist_free(&out);
}

/* ---- blobs, tls_mod ---------------------------------------------------------------------- */

TEST(xact_blobs)
{
    const xblob *t = blob_find("fake_default_tls"), *h = blob_find("fake_default_http"),
                *q = blob_find("fake_default_quic");
    char host[300];
    sbuf e;
    CHECK(t && h && q);
    if (!t || !h || !q)
        return;
    CHECK_INT(t->len, 680);
    CHECK(l7_is_tls_hello(t->data, t->len, 1, 0));
    CHECK_INT(l7_tls_host(t->data, t->len, host, sizeof(host), 0), 1);
    CHECK_STR(host, "www.iana.org");
    CHECK(l7_is_http(h->data, h->len));
    CHECK_INT(l7_http_host(h->data, h->len, host, sizeof(host)), 1);
    CHECK_STR(host, "www.iana.org");
    CHECK_INT(q->len, 620);
    CHECK(q->data[0] == 0x40 && q->data[619] == 0);
    {
        int l7;
        CHECK_INT(l7_probe(t->data, t->len, 1, 0, 1, 0, &l7), L7P_TLS_CLIENT_HELLO);
        CHECK_INT(l7_probe(h->data, h->len, 1, 0, 1, 0, &l7), L7P_HTTP_REQ);
    }
    /* the generator: the same seed, the same bytes; another SNI */
    {
        uint8_t a[2000], c[2000];
        size_t na = blob_make_tls("a.example.net", 0, 7, a, sizeof(a)), nc = blob_make_tls("a.example.net", 0, 7, c,
                                                                                            sizeof(c));
        CHECK(na > 100);
        CHECK_MEM(a, na, c, nc);
        CHECK_INT(l7_tls_host(a, na, host, sizeof(host), 0), 1);
        CHECK_STR(host, "a.example.net");
        CHECK_INT(blob_make_tls("a.example.net", 517, 7, a, sizeof(a)), 517);
        CHECK(l7_is_tls_hello(a, 517, 1, 0));
    }
#  if GENEVA_EXT_CRYPTO
    {
        const xblob *qi = blob_find("fake_quic_initial");
        quic_initial qh;
        uint8_t dec[2000], crypto[2000];
        long dl;
        size_t cl = 0;
        CHECK(qi != NULL);
        if (qi) {
            CHECK_INT(qi->len, 1200);
            CHECK(l7_is_quic_initial(qi->data, qi->len));
            dl = quic_initial_decrypt(qi->data, qi->len, &qh, dec, sizeof(dec));
            CHECK(dl > 0);
            if (dl > 0) {
                CHECK_INT(quic_crypto_stream(dec, (size_t)dl, crypto, sizeof(crypto), &cl), 0);
                CHECK(l7_is_tls_hs_hello(crypto, cl, 1, 0));
                CHECK_INT(l7_tls_hs_host(crypto, cl, host, sizeof(host), 0), 1);
                CHECK_STR(host, "www.iana.org");
            }
        }
    }
#  else
    CHECK(blob_find("fake_quic_initial") == NULL);
#  endif

    /* --ext-blob */
    sb_init(&e);
    CHECK_INT(blob_opt("b1:0x0102", &e), 0);
    CHECK(blob_find("b1") && blob_find("b1")->len == 2);
    CHECK_INT(blob_opt("b1:0x03", &e), -1);
    CHECK(strstr(e.data, "b1"));
    sb_reset(&e);
    CHECK_INT(blob_opt("fake_default_tls:0x03", &e), -1);
    sb_reset(&e);
    CHECK_INT(blob_opt("1bad:0x03", &e), -1);
    sb_reset(&e);
    CHECK_INT(blob_opt("b2:0x0", &e), -1);
    sb_reset(&e);
    CHECK_INT(blob_opt("b2:0xzz", &e), -1);
    sb_reset(&e);
    CHECK_INT(blob_opt("b2", &e), -1);
    sb_reset(&e);
    CHECK_INT(blob_opt("b3:@tests/data/zapret2/rdp.bin", &e), 0);
    CHECK_INT(blob_opt("b4:+3@tests/data/zapret2/rdp.bin", &e), 0);
    CHECK(blob_find("b3") && blob_find("b4") && blob_find("b3")->len == blob_find("b4")->len + 3 &&
          !memcmp(blob_find("b3")->data + 3, blob_find("b4")->data, blob_find("b4")->len));
    CHECK_INT(blob_opt("b5:@tests/data/nosuch.bin", &e), -1);
    sb_reset(&e);
    CHECK_INT(blob_opt("b5:+100000@tests/data/zapret2/rdp.bin", &e), -1);
    sb_reset(&e);
    {
        uint8_t *x;
        size_t xl;
        CHECK_INT(blob_hex("0x", 10, &x, &xl), 0);
        CHECK_INT(xl, 0);
        free(x);
        CHECK_INT(blob_hex("0xABcd", 10, &x, &xl), 0);
        CHECK(xl == 2 && x[0] == 0xab && x[1] == 0xcd);
        free(x);
        CHECK_INT(blob_hex("0x0102", 1, &x, &xl), -1);
    }
    CHECK(blob_name_ok("_a1") && !blob_name_ok("a-b") && !blob_name_ok(""));
    sb_free(&e);
    blob_reset();
    CHECK(blob_find("b1") == NULL && blob_find("fake_default_tls") != NULL);
}

static const char *sni_of(const uint8_t *d, size_t n)
{
    static char host[300];
    if (l7_tls_host(d, n, host, sizeof(host), 0) != 1)
        return "-";
    return host;
}

TEST(xact_tlsmod)
{
    const xblob *t = blob_find("fake_default_tls");
    uint8_t f[3000], ch[3000];
    size_t n, chn;
    tls_modspec m;
    char g[64];
    if (!t)
        return;
    CHECK_INT(tls_mod_parse("rnd,rndsni,dupsid,padencap", &m), 0);
    CHECK_INT(m.mod, TLSMOD_RND | TLSMOD_RNDSNI | TLSMOD_DUPSID | TLSMOD_PADENCAP);
    CHECK_INT(tls_mod_parse("sni=foo.bar", &m), 0);
    CHECK(m.mod == TLSMOD_SNI && !strcmp(m.sni, "foo.bar"));
    CHECK_INT(tls_mod_parse("none", &m), 0);
    CHECK_INT(m.mod, 0);
    CHECK_INT(tls_mod_parse("rnd,xxx", &m), -1);

    /* sni: a longer name, the lengths follow */
    memcpy(f, t->data, t->len);
    n = t->len;
    tls_mod_parse("sni=a-much-longer-host-name.example.com", &m);
    CHECK_INT(tls_mod_apply(&m, NULL, 0, f, &n, sizeof(f)), 0);
    CHECK_STR(sni_of(f, n), "a-much-longer-host-name.example.com");
    CHECK_INT(l7_tls_record_len(f), n);
    /* rndsni: the same length, random */
    memcpy(f, t->data, t->len);
    n = t->len;
    tls_mod_parse("rndsni", &m);
    CHECK_INT(tls_mod_apply(&m, NULL, 0, f, &n, sizeof(f)), 0);
    CHECK_INT(n, t->len);
    CHECK_INT(strlen(sni_of(f, n)), strlen("www.iana.org"));
    CHECK(strcmp(sni_of(f, n), "www.iana.org") != 0);
    /* rnd: the random and the session id change */
    memcpy(f, t->data, t->len);
    n = t->len;
    tls_mod_parse("rnd", &m);
    CHECK_INT(tls_mod_apply(&m, NULL, 0, f, &n, sizeof(f)), 0);
    CHECK(memcmp(f + 11, t->data + 11, 32) != 0);
    CHECK_MEM(f, 11, t->data, 11);
    /* dupsid copies the client's session id; padencap covers the client's
     * hello with the fake's lengths */
    chn = blob_make_tls("victim.example", 0, 99, ch, sizeof(ch));
    memcpy(f, t->data, t->len);
    n = t->len;
    tls_mod_parse("dupsid,padencap", &m);
    CHECK_INT(tls_mod_apply(&m, ch, chn, f, &n, sizeof(f)), 0);
    CHECK_MEM(f + 44, 32, ch + 44, 32);
    CHECK_INT(n, t->len);
    CHECK_INT(l7_tls_record_len(f), t->len + chn);

    /* through xfake, with sni=%blob */
    {
        uint8_t b[3000];
        size_t pn = mkpkt(b, 0, 0, P | A, SEQ, NULL, 0, ch, chn);
        xl7_view v;
        pktlist out = {0};
        memset(&v, 0, sizeof(v));
        v.l7 = L7_TLS, v.l7p = L7P_TLS_CLIENT_HELLO, v.data = ch, v.len = chn;
        CHECK_INT(blob_opt("myname:0x6578616d706c652e6f7267", NULL), 0); /* example.org */
        runx("[TCP:flags:PA]-xfake{blob=fake_default_tls;tlsmod=sni=%myname,dupsid}-| \\/", b, pn, &v, NULL, NULL,
             &out);
        CHECK_INT(out.n, 2);
        if (out.n == 2) {
            CHECK_STR(sni_of(out.v[0]->payload, out.v[0]->payload_len), "example.org");
            CHECK_MEM(out.v[0]->payload + 44, 32, ch + 44, 32);
        }
        pktlist_free(&out);
        blob_reset();
    }

    /* genhost: the length, the template at the end */
    rng_global_seed(3);
    tls_genhost(16, "google.com", g);
    CHECK_INT(strlen(g), 16);
    CHECK(!strcmp(g + 5, ".google.com") || !strcmp(g + 6, "google.com"));
    tls_genhost(5, "google.com", g);
    CHECK_INT(strlen(g), 5);
    tls_genhost(9, NULL, g);
    CHECK_INT(strlen(g), 9);
    CHECK(strchr(g, '.') != NULL);
}

/* ---- the engine: the order on the wire ---------------------------------------------------- */

typedef struct {
    char ev[16][8]; /* "V", "D", "I", "X" */
    size_t len[16];
    uint32_t mark[16];
    int n;
} xlog_t;
static xlog_t xl;

static int x_verdict(eng_worker *w, const void *pctx, int accept, const uint8_t *data, size_t len)
{
    (void)w, (void)pctx, (void)data;
    if (xl.n < 16) {
        snprintf(xl.ev[xl.n], 8, "%s", accept ? "V" : "D");
        xl.len[xl.n] = len;
        xl.n++;
    }
    return 0;
}

static int x_inject(eng_worker *w, const void *pctx, const uint8_t *data, size_t len)
{
    (void)w, (void)pctx, (void)data;
    if (xl.n < 16) {
        snprintf(xl.ev[xl.n], 8, "I");
        xl.len[xl.n] = len;
        xl.n++;
    }
    return 0;
}

static int x_inject_x(eng_worker *w, const void *pctx, const uint8_t *data, size_t len, uint32_t mark,
                      const char *ifout)
{
    (void)w, (void)pctx, (void)data, (void)ifout;
    if (xl.n < 16) {
        snprintf(xl.ev[xl.n], 8, "X");
        xl.len[xl.n] = len;
        xl.mark[xl.n] = mark;
        xl.n++;
    }
    return 0;
}

static const backend xbe = {
    "fake", sizeof(uint32_t), NULL, NULL, NULL, NULL, NULL, x_verdict, x_inject, 0, NULL, NULL, NULL, x_inject_x,
};

static const char *events(void)
{
    static char buf[200];
    size_t k = 0;
    buf[0] = 0;
    for (int i = 0; i < xl.n; i++)
        k += (size_t)snprintf(buf + k, sizeof(buf) - k, "%s%s%zu", i ? "," : "", xl.ev[i], xl.len[i]);
    return buf;
}

static void eng_run(const char *s, const uint8_t *raw, size_t n)
{
    engine e;
    engine_opts o;
    sbuf err;
    uint32_t id = 1;
    sb_init(&err);
    engine_opts_default(&o);
    memset(&e, 0, sizeof(e));
    e.o = &o;
    e.be = &xbe;
    plat_mutex_init(&e.lock);
    e.st = strategy_parse(s, &err);
    CHECK(e.st != NULL);
    CHECK_INT(engine_workers_init(&e, 1, &err), 0);
    memset(&xl, 0, sizeof(xl));
    engine_packet(&e.w[0], raw, n, DIR_OUT, &id);
    engine_run_timers(&e, 1);
    engine_workers_free(&e);
    strategy_free(e.st);
    plat_mutex_destroy(&e.lock);
    sb_free(&err);
}

TEST(xact_engine)
{
    uint8_t b[2000];
    size_t n = http_pkt(b), fl = blob_find("fake_default_http")->len;
    char exp[200];
    /* no view without --ext's hooks: payload=all */
    eng_run("[TCP:flags:PA]-xfake{blob=fake_default_http;payload=all}-| \\/", b, n);
    snprintf(exp, sizeof(exp), "I%zu,V%zu", 40 + fl, n);
    CHECK_STR(events(), exp);
    /* the original dropped, the parts injected in order */
    eng_run("[TCP:flags:PA]-xdisorder{pos=5;payload=all}-| \\/", b, n);
    snprintf(exp, sizeof(exp), "D0,I%zu,I45", n - 5);
    CHECK_STR(events(), exp);
    /* the original rides on the verdict between the packets made */
    eng_run("[TCP:flags:PA]-xfake{blob=fake_default_http;payload=all}(xtcpseg{pos=0,4;payload=all},)-| \\/", b, n);
    snprintf(exp, sizeof(exp), "I%zu,I45,V%zu", 40 + fl, n);
    CHECK_STR(events(), exp);
    /* a mark goes through inject_x */
    eng_run("[TCP:flags:PA]-xfake{blob=fake_default_http;payload=all;fwmark=7}-| \\/", b, n);
    snprintf(exp, sizeof(exp), "X%zu,V%zu", 40 + fl, n);
    CHECK_STR(events(), exp);
    CHECK_INT(xl.mark[0], 7);
    /* a changed original: the verdict carries the new bytes */
    eng_run("[TCP:flags:PA]-xmod{ttl=5}-| \\/", b, n);
    snprintf(exp, sizeof(exp), "V%zu", n);
    CHECK_STR(events(), exp);
}

void suite_xact(void)
{
    RUN(xact_parse);
    RUN(xact_fake);
    RUN(xact_split_disorder);
    RUN(xact_tcpseg_hostfake);
    RUN(xact_faked);
    RUN(xact_fooling);
    RUN(xact_ipv6);
    RUN(xact_ipfrag_mss);
    RUN(xact_meta);
    RUN(xact_blobs);
    RUN(xact_tlsmod);
    RUN(xact_engine);
    strategy_set_xact(NULL);
    blob_free_all();
}

#else
void suite_xact(void) {}
#endif
