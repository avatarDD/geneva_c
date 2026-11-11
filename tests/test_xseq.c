/* Stage X8: seqtrack (src/ext/seqtrack.c) and the x-actions on it, xoob
 * and xtlsrec, and xdrip (src/ext/xact_seq.c). A flow goes through apply's
 * path (xoff_packet, then the strategy) and what reaches each end is put
 * together again: the server must read the changed message and the client
 * must see its own numbering. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ext_opt.h"
#include "log.h"
#include "pkt.h"
#include "strategy.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/ext.h"
#  include "ext/fuzz.h"
#  include "ext/seqtrack.h"

enum { F = 1, S = 2, R = 4, P = 8, A = 16, U = 32 };

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8), p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, v >> 16), put16(p + 2, v & 0xffff); }

/* 10.0.0.1:40000 <-> 10.0.0.2:443; sack: one SACK block (l, r) when l != r */
static size_t mk(uint8_t *b, int from_server, unsigned flags, uint32_t seq, uint32_t ack, const void *d, size_t dl,
                 uint32_t sl, uint32_t sr)
{
    size_t olen = sl != sr ? 12 : 0, l4 = 20 + olen + dl;
    uint8_t *t = b + 20;
    memset(b, 0, 20 + 20 + olen);
    b[0] = 0x45;
    put16(b + 2, (unsigned)(20 + l4));
    b[8] = 64;
    b[9] = 6;
    b[12] = 10, b[15] = from_server ? 2 : 1;
    b[16] = 10, b[19] = from_server ? 1 : 2;
    put16(t, from_server ? 443 : 40000);
    put16(t + 2, from_server ? 40000 : 443);
    put32(t + 4, seq);
    put32(t + 8, ack);
    t[12] = (uint8_t)((5 + olen / 4) << 4);
    t[13] = (uint8_t)flags;
    put16(t + 14, 64000);
    if (olen) {
        t[20] = 1, t[21] = 1, t[22] = 5, t[23] = 10;
        put32(t + 24, sl);
        put32(t + 28, sr);
    }
    if (dl)
        memcpy(t + 20 + olen, d, dl);
    return 20 + l4;
}

/* what came out of one packet */
typedef struct {
    gpkt *v[64];
    int n;
} outs;

static outs g_out;

static void out_add(const uint8_t *b, size_t n)
{
    gpkt *p = pkt_parse(b, n);
    CHECK(p != NULL);
    if (p && g_out.n < 64)
        g_out.v[g_out.n++] = p;
    else
        pkt_free(p);
}

static void out_reset(void)
{
    for (int i = 0; i < g_out.n; i++)
        pkt_free(g_out.v[i]);
    g_out.n = 0;
}

static void out_pkt(gpkt *p)
{
    size_t n;
    uint8_t *b = pkt_bytes(p, &n);
    out_add(b, n);
    free(b);
}

static void replay(void *ud, const uint8_t *raw, size_t len, strat_dir dir, unsigned piece, unsigned pieces,
                   void *xctx)
{
    gpkt *p;
    strategy *st = xctx ? xoff_strategy(xctx) : NULL;
    (void)ud, (void)piece, (void)pieces;
    if (!st) {
        out_add(raw, len);
        return;
    }
    p = pkt_parse(raw, len);
    if (p) {
        pktlist o = {0};
        strategy_apply_x(st, p, dir, &o, xctx);
        for (size_t i = 0; i < o.n; i++)
            if (!o.v[i]->xdrop)
                out_pkt(o.v[i]);
        pktlist_free(&o);
    }
}

/* one packet through apply's path: g_out gets what goes on */
static void step(xoffline *x, strategy *st, const uint8_t *b, size_t n, strat_dir dir, uint64_t t)
{
    gpkt *p = pkt_parse(b, n);
    strategy *pst = st;
    int v;
    void *xctx;
    out_reset();
    CHECK(p != NULL);
    if (!p)
        return;
    xctx = xoff_packet(x, &pst, p, dir, t, b, n, replay, NULL, &v);
    if (v == XOFF_HOLD || v == XOFF_DROP) {
        pkt_free(p);
        return;
    }
    if (v == XOFF_BYPASS || !pst) {
        out_pkt(p);
        pkt_free(p);
        return;
    }
    {
        pktlist o = {0};
        strategy_apply_x(pst, p, dir, &o, xctx);
        for (size_t i = 0; i < o.n; i++)
            if (!o.v[i]->xdrop)
                out_pkt(o.v[i]);
        pktlist_free(&o);
    }
}

/* the bytes of the data packets in g_out, put together from seq0 on;
 * returns the length (holes stop it) */
static size_t stream(uint32_t seq0, uint8_t *buf, size_t cap)
{
    size_t end = 0;
    int more = 1;
    while (more) {
        more = 0;
        for (int i = 0; i < g_out.n; i++) {
            gpkt *p = g_out.v[i];
            uint32_t o = p->seq - seq0;
            if (p->payload_len && o <= end && o + p->payload_len > end && o + p->payload_len <= cap) {
                memcpy(buf + o, p->payload, p->payload_len);
                end = o + p->payload_len;
                more = 1;
            }
        }
    }
    return end;
}

static xoffline *open_x(void)
{
    xfuzz_init();
    return xoff_new();
}

static strategy *parse(const char *s)
{
    sbuf e;
    strategy *st;
    sb_init(&e);
    st = strategy_parse(s, &e);
    if (!st)
        fprintf(stderr, "  %s: %s\n", s, e.data);
    CHECK(st != NULL);
    sb_free(&e);
    return st;
}

TEST(xseq_parse)
{
    static const char *const ok[] = {
        "[TCP:flags:S]-xoob-| \\/",
        "[FLOW:n:1-]-xoob{urp=e;char=X}-| \\/",
        "[FLOW:n:1-]-xoob{urp=midsld;byte=255;ttl=3}-| \\/",
        "[FLOW:n:1-]-xtlsrec{pos=sniext+1}-| \\/",
        "[FLOW:n:1-]-xtlsrec-| \\/",
        "[TCP:flags:PA]-xdrip{n=4;delay=0;payload=all}-| \\/",
    };
    static const char *const bad[] = {
        "[FLOW:n:1-]-xoob{urp=x+}-| \\/",
        "[FLOW:n:1-]-xoob{char=XY}-| \\/",
        "[FLOW:n:1-]-xoob{byte=256}-| \\/",
        "[FLOW:n:1-]-xoob{payload=all}-| \\/",
        "\\/ [FLOW:n:1-]-xoob-|",
        "[FLOW:n:1-]-xtlsrec{pos=nosuch}-| \\/",
        "\\/ [FLOW:n:1-]-xtlsrec-|",
        "[TCP:flags:PA]-xdrip{n=0}-| \\/",
        "[TCP:flags:PA]-xdrip{delay=10001}-| \\/",
        "[TCP:flags:PA]-xdrip{ttl=3}-| \\/",
    };
    sbuf e;
    xfuzz_init();
    sb_init(&e);
    for (size_t i = 0; i < ARRAY_LEN(ok); i++) {
        strategy *st;
        sb_reset(&e);
        st = strategy_parse(ok[i], &e);
        if (!st)
            fprintf(stderr, "  %s: %s\n", ok[i], e.data);
        CHECK(st != NULL);
        strategy_free(st);
    }
    for (size_t i = 0; i < ARRAY_LEN(bad); i++) {
        strategy *st;
        sb_reset(&e);
        st = strategy_parse(bad[i], &e);
        if (st)
            fprintf(stderr, "  parsed: %s\n", bad[i]);
        CHECK(st == NULL);
        strategy_free(st);
    }
    sb_free(&e);
}

/* the mapping alone, around the end of the 32-bit numbering */
TEST(xseq_map)
{
    static const uint32_t isns[] = {1000, 0xfffffff0u, 0xfffffffeu, 0xffffffffu};
    for (size_t i = 0; i < ARRAY_LEN(isns); i++) {
        uint32_t c = isns[i], base;
        ct_flow f;
        xseq *s;
        memset(&f, 0, sizeof(f));
        s = xseq_start(&f, c, 5, "k");
        CHECK(s != NULL && xseq_start(&f, c, 5, "k") == NULL);
        if (!s)
            continue;
        base = c + 1 - 5;
        /* before the message: everything by d */
        CHECK(xseq_ack(s, base) == c + 1);
        CHECK(xseq_seq(s, c + 1) == base);
        /* message of 100 bytes, 5 inserted after its byte 8 */
        xseq_sent(s, 8, 100, (const uint8_t *)"x", 1, 0, 0);
        CHECK(xseq_ack(s, base) == c + 1);
        CHECK(xseq_ack(s, base + 8) == c + 1 + 8);
        CHECK(xseq_ack(s, base + 9) == c + 1 + 8);  /* inside the inserted bytes */
        CHECK(xseq_ack(s, base + 12) == c + 1 + 8);
        CHECK(xseq_ack(s, base + 13) == c + 1 + 8); /* past them: as it is */
        CHECK(xseq_ack(s, base + 105) == c + 1 + 100);
        CHECK(xseq_ack(s, base + 100000) == base + 100000);
        CHECK(xseq_ack(s, base - 3) == base + 2); /* behind (an old ack) */
        CHECK(xseq_seq(s, c) == c - 5);           /* the SYN's seq */
        CHECK(xseq_seq(s, c + 1 + 7) == base + 7);
        CHECK(xseq_seq(s, c + 1 + 8) == c + 1 + 8);
        CHECK(xseq_seq(s, c + 1 + 100) == c + 1 + 100);
        xseq_free(&f);
        CHECK(f.xseq == NULL);
    }
}

/* the TLS record of the tests: 16 03 01 00 40 and 64 bytes */
static void tls_rec(uint8_t *r)
{
    r[0] = 0x16, r[1] = 3, r[2] = 1, r[3] = 0, r[4] = 64;
    for (int i = 0; i < 64; i++)
        r[5 + i] = (uint8_t)('a' + i % 26);
}

/* a whole flow: handshake, the message, its retransmission, acks, SACK,
 * more data; isn near the end of the numbering for the wrap */
static void flow(const char *strat, uint32_t c, const uint8_t *msg, size_t mlen, const uint8_t *want, size_t wlen,
                 uint32_t k, int urg, unsigned urp)
{
    const uint32_t srv = 0x7000;
    uint32_t d = (uint32_t)(wlen - mlen), sv; /* sv: the client's ISN for the server */
    uint8_t b[2048], got[4096];
    size_t n;
    xoffline *x = open_x();
    strategy *st = parse(strat);
    uint64_t t = 1000;
    CHECK(x != NULL);
    if (!x || !st) {
        xoff_free(x);
        strategy_free(st);
        return;
    }
    sv = c - d;
    /* SYN: the server gets ISN - d */
    n = mk(b, 0, S, c, 0, NULL, 0, 0, 0);
    step(x, st, b, n, DIR_OUT, t++);
    CHECK_INT(g_out.n, 1);
    CHECK(g_out.n == 1 && g_out.v[0]->seq == sv);
    /* the SYN again (the hook shifts it, the action lets it be) */
    step(x, st, b, n, DIR_OUT, t++);
    CHECK(g_out.n == 1 && g_out.v[0]->seq == sv);
    /* SYN,ACK: the server acks sv + 1, the client gets c + 1 */
    n = mk(b, 1, S | A, srv, sv + 1, NULL, 0, 0, 0);
    step(x, st, b, n, DIR_IN, t++);
    CHECK(g_out.n == 1 && g_out.v[0]->ack == c + 1);
    /* the client's ACK */
    n = mk(b, 0, A, c + 1, srv + 1, NULL, 0, 0, 0);
    step(x, st, b, n, DIR_OUT, t++);
    CHECK(g_out.n == 1 && g_out.v[0]->seq == sv + 1);
    /* the message */
    n = mk(b, 0, P | A, c + 1, srv + 1, msg, mlen, 0, 0);
    step(x, st, b, n, DIR_OUT, t++);
    CHECK(g_out.n >= 1);
    CHECK_INT((int)stream(sv + 1, got, sizeof(got)), (int)wlen);
    CHECK_MEM(got, wlen < sizeof(got) ? wlen : 0, want, wlen);
    if (g_out.n >= 1) {
        CHECK_INT(!!(g_out.v[0]->tcpflags & U), urg);
        if (urg)
            CHECK_INT(g_out.v[0]->urgptr, (int)urp);
    }
    /* a retransmission of it, with 3 more bytes: the message again whole
     * and the 3 bytes after it */
    {
        uint8_t m2[600];
        memcpy(m2, msg, mlen);
        memcpy(m2 + mlen, "END", 3);
        n = mk(b, 0, P | A, c + 1, srv + 1, m2, mlen + 3, 0, 0);
        step(x, st, b, n, DIR_OUT, t++);
        CHECK_INT((int)stream(sv + 1, got, sizeof(got)), (int)wlen + 3);
        CHECK_MEM(got, wlen, want, wlen);
        CHECK(!memcmp(got + wlen, "END", 3));
    }
    /* a partial retransmission (from byte 2): the message again whole */
    n = mk(b, 0, P | A, c + 1 + 2, srv + 1, msg + 2, mlen - 2, 0, 0);
    step(x, st, b, n, DIR_OUT, t++);
    CHECK_INT((int)stream(sv + 1, got, sizeof(got)), (int)wlen);
    /* the server's ack inside the message with a SACK block: the client's
     * numbering, the inserted bytes counting as the byte before them */
    n = mk(b, 1, A, srv + 1, sv + 1 + 1, NULL, 0, sv + 1 + k, sv + 1 + k + d);
    step(x, st, b, n, DIR_IN, t++);
    CHECK(g_out.n == 1);
    if (g_out.n == 1) {
        gpkt *p = g_out.v[0];
        CHECK(p->ack == (k >= 1 ? c + 2 : c + 1 + k));
        CHECK(p->nopts >= 3 && p->opts[2].kind == 5);
        if (p->nopts >= 3) {
            const uint8_t *o = p->opts[2].data;
            uint32_t l = (uint32_t)o[0] << 24 | (uint32_t)o[1] << 16 | (uint32_t)o[2] << 8 | o[3];
            uint32_t r = (uint32_t)o[4] << 24 | (uint32_t)o[5] << 16 | (uint32_t)o[6] << 8 | o[7];
            CHECK(l == c + 1 + k);
            CHECK(r == c + 1 + k);
        }
    }
    /* the server acks the message: the client's own end of it */
    n = mk(b, 1, P | A, srv + 1, sv + 1 + (uint32_t)wlen + 3, "OK", 2, 0, 0);
    step(x, st, b, n, DIR_IN, t++);
    CHECK(g_out.n == 1 && g_out.v[0]->ack == c + 1 + (uint32_t)mlen + 3);
    /* after it: nothing changes, and a late copy of the message is not
     * sent again */
    n = mk(b, 0, P | A, c + 1 + (uint32_t)mlen + 3, srv + 3, "MORE", 4, 0, 0);
    step(x, st, b, n, DIR_OUT, t++);
    CHECK(g_out.n == 1 && g_out.v[0]->seq == c + 1 + (uint32_t)mlen + 3 && g_out.v[0]->payload_len == 4);
    n = mk(b, 0, A, c + 1 + (uint32_t)mlen + 7, srv + 3, NULL, 0, 0, 0);
    step(x, st, b, n, DIR_OUT, t++);
    CHECK(g_out.n == 1 && g_out.v[0]->seq == c + 1 + (uint32_t)mlen + 7);
    n = mk(b, 0, P | A, c + 1, srv + 3, msg, mlen, 0, 0);
    step(x, st, b, n, DIR_OUT, t++);
    CHECK(g_out.n == 1 && g_out.v[0]->seq == c + 1);
    n = mk(b, 1, A, srv + 3, sv + 1 + (uint32_t)wlen + 7, NULL, 0, 0, 0);
    step(x, st, b, n, DIR_IN, t++);
    CHECK(g_out.n == 1 && g_out.v[0]->ack == c + 1 + (uint32_t)mlen + 7);
    out_reset();
    xoff_free(x);
    strategy_free(st);
}

TEST(xseq_oob)
{
    static const uint32_t isns[] = {5000, 0xfffffffeu, 0xffffffe0u};
    const char *m = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    size_t ml = strlen(m);
    uint8_t w[100];
    for (size_t i = 0; i < ARRAY_LEN(isns); i++) {
        /* urp=b (zapret2's default): the byte first, th_urp 0 */
        w[0] = 0;
        memcpy(w + 1, m, ml);
        flow("[FLOW:n:1-]-xoob-| \\/", isns[i], (const uint8_t *)m, ml, w, ml + 1, 0, 1, 0);
        /* urp=e: last, th_urp past it */
        memcpy(w, m, ml);
        w[ml] = 'X';
        flow("[FLOW:n:1-]-xoob{urp=e;char=X}-| \\/", isns[i], (const uint8_t *)m, ml, w, ml + 1, (uint32_t)ml, 1,
             (unsigned)ml + 1);
        /* a marker: before the host's second byte */
        memcpy(w, m, 23);
        w[23] = 0xab;
        memcpy(w + 24, m + 23, ml - 23);
        flow("[FLOW:n:1-]-xoob{urp=host+1;byte=171}-| \\/", isns[i], (const uint8_t *)m, ml, w, ml + 1, 23, 1, 24);
    }
}

TEST(xseq_tlsrec)
{
    static const uint32_t isns[] = {5000, 0xfffffffdu};
    uint8_t r[69], w[80];
    tls_rec(r);
    for (size_t i = 0; i < ARRAY_LEN(isns); i++) {
        /* cut after 5 bytes of the body: 16 03 01 00 05 abcde 16 03 01 00 3b f... */
        memcpy(w, r, 10);
        w[4] = 5;
        w[10] = 0x16, w[11] = 3, w[12] = 1, w[13] = 0, w[14] = 59;
        memcpy(w + 15, r + 10, 59);
        flow("[FLOW:n:1-]-xtlsrec{pos=10}-| \\/", isns[i], r, sizeof(r), w, sizeof(r) + 5, 10, 0, 0);
        /* a marker that does not resolve: after the first byte */
        memcpy(w, r, 6);
        w[4] = 1;
        w[6] = 0x16, w[7] = 3, w[8] = 1, w[9] = 0, w[10] = 63;
        memcpy(w + 11, r + 6, 63);
        flow("[FLOW:n:1-]-xtlsrec-| \\/", isns[i], r, sizeof(r), w, sizeof(r) + 5, 6, 0, 0);
    }
}

/* what does not fit: no SYN seen, no TLS record, a second shifting action */
TEST(xseq_limits)
{
    uint8_t b[300], got[300];
    size_t n;
    xoffline *x = open_x();
    strategy *st = parse("[FLOW:n:1-]-xtlsrec(xoob,)-| \\/");
    const char *m = "GET / HTTP/1.1\r\n\r\n";
    CHECK(x && st);
    if (!x || !st) {
        xoff_free(x);
        strategy_free(st);
        return;
    }
    /* the first action takes the flow; xoob leaves it */
    n = mk(b, 0, S, 100, 0, NULL, 0, 0, 0);
    step(x, st, b, n, DIR_OUT, 1);
    CHECK(g_out.n == 1 && g_out.v[0]->seq == 95);
    /* not TLS: the message goes as it is, d before */
    n = mk(b, 0, P | A, 101, 1, m, strlen(m), 0, 0);
    step(x, st, b, n, DIR_OUT, 2);
    CHECK_INT((int)stream(96, got, sizeof(got)), (int)strlen(m));
    CHECK(!memcmp(got, m, strlen(m)));
    /* the server's ack of it is the client's */
    n = mk(b, 1, A, 1, 96 + (uint32_t)strlen(m), NULL, 0, 0, 0);
    step(x, st, b, n, DIR_IN, 3);
    CHECK(g_out.n == 1 && g_out.v[0]->ack == 101 + strlen(m));
    xoff_free(x);
    strategy_free(st);
    /* a flow seen from its middle: nothing changes */
    x = open_x();
    st = parse("[FLOW:n:1-]-xoob-| \\/");
    n = mk(b, 0, P | A, 101, 1, m, strlen(m), 0, 0);
    step(x, st, b, n, DIR_OUT, 1);
    CHECK(g_out.n == 1 && g_out.v[0]->seq == 101 && g_out.v[0]->payload_len == strlen(m));
    out_reset();
    xoff_free(x);
    strategy_free(st);
}

TEST(xseq_drip)
{
    uint8_t b[300];
    size_t n;
    xoffline *x = open_x();
    strategy *st = parse("[TCP:flags:PA]-xdrip{n=3;delay=10;payload=all}-| \\/");
    const char *m = "HELLO WORLD";
    CHECK(x && st);
    if (!x || !st) {
        xoff_free(x);
        strategy_free(st);
        return;
    }
    n = mk(b, 0, P | A, 0xfffffffeu, 1, m, strlen(m), 0, 0);
    step(x, st, b, n, DIR_OUT, 1);
    CHECK_INT(g_out.n, 4);
    if (g_out.n == 4) {
        for (int i = 0; i < 3; i++) {
            CHECK(g_out.v[i]->payload_len == 1 && g_out.v[i]->payload[0] == (uint8_t)m[i]);
            CHECK(g_out.v[i]->seq == 0xfffffffeu + (uint32_t)i);
        }
        CHECK(g_out.v[3]->payload_len == 8 && g_out.v[3]->seq == 1);
    }
    out_reset();
    xoff_free(x);
    strategy_free(st);
    /* the pauses: 0 and 10 ms, then the rest after 20 */
    {
        strategy *s2 = parse("[TCP:flags:PA]-xdrip{n=2;delay=10;payload=all}-| \\/");
        pktlist o = {0};
        n = mk(b, 0, P | A, 1, 1, m, strlen(m), 0, 0);
        if (s2) {
            strategy_apply_x(s2, pkt_parse(b, n), DIR_OUT, &o, NULL);
            CHECK_INT((int)o.n, 3); /* the original is dropped */
            if (o.n == 3) {
                CHECK(o.v[0]->sleep == 0);
                CHECK(o.v[1]->sleep > 0.0099 && o.v[1]->sleep < 0.0101);
                CHECK(o.v[2]->sleep > 0.0199 && o.v[2]->sleep < 0.0201);
                CHECK(o.v[2]->payload_len == strlen(m) - 2);
            }
            pktlist_free(&o);
        }
        strategy_free(s2);
    }
}

void suite_xseq(void)
{
    log_level lv = log_get_level();
    RUN(xseq_parse);
    RUN(xseq_map);
    RUN(xseq_oob);
    RUN(xseq_tlsrec);
    RUN(xseq_limits);
    RUN(xseq_drip);
    ext_reset();
    log_set_quiet(0);
    log_set_level(lv);
}

#else
void suite_xseq(void) {}
#endif
