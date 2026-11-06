/* Stage X5b: the rest of zapret2's desync functions as x-actions
 * (src/ext/xact_http.c, xact_misc.c, xact_tcp.c, tls_clone.c) and the
 * packet's own state (blobs that xtlsclone makes, xtag's label). The
 * expectations follow zapret-antidpi.lua and zapret-lib.lua. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "pcap.h"
#include "pkt.h"
#include "strategy.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/blob.h"
#  include "ext/ctrack.h"
#  include "ext/l7.h"
#  include "ext/tls.h"
#  include "ext/xact.h"
#  include "ext/xl7.h"
#  include "ext/xtrig.h"

enum { F = 1, S = 2, R = 4, P = 8, A = 16 };

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8), p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, v >> 16), put16(p + 2, v & 0xffff); }

/* 10.0.0.1:40000 -> 10.0.0.2:443, TCP with options or UDP */
static size_t mk(uint8_t *b, int udp, unsigned flags, const uint8_t *opt, size_t olen, const void *d, size_t dl)
{
    size_t l4h = udp ? 8 : 20 + olen, l4 = l4h + dl;
    uint8_t *t = b + 20;
    memset(b, 0, 20 + l4h);
    b[0] = 0x45;
    put16(b + 2, (unsigned)(20 + l4));
    put16(b + 4, 0x1234);
    b[8] = 64;
    b[9] = udp ? 17 : 6;
    b[12] = 10, b[15] = 1;
    b[16] = 10, b[19] = 2;
    put16(t, 40000);
    put16(t + 2, 443);
    if (udp) {
        put16(t + 4, (unsigned)l4);
    } else {
        put32(t + 4, 1000);
        put32(t + 8, 7777);
        t[12] = (uint8_t)((5 + olen / 4) << 4);
        t[13] = (uint8_t)flags;
        put16(t + 14, 64000);
        if (olen)
            memcpy(t + 20, opt, olen);
    }
    if (dl)
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

static xl7_view view(int l7p, const uint8_t *d, size_t n)
{
    xl7_view v;
    memset(&v, 0, sizeof(v));
    v.l7p = l7p;
    v.data = d;
    v.len = n;
    return v;
}

/* one strategy over several packets (its per-flow state stays) */
typedef struct {
    strategy *st;
    xpkt_ctx c;
    ct_flow f;
    pktlist out;
} run_t;

static void r_open(run_t *r, const char *s)
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
    r->c.f = &r->f;
}

static void r_pkt(run_t *r, strat_dir dir, const uint8_t *b, size_t n, const xl7_view *v)
{
    pktlist_free(&r->out);
    r->c.l7 = v;
    if (r->st)
        strategy_apply_x(r->st, pkt_parse(b, n), dir, &r->out, &r->c);
}

static void r_close(run_t *r)
{
    pktlist_free(&r->out);
    xact_flow_clear(&r->f);
    strategy_free(r->st);
}

/* one packet through s */
static void once(run_t *r, const char *s, const uint8_t *b, size_t n, const xl7_view *v)
{
    r_open(r, s);
    r_pkt(r, DIR_OUT, b, n, v);
}

static const char *pl(gpkt *p)
{
    static char b[2000];
    size_t n = p->payload_len < sizeof(b) - 1 ? p->payload_len : sizeof(b) - 1;
    memcpy(b, p->payload, n);
    b[n] = 0;
    return b;
}

/* the packet as it goes out, parsed again */
static gpkt *wire(gpkt *p)
{
    size_t n;
    uint8_t *b = pkt_bytes(p, &n);
    gpkt *q = pkt_parse(b, n);
    free(b);
    return q;
}

TEST(x5b_parse)
{
    strategy_set_xact(&xact_ops);
    blob_reset();
    CHECK_STR(perr("[TCP:flags:PA]-xhttp{domcase;hostcase=hoSt;methodeol;unixeol}-| \\/"), "OK");
    CHECK_STR(perr("[TCP:flags:PA]-xhttp{hostcase}-| \\/"), "OK");
    CHECK_STR(perr("[TCP:flags:SA]-xsynacksplit{mode=acksyn;repeats=2}-| \\/"), "OK");
    CHECK_STR(perr("[TCP:flags:S]-xsynack-| \\/"), "OK");
    CHECK_STR(perr("\\/ [TCP:flags:SA]-xwsize{wsize=1;scale=6}-|"), "OK");
    CHECK_STR(perr("[TCP:dport:443]-xwssize{wsize=1;scale=6;forced_cutoff=http_req,tls_client_hello}-| \\/"), "OK");
    CHECK_STR(perr("[TCP:flags:S]-xsyndata{blob=fake_default_tls;tlsmod=rnd;ttl=3}-| \\/"), "OK");
    CHECK_STR(perr("[TCP:flags:PA]-xrst{rstack;payload=all;ttl=2}-| \\/"), "OK");
    CHECK_STR(perr("[UDP:dport:443]-xudplen{min=10;max=100;increment=-2;pattern=0x41;pattern_offset=1}-| \\/"),
              "OK");
    CHECK_STR(perr("[UDP:dport:443]-xdhtdn{dn=5}-| \\/"), "OK");
    CHECK_STR(perr("[TCP:flags:PA]-xtlsclone{blob=c;fallback=fake_default_tls;sni_snt=1;sni_snt_new=2;sni_first="
                   "a.com;sni_last=b.com;sni_del}-| \\/"),
              "OK");
    CHECK_STR(perr("[TCP:flags:PA]-xlog{msg=hi;pkt;pos;hex}-| \\/ [TCP:flags:SA]-xlog-|"), "OK");
    CHECK_STR(perr("[TCP:flags:PA]-xtag{pattern=GET;payload=my;undetected=other}(xfake{blob=0x41;payload=my},)-| "
                   "\\/"),
              "OK");
    CHECK_STR(perr("[TCP:flags:PA]-xpcap{file=x.pcap;keep}-| \\/"), "OK");
    CHECK(strstr(perr("[TCP:flags:SA]-xsynacksplit{mode=foo}-| \\/"), "bad mode"));
    CHECK(strstr(perr("[TCP:flags:PA]-xhttp-| \\/"), "nothing to do"));
    CHECK(strstr(perr("[TCP:flags:PA]-xhttp{hostcase=hst}-| \\/"), "invalid host spelling"));
    CHECK(strstr(perr("[TCP:flags:PA]-xhttp{domcase=1}-| \\/"), "takes no value"));
    CHECK(strstr(perr("[TCP:flags:SA]-xwsize{wsize=70000}-| \\/"), "bad wsize"));
    CHECK(strstr(perr("[TCP:flags:SA]-xwsize{ttl=1}-| \\/"), "unknown parameter"));
    CHECK(strstr(perr("[TCP:flags:PA]-xwssize{forced_cutoff}-| \\/"), "forced_cutoff"));
    CHECK(strstr(perr("[UDP:dport:443]-xudplen{increment=0}-| \\/"), "does nothing"));
    CHECK(strstr(perr("[TCP:flags:PA]-xtlsclone{sni_del}-| \\/"), "'blob' arg required"));
    CHECK(strstr(perr("[TCP:flags:PA]-xtlsclone{blob=c;sni_snt=300}-| \\/"), "bad sni_snt"));
    CHECK(strstr(perr("[TCP:flags:PA]-xtag{payload=x}-| \\/"), "missing 'pattern'"));
    CHECK(strstr(perr("[TCP:flags:PA]-xtag{pattern=a;payload=a-b}-| \\/"), "bad name"));
    CHECK(strstr(perr("[TCP:flags:PA]-xpcap-| \\/"), "requires 'file'"));
    CHECK(strstr(perr("\\/ [TCP:flags:PA]-xrst-|"), "inbound forest"));
    CHECK(strstr(perr("\\/ [TCP:flags:SA]-xsynacksplit-|"), "inbound forest"));
    CHECK(strstr(perr("[TCP:flags:S]-xsynack{ttl=1}-| \\/"), "unknown parameter"));
}

TEST(x5b_http)
{
    static const char req[] = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla\r\n\r\n";
    uint8_t b[600];
    size_t n = mk(b, 0, P | A, NULL, 0, req, sizeof(req) - 1);
    xl7_view v = view(L7P_HTTP_REQ, (const uint8_t *)req, sizeof(req) - 1);
    run_t r;
    once(&r, "[TCP:flags:PA]-xhttp{domcase}-| \\/", b, n, &v);
    CHECK_INT(r.out.n, 1);
    if (r.out.n == 1) {
        gpkt *q = wire(r.out.v[0]);
        CHECK_STR(pl(q), "GET / HTTP/1.1\r\nHost: ExAmPlE.CoM\r\nUser-Agent: Mozilla\r\n\r\n");
        pkt_free(q);
    }
    r_close(&r);
    once(&r, "[TCP:flags:PA]-xhttp{hostcase=hoSt}-| \\/", b, n, &v);
    CHECK(r.out.n == 1 && !strcmp(pl(r.out.v[0]), "GET / HTTP/1.1\r\nhoSt: example.com\r\nUser-Agent: Mozilla\r\n\r\n"));
    r_close(&r);
    once(&r, "[TCP:flags:PA]-xhttp{hostcase}-| \\/", b, n, &v);
    CHECK(r.out.n == 1 && strstr(pl(r.out.v[0]), "\r\nhost: example.com"));
    r_close(&r);
    once(&r, "[TCP:flags:PA]-xhttp{methodeol}-| \\/", b, n, &v);
    CHECK(r.out.n == 1 && !strcmp(pl(r.out.v[0]), "\r\nGET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozil\r\n\r\n"));
    r_close(&r);
    once(&r, "[TCP:flags:PA]-xhttp{unixeol}-| \\/", b, n, &v);
    CHECK(r.out.n == 1 && !strcmp(pl(r.out.v[0]), "GET / HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla    \n\n"));
    if (r.out.n == 1)
        CHECK_INT(r.out.v[0]->payload_len, sizeof(req) - 1);
    r_close(&r);
    /* all four, in zapret2's chain order */
    once(&r, "[TCP:flags:PA]-xhttp{methodeol;unixeol;hostcase=HOST;domcase}-| \\/", b, n, &v);
    CHECK(r.out.n == 1 &&
          !strcmp(pl(r.out.v[0]), "\r\nGET / HTTP/1.1\nHOST: ExAmPlE.CoM\nUser-Agent: Mozilla  \n\n"));
    r_close(&r);
    /* not an HTTP request: untouched */
    {
        xl7_view u = view(L7P_UNKNOWN, NULL, 0);
        once(&r, "[TCP:flags:PA]-xhttp{domcase;methodeol}-| \\/", b, n, &u);
        CHECK(r.out.n == 1 && !strcmp(pl(r.out.v[0]), req));
        r_close(&r);
    }
    /* the User-Agent too short for methodeol, a request without one */
    {
        static const char q1[] = "GET / HTTP/1.1\r\nHost: a\r\nUser-Agent: x\r\n\r\n";
        static const char q2[] = "GET /\r\nHost: a\r\n\r\n";
        uint8_t b1[300];
        size_t n1 = mk(b1, 0, P | A, NULL, 0, q1, sizeof(q1) - 1);
        once(&r, "[TCP:flags:PA]-xhttp{methodeol}-| \\/", b1, n1, &v);
        CHECK(r.out.n == 1 && !strcmp(pl(r.out.v[0]), q1));
        r_close(&r);
        n1 = mk(b1, 0, P | A, NULL, 0, q2, sizeof(q2) - 1);
        once(&r, "[TCP:flags:PA]-xhttp{unixeol;hostcase=xxxx}-| \\/", b1, n1, &v);
        CHECK(r.out.n == 1 && !strcmp(pl(r.out.v[0]), "GET /\r\nxxxx: a\r\n\r\n"));
        r_close(&r);
    }
}

static unsigned flags_of(gpkt *p) { return p->tcpflags; }

TEST(x5b_synack)
{
    uint8_t b[200];
    size_t n = mk(b, 0, S | A, NULL, 0, NULL, 0);
    run_t r;
    once(&r, "[TCP:flags:SA]-xsynacksplit-| \\/", b, n, NULL);
    CHECK_INT(r.out.n, 2);
    if (r.out.n == 2) {
        CHECK(r.out.v[0]->xgen && flags_of(r.out.v[0]) == S);
        CHECK(r.out.v[1]->xgen && flags_of(r.out.v[1]) == A);
    }
    r_close(&r);
    once(&r, "[TCP:flags:SA]-xsynacksplit{mode=acksyn}-| \\/", b, n, NULL);
    CHECK(r.out.n == 2 && flags_of(r.out.v[0]) == A && flags_of(r.out.v[1]) == S);
    r_close(&r);
    once(&r, "[TCP:flags:SA]-xsynacksplit{mode=syn;repeats=2}-| \\/", b, n, NULL);
    CHECK(r.out.n == 2 && flags_of(r.out.v[0]) == S && flags_of(r.out.v[1]) == S);
    r_close(&r);
    /* another packet cuts it off on the flow */
    {
        uint8_t b2[200];
        size_t n2 = mk(b2, 0, A, NULL, 0, NULL, 0);
        r_open(&r, "[TCP:dport:443]-xsynacksplit-| \\/");
        r_pkt(&r, DIR_OUT, b2, n2, NULL);
        CHECK(r.out.n == 1 && !r.out.v[0]->xgen);
        r_pkt(&r, DIR_OUT, b, n, NULL);
        CHECK(r.out.n == 1 && !r.out.v[0]->xgen && flags_of(r.out.v[0]) == (S | A));
        r_close(&r);
    }
    /* synack: a SYN gets a SYN,ACK copy before it */
    n = mk(b, 0, S, NULL, 0, NULL, 0);
    once(&r, "[TCP:flags:S]-xsynack-| \\/", b, n, NULL);
    CHECK(r.out.n == 2 && r.out.v[0]->xgen && flags_of(r.out.v[0]) == (S | A) && !r.out.v[1]->xgen &&
          flags_of(r.out.v[1]) == S);
    r_close(&r);
}

TEST(x5b_wsize)
{
    static const uint8_t ws[4] = {1, 3, 3, 7}; /* NOP, window scale 7 */
    uint8_t b[200], d[200];
    size_t n = mk(b, 0, S | A, ws, 4, NULL, 0), dn;
    run_t r;
    once(&r, "[TCP:flags:SA]-xwsize{wsize=1;scale=6}-| \\/", b, n, NULL);
    CHECK_INT(r.out.n, 1);
    if (r.out.n == 1) {
        gpkt *q = wire(r.out.v[0]);
        CHECK_INT(q->window, 1);
        CHECK(q->nopts == 2 && q->opts[1].kind == 3 && q->opts[1].data[0] == 6);
        pkt_free(q);
    }
    r_close(&r);
    once(&r, "[TCP:flags:SA]-xwsize{scale=9}-| \\/", b, n, NULL);
    CHECK(r.out.n == 1 && r.out.v[0]->opts[1].data[0] == 7 && r.out.v[0]->window == 64000);
    r_close(&r);
    /* inbound: the client's SYN,ACK */
    r_open(&r, "\\/ [TCP:flags:SA]-xwsize{wsize=2}-|");
    r_pkt(&r, DIR_IN, b, n, NULL);
    CHECK(r.out.n == 1 && r.out.v[0]->window == 2);
    r_close(&r);
    /* wssize: every outbound packet until the first payload */
    n = mk(b, 0, S, ws, 4, NULL, 0);
    dn = mk(d, 0, P | A, NULL, 0, "GET", 3);
    r_open(&r, "[TCP:dport:443]-xwssize{wsize=1;scale=2}-| \\/");
    r_pkt(&r, DIR_OUT, b, n, NULL);
    CHECK(r.out.n == 1 && r.out.v[0]->window == 1 && r.out.v[0]->opts[1].data[0] == 2);
    r_pkt(&r, DIR_OUT, d, dn, NULL);
    CHECK(r.out.n == 1 && r.out.v[0]->window == 1);
    r_pkt(&r, DIR_OUT, d, dn, NULL);
    CHECK(r.out.n == 1 && r.out.v[0]->window == 64000);
    r_close(&r);
    /* forced_cutoff: only on the payloads listed */
    {
        xl7_view u = view(L7P_UNKNOWN, NULL, 0), h = view(L7P_HTTP_REQ, NULL, 0);
        r_open(&r, "[TCP:dport:443]-xwssize{wsize=1;forced_cutoff=http_req}-| \\/");
        r_pkt(&r, DIR_OUT, d, dn, &u);
        CHECK(r.out.n == 1 && r.out.v[0]->window == 1);
        r_pkt(&r, DIR_OUT, d, dn, &h);
        CHECK(r.out.n == 1 && r.out.v[0]->window == 1);
        r_pkt(&r, DIR_OUT, d, dn, &u);
        CHECK(r.out.n == 1 && r.out.v[0]->window == 64000);
        r_close(&r);
    }
}

TEST(x5b_syndata_rst)
{
    static const char req[] = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    uint8_t b[600];
    size_t n = mk(b, 0, S, NULL, 0, NULL, 0);
    xl7_view h = view(L7P_HTTP_REQ, (const uint8_t *)req, sizeof(req) - 1);
    run_t r;
    once(&r, "[TCP:flags:S]-xsyndata-| \\/", b, n, NULL);
    CHECK_INT(r.out.n, 1);
    if (r.out.n == 1) {
        static const uint8_t z[16];
        CHECK(r.out.v[0]->xgen && flags_of(r.out.v[0]) == S);
        CHECK_MEM(r.out.v[0]->payload, r.out.v[0]->payload_len, z, 16);
    }
    r_close(&r);
    once(&r, "[TCP:flags:S]-xsyndata{blob=0x1603;ttl=3}-| \\/", b, n, NULL);
    CHECK(r.out.n == 1 && r.out.v[0]->payload_len == 2 && r.out.v[0]->payload[0] == 0x16 && r.out.v[0]->ttl == 3);
    r_close(&r);
    /* a SYN fake ClientHello with tlsmod */
    once(&r, "[TCP:flags:S]-xsyndata{blob=fake_default_tls;tlsmod=sni=x.org}-| \\/", b, n, NULL);
    if (r.out.n == 1) {
        char host[300];
        CHECK_INT(l7_tls_host(r.out.v[0]->payload, r.out.v[0]->payload_len, host, sizeof(host), 0), 1);
        CHECK_STR(host, "x.org");
    } else {
        CHECK_INT(r.out.n, 1);
    }
    r_close(&r);
    /* rst: a copy with RST (RST,ACK) and no payload before the packet */
    n = mk(b, 0, P | A, NULL, 0, req, sizeof(req) - 1);
    once(&r, "[TCP:flags:PA]-xrst-| \\/", b, n, &h);
    CHECK(r.out.n == 2 && r.out.v[0]->xgen && flags_of(r.out.v[0]) == R && !r.out.v[0]->payload_len &&
          !r.out.v[1]->xgen && r.out.v[1]->payload_len == sizeof(req) - 1);
    r_close(&r);
    once(&r, "[TCP:flags:PA]-xrst{rstack;ttl=2}-| \\/", b, n, &h);
    CHECK(r.out.n == 2 && flags_of(r.out.v[0]) == (R | A) && r.out.v[0]->ttl == 2);
    r_close(&r);
    /* not a known payload */
    once(&r, "[TCP:flags:PA]-xrst-| \\/", b, n, NULL);
    CHECK_INT(r.out.n, 1);
    r_close(&r);
}

TEST(x5b_udp)
{
    uint8_t b[300];
    size_t n = mk(b, 1, 0, NULL, 0, "0123456789", 10);
    xl7_view q = view(L7P_QUIC_INITIAL, NULL, 0);
    run_t r;
    once(&r, "[UDP:dport:443]-xudplen-| \\/", b, n, &q);
    CHECK(r.out.n == 1 && r.out.v[0]->payload_len == 12 && !r.out.v[0]->payload[11]);
    if (r.out.n == 1) {
        gpkt *w = wire(r.out.v[0]);
        CHECK_INT(w->udplen, 20);
        pkt_free(w);
    }
    r_close(&r);
    once(&r, "[UDP:dport:443]-xudplen{increment=3;pattern=0x4142;pattern_offset=1}-| \\/", b, n, &q);
    CHECK(r.out.n == 1 && !strcmp(pl(r.out.v[0]), "0123456789BAB"));
    r_close(&r);
    once(&r, "[UDP:dport:443]-xudplen{increment=-3}-| \\/", b, n, &q);
    CHECK(r.out.n == 1 && !strcmp(pl(r.out.v[0]), "0123456"));
    r_close(&r);
    once(&r, "[UDP:dport:443]-xudplen{increment=-10}-| \\/", b, n, &q);
    CHECK(r.out.n == 1 && r.out.v[0]->payload_len == 10);
    r_close(&r);
    once(&r, "[UDP:dport:443]-xudplen{min=11}-| \\/", b, n, &q);
    CHECK(r.out.n == 1 && r.out.v[0]->payload_len == 10);
    r_close(&r);
    once(&r, "[UDP:dport:443]-xudplen{max=9}-| \\/", b, n, &q);
    CHECK(r.out.n == 1 && r.out.v[0]->payload_len == 10);
    r_close(&r);
    /* unknown payload: not by default, with payload=all */
    once(&r, "[UDP:dport:443]-xudplen-| \\/", b, n, NULL);
    CHECK(r.out.n == 1 && r.out.v[0]->payload_len == 10);
    r_close(&r);
    once(&r, "[UDP:dport:443]-xudplen{payload=all}-| \\/", b, n, NULL);
    CHECK(r.out.n == 1 && r.out.v[0]->payload_len == 12);
    r_close(&r);
    /* dht_dn */
    {
        static const char dht[] = "d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
        xl7_view d = view(L7P_DHT, NULL, 0);
        n = mk(b, 1, 0, NULL, 0, dht, sizeof(dht) - 1);
        once(&r, "[UDP:dport:443]-xdhtdn-| \\/", b, n, &d);
        CHECK(r.out.n == 1 && !strcmp(pl(r.out.v[0]), "d3:0001:x1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"));
        r_close(&r);
        once(&r, "[UDP:dport:443]-xdhtdn{dn=1}-| \\/", b, n, &d);
        CHECK(r.out.n == 1 && !strncmp(pl(r.out.v[0]), "d1:01:x1:ad2", 12));
        r_close(&r);
        once(&r, "[UDP:dport:443]-xdhtdn-| \\/", b, n, &q);
        CHECK(r.out.n == 1 && !strcmp(pl(r.out.v[0]), dht));
        r_close(&r);
    }
}

/* ---- tls_client_hello_mod ---------------------------------------------------------- */

/* a ClientHello record with extensions ext (elen bytes) */
static size_t mkch(uint8_t *o, const uint8_t *ext, size_t elen)
{
    size_t hl = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + elen, at = 0;
    o[at++] = 0x16, o[at++] = 3, o[at++] = 1;
    put16(o + at, (unsigned)(hl + 4)), at += 2;
    o[at++] = 1, o[at++] = 0;
    put16(o + at, (unsigned)hl), at += 2;
    o[at++] = 3, o[at++] = 3;
    memset(o + at, 0x55, 32), at += 32;
    o[at++] = 0;                                 /* session id */
    put16(o + at, 2), at += 2;                   /* cipher suites */
    o[at++] = 0x13, o[at++] = 1;
    o[at++] = 1, o[at++] = 0;                    /* compression */
    put16(o + at, (unsigned)elen), at += 2;
    memcpy(o + at, ext, elen);
    return at + elen;
}

static const char *names(const uint8_t *t, size_t n)
{
    /* the server names of the SNI extension, "type:name" joined by "," */
    static char out[600];
    size_t at = 5 + 4 + 2 + 32, l;
    out[0] = 0;
    if (n < at + 1)
        return "?";
    at += 1 + t[at];
    at += 2 + ((size_t)t[at] << 8 | t[at + 1]);
    at += 1 + t[at];
    l = (size_t)t[at] << 8 | t[at + 1];
    at += 2;
    for (size_t e = at; e + 4 <= at + l && e + 4 <= n;) {
        unsigned ty = (unsigned)t[e] << 8 | t[e + 1];
        size_t el = (size_t)t[e + 2] << 8 | t[e + 3];
        if (ty == 0) {
            size_t p = e + 6, end = e + 4 + el;
            if (!el)
                return "noext";
            while (p + 3 <= end) {
                size_t nl = (size_t)t[p + 1] << 8 | t[p + 2];
                snprintf(out + strlen(out), sizeof(out) - strlen(out), "%s%u:%.*s", out[0] ? "," : "", t[p],
                         (int)nl, (const char *)t + p + 3);
                p += 3 + nl;
            }
            return out[0] ? out : "empty";
        }
        e += 4 + el;
    }
    return "noext";
}

TEST(x5b_tlsclone_mod)
{
    /* SNI a.b, supported_groups with an odd byte, alpn with junk after its
     * list, padding (not dissected) */
    static const uint8_t ext[] = {0, 0,  0, 8, 0, 6, 0, 0, 3, 'a', '.', 'b', 0, 10, 0, 5, 0, 2, 0, 0x1d, 9,
                                  0, 16, 0, 6, 0, 3, 2, 'h', '2', 0xee, 0, 21, 0, 3, 0, 0, 0};
    uint8_t ch[400], *out;
    size_t n = mkch(ch, ext, sizeof(ext)), ol;
    tls_cloneopt o;
    memset(&o, 0, sizeof(o));
    o.snt = o.snt_new = -1;
    /* nothing to change: the canonical forms only (two bytes shorter) */
    CHECK_INT(tls_ch_clone(ch, n, &o, &out, &ol), 0);
    if (ol == n - 2) {
        static const uint8_t canon[] = {0, 0,  0, 8, 0, 6, 0, 0, 3, 'a', '.', 'b', 0, 10, 0, 4, 0, 2, 0, 0x1d,
                                        0, 16, 0, 5, 0, 3, 2, 'h', '2', 0, 21, 0, 3, 0, 0, 0};
        uint8_t ex[400];
        size_t en = mkch(ex, canon, sizeof(canon));
        CHECK_MEM(out, ol, ex, en);
    } else {
        CHECK_INT(ol, n - 2);
    }
    free(out);
    CHECK_STR(names(ch, n), "0:a.b");
    o.first = "x.com", o.first_len = 5;
    o.last = "y.org", o.last_len = 5;
    o.snt_new = 7;
    CHECK_INT(tls_ch_clone(ch, n, &o, &out, &ol), 0);
    CHECK_STR(names(out, ol), "7:x.com,0:a.b,7:y.org");
    free(out);
    o.snt_new = -1;
    CHECK_INT(tls_ch_clone(ch, n, &o, &out, &ol), 0);
    CHECK_STR(names(out, ol), "0:x.com,0:a.b,0:y.org");
    {
        char host[300];
        CHECK_INT(l7_tls_host(out, ol, host, sizeof(host), 0), 1);
        CHECK_STR(host, "x.com");
    }
    free(out);
    o.snt_new = 7;
    o.snt = 3;
    o.last = NULL;
    CHECK_INT(tls_ch_clone(ch, n, &o, &out, &ol), 0);
    CHECK_STR(names(out, ol), "7:x.com,3:a.b");
    free(out);
    o.del = 1;
    CHECK_INT(tls_ch_clone(ch, n, &o, &out, &ol), 0);
    CHECK_STR(names(out, ol), "7:x.com");
    free(out);
    memset(&o, 0, sizeof(o));
    o.snt = o.snt_new = -1;
    o.del = 1;
    CHECK_INT(tls_ch_clone(ch, n, &o, &out, &ol), 0);
    CHECK_STR(names(out, ol), "empty");
    free(out);
    o.del = 0, o.del_ext = 1;
    CHECK_INT(tls_ch_clone(ch, n, &o, &out, &ol), 0);
    CHECK_STR(names(out, ol), "noext");
    free(out);
    /* no SNI: one goes first */
    {
        uint8_t c2[400];
        size_t n2 = mkch(c2, ext + 12, sizeof(ext) - 12);
        memset(&o, 0, sizeof(o));
        o.snt = o.snt_new = -1;
        o.last = "n.net", o.last_len = 5;
        CHECK_INT(tls_ch_clone(c2, n2, &o, &out, &ol), 0);
        CHECK_STR(names(out, ol), "0:n.net");
        CHECK(ol > 5 + 4 + 40 && out[5 + 4 + 2 + 32 + 1 + 4 + 2 + 2] == 0 && out[5 + 4 + 2 + 32 + 1 + 4 + 2 + 3] == 0);
        free(out);
    }
    /* a bare handshake message (QUIC's CRYPTO) */
    memset(&o, 0, sizeof(o));
    o.snt = o.snt_new = -1;
    o.first = "q.io", o.first_len = 4;
    CHECK_INT(tls_ch_clone(ch + 5, n - 5, &o, &out, &ol), 0);
    CHECK(ol > 4 && out[0] == 1);
    free(out);
    /* not a ClientHello, cut short */
    CHECK_INT(tls_ch_clone((const uint8_t *)"GET / HTTP/1.1\r\n", 16, &o, &out, &ol), -1);
    CHECK_INT(tls_ch_clone(ch, n - 1, &o, &out, &ol), -1);
    /* a bad extension list: no dissect */
    {
        uint8_t c3[400];
        static const uint8_t bad[] = {0, 10, 0, 9, 0, 2};
        size_t n3 = mkch(c3, bad, sizeof(bad));
        CHECK_INT(tls_ch_clone(c3, n3, &o, &out, &ol), -1);
    }
}

TEST(x5b_tlsclone_records)
{
    /* the ClientHello in two records of 60 and the rest: a longer one keeps
     * the first record's length, the last takes the rest */
    const xblob *t = blob_find("fake_default_tls");
    uint8_t two[2000], *out;
    size_t hl = t->len - 5, n = 0, ol;
    tls_cloneopt o;
    two[n++] = 0x16, two[n++] = 3, two[n++] = 1;
    put16(two + n, 60), n += 2;
    memcpy(two + n, t->data + 5, 60), n += 60;
    two[n++] = 0x16, two[n++] = 3, two[n++] = 1;
    put16(two + n, (unsigned)(hl - 60)), n += 2;
    memcpy(two + n, t->data + 65, hl - 60), n += hl - 60;
    memset(&o, 0, sizeof(o));
    o.snt = o.snt_new = -1;
    CHECK_INT(tls_ch_clone(two, n, &o, &out, &ol), 0);
    CHECK_MEM(out, ol, two, n); /* our own fake is canonical */
    free(out);
    CHECK_INT(tls_ch_clone(t->data, t->len, &o, &out, &ol), 0);
    CHECK_MEM(out, ol, t->data, t->len);
    free(out);
    o.first = "longer-name.example", o.first_len = 19;
    CHECK_INT(tls_ch_clone(two, n, &o, &out, &ol), 0);
    CHECK_INT(ol, n + 22);
    if (ol == n + 22) {
        CHECK(out[3] == 0 && out[4] == 60 && out[65] == 0x16);
        CHECK_INT((size_t)out[68] << 8 | out[69], hl - 60 + 22);
    }
    free(out);
    /* the next record is missing: not dissected */
    CHECK_INT(tls_ch_clone(two, 65, &o, &out, &ol), -1);
}

TEST(x5b_tlsclone_tree)
{
    const xblob *t = blob_find("fake_default_tls");
    uint8_t b[2000];
    size_t n = mk(b, 0, P | A, NULL, 0, t->data, t->len);
    xl7_view v = view(L7P_TLS_CLIENT_HELLO, t->data, t->len), h = view(L7P_HTTP_REQ, NULL, 0);
    char host[300];
    run_t r;
    /* the clone goes to the fake of the subtree */
    once(&r, "[TCP:flags:PA]-xtlsclone{blob=c;sni_first=evil.com}(xfake{blob=c;ttl=2},)-| \\/", b, n, &v);
    CHECK_INT(r.out.n, 2);
    if (r.out.n == 2) {
        CHECK(r.out.v[0]->xgen && r.out.v[0]->ttl == 2);
        CHECK_INT(l7_tls_host(r.out.v[0]->payload, r.out.v[0]->payload_len, host, sizeof(host), 0), 1);
        CHECK_STR(host, "evil.com");
        CHECK(!r.out.v[1]->xgen && r.out.v[1]->payload_len == t->len);
    }
    r_close(&r);
    /* and to the trees after it, not to the next packet */
    r_open(&r, "[TCP:flags:PA]-xtlsclone{blob=c;sni_del}-| [TCP:flags:PA]-xfake{blob=c}-| \\/");
    r_pkt(&r, DIR_OUT, b, n, &v);
    CHECK_INT(r.out.n, 3);
    if (r.out.n == 3)
        CHECK(r.out.v[1]->xgen && l7_tls_host(r.out.v[1]->payload, r.out.v[1]->payload_len, host, sizeof(host), 0) != 1);
    r_pkt(&r, DIR_OUT, b, n, &h);
    CHECK_INT(r.out.n, 2); /* no blob c: xfake passes */
    r_close(&r);
    /* fallback when it is not a ClientHello */
    once(&r, "[TCP:flags:PA]-xtlsclone{blob=c;fallback=0x4142}(xfake{blob=c;payload=all},)-| \\/", b, n, &h);
    CHECK(r.out.n == 2 && r.out.v[0]->payload_len == 2 && r.out.v[0]->payload[0] == 'A');
    r_close(&r);
    /* %c and #c read the packet's blob too */
    once(&r, "[TCP:flags:PA]-xtlsclone{blob=c;sni_del_ext}(xsplit{pos=#c},)-| \\/", b, n, &v);
    /* without the server_name of www.iana.org: 21 bytes shorter */
    CHECK(r.out.n == 2 && r.out.v[0]->payload_len == t->len - 21);
    r_close(&r);
}

TEST(x5b_tag)
{
    static const char req[] = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    uint8_t b[600];
    size_t n = mk(b, 0, P | A, NULL, 0, req, sizeof(req) - 1);
    xl7_view h = view(L7P_HTTP_REQ, NULL, 0);
    run_t r;
    once(&r, "[TCP:flags:PA]-xtag{pattern=Host;payload=my}(xfake{blob=0x41;payload=my},)-| \\/", b, n, &h);
    CHECK(r.out.n == 2 && r.out.v[0]->xgen);
    r_close(&r);
    /* the label replaces http_req for later actions */
    once(&r, "[TCP:flags:PA]-xtag{pattern=Host;payload=my}(xfake{blob=0x41;payload=http_req},)-| \\/", b, n, &h);
    CHECK_INT(r.out.n, 1);
    r_close(&r);
    once(&r, "[TCP:flags:PA]-xtag{pattern=Host;payload=my}(xfake{blob=0x41},)-| \\/", b, n, &h);
    CHECK_INT(r.out.n, 2); /* "known": not unknown or empty */
    r_close(&r);
    once(&r, "[TCP:flags:PA]-xtag{pattern=nope;payload=my;undetected=other}(xfake{blob=0x41;payload=~other},)-| \\/",
         b, n, &h);
    CHECK_INT(r.out.n, 1);
    r_close(&r);
    once(&r, "[TCP:flags:PA]-xtag{pattern=nope;payload=my}(xfake{blob=0x41;payload=http_req},)-| \\/", b, n, &h);
    CHECK_INT(r.out.n, 2); /* no undetected: the label stays */
    r_close(&r);
    /* a label a later tree sees; a known name works as one */
    once(&r, "[TCP:flags:PA]-xtag{pattern=GET;payload=tls_client_hello}-| [TCP:flags:PA]-xtlsclone{blob=c;fallback=0x42}(xfake{blob=c;payload=all},)-| \\/",
         b, n, &h);
    CHECK_INT(r.out.n, 3);
    r_close(&r);
}

static sbuf evs;
static void tap(const char *line, size_t len, void *ctx)
{
    (void)ctx;
    sb_append(&evs, line, len);
}

TEST(x5b_log_pcap)
{
    static const char req[] = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    static const char fn[] = "x5b_test.pcap";
    uint8_t b[600];
    size_t n = mk(b, 0, P | A, NULL, 0, req, sizeof(req) - 1);
    xl7_view h = view(L7P_HTTP_REQ, NULL, 0);
    run_t r;
    sb_init(&evs);
    ev_set_tap(tap, NULL);
    once(&r, "[TCP:flags:PA]-xlog{msg=hi;pkt;hex}(xmod{ttl=9},)-| \\/", b, n, &h);
    CHECK(r.out.n == 1 && r.out.v[0]->ttl == 9);
    CHECK(evs.data && strstr(evs.data, "\"ev\":\"ext_pkt\""));
    CHECK(evs.data && strstr(evs.data, "\"msg\":\"hi\""));
    CHECK(evs.data && strstr(evs.data, "\"l7payload\":\"http_req\""));
    CHECK(evs.data && strstr(evs.data, "\"hex\":\"474554"));
    r_close(&r);
    ev_set_tap(NULL, NULL);
    sb_free(&evs);
    /* xpcap: the packet as it is at that point of the tree */
    remove(fn);
    r_open(&r, "[TCP:flags:PA]-xmod{ttl=7}(xpcap{file=x5b_test.pcap},)-| \\/");
    r_pkt(&r, DIR_OUT, b, n, &h);
    r_pkt(&r, DIR_OUT, b, n, &h);
    r_close(&r);
    {
        sbuf e;
        pcap_reader *pr;
        pcap_rec rec;
        int k = 0;
        sb_init(&e);
        pr = pcap_open_read(fn, &e);
        CHECK(pr != NULL);
        while (pr && pcap_next(pr, &rec, &e) == 1) {
            CHECK(rec.ip && rec.ip_len == n && rec.ip[8] == 7);
            k++;
        }
        CHECK_INT(k, 2);
        pcap_close_read(pr);
        /* a new strategy starts the file anew, keep appends */
        r_open(&r, "[TCP:flags:PA]-xpcap{file=x5b_test.pcap}-| \\/");
        r_pkt(&r, DIR_OUT, b, n, &h);
        r_close(&r);
        r_open(&r, "[TCP:flags:PA]-xpcap{file=x5b_test.pcap;keep}-| \\/");
        r_pkt(&r, DIR_OUT, b, n, &h);
        r_close(&r);
        pr = pcap_open_read(fn, &e);
        k = 0;
        while (pr && pcap_next(pr, &rec, &e) == 1)
            k++;
        CHECK_INT(k, 2);
        pcap_close_read(pr);
        sb_free(&e);
    }
    remove(fn);
}

void suite_xact5b(void)
{
    RUN(x5b_parse);
    RUN(x5b_http);
    RUN(x5b_synack);
    RUN(x5b_wsize);
    RUN(x5b_syndata_rst);
    RUN(x5b_udp);
    RUN(x5b_tlsclone_mod);
    RUN(x5b_tlsclone_records);
    RUN(x5b_tlsclone_tree);
    RUN(x5b_tag);
    RUN(x5b_log_pcap);
    strategy_set_xact(NULL);
    blob_free_all();
}

#else
void suite_xact5b(void) {}
#endif
