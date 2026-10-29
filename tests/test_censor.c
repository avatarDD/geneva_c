/* Censor models (censor.c) against hand-made connections. */
#include <stdlib.h>
#include <string.h>

#include "censor.h"
#include "pkt.h"
#include "plat.h"
#include "test.h"
#include "util.h"

#define CLI "10.0.0.1"
#define SRV "10.0.0.2"
#define CP 40000
#define SP 80

enum { F = 0x01, S = 0x02, R = 0x04, P = 0x08, A = 0x10 };

typedef struct {
    uint8_t b[1500];
    size_t n;
} pk;

static uint32_t sum_addr(const uint8_t *a, size_t n)
{
    uint32_t s = 0;
    for (size_t i = 0; i < n; i += 2)
        s += (uint32_t)(a[i] << 8 | a[i + 1]);
    return s;
}

/* An IPv4 TCP packet. optlen zero bytes of options follow the header;
 * dofs < 0 sets the data offset to match, otherwise to dofs. */
static pk tcp4(const char *src, const char *dst, uint16_t sp, uint16_t dp, uint8_t flags, uint32_t seq,
               uint32_t ack, const char *data, int optlen, int dofs, int badsum)
{
    pk p;
    size_t dl = data ? strlen(data) : 0, tl = 20 + (size_t)optlen + dl;
    uint8_t *t = p.b + 20;
    memset(&p, 0, sizeof(p));
    p.b[0] = 0x45;
    p.b[2] = (uint8_t)((20 + tl) >> 8), p.b[3] = (uint8_t)(20 + tl);
    p.b[8] = 64;
    p.b[9] = 6;
    inet_pton(AF_INET, src, p.b + 12);
    inet_pton(AF_INET, dst, p.b + 16);
    t[0] = (uint8_t)(sp >> 8), t[1] = (uint8_t)sp, t[2] = (uint8_t)(dp >> 8), t[3] = (uint8_t)dp;
    for (int i = 0; i < 4; i++) {
        t[4 + i] = (uint8_t)(seq >> (24 - 8 * i));
        t[8 + i] = (uint8_t)(ack >> (24 - 8 * i));
    }
    t[12] = (uint8_t)((dofs < 0 ? 5 + optlen / 4 : dofs) << 4);
    t[13] = flags;
    t[14] = 0xff;
    if (dl)
        memcpy(t + 20 + optlen, data, dl);
    {
        uint32_t ps = sum_addr(p.b + 12, 8) + 6 + (uint32_t)tl;
        uint16_t cs = inet_csum(t, tl, ps);
        if (badsum)
            cs ^= 0x1234;
        t[16] = (uint8_t)(cs >> 8), t[17] = (uint8_t)cs;
    }
    p.n = 20 + tl;
    return p;
}

#define C2S(fl, seq, ack, data) tcp4(CLI, SRV, CP, SP, fl, seq, ack, data, 0, -1, 0)
#define S2C(fl, seq, ack, data) tcp4(SRV, CLI, SP, CP, fl, seq, ack, data, 0, -1, 0)

static const char *GET = "GET /?q=ultrasurf HTTP/1.1\r\n\r\n";

typedef struct {
    pk sent[16];
    int n;
} sink;

static void collect(const uint8_t *p, size_t len, void *ctx)
{
    sink *k = ctx;
    if (k->n < 16 && len <= sizeof(k->sent[0].b)) {
        memcpy(k->sent[k->n].b, p, len);
        k->sent[k->n++].n = len;
    }
}

static censor_result feed(censor *c, pk p, sink *k)
{
    censor_result r;
    censor_packet(c, p.b, p.n, collect, k, &r);
    return r;
}

static censor *mk(const char *name)
{
    censor_cfg cfg;
    sbuf e;
    censor *c;
    sb_init(&e);
    censor_cfg_default(&cfg);
    c = censor_new(name, &cfg, &e);
    CHECK(c != NULL);
    sb_free(&e);
    return c;
}

/* The handshake: client ISN 1000, server ISN 5000. */
static void handshake(censor *c, sink *k)
{
    feed(c, C2S(S, 1000, 0, NULL), k);
    feed(c, S2C(S | A, 5000, 1001, NULL), k);
    feed(c, C2S(A, 1001, 5001, NULL), k);
}

static int verdict(censor *c, pk p, sink *k, int *what)
{
    censor_result r = feed(c, p, k);
    if (what)
        *what = r.what;
    return r.accept;
}

static void check_rst(const pk *p, const char *src, const char *dst, uint16_t sp, uint16_t dp, uint32_t seq,
                      uint32_t ack)
{
    gpkt *g = pkt_parse(p->b, p->n);
    uint8_t a[4], b[4];
    CHECK(g != NULL);
    if (!g)
        return;
    inet_pton(AF_INET, src, a);
    inet_pton(AF_INET, dst, b);
    CHECK(!memcmp(g->src, a, 4) && !memcmp(g->dst, b, 4));
    CHECK_INT(g->sport, sp);
    CHECK_INT(g->dport, dp);
    CHECK_INT(g->seq, seq);
    CHECK_INT(g->ack, ack);
    CHECK_INT(g->tcpflags, R);
    CHECK_INT(g->window, 8192);
    CHECK_INT(g->ttl, 64);
    CHECK_INT(inet_csum(p->b, 20, 0), 0);
    CHECK_INT(inet_csum(p->b + 20, p->n - 20, sum_addr(p->b + 12, 8) + 6 + (uint32_t)(p->n - 20)), 0);
    pkt_free(g);
}

static void test_names(void)
{
    censor_cfg cfg;
    sbuf e;
    size_t n;
    const censor_info *m = censor_models(&n);
    t_current = "censor names";
    sb_init(&e);
    censor_cfg_default(&cfg);
    CHECK_INT(n, 13);
    for (size_t i = 0; i < n; i++) {
        censor *c = censor_new(m[i].name, &cfg, &e);
        CHECK(c != NULL);
        if (c)
            CHECK_STR(censor_name(c), m[i].name);
        censor_free(c);
    }
    {
        censor *c = censor_new("censor8b", &cfg, &e);
        CHECK(c && !strcmp(censor_name(c), "8b"));
        censor_free(c);
    }
    CHECK(censor_new("12", &cfg, &e) == NULL);
    CHECK(strstr(e.data, "unknown censor") != NULL);
    sb_free(&e);
}

static void test_censor1(void)
{
    sink k = {0};
    censor *c = mk("1");
    int what;
    t_current = "censor 1";
    handshake(c, &k);
    CHECK(verdict(c, C2S(P | A, 1001, 5001, "GET / HTTP/1.1\r\n\r\n"), &k, &what));
    CHECK_INT(what, CENSOR_PASS);
    CHECK(!verdict(c, C2S(P | A, 1019, 5001, GET), &k, &what));
    CHECK_INT(what, CENSOR_FIRED);
    /* everything from the client is dropped now, the server still passes */
    CHECK(!verdict(c, C2S(A, 1019, 5001, NULL), &k, &what));
    CHECK_INT(what, CENSOR_BLOCKED);
    CHECK(verdict(c, S2C(A, 5001, 1019, NULL), &k, NULL));
    CHECK_INT(k.n, 0);
    /* a fresh censor: no SYN seen, the sequence number does not match */
    censor_reset(c);
    CHECK(verdict(c, C2S(P | A, 1019, 5001, GET), &k, &what));
    /* a SYN with another sequence number desynchronizes it */
    censor_reset(c);
    handshake(c, &k);
    feed(c, C2S(S, 777, 0, NULL), &k);
    CHECK(verdict(c, C2S(P | A, 1001, 5001, GET), &k, NULL));
    /* data offset 0: the options count as data (scapy), the TCB moves on */
    censor_reset(c);
    feed(c, C2S(S, 1000, 0, NULL), &k);
    feed(c, tcp4(CLI, SRV, CP, SP, A, 1001, 5001, NULL, 12, 0, 0), &k);
    CHECK(verdict(c, C2S(P | A, 1001, 5001, GET), &k, NULL));
    /* the control packet of Geneva's evaluator */
    CHECK(!verdict(c, tcp4(CLI, SRV, 2222, SP, S, 13337, 0, NULL, 0, -1, 0), &k, &what));
    CHECK_INT(what, CENSOR_CONTROL);
    censor_free(c);
}

static void test_rst_censors(void)
{
    sink k = {0};
    censor *c;
    censor_cfg cfg;
    sbuf e;
    int what;
    t_current = "censor 2";
    c = mk("2");
    handshake(c, &k);
    CHECK(verdict(c, C2S(P | A, 1001, 5001, GET), &k, &what));
    CHECK_INT(what, CENSOR_FIRED);
    CHECK_INT(k.n, 5);
    check_rst(&k.sent[0], SRV, CLI, SP, CP, 5001, 1001 + (uint32_t)strlen(GET));
    /* no drop-all: the next request is judged on its own */
    k.n = 0;
    CHECK(verdict(c, C2S(A, 1031, 5001, NULL), &k, &what));
    CHECK_INT(what, CENSOR_PASS);
    censor_free(c);

    t_current = "censor 3";
    c = mk("3");
    k.n = 0;
    handshake(c, &k);
    CHECK(verdict(c, C2S(P | A, 1001, 5001, GET), &k, NULL));
    CHECK_INT(k.n, 10);
    check_rst(&k.sent[0], SRV, CLI, SP, CP, 5001, 1001 + (uint32_t)strlen(GET));
    /* to the server: from the client's address by default */
    check_rst(&k.sent[1], CLI, SRV, CP, SP, 1001, 5001);
    censor_free(c);

    /* Geneva's own behaviour: the censor's address */
    sb_init(&e);
    censor_cfg_default(&cfg);
    cfg.spoof_client = 0;
    cfg.has_ip4 = 1;
    inet_pton(AF_INET, "10.0.0.254", cfg.ip4);
    c = censor_new("3", &cfg, &e);
    k.n = 0;
    handshake(c, &k);
    feed(c, C2S(P | A, 1001, 5001, GET), &k);
    CHECK_INT(k.n, 10);
    check_rst(&k.sent[1], "10.0.0.254", SRV, CP, SP, 1001, 5001);
    censor_free(c);
    /* no address known: only the client gets RSTs */
    cfg.has_ip4 = 0;
    c = censor_new("3", &cfg, &e);
    k.n = 0;
    handshake(c, &k);
    feed(c, C2S(P | A, 1001, 5001, GET), &k);
    CHECK_INT(k.n, 5);
    censor_free(c);
    sb_free(&e);

    t_current = "censor 5";
    c = mk("5");
    k.n = 0;
    handshake(c, &k);
    CHECK(verdict(c, C2S(P | A, 1001, 5001, GET), &k, NULL));
    CHECK_INT(k.n, 5);
    check_rst(&k.sent[4], CLI, SRV, CP, SP, 1001, 5001);
    censor_free(c);
}

static void test_censor4(void)
{
    sink k = {0};
    censor *c = mk("4");
    t_current = "censor 4";
    /* synchronizes on a bare ACK too: an ACK with a wrong sequence number
     * moves the TCB away from the connection */
    feed(c, C2S(S, 1000, 0, NULL), &k);
    feed(c, C2S(A, 50, 5001, NULL), &k);
    CHECK(verdict(c, C2S(P | A, 1001, 5001, GET), &k, NULL));
    /* ... and a right one brings it back */
    feed(c, C2S(A, 1001, 5001, NULL), &k);
    CHECK(!verdict(c, C2S(P | A, 1001, 5001, GET), &k, NULL));
    censor_free(c);
}

static void test_censor6_7(void)
{
    sink k = {0};
    censor *c = mk("6");
    t_current = "censor 6";
    CHECK(!verdict(c, C2S(P | A, 1, 1, GET), &k, NULL)); /* any packet, no TCB needed */
    censor_reset(c);
    feed(c, S2C(R, 1, 0, NULL), &k); /* any RST, from anywhere */
    CHECK(verdict(c, C2S(P | A, 1, 1, GET), &k, NULL));
    censor_reset(c);
    feed(c, C2S(F | A, 1, 0, NULL), &k); /* FA is not "F" */
    CHECK(!verdict(c, C2S(P | A, 1, 1, GET), &k, NULL));
    censor_free(c);

    t_current = "censor 7";
    c = mk("7");
    handshake(c, &k);
    /* a RST of another connection does not tear the TCB down */
    feed(c, tcp4(CLI, SRV, CP + 1, SP, R, 1, 0, NULL, 0, -1, 0), &k);
    CHECK(!verdict(c, C2S(P | A, 1001, 5001, GET), &k, NULL));
    censor_reset(c);
    handshake(c, &k);
    feed(c, C2S(R, 99999, 0, NULL), &k); /* any sequence number */
    CHECK(verdict(c, C2S(P | A, 1001, 5001, GET), &k, NULL));
    censor_free(c);
}

static void test_censor8(void)
{
    sink k = {0};
    censor *c = mk("8");
    t_current = "censor 8";
    handshake(c, &k);
    feed(c, C2S(R, 99999, 0, NULL), &k); /* out of sequence: ignored */
    CHECK(!verdict(c, C2S(P | A, 1001, 5001, GET), &k, NULL));
    censor_reset(c);
    handshake(c, &k);
    feed(c, C2S(R, 1001, 0, NULL), &k);
    CHECK(verdict(c, C2S(P | A, 1001, 5001, GET), &k, NULL));
    /* a bad checksum does not matter to it */
    censor_reset(c);
    handshake(c, &k);
    feed(c, tcp4(CLI, SRV, CP, SP, R, 1001, 0, NULL, 0, -1, 1), &k);
    CHECK(verdict(c, C2S(P | A, 1001, 5001, GET), &k, NULL));
    censor_free(c);
}

static void test_censor8b(void)
{
    sink k = {0};
    censor *c = mk("8b");
    int what;
    t_current = "censor 8b";
    handshake(c, &k);
    CHECK(verdict(c, C2S(P | A, 1001, 5001, GET), &k, &what));
    CHECK_INT(what, CENSOR_FIRED);
    CHECK_INT(k.n, 10);
    /* both hosts are flagged: any later packet between them gets RSTs */
    k.n = 0;
    CHECK(verdict(c, S2C(A, 5001, 1031, NULL), &k, &what));
    CHECK_INT(what, CENSOR_BLOCKED);
    CHECK_INT(k.n, 10);
    censor_reset(c);
    k.n = 0;
    handshake(c, &k);
    feed(c, C2S(R, 1001, 0, NULL), &k);
    CHECK(verdict(c, C2S(P | A, 1001, 5001, GET), &k, &what));
    CHECK_INT(what, CENSOR_PASS);
    /* a second SYN lists the TCB twice (Python list): one RST is not enough */
    censor_reset(c);
    feed(c, C2S(S, 1000, 0, NULL), &k);
    feed(c, C2S(S, 1000, 0, NULL), &k); /* seq is now 1002 */
    feed(c, C2S(R, 1002, 0, NULL), &k);
    verdict(c, C2S(P | A, 1002, 5001, GET), &k, &what);
    CHECK_INT(what, CENSOR_FIRED);
    censor_reset(c);
    feed(c, C2S(S, 1000, 0, NULL), &k);
    feed(c, C2S(S, 1000, 0, NULL), &k);
    feed(c, C2S(R, 1002, 0, NULL), &k);
    feed(c, C2S(R, 1002, 0, NULL), &k);
    verdict(c, C2S(P | A, 1002, 5001, GET), &k, &what);
    CHECK_INT(what, CENSOR_PASS);
    /* data offsets below 5 are ignored */
    censor_reset(c);
    handshake(c, &k);
    verdict(c, tcp4(CLI, SRV, CP, SP, P | A, 1001, 5001, GET, 0, 4, 0), &k, &what);
    CHECK_INT(what, CENSOR_PASS);
    censor_free(c);
}

static void test_censor9(void)
{
    sink k = {0};
    censor *c = mk("9");
    t_current = "censor 9";
    handshake(c, &k);
    CHECK(!verdict(c, C2S(P | A, 1001, 5001, GET), &k, NULL));
    /* RST, then an insertion packet: the TCB follows the wrong sequence */
    censor_reset(c);
    handshake(c, &k);
    feed(c, C2S(R, 1001, 0, NULL), &k);
    feed(c, C2S(A, 7777, 5001, "xx"), &k);
    CHECK(verdict(c, C2S(P | A, 1001, 5001, GET), &k, NULL));
    /* the packet it re-synchronizes on is checked too */
    censor_reset(c);
    handshake(c, &k);
    feed(c, C2S(F, 1001, 0, NULL), &k);
    CHECK(!verdict(c, C2S(P | A, 1001, 5001, GET), &k, NULL));
    censor_free(c);
}

static void test_censor10_11(void)
{
    sink k = {0};
    censor *c = mk("10");
    t_current = "censor 10";
    handshake(c, &k);
    CHECK(verdict(c, C2S(P | A, 1001, 5001, GET), &k, NULL)); /* RSTs, then accept */
    CHECK_INT(k.n, 10);
    /* an insertion RST with a bad checksum is ignored */
    censor_reset(c);
    handshake(c, &k);
    feed(c, tcp4(CLI, SRV, CP, SP, R, 1001, 0, NULL, 0, -1, 1), &k);
    feed(c, C2S(A, 7777, 5001, "xx"), &k);
    k.n = 0;
    feed(c, C2S(P | A, 1001, 5001, GET), &k);
    CHECK_INT(k.n, 10);
    /* a good one: re-synchronizes on the next packet of the tuple */
    censor_reset(c);
    handshake(c, &k);
    feed(c, C2S(R, 1001, 0, NULL), &k);
    feed(c, tcp4(CLI, SRV, CP, SP, A, 1001, 5001, "xx", 0, -1, 0), &k); /* seq -> 1003 */
    k.n = 0;
    feed(c, C2S(P | A, 1001, 5001, GET), &k);
    CHECK_INT(k.n, 0);
    /* RA is no teardown for 10 */
    censor_reset(c);
    handshake(c, &k);
    feed(c, C2S(R | A, 1001, 0, NULL), &k);
    feed(c, C2S(A, 7777, 5001, "xx"), &k);
    k.n = 0;
    feed(c, C2S(P | A, 1001, 5001, GET), &k);
    CHECK_INT(k.n, 10);
    censor_free(c);

    t_current = "censor 11";
    c = mk("11");
    handshake(c, &k);
    feed(c, C2S(R | A, 1001, 0, NULL), &k);
    feed(c, tcp4(CLI, SRV, CP, SP, A, 1001, 5001, "xx", 0, -1, 0), &k);
    k.n = 0;
    feed(c, C2S(P | A, 1001, 5001, GET), &k);
    CHECK_INT(k.n, 0);
    /* no SYN seen: synchronizes on an ACK */
    censor_reset(c);
    feed(c, C2S(A, 1001, 5001, NULL), &k);
    k.n = 0;
    feed(c, C2S(P | A, 1001, 5001, GET), &k);
    CHECK_INT(k.n, 10);
    censor_free(c);
}

static void test_new_run(void)
{
    sink k = {0};
    censor *c = mk("6");
    int what;
    t_current = "censor new run";
    censor_new_run(c); /* "geneva censor" starts with it */
    handshake(c, &k);
    CHECK(!verdict(c, C2S(P | A, 1001, 5001, GET), &k, NULL));
    censor_new_run(c);
    /* a late RST of the previous run is not seen: no teardown, no drop */
    CHECK(verdict(c, S2C(R, 5001, 0, NULL), &k, &what));
    CHECK_INT(what, CENSOR_OLD);
    CHECK(verdict(c, C2S(P | A, 1001, 5001, GET), &k, &what));
    CHECK_INT(what, CENSOR_OLD);
    /* the next run's connection is censored */
    feed(c, tcp4(CLI, SRV, CP + 1, SP, S, 1, 0, NULL, 0, -1, 0), &k);
    CHECK(!verdict(c, tcp4(CLI, SRV, CP + 1, SP, P | A, 2, 1, GET, 0, -1, 0), &k, &what));
    CHECK_INT(what, CENSOR_FIRED);
    /* a SYN opens an old 4-tuple again */
    censor_new_run(c);
    CHECK(verdict(c, C2S(S, 1000, 0, NULL), &k, &what));
    CHECK_INT(what, CENSOR_PASS);
    CHECK(!verdict(c, C2S(P | A, 1001, 5001, GET), &k, &what));
    CHECK_INT(what, CENSOR_FIRED);
    censor_free(c);
}

static pk udp4(const char *src, const char *dst, uint16_t sp, uint16_t dp, const uint8_t *data, size_t dl)
{
    pk p;
    memset(&p, 0, sizeof(p));
    p.b[0] = 0x45;
    p.b[2] = (uint8_t)((28 + dl) >> 8), p.b[3] = (uint8_t)(28 + dl);
    p.b[8] = 64;
    p.b[9] = 17;
    inet_pton(AF_INET, src, p.b + 12);
    inet_pton(AF_INET, dst, p.b + 16);
    p.b[20] = (uint8_t)(sp >> 8), p.b[21] = (uint8_t)sp, p.b[22] = (uint8_t)(dp >> 8), p.b[23] = (uint8_t)dp;
    p.b[24] = (uint8_t)((8 + dl) >> 8), p.b[25] = (uint8_t)(8 + dl);
    memcpy(p.b + 28, data, dl);
    p.n = 28 + dl;
    return p;
}

static void test_dns(void)
{
    static const uint8_t q[] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 9, 'U', 'l', 't', 'r',
                                'a', 's', 'u', 'r', 'f', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1};
    uint8_t buf[64];
    sink k = {0};
    censor *c = mk("dns");
    censor_result r;
    gpkt *g;
    t_current = "dns censor";
    r = feed(c, udp4(CLI, SRV, 5353, 53, q, sizeof(q)), &k);
    CHECK(r.accept);
    CHECK_INT(r.what, CENSOR_FIRED);
    CHECK_STR(r.action, "dns");
    CHECK_INT(k.n, 1);
    g = pkt_parse(k.sent[0].b, k.sent[0].n);
    CHECK(g && g->l4 == LAYER_UDP);
    if (g) {
        const uint8_t *d = g->payload;
        CHECK_INT(g->sport, 53);
        CHECK_INT(g->dport, 5353);
        CHECK_INT(g->payload_len, sizeof(q) + 16);
        CHECK(d[0] == 0x12 && d[1] == 0x34 && d[2] == 0x81 && d[3] == 0x80);
        CHECK(d[6] == 0 && d[7] == 1);
        CHECK(!memcmp(d + sizeof(q) + 12, "\x0a\x0a\x22\x22", 4));
        CHECK_INT(inet_csum(k.sent[0].b + 20, k.sent[0].n - 20,
                            sum_addr(k.sent[0].b + 12, 8) + 17 + (uint32_t)(k.sent[0].n - 20)),
                  0);
        pkt_free(g);
    }
    /* AAAA */
    memcpy(buf, q, sizeof(q));
    buf[sizeof(q) - 3] = 28;
    k.n = 0;
    feed(c, udp4(CLI, SRV, 5353, 53, buf, sizeof(q)), &k);
    CHECK_INT(k.n, 1);
    CHECK_INT(k.sent[0].n, 28 + sizeof(q) + 12 + 16);
    /* answers and other names pass */
    buf[sizeof(q) - 3] = 1;
    buf[2] = 0x81;
    k.n = 0;
    CHECK_INT(feed(c, udp4(SRV, CLI, 53, 5353, buf, sizeof(q)), &k).what, CENSOR_PASS);
    memcpy(buf, q, sizeof(q));
    buf[14] = 'x';
    CHECK_INT(feed(c, udp4(CLI, SRV, 5353, 53, buf, sizeof(q)), &k).what, CENSOR_PASS);
    /* a compressed name is not followed */
    {
        static const uint8_t cq[] = {0x12, 0x34, 0x01, 0x00, 0, 2, 0, 0, 0, 0, 0, 0,
                                     9, 'u', 'l', 't', 'r', 'a', 's', 'u', 'r', 'f', 0xc0, 28, 0, 1, 0, 1,
                                     7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1};
        CHECK_INT(feed(c, udp4(CLI, SRV, 5353, 53, cq, sizeof(cq)), &k).what, CENSOR_PASS);
    }
    /* truncated queries */
    for (size_t n = 0; n < sizeof(q); n++)
        CHECK_INT(feed(c, udp4(CLI, SRV, 5353, 53, q, n), &k).what, CENSOR_PASS);
    CHECK_INT(k.n, 0);
    censor_free(c);
}

/* Random packets: no crash, no read past the end (run under ASan). */
static void test_fuzz(void)
{
    size_t n;
    const censor_info *m = censor_models(&n);
    uint8_t b[96];
    uint32_t x = 12345;
    t_current = "censor fuzz";
    for (size_t i = 0; i < n; i++) {
        censor *c = mk(m[i].name);
        sink k = {0};
        for (int it = 0; it < 3000; it++) {
            size_t len = (x = x * 1103515245 + 12345) % sizeof(b);
            uint8_t *p = xmalloc(len ? len : 1);
            censor_result r;
            for (size_t j = 0; j < len; j++)
                b[j] = (uint8_t)((x = x * 1103515245 + 12345) >> 16);
            if (len) {
                b[0] = (uint8_t)((it & 1 ? 0x40 : 0x60) | (b[0] & 15));
                if (len > 9 && it % 3 == 0)
                    b[9] = (it & 2) ? 6 : 17;
            }
            memcpy(p, b, len);
            k.n = 0;
            censor_packet(c, p, len, collect, &k, &r);
            free(p);
        }
        censor_free(c);
    }
    CHECK(1);
}

void suite_censor(void)
{
    test_names();
    test_censor1();
    test_rst_censors();
    test_censor4();
    test_censor6_7();
    test_censor8();
    test_censor8b();
    test_censor9();
    test_censor10_11();
    test_new_run();
    test_dns();
    test_fuzz();
}
