/* Lab censors 12-20 (src/ext/censor_x.c) against hand-made connections. */
#include <stdlib.h>
#include <string.h>

#include "censor.h"
#include "ext/ext.h"
#include "ext_opt.h"
#include "plat.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT

typedef struct {
    uint8_t b[2000];
    size_t n;
} xp;

typedef struct {
    int v6, udp, ttl, badsum;
    int ts;         /* add a timestamp option with this TSval (0 = none) */
    int frag;       /* IPv4: 1 = first fragment (MF), 2 = a later one */
    int v6frag;     /* IPv6 fragment header: 1 = first, 2 = later */
} xopt;

enum { F = 1, S = 2, R = 4, P = 8, A = 16 };
static const char *CLI4 = "10.0.0.1", *SRV4 = "10.0.0.2", *CLI6 = "2001:db8::1", *SRV6 = "2001:db8::2";

static uint32_t sumb(const uint8_t *p, size_t n, uint32_t s)
{
    for (size_t i = 0; i + 1 < n; i += 2)
        s += (uint32_t)(p[i] << 8 | p[i + 1]);
    if (n & 1)
        s += (uint32_t)(p[n - 1] << 8);
    return s;
}

static uint16_t fold(uint32_t s)
{
    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

/* A TCP (or UDP) packet from the client (c2s) or the server */
static xp mk(int c2s, uint8_t flags, uint32_t seq, uint32_t ack, const void *data, size_t dl, const xopt *o)
{
    static const xopt none = {0, 0, 0, 0, 0, 0, 0};
    xp p;
    size_t hl, l4h, optl, l4;
    uint8_t *t, nh;
    const char *src, *dst;
    if (!o)
        o = &none;
    memset(&p, 0, sizeof(p));
    src = o->v6 ? (c2s ? CLI6 : SRV6) : (c2s ? CLI4 : SRV4);
    dst = o->v6 ? (c2s ? SRV6 : CLI6) : (c2s ? SRV4 : CLI4);
    optl = o->ts && !o->udp ? 12 : 0;
    l4h = o->udp ? 8 : 20 + optl;
    l4 = l4h + dl;
    nh = o->udp ? 17 : 6;
    if (o->v6) {
        hl = 40 + (o->v6frag ? 8 : 0);
        p.b[0] = 0x60;
        p.b[4] = (uint8_t)((hl - 40 + l4) >> 8), p.b[5] = (uint8_t)(hl - 40 + l4);
        p.b[6] = o->v6frag ? 44 : nh;
        p.b[7] = (uint8_t)(o->ttl ? o->ttl : 64);
        inet_pton(AF_INET6, src, p.b + 8);
        inet_pton(AF_INET6, dst, p.b + 24);
        if (o->v6frag) {
            p.b[40] = nh;
            p.b[42] = o->v6frag == 2 ? 0x01 : 0x00; /* offset 32 */
            p.b[43] = o->v6frag == 1 ? 0x01 : 0x00; /* M */
        }
    } else {
        hl = 20;
        p.b[0] = 0x45;
        p.b[2] = (uint8_t)((hl + l4) >> 8), p.b[3] = (uint8_t)(hl + l4);
        if (o->frag == 1)
            p.b[6] = 0x20; /* MF */
        if (o->frag == 2)
            p.b[7] = 0x04;
        p.b[8] = (uint8_t)(o->ttl ? o->ttl : 64);
        p.b[9] = nh;
        inet_pton(AF_INET, src, p.b + 12);
        inet_pton(AF_INET, dst, p.b + 16);
        {
            uint16_t cs = fold(sumb(p.b, 20, 0));
            p.b[10] = (uint8_t)(cs >> 8), p.b[11] = (uint8_t)cs;
        }
    }
    t = p.b + hl;
    t[0] = (uint8_t)((c2s ? 40000 : 443) >> 8), t[1] = (uint8_t)(c2s ? 40000 : 443);
    t[2] = (uint8_t)((c2s ? 443 : 40000) >> 8), t[3] = (uint8_t)(c2s ? 443 : 40000);
    if (o->udp) {
        t[4] = (uint8_t)(l4 >> 8), t[5] = (uint8_t)l4;
    } else {
        for (int i = 0; i < 4; i++) {
            t[4 + i] = (uint8_t)(seq >> (24 - 8 * i));
            t[8 + i] = (uint8_t)(ack >> (24 - 8 * i));
        }
        t[12] = (uint8_t)((l4h / 4) << 4);
        t[13] = flags;
        t[14] = 0xff;
        if (optl) {
            t[20] = 1, t[21] = 1, t[22] = 8, t[23] = 10;
            for (int i = 0; i < 4; i++)
                t[24 + i] = (uint8_t)((uint32_t)o->ts >> (24 - 8 * i));
        }
    }
    if (dl)
        memcpy(t + l4h, data, dl);
    {
        int alen = o->v6 ? 16 : 4;
        const uint8_t *sa = o->v6 ? p.b + 8 : p.b + 12;
        uint32_t ps = sumb(sa, (size_t)alen * 2, 0) + nh + (uint32_t)l4;
        uint16_t cs = fold(sumb(t, l4, ps));
        if (o->badsum)
            cs ^= 0x1111;
        if (o->udp)
            t[6] = (uint8_t)(cs >> 8), t[7] = (uint8_t)cs;
        else
            t[16] = (uint8_t)(cs >> 8), t[17] = (uint8_t)cs;
    }
    p.n = hl + l4;
    return p;
}

typedef struct {
    xp sent[8];
    int n;
} xsink;

static void xcollect(const uint8_t *p, size_t len, void *ctx)
{
    xsink *k = ctx;
    if (k->n < 8 && len <= sizeof(k->sent[0].b)) {
        memcpy(k->sent[k->n].b, p, len);
        k->sent[k->n].n = len;
    }
    k->n++;
}

static censor_result run(censor *c, xp p, xsink *k)
{
    censor_result r;
    censor_packet(c, p.b, p.n, xcollect, k, &r);
    return r;
}

static uint64_t fake_now;
static uint64_t clock_ms(void) { return fake_now; }

static censor *open_censor(const char *name, censor_cfg *cfg)
{
    sbuf e;
    censor *c;
    sb_init(&e);
    c = censor_new(name, cfg, &e);
    CHECK(c != NULL);
    sb_free(&e);
    return c;
}

/* a handshake, then the client's first payload */
static void handshake(censor *c, xsink *k, const xopt *o)
{
    run(c, mk(1, S, 1000, 0, NULL, 0, o), k);
    run(c, mk(0, S | A, 5000, 1001, NULL, 0, o), k);
    run(c, mk(1, A, 1001, 5001, NULL, 0, o), k);
}

static uint8_t *load(const char *name, size_t *n)
{
    char path[256];
    snprintf(path, sizeof(path), "tests/data/zapret2/%s", name);
    return (uint8_t *)read_file(path, n);
}

static void test_shape(void)
{
    censor_cfg cfg;
    censor *c;
    xsink k = {0};
    censor_result r;
    char big[1000];
    int dropped = 0, passed = 0;
    static const char req[] = "GET /?q=ultrasurf HTTP/1.1\r\nHost: x\r\n\r\n";

    t_current = "censor 12: freeze after N bytes";
    censor_cfg_default(&cfg);
    cfg.freeze_bytes = 4000;
    c = open_censor("12", &cfg);
    handshake(c, &k, NULL);
    r = run(c, mk(1, P | A, 1001, 5001, req, strlen(req), NULL), &k);
    CHECK_INT(r.what, CENSOR_FIRED);
    CHECK_INT(r.accept, 1);
    memset(big, 'x', sizeof(big));
    for (int i = 0; i < 10; i++) {
        r = run(c, mk(0, P | A, 5001 + 1000u * (uint32_t)i, 1001, big, sizeof(big), NULL), &k);
        if (r.accept)
            passed++;
        else
            dropped++;
    }
    CHECK_INT(passed, 4);
    CHECK_INT(dropped, 6);
    /* a pure ACK of the server still passes: the connection is not closed */
    CHECK_INT(run(c, mk(0, A, 15001, 1001, NULL, 0, NULL), &k).accept, 1);
    /* another connection without the word is left alone */
    censor_reset(c);
    handshake(c, &k, NULL);
    run(c, mk(1, P | A, 1001, 5001, "GET / HTTP/1.1\r\n\r\n", 18, NULL), &k);
    for (int i = 0; i < 10; i++)
        CHECK_INT(run(c, mk(0, P | A, 5001 + 1000u * (uint32_t)i, 1001, big, sizeof(big), NULL), &k).accept, 1);
    /* the word only in the second request: the decision is made on the first */
    censor_reset(c);
    handshake(c, &k, NULL);
    run(c, mk(1, P | A, 1001, 5001, "GET / HTTP/1.1\r\n\r\n", 18, NULL), &k);
    run(c, mk(1, P | A, 1019, 5001, req, strlen(req), NULL), &k);
    for (int i = 0; i < 10; i++)
        CHECK_INT(run(c, mk(0, P | A, 5001 + 1000u * (uint32_t)i, 1001, big, sizeof(big), NULL), &k).accept, 1);
    censor_free(c);

    t_current = "censor 13: token bucket";
    censor_cfg_default(&cfg);
    cfg.rate = 1000; /* bytes per second */
    cfg.burst = 2000;
    cfg.now_ms = clock_ms;
    fake_now = 100000;
    c = open_censor("13", &cfg);
    handshake(c, &k, NULL);
    run(c, mk(1, P | A, 1001, 5001, req, strlen(req), NULL), &k);
    passed = dropped = 0;
    for (int i = 0; i < 5; i++) {
        r = run(c, mk(0, P | A, 5001 + 1000u * (uint32_t)i, 1001, big, sizeof(big), NULL), &k);
        r.accept ? passed++ : dropped++;
    }
    CHECK_INT(passed, 2); /* the burst */
    CHECK_INT(dropped, 3);
    fake_now += 1000; /* one second: 1000 bytes more */
    CHECK_INT(run(c, mk(0, P | A, 9001, 1001, big, sizeof(big), NULL), &k).accept, 1);
    CHECK_INT(run(c, mk(0, P | A, 10001, 1001, big, sizeof(big), NULL), &k).accept, 0);
    censor_free(c);
}

static void test_tls(void)
{
    censor_cfg cfg;
    censor *c;
    xsink k = {0};
    censor_result r;
    size_t n;
    uint8_t *ch = load("tls_clienthello_iana_org.bin", &n), *kyber;
    size_t kn;

    if (!ch)
        return;
    t_current = "censor 14: SNI in the first segment, RST with TTL 64";
    censor_cfg_default(&cfg);
    cfg.words[0] = "iana";
    c = open_censor("14", &cfg);
    handshake(c, &k, NULL);
    k.n = 0;
    r = run(c, mk(1, P | A, 1001, 5001, ch, n, NULL), &k);
    CHECK_INT(r.what, CENSOR_FIRED);
    CHECK_INT(r.accept, 1); /* the packet goes on; the RSTs do the harm */
    CHECK_INT(k.n, 3);
    CHECK_INT(k.sent[0].b[8], 64);                         /* TTL */
    CHECK_INT(k.sent[0].b[33], R | A);                     /* flags */
    CHECK(!memcmp(k.sent[0].b + 12, k.sent[0].b + 12, 4)); /* from the server */
    {
        uint8_t srv[4];
        inet_pton(AF_INET, SRV4, srv);
        CHECK(!memcmp(k.sent[0].b + 12, srv, 4));
    }
    /* split before the name: the first segment has no SNI, nothing happens */
    censor_reset(c);
    handshake(c, &k, NULL);
    k.n = 0;
    r = run(c, mk(1, P | A, 1001, 5001, ch, 60, NULL), &k);
    CHECK_INT(r.what, CENSOR_PASS);
    r = run(c, mk(1, P | A, 1061, 5001, ch + 60, n - 60, NULL), &k);
    CHECK_INT(r.what, CENSOR_PASS);
    CHECK_INT(k.n, 0);
    /* a fake first segment with another name: the real one is not looked at */
    censor_reset(c);
    handshake(c, &k, NULL);
    run(c, mk(1, P | A, 1001, 5001, "\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00", 10, NULL), &k);
    CHECK_INT(run(c, mk(1, P | A, 1001, 5001, ch, n, NULL), &k).what, CENSOR_PASS);
    /* without the SYN the censor does not know the connection */
    censor_reset(c);
    CHECK_INT(run(c, mk(1, P | A, 1001, 5001, ch, n, NULL), &k).what, CENSOR_PASS);
    censor_free(c);

    t_current = "censor 15: reassembly of two segments";
    kyber = load("tls_clienthello_vk_com_kyber.bin", &kn);
    censor_cfg_default(&cfg);
    cfg.words[0] = "vk.com";
    c = open_censor("15", &cfg);
    if (kyber) {
        /* a ClientHello in two segments, the name in the second (it starts at
         * byte 218), is caught on the second */
        handshake(c, &k, NULL);
        CHECK_INT(run(c, mk(1, P | A, 1001, 5001, kyber, 200, NULL), &k).accept, 1);
        r = run(c, mk(1, P | A, 1201, 5001, kyber + 200, kn - 200, NULL), &k);
        CHECK_INT(r.what, CENSOR_FIRED);
        CHECK_INT(r.accept, 0);
        CHECK_INT(run(c, mk(1, A, 1201, 5001, NULL, 0, NULL), &k).what, CENSOR_BLOCKED);
        /* in reverse order: the censor gives up */
        censor_reset(c);
        handshake(c, &k, NULL);
        CHECK_INT(run(c, mk(1, P | A, 1201, 5001, kyber + 200, kn - 200, NULL), &k).what, CENSOR_PASS);
        CHECK_INT(run(c, mk(1, P | A, 1001, 5001, kyber, 200, NULL), &k).what, CENSOR_PASS);
        /* three segments: the name comes after the second */
        censor_reset(c);
        handshake(c, &k, NULL);
        run(c, mk(1, P | A, 1001, 5001, kyber, 50, NULL), &k);
        CHECK_INT(run(c, mk(1, P | A, 1051, 5001, kyber + 50, 50, NULL), &k).what, CENSOR_PASS);
        CHECK_INT(run(c, mk(1, P | A, 1101, 5001, kyber + 100, kn - 100, NULL), &k).what, CENSOR_PASS);
        free(kyber);
    }
    censor_free(c);
    free(ch);
}

static void test_quic(void)
{
#if !GENEVA_EXT_CRYPTO
    censor_cfg cfg;
    sbuf e;
    sb_init(&e);
    t_current = "censor 16: not in a build without cryptography";
    censor_cfg_default(&cfg);
    CHECK(censor_new("16", &cfg, &e) == NULL);
    CHECK(strstr(e.data, "EXT_CRYPTO=0") != NULL);
    sb_free(&e);
#else
    censor_cfg cfg;
    censor *c;
    xsink k = {0};
    xopt u = {0, 1, 0, 0, 0, 0, 0};
    size_t n, gn;
    uint8_t *q = load("quic_initial_www_google_com.bin", &n), *g = load("quic2_example_com.bin", &gn);

    t_current = "censor 16: QUIC Initial SNI";
    censor_cfg_default(&cfg);
    cfg.words[0] = "google";
    c = open_censor("16", &cfg);
    if (q && g) {
        censor_result r = run(c, mk(1, 0, 0, 0, q, n, &u), &k);
        CHECK_INT(r.what, CENSOR_FIRED);
        CHECK_INT(r.accept, 0);
        CHECK_INT(run(c, mk(1, 0, 0, 0, "x", 1, &u), &k).what, CENSOR_BLOCKED);
        /* the server's datagrams are not touched */
        CHECK_INT(run(c, mk(0, 0, 0, 0, "y", 1, &u), &k).accept, 1);
        /* a first Initial with another name decides the flow */
        censor_reset(c);
        CHECK_INT(run(c, mk(1, 0, 0, 0, g, gn, &u), &k).what, CENSOR_PASS);
        CHECK_INT(run(c, mk(1, 0, 0, 0, q, n, &u), &k).what, CENSOR_PASS);
        /* garbage first: still waiting for an Initial */
        censor_reset(c);
        CHECK_INT(run(c, mk(1, 0, 0, 0, "garbage", 7, &u), &k).what, CENSOR_PASS);
        CHECK_INT(run(c, mk(1, 0, 0, 0, q, n, &u), &k).what, CENSOR_FIRED);
        /* a later IP fragment is never read */
        censor_reset(c);
        u.frag = 2;
        CHECK_INT(run(c, mk(1, 0, 0, 0, q, n, &u), &k).what, CENSOR_PASS);
    }
    free(q);
    free(g);
    censor_free(c);
#endif
}

static void test_misc(void)
{
    censor_cfg cfg;
    censor *c;
    xsink k = {0};
    censor_result r;
    static const char req[] = "GET / HTTP/1.1\r\nHost: ultrasurf.example\r\n\r\n";

    t_current = "censor 17: IP block";
    censor_cfg_default(&cfg);
    cfg.block_ip[0].ver = 4;
    inet_pton(AF_INET, SRV4, cfg.block_ip[0].a);
    cfg.nblock_ip = 1;
    c = open_censor("17", &cfg);
    r = run(c, mk(1, S, 1000, 0, NULL, 0, NULL), &k);
    CHECK_INT(r.accept, 0);
    CHECK_INT(r.what, CENSOR_FIRED);
    /* reported once: the next packets of the address are "blocked" */
    r = run(c, mk(0, S | A, 1, 1001, NULL, 0, NULL), &k);
    CHECK_INT(r.accept, 0);
    CHECK_INT(r.what, CENSOR_BLOCKED);
    censor_reset(c);
    CHECK_INT(run(c, mk(1, S, 1000, 0, NULL, 0, NULL), &k).what, CENSOR_FIRED);
    {
        xopt v6 = {1, 0, 0, 0, 0, 0, 0};
        CHECK_INT(run(c, mk(1, S, 1000, 0, NULL, 0, &v6), &k).accept, 1);
    }
    censor_free(c);

    t_current = "censor 18: HTTP redirect";
    censor_cfg_default(&cfg);
    c = open_censor("18", &cfg);
    handshake(c, &k, NULL);
    k.n = 0;
    r = run(c, mk(1, P | A, 1001, 5001, req, strlen(req), NULL), &k);
    CHECK_INT(r.what, CENSOR_FIRED);
    CHECK_INT(r.accept, 0);
    CHECK_INT(k.n, 2);
    CHECK(k.n >= 1 && k.sent[0].n > 40 && !memcmp(k.sent[0].b + 40, "HTTP/1.1 302 Found\r\n", 20));
    CHECK(k.n >= 1 && strstr((const char *)k.sent[0].b + 40, "Location: http://block.example/") != NULL);
    CHECK(k.n >= 2 && k.sent[1].b[33] == R);
    /* "hoSt:" and a method after "\r\n" are not seen by this DPI */
    censor_reset(c);
    handshake(c, &k, NULL);
    CHECK_INT(run(c, mk(1, P | A, 1001, 5001, "GET / HTTP/1.1\r\nhoSt: ultrasurf.example\r\n\r\n", 43, NULL), &k).what,
              CENSOR_PASS);
    censor_reset(c);
    handshake(c, &k, NULL);
    CHECK_INT(run(c, mk(1, P | A, 1001, 5001, "\r\nGET / HTTP/1.1\r\nHost: ultrasurf.example\r\n\r\n", 45, NULL), &k)
                  .what,
              CENSOR_PASS);
    censor_reset(c);
    handshake(c, &k, NULL);
    CHECK_INT(run(c, mk(1, P | A, 1001, 5001, "GET / HTTP/1.1\r\nHost: UltraSurf.example\r\n\r\n", 43, NULL), &k).what,
              CENSOR_PASS);
    censor_free(c);

    t_current = "censor 19: TTL, checksum and PAWS checks";
    censor_cfg_default(&cfg);
    cfg.min_ttl = 5;
    c = open_censor("19", &cfg);
    {
        xopt ts = {0, 0, 0, 0, 1000, 0, 0}, lowttl = {0, 0, 3, 0, 1001, 0, 0}, bad = {0, 0, 0, 1, 1001, 0, 0},
             old = {0, 0, 0, 0, 900, 0, 0}, ok = {0, 0, 0, 0, 1002, 0, 0};
        static const char fake[] = "GET / HTTP/1.1\r\n\r\n12345678901234";
        static const char real[] = "GET /?ultrasurf HTTP/1.1\r\n\r\n";
        const xopt *fooling[] = {&lowttl, &bad, &old};
        for (int i = 0; i < 3; i++) {
            censor_reset(c);
            handshake(c, &k, &ts);
            /* a fake of the same length: the censor ignores it ... */
            CHECK_INT(run(c, mk(1, P | A, 1001, 5001, fake, strlen(real), fooling[i]), &k).what, CENSOR_PASS);
            /* ... and catches the real request */
            CHECK_INT(run(c, mk(1, P | A, 1001, 5001, real, strlen(real), &ok), &k).what, CENSOR_FIRED);
        }
        /* a fake it believes (no fooling) moves its sequence number: the real one passes */
        censor_reset(c);
        handshake(c, &k, &ts);
        CHECK_INT(run(c, mk(1, P | A, 1001, 5001, fake, strlen(real), &ok), &k).what, CENSOR_PASS);
        CHECK_INT(run(c, mk(1, P | A, 1001, 5001, real, strlen(real), &ok), &k).what, CENSOR_PASS);
        /* a fake SYN (low TTL, bad checksum) does not re-synchronize it */
        for (int i = 0; i < 2; i++) {
            censor_reset(c);
            handshake(c, &k, &ts);
            run(c, mk(1, S, 77777, 0, NULL, 0, fooling[i]), &k);
            CHECK_INT(run(c, mk(1, P | A, 1001, 5001, real, strlen(real), &ok), &k).what, CENSOR_FIRED);
        }
        /* a new connection on the same 4-tuple starts afresh: the old TSval
         * does not hide the packets of the new one (PAWS) */
        censor_reset(c);
        handshake(c, &k, &ok);
        CHECK_INT(run(c, mk(1, P | A, 1001, 5001, fake, strlen(fake), &ok), &k).what, CENSOR_PASS);
        handshake(c, &k, &old);
        CHECK_INT(run(c, mk(1, P | A, 1001, 5001, real, strlen(real), &old), &k).what, CENSOR_FIRED);
    }
    censor_free(c);

    t_current = "censors 12-20 answer Geneva's readiness probe";
    censor_cfg_default(&cfg);
    c = open_censor("15", &cfg);
    {
        xp p = mk(1, S, 13337, 0, NULL, 0, NULL);
        p.b[(p.b[0] & 15) * 4] = 2222 >> 8, p.b[(p.b[0] & 15) * 4 + 1] = 2222 & 0xff;
        CHECK_INT(run(c, p, &k).what, CENSOR_CONTROL);
    }
    censor_free(c);

    t_current = "censor 20: only first fragments";
    censor_cfg_default(&cfg);
    c = open_censor("20", &cfg);
    {
        xopt f1 = {0, 0, 0, 0, 0, 1, 0}, f2 = {0, 0, 0, 0, 0, 2, 0}, v6 = {1, 0, 0, 0, 0, 0, 1},
             v6b = {1, 0, 0, 0, 0, 0, 2}, v6s = {1, 0, 0, 0, 0, 0, 0};
        handshake(c, &k, NULL);
        CHECK_INT(run(c, mk(1, P | A, 1001, 5001, "GET / HTTP/1.1", 14, &f1), &k).what, CENSOR_PASS);
        CHECK_INT(run(c, mk(1, P | A, 1001, 5001, "?q=ultrasurf", 12, &f2), &k).what, CENSOR_PASS);
        r = run(c, mk(1, P | A, 1001, 5001, "?q=ultrasurf", 12, &f1), &k);
        CHECK_INT(r.what, CENSOR_FIRED);
        CHECK_INT(r.accept, 0);
        /* IPv6: through the fragment header */
        censor_reset(c);
        handshake(c, &k, &v6s);
        CHECK_INT(run(c, mk(1, P | A, 1001, 5001, "?q=ultrasurf", 12, &v6b), &k).what, CENSOR_PASS);
        CHECK_INT(run(c, mk(1, P | A, 1001, 5001, "?q=ultrasurf", 12, &v6), &k).what, CENSOR_FIRED);
    }
    censor_free(c);

    t_current = "censors 12-20 need --ext";
    ext_reset();
    censor_cfg_default(&cfg);
    {
        sbuf e;
        sb_init(&e);
        CHECK(censor_new("14", &cfg, &e) == NULL);
        sb_free(&e);
    }
}

void suite_censor_x(void)
{
    /* the models of the extensions exist only with --ext */
    static const optdef defs[] = {EXT_OPT, {NULL, 0, 0, NULL, NULL}};
    const char *argv[] = {"--ext", NULL};
    args_t a;
    char err[64];
    args_parse(&a, 1, (char **)argv, defs, err, sizeof(err));
    ext_parse_args(&a, "test");
    args_free(&a);
    test_shape();
    test_tls();
    test_quic();
    test_misc();
    ext_reset();
}
#else
void suite_censor_x(void) {}
#endif
