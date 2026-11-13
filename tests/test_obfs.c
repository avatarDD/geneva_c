/* Stage X13a: the two-sided obfuscation x-actions of zapret2's
 * zapret-obfs.lua (src/ext/xact_obfs.c): each one run on one end's
 * outbound forest and the other end's inbound forest gives back the
 * packet it started from. */
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "ext_opt.h"
#include "pkt.h"
#include "strategy.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/l7.h"
#  include "ext/xl7.h"
#  include "ext/xtrig.h"

static int ext_on(void)
{
    static const optdef defs[] = {EXT_OPT, EXT_CTRACK_OPTS, {NULL, 0, 0, NULL, NULL}};
    const char *argv[] = {"--ext", NULL};
    args_t a;
    char err[128];
    int r;
    if (args_parse(&a, 1, (char **)argv, defs, err, sizeof(err)) < 0)
        return -2;
    r = ext_parse_args(&a, "test");
    args_free(&a);
    return r;
}

enum { F = 1, S = 2, R = 4, P = 8, A = 16, U = 32 };

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8), p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, v >> 16), put16(p + 2, v & 0xffff); }

/* what a NAT does to an ICMP echo: a new identifier, the checksum updated
 * (RFC 1624) */
static void nat_id(uint8_t *b, size_t l3, unsigned id)
{
    uint8_t *ic = b + l3;
    uint32_t c = (uint32_t)(~((unsigned)ic[2] << 8 | ic[3]) & 0xffff);
    c += (~((unsigned)ic[4] << 8 | ic[5]) & 0xffff) + id;
    while (c >> 16)
        c = (c & 0xffff) + (c >> 16);
    put16(ic + 2, ~c & 0xffff);
    put16(ic + 4, id);
}
static unsigned get16(const uint8_t *p) { return (unsigned)p[0] << 8 | p[1]; }

/* 10.0.0.1:40000 -> 10.0.0.2:443 ([fd00::1] -> [fd00::2] with v6): proto 6
 * (TCP with options opt) or 17 (UDP); checksums right */
static size_t mkpkt(uint8_t *b, int v6, int proto, unsigned flags, uint32_t seq, uint32_t ack, const uint8_t *opt,
                    size_t olen, const uint8_t *d, size_t dl)
{
    size_t l3 = v6 ? 40 : 20, l4h = proto == 17 ? 8 : 20 + olen, l4 = l4h + dl;
    uint8_t *t = b + l3;
    uint32_t s = 0;
    memset(b, 0, l3 + l4h);
    if (v6) {
        b[0] = 0x60;
        put16(b + 4, (unsigned)l4);
        b[6] = (uint8_t)proto;
        b[7] = 64;
        b[8] = 0xfd, b[23] = 1;
        b[24] = 0xfd, b[39] = 2;
    } else {
        b[0] = 0x45;
        put16(b + 2, (unsigned)(20 + l4));
        put16(b + 4, 0x1234);
        b[6] = 0x40;
        b[8] = 64;
        b[9] = (uint8_t)proto;
        b[12] = 10, b[15] = 1;
        b[16] = 10, b[19] = 2;
        put16(b + 10, inet_csum(b, 20, 0));
    }
    put16(t, 40000);
    put16(t + 2, 443);
    if (proto == 17) {
        put16(t + 4, (unsigned)l4);
    } else {
        put32(t + 4, seq);
        put32(t + 8, ack);
        t[12] = (uint8_t)((5 + olen / 4) << 4);
        t[13] = (uint8_t)flags;
        put16(t + 14, 64000);
        if (olen)
            memcpy(t + 20, opt, olen);
    }
    if (dl)
        memcpy(t + l4h, d, dl);
    for (int i = 0; i < (v6 ? 32 : 8); i += 2)
        s += get16(b + (v6 ? 8 : 12) + i);
    s += (uint32_t)proto + (uint32_t)l4;
    put16(t + (proto == 17 ? 6 : 16), inet_csum(t, l4, s));
    return l3 + l4;
}

/* the L4 checksum of the bytes is right (TCP, UDP, ICMP, ICMPv6) */
static int csum_ok(const uint8_t *b, size_t n)
{
    int v6 = (b[0] >> 4) == 6;
    size_t l3 = v6 ? 40 : (size_t)(b[0] & 15) * 4;
    uint8_t proto = v6 ? b[6] : b[9];
    uint32_t s = 0;
    if (!v6 && inet_csum(b, l3, 0) != 0)
        return 0;
    if (proto != 1) {
        for (int i = 0; i < (v6 ? 32 : 8); i += 2)
            s += get16(b + (v6 ? 8 : 12) + i);
        s += proto + (uint32_t)(n - l3);
    }
    return inet_csum(b + l3, n - l3, s) == 0;
}

/* runs raw (n) through the forest dir of s, with payload type l7p; the
 * first result's bytes into out (*on), the number of results returned */
static size_t runx(const char *s, int dir, int l7p, const uint8_t *raw, size_t n, uint8_t *out, size_t *on,
                   pktlist *res)
{
    sbuf e;
    strategy *st;
    xpkt_ctx c;
    xl7_view v;
    pktlist o = {0};
    pktlist *l = res ? res : &o;
    size_t k;
    l->n = 0;
    *on = 0;
    sb_init(&e);
    st = strategy_parse(s, &e);
    if (!st)
        fprintf(stderr, "  %s: %s\n", s, e.data);
    CHECK(st != NULL);
    sb_free(&e);
    if (!st)
        return 0;
    memset(&c, 0, sizeof(c));
    memset(&v, 0, sizeof(v));
    v.l7p = l7p;
    c.st = st;
    c.l7 = &v;
    strategy_apply_x(st, pkt_parse(raw, n), dir ? DIR_IN : DIR_OUT, l, &c);
    c.st = NULL;
    k = l->n;
    if (k) {
        /* the one that is not a made packet: the captured one */
        size_t i = 0;
        uint8_t *b;
        while (i + 1 < l->n && l->v[i]->xgen)
            i++;
        b = pkt_bytes(l->v[i], on);
        memcpy(out, b, *on);
        free(b);
    }
    if (!res)
        pktlist_free(&o);
    strategy_free(st);
    return k;
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

/* 38 bytes of option data, the most there is room for */
#define REP38 "abababababababababababababababababababababababababababababababababababababab"

TEST(obfs_parse)
{
#  if GENEVA_EXT_CRYPTO
    CHECK_STR(parse_err("[UDP:dport:443]-xwgobfs{secret=x}-| \\/"), "OK");
    CHECK_STR(parse_err("[UDP:dport:443]-xwgobfs-| \\/"), "xwgobfs: secret required");
    CHECK_STR(parse_err("[UDP:dport:443]-xwgobfs{secret=x;padmin=5;padmax=4}-| \\/"), "xwgobfs: padmin>padmax");
#  else
    CHECK(strstr(parse_err("[UDP:dport:443]-xwgobfs{secret=x}-| \\/"), "no cryptography"));
#  endif
    CHECK_STR(parse_err("[TCP:dport:443]-xippxor{ippxor=192;dataxor=0xABCD}-| \\/"), "OK");
    CHECK_STR(parse_err("[TCP:dport:443]-xippxor-| \\/"), "xippxor: ippxor value required");
    CHECK(strstr(parse_err("[TCP:dport:443]-xippxor{ippxor=256}-| \\/"), "ippxor"));
    CHECK_STR(parse_err("[UDP:dport:443]-xudp2icmp{ctype=13;stype=14}-| \\/"), "OK");
    CHECK_STR(parse_err("[UDP:dport:443]-xudp2icmp{ctype=13}-| \\/"), "xudp2icmp: ctype and stype must be both set or not set");
    CHECK_STR(parse_err("[UDP:dport:443]-xudp2icmp{scode=1}-| \\/"), "xudp2icmp: ccode and scode must be both set or not set");
    CHECK_STR(parse_err("[UDP:dport:443]-xudp2icmp{cgnat;id_lifetime=600}-| \\/"), "OK");
    CHECK(strstr(parse_err("[UDP:dport:443]-xudp2icmp{id_lifetime=0}-| \\/"), "id_lifetime"));
    CHECK(strstr(parse_err("[UDP:dport:443]-xudp2icmp{cgnat=1}-| \\/"), "cgnat"));
    CHECK_STR(parse_err("[TCP:dport:443]-xsynhide{magic=foo}-| \\/"), "xsynhide: invalid magic mode 'foo'");
    CHECK_STR(parse_err("[TCP:dport:443]-xsynhide{xorseq=0102}-| \\/"), "xsynhide: invalid xorseq value");
    CHECK(strstr(parse_err("[TCP:dport:443]-xsynhide{x2=16}-| \\/"), "x2"));
    CHECK_STR(parse_err("[TCP:dport:443]-xsynhide{synack;ghost=3;magic=opt;kind=253;opt=0102;xorseq=deadbeef}-| \\/"),
              "OK");
    {
        char s[200];
        snprintf(s, sizeof(s), "[TCP:dport:443]-xsynhide{magic=opt;opt=%s}-| \\/", REP38);
        CHECK_STR(parse_err(s), "OK");
        snprintf(s, sizeof(s), "[TCP:dport:443]-xsynhide{magic=opt;opt=%sab}-| \\/", REP38);
        CHECK_STR(parse_err(s), "xsynhide: invalid opt value");
    }
}

#  if GENEVA_EXT_CRYPTO
TEST(obfs_wgobfs)
{
    uint8_t wg[148], raw[400], enc[400], dec[400];
    size_t n, ne, nd;
    const char *out = "[UDP:dport:443]-xwgobfs{secret=mycoolpassword;padmax=8}-| \\/";
    const char *in = "\\/ [UDP:dport:443]-xwgobfs{secret=mycoolpassword;padmax=8}-|";
    const char *bad = "\\/ [UDP:dport:443]-xwgobfs{secret=other;padmax=8}-|";
    for (size_t i = 0; i < sizeof(wg); i++)
        wg[i] = (uint8_t)(i * 7 + 1);
    wg[0] = 1;
    n = mkpkt(raw, 0, 17, 0, 0, 0, NULL, 0, wg, sizeof(wg));
    /* the initiation goes encrypted, 30 to 38 bytes longer */
    CHECK_INT(runx(out, 0, L7P_WIREGUARD_INITIATION, raw, n, enc, &ne, NULL), 1);
    CHECK(ne >= n + 30 && ne <= n + 38);
    CHECK(csum_ok(enc, ne));
    CHECK(memcmp(enc + 28 + 28, wg, 16) != 0);
    /* the other end: the same message back */
    CHECK_INT(runx(in, 1, L7P_UNKNOWN, enc, ne, dec, &nd, NULL), 1);
    CHECK_MEM(dec, nd, raw, n);
    /* another secret leaves it as it came */
    CHECK_INT(runx(bad, 1, L7P_UNKNOWN, enc, ne, dec, &nd, NULL), 1);
    CHECK_MEM(dec, nd, enc, ne);
    /* every message its own iv */
    {
        uint8_t enc2[400];
        size_t ne2;
        runx(out, 0, L7P_WIREGUARD_INITIATION, raw, n, enc2, &ne2, NULL);
        CHECK(memcmp(enc + 28, enc2 + 28, 12) != 0);
    }
    /* data messages and keepalives go as they are */
    CHECK_INT(runx(out, 0, L7P_WIREGUARD_DATA, raw, n, enc, &ne, NULL), 1);
    CHECK_MEM(enc, ne, raw, n);
    /* IPv6, the response with no padding */
    n = mkpkt(raw, 1, 17, 0, 0, 0, NULL, 0, wg, 92);
    runx("[UDP:dport:443]-xwgobfs{secret=s;padmax=0}-| \\/", 0, L7P_WIREGUARD_RESPONSE, raw, n, enc, &ne, NULL);
    CHECK_INT((long)ne, (long)(n + 30));
    runx("\\/ [UDP:dport:443]-xwgobfs{secret=s;padmax=0}-|", 1, L7P_UNKNOWN, enc, ne, dec, &nd, NULL);
    CHECK_MEM(dec, nd, raw, n);
}
#  endif

TEST(obfs_ippxor)
{
    static const char data[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    uint8_t raw[400], x[400], y[400];
    size_t n, nx, ny;
    /* TCP: the number 6^192, the payload XORed; back on the other end */
    n = mkpkt(raw, 0, 6, P | A, 1000, 2000, NULL, 0, (const uint8_t *)data, sizeof(data) - 1);
    CHECK_INT(runx("[TCP:dport:443]-xippxor{ippxor=192;dataxor=0xABCD}-| \\/", 0, L7P_HTTP_REQ, raw, n, x, &nx, NULL), 1);
    CHECK_INT(nx, n);
    CHECK_INT(x[9], 6 ^ 192);
    CHECK_INT(inet_csum(x, 20, 0), 0);
    CHECK_INT(x[40], (uint8_t)('G' ^ 0xAB));
    CHECK_INT(x[41], (uint8_t)('E' ^ 0xCD));
    CHECK_INT(runx("\\/ [IP:proto:198]-xippxor{ippxor=192;dataxor=0xABCD}-|", 1, L7P_UNKNOWN, x, nx, y, &ny, NULL), 1);
    CHECK_MEM(y, ny, raw, n);
    /* UDP without dataxor: only the number */
    n = mkpkt(raw, 0, 17, 0, 0, 0, NULL, 0, (const uint8_t *)data, 10);
    runx("[UDP:dport:443]-xippxor{ippxor=0x11}-| \\/", 0, L7P_UNKNOWN, raw, n, x, &nx, NULL);
    CHECK_INT(x[9], 0);
    CHECK_MEM(x + 20, nx - 20, raw + 20, n - 20);
    runx("\\/ [IP:proto:0]-xippxor{ippxor=0x11}-|", 1, L7P_UNKNOWN, x, nx, y, &ny, NULL);
    CHECK_MEM(y, ny, raw, n);
    /* IPv6 */
    n = mkpkt(raw, 1, 6, P | A, 1000, 2000, NULL, 0, (const uint8_t *)data, sizeof(data) - 1);
    runx("[TCP:dport:443]-xippxor{ippxor=192;dataxor=0x55}-| \\/", 0, L7P_HTTP_REQ, raw, n, x, &nx, NULL);
    CHECK_INT(x[6], 198);
    runx("\\/ [IPv6:nh:198]-xippxor{ippxor=192;dataxor=0x55}-|", 1, L7P_UNKNOWN, x, nx, y, &ny, NULL);
    CHECK_MEM(y, ny, raw, n);
}

TEST(obfs_udp2icmp)
{
    static const char data[] = "a datagram of the client";
    uint8_t raw[400], x[400], y[400], rep[400];
    size_t n, nx, ny, nr;
    for (int v6 = 0; v6 <= 1; v6++) {
        size_t l3 = v6 ? 40 : 20;
        n = mkpkt(raw, v6, 17, 0, 0, 0, NULL, 0, (const uint8_t *)data, sizeof(data) - 1);
        /* the client: an echo request of the same size */
        runx("[UDP:dport:443]-xudp2icmp{dataxor=0x1234}-| \\/", 0, L7P_UNKNOWN, raw, n, x, &nx, NULL);
        CHECK_INT(nx, n);
        CHECK_INT(v6 ? x[6] : x[9], v6 ? 58 : 1);
        CHECK_INT(x[l3], v6 ? 128 : 8);
        CHECK_INT(get16(x + l3 + 4), 40000 ^ 443);
        CHECK_INT(get16(x + l3 + 6), 443);
        CHECK_INT(x[l3 + 8], (uint8_t)('a' ^ 0x12));
        CHECK(csum_ok(x, nx));
        /* the server: the datagram back */
        runx(v6 ? "\\/ [IPv6:nh:58]-xudp2icmp{dataxor=0x1234;server=1}-|"
                : "\\/ [IP:proto:1]-xudp2icmp{dataxor=0x1234;server=1}-|",
             1, L7P_UNKNOWN, x, nx, y, &ny, NULL);
        CHECK_MEM(y, ny, raw, n);
        /* the client does not take its own kind of message */
        runx(v6 ? "\\/ [IPv6:nh:58]-xudp2icmp{dataxor=0x1234}-|" : "\\/ [IP:proto:1]-xudp2icmp{dataxor=0x1234}-|", 1,
             L7P_UNKNOWN, x, nx, y, &ny, NULL);
        CHECK_MEM(y, ny, x, nx);
        /* the server's answer 443 -> 40000: an echo reply, a datagram again
         * at the client */
        n = mkpkt(raw, v6, 17, 0, 0, 0, NULL, 0, (const uint8_t *)data, 5);
        memcpy(rep, raw, n);
        nr = n;
        if (v6) {
            uint8_t t[16];
            memcpy(t, rep + 8, 16), memcpy(rep + 8, rep + 24, 16), memcpy(rep + 24, t, 16);
        } else {
            uint8_t t[4];
            memcpy(t, rep + 12, 4), memcpy(rep + 12, rep + 16, 4), memcpy(rep + 16, t, 4);
        }
        put16(rep + l3, 443);
        put16(rep + l3 + 2, 40000);
        runx("[UDP:sport:443]-xudp2icmp{server=1}-| \\/", 0, L7P_UNKNOWN, rep, nr, x, &nx, NULL);
        CHECK_INT(x[l3], v6 ? 129 : 0);
        runx(v6 ? "\\/ [IPv6:nh:58]-xudp2icmp-|" : "\\/ [IP:proto:1]-xudp2icmp-|", 1, L7P_UNKNOWN, x, nx, y, &ny, NULL);
        CHECK_INT(get16(y + l3), 443);
        CHECK_INT(get16(y + l3 + 2), 40000);
        CHECK(csum_ok(y, ny));
        CHECK_MEM(y + l3 + 8, ny - l3 - 8, rep + l3 + 8, nr - l3 - 8);

        /* cgnat: the client appends the identifier, a NAT changes it, the
         * server answers with the one it saw */
        {
            const char *cin = v6 ? "\\/ [IPv6:nh:58]-xudp2icmp{cgnat;dataxor=0x55;server=1}-|"
                                 : "\\/ [IP:proto:1]-xudp2icmp{cgnat;dataxor=0x55;server=1}-|";
            uint8_t z[400];
            size_t nz;
            n = mkpkt(raw, v6, 17, 0, 0, 0, NULL, 0, (const uint8_t *)data, sizeof(data) - 1);
            runx("[UDP:dport:443]-xudp2icmp{cgnat;dataxor=0x55}-| \\/", 0, L7P_UNKNOWN, raw, n, x, &nx, NULL);
            CHECK_INT(nx, n + 2);
            CHECK_INT(get16(x + nx - 2), 40000 ^ 443);
            CHECK_INT(x[l3 + 8], (uint8_t)('a' ^ 0x55));
            CHECK(csum_ok(x, nx));
            nat_id(x, l3, 0x7777);
            runx(cin, 1, L7P_UNKNOWN, x, nx, y, &ny, NULL);
            CHECK_MEM(y, ny, raw, n);
            /* the answer carries 0x7777, and is not longer */
            runx("[UDP:sport:443]-xudp2icmp{cgnat;dataxor=0x55;server=1}-| \\/", 0, L7P_UNKNOWN, rep, nr, z, &nz, NULL);
            CHECK_INT(nz, nr);
            CHECK_INT(get16(z + l3 + 4), 0x7777);
            CHECK_INT(get16(z + l3 + 6), 443);
            CHECK(csum_ok(z, nz));
            /* the NAT gives the client its identifier back */
            nat_id(z, l3, 40000 ^ 443);
            runx(v6 ? "\\/ [IPv6:nh:58]-xudp2icmp{cgnat;dataxor=0x55}-|" : "\\/ [IP:proto:1]-xudp2icmp{cgnat;dataxor=0x55}-|",
                 1, L7P_UNKNOWN, z, nz, y, &ny, NULL);
            CHECK_MEM(y, ny, rep, nr);
            /* another client port: nothing mapped, the plain identifier */
            put16(rep + l3 + 2, 40001);
            runx("[UDP:sport:443]-xudp2icmp{cgnat;server=1}-| \\/", 0, L7P_UNKNOWN, rep, nr, z, &nz, NULL);
            CHECK_INT(get16(z + l3 + 4), 40001 ^ 443);
            /* less than the 2 bytes: left alone */
            n = mkpkt(raw, v6, 17, 0, 0, 0, NULL, 0, NULL, 0);
            runx("[UDP:dport:443]-xudp2icmp-| \\/", 0, L7P_UNKNOWN, raw, n, x, &nx, NULL);
            runx(cin, 1, L7P_UNKNOWN, x, nx, y, &ny, NULL);
            CHECK_MEM(y, ny, x, nx);
        }
    }
    /* own types and codes */
    n = mkpkt(raw, 0, 17, 0, 0, 0, NULL, 0, (const uint8_t *)data, 4);
    runx("[UDP:dport:443]-xudp2icmp{ctype=13;stype=14;ccode=1;scode=2}-| \\/", 0, L7P_UNKNOWN, raw, n, x, &nx, NULL);
    CHECK_INT(x[20], 13);
    CHECK_INT(x[21], 1);
    runx("\\/ [IP:proto:1]-xudp2icmp{ctype=13;stype=14;ccode=1;scode=2;server=1}-|", 1, L7P_UNKNOWN, x, nx, y, &ny, NULL);
    CHECK_MEM(y, ny, raw, n);
}

TEST(obfs_synhide)
{
    static const struct {
        const char *args;
        int tsopt;
    } cases[] = {
        {"", 0},
        {"magic=x2;x2=6", 0},
        {"magic=urp", 0},
        {"magic=opt;kind=253;opt=c0de", 0},
        {"magic=tsecr", 1},
        {"magic=urp;xorseq=deadbeef", 0},
    };
    /* MSS, then NOP NOP TS */
    static const uint8_t opts[] = {2, 4, 5, 0xb4, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0};
    uint8_t raw[400], x[400], y[400];
    size_t n, nx, ny;
    char s[300];
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); i++) {
        size_t k;
        n = mkpkt(raw, 0, 6, S, 0x12345678, 0, opts, cases[i].tsopt ? 16 : 4, NULL, 0);
        snprintf(s, sizeof(s), "[TCP:flags:S]-xsynhide%s%s%s-| \\/", *cases[i].args ? "{" : "", cases[i].args,
                 *cases[i].args ? "}" : "");
        k = runx(s, 0, L7P_EMPTY, raw, n, x, &nx, NULL);
        CHECK_INT(k, 1);
        CHECK_INT(x[33] & 0x17, A); /* no SYN, ACK */
        CHECK(csum_ok(x, nx));
        snprintf(s, sizeof(s), "\\/ [TCP:dport:443]-xsynhide%s%s%s-|", *cases[i].args ? "{" : "", cases[i].args,
                 *cases[i].args ? "}" : "");
        runx(s, 1, L7P_EMPTY, x, nx, y, &ny, NULL);
        if (memcmp(y, raw, n) || ny != n)
            fprintf(stderr, "  synhide %s: not restored\n", cases[i].args);
        CHECK_MEM(y, ny, raw, n);
    }
    /* magic=opt only when the option fits in the 40 bytes: the SYN goes
     * as it is otherwise */
    {
        uint8_t full[36] = {2, 4, 5, 0xb4};
        memset(full + 4, 1, sizeof(full) - 4);
        n = mkpkt(raw, 0, 6, S, 0x12345678, 0, full, sizeof(full), NULL, 0);
        runx("[TCP:flags:S]-xsynhide{magic=opt;kind=253;opt=c0de}-| \\/", 0, L7P_EMPTY, raw, n, x, &nx, NULL);
        CHECK_INT(x[33] & 0x17, A);
        CHECK_INT(nx, n + 4);
        runx("[TCP:flags:S]-xsynhide{magic=opt;kind=253;opt=c0de00}-| \\/", 0, L7P_EMPTY, raw, n, x, &nx, NULL);
        CHECK_MEM(x, nx, raw, n);
    }
    /* a plain ACK is not taken for one */
    n = mkpkt(raw, 0, 6, A, 0x12345678, 1, opts, 4, NULL, 0);
    runx("\\/ [TCP:flags:A]-xsynhide{magic=urp}-|", 1, L7P_EMPTY, raw, n, y, &ny, NULL);
    CHECK_MEM(y, ny, raw, n);
    /* synack: the server's SYN,ACK as RST,ACK, a SYN,ACK again at the client */
    n = mkpkt(raw, 0, 6, S | A, 0x55555555, 0x12345679, opts, 4, NULL, 0);
    runx("[TCP:flags:SA]-xsynhide{synack;magic=urp}-| \\/", 0, L7P_EMPTY, raw, n, x, &nx, NULL);
    CHECK_INT(x[33] & 0x17, R | A);
    CHECK_INT(get16(x + 38), (0x1234 ^ 0x5678));
    runx("\\/ [TCP:flags:RA]-xsynhide{synack;magic=urp}-|", 1, L7P_EMPTY, x, nx, y, &ny, NULL);
    CHECK_MEM(y, ny, raw, n);
    /* ghost: a SYN with TTL 3 first */
    {
        pktlist l = {0};
        n = mkpkt(raw, 0, 6, S, 0x12345678, 0, opts, 4, NULL, 0);
        CHECK_INT(runx("[TCP:flags:S]-xsynhide{ghost=3}-| \\/", 0, L7P_EMPTY, raw, n, x, &nx, &l), 2);
        if (l.n == 2) {
            CHECK(l.v[0]->xgen);
            CHECK_INT(l.v[0]->ttl, 3);
            CHECK_INT(l.v[0]->tcpflags, S);
            CHECK_INT(l.v[1]->tcpflags & 0x17, A);
        }
        pktlist_free(&l);
    }
}

void suite_obfs(void);
void suite_obfs(void)
{
    if (ext_on() != 0) {
        CHECK(!"ext_on");
        return;
    }
    RUN(obfs_parse);
#  if GENEVA_EXT_CRYPTO
    RUN(obfs_wgobfs);
#  endif
    RUN(obfs_ippxor);
    RUN(obfs_udp2icmp);
    RUN(obfs_synhide);
    ext_reset();
}

#else
void suite_obfs(void);
void suite_obfs(void) {}
#endif
