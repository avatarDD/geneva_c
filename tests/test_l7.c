/* Stage X4: L7 recognition (src/ext/l7.c), position markers (markers.c),
 * the reassembly of a ClientHello over TCP segments and QUIC Initials
 * (xl7.c), the L7: triggers and the hold and replay in the engine. The
 * parsers are checked line by line against zapret2's own code
 * (tests/data/l7_expected.txt, tests/fuzz). */
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "engine_int.h"
#include "ext/ext.h"
#include "ext_opt.h"
#include "pkt.h"
#include "strategy.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/ctrack.h"
#  include "ext/xl7.h"
#  include "ext/xtrig.h"
#  include "fuzz/l7_line.c"

static uint8_t *load(const char *path, size_t *n)
{
    uint8_t *p = (uint8_t *)read_file(path, n);
    if (!p)
        fprintf(stderr, "  cannot read %s\n", path);
    CHECK(p != NULL);
    return p;
}

/* ---- the same lines as zapret2 --------------------------------------------- */

static void cut_crypto(char *s)
{
#  if !GENEVA_EXT_CRYPTO
    /* no QUIC decryption and no MTProto: compare the rest */
    char *q = strstr(s, " quic_dec=");
    char *m = strstr(s, "mtproto_initial");
    if (q)
        *q = 0;
    if (m)
        memcpy(m, "unknown", 8), memmove(m + 7, m + 15, strlen(m + 15) + 1);
#  else
    (void)s;
#  endif
}

TEST(l7_zapret2_lines)
{
    size_t n, lines = 0;
    char *all = (char *)read_file("tests/data/l7_expected.txt", &n), *line, *next;
    sbuf o;
    CHECK(all != NULL);
    if (!all)
        return;
    sb_init(&o);
    for (line = all; *line; line = next) {
        char path[300], *sp, *at, *exp;
        size_t len, cut = 0;
        uint8_t *d;
        next = line + strcspn(line, "\r\n");
        if (*next)
            *next++ = 0;
        next += strspn(next, "\r\n");
        if (*line == '#' || !*line)
            continue;
        sp = strchr(line, ' ');
        CHECK(sp != NULL);
        if (!sp)
            break;
        *sp = 0;
        exp = sp + 1;
        snprintf(path, sizeof(path), "tests/data/%s", line);
        if ((at = strchr(path, '@')))
            *at = 0, cut = (size_t)atoi(at + 1);
        d = load(path, &len);
        if (!d)
            continue;
        if (at && cut < len)
            len = cut;
        sb_reset(&o);
        l7_line(d, len, &o);
        cut_crypto(o.data);
        cut_crypto(exp);
        t_current = line;
        CHECK_STR(o.data, exp);
        free(d);
        lines++;
    }
    t_current = "zapret2 lines";
    CHECK(lines > 400);
    sb_free(&o);
    free(all);
}

/* ---- names, lists, markers ---------------------------------------------------- */

static const char *list_err(int proto, const char *s, uint64_t *set, int *neg)
{
    static char buf[200];
    sbuf e;
    int r;
    sb_init(&e);
    r = proto ? l7_proto_list(s, set, neg, &e) : l7_payload_list(s, set, neg, &e);
    snprintf(buf, sizeof(buf), "%s", r < 0 ? e.data : "OK");
    sb_free(&e);
    return buf;
}

TEST(l7_names_lists)
{
    uint64_t set;
    int neg;
    CHECK_INT(L7_LAST, 16);
    CHECK_INT(L7P_LAST, 31);
    CHECK_STR(l7_proto_name(L7_UTP_BT), "utp_bt");
    CHECK_STR(l7_payload_name(L7P_TLS_CLIENT_HELLO), "tls_client_hello");
    CHECK(l7_payload_name(L7P_LAST) == NULL);
    CHECK_INT(l7_payload_by_name("quic_initial"), L7P_QUIC_INITIAL);
    CHECK_INT(l7_proto_by_name("nosuch"), -1);
    for (int i = 0; i < L7P_LAST; i++)
        CHECK_INT(l7_payload_by_name(l7_payload_name(i)), i);

    CHECK_STR(list_err(0, "tls_client_hello,http_req", &set, &neg), "OK");
    CHECK(set == ((1ULL << L7P_TLS_CLIENT_HELLO) | (1ULL << L7P_HTTP_REQ)) && !neg);
    CHECK(l7_payload_match(L7P_HTTP_REQ, set) && !l7_payload_match(L7P_QUIC_INITIAL, set));
    CHECK_STR(list_err(0, "~known", &set, &neg), "OK");
    CHECK(neg && l7_payload_match(L7P_DHT, set) && !l7_payload_match(L7P_UNKNOWN, set) &&
          !l7_payload_match(L7P_EMPTY, set));
    CHECK_STR(list_err(1, "all", &set, &neg), "OK");
    CHECK(set == 0 && l7_proto_match(L7_UNKNOWN, set));
    CHECK_STR(list_err(1, "known", &set, &neg), "OK");
    CHECK(l7_proto_match(L7_TLS, set) && !l7_proto_match(L7_UNKNOWN, set));
    CHECK(strstr(list_err(1, "tls,nosuch", &set, &neg), "unknown protocol \"nosuch\""));
    CHECK(strstr(list_err(0, "all,dht", &set, &neg), "cannot be listed"));
    CHECK(strstr(list_err(0, "", &set, &neg), "unknown payload"));
}

static const char *mprint(const char *s)
{
    static char buf[64];
    xmarker m;
    sbuf o;
    if (xmarker_parse(s, &m) < 0)
        return "BAD";
    sb_init(&o);
    xmarker_print(&m, &o);
    snprintf(buf, sizeof(buf), "%s", o.data);
    sb_free(&o);
    return buf;
}

TEST(l7_markers)
{
    xmarker m[XMARKER_MAX];
    long pos[XMARKER_MAX], from, to;
    sbuf e;
    size_t n;
    uint8_t *ch = load("tests/data/zapret2/tls_clienthello_iana_org.bin", &n);
    const char *http = "GET / HTTP/1.1\r\nHost: www.iana.org\r\n\r\n";
    int k;

    CHECK_STR(mprint("5"), "5");
    CHECK_STR(mprint("-1"), "-1");
    CHECK_STR(mprint("+7"), "7");
    CHECK_STR(mprint("midsld"), "midsld");
    CHECK_STR(mprint("endhost-1"), "endhost-1");
    CHECK_STR(mprint("sniext+0"), "sniext");
    /* strict where zapret2's atoi is not */
    CHECK_STR(mprint("5x"), "BAD");
    CHECK_STR(mprint("host+"), "BAD");
    CHECK_STR(mprint("40000"), "BAD");
    CHECK_STR(mprint("nosuch"), "BAD");
    CHECK_STR(mprint(""), "BAD");

    sb_init(&e);
    CHECK_INT(xmarker_list_parse("1,midsld,endhost-1", m, XMARKER_MAX, &e), 3);
    CHECK_INT(xmarker_list_parse("1,2,3", m, 2, &e), -1);
    CHECK(strstr(e.data, "too many"));
    sb_reset(&e);
    CHECK_INT(xmarker_list_parse("1,,2", m, XMARKER_MAX, &e), -1);
    CHECK(strstr(e.data, "bad position"));
    CHECK_INT(xmarker_list_parse("", m, XMARKER_MAX, &e), 0);

    if (ch) {
        /* host iana.org at 153 (see tests/data/l7_expected.txt) */
        CHECK_INT(xmarker_list_parse("midsld,1,host,midsld,-1,method", m, XMARKER_MAX, &e), 6);
        k = xmarker_resolve_list(ch, n, L7P_TLS_CLIENT_HELLO, m, 6, pos);
        CHECK_INT(k, 4); /* sorted, unique, method not found */
        CHECK(k == 4 && pos[0] == 1 && pos[1] == 153 && pos[2] == 155 && pos[3] == (long)n - 1);
        /* resolve_range: both, one missing (start or last byte), strict */
        CHECK_INT(xmarker_list_parse("host,endhost", m, XMARKER_MAX, &e), 2);
        CHECK_INT(xmarker_resolve_range(ch, n, L7P_TLS_CLIENT_HELLO, m, 2, 0, &from, &to), 0);
        CHECK(from == 153 && to == 161);
        CHECK_INT(xmarker_list_parse("method,sld", m, XMARKER_MAX, &e), 2);
        CHECK_INT(xmarker_resolve_range(ch, n, L7P_TLS_CLIENT_HELLO, m, 2, 0, &from, &to), 0);
        CHECK(from == 0 && to == 153);
        CHECK_INT(xmarker_resolve_range(ch, n, L7P_TLS_CLIENT_HELLO, m, 2, 1, &from, &to), -1);
        CHECK_INT(xmarker_list_parse("endhost,host", m, XMARKER_MAX, &e), 2);
        CHECK_INT(xmarker_resolve_range(ch, n, L7P_TLS_CLIENT_HELLO, m, 2, 0, &from, &to), -1);
        CHECK_INT(xmarker_resolve_range(ch, n, L7P_TLS_CLIENT_HELLO, m, 1, 0, &from, &to), -1);
    }
    CHECK_INT(xmarker_list_parse("method+2,host,midsld,endhost", m, XMARKER_MAX, &e), 4);
    k = xmarker_resolve_list((const uint8_t *)http, strlen(http), L7P_HTTP_REQ, m, 4, pos);
    CHECK(k == 4 && pos[0] == 2 && pos[1] == 22 && pos[2] == 28 && pos[3] == 34);
    /* on an unknown payload only absolute positions exist */
    CHECK_INT(xmarker_resolve_list((const uint8_t *)http, strlen(http), L7P_UNKNOWN, m, 4, pos), 0);
    sb_free(&e);
    free(ch);
}

/* ---- reassembly ---------------------------------------------------------------- */

enum { F = 1, S = 2, R = 4, P = 8, A = 16 };

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8), p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, v >> 16), put16(p + 2, v & 0xffff); }

/* IPv4 10.0.0.1:40000 <-> 10.0.0.2:443 (TCP, or UDP); returns the length */
static size_t mkraw(uint8_t *b, int c2s, int udp, unsigned flags, uint32_t seq, uint32_t ack, uint16_t win,
                    const uint8_t *d, size_t dl)
{
    size_t l4h = udp ? 8 : 20, l4 = l4h + dl;
    uint8_t *t = b + 20;
    memset(b, 0, 20 + l4h);
    b[0] = 0x45;
    put16(b + 2, (unsigned)(20 + l4));
    b[8] = 64;
    b[9] = udp ? 17 : 6;
    b[12] = 10, b[15] = c2s ? 1 : 2;
    b[16] = 10, b[19] = c2s ? 2 : 1;
    put16(t, c2s ? 40000 : 443);
    put16(t + 2, c2s ? 443 : 40000);
    if (udp) {
        put16(t + 4, (unsigned)l4);
    } else {
        put32(t + 4, seq);
        put32(t + 8, ack);
        t[12] = 5 << 4;
        t[13] = (uint8_t)flags;
        put16(t + 14, win);
    }
    if (dl)
        memcpy(t + l4h, d, dl);
    return 20 + l4;
}

typedef struct {
    int n, passed;
    unsigned piece[80], pieces[80];
    size_t len[80], offset[80], plen[80], dec_len[80];
    int partial[80], l7p[80];
    char host[80][64];
    uint64_t seq_n[80]; /* client n as the piece saw it */
} replays;

static void on_replay(void *ud, const uint8_t *raw, size_t len, strat_dir dir, const void *pctx, const xl7_view *v)
{
    replays *r = ud;
    int i;
    (void)raw, (void)dir, (void)pctx;
    if (!v) {
        r->passed++;
        return;
    }
    i = r->n++;
    if (i >= 80)
        return;
    r->piece[i] = v->piece;
    r->pieces[i] = v->pieces;
    r->len[i] = v->len;
    r->offset[i] = v->offset;
    r->plen[i] = len - 20 - (raw[9] == 17 ? 8 : 20);
    r->dec_len[i] = v->dec_len;
    r->partial[i] = v->partial;
    r->l7p[i] = v->l7p;
    snprintf(r->host[i], sizeof(r->host[i]), "%s", v->host ? v->host : "-");
    r->seq_n[i] = v->cli ? v->cli->pcounter : 0;
}

typedef struct {
    ctrack *t;
    xl7 *x;
    ct_flow *f;
    int rev;
    replays r;
    xl7_view v;
} rig;

static void rig_clear(ct_flow *f, void *ud) { xl7_clear(f, on_replay, ud); }

static void rig_init(rig *g, const xl7_config *c)
{
    ct_config cc;
    memset(g, 0, sizeof(*g));
    ct_config_default(&cc);
    cc.clear = rig_clear;
    cc.clear_ud = &g->r;
    g->t = ctrack_new(&cc);
    g->x = xl7_new(c);
}

static void rig_free(rig *g)
{
    ctrack_free(g->t);
    xl7_free(g->x);
}

/* One packet through ctrack and xl7; returns XL7_GO or XL7_HOLD */
static int rig_pkt(rig *g, int c2s, int udp, unsigned flags, uint32_t seq, uint32_t ack, uint16_t win,
                   const uint8_t *d, size_t dl)
{
    uint8_t b[2100];
    size_t n = mkraw(b, c2s, udp, flags, seq, ack, win, d, dl);
    gpkt *p = pkt_parse(b, n);
    uint32_t pctx = 0;
    int r;
    CHECK(p != NULL);
    if (!p)
        return -1;
    g->f = ctrack_feed(g->t, p, 1000, &g->rev);
    r = xl7_packet(g->x, g->f, g->rev, p, c2s ? DIR_OUT : DIR_IN, b, n, &pctx, sizeof(pctx), 1, on_replay, &g->r,
                   &g->v);
    pkt_free(p);
    return r;
}

/* SYN, SYN+ACK (window win), ACK: client ISN 1000, server 5000 */
static void handshake(rig *g, uint16_t win)
{
    rig_pkt(g, 1, 0, S, 1000, 0, 64000, NULL, 0);
    rig_pkt(g, 0, 0, S | A, 5000, 1001, win, NULL, 0);
    rig_pkt(g, 1, 0, A, 1001, 5001, 64000, NULL, 0);
}

TEST(l7_reasm_tcp)
{
    size_t n;
    uint8_t *ch = load("tests/data/ext/tls_clienthello_chromium_mlkem.bin", &n);
    xl7_config c = {0, 0, 0};
    rig g;
    if (!ch)
        return;

    t_current = "TCP: a ClientHello in three segments";
    rig_init(&g, &c);
    handshake(&g, 65535);
    CHECK_INT(rig_pkt(&g, 1, 0, P | A, 1001, 5001, 64000, ch, 600), XL7_HOLD);
    CHECK_INT(xl7_held(g.f), 1);
    CHECK_INT(rig_pkt(&g, 1, 0, P | A, 1601, 5001, 64000, ch + 600, 600), XL7_HOLD);
    CHECK_INT(g.r.n, 0);
    CHECK_INT(rig_pkt(&g, 1, 0, P | A, 2201, 5001, 64000, ch + 1200, n - 1200), XL7_HOLD);
    CHECK_INT(g.r.n, 3);
    CHECK_INT(xl7_held(g.f), 0);
    for (int i = 0; i < 3 && g.r.n == 3; i++) {
        CHECK_INT(g.r.piece[i], (unsigned)i + 1);
        CHECK_INT(g.r.pieces[i], 3);
        CHECK_INT(g.r.len[i], n); /* the whole message on every piece */
        CHECK_INT(g.r.offset[i], 600 * i);
        CHECK_INT(g.r.l7p[i], L7P_TLS_CLIENT_HELLO);
        CHECK_STR(g.r.host[i], "example.com"); /* the SNI is in the last piece */
        CHECK_INT(g.r.partial[i], 0);
        CHECK_INT(g.r.seq_n[i], 3 + i); /* the client's packets as each piece saw them */
    }
    CHECK_INT(g.r.plen[2], n - 1200);
    CHECK_STR(g.f->host, "example.com");
    CHECK_INT(g.f->l7proto, L7_TLS);
    /* the next data packet goes on */
    CHECK_INT(rig_pkt(&g, 1, 0, P | A, 1001 + (uint32_t)n, 5001, 64000, (const uint8_t *)"\x17\x03\x03\x00\x01x", 6),
              XL7_GO);
    CHECK_INT(g.v.l7p, L7P_UNKNOWN);
    CHECK_STR(g.v.host, "example.com");
    rig_free(&g);

    t_current = "TCP: a retransmitted piece overwrites, a gap releases";
    rig_init(&g, &c);
    handshake(&g, 65535);
    CHECK_INT(rig_pkt(&g, 1, 0, P | A, 1001, 5001, 64000, ch, 600), XL7_HOLD);
    CHECK_INT(rig_pkt(&g, 1, 0, P | A, 1001, 5001, 64000, ch, 600), XL7_HOLD); /* retransmission */
    CHECK_INT(xl7_held(g.f), 2);
    /* a gap: the held packets go alone, as partial; this one goes on */
    CHECK_INT(rig_pkt(&g, 1, 0, P | A, 1801, 5001, 64000, ch + 800, 300), XL7_GO);
    CHECK_INT(g.r.n, 2);
    CHECK(g.r.partial[0] && g.r.partial[1] && g.r.pieces[0] == 0);
    CHECK_INT(g.r.l7p[0], L7P_TLS_CLIENT_HELLO);
    CHECK_INT(g.r.len[0], 600);
    CHECK_INT(g.v.l7p, L7P_UNKNOWN);
    CHECK_INT(g.v.len, 300);
    rig_free(&g);

    t_current = "TCP: no reassembly when the server window is too small";
    rig_init(&g, &c);
    handshake(&g, 1000);
    CHECK_INT(rig_pkt(&g, 1, 0, P | A, 1001, 5001, 64000, ch, 600), XL7_GO);
    CHECK_INT(g.v.l7p, L7P_TLS_CLIENT_HELLO);
    CHECK_INT(g.v.len, 600);
    CHECK(g.v.host == NULL); /* the SNI is not in the first piece */
    rig_free(&g);

    t_current = "TCP: --ext-reasm-disable";
    c.reasm_disable = 1ULL << L7P_TLS_CLIENT_HELLO;
    rig_init(&g, &c);
    handshake(&g, 65535);
    CHECK_INT(rig_pkt(&g, 1, 0, P | A, 1001, 5001, 64000, ch, 600), XL7_GO);
    CHECK_INT(g.v.l7p, L7P_TLS_CLIENT_HELLO);
    rig_free(&g);
    c.reasm_disable = 0;

    t_current = "TCP: --ext-payload-disable";
    c.payload_disable = 1ULL << L7P_TLS_CLIENT_HELLO;
    rig_init(&g, &c);
    handshake(&g, 65535);
    CHECK_INT(rig_pkt(&g, 1, 0, P | A, 1001, 5001, 64000, ch, 600), XL7_GO);
    CHECK_INT(g.v.l7p, L7P_UNKNOWN);
    CHECK_INT(g.f->l7proto, 0);
    rig_free(&g);
    c.payload_disable = 0;

    t_current = "TCP: --ext-reasm-max below the record";
    c.reasm_max = 1024;
    rig_init(&g, &c);
    handshake(&g, 65535);
    CHECK_INT(rig_pkt(&g, 1, 0, P | A, 1001, 5001, 64000, ch, 600), XL7_GO);
    CHECK_INT(g.v.l7p, L7P_TLS_CLIENT_HELLO);
    rig_free(&g);
    c.reasm_max = 0;

    t_current = "TCP: at most 64 held packets";
    rig_init(&g, &c);
    handshake(&g, 65535);
    CHECK_INT(rig_pkt(&g, 1, 0, P | A, 1001, 5001, 64000, ch, 100), XL7_HOLD);
    for (int i = 0; i < 63; i++)
        CHECK_INT(rig_pkt(&g, 1, 0, P | A, 1101 + 10 * (uint32_t)i, 5001, 64000, ch + 100 + 10 * i, 10), XL7_HOLD);
    CHECK_INT(rig_pkt(&g, 1, 0, P | A, 1731, 5001, 64000, ch + 730, 10), XL7_GO);
    CHECK_INT(g.r.n, 64);
    CHECK(g.r.partial[63]);
    CHECK_INT(g.v.l7p, L7P_UNKNOWN); /* a middle piece */
    rig_free(&g);

    t_current = "TCP: a full ClientHello in one segment, an HTTP request";
    rig_init(&g, &c);
    handshake(&g, 65535);
    CHECK_INT(rig_pkt(&g, 1, 0, P | A, 1001, 5001, 64000, ch, n), XL7_GO);
    CHECK_INT(g.v.l7p, L7P_TLS_CLIENT_HELLO);
    CHECK_STR(g.v.host, "example.com");
    CHECK_INT(rig_pkt(&g, 0, 0, P | A, 5001, 1001 + (uint32_t)n, 64000, (const uint8_t *)"HTTP/1.1 200 OK\r\n\r\n", 19),
              XL7_GO);
    CHECK_INT(g.v.l7p, L7P_HTTP_REPLY);
    CHECK_INT(g.v.l7, L7_TLS); /* the flow's protocol sticks */
    rig_free(&g);
    free(ch);

    t_current = "TCP: the cleanup of a flow frees held packets";
    ch = load("tests/data/ext/tls_clienthello_chromium_mlkem.bin", &n);
    rig_init(&g, &c);
    handshake(&g, 65535);
    CHECK_INT(rig_pkt(&g, 1, 0, P | A, 1001, 5001, 64000, ch, 600), XL7_HOLD);
    rig_pkt(&g, 1, 0, S, 7000, 0, 64000, NULL, 0); /* a new SYN starts the flow over */
    CHECK_INT(xl7_held(g.f), 0);
    CHECK_INT(g.r.n, 0);
    CHECK_INT(g.r.passed, 1); /* it goes on as it is (nfqws2 loses it) */
    CHECK_INT(rig_pkt(&g, 1, 0, P | A, 7001, 5001, 64000, ch, 600), XL7_HOLD);
    rig_free(&g); /* the end: the same */
    CHECK_INT(g.r.passed, 2);
    free(ch);
}

TEST(l7_icmp)
{
    /* nfqws2: an ICMP error carrying a packet is ipv4/ipv6, others icmp */
    uint8_t b[200], in[100];
    size_t n = mkraw(in, 1, 0, P | A, 1, 1, 100, (const uint8_t *)"abc", 3);
    xl7 *x = xl7_new(NULL);
    xl7_view v;
    gpkt *p;
    uint8_t types[] = {3, 11, 0, 8};
    int want[] = {L7P_IPV4, L7P_IPV4, L7P_ICMP, L7P_ICMP};
    for (int i = 0; i < 4; i++) {
        memset(b, 0, sizeof(b));
        b[0] = 0x45, b[8] = 64, b[9] = 1;
        put16(b + 2, (unsigned)(20 + 8 + n));
        b[12] = 10, b[15] = 2, b[16] = 10, b[19] = 1;
        b[20] = types[i];
        memcpy(b + 28, in, n);
        p = pkt_parse(b, 28 + n);
        CHECK(p != NULL);
        if (!p)
            continue;
        CHECK_INT(xl7_packet(x, NULL, 0, p, DIR_IN, b, 28 + n, NULL, 0, 1, NULL, NULL, &v), XL7_GO);
        CHECK_INT(v.l7p, want[i]);
        pkt_free(p);
    }
    xl7_free(x);
}

#  if GENEVA_EXT_CRYPTO
TEST(l7_reasm_quic)
{
    size_t n1, n2;
    uint8_t *a = load("tests/data/zapret2/quic_initial_rutracker_org_kyber_1.bin", &n1);
    uint8_t *b = load("tests/data/zapret2/quic_initial_rutracker_org_kyber_2.bin", &n2);
    xl7_config c = {0, 0, 0};
    rig g;
    if (!a || !b) {
        free(a), free(b);
        return;
    }
    t_current = "QUIC: a ClientHello in two Initials";
    rig_init(&g, &c);
    CHECK_INT(rig_pkt(&g, 1, 1, 0, 0, 0, 0, a, n1), XL7_HOLD);
    CHECK_INT(rig_pkt(&g, 1, 1, 0, 0, 0, 0, b, n2), XL7_HOLD);
    CHECK_INT(g.r.n, 2);
    if (g.r.n == 2) {
        CHECK(g.r.piece[0] == 1 && g.r.piece[1] == 2 && g.r.pieces[1] == 2);
        CHECK_INT(g.r.len[0], n1); /* UDP: its own datagram, and the decrypted hello */
        CHECK_INT(g.r.len[1], n2);
        CHECK(g.r.dec_len[0] > 1191 && g.r.dec_len[0] == g.r.dec_len[1]);
        CHECK_STR(g.r.host[0], "rutracker.org");
        CHECK_INT(g.r.l7p[1], L7P_QUIC_INITIAL);
    }
    CHECK_STR(g.f->host, "rutracker.org");
    CHECK_INT(g.f->l7proto, L7_QUIC);
    rig_free(&g);

    t_current = "QUIC: another packet of the flow ends the reassembly";
    rig_init(&g, &c);
    CHECK_INT(rig_pkt(&g, 1, 1, 0, 0, 0, 0, a, n1), XL7_HOLD);
    CHECK_INT(rig_pkt(&g, 0, 1, 0, 0, 0, 0, (const uint8_t *)"xx", 2), XL7_GO);
    CHECK_INT(g.r.n, 1);
    CHECK(g.r.partial[0]);
    CHECK_INT(g.r.l7p[0], L7P_QUIC_INITIAL);
    rig_free(&g);

    t_current = "QUIC: --ext-reasm-disable";
    c.reasm_disable = ~0ULL;
    rig_init(&g, &c);
    CHECK_INT(rig_pkt(&g, 1, 1, 0, 0, 0, 0, a, n1), XL7_GO);
    CHECK_INT(g.v.l7p, L7P_QUIC_INITIAL);
    CHECK(g.v.dec != NULL); /* a partial hello: no host yet */
    CHECK(g.v.host == NULL);
    rig_free(&g);

    t_current = "QUIC: --ext-reasm-max below one Initial";
    c.reasm_disable = 0;
    c.reasm_max = 1024;
    rig_init(&g, &c);
    CHECK_INT(rig_pkt(&g, 1, 1, 0, 0, 0, 0, a, n1), XL7_GO);
    CHECK_INT(g.v.l7p, L7P_QUIC_INITIAL);
    CHECK_INT(xl7_held(g.f), 0);
    rig_free(&g);
    c.reasm_max = 0;
    free(a), free(b);

    t_current = "QUIC: Chromium scatters its CRYPTO frames over two Initials";
    a = load("tests/data/ext/quic_chromium_0.bin", &n1);
    b = load("tests/data/ext/quic_chromium_1.bin", &n2);
    c.reasm_disable = 0;
    rig_init(&g, &c);
    if (a && b) {
        CHECK_INT(rig_pkt(&g, 1, 1, 0, 0, 0, 0, a, n1), XL7_HOLD);
        CHECK_INT(rig_pkt(&g, 1, 1, 0, 0, 0, 0, b, n2), XL7_HOLD);
        CHECK_INT(g.r.n, 2);
        CHECK_STR(g.r.host[1], "example.com");
    }
    rig_free(&g);
    free(a), free(b);

    t_current = "QUIC: one Initial with the whole hello";
    a = load("tests/data/zapret2/quic_initial_www_google_com.bin", &n1);
    rig_init(&g, &c);
    if (a) {
        CHECK_INT(rig_pkt(&g, 1, 1, 0, 0, 0, 0, a, n1), XL7_GO);
        CHECK_STR(g.v.host, "www.google.com");
        CHECK_INT(g.v.dec_len, 273);
    }
    rig_free(&g);
    free(a);
}
#  endif

/* ---- triggers ------------------------------------------------------------------ */

static const char *parse_err(const char *s)
{
    static char buf[256];
    sbuf e;
    strategy *st;
    sb_init(&e);
    st = strategy_parse(s, &e);
    snprintf(buf, sizeof(buf), "%s", st ? "OK" : e.data);
    strategy_free(st);
    sb_free(&e);
    return buf;
}

static int fires(const char *s, xl7_view *v)
{
    sbuf e;
    strategy *st;
    pktlist out = {0};
    xpkt_ctx c;
    uint8_t b[100];
    int k = -1;
    sb_init(&e);
    st = strategy_parse(s, &e);
    CHECK(st != NULL);
    if (st) {
        memset(&c, 0, sizeof(c));
        c.st = st;
        c.l7 = v;
        k = strategy_apply_x(st, pkt_parse(b, mkraw(b, 1, 0, P | A, 1, 1, 100, (const uint8_t *)"abc", 3)), DIR_OUT,
                             &out, &c);
    }
    pktlist_free(&out);
    strategy_free(st);
    sb_free(&e);
    return k;
}

TEST(l7_triggers)
{
    xl7_view v;
    strategy_set_xtrig(&xtrig_ops);
    CHECK_STR(parse_err("[L7:payload:tls_client_hello]-drop-| \\/"), "OK");
    CHECK_STR(parse_err("[L7:proto:~tls,quic]-drop-| \\/"), "OK");
    CHECK_STR(parse_err("[L7:host:example.com,*cdn.net]-drop-| \\/"), "OK");
    CHECK(strstr(parse_err("[L7:payload:tls]-drop-| \\/"), "unknown payload \"tls\""));
    CHECK(strstr(parse_err("[L7:proto:tls_client_hello]-drop-| \\/"), "unknown protocol"));
    CHECK(strstr(parse_err("[L7:host:a*b]-drop-| \\/"), "bad host"));
    CHECK(strstr(parse_err("[L7:host:*]-drop-| \\/"), "bad host"));
    CHECK(strstr(parse_err("[L7:sni:x]-drop-| \\/"), "unknown field \"sni\" for L7"));

    memset(&v, 0, sizeof(v));
    v.l7 = L7_TLS;
    v.l7p = L7P_TLS_CLIENT_HELLO;
    v.host = "www.example.com";
    CHECK_INT(fires("[L7:payload:tls_client_hello,http_req]-drop-| \\/", &v), 1);
    CHECK_INT(fires("[L7:payload:~tls_client_hello]-drop-| \\/", &v), 0);
    CHECK_INT(fires("[L7:payload:known]-drop-| \\/", &v), 1);
    CHECK_INT(fires("[L7:proto:quic]-drop-| \\/", &v), 0);
    CHECK_INT(fires("[L7:proto:~quic]-drop-| \\/", &v), 1);
    CHECK_INT(fires("[L7:host:example.com]-drop-| \\/", &v), 1);
    CHECK_INT(fires("[L7:host:EXAMPLE.com]-drop-| \\/", &v), 1);
    CHECK_INT(fires("[L7:host:ample.com]-drop-| \\/", &v), 0);
    CHECK_INT(fires("[L7:host:*ample.com]-drop-| \\/", &v), 1);
    CHECK_INT(fires("[L7:host:www.example.com]-drop-| \\/", &v), 1);
    CHECK_INT(fires("[L7:host:x.www.example.com]-drop-| \\/", &v), 0);
    CHECK_INT(fires("[L7:host:a.org,example.com]-drop-| \\/", &v), 1);
    v.host = NULL;
    CHECK_INT(fires("[L7:host:example.com]-drop-| \\/", &v), 0);
    v.l7 = L7_UNKNOWN;
    v.l7p = L7P_EMPTY;
    CHECK_INT(fires("[L7:payload:empty]-drop-| \\/", &v), 1);
    CHECK_INT(fires("[L7:payload:known]-drop-| \\/", &v), 0);
    CHECK_INT(fires("[L7:proto:unknown]-drop-| \\/", &v), 1);
    CHECK_INT(fires("[L7:proto:all]-drop-| \\/", &v), 1);
    /* without a view (no --ext path): unknown */
    CHECK_INT(fires("[L7:payload:unknown]-drop-| \\/", NULL), 1);
    CHECK_INT(fires("[L7:proto:unknown]-drop-| \\/", NULL), 1);
    /* round trip */
    {
        sbuf e, o;
        strategy *st;
        sb_init(&e);
        sb_init(&o);
        st = strategy_parse("[L7:host:Example.COM,*cdn]-drop-| [L7:payload:~known]-drop-| \\/", &e);
        CHECK(st != NULL);
        if (st)
            strategy_print(st, &o);
        CHECK_STR(o.data, "[L7:host:Example.COM,*cdn]-drop-| [L7:payload:~known]-drop-| \\/");
        strategy_free(st);
        sb_free(&e);
        sb_free(&o);
    }
    strategy_set_xtrig(NULL);
    CHECK(strcmp(parse_err("[L7:payload:empty]-drop-| \\/"), "OK") != 0);
}

/* ---- the engine: hold, replay ------------------------------------------------------ */

typedef struct {
    int accepts, drops, injects, resends;
    size_t inj_len[8], resend_len[8];
} elog_t;
static elog_t elog;

static int e_verdict(eng_worker *w, const void *pctx, int accept, const uint8_t *data, size_t len)
{
    uint32_t id;
    (void)w;
    memcpy(&id, pctx, sizeof(id));
    if (id & 0x80000000u) {
        /* detached: an accept sends the bytes anew, a drop does nothing */
        if (accept && data) {
            if (elog.resends < 8)
                elog.resend_len[elog.resends] = len;
            elog.resends++;
        } else if (accept) {
            elog.drops += 100; /* no bytes to send: wrong */
        }
        return 0;
    }
    if (accept)
        elog.accepts++;
    else
        elog.drops++;
    return 0;
}

static int e_inject(eng_worker *w, const void *pctx, const uint8_t *data, size_t len)
{
    (void)w, (void)pctx, (void)data;
    if (elog.injects < 8)
        elog.inj_len[elog.injects] = len;
    elog.injects++;
    return 0;
}

static void e_detach(const void *pctx, void *out)
{
    uint32_t id;
    memcpy(&id, pctx, sizeof(id));
    id |= 0x80000000u;
    memcpy(out, &id, sizeof(id));
}

static const backend ebe = {
    "fake", sizeof(uint32_t), NULL, NULL, NULL, NULL, NULL, e_verdict, e_inject, 0, NULL, NULL, NULL, NULL, NULL,
};
/* NFQUEUE-like: held packets are dropped at once and sent anew */
static const backend ebe_d = {
    "fake", sizeof(uint32_t), NULL, NULL, NULL, NULL, NULL, e_verdict, e_inject, 0, NULL, NULL, NULL, NULL, e_detach,
};

static int ext_on(const char *opt, const char *val)
{
    static const optdef defs[] = {EXT_OPT, EXT_CTRACK_OPTS, {NULL, 0, 0, NULL, NULL}};
    const char *argv[] = {"--ext", opt, val, NULL};
    args_t a;
    char err[128];
    int r;
    if (args_parse(&a, opt ? 3 : 1, (char **)argv, defs, err, sizeof(err)) < 0)
        return -2;
    r = ext_parse_args(&a, "test");
    args_free(&a);
    return r;
}

static void eng_pkt(engine *e, int c2s, unsigned flags, uint32_t seq, uint32_t ack, uint16_t win, const uint8_t *d,
                    size_t dl)
{
    uint8_t b[2100];
    uint32_t id = 1;
    size_t n = mkraw(b, c2s, 0, flags, seq, ack, win, d, dl);
    engine_packet(&e->w[0], b, n, c2s ? DIR_OUT : DIR_IN, &id);
}

/* a client's packet that comes in */
static void eng_pkt_in(engine *e, unsigned flags, uint32_t seq, uint32_t ack, uint16_t win, const uint8_t *d,
                       size_t dl)
{
    uint8_t b[2100];
    uint32_t id = 1;
    size_t n = mkraw(b, 1, 0, flags, seq, ack, win, d, dl);
    engine_packet(&e->w[0], b, n, DIR_IN, &id);
}

TEST(l7_engine_detach)
{
    engine e;
    engine_opts o;
    sbuf err;
    size_t n;
    uint8_t *ch = load("tests/data/ext/tls_clienthello_chromium_mlkem.bin", &n);
    if (!ch)
        return;
    CHECK_INT(ext_on(NULL, NULL), 0);
    sb_init(&err);
    engine_opts_default(&o);
    o.ext = ext_engine_hooks();
    memset(&e, 0, sizeof(e));
    e.o = &o;
    e.be = &ebe_d;
    plat_mutex_init(&e.lock);
    e.st = strategy_parse("[L7:host:example.com]-duplicate-| \\/", &err);
    CHECK(e.st != NULL);
    CHECK_INT(engine_workers_init(&e, 1, &err), 0);
    memset(&elog, 0, sizeof(elog));
    eng_pkt(&e, 1, S, 1000, 0, 64000, NULL, 0);
    eng_pkt(&e, 0, S | A, 5000, 1001, 65535, NULL, 0);
    eng_pkt(&e, 1, A, 1001, 5001, 64000, NULL, 0);
    /* held: the captured packet is dropped now */
    eng_pkt(&e, 1, P | A, 1001, 5001, 64000, ch, 1000);
    CHECK_INT(elog.drops, 1);
    CHECK_INT(e.w[0].c.held, 1);
    /* the second piece completes the hello: both go anew, each with its copy */
    eng_pkt(&e, 1, P | A, 2001, 5001, 64000, ch + 1000, n - 1000);
    CHECK_INT(elog.drops, 2);
    CHECK_INT(elog.resends, 2);
    CHECK_INT((int)elog.resend_len[0], (int)(40 + 1000));
    CHECK_INT((int)elog.resend_len[1], (int)(40 + n - 1000));
    CHECK_INT(elog.injects, 2);
    CHECK_INT(elog.accepts, 3);
    /* a client from outside (--server-side): its packet stays held, not
     * dropped, and goes on its own verdict when the flow starts over */
    eng_pkt_in(&e, S, 7000, 0, 64000, NULL, 0);
    eng_pkt(&e, 0, S | A, 5000, 7001, 65535, NULL, 0);
    eng_pkt_in(&e, P | A, 7001, 5001, 64000, ch, 1000);
    CHECK_INT(e.w[0].c.held, 3);
    CHECK_INT(elog.drops, 2);
    CHECK_INT(elog.resends, 2);
    /* the capture closes: a held packet is sent as it was */
    eng_pkt(&e, 1, S, 9000, 0, 64000, NULL, 0);
    eng_pkt(&e, 0, S | A, 5000, 9001, 65535, NULL, 0);
    eng_pkt(&e, 1, P | A, 9001, 5001, 64000, ch, 1000);
    CHECK_INT(elog.drops, 3);
    engine_run_timers(&e, 1);
    engine_workers_free(&e);
    CHECK_INT(elog.resends, 3);
    CHECK_INT((int)elog.resend_len[2], (int)(40 + 1000));
    strategy_free(e.st);
    plat_mutex_destroy(&e.lock);
    sb_free(&err);
    ext_reset();
    free(ch);
}

TEST(l7_engine)
{
    engine e;
    engine_opts o;
    sbuf err;
    size_t n;
    uint8_t *ch = load("tests/data/ext/tls_clienthello_chromium_mlkem.bin", &n);
    if (!ch)
        return;
    CHECK_INT(ext_on("--ext-reasm-disable", "nosuch"), -1);
    CHECK_INT(ext_on("--ext-payload-disable", "~dht"), -1);
    CHECK_INT(ext_on(NULL, NULL), 0);

    sb_init(&err);
    engine_opts_default(&o);
    o.ext = ext_engine_hooks();
    CHECK(o.ext != NULL);
    memset(&e, 0, sizeof(e));
    e.o = &o;
    e.be = &ebe;
    plat_mutex_init(&e.lock);
    /* the hello's pieces get a duplicate each when the host matches */
    e.st = strategy_parse("[L7:host:example.com]-duplicate-| \\/", &err);
    CHECK(e.st != NULL);
    CHECK_INT(engine_workers_init(&e, 1, &err), 0);
    memset(&elog, 0, sizeof(elog));

    eng_pkt(&e, 1, S, 1000, 0, 64000, NULL, 0);
    eng_pkt(&e, 0, S | A, 5000, 1001, 65535, NULL, 0);
    eng_pkt(&e, 1, A, 1001, 5001, 64000, NULL, 0);
    CHECK_INT(elog.accepts, 3);
    eng_pkt(&e, 1, P | A, 1001, 5001, 64000, ch, 1000);
    CHECK_INT(elog.accepts + elog.drops, 3); /* held: its verdict waits */
    CHECK_INT(e.w[0].c.held, 1);
    eng_pkt(&e, 1, P | A, 2001, 5001, 64000, ch + 1000, n - 1000);
    CHECK_INT(e.w[0].c.held, 2);
    /* both pieces replayed: each fires, rides on its verdict and has a copy */
    CHECK_INT(elog.accepts, 5);
    CHECK_INT(elog.drops, 0);
    CHECK_INT(elog.injects, 2);
    CHECK_INT(elog.inj_len[0], 40 + 1000);
    CHECK_INT(elog.inj_len[1], 40 + n - 1000);
    CHECK_INT(e.w[0].c.triggered, 2);
    CHECK_INT(e.st->out[0]->fired, 2);

    /* paused: nothing is held */
    e.paused = 1;
    eng_pkt(&e, 1, S, 3000, 0, 64000, NULL, 0);
    eng_pkt(&e, 1, P | A, 3001, 5001, 64000, ch, 1000);
    CHECK_INT(elog.accepts, 7);
    e.paused = 0;

    /* the capture closes: a held packet gets its verdict first */
    eng_pkt(&e, 1, S, 9000, 0, 64000, NULL, 0);
    eng_pkt(&e, 0, S | A, 5000, 9001, 65535, NULL, 0);
    eng_pkt(&e, 1, P | A, 9001, 5001, 64000, ch, 1000);
    CHECK_INT(elog.accepts, 9);
    CHECK_INT(e.w[0].c.held, 3);
    engine_run_timers(&e, 1);
    CHECK_INT(elog.accepts, 10);

    engine_workers_free(&e);
    strategy_free(e.st);
    plat_mutex_destroy(&e.lock);
    sb_free(&err);
    ext_reset();
    free(ch);
}

void suite_l7(void)
{
    RUN(l7_zapret2_lines);
    RUN(l7_names_lists);
    RUN(l7_markers);
    RUN(l7_reasm_tcp);
    RUN(l7_icmp);
#  if GENEVA_EXT_CRYPTO
    RUN(l7_reasm_quic);
#  endif
    RUN(l7_triggers);
    RUN(l7_engine);
    RUN(l7_engine_detach);
}

#else
void suite_l7(void) {}
#endif
