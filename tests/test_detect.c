/* Stage X9: the detector of --ext-auto (src/ext/detect.c), the NFLOG
 * parser (src/ext/nflog.c), the observation rules (src/fw.c) and the
 * options (src/ext/auto.c). Flows are made packet by packet: each class
 * of detect.h, success, and the keys' sequential test. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "ext_opt.h"
#include "fw.h"
#include "json.h"
#include "pkt.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/auto.h"
#  include "ext/ctnl.h"
#  include "ext/detect.h"
#  include "ext/ipcache.h"
#  include "ext/nflog.h"

enum { F = 1, S = 2, R = 4, P = 8, A = 16 };

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8), p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, v >> 16), put16(p + 2, v & 0xffff); }

/* the client 10.0.0.1:cport, the server 10.9.<srv>.2:sport */
typedef struct {
    uint16_t cport, sport;
    uint8_t srv, ttl;
    int udp;
} fl;

static size_t mk(uint8_t *b, const fl *f, int from_server, unsigned flags, uint32_t seq, uint32_t ack, const void *d,
                 size_t dl)
{
    size_t l4h = f->udp ? 8 : 20, l4 = l4h + dl;
    uint8_t *t = b + 20, *cli, *srv;
    memset(b, 0, 20 + l4);
    b[0] = 0x45;
    put16(b + 2, (unsigned)(20 + l4));
    b[8] = f->ttl ? f->ttl : 64;
    b[9] = f->udp ? 17 : 6;
    cli = from_server ? b + 16 : b + 12;
    srv = from_server ? b + 12 : b + 16;
    cli[0] = 10, cli[3] = 1;
    srv[0] = 10, srv[1] = 9, srv[2] = f->srv, srv[3] = 2;
    put16(t, from_server ? f->sport : f->cport);
    put16(t + 2, from_server ? f->cport : f->sport);
    if (f->udp) {
        put16(t + 4, (unsigned)l4);
    } else {
        put32(t + 4, seq);
        put32(t + 8, ack);
        t[12] = 5 << 4;
        t[13] = (uint8_t)flags;
        put16(t + 14, 65535);
    }
    if (dl)
        memcpy(t + l4h, d, dl);
    return 20 + l4;
}

/* ---- the sink ---- */

typedef struct {
    int flows_ok, flows_bad, last_cls;
    int links, link_deg;
    unsigned link_bad, link_active;
    char last_host[64], last_why[128];
    int nkey;
    struct {
        char key[64];
        int level, impaired, cls, change;
    } k[64];
} rec;

static void on_flow(void *ud, const xdet_flow_ev *ev)
{
    rec *r = ud;
    if (ev->ok)
        r->flows_ok++;
    else
        r->flows_bad++, r->last_cls = ev->cls;
    snprintf(r->last_why, sizeof(r->last_why), "%s", ev->why ? ev->why : "");
    snprintf(r->last_host, sizeof(r->last_host), "%s", ev->host ? ev->host : "");
}

static void on_key(void *ud, const xdet_key_ev *ev)
{
    rec *r = ud;
    if (r->nkey < 64) {
        snprintf(r->k[r->nkey].key, sizeof(r->k[0].key), "%s", ev->key);
        r->k[r->nkey].level = ev->level;
        r->k[r->nkey].impaired = ev->impaired;
        r->k[r->nkey].cls = ev->cls;
        r->k[r->nkey].change = ev->class_change;
        r->nkey++;
    }
}

static void on_link(void *ud, int degraded, unsigned bad, unsigned active)
{
    rec *r = ud;
    r->links++;
    r->link_deg = degraded;
    r->link_bad = bad;
    r->link_active = active;
}

/* the last event of a key: 1 impaired, 0 healthy, -1 none */
static int key_state(const rec *r, const char *key, int *cls)
{
    for (int i = r->nkey - 1; i >= 0; i--)
        if (!strcmp(r->k[i].key, key)) {
            if (cls)
                *cls = r->k[i].cls;
            return r->k[i].impaired;
        }
    return -1;
}

static xdet *det_self(rec *r, int self_count)
{
    xdet_config c;
    ct_config ct;
    xdet_sink s = {on_flow, on_key, on_link, NULL};
    memset(r, 0, sizeof(*r));
    s.ud = r;
    xipc_reset();
    xipc_config(XIPC_LIFETIME, 1); /* --ext-ipcache-hostname 1 */
    xdet_config_default(&c);
    c.self_count = self_count;
    ct_config_default(&ct);
    return xdet_new(&c, &ct, &s);
}

static xdet *det(rec *r) { return det_self(r, 0); }

static uint64_t g_now = 1000000;

static void feed(xdet *d, const uint8_t *b, size_t n)
{
    gpkt *p = pkt_parse(b, n);
    CHECK(p != NULL);
    if (p) {
        xdet_packet(d, p, g_now);
        pkt_free(p);
    }
    g_now += 10;
}

#  define CISN 1000u
#  define SISN 50000u

/* the handshake */
static void hs(xdet *d, const fl *f)
{
    uint8_t b[2048];
    feed(d, b, mk(b, f, 0, S, CISN, 0, NULL, 0));
    feed(d, b, mk(b, f, 1, S | A, SISN, CISN + 1, NULL, 0));
    feed(d, b, mk(b, f, 0, A, CISN + 1, SISN + 1, NULL, 0));
}

static const char HTTP_REQ[] = "GET / HTTP/1.1\r\nHost: Blocked.Example\r\n\r\n";

/* a request sent again n times without an answer */
static void retrans_flow(xdet *d, const fl *f, int n)
{
    uint8_t b[2048];
    hs(d, f);
    for (int i = 0; i <= n; i++)
        feed(d, b, mk(b, f, 0, P | A, CISN + 1, SISN + 1, HTTP_REQ, sizeof(HTTP_REQ) - 1));
}

/* a download: the server sends 6 KB */
static void ok_flow(xdet *d, const fl *f)
{
    uint8_t b[2048], data[1400];
    memset(data, 'y', sizeof(data));
    hs(d, f);
    feed(d, b, mk(b, f, 0, P | A, CISN + 1, SISN + 1, HTTP_REQ, sizeof(HTTP_REQ) - 1));
    for (uint32_t o = 0; o < 6000; o += 1400)
        feed(d, b, mk(b, f, 1, A, SISN + 1 + o, CISN + 1 + sizeof(HTTP_REQ) - 1, data, sizeof(data)));
}

TEST(detect_retrans)
{
    rec r;
    xdet *d = det(&r);
    fl f = {40001, 80, 1, 0, 0};
    xdet_stats st;
    int cls = 0;
    /* two retransmissions: not yet */
    retrans_flow(d, &f, 2);
    CHECK_INT(r.flows_bad, 0);
    /* the third */
    retrans_flow(d, &f, 3);
    CHECK_INT(r.flows_bad, 1);
    CHECK_INT(r.last_cls, XC_RETRANS);
    CHECK_STR(r.last_host, "blocked.example");
    CHECK_INT(r.nkey, 0); /* one failure decides nothing */
    f.cport++;
    retrans_flow(d, &f, 3);
    CHECK_INT(r.flows_bad, 2);
    CHECK_INT(key_state(&r, "tcp/80", &cls), 1);
    CHECK_INT(cls, XC_RETRANS);
    CHECK_INT(key_state(&r, "10.9.1.0/24", NULL), 1);
    CHECK_INT(key_state(&r, "10.9.1.2", NULL), 1);
    CHECK_INT(key_state(&r, "blocked.example", NULL), 1);
    xdet_get_stats(d, &st);
    CHECK_INT(st.flows_failed, 2);
    CHECK_INT(st.impaired, 4);
    CHECK_INT(st.keys, 4);
    /* the detector does not write the address cache (the profiles' names) */
    {
        char h[64];
        int ip = 1;
        CHECK_INT(xipc_get_host(4, (const uint8_t[]){10, 9, 1, 2}, h, sizeof(h), &ip), 0);
    }
    /* successes take it back: eight of them (llr from A to B) */
    for (int i = 0; i < 7; i++) {
        f.cport++;
        ok_flow(d, &f);
    }
    CHECK_INT(r.flows_ok, 7);
    CHECK_INT(key_state(&r, "tcp/80", NULL), 1);
    f.cport++;
    ok_flow(d, &f);
    CHECK_INT(key_state(&r, "tcp/80", NULL), 0);
    CHECK_INT(key_state(&r, "blocked.example", NULL), 0);
    xdet_get_stats(d, &st);
    CHECK_INT(st.impaired, 0);
    /* the JSON of the keys */
    {
        sbuf s;
        jw w;
        sb_init(&s);
        jw_init(&w, &s);
        xdet_keys_json(d, &w, 0);
        CHECK(strstr(s.data, "{\"key\":\"tcp/80\",\"level\":\"port\",\"impaired\":false,\"flows\":10,\"fails\":2,"
                             "\"classes\":{\"RETRANS\":2}}") != NULL);
        sb_reset(&s);
        jw_init(&w, &s);
        xdet_keys_json(d, &w, 1);
        CHECK_STR(s.data, "[]");
        sb_free(&s);
    }
    xdet_free(d);
    xipc_reset();
}

TEST(detect_success_edges)
{
    rec r;
    xdet *d = det(&r);
    fl f = {40100, 443, 2, 0, 0};
    uint8_t b[2048], data[1000];
    memset(data, 'z', sizeof(data));
    /* the server sends exactly incoming_maxseq bytes: undecided */
    hs(d, &f);
    for (uint32_t o = 0; o < 4096; o += 1024)
        feed(d, b, mk(&b[0], &f, 1, A, SISN + 1 + o, CISN + 1, data, 1000));
    CHECK_INT(r.flows_ok, 0);
    feed(d, b, mk(b, &f, 1, A, SISN + 1 + 4096, CISN + 1, data, 1000));
    CHECK_INT(r.flows_ok, 1);
    /* a decided flow is not decided again: a later RST changes nothing */
    feed(d, b, mk(b, &f, 1, R, SISN + 2, 0, NULL, 0));
    CHECK_INT(r.flows_bad, 0);
    /* the client past retrans_maxseq */
    f.cport++;
    hs(d, &f);
    for (uint32_t o = 0; o <= 33000; o += 1000)
        feed(d, b, mk(b, &f, 0, A, CISN + 1 + o, SISN + 1, data, 1000));
    CHECK_INT(r.flows_ok, 2);
    xdet_free(d);
}

TEST(detect_rst)
{
    rec r;
    xdet *d = det(&r);
    fl f = {40200, 443, 3, 60, 0};
    uint8_t b[2048];
    int cls = 0;
    /* the RST with the SYN,ACK's TTL: RST_IN */
    for (int i = 0; i < 2; i++) {
        hs(d, &f);
        feed(d, b, mk(b, &f, 0, P | A, CISN + 1, SISN + 1, "hello", 5));
        feed(d, b, mk(b, &f, 1, R | A, SISN + 1, CISN + 6, NULL, 0));
        f.cport++;
    }
    CHECK_INT(r.flows_bad, 2);
    CHECK_INT(r.last_cls, XC_RST_IN);
    CHECK_INT(key_state(&r, "10.9.3.2", &cls), 1);
    CHECK_INT(cls, XC_RST_IN);
    /* another TTL (one off is still the server's): injected */
    f.srv = 4;
    for (int i = 0; i < 5; i++) {
        hs(d, &f);
        f.ttl = (uint8_t)(i ? 64 : 61);
        feed(d, b, mk(b, &f, 1, R | A, SISN + 1, CISN + 1, NULL, 0));
        f.ttl = 60;
        f.cport++;
    }
    CHECK_INT(r.flows_bad, 7);
    CHECK_INT(r.last_cls, XC_RST_INJECT);
    CHECK_INT(key_state(&r, "10.9.4.2", &cls), 1);
    CHECK_INT(cls, XC_RST_INJECT);
    /* the port's commonest class went over from RST_IN (3) to RST_INJECT (4) */
    CHECK_INT(key_state(&r, "tcp/443", &cls), 1);
    CHECK_INT(cls, XC_RST_INJECT);
    {
        int changed = 0;
        for (int i = 0; i < r.nkey; i++)
            changed += r.k[i].change && !strcmp(r.k[i].key, "tcp/443");
        CHECK_INT(changed, 1);
    }
    /* a RST after the server's answer, with its TTL: a short exchange
     * ended, no class; with another TTL it is injected */
    f.srv = 12;
    for (int i = 0; i < 2; i++) {
        hs(d, &f);
        feed(d, b, mk(b, &f, 0, P | A, CISN + 1, SISN + 1, "hello", 5));
        feed(d, b, mk(b, &f, 1, P | A, SISN + 1, CISN + 6, "answer", 6));
        f.ttl = (uint8_t)(i ? 30 : 60);
        feed(d, b, mk(b, &f, 1, R | A, SISN + 7, CISN + 6, NULL, 0));
        f.ttl = 60;
        f.cport++;
    }
    CHECK_INT(r.flows_bad, 8);
    CHECK_INT(r.last_cls, XC_RST_INJECT);
    r.flows_bad = 7;
    /* a RST past incoming_maxseq is not one: the flow already succeeded */
    f.srv = 5;
    hs(d, &f);
    feed(d, b, mk(b, &f, 1, R | A, SISN + 5000, CISN + 1, NULL, 0));
    CHECK_INT(r.flows_bad, 7);
    CHECK_INT(r.flows_ok, 1);
    /* a refused connection (RST to the SYN) is no class */
    f.cport++;
    feed(d, b, mk(b, &f, 0, S, CISN, 0, NULL, 0));
    feed(d, b, mk(b, &f, 1, R | A, 0, CISN + 1, NULL, 0));
    CHECK_INT(r.flows_bad, 7);
    xdet_free(d);
}

TEST(detect_redirect)
{
    rec r;
    xdet *d = det(&r);
    fl f = {40300, 80, 6, 0, 0};
    uint8_t b[2048];
    static const char same[] = "HTTP/1.1 302 Found\r\nLocation: http://www.blocked.example/x\r\n\r\n";
    static const char other[] = "HTTP/1.1 302 Found\r\nLocation: http://block.example/\r\n\r\n";
    /* to the same domain: no class, undecided */
    hs(d, &f);
    feed(d, b, mk(b, &f, 0, P | A, CISN + 1, SISN + 1, HTTP_REQ, sizeof(HTTP_REQ) - 1));
    feed(d, b, mk(b, &f, 1, P | A, SISN + 1, CISN + 1 + sizeof(HTTP_REQ) - 1, same, sizeof(same) - 1));
    CHECK_INT(r.flows_bad, 0);
    f.cport++;
    hs(d, &f);
    feed(d, b, mk(b, &f, 0, P | A, CISN + 1, SISN + 1, HTTP_REQ, sizeof(HTTP_REQ) - 1));
    feed(d, b, mk(b, &f, 1, P | A, SISN + 1, CISN + 1 + sizeof(HTTP_REQ) - 1, other, sizeof(other) - 1));
    CHECK_INT(r.flows_bad, 1);
    CHECK_INT(r.last_cls, XC_REDIRECT);
    xdet_free(d);
    xipc_reset();
}

TEST(detect_udp_syn_icmp)
{
    rec r;
    xdet *d = det(&r);
    fl f = {40400, 443, 7, 0, 1};
    uint8_t b[2048];
    int cls = 0;
    /* QUIC without an answer: four datagrams */
    for (int k = 0; k < 2; k++) {
        for (int i = 0; i < 4; i++) {
            CHECK_INT(r.flows_bad, k);
            feed(d, b, mk(b, &f, 0, 0, 0, 0, "quic", 4));
        }
        f.cport++;
    }
    CHECK_INT(r.flows_bad, 2);
    CHECK_INT(r.last_cls, XC_UDP_NOANSWER);
    CHECK_INT(key_state(&r, "udp/443", &cls), 1);
    CHECK_INT(cls, XC_UDP_NOANSWER);
    /* one answer is not enough, two are */
    f.srv = 8;
    feed(d, b, mk(b, &f, 0, 0, 0, 0, "quic", 4));
    feed(d, b, mk(b, &f, 1, 0, 0, 0, "ans", 3));
    CHECK_INT(r.flows_ok, 0);
    feed(d, b, mk(b, &f, 1, 0, 0, 0, "ans", 3));
    CHECK_INT(r.flows_ok, 1);

    /* SYNs into a black hole */
    f.udp = 0;
    f.srv = 9;
    f.sport = 8443;
    feed(d, b, mk(b, &f, 0, S, CISN, 0, NULL, 0));
    CHECK_INT(r.flows_bad, 2);
    feed(d, b, mk(b, &f, 0, S, CISN, 0, NULL, 0));
    CHECK_INT(r.flows_bad, 3);
    CHECK_INT(r.last_cls, XC_BLACKHOLE_SYN);

    /* ICMP administratively prohibited about a SYN */
    f.srv = 10;
    f.cport++;
    {
        uint8_t syn[64], ic[128];
        size_t n = mk(syn, &f, 0, S, CISN, 0, NULL, 0);
        feed(d, syn, n);
        memset(ic, 0, sizeof(ic));
        ic[0] = 0x45;
        put16(ic + 2, (unsigned)(20 + 8 + 28));
        ic[8] = 64;
        ic[9] = 1;
        ic[12] = 10, ic[13] = 9, ic[14] = 10, ic[15] = 1; /* a router */
        ic[16] = 10, ic[19] = 1;
        ic[20] = 3, ic[21] = 13;
        memcpy(ic + 28, syn, 28);
        feed(d, ic, 20 + 8 + 28);
        CHECK_INT(r.flows_bad, 4);
        CHECK_INT(r.last_cls, XC_ICMP_PROHIBIT);
        /* port unreachable is no class */
        f.cport++;
        n = mk(syn, &f, 0, S, CISN, 0, NULL, 0);
        feed(d, syn, n);
        memcpy(ic + 28, syn, 28);
        ic[21] = 3;
        feed(d, ic, 20 + 8 + 28);
        CHECK_INT(r.flows_bad, 4);
    }
    xdet_free(d);
}

/* a flow without a request takes its name from the address cache;
 * multicast and link-local get no outcome */
TEST(detect_cache_multicast)
{
    rec r;
    xdet *d = det(&r);
    fl f = {40600, 443, 13, 0, 1};
    uint8_t b[256];
    xipc_put_host(4, (const uint8_t[]){10, 9, 13, 2}, "quic.example", 0, g_now);
    for (int i = 0; i < 4; i++)
        feed(d, b, mk(b, &f, 0, 0, 0, 0, "quic", 4));
    CHECK_INT(r.flows_bad, 1);
    CHECK_STR(r.last_host, "quic.example");
    /* SSDP to 239.255.255.250, then to 169.254.1.1 */
    for (int k = 0; k < 2; k++) {
        f.cport++;
        for (int i = 0; i < 6; i++) {
            size_t n = mk(b, &f, 0, 0, 0, 0, "M-SEARCH", 8);
            b[16] = k ? 169 : 239, b[17] = k ? 254 : 255, b[18] = k ? 1 : 255, b[19] = k ? 1 : 250;
            feed(d, b, n);
        }
    }
    CHECK_INT(r.flows_bad, 1);
    xdet_free(d);
    xipc_reset();
}

/* ---- volume (X9b) ---- */

/* the conntrack's counters of flow f */
static void ctr(xdet *d, const fl *f, uint64_t rbytes, int open, uint64_t now)
{
    xdet_ctr c;
    memset(&c, 0, sizeof(c));
    c.t.ver = 4;
    c.t.proto = f->udp ? 17 : 6;
    c.t.cli[0] = 10, c.t.cli[3] = 1;
    c.t.srv[0] = 10, c.t.srv[1] = 9, c.t.srv[2] = f->srv, c.t.srv[3] = 2;
    c.t.cport = f->cport;
    c.t.sport = f->sport;
    c.found = 1;
    c.open = open;
    c.rbytes = rbytes;
    xdet_counters(d, &c, now);
}

static int g_nreq;
static xdet_tuple g_req;
static void on_req(void *ud, const xdet_tuple *t)
{
    (void)ud;
    g_nreq++;
    g_req = *t;
}

/* the keys as ext_keys shows them */
static void keys_json(xdet *d, sbuf *s)
{
    jw w;
    sb_reset(s);
    jw_init(&w, s);
    xdet_keys_json(d, &w, 0);
}

/* a download that stops at b bytes for 3 s while the flow stays open */
static void freeze_flow(xdet *d, fl *f, uint64_t b)
{
    uint64_t t;
    ok_flow(d, f);
    t = g_now;
    ctr(d, f, b, 1, t);
    ctr(d, f, b, 1, t + 2900);
    ctr(d, f, b, 1, t + 3000);
    g_now = t + 3010;
    f->cport++;
}

TEST(detect_freeze)
{
    rec r;
    xdet *d = det(&r);
    fl f = {41000, 443, 20, 0, 0};
    sbuf s;
    int cls = 0;
    sb_init(&s);
    /* the watch: one request per watched flow and tick */
    ok_flow(d, &f);
    g_nreq = 0;
    xdet_tick(d, g_now, on_req, NULL);
    CHECK_INT(g_nreq, 1);
    CHECK_INT(g_req.cport, 41000);
    CHECK_INT(g_req.srv[2], 20);
    /* a flow that closes is no freeze, and its watch ends */
    ctr(d, &f, 20000, 0, g_now + 5000);
    g_nreq = 0;
    xdet_tick(d, g_now + 5000, on_req, NULL);
    CHECK_INT(g_nreq, 0);
    CHECK_INT(r.flows_bad, 0);
    f.cport++;
    /* a flow that goes on after a pause is no freeze */
    ok_flow(d, &f);
    ctr(d, &f, 20000, 1, g_now);
    ctr(d, &f, 30000, 1, g_now + 2000);
    ctr(d, &f, 30000, 1, g_now + 4000);
    CHECK_INT(r.flows_bad, 0);
    g_now += 4000;
    f.cport++;
    /* three freezes at about 20 KB: the key's class */
    freeze_flow(d, &f, 20000);
    CHECK_INT(r.flows_bad, 1);
    CHECK_INT(r.last_cls, XC_FREEZE);
    CHECK_INT(key_state(&r, "10.9.20.2", NULL), -1);
    freeze_flow(d, &f, 20500);
    CHECK_INT(key_state(&r, "10.9.20.2", NULL), -1);
    freeze_flow(d, &f, 21500);
    CHECK_INT(r.flows_bad, 3);
    CHECK_INT(key_state(&r, "10.9.20.2", &cls), 1);
    CHECK_INT(cls, XC_FREEZE);
    CHECK_INT(key_state(&r, "blocked.example", &cls), 1);
    keys_json(d, &s);
    CHECK(strstr(s.data, "{\"key\":\"10.9.20.2\",\"level\":\"ip\",\"impaired\":true,\"class\":\"FREEZE_N\","
                         "\"flows\":5,\"fails\":3,\"classes\":{\"FREEZE_N\":3}}") != NULL);
    /* now a success needs more than twice B (20500) */
    ok_flow(d, &f);
    ctr(d, &f, 30000, 0, g_now);
    keys_json(d, &s);
    CHECK(strstr(s.data, "\"10.9.20.2\",\"level\":\"ip\",\"impaired\":true,\"class\":\"FREEZE_N\",\"flows\":5,") !=
          NULL);
    f.cport++;
    ok_flow(d, &f);
    ctr(d, &f, 30000, 1, g_now);
    ctr(d, &f, 50000, 1, g_now + 1000);
    keys_json(d, &s);
    CHECK(strstr(s.data, "\"10.9.20.2\",\"level\":\"ip\",\"impaired\":true,\"class\":\"FREEZE_N\",\"flows\":6,") !=
          NULL);
    /* freezes far apart are no class */
    f.srv = 21;
    freeze_flow(d, &f, 10000);
    freeze_flow(d, &f, 30000);
    freeze_flow(d, &f, 60000);
    CHECK_INT(key_state(&r, "10.9.21.2", NULL), -1);
    /* nor are counts out of [8 KB, 64 KB] */
    f.srv = 22;
    for (int i = 0; i < 3; i++)
        freeze_flow(d, &f, 100000);
    CHECK_INT(r.flows_bad, 6);
    xdet_free(d);
    sb_free(&s);
}

/* a download of n windows of rate bytes a second, from t */
static void rate_flow(xdet *d, fl *f, int n, uint64_t rate, int close)
{
    uint64_t t, b = 6000;
    ok_flow(d, f);
    t = g_now;
    for (int i = 0; i <= n; i++, b += rate)
        ctr(d, f, b, 1, t + 1000u * (unsigned)i);
    if (close)
        ctr(d, f, b - rate, 0, t + 1000u * (unsigned)n + 10);
    g_now = t + 1000u * (unsigned)n + 20;
    f->cport++;
}

TEST(detect_throttle)
{
    rec r;
    xdet *d = det(&r);
    fl f = {42000, 443, 30, 0, 0};
    xdet_stats st;
    sbuf s;
    int cls = 0;
    sb_init(&s);
    /* without C nothing is slow */
    f.srv = 33;
    rate_flow(d, &f, 8, 20000, 1);
    CHECK_INT(r.flows_bad, 0);
    /* a fast download: C, 1 MB/s */
    f.srv = 30;
    rate_flow(d, &f, 3, 1000000, 1);
    xdet_get_stats(d, &st);
    CHECK(st.capacity > 999000 && st.capacity < 1001000);
    /* a flat 20 KB/s: THROTTLE; twice: the key's class */
    f.srv = 31;
    rate_flow(d, &f, 6, 20000, 0);
    CHECK_INT(r.flows_bad, 1);
    CHECK_INT(r.last_cls, XC_THROTTLE);
    rate_flow(d, &f, 6, 20000, 0);
    CHECK_INT(key_state(&r, "10.9.31.2", &cls), 1);
    CHECK_INT(cls, XC_THROTTLE);
    keys_json(d, &s);
    CHECK(strstr(s.data, "\"10.9.31.2\",\"level\":\"ip\",\"impaired\":true,\"class\":\"THROTTLE\",\"flows\":2,") !=
          NULL);
    /* now a success needs three times the plateau */
    rate_flow(d, &f, 3, 50000, 1);
    keys_json(d, &s);
    CHECK(strstr(s.data, "\"10.9.31.2\",\"level\":\"ip\",\"impaired\":true,\"class\":\"THROTTLE\",\"flows\":2,") !=
          NULL);
    rate_flow(d, &f, 3, 100000, 1);
    keys_json(d, &s);
    CHECK(strstr(s.data, "\"10.9.31.2\",\"level\":\"ip\",\"impaired\":true,\"class\":\"THROTTLE\",\"flows\":3,") !=
          NULL);
    /* a rate that varies is no plateau, nor is one with a burst */
    f.srv = 32;
    {
        uint64_t t, b = 6000;
        static const uint64_t v[] = {0, 5000, 40000, 8000, 30000, 6000, 35000, 9000};
        ok_flow(d, &f);
        t = g_now;
        for (int i = 0; i < 8; i++)
            ctr(d, &f, b += v[i], 1, t + 1000u * (unsigned)i);
        g_now = t + 9000;
    }
    CHECK_INT(r.flows_bad, 2);
    xdet_free(d);
    sb_free(&s);
}

/* two downloads to other networks at once, both on a plateau: the link,
 * no THROTTLE; then one alone: THROTTLE */
TEST(detect_throttle_parallel)
{
    rec r;
    xdet *d = det(&r);
    fl f = {43000, 443, 40, 0, 0}, a = {43100, 443, 41, 0, 0}, b = {43200, 443, 42, 0, 0};
    uint64_t t, ba = 6000, bb = 6000;
    rate_flow(d, &f, 3, 1000000, 1); /* C */
    ok_flow(d, &a);
    ok_flow(d, &b);
    t = g_now;
    for (int i = 0; i <= 8; i++, ba += 20000, bb += 22000) {
        ctr(d, &a, ba, 1, t + 1000u * (unsigned)i);
        ctr(d, &b, bb, 1, t + 1000u * (unsigned)i + 5);
    }
    CHECK_INT(r.flows_bad, 0);
    /* a parallel flow to the same network is no excuse */
    g_now = t + 9000;
    a.cport += 10, b.cport += 10, b.srv = 41;
    ok_flow(d, &a);
    ok_flow(d, &b);
    t = g_now, ba = bb = 6000;
    for (int i = 0; i <= 8; i++, ba += 20000, bb += 22000) {
        ctr(d, &a, ba, 1, t + 1000u * (unsigned)i);
        ctr(d, &b, bb, 1, t + 1000u * (unsigned)i + 5);
    }
    CHECK_INT(r.flows_bad, 2);
    CHECK_INT(r.last_cls, XC_THROTTLE);
    /* nor is a fast one to another network */
    g_now = t + 9000;
    a.cport += 10, b.cport += 10, b.srv = 43;
    ok_flow(d, &a);
    ok_flow(d, &b);
    t = g_now, ba = bb = 6000;
    for (int i = 0; i <= 8; i++, ba += 20000, bb += 900000) {
        ctr(d, &a, ba, 1, t + 1000u * (unsigned)i);
        ctr(d, &b, bb, 1, t + 1000u * (unsigned)i + 5);
    }
    CHECK_INT(r.flows_bad, 3);
    xdet_free(d);
}

/* the observer sees every packet (WinDivert SNIFF): the detector counts */
static void srv_data(xdet *d, const fl *f, uint32_t off, int n)
{
    uint8_t b[2048], data[1400];
    memset(data, 'z', sizeof(data));
    for (int i = 0; i < n; i++, off += 1400)
        feed(d, b, mk(b, f, 1, A, SISN + 1 + off, CISN + 1 + sizeof(HTTP_REQ) - 1, data, sizeof(data)));
}

TEST(detect_self_count)
{
    rec r;
    xdet *d = det_self(&r, 1);
    fl f = {44000, 443, 50, 0, 0};
    xdet_stats st;
    uint8_t b[256];
    /* no requests, and the conntrack's counters are not wanted */
    ok_flow(d, &f); /* 5 packets of 1440 bytes */
    g_nreq = 0;
    xdet_tick(d, g_now, on_req, NULL);
    CHECK_INT(g_nreq, 0);
    xdet_get_stats(d, &st);
    CHECK_INT((int)st.watched, 1);
    ctr(d, &f, 1, 1, g_now); /* ignored */
    srv_data(d, &f, 7000, 4);
    {
        /* a copy cut short (WinDivert's range): the IP length counts */
        uint8_t big[2048], data[1400];
        memset(data, 'z', sizeof(data));
        feed(d, big, mk(big, &f, 1, A, SISN + 1 + 12600, CISN + 1 + sizeof(HTTP_REQ) - 1, data, sizeof(data)) - 900);
    } /* 14400 bytes: in [8 KB, 64 KB] */
    xdet_tick(d, g_now + 1000, NULL, NULL);
    xdet_tick(d, g_now + 3000, NULL, NULL);
    CHECK_INT(r.flows_bad, 0);
    xdet_tick(d, g_now + 4100, NULL, NULL);
    CHECK_INT(r.flows_bad, 1);
    CHECK_INT(r.last_cls, XC_FREEZE);
    CHECK(strstr(r.last_why, "14400") != NULL);
    /* a flow the server closes is no freeze */
    g_now += 5000;
    f.cport++;
    ok_flow(d, &f);
    srv_data(d, &f, 7000, 5);
    xdet_tick(d, g_now, NULL, NULL);
    feed(d, b, mk(b, &f, 1, F | A, SISN + 1 + 14000, CISN + 1 + sizeof(HTTP_REQ) - 1, NULL, 0));
    xdet_tick(d, g_now + 4000, NULL, NULL);
    xdet_tick(d, g_now + 5000, NULL, NULL);
    CHECK_INT(r.flows_bad, 1);
    xdet_get_stats(d, &st);
    CHECK_INT((int)st.watched, 1); /* the first one, frozen, still open */
    xdet_free(d);
}

/* a DNS answer for blocked.example: a, its address; 0 for a stub */
static size_t dns_ans(uint8_t *m, uint16_t id, const uint8_t a[4])
{
    static const uint8_t q[] = {7, 'b', 'l', 'o', 'c', 'k', 'e', 'd', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1};
    size_t n = 12;
    memset(m, 0, 12);
    put16(m, id);
    put16(m + 2, 0x8180);
    put16(m + 4, 1);
    put16(m + 6, 1);
    memcpy(m + n, q, sizeof(q));
    n += sizeof(q);
    put16(m + n, 0xc00c), put16(m + n + 2, 1), put16(m + n + 4, 1), put32(m + n + 6, 60), put16(m + n + 10, 4);
    memcpy(m + n + 12, a, 4);
    return n + 16;
}

TEST(detect_dns)
{
    rec r;
    xdet *d = det(&r);
    fl f = {43000, 53, 40, 0, 1};
    uint8_t b[512], m[256];
    int cls = 0;
    static const uint8_t real[4] = {93, 184, 215, 14}, stub[4] = {127, 0, 0, 1}, zero[4] = {0, 0, 0, 0};
    /* an answer: a success, and a second alike one changes nothing */
    feed(d, b, mk(b, &f, 0, 0, 0, 0, "q", 1));
    feed(d, b, mk(b, &f, 1, 0, 0, 0, m, dns_ans(m, 7, real)));
    CHECK_INT(r.flows_ok, 1);
    CHECK_STR(r.last_host, "blocked.example");
    feed(d, b, mk(b, &f, 1, 0, 0, 0, m, dns_ans(m, 7, real)));
    CHECK_INT(r.flows_bad, 0);
    /* a stub address */
    f.cport++;
    feed(d, b, mk(b, &f, 0, 0, 0, 0, "q", 1));
    feed(d, b, mk(b, &f, 1, 0, 0, 0, m, dns_ans(m, 8, stub)));
    CHECK_INT(r.flows_bad, 1);
    CHECK_INT(r.last_cls, XC_DNS_POISON);
    /* two answers, the first with another TTL: it was injected */
    f.cport++;
    feed(d, b, mk(b, &f, 0, 0, 0, 0, "q", 1));
    f.ttl = 60;
    feed(d, b, mk(b, &f, 1, 0, 0, 0, m, dns_ans(m, 9, real)));
    CHECK_INT(r.flows_ok, 2);
    f.ttl = 52;
    feed(d, b, mk(b, &f, 1, 0, 0, 0, m, dns_ans(m, 9, real)));
    CHECK_INT(r.flows_bad, 2);
    /* another id is another query; a stub after a real answer is poison */
    f.cport++;
    f.ttl = 0;
    feed(d, b, mk(b, &f, 0, 0, 0, 0, "q", 1));
    feed(d, b, mk(b, &f, 1, 0, 0, 0, m, dns_ans(m, 10, real)));
    f.ttl = 50;
    feed(d, b, mk(b, &f, 1, 0, 0, 0, m, dns_ans(m, 11, real)));
    CHECK_INT(r.flows_bad, 2);
    feed(d, b, mk(b, &f, 1, 0, 0, 0, m, dns_ans(m, 11, zero)));
    CHECK_INT(r.flows_bad, 3);
    CHECK_INT(key_state(&r, "blocked.example", &cls), 1);
    CHECK_INT(cls, XC_DNS_POISON);
    /* the stubs are the name's: the resolver had one injection only */
    CHECK_INT(key_state(&r, "udp/53", NULL), -1);
    CHECK_INT(key_state(&r, "10.9.40.2", NULL), -1);
    /* two more injections: the resolver's port too */
    for (int i = 0; i < 2; i++) {
        f.cport++;
        f.ttl = 60;
        feed(d, b, mk(b, &f, 0, 0, 0, 0, "q", 1));
        feed(d, b, mk(b, &f, 1, 0, 0, 0, m, dns_ans(m, (uint16_t)(20 + i), real)));
        f.ttl = 52;
        feed(d, b, mk(b, &f, 1, 0, 0, 0, m, dns_ans(m, (uint16_t)(20 + i), real)));
    }
    CHECK_INT(key_state(&r, "udp/53", &cls), 1);
    CHECK_INT(cls, XC_DNS_POISON);
    f.ttl = 0;
    /* queries without an answer */
    f.cport++;
    for (int i = 0; i < 4; i++)
        feed(d, b, mk(b, &f, 0, 0, 0, 0, "q", 1));
    CHECK_INT(r.flows_bad, 6);
    CHECK_INT(r.last_cls, XC_UDP_NOANSWER);
    /* junk and a query are no answer */
    f.cport++;
    feed(d, b, mk(b, &f, 1, 0, 0, 0, "\x01\x02\x81\x80\0\1\0\1\0\0\0\0\x05" "abc", 17));
    m[2] = 0x01;
    feed(d, b, mk(b, &f, 1, 0, 0, 0, m, dns_ans(m, 12, stub) - 0));
    CHECK_INT(r.flows_bad, 6);
    xdet_free(d);
}

TEST(detect_link)
{
    rec r;
    xdet *d = det(&r);
    fl f = {44000, 443, 50, 0, 0};
    uint8_t b[256];
    for (int i = 0; i < 5; i++, f.srv++, f.cport++)
        if (i < 2) {
            feed(d, b, mk(b, &f, 0, S, CISN, 0, NULL, 0));
            feed(d, b, mk(b, &f, 0, S, CISN, 0, NULL, 0));
        } else {
            ok_flow(d, &f);
        }
    xdet_tick(d, g_now, NULL, NULL);
    CHECK_INT(r.links, 1);
    CHECK_INT(r.link_deg, 1);
    CHECK_INT(r.link_bad, 2);
    CHECK_INT(r.link_active, 5);
    xdet_tick(d, g_now + 500, NULL, NULL);
    CHECK_INT(r.links, 1);
    g_now += 31000;
    xdet_tick(d, g_now, NULL, NULL);
    CHECK_INT(r.links, 2);
    CHECK_INT(r.link_deg, 0);
    /* one bad address of five is no degradation */
    f.srv = 60;
    for (int i = 0; i < 5; i++, f.srv++, f.cport++)
        if (!i) {
            feed(d, b, mk(b, &f, 0, S, CISN, 0, NULL, 0));
            feed(d, b, mk(b, &f, 0, S, CISN, 0, NULL, 0));
        } else {
            ok_flow(d, &f);
        }
    g_now += 1000;
    xdet_tick(d, g_now, NULL, NULL);
    CHECK_INT(r.links, 2);
    xdet_free(d);
}

/* ---- ctnetlink ---- */

static void h16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void h32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

static size_t nla(uint8_t *p, uint16_t type, const void *d, size_t n)
{
    h16(p, (uint16_t)(4 + n));
    h16(p + 2, type);
    memcpy(p + 4, d, n);
    memset(p + 4 + n, 0, ((4 + n + 3) & ~3u) - (4 + n));
    return (4 + n + 3) & ~3u;
}

static int g_nent;
static ctnl_entry g_ent;
static void on_ent(const ctnl_entry *e, void *ctx)
{
    (void)ctx;
    g_nent++;
    g_ent = *e;
}

static const ctnl_tuple *lookup7(uint32_t seq, void *ctx)
{
    return seq == 7 ? ctx : NULL;
}

TEST(ctnl_messages)
{
    ctnl_tuple t;
    uint8_t m[512], in[64];
    size_t n, k;
    memset(&t, 0, sizeof(t));
    t.ver = 4, t.proto = 6;
    t.src[0] = 192, t.src[1] = 168, t.src[3] = 2;
    t.dst[0] = 10, t.dst[1] = 9, t.dst[3] = 7;
    t.sport = 40001, t.dport = 443;
    CHECK_INT(ctnl_build_get(m, 16, &t, 1), 0);
    n = ctnl_build_get(m, sizeof(m), &t, 5);
    CHECK_INT(n, 16 + 4 + 4 + 4 + 8 + 8 + 4 + 8 + 8 + 8);
    {
        uint16_t ty;
        memcpy(&ty, m + 4, 2); /* netlink's header is in host order */
        CHECK_INT(ty, 0x101);  /* IPCTNL_MSG_CT_GET */
    }
    CHECK_INT(m[16], 2);
    /* the kernel's answer: the same tuple, with counters and the TCP state */
    h16(m + 4, 0x100); /* IPCTNL_MSG_CT_NEW */
    {
        uint8_t ctrs[64], pk[8] = {0, 0, 0, 0, 0, 0, 0, 99}, by[8] = {0, 0, 0, 0, 0, 1, 0xe2, 0x40};
        uint8_t st = 3, tcp[16], pi[32];
        size_t c = 0;
        c += nla(ctrs + c, 1, pk, 8);
        c += nla(ctrs + c, 2, by, 8);
        n += nla(m + n, 10 | 0x8000, ctrs, c);
        k = nla(tcp, 1, &st, 1);
        k = nla(pi, 1 | 0x8000, tcp, k);
        n += nla(m + n, 4 | 0x8000, pi, k);
        h32(m, (uint32_t)n);
    }
    g_nent = 0;
    CHECK_INT(ctnl_parse(m, n, NULL, on_ent, NULL), 1);
    CHECK_INT(g_nent, 1);
    CHECK_INT(g_ent.found, 1);
    CHECK_INT(g_ent.t.sport, 40001);
    CHECK_INT(g_ent.t.dport, 443);
    CHECK_INT(g_ent.t.proto, 6);
    CHECK_MEM(g_ent.t.src, 4, t.src, 4);
    CHECK_MEM(g_ent.t.dst, 4, t.dst, 4);
    CHECK_INT(g_ent.tcp_state, CTNL_TCP_ESTABLISHED);
    CHECK_INT(g_ent.rbytes, 123456);
    CHECK_INT(g_ent.rpackets, 99);
    /* two in one datagram, the second cut short */
    memcpy(m + n, m, n);
    CHECK_INT(ctnl_parse(m, 2 * n - 1, NULL, on_ent, NULL), 1);
    /* an error answer (ENOENT) to request 7: the flow is gone */
    memset(in, 0, sizeof(in));
    h32(in, 36);
    h16(in + 4, 2);
    h32(in + 8, 7);
    h32(in + 16, (uint32_t)-2);
    g_nent = 0;
    CHECK_INT(ctnl_parse(in, 36, lookup7, on_ent, &t), 1);
    CHECK_INT(g_ent.found, 0);
    CHECK_INT(g_ent.t.sport, 40001);
    h32(in + 8, 8);
    CHECK_INT(ctnl_parse(in, 36, lookup7, on_ent, &t), 0);
    /* an acknowledgement (error 0) is no answer */
    h32(in + 8, 7);
    h32(in + 16, 0);
    CHECK_INT(ctnl_parse(in, 36, lookup7, on_ent, &t), 0);
    CHECK_INT(ctnl_parse(in, 10, lookup7, on_ent, &t), 0);
}

TEST(detect_names)
{
    CHECK_STR(xdet_class_name(XC_RST_INJECT), "RST_INJECT");
    CHECK_STR(xdet_class_name(XC_FREEZE), "FREEZE_N");
    CHECK_STR(xdet_class_name(XC_N), "?");
    CHECK_STR(xdet_level_name(XK_HOST), "host");
}

/* ---- NFLOG ---- */

static void nl_attr(sbuf *s, uint16_t type, const void *d, size_t n)
{
    uint16_t len = (uint16_t)(4 + n);
    static const uint8_t pad[4];
    sb_append(s, &len, 2);
    sb_append(s, &type, 2);
    sb_append(s, d, n);
    sb_append(s, pad, ((n + 3) & ~(size_t)3) - n);
}

static void nl_msg(sbuf *s, uint16_t type, const sbuf *attrs)
{
    uint32_t len = (uint32_t)(16 + 4 + attrs->len);
    uint16_t flags = 0;
    uint32_t z = 0;
    static const uint8_t nfgen[4] = {2, 0, 0, 0};
    sb_append(s, &len, 4);
    sb_append(s, &type, 2);
    sb_append(s, &flags, 2);
    sb_append(s, &z, 4);
    sb_append(s, &z, 4);
    sb_append(s, nfgen, 4);
    sb_append(s, attrs->data, attrs->len);
}

typedef struct {
    int n;
    nflog_msg m[4];
    char prefix[4][32];
} nlrec;

static void on_nl(const nflog_msg *m, void *ctx)
{
    nlrec *r = ctx;
    if (r->n < 4) {
        r->m[r->n] = *m;
        snprintf(r->prefix[r->n], 32, "%s", m->prefix);
        r->n++;
    }
}

TEST(nflog_parse_msgs)
{
    sbuf a, s;
    nlrec r;
    static const uint8_t hdr[4] = {0x08, 0x00, 4, 0}, mark[4] = {0x20, 0, 0, 1}, dev[4] = {0, 0, 0, 3};
    static const uint8_t pkt[5] = {0x45, 1, 2, 3, 4};
    sb_init(&a);
    sb_init(&s);
    memset(&r, 0, sizeof(r));
    nl_attr(&a, 1, hdr, 4);
    nl_attr(&a, 2, mark, 4);
    nl_attr(&a, 5, dev, 4);
    nl_attr(&a, 10, "obs", 4);
    nl_attr(&a, 9, pkt, 5);
    nl_msg(&s, 4 << 8, &a);
    /* a message of another type in between, then a packet without payload */
    nl_msg(&s, 3, &a);
    sb_reset(&a);
    nl_attr(&a, 1, hdr, 4);
    nl_msg(&s, 4 << 8, &a);
    CHECK_INT(nflog_parse((const uint8_t *)s.data, s.len, on_nl, &r), 1);
    CHECK_INT(r.n, 1);
    CHECK_INT(r.m[0].hook, 4);
    CHECK_INT((long long)r.m[0].mark, 0x20000001);
    CHECK_INT((long long)r.m[0].outdev, 3);
    CHECK_INT((long long)r.m[0].len, 5);
    CHECK_STR(r.prefix[0], "obs");
    /* cut short: nothing past the cut, no overread */
    memset(&r, 0, sizeof(r));
    CHECK_INT(nflog_parse((const uint8_t *)s.data, 30, on_nl, &r), 0);
    for (size_t n = 0; n < s.len; n++)
        nflog_parse((const uint8_t *)s.data, n, on_nl, &r);
    sb_free(&a);
    sb_free(&s);
}

/* ---- rules and options ---- */

static int count(const char *hay, const char *needle)
{
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p++)
        n++;
    return n;
}

TEST(detect_fw)
{
    fw_config c;
    sbuf s;
    sb_init(&s);
    fw_config_default(&c);
    ports_parse("443", &c.ports);
    c.obs = 1;
    c.obs_group = 77;
    c.obs_first = 16;
    fw_script(&c, FW_NFT, 1, &s);
    CHECK(strstr(s.data, "\tchain obs_out {\n\t\ttype filter hook postrouting priority 99; policy accept;\n\t\tmeta "
                         "mark & 0x20000000 == 0x20000000 return\n\t\toifname \"lo\" return\n\t\tmeta l4proto { tcp, "
                         "udp } ct direction original ct original packets 1-16 log group 77\n\t}\n") != NULL);
    CHECK(strstr(s.data, "\tchain obs_in {\n\t\ttype filter hook prerouting priority -99; policy accept;\n\t\tiifname "
                         "\"lo\" return\n\t\tmeta l4proto { tcp, udp } ct direction reply ct reply packets 1-16 log "
                         "group 77\n\t\ticmp type destination-unreachable log group 77\n\t\ticmpv6 type "
                         "destination-unreachable log group 77\n\t}\n") != NULL);
    /* the queue's chains stay as they were */
    CHECK_INT(count(s.data, "queue num 310"), 2);
    sb_reset(&s);
    c.iface = "eth0";
    c.ipv6 = 0;
    c.prenat = 1;
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT(count(s.data, "hook postrouting priority -151;"), 1);
    CHECK_INT(count(s.data, "meta nfproto ipv4 oifname \"eth0\" meta l4proto { tcp, udp } ct direction original"), 1);
    CHECK_INT(count(s.data, "icmpv6"), 0);
    sb_reset(&s);
    c.ipv6 = 1;
    c.prenat = 0;
    fw_script(&c, FW_IPTABLES, 1, &s);
    CHECK_INT(count(s.data, "iptables -t mangle -A GENEVA_310_OBO -o eth0 -p udp -m conntrack --ctdir ORIGINAL -m "
                            "connbytes --connbytes 1:16 --connbytes-dir original --connbytes-mode packets -j NFLOG "
                            "--nflog-group 77\n"),
              1);
    CHECK_INT(count(s.data, "ip6tables -t mangle -A GENEVA_310_OBI -i eth0 -p ipv6-icmp -m icmp6 --icmpv6-type "
                            "destination-unreachable -j NFLOG --nflog-group 77\n"),
              1);
    CHECK_INT(count(s.data, "-A GENEVA_310_OBI -m mark"), 0);
    /* out first in POSTROUTING: inserted after the queue's chain; in from
     * INPUT and FORWARD */
    CHECK(strstr(s.data, "-I POSTROUTING -j GENEVA_310_OUT") < strstr(s.data, "-I POSTROUTING -j GENEVA_310_OBO"));
    CHECK_INT(count(s.data, "-t mangle -I INPUT -j GENEVA_310_OBI\n"), 2);
    CHECK_INT(count(s.data, "-t mangle -I FORWARD -j GENEVA_310_OBI\n"), 2);
    CHECK_INT(count(s.data, "-I PREROUTING -j GENEVA_310_OBI"), 0);
    /* down removes them */
    sb_reset(&s);
    fw_script(&c, FW_IPTABLES, 0, &s);
    CHECK_INT(count(s.data, "-D POSTROUTING -j GENEVA_310_OBO"), 2);
    CHECK_INT(count(s.data, "-D INPUT -j GENEVA_310_OBI"), 2);
    CHECK_INT(count(s.data, "-D FORWARD -j GENEVA_310_OBI"), 2);
    CHECK_INT(count(s.data, "-X GENEVA_310_OBI"), 4);
    sb_free(&s);
}

static const optdef g_defs[] = {
    EXT_AUTO_OPTS,
    {NULL, 0, 0, NULL, NULL},
};

static int auto_parse(fw_config *c, sbuf *err, const char *w0, const char *w1, const char *w2, const char *w3)
{
    const char *words[] = {"x", w0, w1, w2, w3};
    char *argv[6], e[128];
    int argc = 1, r;
    args_t a;
    argv[0] = (char *)words[0];
    for (int i = 1; i < 5 && words[i]; i++)
        argv[argc++] = (char *)words[i];
    argv[argc] = NULL;
    sb_reset(err);
    fw_config_default(c);
    if (args_parse(&a, argc, argv, g_defs, e, sizeof(e)) < 0) {
        sb_puts(err, e);
        return -1;
    }
    r = xauto_parse(&a, c, err);
    args_free(&a);
    return r;
}

TEST(detect_options)
{
    fw_config c;
    sbuf e;
    sb_init(&e);
    CHECK_INT(auto_parse(&c, &e, NULL, NULL, NULL, NULL), 0);
    CHECK_INT(c.obs, 0);
    CHECK_INT(xauto_on(), 0);
    if (!FW_WINDOWS) {
        CHECK_INT(auto_parse(&c, &e, "--ext-auto", "observe", NULL, NULL), 0);
        CHECK_INT(c.obs, 1);
        CHECK_INT(c.obs_group, 310);
        CHECK_INT(c.obs_first, XAUTO_FIRST);
        CHECK_INT(xauto_on(), 1);
        CHECK_INT(auto_parse(&c, &e, "--ext-auto", "observe", "--ext-nflog-group", "5"), 0);
        CHECK_INT(c.obs_group, 5);
        CHECK_INT(auto_parse(&c, &e, "--ext-auto", "observe", "--ext-observe-first", "3"), -1);
    }
    if (FW_WINDOWS) {
        /* the SNIFF handle: no rules */
        CHECK_INT(auto_parse(&c, &e, "--ext-auto", "observe", NULL, NULL), 0);
        CHECK_INT(c.obs, 0);
        CHECK_INT(xauto_on(), 1);
        CHECK_INT(auto_parse(&c, &e, "--ext-auto", "observe", "--ext-nflog-group", "5"), -1);
        CHECK_STR(e.data, "--ext-nflog-group: Windows observes through WinDivert");
    }
    CHECK_INT(auto_parse(&c, &e, "--ext-auto", "apply", NULL, NULL), -1);
    CHECK_STR(e.data, "--ext-auto apply is not there yet: observe");
    CHECK_INT(auto_parse(&c, &e, "--ext-auto", "watch", NULL, NULL), -1);
    CHECK_INT(auto_parse(&c, &e, "--ext-nflog-group", "5", NULL, NULL), -1);
    CHECK_STR(e.data, "--ext-nflog-group is for --ext-auto");
    xauto_reset();
    sb_free(&e);
}

/* the observer without NFLOG: packets in, status out */
TEST(detect_auto_feed)
{
    fw_config c;
    sbuf e, s;
    jw w;
    uint8_t b[256];
    fl f = {40500, 443, 11, 0, 0};
    sb_init(&e);
    sb_init(&s);
    CHECK_INT(auto_parse(&c, &e, "--ext-auto", "observe", NULL, NULL), 0);
    for (int i = 0; i < 2; i++) {
        xauto_feed(b, mk(b, &f, 0, S, CISN, 0, NULL, 0), 1000);
        xauto_feed(b, mk(b, &f, 0, S, CISN, 0, NULL, 0), 2000);
        f.cport++;
    }
    xauto_feed((const uint8_t *)"junk", 4, 3000);
    jw_init(&w, &s);
    jw_obj(&w);
    xauto_status(&w);
    jw_obj_end(&w);
    CHECK(strstr(s.data, FW_WINDOWS ? "\"auto\":\"observe\",\"source\":\"windivert\",\"observing\":false,"
                                      : "\"auto\":\"observe\",\"source\":\"nflog\",\"nflog_group\":310,\"observing\":false,") !=
          NULL);
    CHECK(strstr(s.data, FW_WINDOWS ? "\"counters\":true," : "\"counters\":false,") != NULL);
    CHECK(strstr(s.data, "\"observing\":false,\"packets\":4,\"lost\":0,\"flows\":2,\"flows_ok\":0,\"flows_failed\":2,"
                         "\"keys\":3,") != NULL);
    CHECK(strstr(s.data, "\"watched\":0,\"capacity\":0,\"link_degraded\":false,\"impaired\":[{\"key\":\"tcp/443\"") !=
          NULL);
    CHECK(strstr(s.data, "\"class\":\"BLACKHOLE_SYN\"") != NULL);
    xauto_reset();
    sb_free(&e);
    sb_free(&s);
}

/* every packet, with its direction (WinDivert): only the PC's own flows */
TEST(detect_packet_dir)
{
    rec r;
    xdet *d = det_self(&r, 1);
    fl f = {45000, 8080, 60, 0, 0}, u = {45100, 5000, 61, 0, 1};
    uint8_t b[256];
    gpkt *p;
    xdet_stats st;
#  define DIR(out, n)                       \
    do {                                    \
        p = pkt_parse(b, n);                \
        CHECK(p != NULL);                   \
        if (p) {                            \
            xdet_packet_dir(d, p, g_now, out); \
            pkt_free(p);                    \
        }                                   \
        g_now += 10;                        \
    } while (0)
    /* a peer connects to a server of the PC: its SYN comes in, the
     * SYN,ACK goes out; and a datagram comes in: no flows */
    for (int i = 0; i < 3; i++) {
        DIR(0, mk(b, &f, 0, S, CISN, 0, NULL, 0));
        DIR(1, mk(b, &f, 1, S | A, SISN, CISN + 1, NULL, 0));
        DIR(0, mk(b, &u, 0, 0, 0, 0, "q", 1));
    }
    xdet_get_stats(d, &st);
    CHECK_INT((int)st.flows, 0);
    CHECK_INT((int)st.packets, 9);
    /* the PC's own flow: its SYN goes out, the answer comes in */
    f.cport++;
    DIR(1, mk(b, &f, 0, S, CISN, 0, NULL, 0));
    DIR(0, mk(b, &f, 1, S | A, SISN, CISN + 1, NULL, 0));
    DIR(1, mk(b, &u, 0, 0, 0, 0, "q", 1));
    DIR(0, mk(b, &u, 1, 0, 0, 0, "a", 1));
    DIR(0, mk(b, &u, 1, 0, 0, 0, "a", 1));
    xdet_get_stats(d, &st);
    CHECK_INT((int)st.flows, 2);
    CHECK_INT((int)st.watched, 1);
    CHECK_INT(r.flows_ok, 1);
    {
        /* ICMP prohibited about the PC's own flow: out, nothing; in, its
         * failure */
        uint8_t ic[128];
        size_t n = mk(b, &f, 0, A, CISN + 1, SISN + 1, NULL, 0);
        memset(ic, 0, 28);
        ic[0] = 0x45, ic[8] = 64, ic[9] = 1;
        put16(ic + 2, (unsigned)(28 + n));
        ic[12] = 10, ic[13] = 9, ic[14] = 60, ic[15] = 1; /* a router */
        ic[16] = 10, ic[19] = 1;
        ic[20] = 3, ic[21] = 13;
        memcpy(ic + 28, b, n);
        memcpy(b, ic, 28 + n);
        DIR(1, 28 + n);
        CHECK_INT(r.flows_bad, 0);
        DIR(0, 28 + n);
        CHECK_INT(r.flows_bad, 1);
        CHECK_INT(r.last_cls, XC_ICMP_PROHIBIT);
    }
#  undef DIR
    xdet_free(d);
}

void suite_detect(void)
{
    RUN(detect_retrans);
    RUN(detect_success_edges);
    RUN(detect_rst);
    RUN(detect_redirect);
    RUN(detect_udp_syn_icmp);
    RUN(detect_cache_multicast);
    RUN(detect_freeze);
    RUN(detect_throttle);
    RUN(detect_throttle_parallel);
    RUN(detect_self_count);
    RUN(detect_packet_dir);
    RUN(detect_dns);
    RUN(detect_link);
    RUN(ctnl_messages);
    RUN(detect_names);
    RUN(nflog_parse_msgs);
    RUN(detect_fw);
    RUN(detect_options);
    RUN(detect_auto_feed);
    xipc_reset();
}

#else
void suite_detect(void) {}
#endif
