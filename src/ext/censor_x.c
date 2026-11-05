/*
 * Lab censors 12-20. Each one models a DPI behaviour the extensions answer
 * (docs/EXT_ROADMAP.md, 7.3):
 *
 *   12 freeze     forbidden word in the first client payload: the server's
 *                 data stops after freeze_bytes (dropped, the connection stays)
 *   13 policer    the same flows: data to the client through a token bucket
 *   14 rst        SNI of a ClientHello in the first client segment, no
 *                 reassembly: RSTs to the client with TTL rst_ttl, packet passes
 *   15 reasm      the ClientHello reassembled from up to 2 in-order segments:
 *                 the matching segment and the rest from the client dropped
 *   16 quic       SNI of the first QUIC Initial of a UDP flow (decrypted):
 *                 that datagram and the rest from the client dropped
 *   17 ipblock    every packet to or from block_ip dropped
 *   18 redirect   HTTP request with "Host: " holding the word: dropped, a
 *                 302 to the client, RST to the server
 *   19 strict     like censor 1 (sequence-synchronized, drops the client
 *                 after the word) but ignores packets with TTL < min_ttl, a
 *                 bad TCP checksum or a TSval older than the last (PAWS)
 *   20 firstfrag  reads only unfragmented packets and first IP fragments
 *                 (IPv6 extension headers followed); drops on the word
 *
 * The client of a TCP connection is the side of the SYN; connections whose
 * SYN the censor did not see are not inspected. For UDP the client is the
 * side of the first datagram. Matching of names and HTTP headers is naive on
 * purpose, as in the DPI they model: case-sensitive "Host: " at the start of
 * a line, a request must start with the method, the word is compared
 * byte for byte in HTTP and without case in SNI.
 */
#include "censor_x.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ext.h"
#include "plat.h"
#include "quic.h"
#include "tls.h"
#include "util.h"

enum { X12 = 12, X13, X14, X15, X16, X17, X18, X19, X20 };

const censor_info cx_models[] = {
    {"12", "freeze: the server's data stops after N bytes for flows with the word in the first request", 0},
    {"13", "policer: a token bucket on the server's data for flows with the word in the first request", 0},
    {"14", "SNI in the first segment, no reassembly: RSTs to the client with TTL 64", 0},
    {"15", "SNI reassembled from up to 2 in-order segments: drops the client", 0},
#if GENEVA_EXT_CRYPTO
    {"16", "SNI of the first QUIC Initial (decrypted): drops the client's datagrams", 1},
#else
    {"16", "SNI of the first QUIC Initial: not in this build (EXT_CRYPTO=0)", 1},
#endif
    {"17", "IP block: drops everything to and from --block-ip", 0},
    {"18", "HTTP Host with the word: a 302 to a block page, RST to the server", 0},
    {"19", "sequence-synchronized, ignores low TTL, bad checksums and old timestamps: drops", 0},
    {"20", "reads only first IP fragments: drops on the word", 0},
    {NULL, NULL, 0},
};

/* ---- packets ------------------------------------------------------------- */

typedef struct {
    int ver, alen, ttl;
    const uint8_t *src, *dst;
    int frag_later; /* a fragment other than the first: no transport header */
    int proto;      /* 6, 17 or 0 */
    const uint8_t *l4;
    size_t l4len;
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint8_t flags;
    int has_ts;
    uint32_t tsval;
    const uint8_t *pl;
    size_t plen;
} xv;

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8), p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) { wr16(p, (uint16_t)(v >> 16)), wr16(p + 2, (uint16_t)v); }

static uint32_t sum16(const uint8_t *p, size_t n, uint32_t s)
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

static uint32_t pseudo(int alen, const uint8_t *src, const uint8_t *dst, uint8_t proto, size_t len)
{
    return sum16(dst, (size_t)alen, sum16(src, (size_t)alen, 0)) + proto + (uint32_t)(len >> 16) +
           (uint32_t)(len & 0xffff);
}

enum { F_FIN = 1, F_SYN = 2, F_RST = 4, F_PSH = 8, F_ACK = 16 };

static void tcp_options(xv *v, size_t thl)
{
    size_t off = 20;
    while (off < thl) {
        uint8_t k = v->l4[off];
        if (k == 0)
            break;
        if (k == 1) {
            off++;
            continue;
        }
        if (off + 1 >= thl || v->l4[off + 1] < 2 || off + v->l4[off + 1] > thl)
            break;
        if (k == 8 && v->l4[off + 1] == 10) {
            v->has_ts = 1;
            v->tsval = rd32(v->l4 + off + 2);
        }
        off += v->l4[off + 1];
    }
}

static int xparse(const uint8_t *p, size_t len, xv *v)
{
    size_t hl, tot;
    int nh;
    memset(v, 0, sizeof(*v));
    if (len < 1)
        return -1;
    v->ver = p[0] >> 4;
    if (v->ver == 4) {
        if (len < 20 || (p[0] & 15) < 5 || (size_t)(p[0] & 15) * 4 > len)
            return -1;
        hl = (size_t)(p[0] & 15) * 4;
        tot = rd16(p + 2);
        if (tot < hl || tot > len)
            tot = len;
        v->alen = 4;
        v->ttl = p[8];
        v->src = p + 12;
        v->dst = p + 16;
        nh = p[9];
        if (rd16(p + 6) & 0x1fff)
            v->frag_later = 1;
    } else if (v->ver == 6) {
        if (len < 40)
            return -1;
        tot = 40 + (size_t)rd16(p + 4);
        if (tot > len)
            tot = len;
        v->alen = 16;
        v->ttl = p[7];
        v->src = p + 8;
        v->dst = p + 24;
        nh = p[6];
        hl = 40;
        /* extension headers: hop-by-hop, routing, fragment, destination, AH */
        for (int guard = 0; guard < 8; guard++) {
            if (nh == 0 || nh == 43 || nh == 60) {
                if (hl + 8 > tot)
                    return 0;
                nh = p[hl];
                hl += 8 + (size_t)p[hl + 1] * 8;
            } else if (nh == 44) {
                if (hl + 8 > tot)
                    return 0;
                if (rd16(p + hl + 2) & 0xfff8)
                    v->frag_later = 1;
                nh = p[hl];
                hl += 8;
            } else if (nh == 51) {
                if (hl + 8 > tot)
                    return 0;
                nh = p[hl];
                hl += ((size_t)p[hl + 1] + 2) * 4;
            } else {
                break;
            }
        }
        if (hl > tot)
            return 0;
    } else {
        return -1;
    }
    if (v->frag_later)
        return 0;
    v->l4 = p + hl;
    v->l4len = tot - hl;
    if (nh == 6 && v->l4len >= 20) {
        size_t thl = (size_t)(v->l4[12] >> 4) * 4;
        if (thl < 20 || thl > v->l4len)
            thl = thl < 20 ? 20 : v->l4len;
        v->proto = 6;
        v->sport = rd16(v->l4);
        v->dport = rd16(v->l4 + 2);
        v->seq = rd32(v->l4 + 4);
        v->ack = rd32(v->l4 + 8);
        v->flags = v->l4[13];
        tcp_options(v, thl);
        v->pl = v->l4 + thl;
        v->plen = v->l4len - thl;
    } else if (nh == 17 && v->l4len >= 8) {
        v->proto = 17;
        v->sport = rd16(v->l4);
        v->dport = rd16(v->l4 + 2);
        v->pl = v->l4 + 8;
        v->plen = v->l4len - 8;
    }
    return 0;
}

static int tcp_csum_ok(const xv *v)
{
    uint32_t s = pseudo(v->alen, v->src, v->dst, 6, v->l4len);
    return fold(sum16(v->l4, v->l4len, s)) == 0;
}

/* ---- injected packets ---------------------------------------------------- */

static size_t build_tcp(uint8_t *o, size_t cap, int ver, const uint8_t *src, const uint8_t *dst, uint16_t sport,
                        uint16_t dport, uint32_t seq, uint32_t ack, uint8_t flags, int ttl, const char *data,
                        size_t dlen)
{
    int alen = ver == 4 ? 4 : 16;
    size_t hl = ver == 4 ? 20 : 40, l4 = 20 + dlen;
    uint8_t *t;
    if (hl + l4 > cap)
        return 0;
    memset(o, 0, hl + 20);
    if (ver == 4) {
        o[0] = 0x45;
        wr16(o + 2, (uint16_t)(hl + l4));
        wr16(o + 4, 0x2c1d); /* a fixed IP ID, unlike the server's */
        o[8] = (uint8_t)ttl;
        o[9] = 6;
        memcpy(o + 12, src, 4);
        memcpy(o + 16, dst, 4);
        wr16(o + 10, fold(sum16(o, 20, 0)));
    } else {
        o[0] = 0x60;
        wr16(o + 4, (uint16_t)l4);
        o[6] = 6;
        o[7] = (uint8_t)ttl;
        memcpy(o + 8, src, 16);
        memcpy(o + 24, dst, 16);
    }
    t = o + hl;
    wr16(t, sport);
    wr16(t + 2, dport);
    wr32(t + 4, seq);
    wr32(t + 8, ack);
    t[12] = 5 << 4;
    t[13] = flags;
    wr16(t + 14, 8192);
    if (dlen)
        memcpy(t + 20, data, dlen);
    wr16(t + 16, fold(sum16(t, l4, pseudo(alen, src, dst, 6, l4))));
    return hl + l4;
}

/* ---- connections --------------------------------------------------------- */

enum { XS_NEW = 0, XS_OK, XS_BLOCKED };

typedef struct {
    int used;
    uint8_t ver, proto;
    uint8_t cli[16], srv[16];
    uint16_t cport, sport;
    int state;
    int syn_seen;
    uint32_t cnext;     /* 15, 19: next client sequence number */
    uint8_t *buf;       /* 15: the first segment, kept until the second */
    size_t nbuf;
    uint64_t to_client; /* 12: payload bytes to the client */
    double tokens;      /* 13 */
    uint64_t t_fill;
    int has_ts;         /* 19: the client's last TSval */
    uint32_t ts;
    uint64_t used_at;
} xflow;

struct cx {
    int m;
    const censor_cfg *cfg;
    xflow *f;
    size_t nf;
    uint64_t tick;
    uint32_t ip_fired; /* 17: the block_ip entries already reported */
    uint8_t scratch[16384]; /* the TLS records of a ClientHello, joined */
};

cx *cx_new(const char *name, const censor_cfg *cfg)
{
    cx *x;
    int m = -1;
    if (!strncmp(name, "censor", 6))
        name += 6;
    for (int i = 0; cx_models[i].name; i++)
        if (!strcmp(name, cx_models[i].name))
            m = X12 + i;
    if (m < 0 || (m == X16 && !GENEVA_EXT_CRYPTO))
        return NULL;
    x = xcalloc(1, sizeof(*x));
    x->m = m;
    x->cfg = cfg;
    x->nf = cfg->max_tcbs > 0 ? (size_t)cfg->max_tcbs : 4096;
    x->f = xcalloc(x->nf, sizeof(*x->f));
    return x;
}

void cx_reset(cx *x)
{
    for (size_t i = 0; i < x->nf; i++)
        free(x->f[i].buf);
    memset(x->f, 0, x->nf * sizeof(*x->f));
    x->ip_fired = 0;
}

void cx_free(cx *x)
{
    if (!x)
        return;
    cx_reset(x);
    free(x->f);
    free(x);
}

static uint64_t now(const cx *x)
{
    return x->cfg->now_ms ? x->cfg->now_ms() : plat_now_ms();
}

/* The connection of v and whether v comes from its client (*from_cli). */
static xflow *find(cx *x, const xv *v, int *from_cli)
{
    for (size_t i = 0; i < x->nf; i++) {
        xflow *f = &x->f[i];
        if (!f->used || f->ver != v->ver || f->proto != v->proto)
            continue;
        if (f->cport == v->sport && f->sport == v->dport && !memcmp(f->cli, v->src, (size_t)v->alen) &&
            !memcmp(f->srv, v->dst, (size_t)v->alen)) {
            *from_cli = 1;
            f->used_at = ++x->tick;
            return f;
        }
        if (f->cport == v->dport && f->sport == v->sport && !memcmp(f->cli, v->dst, (size_t)v->alen) &&
            !memcmp(f->srv, v->src, (size_t)v->alen)) {
            *from_cli = 0;
            f->used_at = ++x->tick;
            return f;
        }
    }
    return NULL;
}

/* f becomes a new connection with v's sender as the client */
static void flow_init(cx *x, xflow *f, const xv *v)
{
    free(f->buf);
    memset(f, 0, sizeof(*f));
    f->used = 1;
    f->ver = (uint8_t)v->ver;
    f->proto = (uint8_t)v->proto;
    memcpy(f->cli, v->src, (size_t)v->alen);
    memcpy(f->srv, v->dst, (size_t)v->alen);
    f->cport = v->sport;
    f->sport = v->dport;
    f->used_at = ++x->tick;
}

/* A new connection; the least recently used one makes room in a full table. */
static xflow *add(cx *x, const xv *v)
{
    xflow *f = NULL;
    for (size_t i = 0; i < x->nf && !f; i++)
        if (!x->f[i].used)
            f = &x->f[i];
    if (!f) {
        f = &x->f[0];
        for (size_t i = 1; i < x->nf; i++)
            if (x->f[i].used_at < f->used_at)
                f = &x->f[i];
    }
    flow_init(x, f, v);
    return f;
}

static int lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

/* the word anywhere in p, byte for byte (nocase: ASCII letters fold) */
static int has_word(const censor_cfg *cfg, const uint8_t *p, size_t n, int nocase)
{
    for (int w = 0; w < cfg->nwords; w++) {
        const char *word = cfg->words[w];
        size_t wl = strlen(word);
        for (size_t i = 0; wl && i + wl <= n; i++) {
            size_t k = 0;
            while (k < wl && (nocase ? lower(p[i + k]) == lower((uint8_t)word[k]) : p[i + k] == (uint8_t)word[k]))
                k++;
            if (k == wl)
                return 1;
        }
    }
    return 0;
}

static int sni_has_word(const censor_cfg *cfg, const char *sni)
{
    return has_word(cfg, (const uint8_t *)sni, strlen(sni), 1);
}

/* The value of the "Host: " header of an HTTP request, case-sensitive and
 * only when the request starts with its method. */
static int http_host(const uint8_t *p, size_t n, const uint8_t **host, size_t *hlen)
{
    static const char *const methods[] = {"GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "DELETE ", "CONNECT "};
    int is_req = 0;
    for (size_t i = 0; i < ARRAY_LEN(methods) && !is_req; i++)
        is_req = n >= strlen(methods[i]) && !memcmp(p, methods[i], strlen(methods[i]));
    if (!is_req)
        return 0;
    for (size_t i = 0; i + 8 <= n; i++)
        if (!memcmp(p + i, "\r\nHost: ", 8)) {
            size_t s = i + 8, e = s;
            while (e < n && p[e] != '\r' && p[e] != '\n')
                e++;
            *host = p + s;
            *hlen = e - s;
            return 1;
        }
    return 0;
}

typedef struct {
    censor_send_fn fn;
    void *ctx;
    int n;
} xsend;

static void emit(xsend *s, const uint8_t *p, size_t n)
{
    if (n && s->fn)
        s->fn(p, n, s->ctx);
    if (n)
        s->n++;
}

static void fired(censor_result *r, const char *act, int accept)
{
    r->what = CENSOR_FIRED;
    r->action = act;
    r->accept = accept;
}

static void blocked(censor_result *r)
{
    r->what = CENSOR_BLOCKED;
    r->action = "drop";
    r->accept = 0;
}

/* ---- the models ---------------------------------------------------------- */

/* 12, 13: the decision on the first client payload, then the server's data */
static void shape(cx *x, xflow *f, const xv *v, int from_cli, censor_result *r)
{
    if (from_cli) {
        if (f->state == XS_NEW && v->plen) {
            f->state = has_word(x->cfg, v->pl, v->plen, 0) ? XS_BLOCKED : XS_OK;
            if (f->state == XS_BLOCKED) {
                r->what = CENSOR_FIRED;
                r->action = x->m == X12 ? "freeze" : "police";
                f->tokens = (double)x->cfg->burst;
                f->t_fill = now(x);
            }
        }
        return;
    }
    if (f->state != XS_BLOCKED || !v->plen)
        return;
    if (x->m == X12) {
        if (f->to_client + v->plen > x->cfg->freeze_bytes) {
            blocked(r);
            return;
        }
        f->to_client += v->plen;
        return;
    }
    {
        uint64_t t = now(x);
        f->tokens += (double)(t - f->t_fill) * (double)x->cfg->rate / 1000.0;
        if (f->tokens > (double)x->cfg->burst)
            f->tokens = (double)x->cfg->burst;
        f->t_fill = t;
        if (f->tokens < (double)v->plen) {
            blocked(r);
            return;
        }
        f->tokens -= (double)v->plen;
    }
}

static void rst14(cx *x, xflow *f, const xv *v, xsend *s, censor_result *r)
{
    char sni[256];
    uint8_t b[64];
    if (f->state != XS_NEW || !v->plen)
        return;
    f->state = XS_OK;
    if (tls_rec_sni(v->pl, v->plen, sni, sizeof(sni), x->scratch, sizeof(x->scratch)) != TLS_SNI ||
        !sni_has_word(x->cfg, sni))
        return;
    f->state = XS_BLOCKED;
    for (int i = 0; i < 3; i++)
        emit(s,
             b,
             build_tcp(b, sizeof(b), v->ver, v->dst, v->src, v->dport, v->sport, v->ack, v->seq + (uint32_t)v->plen,
                       F_RST | F_ACK, x->cfg->rst_ttl, NULL, 0));
    fired(r, "rst", 1);
}

static void reasm15(cx *x, xflow *f, const xv *v, censor_result *r)
{
    char sni[256];
    int t;
    if (f->state == XS_BLOCKED) {
        blocked(r);
        return;
    }
    if (f->state != XS_NEW || !v->plen)
        return;
    if (!f->buf) {
        t = tls_rec_sni(v->pl, v->plen, sni, sizeof(sni), x->scratch, sizeof(x->scratch));
        if (t == TLS_PARTIAL) {
            /* keep the first segment and wait for the next one in order */
            f->buf = xmalloc(v->plen);
            memcpy(f->buf, v->pl, v->plen);
            f->nbuf = v->plen;
            f->cnext = v->seq + (uint32_t)v->plen;
            return;
        }
    } else {
        uint8_t *both;
        if (v->seq != f->cnext) {
            free(f->buf);
            f->buf = NULL;
            f->state = XS_OK; /* out of order: given up */
            return;
        }
        both = xmalloc(f->nbuf + v->plen);
        memcpy(both, f->buf, f->nbuf);
        memcpy(both + f->nbuf, v->pl, v->plen);
        t = tls_rec_sni(both, f->nbuf + v->plen, sni, sizeof(sni), x->scratch, sizeof(x->scratch));
        free(both);
        free(f->buf);
        f->buf = NULL;
    }
    f->state = XS_OK;
    if (t == TLS_SNI && sni_has_word(x->cfg, sni)) {
        f->state = XS_BLOCKED;
        fired(r, "drop", 0);
    }
}

static void quic16(cx *x, xflow *f, const xv *v, censor_result *r)
{
    uint8_t frames[2048], stream[2048];
    char sni[256];
    size_t slen;
    long fl;
    quic_initial h;
    if (f->state == XS_BLOCKED) {
        blocked(r);
        return;
    }
    if (f->state != XS_NEW)
        return;
    fl = quic_initial_decrypt(v->pl, v->plen, &h, frames, sizeof(frames));
    if (fl < 0)
        return; /* not an Initial: still waiting for one */
    f->state = XS_OK;
    if (quic_crypto_stream(frames, (size_t)fl, stream, sizeof(stream), &slen) == 0 &&
        tls_hs_sni(stream, slen, sni, sizeof(sni), NULL) == TLS_SNI && sni_has_word(x->cfg, sni)) {
        f->state = XS_BLOCKED;
        fired(r, "drop", 0);
    }
}

static void redirect18(cx *x, xflow *f, const xv *v, xsend *s, censor_result *r)
{
    const uint8_t *host;
    size_t hlen;
    char resp[512];
    uint8_t b[600];
    int n;
    if (f->state == XS_BLOCKED) {
        blocked(r);
        return;
    }
    if (f->state != XS_NEW || !v->plen)
        return;
    f->state = XS_OK;
    if (!http_host(v->pl, v->plen, &host, &hlen) || !has_word(x->cfg, host, hlen, 0))
        return;
    f->state = XS_BLOCKED;
    n = snprintf(resp, sizeof(resp),
                 "HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                 x->cfg->redirect);
    if (n < 0 || (size_t)n >= sizeof(resp))
        n = 0;
    emit(s, b,
         build_tcp(b, sizeof(b), v->ver, v->dst, v->src, v->dport, v->sport, v->ack, v->seq + (uint32_t)v->plen,
                   F_PSH | F_ACK | F_FIN, 64, resp, (size_t)n));
    emit(s, b,
         build_tcp(b, sizeof(b), v->ver, v->src, v->dst, v->sport, v->dport, v->seq, v->ack, F_RST, 64, NULL, 0));
    fired(r, "redirect", 0);
}

static void strict19(cx *x, xflow *f, const xv *v, censor_result *r)
{
    if (f->state == XS_BLOCKED) {
        blocked(r);
        return;
    }
    if (v->has_ts) {
        if (f->has_ts && (int32_t)(v->tsval - f->ts) < 0)
            return; /* PAWS */
        f->has_ts = 1;
        f->ts = v->tsval;
    }
    if (v->flags == F_SYN) {
        f->cnext = v->seq + 1;
        return;
    }
    if (v->seq != f->cnext || !v->plen)
        return;
    f->cnext += (uint32_t)v->plen;
    if (has_word(x->cfg, v->pl, v->plen, 0)) {
        f->state = XS_BLOCKED;
        fired(r, "drop", 0);
    }
}

static void frag20(cx *x, xflow *f, const xv *v, censor_result *r)
{
    if (f->state == XS_BLOCKED) {
        blocked(r);
        return;
    }
    if (v->plen && has_word(x->cfg, v->pl, v->plen, 0)) {
        f->state = XS_BLOCKED;
        fired(r, "drop", 0);
    }
}

/* the index of a in block_ip, or -1 */
static int blocked_ip(const censor_cfg *cfg, int ver, const uint8_t *a)
{
    for (int i = 0; i < cfg->nblock_ip; i++)
        if (cfg->block_ip[i].ver == ver && !memcmp(cfg->block_ip[i].a, a, ver == 4 ? 4 : 16))
            return i;
    return -1;
}

void cx_packet(cx *x, const uint8_t *pkt, size_t len, censor_send_fn send, void *ctx, censor_result *r)
{
    xv v;
    xflow *f;
    int from_cli = 0;
    xsend s = {send, ctx, 0};

    memset(r, 0, sizeof(*r));
    r->accept = 1;
    if (xparse(pkt, len, &v) < 0)
        return;
    if (x->m == X17) {
        int i = blocked_ip(x->cfg, v.ver, v.dst);
        if (i < 0)
            i = blocked_ip(x->cfg, v.ver, v.src);
        if (i < 0)
            return;
        /* reported once per address, as the other models report a host once */
        if (x->ip_fired >> i & 1) {
            blocked(r);
        } else {
            x->ip_fired |= 1u << i;
            fired(r, "drop", 0);
        }
        return;
    }
    if (v.frag_later)
        return; /* no transport header: nobody here reassembles */
    /* 19: what would not reach the server or what the server would reject
     * does not move the censor, not even a SYN */
    if (x->m == X19 && v.proto == 6 && (v.ttl < x->cfg->min_ttl || !tcp_csum_ok(&v)))
        return;
    if (v.proto == 6 && x->m != X16) {
        f = find(x, &v, &from_cli);
        if (v.flags == F_SYN) {
            if (!f || !from_cli) {
                f = add(x, &v);
                from_cli = 1;
            } else {
                flow_init(x, f, &v); /* a new connection on the same 4-tuple */
            }
        }
        if (!f)
            return; /* the censor did not see its SYN */
    } else if (v.proto == 17 && x->m == X16) {
        f = find(x, &v, &from_cli);
        if (!f) {
            f = add(x, &v);
            from_cli = 1;
        }
    } else {
        return;
    }
    switch (x->m) {
    case X12:
    case X13:
        shape(x, f, &v, from_cli, r);
        break;
    case X14:
        if (from_cli)
            rst14(x, f, &v, &s, r);
        break;
    case X15:
        if (from_cli)
            reasm15(x, f, &v, r);
        break;
    case X16:
        if (from_cli)
            quic16(x, f, &v, r);
        break;
    case X18:
        if (from_cli)
            redirect18(x, f, &v, &s, r);
        break;
    case X19:
        if (from_cli)
            strict19(x, f, &v, r);
        break;
    case X20:
        if (from_cli)
            frag20(x, f, &v, r);
        break;
    }
    r->sent = s.n;
}
