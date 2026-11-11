/*
 * Ported from zapret2 nfq2/desync.c and conntrack.c (MIT License, Copyright
 * (c) bol-van; the notice is in docs/EXT.md): dpi_desync_tcp_packet_play,
 * dpi_desync_udp_packet_play, ReasmFeed, replay_queue.
 */
#include "xl7.h"

#include <stdlib.h>
#include <string.h>

#include "l7.h"
#include "quic.h"
#include "util.h"

#define REASM_MAX_NEG 0x100000u

typedef struct held held;
struct held {
    held *next;
    strat_dir dir;
    uint32_t seq; /* TCP: the packet's seq */
    ct_side cli, srv;
    size_t len, plen;
    uint8_t pctx[XL7_PCTX];
    uint8_t b[]; /* raw bytes, then the payload */
};

typedef struct {
    int tcp;
    uint32_t seq; /* TCP: the seq of the next byte */
    size_t size, present;
    held *h, **tail;
    unsigned n;
    uint8_t buf[]; /* size bytes */
} reasm;

struct xl7 {
    xl7_config c;
    uint8_t clean[XL7_REASM_MAX]; /* one decrypted Initial (nfqws2: UDP_MAX_REASM) */
    char host[XL7_HOST_MAX];
    uint8_t defrag[]; /* c.reasm_max bytes */
};

xl7 *xl7_new(const xl7_config *c)
{
    xl7_config d = {0, 0, 0};
    xl7 *x;
    if (c)
        d = *c;
    if (!d.reasm_max)
        d.reasm_max = XL7_REASM_MAX;
    x = xcalloc(1, sizeof(*x) + d.reasm_max);
    x->c = d;
    return x;
}

void xl7_free(xl7 *x) { free(x); }

static int disabled(uint64_t set, int l7p) { return set && l7_payload_match(l7p, set); }

/* ---- the reassembly (conntrack.c Reasm*) ------------------------------------ */

static reasm *rstart(const xl7 *x, ct_flow *f, int tcp, size_t size, uint32_t seq)
{
    reasm *r;
    if (size > x->c.reasm_max)
        return NULL;
    r = xcalloc(1, sizeof(*r) + size);
    r->tcp = tcp;
    r->size = size;
    r->seq = seq;
    r->tail = &r->h;
    f->xr = r;
    return r;
}

/* ReasmFeed: a gap fails, an overlap replaces what was there */
static int rfeed(reasm *r, uint32_t seq, const uint8_t *d, size_t len)
{
    uint32_t dseq = seq - r->seq, neg = r->seq - seq;
    size_t ign, cp;
    if (dseq && dseq < REASM_MAX_NEG)
        return 0;
    if (neg > REASM_MAX_NEG)
        return 0;
    ign = neg > r->present ? neg - r->present : 0;
    if (ign >= len)
        return 1;
    cp = len - ign;
    neg -= (uint32_t)ign;
    if (r->present - neg + cp > r->size)
        return 0;
    memcpy(r->buf + r->present - neg, d + ign, cp);
    if (cp > neg) {
        r->present += cp - neg;
        r->seq += (uint32_t)(cp - neg);
    }
    return 1;
}

static int rhold(reasm *r, const ct_flow *f, const gpkt *p, strat_dir dir, const uint8_t *raw, size_t rawlen,
                 const void *pctx, size_t pctx_len)
{
    held *h;
    if (r->n >= XL7_HELD_MAX || pctx_len > XL7_PCTX)
        return 0;
    h = xcalloc(1, sizeof(*h) + rawlen + p->payload_len);
    h->dir = dir;
    h->seq = f->client.seq_last;
    h->cli = f->client;
    h->srv = f->server;
    h->len = rawlen;
    h->plen = p->payload_len;
    if (pctx_len)
        memcpy(h->pctx, pctx, pctx_len);
    memcpy(h->b, raw, rawlen);
    if (p->payload_len)
        memcpy(h->b + rawlen, p->payload, p->payload_len);
    *r->tail = h;
    r->tail = &h->next;
    r->n++;
    return 1;
}

/* fn (non-NULL) gets each held packet with no view: it goes as it is */
static void rfree(reasm *r, xl7_replay_fn fn, void *ud)
{
    held *h, *n;
    if (!r)
        return;
    for (h = r->h; h; h = n) {
        n = h->next;
        if (fn)
            fn(ud, h->b, h->len, h->dir, h->pctx, NULL);
        free(h);
    }
    free(r);
}

/* Takes the reassembly off f and replays its packets: ok, as pieces of the
 * whole message (v carries what is common to them); otherwise each with its
 * own payload, as partial. */
static void rend(ct_flow *f, int ok, const xl7_view *common, uint64_t pdis, xl7_replay_fn fn, void *ud)
{
    reasm *r = f->xr;
    unsigned i = 0;
    uint32_t seq0;
    if (!r)
        return;
    f->xr = NULL;
    seq0 = r->h ? r->h->seq : 0;
    for (held *h = r->h; h; h = h->next) {
        xl7_view v;
        const uint8_t *pl = h->b + h->len;
        if (ok) {
            v = *common;
            v.piece = ++i;
            v.pieces = r->n;
            v.offset = r->tcp ? (size_t)(h->seq - seq0) : 0;
        } else {
            int l7 = f->l7proto ? f->l7proto : L7_UNKNOWN;
            memset(&v, 0, sizeof(v));
            v.l7p = l7_probe(pl, h->plen, r->tcp, 0, 0, pdis, &l7);
            v.l7 = l7;
            v.data = pl;
            v.len = h->plen;
            v.host = f->host;
            v.partial = 1;
        }
        if (!r->tcp && ok) {
            v.data = pl;
            v.len = h->plen;
        }
        v.cli = &h->cli;
        v.srv = &h->srv;
        if (fn)
            fn(ud, h->b, h->len, h->dir, h->pctx, &v);
    }
    rfree(r, NULL, NULL);
}

void xl7_flush(ct_flow *f, xl7_replay_fn fn, void *ud)
{
    if (f)
        rend(f, 0, NULL, 0, fn, ud);
}

void xl7_clear(ct_flow *f, xl7_replay_fn fn, void *ud)
{
    rfree(f->xr, fn, ud);
    f->xr = NULL;
    free(f->host);
    f->host = NULL;
    free(f->chost);
    f->chost = NULL;
}

unsigned xl7_held(const ct_flow *f) { return f && f->xr ? ((const reasm *)f->xr)->n : 0; }

/* ---- per packet ---------------------------------------------------------- */

static void set_l7(ct_flow *f, int l7)
{
    if (f && !f->l7proto && l7 != L7_UNKNOWN)
        f->l7proto = (uint8_t)l7;
}

static void set_host(xl7 *x, ct_flow *f, int found)
{
    if (!found || !x->host[0])
        return;
    if (f && !f->host)
        f->host = xstrdup(x->host);
}

static void cancel(xl7 *x, ct_flow *f, xl7_replay_fn fn, void *ud)
{
    if (f && f->xr)
        rend(f, 0, NULL, x->c.payload_disable, fn, ud);
}

static int tcp_packet(xl7 *x, ct_flow *f, int reverse, const gpkt *p, strat_dir dir, const uint8_t *raw,
                      size_t rawlen, const void *pctx, size_t pctx_len, int hold, xl7_replay_fn fn, void *ud,
                      xl7_view *v, int *l7)
{
    const uint8_t *d = p->payload, *rd = d;
    size_t n = p->payload_len, rn = n;
    reasm *r;
    if ((p->tcpflags & 2) || !n)
        return XL7_GO;
    if (reverse) {
        v->l7p = l7_probe(d, n, 1, 1, 0, x->c.payload_disable, l7);
        set_l7(f, *l7);
        return XL7_GO;
    }
    r = f ? f->xr : NULL;
    if (r) {
        if (rfeed(r, f->client.seq_last, d, n)) {
            rd = r->buf;
            rn = r->present;
        } else {
            cancel(x, f, fn, ud);
            r = NULL;
        }
    }
    if (!r) {
        /* MTProto only on the first data packet: it costs an AES */
        int first = f && f->client.seq_last - f->client.seq0 == 1;
        v->l7p = l7_probe(rd, rn, 1, 0, first, x->c.payload_disable, l7);
        set_l7(f, *l7);
    }
    if (v->l7p == L7P_TLS_CLIENT_HELLO || r) {
        int full = rn >= 5 && l7_tls_record_len(rd) <= rn;
        v->l7p = L7P_TLS_CLIENT_HELLO;
        if (f && hold && !disabled(x->c.reasm_disable, L7P_TLS_CLIENT_HELLO)) {
            /* not a retransmission: the client sends the rest anyway */
            if (!full && !r && !ct_is_retrans(&f->client)) {
                size_t size = n >= 5 ? l7_tls_record_len(d) : 0;
                /* the client will not send more than the server's window:
                 * we would wait for retransmissions */
                if (size && !(f->server.pcounter && f->server.winsize_calc < size) &&
                    (r = rstart(x, f, 1, size, f->client.seq_last)))
                    rfeed(r, f->client.seq_last, d, n);
            }
            if (r) {
                if (!rhold(r, f, p, dir, raw, rawlen, pctx, pctx_len)) {
                    cancel(x, f, fn, ud);
                    v->l7p = L7P_UNKNOWN; /* could be a middle piece */
                    return XL7_GO;
                }
                if (r->present == r->size) {
                    xl7_view c;
                    set_host(x, f, l7_tls_host(r->buf, r->present, x->host, sizeof(x->host), 1));
                    memset(&c, 0, sizeof(c));
                    c.l7 = *l7;
                    c.l7p = L7P_TLS_CLIENT_HELLO;
                    c.data = r->buf;
                    c.len = r->present;
                    c.host = f->host;
                    rend(f, 1, &c, 0, fn, ud);
                }
                return XL7_HOLD;
            }
        }
        set_host(x, f, l7_tls_host(rd, rn, x->host, sizeof(x->host), 1));
    } else if (v->l7p == L7P_HTTP_REQ) {
        set_host(x, f, l7_http_host(rd, rn, x->host, sizeof(x->host)));
    }
    v->data = rd;
    v->len = rn;
    return XL7_GO;
}

static int quic(xl7 *x, ct_flow *f, const gpkt *p, strat_dir dir, const uint8_t *raw, size_t rawlen,
                const void *pctx, size_t pctx_len, int hold, xl7_replay_fn fn, void *ud, xl7_view *v, int l7)
{
    const uint8_t *d = p->payload, *pc;
    size_t n = p->payload_len, pcn, dl = x->c.reasm_max, ho, hl;
    int can = f && hold && !disabled(x->c.reasm_disable, L7P_QUIC_INITIAL), full, hello, hfull;
    reasm *r = f ? f->xr : NULL;
    quic_initial h;
    long cl = quic_initial_decrypt(d, n, &h, x->clean, sizeof(x->clean));
    if (cl < 0)
        return 0;
    pc = x->clean;
    pcn = (size_t)cl;
    if (can && r) {
        if (r->present + pcn > r->size)
            return 0; /* too long */
        rfeed(r, (uint32_t)r->present, pc, pcn);
        pc = r->buf;
        pcn = r->present;
    }
    if (!l7_quic_defrag(pc, pcn, x->defrag, &dl, &full))
        return 0;
    if (!full) {
        /* a CRYPTO piece is missing: wait for the next Initial */
        if (!can || (!r && !(r = rstart(x, f, 0, x->c.reasm_max, 0))))
            return 0;
        if (!r->n && !r->present && !rfeed(r, 0, x->clean, (size_t)cl))
            return 0;
        return rhold(r, f, p, dir, raw, rawlen, pctx, pctx_len) ? 2 : 0;
    }
    hello = l7_quic_crypto_hello(x->defrag, dl, &ho, &hl);
    hfull = hello && hl >= 4 && l7_tls_hs_len(x->defrag + ho) <= hl;
    if (can) {
        if (hello && !hfull && !r) {
            if (!(r = rstart(x, f, 0, x->c.reasm_max, 0)) || !rfeed(r, 0, x->clean, (size_t)cl))
                return 0;
        }
        if (r) {
            if (!rhold(r, f, p, dir, raw, rawlen, pctx, pctx_len))
                return 0;
            if (hfull) {
                xl7_view c;
                set_host(x, f, l7_tls_hs_host(x->defrag + ho, hl, x->host, sizeof(x->host), 1));
                memset(&c, 0, sizeof(c));
                c.l7 = l7;
                c.l7p = L7P_QUIC_INITIAL;
                c.dec = x->defrag + ho;
                c.dec_len = hl;
                c.host = f->host;
                rend(f, 1, &c, 0, fn, ud);
            }
            return 2;
        }
    }
    if (!hello)
        return 0;
    v->dec = x->defrag + ho;
    v->dec_len = hl;
    set_host(x, f, l7_tls_hs_host(v->dec, hl, x->host, sizeof(x->host), 1));
    return 1;
}

static int udp_packet(xl7 *x, ct_flow *f, int reverse, const gpkt *p, strat_dir dir, const uint8_t *raw,
                      size_t rawlen, const void *pctx, size_t pctx_len, int hold, xl7_replay_fn fn, void *ud,
                      xl7_view *v, int *l7)
{
    if (p->payload_len) {
        v->l7p = l7_probe(p->payload, p->payload_len, 0, reverse, 0, x->c.payload_disable, l7);
        set_l7(f, *l7);
        if (!reverse && v->l7p == L7P_QUIC_INITIAL &&
            quic(x, f, p, dir, raw, rawlen, pctx, pctx_len, hold, fn, ud, v, *l7) == 2)
            return XL7_HOLD;
    }
    /* any other packet of the flow ends a QUIC reassembly */
    cancel(x, f, fn, ud);
    return XL7_GO;
}

/* nfqws2's dpi_desync_icmp_packet: an error carrying a packet is ipv4 or
 * ipv6 (by that packet), any other ICMP is icmp. Its one switch takes the
 * ICMPv4 and ICMPv6 type numbers together for both. */
static int icmp_payload(const gpkt *p)
{
    const uint8_t *d;
    size_t n = p->payload_len, off;
    if (n < 8 || !strchr("\1\2\3\4\5\13\14", p->payload[0]) || !p->payload[0])
        return L7P_ICMP;
    d = p->payload + 8;
    n -= 8;
    off = n >= 20 ? (size_t)(d[0] & 15) * 4 : 0;
    if (n >= 20 && d[0] >> 4 == 4 && off >= 20 && n >= off && ((size_t)d[2] << 8 | d[3]) >= off)
        return L7P_IPV4;
    if (n >= 40 && d[0] >> 4 == 6)
        return L7P_IPV6;
    return L7P_ICMP;
}

int xl7_packet(xl7 *x, ct_flow *f, int reverse, const gpkt *p, strat_dir dir, const uint8_t *raw, size_t rawlen,
               const void *pctx, size_t pctx_len, int hold, xl7_replay_fn fn, void *ud, xl7_view *v)
{
    int l7 = f && f->l7proto ? f->l7proto : L7_UNKNOWN, r = XL7_GO;
    memset(v, 0, sizeof(*v));
    v->l7p = p->payload_len ? L7P_UNKNOWN : L7P_EMPTY;
    v->data = p->payload;
    v->len = p->payload_len;
    x->host[0] = 0;
    if (!hold)
        cancel(x, f, fn, ud);
    if (p->l4 == LAYER_TCP)
        r = tcp_packet(x, f, reverse, p, dir, raw, rawlen, pctx, pctx_len, hold, fn, ud, v, &l7);
    else if (p->l4 == LAYER_UDP)
        r = udp_packet(x, f, reverse, p, dir, raw, rawlen, pctx, pctx_len, hold, fn, ud, v, &l7);
    else if (p->l4proto == 1 || p->l4proto == 58)
        v->l7p = icmp_payload(p);
    v->l7 = l7;
    v->host = f && f->host ? f->host : x->host[0] ? x->host : NULL;
    return r;
}
