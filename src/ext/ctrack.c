#include "ctrack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

#define CT_BUCKETS 4096 /* power of 2 */
#define CT_PURGE_MS 10000

struct ctrack {
    ct_config c;
    ct_flow *b[CT_BUCKETS];
    ct_flow *lru_head, *lru_tail; /* head: most recently active */
    size_t n;
    uint64_t evictions;
    uint64_t last_purge;
    uint64_t now; /* the latest time fed: time never goes back */
};

typedef struct {
    uint8_t ver, proto;
    const uint8_t *src, *dst;
    uint16_t sport, dport;
} ct_key;

void ct_config_default(ct_config *c)
{
    c->t_syn = 60;
    c->t_est = 300;
    c->t_fin = 60;
    c->t_udp = 60;
    c->max = CT_DEFAULT_MAX;
}

int ct_timeouts_parse(const char *s, ct_config *c)
{
    unsigned v[4] = {0, 0, 0, c->t_udp};
    int k = 0;
    const char *q = s;
    while (k < 4) {
        unsigned long x = 0;
        if (*q < '0' || *q > '9')
            return -1;
        while (*q >= '0' && *q <= '9') {
            x = x * 10 + (unsigned long)(*q++ - '0');
            if (x > 86400 * 30)
                return -1;
        }
        v[k++] = (unsigned)x;
        if (!*q)
            break;
        if (*q++ != ':')
            return -1;
    }
    if (*q || k < 3)
        return -1;
    c->t_syn = v[0], c->t_est = v[1], c->t_fin = v[2], c->t_udp = v[3];
    return 0;
}

ctrack *ctrack_new(const ct_config *c)
{
    ctrack *t = xcalloc(1, sizeof(*t));
    t->c = *c;
    if (!t->c.max)
        t->c.max = CT_DEFAULT_MAX;
    return t;
}

void ctrack_free(ctrack *t)
{
    ct_flow *f, *nx;
    if (!t)
        return;
    for (f = t->lru_head; f; f = nx) {
        nx = f->lnext;
        free(f);
    }
    free(t);
}

size_t ctrack_count(const ctrack *t) { return t->n; }
uint64_t ctrack_evictions(const ctrack *t) { return t->evictions; }

/* ---- table --------------------------------------------------------------- */

static uint32_t key_hash(const ct_key *k)
{
    /* FNV-1a over the key as the client sent it */
    uint32_t h = 2166136261u;
    size_t al = k->ver == 4 ? 4 : 16;
    for (size_t i = 0; i < al; i++)
        h = (h ^ k->src[i]) * 16777619u;
    for (size_t i = 0; i < al; i++)
        h = (h ^ k->dst[i]) * 16777619u;
    h = (h ^ (uint8_t)(k->sport >> 8)) * 16777619u;
    h = (h ^ (uint8_t)k->sport) * 16777619u;
    h = (h ^ (uint8_t)(k->dport >> 8)) * 16777619u;
    h = (h ^ (uint8_t)k->dport) * 16777619u;
    h = (h ^ k->proto) * 16777619u;
    return h;
}

static int key_eq(const ct_flow *f, const ct_key *k)
{
    size_t al = k->ver == 4 ? 4 : 16;
    return f->ver == k->ver && f->proto == k->proto && f->cport == k->sport && f->sport == k->dport &&
           !memcmp(f->cli, k->src, al) && !memcmp(f->srv, k->dst, al);
}

static ct_flow *lookup(ctrack *t, const ct_key *k)
{
    uint32_t h = key_hash(k);
    for (ct_flow *f = t->b[h & (CT_BUCKETS - 1)]; f; f = f->hnext)
        if (f->hash == h && key_eq(f, k))
            return f;
    return NULL;
}

static void lru_unlink(ctrack *t, ct_flow *f)
{
    if (f->lprev)
        f->lprev->lnext = f->lnext;
    else
        t->lru_head = f->lnext;
    if (f->lnext)
        f->lnext->lprev = f->lprev;
    else
        t->lru_tail = f->lprev;
    f->lprev = f->lnext = NULL;
}

static void lru_front(ctrack *t, ct_flow *f)
{
    if (t->lru_head == f)
        return;
    if (f->lprev || f->lnext || t->lru_tail == f)
        lru_unlink(t, f);
    f->lnext = t->lru_head;
    if (t->lru_head)
        t->lru_head->lprev = f;
    t->lru_head = f;
    if (!t->lru_tail)
        t->lru_tail = f;
}

static void drop(ctrack *t, ct_flow *f)
{
    ct_flow **pp = &t->b[f->hash & (CT_BUCKETS - 1)];
    while (*pp != f)
        pp = &(*pp)->hnext;
    *pp = f->hnext;
    lru_unlink(t, f);
    free(f);
    t->n--;
}

static ct_flow *create(ctrack *t, const ct_key *k)
{
    ct_flow *f;
    size_t al = k->ver == 4 ? 4 : 16;
    if (t->n >= t->c.max && t->lru_tail) {
        drop(t, t->lru_tail);
        t->evictions++;
    }
    f = xcalloc(1, sizeof(*f));
    f->ver = k->ver;
    f->proto = k->proto;
    memcpy(f->cli, k->src, al);
    memcpy(f->srv, k->dst, al);
    f->cport = k->sport;
    f->sport = k->dport;
    f->hash = key_hash(k);
    f->hnext = t->b[f->hash & (CT_BUCKETS - 1)];
    t->b[f->hash & (CT_BUCKETS - 1)] = f;
    lru_front(t, f);
    t->n++;
    return f;
}

/* ConntrackReInitTrack: everything but the key and the links */
static void reinit(ct_flow *f)
{
    size_t keep = offsetof(ct_flow, client);
    size_t end = offsetof(ct_flow, hnext);
    memset((uint8_t *)f + keep, 0, end - keep);
}

/* ---- positions (ConntrackApplyPos, ConntrackFeedPacket) ------------------- */

enum { TH_FIN = 1, TH_SYN = 2, TH_RST = 4, TH_PUSH = 8, TH_ACK = 16, TH_URG = 32 };

static int syn_segment(const gpkt *p) { return (p->tcpflags & 0x3f) == TH_SYN; }
static int synack_segment(const gpkt *p) { return (p->tcpflags & 0x3f) == (TH_SYN | TH_ACK); }

/* the first option of this kind (tcp_find_option) */
static const tcp_opt *find_opt(const gpkt *p, uint8_t kind)
{
    for (int i = 0; i < p->nopts; i++)
        if (p->opts[i].kind == kind)
            return &p->opts[i];
    return NULL;
}

static void apply_pos(ct_flow *f, int reverse, const gpkt *p)
{
    ct_side *direct = reverse ? &f->server : &f->client;
    ct_side *rev = reverse ? &f->client : &f->server;
    uint32_t plen = (uint32_t)p->payload_len;

    if (p->ipver == 6)
        direct->ip6flow = p->fl;
    direct->winsize_calc = direct->winsize = p->window;
    if (f->state == CT_SYN) {
        /* scale and MSS are valid in SYN packets only */
        const tcp_opt *o = find_opt(p, 3);
        if (o && o->len == 1)
            direct->scale = o->data[0] < 14 ? o->data[0] : 14; /* RFC 7323 limit */
        o = find_opt(p, 2);
        direct->mss = o && o->len == 2 ? (uint16_t)(o->data[0] << 8 | o->data[1]) : 0;
    } else {
        direct->winsize_calc <<= direct->scale;
    }
    direct->seq_last = p->seq;
    direct->pos = direct->seq_last + plen;
    rev->pos = rev->seq_last = p->ack;
    if (f->state == CT_SYN) {
        direct->uppos_prev = direct->uppos = direct->pos;
    } else if (plen) {
        direct->uppos_prev = direct->uppos;
        if (!((direct->pos - direct->uppos) & 0x80000000u))
            direct->uppos = direct->pos;
    }
    if (!direct->rseq_over_2g && ((direct->seq_last - direct->seq0) & 0x80000000u))
        direct->rseq_over_2g = 1;
    if (!rev->rseq_over_2g && ((rev->seq_last - rev->seq0) & 0x80000000u))
        rev->rseq_over_2g = 1;
}

static void feed_packet(ct_flow *f, int reverse, const gpkt *p, uint64_t now)
{
    ct_side *s = reverse ? &f->server : &f->client;
    s->pcounter++;
    s->pdcounter += p->payload_len ? 1 : 0;
    s->pbcounter += p->payload_len;

    if (p->l4 == LAYER_TCP) {
        if (syn_segment(p)) {
            if (f->state != CT_SYN)
                reinit(f); /* a new connection on this 4-tuple; as in zapret2
                            * the SYN counted above is erased too */
            f->client.seq0 = p->seq;
        } else if (synack_segment(p)) {
            /* duplicates of the SYN+ACK change nothing */
            uint32_t seq0 = p->ack - 1;
            if (f->state != CT_SYN && f->client.seq0 != seq0)
                reinit(f);
            if (!f->client.seq0)
                f->client.seq0 = seq0;
            f->server.seq0 = p->seq;
        } else if (p->tcpflags & (TH_FIN | TH_RST)) {
            f->state = CT_FIN;
        } else if (f->state == CT_SYN) {
            f->state = CT_EST;
            if (!reverse && !f->server.seq0)
                f->server.seq0 = p->ack - 1;
        }
        apply_pos(f, reverse, p);
    }
    if (reverse && !f->incoming_ttl)
        f->incoming_ttl = p->ipver == 6 ? p->hlim : p->ttl; /* zapret2: the first reply's */
    f->t_last = now;
    if (!f->t_start)
        f->t_start = now;
}

/* ---- keys ---------------------------------------------------------------- */

static int pkt_key(const gpkt *p, ct_key *k)
{
    if (p->l4 != LAYER_TCP && p->l4 != LAYER_UDP)
        return -1;
    k->ver = (uint8_t)p->ipver;
    k->proto = p->l4 == LAYER_TCP ? 6 : 17;
    k->src = p->src;
    k->dst = p->dst;
    k->sport = p->sport;
    k->dport = p->dport;
    return 0;
}

static void swap(ct_key *k)
{
    const uint8_t *a = k->src;
    uint16_t pt = k->sport;
    k->src = k->dst, k->dst = a;
    k->sport = k->dport, k->dport = pt;
}

/* The packet an ICMP error carries: its key as it was sent. */
static int icmp_inner_key(const gpkt *p, ct_key *k)
{
    const uint8_t *q = p->payload;
    size_t n = p->payload_len, off, hl;
    uint8_t nh;
    if (p->l4 != LAYER_NONE || p->frag & 0x1fff || n < 8)
        return -1;
    if (p->ipver == 4 && p->l4proto == 1) {
        if (q[0] != 3 && q[0] != 5 && q[0] != 11 && q[0] != 12)
            return -1;
    } else if (p->ipver == 6 && p->l4proto == 58) {
        if (q[0] < 1 || q[0] > 4)
            return -1;
    } else {
        return -1;
    }
    q += 8, n -= 8;
    if (p->ipver == 4) {
        if (n < 20 || q[0] >> 4 != 4 || (q[0] & 15) < 5)
            return -1;
        hl = (size_t)(q[0] & 15) * 4;
        if ((q[6] << 8 | q[7]) & 0x1fff)
            return -1; /* a later fragment: no ports */
        nh = q[9];
        k->ver = 4;
        k->src = q + 12;
        k->dst = q + 16;
    } else {
        if (n < 40 || q[0] >> 4 != 6)
            return -1;
        hl = 40;
        nh = q[6];
        k->ver = 6;
        k->src = q + 8;
        k->dst = q + 24;
    }
    if (nh != 6 && nh != 17)
        return -1; /* extension headers are not followed */
    off = hl;
    if (n < off + 4)
        return -1;
    k->proto = nh;
    k->sport = (uint16_t)(q[off] << 8 | q[off + 1]);
    k->dport = (uint16_t)(q[off + 2] << 8 | q[off + 3]);
    return 0;
}

static ct_flow *search(ctrack *t, ct_key *k, int *reverse)
{
    ct_flow *f = lookup(t, k);
    if (f) {
        *reverse = 0;
        return f;
    }
    swap(k);
    f = lookup(t, k);
    swap(k);
    if (f)
        *reverse = 1;
    return f;
}

/* ---- API ----------------------------------------------------------------- */

void ctrack_purge(ctrack *t, uint64_t now)
{
    ct_flow *f, *nx;
    for (f = t->lru_head; f; f = nx) {
        uint64_t idle = (now - f->t_last) / 1000;
        int dead;
        nx = f->lnext;
        if (f->proto == 6)
            dead = (f->state == CT_SYN && idle >= t->c.t_syn) || (f->state == CT_EST && idle >= t->c.t_est) ||
                   (f->state == CT_FIN && idle >= t->c.t_fin);
        else
            dead = idle >= t->c.t_udp;
        if (dead)
            drop(t, f);
    }
    t->last_purge = now;
}

ct_flow *ctrack_find(ctrack *t, const gpkt *p, int *reverse)
{
    ct_key k;
    int r = 0;
    ct_flow *f;
    if (pkt_key(p, &k) == 0) {
        f = search(t, &k, &r);
    } else if (icmp_inner_key(p, &k) == 0) {
        f = search(t, &k, &r);
        r = !r; /* the ICMP goes back to the sender of the embedded packet */
    } else {
        return NULL;
    }
    if (f && reverse)
        *reverse = r;
    return f;
}

ct_flow *ctrack_feed(ctrack *t, const gpkt *p, uint64_t now, int *reverse)
{
    ct_key k;
    ct_flow *f;
    int r = 0;
    if (now < t->now)
        now = t->now; /* a capture merged out of order: no purge of everything */
    t->now = now;
    if (!t->last_purge)
        t->last_purge = now;
    else if (now - t->last_purge >= CT_PURGE_MS)
        ctrack_purge(t, now);
    if (pkt_key(p, &k) < 0)
        return ctrack_find(t, p, reverse); /* ICMP errors: nothing to count */
    f = search(t, &k, &r);
    if (!f) {
        r = p->l4 == LAYER_TCP && synack_segment(p);
        if (!(p->l4 == LAYER_TCP && syn_segment(p)) && !r && p->l4 != LAYER_UDP)
            return NULL;
        if (r)
            swap(&k);
        f = create(t, &k);
    } else {
        lru_front(t, f);
    }
    feed_packet(f, r, p, now);
    if (reverse)
        *reverse = r;
    return f;
}

int ct_is_retrans(const ct_side *s) { return !((s->uppos_prev - s->pos) & 0x80000000u); }

unsigned ct_mss(const ct_flow *f)
{
    if (f->client.mss && f->server.mss)
        return f->client.mss < f->server.mss ? f->client.mss : f->server.mss;
    return CT_DEFAULT_MSS;
}

void ct_view(const ct_side *s, xside_view *v)
{
    v->n = s->pcounter;
    v->d = s->pdcounter;
    v->b = s->pbcounter;
    v->s = s->seq_last - s->seq0;
    v->p = s->pos - s->seq0;
    v->over2g = s->rseq_over_2g;
}
