#include "flowtab.h"

#include <stdlib.h>
#include <string.h>

#include "util.h"

#define NIL UINT32_MAX

#define TCP_FIN 0x01
#define TCP_RST 0x04

typedef struct {
    uint8_t la[16], ra[16]; /* local, remote address (IPv4 in the first 4 bytes) */
    uint16_t lp, rp;
    uint8_t proto, v6;
} flow_key;

typedef struct {
    flow_key k;
    uint32_t hnext;          /* hash chain, or the free list */
    uint32_t newer, older;   /* LRU list */
    uint64_t expires;        /* ms */
    uint32_t n[2];           /* packets out, in */
    uint8_t fin;             /* bit 0: FIN out, bit 1: FIN in */
    uint8_t closed;          /* FIN both ways or RST */
} flow;

struct flowtab {
    size_t max, n;
    flow *v;
    size_t cap;              /* entries allocated in v */
    uint32_t *buckets;
    uint32_t nb;             /* power of two */
    uint32_t free_head;
    uint32_t newest, oldest;
};

flowtab *flowtab_new(size_t max)
{
    flowtab *t = xcalloc(1, sizeof(*t));
    if (!max)
        max = FLOW_MAX;
    if (max > FLOW_MAX * 16)
        max = FLOW_MAX * 16;
    t->max = max;
    t->nb = 16;
    while (t->nb < max * 2)
        t->nb <<= 1;
    t->buckets = xmalloc(t->nb * sizeof(*t->buckets));
    for (uint32_t i = 0; i < t->nb; i++)
        t->buckets[i] = NIL;
    t->free_head = t->newest = t->oldest = NIL;
    return t;
}

void flowtab_free(flowtab *t)
{
    if (!t)
        return;
    free(t->v);
    free(t->buckets);
    free(t);
}

size_t flowtab_count(const flowtab *t) { return t->n; }

/* The flow key of p, normalized by direction. Returns -1 without one. */
static int make_key(const gpkt *p, strat_dir dir, flow_key *k)
{
    size_t alen = p->ipver == 6 ? 16 : 4;
    const uint8_t *la, *ra;
    if (p->l4 != LAYER_TCP && p->l4 != LAYER_UDP)
        return -1;
    memset(k, 0, sizeof(*k));
    k->proto = p->l4 == LAYER_TCP ? 6 : 17;
    k->v6 = p->ipver == 6;
    if (dir == DIR_OUT) {
        la = p->src, ra = p->dst;
        k->lp = p->sport, k->rp = p->dport;
    } else {
        la = p->dst, ra = p->src;
        k->lp = p->dport, k->rp = p->sport;
    }
    memcpy(k->la, la, alen);
    memcpy(k->ra, ra, alen);
    return 0;
}

static uint32_t hash_key(const flow_key *k)
{
    const uint8_t *b = (const uint8_t *)k;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < sizeof(*k); i++)
        h = (h ^ b[i]) * 16777619u;
    return h ^ (h >> 15);
}

static uint32_t find(const flowtab *t, const flow_key *k, uint32_t h)
{
    uint32_t i = t->buckets[h & (t->nb - 1)];
    while (i != NIL && memcmp(&t->v[i].k, k, sizeof(*k)))
        i = t->v[i].hnext;
    return i;
}

static void lru_unlink(flowtab *t, uint32_t i)
{
    flow *f = &t->v[i];
    if (f->newer != NIL)
        t->v[f->newer].older = f->older;
    else
        t->newest = f->older;
    if (f->older != NIL)
        t->v[f->older].newer = f->newer;
    else
        t->oldest = f->newer;
    f->newer = f->older = NIL;
}

static void lru_push(flowtab *t, uint32_t i)
{
    flow *f = &t->v[i];
    f->older = t->newest;
    f->newer = NIL;
    if (t->newest != NIL)
        t->v[t->newest].newer = i;
    t->newest = i;
    if (t->oldest == NIL)
        t->oldest = i;
}

static void remove_flow(flowtab *t, uint32_t i)
{
    uint32_t *pp = &t->buckets[hash_key(&t->v[i].k) & (t->nb - 1)];
    while (*pp != i)
        pp = &t->v[*pp].hnext;
    *pp = t->v[i].hnext;
    lru_unlink(t, i);
    t->v[i].hnext = t->free_head;
    t->free_head = i;
    t->n--;
}

static uint32_t alloc_flow(flowtab *t)
{
    uint32_t i;
    if (t->free_head != NIL) {
        i = t->free_head;
        t->free_head = t->v[i].hnext;
        return i;
    }
    if (t->cap == t->n) {
        size_t nc = t->cap ? t->cap * 2 : 256;
        if (nc > t->max)
            nc = t->max;
        t->v = xrealloc(t->v, nc * sizeof(*t->v));
        t->cap = nc;
    }
    return (uint32_t)t->n; /* no free entries: the used ones are 0 .. n-1 */
}

static uint64_t lifetime(const flow *f)
{
    if (f->closed)
        return FLOW_CLOSED_MS;
    return f->k.proto == 6 ? FLOW_TCP_IDLE_MS : FLOW_UDP_IDLE_MS;
}

int flowtab_packet(flowtab *t, const gpkt *p, strat_dir dir, uint32_t first, uint64_t now, int *evicted)
{
    flow_key k;
    uint32_t h, i;
    flow *f;
    int d = dir == DIR_OUT ? 0 : 1;
    *evicted = 0;
    if (make_key(p, dir, &k) < 0)
        return 1;
    h = hash_key(&k);
    i = find(t, &k, h);
    if (i != NIL && now >= t->v[i].expires) {
        remove_flow(t, i); /* expired: this packet starts a new flow */
        i = NIL;
    }
    if (i == NIL) {
        if (t->n >= t->max) {
            uint32_t old = t->oldest;
            if (now < t->v[old].expires)
                *evicted = 1; /* a live flow makes room */
            remove_flow(t, old);
        }
        i = alloc_flow(t);
        f = &t->v[i];
        memset(f, 0, sizeof(*f));
        f->k = k;
        f->hnext = t->buckets[h & (t->nb - 1)];
        t->buckets[h & (t->nb - 1)] = i;
        f->newer = f->older = NIL;
        lru_push(t, i);
        t->n++;
    } else {
        f = &t->v[i];
        lru_unlink(t, i);
        lru_push(t, i);
    }
    if (f->n[d] < UINT32_MAX)
        f->n[d]++;
    if (k.proto == 6) {
        if (p->tcpflags & TCP_RST)
            f->closed = 1;
        if (p->tcpflags & TCP_FIN) {
            f->fin |= (uint8_t)(1 << d);
            if (f->fin == 3)
                f->closed = 1;
        }
    }
    f->expires = now + lifetime(f);
    return f->n[d] <= first;
}

size_t flowtab_expire(flowtab *t, uint64_t now)
{
    size_t removed = 0;
    uint32_t i = t->oldest;
    while (i != NIL) {
        uint32_t next = t->v[i].newer;
        if (now >= t->v[i].expires) {
            remove_flow(t, i);
            removed++;
        }
        i = next;
    }
    return removed;
}

int flowtab_peek(const flowtab *t, const gpkt *p, strat_dir dir, uint64_t now, uint32_t *out, uint32_t *in)
{
    flow_key k;
    uint32_t i;
    if (make_key(p, dir, &k) < 0)
        return 0;
    i = find(t, &k, hash_key(&k));
    if (i == NIL || now >= t->v[i].expires)
        return 0;
    *out = t->v[i].n[0];
    *in = t->v[i].n[1];
    return 1;
}
