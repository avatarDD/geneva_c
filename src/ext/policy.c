/*
 * The policy of --ext as snapshots freed by QSBR (policy.h).
 *
 * Memory order: generations are ints read and written through plat.h's
 * atomics, which are sequentially consistent (on ARMv5, single-core, a
 * compiler barrier). A reader's announce (store) comes before its second
 * load of the current generation, so a writer that later looks at the
 * readers sees it; a snapshot is written whole before its generation is
 * published, so a reader that sees the generation sees the snapshot.
 */
#include "policy.h"

#include <stdlib.h>
#include <string.h>

#include "plat.h"
#include "util.h"

#define OFFLINE (-1)
#define STRIDE 16 /* ints between two readers' announcements: own cache lines */

struct xpol_snap {
    size_t n;
    char **keys; /* sorted */
    uint8_t *state;
    char *pool;
};

typedef struct {
    char *key;
    int state;
} wkey;

static struct {
    int on;
    unsigned readers;
    volatile int *ann;         /* reader r at ann[r * STRIDE] */
    volatile int pub;          /* the current generation */
    xpol_snap *slot[XPOL_SLOTS]; /* generation g at slot[g % XPOL_SLOTS], NULL: free */
    /* the writer's own */
    wkey *k;
    size_t n, cap;
    int dirty;
} g;

static void snap_free(xpol_snap *s)
{
    if (!s)
        return;
    free(s->keys);
    free(s->state);
    free(s->pool);
    free(s);
}

static int cmp_wkey(const void *a, const void *b)
{
    return strcmp(((const wkey *)a)->key, ((const wkey *)b)->key);
}

static xpol_snap *snap_build(void)
{
    xpol_snap *s = xcalloc(1, sizeof(*s));
    size_t bytes = 0, off = 0;
    if (g.n)
        qsort(g.k, g.n, sizeof(*g.k), cmp_wkey);
    for (size_t i = 0; i < g.n; i++)
        bytes += strlen(g.k[i].key) + 1;
    s->n = g.n;
    s->keys = xcalloc(g.n ? g.n : 1, sizeof(*s->keys));
    s->state = xcalloc(g.n ? g.n : 1, 1);
    s->pool = xmalloc(bytes ? bytes : 1);
    for (size_t i = 0; i < g.n; i++) {
        size_t l = strlen(g.k[i].key) + 1;
        memcpy(s->pool + off, g.k[i].key, l);
        s->keys[i] = s->pool + off;
        s->state[i] = (uint8_t)g.k[i].state;
        off += l;
    }
    return s;
}

void xpol_init(unsigned readers)
{
    xpol_free();
    g.on = 1;
    g.readers = readers ? readers : 1;
    g.ann = xcalloc((size_t)g.readers * STRIDE, sizeof(*g.ann));
    for (unsigned r = 0; r < g.readers; r++)
        atomic_store_int(&g.ann[r * STRIDE], OFFLINE);
    g.slot[0] = snap_build();
    atomic_store_int(&g.pub, 0);
}

void xpol_free(void)
{
    for (int i = 0; i < XPOL_SLOTS; i++) {
        snap_free(g.slot[i]);
        g.slot[i] = NULL;
    }
    for (size_t i = 0; i < g.n; i++)
        free(g.k[i].key);
    free(g.k);
    free((void *)g.ann);
    memset(&g, 0, sizeof(g));
}

void xpol_set(const char *key, int state)
{
    size_t i;
    if (!g.on || !key || !*key)
        return;
    for (i = 0; i < g.n && strcmp(g.k[i].key, key); i++)
        ;
    if (i < g.n) {
        if (state == XPOL_HEALTHY) {
            free(g.k[i].key);
            g.k[i] = g.k[--g.n];
            g.dirty = 1;
        } else if (g.k[i].state != state) {
            g.k[i].state = state;
            g.dirty = 1;
        }
        return;
    }
    if (state == XPOL_HEALTHY)
        return;
    if (g.n == g.cap) {
        g.cap = g.cap ? g.cap * 2 : 16;
        g.k = xrealloc(g.k, g.cap * sizeof(*g.k));
    }
    g.k[g.n].key = xstrdup(key);
    g.k[g.n].state = state;
    g.n++;
    g.dirty = 1;
}

/* Has every reader moved past generation gen (or is it out)? */
static int passed(int gen)
{
    for (unsigned r = 0; r < g.readers; r++) {
        int a = atomic_load_int(&g.ann[r * STRIDE]);
        if (a != OFFLINE && a <= gen)
            return 0;
    }
    return 1;
}

/* Frees the replaced snapshots no reader can hold any more */
static void reclaim(void)
{
    int cur = atomic_load_int(&g.pub);
    for (int k = cur - XPOL_SLOTS + 1; k < cur; k++) {
        xpol_snap **sp;
        if (k < 0)
            continue;
        sp = &g.slot[k % XPOL_SLOTS];
        if (*sp && passed(k)) {
            snap_free(*sp);
            *sp = NULL;
        }
    }
}

int xpol_publish(void)
{
    int next;
    if (!g.on)
        return 0;
    reclaim();
    if (!g.dirty)
        return 0;
    next = atomic_load_int(&g.pub) + 1;
    if (g.slot[next % XPOL_SLOTS]) /* a slow reader holds it: next time */
        return 0;
    g.slot[next % XPOL_SLOTS] = snap_build();
    atomic_store_int(&g.pub, next); /* after the snapshot is complete */
    g.dirty = 0;
    return 1;
}

void xpol_stats(unsigned *gen, size_t *keys, size_t *pending)
{
    *gen = g.on ? (unsigned)atomic_load_int(&g.pub) : 0;
    *keys = g.n;
    *pending = 0;
    for (int i = 0; i < XPOL_SLOTS; i++)
        *pending += g.slot[i] != NULL;
    if (*pending)
        (*pending)--; /* the current one */
}

const xpol_snap *xpol_enter(unsigned r)
{
    int gen;
    if (!g.on || r >= g.readers)
        return NULL;
    atomic_store_int(&g.ann[r * STRIDE], atomic_load_int(&g.pub));
    gen = atomic_load_int(&g.pub); /* not older than the announced one */
    return g.slot[gen % XPOL_SLOTS];
}

void xpol_leave(unsigned r)
{
    if (g.on && r < g.readers)
        atomic_store_int(&g.ann[r * STRIDE], OFFLINE);
}

size_t xpol_count(const xpol_snap *s) { return s ? s->n : 0; }

int xpol_state(const xpol_snap *s, const char *key)
{
    size_t lo = 0, hi;
    if (!s || !key || !*key)
        return XPOL_HEALTHY;
    hi = s->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(s->keys[mid], key);
        if (!c)
            return s->state[mid];
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return XPOL_HEALTHY;
}

int xpol_any_impaired(const xpol_snap *s, const char *const keys[XPOL_KEYS])
{
    for (int i = 0; i < XPOL_KEYS; i++)
        if (xpol_state(s, keys[i]) == XPOL_IMPAIRED)
            return 1;
    return 0;
}

void xpol_json(jw *w)
{
    unsigned gen;
    size_t keys, pending;
    xpol_stats(&gen, &keys, &pending);
    jw_key(w, "policy");
    jw_obj(w);
    jw_kuint(w, "gen", gen);
    jw_kuint(w, "keys", keys);
    jw_kuint(w, "retired", pending);
    jw_obj_end(w);
}
