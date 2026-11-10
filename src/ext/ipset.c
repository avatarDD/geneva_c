/*
 * IP sets (ipset.h)
 */
#include "ipset.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "plat.h"
#include "util.h"

void xips_free(xipset *s)
{
    free(s->v4);
    free(s->v6);
    memset(s, 0, sizeof(*s));
}

int xips_empty(const xipset *s) { return !s->n4 && !s->n6; }

/* "%u" without sscanf's leniency on what follows */
static int plen(const char *s, unsigned max, unsigned *out)
{
    unsigned v = 0;
    if (!*s)
        return -1;
    for (; *s; s++) {
        if (*s < '0' || *s > '9')
            return -1;
        v = v * 10 + (unsigned)(*s - '0');
        if (v > max)
            return -1;
    }
    *out = v;
    return 0;
}

static uint64_t be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = v << 8 | p[i];
    return v;
}

int xips_add_str(xipset *s, const char *cidr)
{
    char a[64];
    const char *sl = strchr(cidr, '/');
    size_t l = sl ? (size_t)(sl - cidr) : strlen(cidr);
    uint8_t b[16];
    unsigned pl;
    int v6;
    if (l >= sizeof(a))
        return -1;
    memcpy(a, cidr, l);
    a[l] = 0;
    if (inet_pton(AF_INET, a, b) == 1)
        v6 = 0;
    else if (inet_pton(AF_INET6, a, b) == 1)
        v6 = 1;
    else
        return -1;
    if (sl) {
        if (plen(sl + 1, v6 ? 128 : 32, &pl) < 0)
            return -1;
    } else {
        pl = v6 ? 128 : 32;
    }
    if (!v6) {
        uint32_t ip = (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
        uint32_t mask = pl ? 0xffffffffu << (32 - pl) : 0;
        if (s->n4 == s->cap4) {
            s->cap4 = s->cap4 ? s->cap4 * 2 : 16;
            s->v4 = xrealloc(s->v4, s->cap4 * sizeof(*s->v4));
        }
        s->v4[s->n4].lo = ip & mask;
        s->v4[s->n4].hi = (ip & mask) | ~mask;
        s->n4++;
    } else {
        uint64_t hi = be64(b), lo = be64(b + 8), mh, ml;
        mh = pl >= 64 ? ~0ULL : pl ? ~0ULL << (64 - pl) : 0;
        ml = pl <= 64 ? 0 : pl >= 128 ? ~0ULL : ~0ULL << (128 - pl);
        if (s->n6 == s->cap6) {
            s->cap6 = s->cap6 ? s->cap6 * 2 : 16;
            s->v6 = xrealloc(s->v6, s->cap6 * sizeof(*s->v6));
        }
        s->v6[s->n6].lo[0] = hi & mh;
        s->v6[s->n6].lo[1] = lo & ml;
        s->v6[s->n6].hi[0] = (hi & mh) | ~mh;
        s->v6[s->n6].hi[1] = (lo & ml) | ~ml;
        s->n6++;
    }
    s->sorted = 0;
    return 0;
}

size_t xips_parse(xipset *s, const char *p, size_t n, size_t *bad, char *first_bad, size_t cap)
{
    const char *end = p + n;
    size_t ct = 0;
    while (p < end) {
        while (p < end && (*p == ' ' || *p == '\t'))
            p++;
        if (p < end && *p != '#' && *p != ';' && *p != '/' && *p != '\r' && *p != '\n') {
            char tok[128];
            const char *t = p;
            size_t l;
            for (; p < end && *p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n'; p++)
                ;
            l = (size_t)(p - t);
            if (l >= sizeof(tok))
                l = sizeof(tok) - 1;
            memcpy(tok, t, l);
            tok[l] = 0;
            if (xips_add_str(s, tok) == 0) {
                ct++;
            } else {
                if (bad && !(*bad)++ && first_bad && cap)
                    snprintf(first_bad, cap, "%s", tok);
            }
        }
        while (p < end && *p && *p != '\r' && *p != '\n')
            p++;
        while (p < end && (!*p || *p == '\r' || *p == '\n'))
            p++;
    }
    return ct;
}

static int cmp4(const void *a, const void *b)
{
    const xip4r *x = a, *y = b;
    return x->lo < y->lo ? -1 : x->lo > y->lo;
}

static int lt6(const uint64_t *a, const uint64_t *b) { return a[0] < b[0] || (a[0] == b[0] && a[1] < b[1]); }

static int cmp6(const void *a, const void *b)
{
    const xip6r *x = a, *y = b;
    return lt6(x->lo, y->lo) ? -1 : lt6(y->lo, x->lo);
}

void xips_finish(xipset *s)
{
    size_t i, k;
    if (s->sorted)
        return;
    if (s->n4) {
        qsort(s->v4, s->n4, sizeof(*s->v4), cmp4);
        for (i = 1, k = 0; i < s->n4; i++) {
            if (s->v4[k].hi == 0xffffffffu || s->v4[i].lo <= s->v4[k].hi + 1) {
                if (s->v4[i].hi > s->v4[k].hi)
                    s->v4[k].hi = s->v4[i].hi;
            } else {
                s->v4[++k] = s->v4[i];
            }
        }
        s->n4 = k + 1;
    }
    if (s->n6) {
        qsort(s->v6, s->n6, sizeof(*s->v6), cmp6);
        for (i = 1, k = 0; i < s->n6; i++) {
            /* overlapping (adjacent ones stay apart: no harm) */
            if (!lt6(s->v6[k].hi, s->v6[i].lo)) {
                if (lt6(s->v6[k].hi, s->v6[i].hi)) {
                    s->v6[k].hi[0] = s->v6[i].hi[0];
                    s->v6[k].hi[1] = s->v6[i].hi[1];
                }
            } else {
                s->v6[++k] = s->v6[i];
            }
        }
        s->n6 = k + 1;
    }
    s->sorted = 1;
}

int xips_has(const xipset *s, int ver, const uint8_t *a)
{
    size_t lo = 0, hi;
    if (ver == 4) {
        uint32_t ip = (uint32_t)a[0] << 24 | (uint32_t)a[1] << 16 | (uint32_t)a[2] << 8 | a[3];
        hi = s->n4;
        while (lo < hi) { /* the last interval with lo <= ip */
            size_t m = lo + (hi - lo) / 2;
            if (s->v4[m].lo <= ip)
                lo = m + 1;
            else
                hi = m;
        }
        return lo && ip <= s->v4[lo - 1].hi;
    }
    if (ver == 6) {
        uint64_t ip[2];
        ip[0] = be64(a);
        ip[1] = be64(a + 8);
        hi = s->n6;
        while (lo < hi) {
            size_t m = lo + (hi - lo) / 2;
            if (!lt6(ip, s->v6[m].lo))
                lo = m + 1;
            else
                hi = m;
        }
        return lo && !lt6(s->v6[lo - 1].hi, ip);
    }
    return 0;
}
