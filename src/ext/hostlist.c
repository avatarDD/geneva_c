/*
 * Host lists (hostlist.h): an open-addressing hash set of names in one
 * string pool, so a list of a hundred thousand names takes a few
 * allocations.
 */
#include "hostlist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "plat.h"
#include "util.h"

static uint32_t hash(const char *s, size_t n)
{
    uint32_t h = 2166136261u; /* FNV-1a */
    for (size_t i = 0; i < n; i++) {
        h ^= (uint8_t)s[i];
        h *= 16777619u;
    }
    return h;
}

void xhs_free(xhostset *h)
{
    free(h->pool);
    free(h->slot);
    free(h->flags);
    memset(h, 0, sizeof(*h));
}

/* the slot of s, or the empty one where it would go */
static size_t find(const xhostset *h, const char *s, size_t n, uint32_t hv)
{
    size_t m = h->cap - 1, i = hv & m;
    for (;;) {
        uint32_t o = h->slot[i];
        if (!o)
            return i;
        if (!strncmp(h->pool + o - 1, s, n) && !h->pool[o - 1 + n])
            return i;
        i = (i + 1) & m;
    }
}

static void grow(xhostset *h)
{
    size_t ocap = h->cap;
    uint32_t *os = h->slot;
    uint8_t *of = h->flags;
    h->cap = ocap ? ocap * 2 : 64;
    h->slot = xcalloc(h->cap, sizeof(*h->slot));
    h->flags = xcalloc(h->cap, 1);
    for (size_t i = 0; i < ocap; i++)
        if (os[i]) {
            const char *s = h->pool + os[i] - 1;
            size_t l = strlen(s), j = find(h, s, l, hash(s, l));
            h->slot[j] = os[i];
            h->flags[j] = of[i];
        }
    free(os);
    free(of);
}

int xhs_add(xhostset *h, const char *s, size_t n, uint8_t flags)
{
    char low[256], *k = n < sizeof(low) ? low : xmalloc(n + 1);
    size_t i;
    for (i = 0; i < n; i++)
        k[i] = (char)(s[i] >= 'A' && s[i] <= 'Z' ? s[i] + 32 : s[i]);
    k[n] = 0;
    n = strlen(k); /* a NUL inside: the name ends there */
    if ((h->n + 1) * 4 > h->cap * 3)
        grow(h);
    i = find(h, k, n, hash(k, n));
    if (!h->slot[i] && h->plen + n + 1 < UINT32_MAX) { /* offsets are 32-bit */
        if (h->plen + n + 1 > h->pcap) {
            while (h->plen + n + 1 > h->pcap)
                h->pcap = h->pcap ? h->pcap * 2 : 4096;
            h->pool = xrealloc(h->pool, h->pcap);
        }
        memcpy(h->pool + h->plen, k, n + 1);
        h->slot[i] = (uint32_t)(h->plen + 1);
        h->flags[i] = flags;
        h->plen += n + 1;
        h->n++;
    }
    if (k != low)
        free(k);
    return 0;
}

int xhs_get(const xhostset *h, const char *s, size_t n, uint8_t *flags)
{
    size_t i;
    if (!h->n)
        return 0;
    i = find(h, s, n, hash(s, n));
    if (!h->slot[i])
        return 0;
    if (flags)
        *flags = h->flags[i];
    return 1;
}

size_t xhs_parse(xhostset *h, const char *p, size_t n)
{
    const char *end = p + n;
    size_t ct = 0;
    while (p < end) {
        while (p < end && (*p == ' ' || *p == '\t'))
            p++;
        if (p < end && *p != '#' && *p != ';' && *p != '/' && *p != '\r' && *p != '\n') {
            uint8_t flags = 0;
            const char *s;
            for (; p < end && (*p == '^' || *p == '!'); p++)
                flags |= *p == '^' ? XHL_STRICT : XHL_EXEMPT;
            for (s = p; p < end && *p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n'; p++)
                ;
            xhs_add(h, s, (size_t)(p - s), flags);
            ct++;
        }
        while (p < end && *p && *p != '\r' && *p != '\n')
            p++;
        while (p < end && (!*p || *p == '\r' || *p == '\n'))
            p++;
    }
    return ct;
}

int xhs_search(const xhostset *h, const char *host, int no_subdom, int *exempt)
{
    const char *p = host;
    int full = 1;
    if (exempt)
        *exempt = 0;
    if (!h->n)
        return 0;
    while (p) {
        uint8_t fl;
        if (xhs_get(h, p, strlen(p), &fl) && !((fl & XHL_STRICT) && !full)) {
            if (!(fl & XHL_EXEMPT))
                return 1;
            if (exempt)
                *exempt = 1;
            return 0;
        }
        if (no_subdom)
            break;
        p = strchr(p, '.');
        if (p)
            p++;
        full = 0;
    }
    return 0;
}

int xhost_norm(const char *host, char *out, size_t cap)
{
    uint8_t a[16];
    const char *h = host, *p;
    size_t l;
    while (*h == ' ' || *h == '\t')
        h++;
    l = strlen(h);
    snprintf(out, cap, "%s", h);
    if (l < 2)
        return 0;
    if (*h == '[') {
        if (!(p = strchr(h + 1, ']')))
            return 0;
        snprintf(out, cap, "%.*s", (int)(p - h - 1), h + 1);
        return inet_pton(AF_INET6, out, a) == 1;
    }
    if (inet_pton(AF_INET6, out, a) == 1)
        return 1;
    out[strcspn(out, ":")] = 0;
    return inet_pton(AF_INET, out, a) == 1;
}
