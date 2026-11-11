/*
 * The IP cache (ipcache.h): a chained hash table keyed by the address and
 * the interface name.
 */
#include "ipcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "util.h"

#define BUCKETS0 256 /* doubled while the entries outnumber the buckets 2:1 */
#define IFNAME 16

typedef struct ent {
    struct ent *next;
    uint8_t ver, addr[16];
    char ifname[IFNAME];
    char *host;
    uint8_t host_ip, ttl;
    uint64_t last; /* seconds */
} ent;

static ent **g_b;
static size_t g_nb, g_n;
static unsigned g_lifetime = XIPC_LIFETIME;
static int g_hostname;
static uint64_t g_purged;

void xipc_config(unsigned lifetime_s, int hostname)
{
    g_lifetime = lifetime_s;
    g_hostname = hostname;
}

int xipc_hostname_on(void) { return g_hostname; }
size_t xipc_count(void) { return g_n; }

static void ent_free(ent *e)
{
    free(e->host);
    free(e);
}

void xipc_reset(void)
{
    for (size_t i = 0; i < g_nb; i++)
        while (g_b[i]) {
            ent *e = g_b[i];
            g_b[i] = e->next;
            ent_free(e);
        }
    free(g_b);
    g_b = NULL;
    g_nb = g_n = 0;
    g_purged = 0;
    g_lifetime = XIPC_LIFETIME;
    g_hostname = 0;
}

/* FNV-1a of the address and the interface name as stored (IFNAME - 1) */
static uint32_t hash(int ver, const uint8_t *a, const char *ifn)
{
    uint32_t h = 2166136261u;
    size_t n = ver == 6 ? 16 : 4;
    for (size_t i = 0; i < n; i++)
        h = (h ^ a[i]) * 16777619u;
    for (size_t i = 0; ifn && ifn[i] && i < IFNAME - 1; i++)
        h = (h ^ (uint8_t)ifn[i]) * 16777619u;
    return h;
}

static void grow(void)
{
    size_t nb = g_nb ? g_nb * 2 : BUCKETS0;
    ent **b = xcalloc(nb, sizeof(*b));
    for (size_t i = 0; i < g_nb; i++)
        while (g_b[i]) {
            ent *e = g_b[i];
            size_t k = hash(e->ver, e->addr, e->ifname) & (nb - 1);
            g_b[i] = e->next;
            e->next = b[k];
            b[k] = e;
        }
    free(g_b);
    g_b = b;
    g_nb = nb;
}

static ent *find(int ver, const uint8_t *a, const char *ifn, unsigned *b)
{
    size_t n = ver == 6 ? 16 : 4;
    if (!ifn)
        ifn = "";
    if (!g_nb)
        grow();
    *b = (unsigned)(hash(ver, a, ifn) & (g_nb - 1));
    for (ent *e = g_b[*b]; e; e = e->next)
        if (e->ver == ver && !memcmp(e->addr, a, n) && !strncmp(e->ifname, ifn, IFNAME - 1))
            return e;
    return NULL;
}

/* ipcacheTouch: found or added, its time set */
static ent *touch(int ver, const uint8_t *a, const char *ifn, uint64_t now_ms)
{
    unsigned b;
    ent *e;
    if (ver != 4 && ver != 6)
        return NULL;
    e = find(ver, a, ifn, &b);
    if (!e) {
        if (g_n >= g_nb * 2) {
            grow();
            b = (unsigned)(hash(ver, a, ifn ? ifn : "") & (g_nb - 1));
        }
        e = xcalloc(1, sizeof(*e));
        e->ver = (uint8_t)ver;
        memcpy(e->addr, a, ver == 6 ? 16 : 4);
        snprintf(e->ifname, sizeof(e->ifname), "%s", ifn ? ifn : "");
        e->next = g_b[b];
        g_b[b] = e;
        g_n++;
    }
    e->last = now_ms / 1000;
    return e;
}

void xipc_put_host(int ver, const uint8_t *a, const char *host, int is_ip, uint64_t now_ms)
{
    ent *e;
    if (!g_hostname || !host || !*host || !(e = touch(ver, a, NULL, now_ms)))
        return;
    if (!e->host || strcmp(e->host, host)) {
        free(e->host);
        e->host = xstrdup(host);
        e->host_ip = (uint8_t)!!is_ip;
        LOGD("ipcache", "hostname cached (is_ip=%d): %s", !!is_ip, host);
    }
}

int xipc_get_host(int ver, const uint8_t *a, char *out, size_t cap, int *is_ip)
{
    unsigned b;
    ent *e;
    if (!g_hostname || (ver != 4 && ver != 6) || !(e = find(ver, a, NULL, &b)) || !e->host)
        return 0;
    snprintf(out, cap, "%s", e->host);
    if (is_ip)
        *is_ip = e->host_ip;
    return 1;
}

void xipc_put_ttl(int ver, const uint8_t *a, const char *iface, uint8_t ttl, uint64_t now_ms)
{
    ent *e = ttl ? touch(ver, a, iface, now_ms) : NULL;
    if (e)
        e->ttl = ttl;
}

uint8_t xipc_get_ttl(int ver, const uint8_t *a, const char *iface)
{
    unsigned b;
    ent *e = ver == 4 || ver == 6 ? find(ver, a, iface, &b) : NULL;
    return e ? e->ttl : 0;
}

void xipc_purge(uint64_t now_ms)
{
    uint64_t now = now_ms / 1000;
    if (!g_lifetime || now == g_purged)
        return;
    g_purged = now;
    for (size_t i = 0; i < g_nb; i++)
        for (ent **pe = &g_b[i]; *pe;) {
            ent *e = *pe;
            if (now >= e->last + g_lifetime) {
                *pe = e->next;
                ent_free(e);
                g_n--;
            } else {
                pe = &e->next;
            }
        }
}

/* ---- DNS (desync.c dns_extract_name, dns_skip_name, feed_dns_response) -- */

/* The name at a (a pointer, or labels without pointers) into name; the
 * byte after it, NULL when it does not fit or is cut */
static const uint8_t *extract_name(const uint8_t *a, const uint8_t *b, const uint8_t *e, char *name, size_t cap)
{
    const uint8_t *p;
    size_t nl = 0;
    int ptr = (*a & 0xC0) == 0xC0;
    if (ptr) {
        if (a + 1 >= e)
            return NULL;
        p = b + ((size_t)(*a & 0x3F) << 8 | a[1]);
    } else {
        p = a;
    }
    if (p >= e)
        return NULL;
    while (*p) {
        size_t y;
        if (nl) {
            if (nl >= cap)
                return NULL;
            name[nl++] = '.';
        }
        /* mixed pointer and labels are not supported (zapret2) */
        if ((*p & 0xC0) || p + *p + 1 >= e || (size_t)*p + 1 >= cap - nl)
            return NULL;
        y = *p++;
        for (size_t x = 0; x < y; x++, p++)
            name[nl + x] = (char)(*p >= 'A' && *p <= 'Z' ? *p + 32 : *p);
        nl += y;
    }
    if (nl >= cap)
        return NULL;
    name[nl] = 0;
    return ptr ? a + 2 : p + 1;
}

static int skip_name(const uint8_t **a, size_t *len)
{
    for (;;) {
        if (*len < 2)
            return -1;
        if ((**a & 0xC0) == 0xC0) {
            *a += 2, *len -= 2;
            return 0;
        }
        if (!**a) {
            (*a)++, (*len)--;
            return 0;
        }
        if (*len < (size_t)**a + 1)
            return -1;
        *len -= (size_t)**a + 1;
        *a += **a + 1;
    }
}

int xipc_dns_response(const uint8_t *d, size_t n, uint64_t now_ms)
{
    const uint8_t *a = d, *e = d + n, *p;
    size_t len = n;
    unsigned qcount, acount, k;
    char name[256] = "";
    int ct = 0;
    if (!g_hostname)
        return 0;
    if (n < 12)
        return -1;
    qcount = (unsigned)d[4] << 8 | d[5];
    acount = (unsigned)d[6] << 8 | d[7];
    if (!qcount || !(d[2] & 0x80) || !acount)
        return -1;
    a += 12, len -= 12;
    for (k = 0; k < qcount; k++) {
        unsigned typ;
        if (*name || !len)
            return -1; /* one question only */
        if (!(p = extract_name(a, d, e, name, sizeof(name))))
            return -1;
        len -= (size_t)(p - a);
        if (len < 4 || p[2] || p[3] != 1)
            return -1;
        typ = (unsigned)p[0] << 8 | p[1];
        if (typ != 1 && typ != 28)
            return -1;
        a = p + 4, len -= 4;
    }
    if (!*name)
        return -1;
    for (k = 0; k < acount; k++) {
        size_t dlen;
        if (skip_name(&a, &len) < 0 || len < 10)
            break;
        dlen = (size_t)a[8] << 8 | a[9];
        if (len < dlen + 10)
            break;
        if (a[2] == 0 && a[3] == 1) {
            unsigned typ = (unsigned)a[0] << 8 | a[1];
            if ((typ == 1 && dlen == 4) || (typ == 28 && dlen == 16)) {
                xipc_put_host(typ == 1 ? 4 : 6, a + 10, name, 0, now_ms);
                ct++;
            }
        }
        a += dlen + 10, len -= dlen + 10;
    }
    return ct;
}
