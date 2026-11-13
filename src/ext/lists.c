/*
 * List files (lists.h)
 */
#include "lists.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifndef _WIN32
#  include <limits.h>
#endif

#include "inflate.h"
#include "log.h"

#define XLIST_MAX_INFLATE ((size_t)1 << 30) /* 1 GiB of text at most */

static xlist **g_lists;
static size_t g_nlists;
static uint64_t g_next_check;

size_t xlists_count(void) { return g_nlists; }

static char *full_path(const char *path)
{
#ifdef _WIN32
    char b[4096];
    return _fullpath(b, path, sizeof(b)) ? xstrdup(b) : NULL;
#else
    char b[PATH_MAX];
    return realpath(path, b) ? xstrdup(b) : NULL;
#endif
}

/* file_mod_signature: 0, or -1 when stat fails */
static int sig(const char *path, int64_t *mtime, int64_t *ns, int64_t *size)
{
    struct stat st;
    if (stat(path, &st) < 0)
        return -1;
    *mtime = (int64_t)st.st_mtime;
#if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    *ns = (int64_t)st.st_mtim.tv_nsec;
#else
    *ns = 0;
#endif
    *size = (int64_t)st.st_size;
    return 0;
}

static void clear(xlist *l)
{
    xhs_free(&l->hs);
    xips_free(&l->ips);
}

static size_t parse(xlist *l, const char *d, size_t n, size_t *bad, char *first_bad, size_t cap)
{
    return l->ip ? xips_parse(&l->ips, d, n, bad, first_bad, cap) : xhs_parse(&l->hs, d, n);
}

/* Reads l's file into l (emptied first, as zapret2 does to spare memory):
 * a plain file line by line, a gzip or zlib one whole. Returns 0, or -1
 * with err (l stays empty). */
static int load(xlist *l, sbuf *err)
{
    enum { CHUNK = 65536 };
    size_t n = 0, bad = 0, have = 0, got;
    char *buf, first_bad[64] = "";
    int64_t mt, ns, sz;
    FILE *f;
    if (sig(l->path, &mt, &ns, &sz) < 0) {
        sb_printf(err, "cannot access %s: %s", l->name, strerror(errno));
        return -1;
    }
    clear(l);
    if (!(f = fopen(l->path, "rb"))) {
        sb_printf(err, "cannot read %s: %s", l->name, strerror(errno));
        l->failed = 1;
        return -1;
    }
    buf = xmalloc(CHUNK);
    got = fread(buf, 1, CHUNK, f);
    if (xinf_is_gzip((const uint8_t *)buf, got)) {
        /* gzip (zapret2's is_gzip: the magic): the whole file, then the
         * whole text */
        sbuf all;
        uint8_t *z;
        size_t zl;
        int r;
        sb_init(&all);
        sb_append(&all, buf, got);
        while ((got = fread(buf, 1, CHUNK, f)) > 0)
            sb_append(&all, buf, got);
        r = ferror(f) ? -1 : xinf_unwrap((const uint8_t *)all.data, all.len, XLIST_MAX_INFLATE, &z, &zl);
        sb_free(&all);
        if (r < 0) {
            sb_printf(err, "%s: %s", l->name, r == -2 ? "inflates to more than 1 GiB" : "bad or truncated gzip");
            goto fail;
        }
        n = parse(l, (const char *)z, zl, &bad, first_bad, sizeof(first_bad));
        free(z);
    } else {
        /* plain: whole lines from each chunk, the rest carried over */
        have = got;
        for (;;) {
            size_t cut = have;
            int eof = have < CHUNK && (feof(f) || ferror(f));
            if (!eof) {
                while (cut && buf[cut - 1] != '\n')
                    cut--;
                if (!cut)
                    cut = have; /* a line longer than the chunk is cut, as fgets does */
            }
            n += parse(l, buf, cut, &bad, first_bad, sizeof(first_bad));
            memmove(buf, buf + cut, have - cut);
            have -= cut;
            if (eof && !have)
                break;
            have += fread(buf + have, 1, CHUNK - have, f);
        }
        if (ferror(f)) {
            sb_printf(err, "cannot read %s", l->name);
            goto fail;
        }
    }
    fclose(f);
    free(buf);
    if (l->ip) {
        xips_finish(&l->ips);
        if (bad)
            LOGW("lists", "%s: %zu bad ip or subnet (the first: %s)", l->name, bad, first_bad);
    }
    if (l->autolist && !l->hs.n)
        xhs_add(&l->hs, "@&()", 4, 0); /* NonEmptyHostlist */
    l->mtime = mt;
    l->mtime_ns = ns;
    l->size = sz;
    l->failed = 0;
    LOGI("lists", "loaded %zu %s from %s", n, l->ip ? "ip/subnets" : "hosts", l->name);
    return 0;
fail:
    fclose(f);
    free(buf);
    clear(l);
    l->failed = 1;
    return -1;
}

static void reg(xlist *l)
{
    g_lists = xrealloc(g_lists, sizeof(*g_lists) * (g_nlists + 1));
    g_lists[g_nlists++] = l;
}

xlist *xlist_file(const char *path, int ip, sbuf *err)
{
    char *fp = full_path(path);
    xlist *l;
    if (!fp) {
        sb_printf(err, "cannot access %s: %s", path, strerror(errno));
        return NULL;
    }
    for (size_t i = 0; i < g_nlists; i++)
        if (g_lists[i]->path && g_lists[i]->ip == ip && !strcmp(g_lists[i]->path, fp)) {
            free(fp);
            return g_lists[i];
        }
    l = xcalloc(1, sizeof(*l));
    l->path = fp;
    l->name = xstrdup(path);
    l->ip = ip;
    if (load(l, err) < 0) {
        clear(l);
        free(l->path);
        free(l->name);
        free(l);
        return NULL;
    }
    reg(l);
    return l;
}

xlist *xlist_auto(const char *path, sbuf *err)
{
    FILE *f = fopen(path, "ab");
    uint8_t m[2] = {0, 0};
    xlist *l;
    if (!f) {
        sb_printf(err, "cannot create %s: %s", path, strerror(errno));
        return NULL;
    }
    fclose(f);
    if ((f = fopen(path, "rb"))) {
        size_t got = fread(m, 1, 2, f);
        fclose(f);
        if (xinf_is_gzip(m, got)) {
            sb_printf(err, "%s: an autolist cannot be in gzip", path);
            return NULL;
        }
    }
    if (!(l = xlist_file(path, 0, err)))
        return NULL;
    if (!l->autolist) {
        l->autolist = 1;
        if (!l->hs.n)
            xhs_add(&l->hs, "@&()", 4, 0);
    }
    return l;
}

int xlist_append(xlist *l, const char *host)
{
    FILE *f;
    int ok;
    xhs_add(&l->hs, host, strlen(host), 0);
    if (!l->path || !(f = fopen(l->path, "ab") /* "\n" lines on Windows too */))
        return -1;
    ok = fprintf(f, "%s\n", host) > 0;
    ok &= fclose(f) == 0;
    /* what we wrote is what is loaded: no reload for it */
    sig(l->path, &l->mtime, &l->mtime_ns, &l->size);
    return ok ? 0 : -1;
}

xlist *xlist_fixed(int ip)
{
    xlist *l = xcalloc(1, sizeof(*l));
    l->ip = ip;
    reg(l);
    return l;
}

static void unref(xlist *l)
{
    if (--l->refs > 0)
        return;
    for (size_t i = 0; i < g_nlists; i++)
        if (g_lists[i] == l) {
            g_lists[i] = g_lists[--g_nlists];
            break;
        }
    clear(l);
    free(l->path);
    free(l->name);
    free(l);
    if (!g_nlists) {
        free(g_lists);
        g_lists = NULL;
        g_next_check = 0;
    }
}

int xlistref_add(xlistref *r, xlist *l)
{
    for (size_t i = 0; i < r->n; i++)
        if (r->v[i] == l)
            return -1;
    r->v = xrealloc(r->v, sizeof(*r->v) * (r->n + 1));
    r->v[r->n++] = l;
    l->refs++;
    return 0;
}

void xlistref_free(xlistref *r)
{
    for (size_t i = 0; i < r->n; i++)
        unref(r->v[i]);
    free(r->v);
    r->v = NULL;
    r->n = 0;
}

void xlistref_copy(xlistref *to, const xlistref *from)
{
    for (size_t i = 0; i < from->n; i++)
        xlistref_add(to, from->v[i]);
}

int xlistref_empty(const xlistref *r)
{
    for (size_t i = 0; i < r->n; i++)
        if (r->v[i]->ip ? !xips_empty(&r->v[i]->ips) : r->v[i]->hs.n > 0)
            return 0;
    return 1;
}

int xlistref_ok(const xlistref *r)
{
    for (size_t i = 0; i < r->n; i++)
        if (r->v[i]->failed)
            return 0;
    return 1;
}

int xlists_host(const xlistref *inc, const xlistref *exc, const char *host, int no_subdom, int *excluded)
{
    if (excluded)
        *excluded = 0;
    for (size_t i = 0; i < exc->n; i++)
        if (xhs_search(&exc->v[i]->hs, host, no_subdom, NULL)) {
            if (excluded)
                *excluded = 1;
            return 0;
        }
    if (xlistref_empty(inc))
        return 1; /* zapret2: every include list empty, the check passes */
    for (size_t i = 0; i < inc->n; i++) {
        int ex;
        if (xhs_search(&inc->v[i]->hs, host, no_subdom, &ex))
            return 1;
        if (ex && inc->v[i]->autolist && excluded)
            *excluded = 1; /* in an autolist "!" is an exclusion */
    }
    return 0;
}

int xlists_ip(const xlistref *inc, const xlistref *exc, int ver, const uint8_t *ip)
{
    for (size_t i = 0; i < exc->n; i++)
        if (xips_has(&exc->v[i]->ips, ver, ip))
            return 0;
    if (xlistref_empty(inc))
        return 1;
    for (size_t i = 0; i < inc->n; i++)
        if (xips_has(&inc->v[i]->ips, ver, ip))
            return 1;
    return 0;
}

int xlists_reload(uint64_t now_ms, int force)
{
    int ct = 0;
    if (!force) {
        if (now_ms < g_next_check)
            return 0;
        g_next_check = now_ms + 1000;
    }
    for (size_t i = 0; i < g_nlists; i++) {
        xlist *l = g_lists[i];
        int64_t mt, ns, sz;
        sbuf err;
        if (!l->path)
            continue;
        if (sig(l->path, &mt, &ns, &sz) < 0) {
            LOGE("lists", "cannot access %s: %s; what was loaded stays", l->name, strerror(errno));
            continue;
        }
        if (!force && !l->failed && mt == l->mtime && ns == l->mtime_ns && sz == l->size)
            continue;
        {
            FILE *f = fopen(l->path, "rb"); /* file_open_test: an unreadable file keeps the list */
            if (!f) {
                LOGE("lists", "cannot open %s: %s; what was loaded stays", l->name, strerror(errno));
                continue;
            }
            fclose(f);
        }
        sb_init(&err);
        if (load(l, &err) < 0)
            LOGE("lists", "%s; the profiles with this list match nothing until it loads", err.data);
        else
            ct++;
        sb_free(&err);
    }
    return ct;
}
