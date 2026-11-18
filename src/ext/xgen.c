/*
 * The genetic operators for x-actions (docs/EVOLVE.md, "x-действия"):
 * geneva evolve --ext makes new x-actions and changes the parameters of the
 * ones it has, as Geneva's mutate does for tamper and fragment. The values
 * are the ones zapret2's strategies and blockcheck2 use (markers, TTLs,
 * foolings, blobs, repeats, ...), drawn at random.
 *
 * A changed action is written as text and parsed again by xa_parse(), so
 * it passes the same checks as one a person writes; what the checks refuse
 * is drawn again.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blob.h"
#include "rng.h"
#include "xact.h"

/* ---- the actions the operators make ------------------------------------------- */

typedef struct {
    const char *name;
    unsigned char tcp, udp; /* transports it acts on */
    unsigned char out, in;  /* forests it is made in */
    unsigned char fool;     /* sends fakes: the fooling that breaks a packet (TTL,
                             * seq, md5, badsum, ...) is drawn; not for the real data */
    unsigned char w;        /* weight among new ones; 0: never made, only changed */
    const char *req;        /* keys a new one gets, ";"-separated */
} gkind;

/* Client-side actions only: the obfuscators (xwgobfs, xippxor, xudp2icmp,
 * xsynhide) need the other end, xlog, xtag, xpcap and xtlsclone do nothing a
 * censor sees on their own. xwsize changes the server's SYN,ACK, so it is
 * made in the inbound forest. */
static const gkind gkinds[] = {
    {"xfake", 1, 1, 1, 0, 1, 8, "blob"},
    {"xsplit", 1, 0, 1, 0, 0, 5, "pos"},
    {"xdisorder", 1, 0, 1, 0, 0, 5, "pos"},
    {"xfakedsplit", 1, 0, 1, 0, 1, 3, "pos"},
    {"xfakeddisorder", 1, 0, 1, 0, 1, 3, "pos"},
    {"xtcpseg", 1, 0, 1, 0, 0, 2, "pos"},
    {"xhostfake", 1, 0, 1, 0, 1, 2, ""},
    {"xtlsrec", 1, 0, 1, 0, 0, 2, "pos"},
    {"xoob", 1, 0, 1, 0, 0, 1, "urp"},
    {"xdrip", 1, 0, 1, 0, 0, 1, "n"},
    {"xrst", 1, 0, 1, 0, 1, 1, ""},
    {"xsyndata", 1, 0, 1, 0, 1, 1, ""},
    {"xsynack", 1, 0, 1, 0, 1, 1, ""},
    {"xwssize", 1, 0, 1, 0, 0, 1, "wsize;scale"},
    {"xwsize", 1, 0, 0, 1, 0, 1, "wsize;scale"},
    {"xhttp", 1, 0, 1, 0, 0, 1, "hostcase"},
    {"xsend", 1, 1, 1, 0, 0, 2, "ipfrag"},
    {"xmod", 1, 1, 1, 0, 0, 1, "ipid"},
    {"xudplen", 0, 1, 1, 0, 0, 2, "increment"},
    {"xdhtdn", 0, 1, 1, 0, 0, 1, "dn"},
    {"xrepeat", 1, 1, 1, 0, 0, 1, "repeats"},
    {"xwhen", 1, 1, 1, 0, 0, 1, "iff"},
    {"xcutoff", 1, 1, 1, 0, 0, 1, ""},
    {"xstop", 1, 1, 1, 0, 0, 0, "iff"},
    {"xsynacksplit", 1, 0, 1, 0, 0, 0, ""},
};

static const gkind *gkind_of(const char *name)
{
    for (size_t i = 0; i < ARRAY_LEN(gkinds); i++)
        if (!strcmp(gkinds[i].name, name))
            return &gkinds[i];
    return NULL;
}

static int fits(const gkind *k, const strat_xgen *g)
{
    if (!k->w || !(g->dir == DIR_IN ? k->in : k->out) || !((k->tcp && g->tcp) || (k->udp && g->udp)))
        return 0;
    return !g->skip || !*g->skip || !xa_in_list(g->skip, k->name);
}

/* ---- parameters ------------------------------------------------------------------ */

#define GP_MAX 24

typedef struct {
    char *k;
    char *v; /* NULL: a flag */
} gparam;

typedef struct {
    gparam p[GP_MAX];
    int n;
} plist;

static void pl_free(plist *l)
{
    for (int i = 0; i < l->n; i++) {
        free(l->p[i].k);
        free(l->p[i].v);
    }
    l->n = 0;
}

static int pl_find(const plist *l, const char *k)
{
    for (int i = 0; i < l->n; i++)
        if (!strcmp(l->p[i].k, k))
            return i;
    return -1;
}

static void pl_del(plist *l, int i)
{
    free(l->p[i].k);
    free(l->p[i].v);
    memmove(&l->p[i], &l->p[i + 1], (size_t)(l->n - i - 1) * sizeof(l->p[0]));
    l->n--;
}

static void pl_set(plist *l, const char *k, char *v)
{
    int i = pl_find(l, k);
    if (i >= 0) {
        free(l->p[i].v);
        l->p[i].v = v;
        return;
    }
    if (l->n == GP_MAX) {
        free(v);
        return;
    }
    l->p[l->n].k = xstrdup(k);
    l->p[l->n].v = v;
    l->n++;
}

/* "k=v;k2" or NULL without parameters (no braces) */
static char *pl_text(const plist *l)
{
    sbuf b;
    if (!l->n)
        return NULL;
    sb_init(&b);
    for (int i = 0; i < l->n; i++) {
        if (i)
            sb_putc(&b, ';');
        sb_puts(&b, l->p[i].k);
        if (l->p[i].v)
            sb_printf(&b, "=%s", l->p[i].v);
    }
    return sb_take(&b);
}

/* ---- values ------------------------------------------------------------------------- */

static const char *pick(const char *const *v, size_t n) { return v[rng_index(n)]; }
#define PICK(arr) pick(arr, ARRAY_LEN(arr))

/* a blob that fits the transports: a TLS record or an HTTP request for TCP,
 * the rest for UDP; the default fakes come up more often */
static int blob_tcp(const xblob *b)
{
    const uint8_t *d = b->data;
    size_t i = 0;
    if (b->len >= 2 && d[0] == 0x16 && d[1] == 0x03)
        return 1;
    while (i < b->len && i < 8 && d[i] >= 'A' && d[i] <= 'Z')
        i++;
    return i >= 3 && i < b->len && d[i] == ' ';
}

static void gen_blob(const strat_xgen *g, sbuf *v)
{
    const char *names[256];
    size_t n = 0;
    const xblob *b;
    const char *nm;
    if (rng_chance(0.4)) {
        static const char *const tcp[] = {"fake_default_tls", "fake_default_tls", "fake_default_http"};
        static const char *const udp[] = {"fake_quic_initial", "fake_default_quic"};
        const char *d = g->tcp && (!g->udp || rng_chance(0.5)) ? PICK(tcp) : PICK(udp);
        if (blob_find(d)) {
            sb_puts(v, d);
            return;
        }
    }
    for (size_t i = 0; n < ARRAY_LEN(names) && (nm = blob_name_at(i, &b)); i++) {
        int t = blob_tcp(b);
        if ((t && g->tcp) || (!t && g->udp))
            names[n++] = nm;
    }
    if (!n || rng_chance(0.1)) {
        /* a few bytes of one value, as the zero fakes of zapret2's UDP lines */
        int len = (int)rng_range(1, 64), byte = rng_chance(0.5) ? 0 : (int)rng_range(0, 255);
        sb_puts(v, "0x");
        for (int i = 0; i < len; i++)
            sb_printf(v, "%02x", byte);
        return;
    }
    sb_puts(v, names[rng_index(n)]);
}

/* a position marker: a number or a named place with an offset */
static void gen_marker(sbuf *v, int tls)
{
    static const char *const names[] = {"host", "endhost", "sld", "midsld", "endsld", "method", "extlen", "sniext"};
    static const char *const tlsn[] = {"host", "endhost", "sld", "midsld", "endsld", "extlen", "sniext"};
    if (rng_chance(0.4)) {
        static const int small[] = {1, 2, 3, 4, 5, 6, 8, 10, 16, 32};
        sb_printf(v, "%d", rng_chance(0.8) ? small[rng_index(ARRAY_LEN(small))] : (int)rng_range(1, 400));
        return;
    }
    sb_puts(v, tls ? PICK(tlsn) : PICK(names));
    if (rng_chance(0.3)) {
        int d = (int)rng_range(-2, 4);
        if (d)
            sb_printf(v, "%+d", d);
    }
}

static void gen_markers(sbuf *v, int n, int tls)
{
    for (int i = 0; i < n; i++) {
        if (i)
            sb_putc(v, ',');
        gen_marker(v, tls);
    }
}

static void gen_tlsmod(sbuf *v)
{
    static const char *const mods[] = {"rnd", "rndsni", "dupsid", "padencap"};
    static const char *const snis[] = {"www.google.com", "www.microsoft.com", "yandex.ru", "vk.com", "www.iana.org"};
    int any = 0;
    for (size_t i = 0; i < ARRAY_LEN(mods); i++)
        if (rng_chance(0.35)) {
            sb_printf(v, "%s%s", any ? "," : "", mods[i]);
            any = 1;
        }
    if (!any || rng_chance(0.2))
        sb_printf(v, "%ssni=%s", any ? "," : "", PICK(snis));
}

static void gen_flags(sbuf *v)
{
    static const char *const fl[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};
    size_t a = rng_index(ARRAY_LEN(fl)), b = rng_index(ARRAY_LEN(fl));
    sb_puts(v, fl[a]);
    if (b != a && rng_chance(0.3))
        sb_printf(v, ",%s", fl[b]);
}

static void gen_ip6ext(sbuf *v)
{
    static const char *const ext[] = {"hopbyhop", "hopbyhop2", "destopt", "destopt2", "routing", "ah"};
    size_t a = rng_index(ARRAY_LEN(ext)), b = rng_index(ARRAY_LEN(ext));
    sb_puts(v, ext[a]);
    if (b != a && rng_chance(0.3))
        sb_printf(v, ",%s", ext[b]);
}

static void gen_iff(const strat_xgen *g, sbuf *v)
{
    static const char *const tcp[] = {"L7:payload:tls_client_hello", "L7:payload:http_req", "cond_tcp_has_ts"};
    static const char *const udp[] = {"L7:payload:quic_initial"};
    static const char *const any[] = {"cond_random", "FLOW:n:1-2", "FLOW:d:1", "FLOW:n:<5", "L7:payload:known"};
    int r = (int)rng_index(3);
    if (r == 0 && g->tcp)
        sb_puts(v, PICK(tcp));
    else if (r == 1 && g->udp)
        sb_puts(v, PICK(udp));
    else
        sb_puts(v, PICK(any));
}

static int64_t gen_offset(const int64_t *common, size_t n, int64_t lo, int64_t hi)
{
    return rng_chance(0.7) ? common[rng_index(n)] : rng_range(lo, hi);
}

/* Draws a value of key for an action named kind. Returns 1 with the value
 * in v, 0 for a flag (no value), -1 when the key is never drawn (files,
 * interfaces, marks, delays: what a search has no business changing). */
static int gen_value(const char *kind, const char *key, const strat_xgen *g, sbuf *v)
{
    static const char *const flags[] = {"md5",      "badsum",  "tsup",    "nopdel",  "ipid_conn", "ipfrag",
                                        "ipfrag_disorder", "optional", "nodrop", "legacy",  "nofake1",
                                        "nofake2",  "nofake3", "nofake4", "rstack",  "neg",       "domcase",
                                        "methodeol", "unixeol"};
    int tls = g->tcp && !strcmp(kind, "xtlsrec");
    for (size_t i = 0; i < ARRAY_LEN(flags); i++)
        if (!strcmp(key, flags[i]))
            return 0;
    if (!strcmp(key, "ttl")) {
        if (rng_chance(0.6)) {
            sb_printf(v, "%d", (int)rng_range(1, 12));
        } else {
            static const int mx[] = {12, 16, 20, 32, 64};
            sb_printf(v, "auto:%d:%d-%d", -(int)rng_range(1, 4), (int)rng_range(1, 5), mx[rng_index(ARRAY_LEN(mx))]);
        }
    } else if (!strcmp(key, "seq") || !strcmp(key, "ack")) {
        static const int64_t c[] = {1, 100, 1000, 10000, 66000, 100000, 1000000};
        int64_t n = gen_offset(c, ARRAY_LEN(c), 1, 1 << 24);
        sb_printf(v, "%lld", (long long)(rng_chance(0.85) ? -n : n));
    } else if (!strcmp(key, "ts")) {
        static const int64_t c[] = {1000, 60000, 600000, 6000000};
        sb_printf(v, "%lld", -(long long)gen_offset(c, ARRAY_LEN(c), 1, 10000000));
    } else if (!strcmp(key, "flags+") || !strcmp(key, "flags-")) {
        gen_flags(v);
    } else if (!strcmp(key, "repeats")) {
        if (!strcmp(kind, "xrepeat"))
            sb_printf(v, "%d", (int)rng_range(2, 6));
        else
            sb_printf(v, "%d", rng_chance(0.7) ? (int)rng_range(1, 6) : (int)rng_range(7, 20));
    } else if (!strcmp(key, "ipid")) {
        static const char *const ids[] = {"seq", "rnd", "zero", "none"};
        sb_puts(v, PICK(ids));
    } else if (!strcmp(key, "ipfrag_pos_tcp")) {
        if (!g->tcp)
            return -1;
        sb_printf(v, "%d", 8 * (int)rng_range(1, 8));
    } else if (!strcmp(key, "ipfrag_pos_udp")) {
        if (!g->udp)
            return -1;
        sb_printf(v, "%d", 8 * (int)rng_range(1, 4));
    } else if (!strcmp(key, "ip6ext")) {
        gen_ip6ext(v);
    } else if (!strcmp(key, "payload")) {
        static const char *const pl[] = {"known", "all"};
        if (g->tcp && rng_chance(0.2))
            sb_puts(v, rng_chance(0.5) ? "tls_client_hello" : "http_req");
        else if (g->udp && rng_chance(0.2))
            sb_puts(v, "quic_initial");
        else
            sb_puts(v, PICK(pl));
    } else if (!strcmp(key, "pos")) {
        if (!strcmp(kind, "xtcpseg")) {
            if (rng_chance(0.5))
                sb_puts(v, "0,");
            else
                gen_marker(v, 0), sb_putc(v, ',');
            gen_marker(v, 0);
        } else if (!strcmp(kind, "xfakedsplit") || !strcmp(kind, "xfakeddisorder") || !strcmp(kind, "xtlsrec")) {
            gen_marker(v, tls);
        } else {
            gen_markers(v, rng_chance(0.6) ? 1 : (int)rng_range(2, 4), 0);
        }
    } else if (!strcmp(key, "midhost") || !strcmp(key, "disorder_after")) {
        gen_marker(v, 0);
    } else if (!strcmp(key, "seqovl")) {
        static const int64_t c[] = {1, 2, 5, 10, 100, 336, 568, 652};
        sb_printf(v, "%lld", (long long)gen_offset(c, ARRAY_LEN(c), 1, 700));
    } else if (!strcmp(key, "blob") || !strcmp(key, "pattern") || !strcmp(key, "seqovl_pattern")) {
        if (!strcmp(kind, "xwhen") || !strcmp(kind, "xstop") || !strcmp(kind, "xrepeat"))
            return -1; /* cond_payload_str's text */
        gen_blob(g, v);
    } else if (!strcmp(key, "tlsmod")) {
        gen_tlsmod(v);
    } else if (!strcmp(key, "urp")) {
        if (rng_chance(0.4))
            sb_puts(v, rng_chance(0.7) ? "b" : "e");
        else
            gen_marker(v, 0);
    } else if (!strcmp(key, "char")) {
        sb_printf(v, "%c", (char)('a' + rng_index(26)));
    } else if (!strcmp(key, "byte")) {
        sb_printf(v, "%d", (int)rng_range(0, 255));
    } else if (!strcmp(key, "n")) {
        sb_printf(v, "%d", (int)rng_range(2, 16));
    } else if (!strcmp(key, "delay")) {
        if (strcmp(kind, "xdrip"))
            return -1; /* xsend's pause holds the connection */
        sb_printf(v, "%d", (int)rng_range(0, 100));
    } else if (!strcmp(key, "wsize")) {
        sb_printf(v, "%d", rng_chance(0.7) ? (int)rng_range(1, 64) : (int)rng_range(65, 4096));
    } else if (!strcmp(key, "scale")) {
        sb_printf(v, "%d", (int)rng_range(0, 14));
    } else if (!strcmp(key, "hostcase")) {
        char h[5] = "host";
        if (rng_chance(0.5))
            return 0;
        for (int i = 0; i < 4; i++)
            if (rng_chance(0.5))
                h[i] = (char)(h[i] - 'a' + 'A');
        sb_puts(v, h);
    } else if (!strcmp(key, "increment")) {
        int64_t n = rng_range(1, 64);
        sb_printf(v, "%lld", (long long)(rng_chance(0.8) ? n : -n));
    } else if (!strcmp(key, "min")) {
        sb_printf(v, "%d", (int)rng_range(64, 1200));
    } else if (!strcmp(key, "max")) {
        sb_printf(v, "%d", (int)rng_range(1200, 1500));
    } else if (!strcmp(key, "dn")) {
        sb_printf(v, "%d", (int)rng_range(1, 10));
    } else if (!strcmp(key, "dir")) {
        static const char *const d[] = {"in", "out", "both"};
        sb_puts(v, PICK(d));
    } else if (!strcmp(key, "iff")) {
        gen_iff(g, v);
    } else if (!strcmp(key, "percent")) {
        sb_printf(v, "%d", (int)rng_range(1, 99));
    } else if (!strcmp(key, "mode")) {
        static const char *const m[] = {"syn", "synack", "acksyn"};
        sb_puts(v, PICK(m));
    } else {
        return -1;
    }
    return 1;
}

/* the common arguments a search draws (others: ifout, fwmark, the per-family
 * TTLs and fragment positions are left to people); the first ones break the
 * packet they are on, so only fakes get them */
static const char *const std_drawn[] = {"ttl",  "seq",  "ack",  "ts",  "md5",  "flags+", "flags-", "badsum",
                                        "ip6ext", "tsup", "nopdel", "repeats", "ipid", "ipid_conn", "ipfrag",
                                        "ipfrag_disorder", "ipfrag_pos_tcp", "ipfrag_pos_udp", "payload"};
#define STD_BREAKING 9

/* the keys of k that can be drawn, as k takes them */
static int drawable_keys(const xa_kind *k, const gkind *gk, const char **out, int max)
{
    int n = 0;
    for (size_t i = gk->fool ? 0 : STD_BREAKING; i < ARRAY_LEN(std_drawn) && n < max; i++)
        if (xa_canon_key(k, std_drawn[i]))
            out[n++] = std_drawn[i];
    for (int i = 0; k->keys && k->keys[i] && n < max; i++)
        out[n++] = k->keys[i];
    return n;
}

/* sets key to a drawn value; 0 when it cannot be drawn */
static int draw(const xa_kind *k, const char *key, const strat_xgen *g, plist *l)
{
    sbuf v;
    int r;
    sb_init(&v);
    r = gen_value(k->name, key, g, &v);
    if (r < 0) {
        sb_free(&v);
        return 0;
    }
    if (r == 0) {
        sb_free(&v);
        pl_set(l, key, NULL);
    } else {
        pl_set(l, key, sb_take(&v));
    }
    return 1;
}

static int add_one(const xa_kind *k, const gkind *gk, const strat_xgen *g, plist *l)
{
    const char *keys[64], *free_keys[64];
    int n = drawable_keys(k, gk, keys, 64), nf = 0;
    for (int i = 0; i < n; i++)
        if (pl_find(l, keys[i]) < 0)
            free_keys[nf++] = keys[i];
    for (int tries = 0; tries < 8 && nf; tries++)
        if (draw(k, free_keys[rng_index((size_t)nf)], g, l))
            return 1;
    return 0;
}

static void add_required(const xa_kind *k, const gkind *gk, const strat_xgen *g, plist *l)
{
    const char *p = gk->req;
    while (p && *p) {
        const char *e = strchr(p, ';');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        char key[32];
        if (n < sizeof(key)) {
            memcpy(key, p, n);
            key[n] = 0;
            if (pl_find(l, key) < 0)
                draw(k, key, g, l);
        }
        p = e ? e + 1 : NULL;
    }
}

/* parses the list as an action of k; 1 with *x when it passes the checks
 * and takes kids subtrees (-1: any) */
static int build(const xa_kind *k, const plist *l, const strat_xgen *g, int kids, void **x, int *got)
{
    char *text = pl_text(l);
    sbuf err;
    int rc;
    sb_init(&err);
    rc = xa_parse(k->name, text, g->dir, x, got, &err);
    free(text);
    sb_free(&err);
    if (rc != 1)
        return 0;
    if (kids >= 0 && *got != kids) {
        xa_free(*x);
        *x = NULL;
        return 0;
    }
    return 1;
}

/* ---- the operators ------------------------------------------------------------------ */

int xgen_random(const strat_xgen *g, void **x, int *kids)
{
    int total = 0;
    const gkind *gk = NULL;
    const xa_kind *k;
    for (size_t i = 0; i < ARRAY_LEN(gkinds); i++)
        if (fits(&gkinds[i], g) && xa_kind_find(gkinds[i].name))
            total += gkinds[i].w;
    if (!total)
        return 0;
    {
        int r = (int)rng_index((size_t)total);
        for (size_t i = 0; i < ARRAY_LEN(gkinds); i++) {
            if (!fits(&gkinds[i], g) || !xa_kind_find(gkinds[i].name))
                continue;
            if (r < gkinds[i].w) {
                gk = &gkinds[i];
                break;
            }
            r -= gkinds[i].w;
        }
    }
    k = xa_kind_find(gk->name);
    for (int tries = 0; tries < 32; tries++) {
        plist l = {.n = 0};
        int extra = (int)rng_index(3), ok;
        add_required(k, gk, g, &l);
        for (int i = 0; i < extra; i++)
            add_one(k, gk, g, &l);
        ok = build(k, &l, g, -1, x, kids);
        pl_free(&l);
        if (ok)
            return 1;
    }
    return 0;
}

/* another action that takes as many subtrees, keeping what parameters it
 * takes */
static const xa_kind *retype(const xa_kind *from, const strat_xgen *g, int kids, plist *l, const gkind **gk)
{
    const gkind *cand[ARRAY_LEN(gkinds)];
    size_t n = 0;
    const xa_kind *k;
    for (size_t i = 0; i < ARRAY_LEN(gkinds); i++) {
        const xa_kind *c = xa_kind_find(gkinds[i].name);
        if (c && c != from && c->kids == kids && fits(&gkinds[i], g))
            cand[n++] = &gkinds[i];
    }
    if (!n)
        return NULL;
    *gk = cand[rng_index(n)];
    k = xa_kind_find((*gk)->name);
    for (int i = l->n - 1; i >= 0; i--)
        if (!xa_canon_key(k, l->p[i].k))
            pl_del(l, i);
    add_required(k, *gk, g, l);
    return k;
}

int xgen_mutate(const strat_xgen *g, void **x, int kids)
{
    const xact *a = *x;
    const gkind *gk = gkind_of(a->kind->name);
    char *old;
    plist start = {.n = 0};
    if (!gk)
        return 0; /* the obfuscators, logs, captures, clones: left as written */
    for (int i = 0; i < a->np && i < GP_MAX; i++)
        pl_set(&start, a->p[i].k, a->p[i].v ? xstrdup(a->p[i].v) : NULL);
    old = pl_text(&start);
    for (int tries = 0; tries < 32; tries++) {
        plist l = {.n = 0};
        const xa_kind *k = a->kind;
        const gkind *nk = gk;
        double r = rng_real();
        void *nx = NULL;
        int got, ok = 0;
        char *text;
        for (int i = 0; i < start.n; i++)
            pl_set(&l, start.p[i].k, start.p[i].v ? xstrdup(start.p[i].v) : NULL);
        if (r < 0.15) {
            k = retype(a->kind, g, kids, &l, &nk);
            if (!k)
                k = a->kind;
        } else if (r < 0.60 && l.n) {
            /* a new value for a parameter that has one (a flag stays a
             * flag: it can only go) */
            int i = (int)rng_index((size_t)l.n);
            if (l.p[i].v) {
                char *key = xstrdup(l.p[i].k);
                draw(k, key, g, &l);
                free(key);
            } else {
                add_one(k, nk, g, &l);
            }
        } else if (r < 0.85 || !l.n) {
            add_one(k, nk, g, &l);
        } else {
            pl_del(&l, (int)rng_index((size_t)l.n));
        }
        text = pl_text(&l);
        if (k != a->kind || !text != !old || (text && strcmp(text, old)))
            ok = build(k, &l, g, kids, &nx, &got);
        free(text);
        pl_free(&l);
        if (ok) {
            xa_free(*x);
            *x = nx;
            free(old);
            pl_free(&start);
            return 1;
        }
    }
    free(old);
    pl_free(&start);
    return 0;
}
