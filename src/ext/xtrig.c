#include "xtrig.h"

#include <stdlib.h>
#include <string.h>

#include "l7.h"
#include "util.h"

enum { XT_RANGE, XT_STATE, XT_RETRANS, XT_IFIN, XT_IFOUT, XT_MARK, XT_PROTO, XT_PAYLOAD, XT_HOST };

typedef struct {
    int kind;
    int other;  /* XT_RANGE: the other side's counters */
    xrange r;
    int value;  /* XT_STATE, XT_RETRANS; XT_PROTO, XT_PAYLOAD: negated */
    char name[32];
    uint32_t mark, mask;
    uint64_t set; /* XT_PROTO, XT_PAYLOAD */
    char *hosts;  /* XT_HOST: the list as written, lowercased */
} xtrig;

/* "example.com,*cdn.net": a name and its subdomains, or with a leading "*"
 * any host that ends so */
static int host_list_ok(const char *v, sbuf *err)
{
    const char *p = v;
    for (;;) {
        const char *e = strchr(p, ',');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        size_t k = n && *p == '*' ? 1 : 0;
        if (n == k || n >= XL7_HOST_MAX) {
            sb_printf(err, "bad host \"%.*s\" in L7:host (a name, or *suffix)", (int)n, p);
            return -1;
        }
        for (; k < n; k++)
            if (p[k] == '*' || (unsigned char)p[k] <= ' ') {
                sb_printf(err, "bad host \"%.*s\" in L7:host (a name, or *suffix)", (int)n, p);
                return -1;
            }
        if (!e)
            return 0;
        p = e + 1;
    }
}

static int host_match(const char *list, const char *host)
{
    size_t hl = strlen(host);
    const char *p = list;
    for (;;) {
        const char *e = strchr(p, ',');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if (*p == '*') {
            if (n - 1 <= hl && !memcmp(host + hl - (n - 1), p + 1, n - 1))
                return 1;
        } else if (n <= hl && !memcmp(host + hl - n, p, n) && (n == hl || host[hl - n - 1] == '.')) {
            return 1;
        }
        if (!e)
            return 0;
        p = e + 1;
    }
}

static int parse(const char *layer, const char *field, const char *value, void **out, sbuf *err)
{
    xtrig t;
    memset(&t, 0, sizeof(t));
    if (str_ieq(layer, "FLOW")) {
        const char *f = field;
        if (f[0] == 'r' && f[1] && !f[2]) {
            t.other = 1;
            f++;
        }
        if (f[0] && !f[1] && strchr("ndbsp", f[0])) {
            t.kind = XT_RANGE;
            if (xrange_parse(value, f[0], &t.r, err) < 0)
                return -1;
        } else if (!strcmp(field, "state")) {
            t.kind = XT_STATE;
            if (!strcmp(value, "syn"))
                t.value = CT_SYN;
            else if (!strcmp(value, "est"))
                t.value = CT_EST;
            else if (!strcmp(value, "fin"))
                t.value = CT_FIN;
            else {
                sb_printf(err, "FLOW:state is syn, est or fin, not \"%s\"", value);
                return -1;
            }
        } else if (!strcmp(field, "retrans")) {
            t.kind = XT_RETRANS;
            if (strcmp(value, "0") && strcmp(value, "1")) {
                sb_printf(err, "FLOW:retrans is 0 or 1, not \"%s\"", value);
                return -1;
            }
            t.value = value[0] == '1';
        } else {
            sb_printf(err, "unknown field \"%s\" for FLOW in trigger (n, d, b, s, p, rn, rd, rb, rs, rp, state, retrans)",
                      field);
            return -1;
        }
    } else if (str_ieq(layer, "META")) {
        if (!strcmp(field, "ifin") || !strcmp(field, "ifout")) {
            t.kind = !strcmp(field, "ifin") ? XT_IFIN : XT_IFOUT;
            if (!*value || strlen(value) >= sizeof(t.name)) {
                sb_printf(err, "bad interface name \"%s\" in META:%s", value, field);
                return -1;
            }
            strcpy(t.name, value);
        } else if (!strcmp(field, "mark")) {
            char *end;
            unsigned long long m, k = 0xffffffffULL;
            t.kind = XT_MARK;
            m = strtoull(value, &end, 0);
            if (*end == '/')
                k = strtoull(end + 1, &end, 0);
            if (end == value || *end || m > 0xffffffffULL || k > 0xffffffffULL) {
                sb_printf(err, "META:mark is N or N/MASK, not \"%s\"", value);
                return -1;
            }
            if (m & ~k) {
                sb_printf(err, "META:mark %s has bits outside the mask: it never matches", value);
                return -1;
            }
            t.mark = (uint32_t)m;
            t.mask = (uint32_t)k;
        } else {
            sb_printf(err, "unknown field \"%s\" for META in trigger (ifin, ifout, mark)", field);
            return -1;
        }
    } else if (str_ieq(layer, "L7")) {
        if (!strcmp(field, "proto") || !strcmp(field, "payload")) {
            int neg = 0;
            t.kind = field[1] == 'r' ? XT_PROTO : XT_PAYLOAD;
            if ((t.kind == XT_PROTO ? l7_proto_list(value, &t.set, &neg, err)
                                    : l7_payload_list(value, &t.set, &neg, err)) < 0)
                return -1;
            t.value = neg;
        } else if (!strcmp(field, "host")) {
            t.kind = XT_HOST;
            if (host_list_ok(value, err) < 0)
                return -1;
            t.hosts = xstrdup(value);
            for (char *q = t.hosts; *q; q++)
                if (*q >= 'A' && *q <= 'Z')
                    *q = (char)(*q - 'A' + 'a');
        } else {
            sb_printf(err, "unknown field \"%s\" for L7 in trigger (proto, payload, host)", field);
            return -1;
        }
    } else {
        return 0;
    }
    *out = xmalloc(sizeof(t));
    memcpy(*out, &t, sizeof(t));
    return 1;
}

static const ct_side *side(const xpkt_ctx *c, int other)
{
    int srv = c->reverse ^ other;
    if (c->l7 && c->l7->cli) /* a replayed piece: the sides as it saw them */
        return srv ? c->l7->srv : c->l7->cli;
    return srv ? &c->f->server : &c->f->client;
}

/* the cut bits are about the strategy running: another one clears them */
static void cut_sync(const xpkt_ctx *c, ct_flow *f)
{
    int serial = c->st ? c->st->serial : 0;
    if (f->cut_serial != serial) {
        f->tree_cut[0] = f->tree_cut[1] = 0;
        f->all_cut[0] = f->all_cut[1] = 0;
        f->cut_serial = serial;
    }
}

static int match(const void *x, void *ctx, strat_dir dir, size_t tree, const gpkt *p)
{
    const xtrig *t = x;
    xpkt_ctx *c = ctx;
    xside_view v;
    ct_flow *f = c ? c->f : NULL;
    (void)p;
    switch (t->kind) {
    case XT_RANGE:
        if (!f)
            return xrange_in(NULL, &t->r);
        cut_sync(c, f); /* a tree already cut is not looked at (is_cut) */
        ct_view(side(c, t->other), &v);
        if (!t->other && xrange_cutoff(&v, &t->r)) {
            if (tree < CT_MAX_TREES)
                f->tree_cut[dir] |= 1ULL << tree;
            return 0;
        }
        return xrange_in(&v, &t->r);
    case XT_STATE:
        return f && f->state == t->value;
    case XT_RETRANS:
        return f && f->proto == 6 && p->payload_len && ct_is_retrans(side(c, 0)) == t->value;
    case XT_IFIN:
        return c && c->ifin && !strcmp(c->ifin, t->name);
    case XT_IFOUT:
        return c && c->ifout && !strcmp(c->ifout, t->name);
    case XT_MARK:
        return c && c->has_meta && (c->mark & t->mask) == t->mark;
    case XT_PROTO:
        return l7_proto_match(c && c->l7 ? c->l7->l7 : L7_UNKNOWN, t->set) != t->value;
    case XT_PAYLOAD:
        return l7_payload_match(c && c->l7 ? c->l7->l7p : (p->payload_len ? L7P_UNKNOWN : L7P_EMPTY), t->set) !=
               t->value;
    case XT_HOST:
        return c && c->l7 && c->l7->host && host_match(t->hosts, c->l7->host);
    }
    return 0;
}

static void *dup(const void *x)
{
    xtrig *d = xmalloc(sizeof(xtrig));
    memcpy(d, x, sizeof(xtrig));
    if (d->hosts)
        d->hosts = xstrdup(d->hosts);
    return d;
}

static void xfree(void *x)
{
    if (x)
        free(((xtrig *)x)->hosts);
    free(x);
}

static int is_cut(void *ctx, strat_dir dir, size_t tree)
{
    xpkt_ctx *c = ctx;
    if (!c || !c->f)
        return 0;
    cut_sync(c, c->f);
    return c->f->all_cut[dir] || (tree < CT_MAX_TREES && c->f->tree_cut[dir] >> tree & 1);
}

const strat_xtrig xtrig_ops = {parse, match, dup, xfree, is_cut};

int xtrig_cut(void *ctx, strat_dir dir, size_t tree, int all)
{
    xpkt_ctx *c = ctx;
    if (!c || !c->f)
        return 0;
    cut_sync(c, c->f);
    if (all) {
        c->f->tree_cut[dir] = ~0ULL;
        c->f->all_cut[dir] = 1;
    } else if (tree < CT_MAX_TREES) {
        c->f->tree_cut[dir] |= 1ULL << tree;
    } else {
        return 0;
    }
    return 1;
}

int xtrig_all_cut(const strategy *s, strat_dir dir, ct_flow *f)
{
    size_t n = dir == DIR_IN ? s->nin : s->nout;
    if (!f || f->cut_serial != s->serial || !n)
        return 0;
    if (f->all_cut[dir])
        return 1; /* xcutoff{dir=...}, or every tree below */
    if (n > CT_MAX_TREES)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (!(f->tree_cut[dir] >> i & 1))
            return 0;
    f->all_cut[dir] = 1;
    return 1;
}
