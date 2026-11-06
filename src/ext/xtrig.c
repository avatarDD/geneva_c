#include "xtrig.h"

#include <stdlib.h>
#include <string.h>

#include "util.h"

enum { XT_RANGE, XT_STATE, XT_RETRANS, XT_IFIN, XT_IFOUT, XT_MARK };

typedef struct {
    int kind;
    int other;  /* XT_RANGE: the other side's counters */
    xrange r;
    int value;  /* XT_STATE, XT_RETRANS */
    char name[32];
    uint32_t mark, mask;
} xtrig;

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
    return srv ? &c->f->server : &c->f->client;
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
        if (f->cut_serial != (c->st ? c->st->serial : 0)) {
            f->tree_cut[0] = f->tree_cut[1] = 0;
            f->all_cut[0] = f->all_cut[1] = 0;
            f->cut_serial = c->st ? c->st->serial : 0;
        }
        if (tree < CT_MAX_TREES && f->tree_cut[dir] >> tree & 1)
            return 0;
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
    }
    return 0;
}

static void *dup(const void *x)
{
    void *d = xmalloc(sizeof(xtrig));
    memcpy(d, x, sizeof(xtrig));
    return d;
}

static void xfree(void *x) { free(x); }

const strat_xtrig xtrig_ops = {parse, match, dup, xfree};

int xtrig_all_cut(const strategy *s, strat_dir dir, ct_flow *f)
{
    size_t n = dir == DIR_IN ? s->nin : s->nout;
    if (!f || f->cut_serial != s->serial || !n || n > CT_MAX_TREES)
        return 0;
    if (f->all_cut[dir])
        return 1;
    for (size_t i = 0; i < n; i++)
        if (!(f->tree_cut[dir] >> i & 1))
            return 0;
    f->all_cut[dir] = 1;
    return 1;
}
