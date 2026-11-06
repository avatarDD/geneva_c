/*
 * Combinators (docs/EXT_ROADMAP.md K6-K8): zapret2's orchestrators of
 * zapret-auto.lua as x-actions that steer the packet through their
 * subtrees.
 *
 *   xwhen{iff=COND;neg}(then,else)    condition, per_instance_condition
 *   xstop{iff=COND;neg}(rest)         stopif
 *   xrepeat{repeats=N;iff=COND;neg;stop;clear}(body,rest)   repeater
 *   xcutoff{dir=in|out|both}(rest)    instance_cutoff
 *
 * COND is one of zapret2's conditions (cond_true, cond_false, cond_random
 * with percent=, cond_payload_str with pattern=, cond_tcp_has_ts) or a
 * trigger expression of its own ("FLOW:n:<5", "TCP:flags:PA",
 * "L7:payload:empty"). cond_lua is not ported (decision 11.1).
 */
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "rng.h"
#include "xact.h"

enum { C_TRUE, C_FALSE, C_RANDOM, C_PAYLOAD, C_TCPTS, C_TRIG };

static const char *const cond_names[] = {"cond_true", "cond_false", "cond_random", "cond_payload_str",
                                         "cond_tcp_has_ts"};

static int cond_kind(const char *v)
{
    if (strchr(v, ':'))
        return C_TRIG;
    for (int i = 0; i < (int)ARRAY_LEN(cond_names); i++)
        if (!strcmp(v, cond_names[i]))
            return i;
    return -1;
}

static const char *iff_of(const xact *a)
{
    const char *v = xa_raw(a, "iff");
    return v ? v : "cond_true";
}

static int check_cond(const xact *a, int need_iff, sbuf *err)
{
    const char *n = a->kind->name, *v = xa_raw(a, "iff");
    int k;
    if (xa_has(a, "iff") && !v) {
        sb_printf(err, "%s: iff needs a condition", n);
        return -1;
    }
    if (!v && need_iff) {
        sb_printf(err, "%s: missing iff (a condition: cond_random, cond_payload_str, cond_tcp_has_ts, "
                       "cond_true, cond_false or a trigger such as FLOW:n:<5)", n);
        return -1;
    }
    v = iff_of(a);
    k = cond_kind(v);
    if (k < 0) {
        if (!strcmp(v, "cond_lua"))
            sb_printf(err, "%s: cond_lua is not supported (no Lua in geneva)", n);
        else
            sb_printf(err, "%s: unknown condition \"%s\"", n, v);
        return -1;
    }
    if (k == C_PAYLOAD && !xa_has(a, "pattern")) {
        sb_printf(err, "%s: cond_payload_str needs pattern", n);
        return -1;
    }
    if (xa_has(a, "percent") && k != C_RANDOM) {
        sb_printf(err, "%s: percent is for cond_random only", n);
        return -1;
    }
    if (xa_has(a, "pattern") && k != C_PAYLOAD) {
        sb_printf(err, "%s: pattern is for cond_payload_str only", n);
        return -1;
    }
    if (xa_check_num(a, "percent", 0, 100, err) < 0 || xa_check_flag(a, "neg", err) < 0)
        return -1;
    return 0;
}

/* what a combinator keeps: the kind of its condition, and the trigger */
typedef struct {
    int kind;
    int neg;
    trigger *t;
} xcond;

static void cond_release(xact *a)
{
    xcond *c = a->priv;
    if (c) {
        if (c->t) {
            trigger_clear(c->t);
            free(c->t);
        }
        free(c);
        a->priv = NULL;
    }
}

static int cond_prepare(xact *a, sbuf *err)
{
    xcond *c = xcalloc(1, sizeof(*c));
    a->priv = c;
    c->kind = cond_kind(iff_of(a));
    c->neg = xa_has(a, "neg");
    if (c->kind == C_TRIG) {
        sbuf e2;
        int rc;
        c->t = xcalloc(1, sizeof(*c->t));
        sb_init(&e2);
        rc = trigger_parse(c->t, iff_of(a), &e2);
        if (rc < 0) {
            sb_printf(err, "%s: %s", a->kind->name, e2.data);
            free(c->t);
            c->t = NULL;
        } else if (c->t->has_gas) {
            sb_printf(err, "%s: a condition has no gas", a->kind->name);
            rc = -1;
        }
        sb_free(&e2);
        if (rc < 0)
            return -1; /* freed with the action */
    }
    return 0;
}

static int has(const uint8_t *d, size_t n, const char *pat, size_t pl)
{
    if (!pl)
        return 1;
    for (size_t i = 0; i + pl <= n; i++)
        if (d[i] == (uint8_t)pat[0] && !memcmp(d + i, pat, pl))
            return 1;
    return 0;
}

static int has_ts(const gpkt *p)
{
    if (p->l4 != LAYER_TCP)
        return 0;
    for (int i = 0; i < p->nopts; i++)
        if (p->opts[i].kind == 8)
            return 1;
    return 0;
}

/* the condition on p: 1 or 0, -1 when it cannot be told (logged) */
static int cond(const xact *a, const gpkt *p, xrun *r)
{
    const xcond *c = a->priv;
    int v = 0;
    switch (c->kind) {
    case C_TRUE: v = 1; break;
    case C_FALSE: v = 0; break;
    case C_RANDOM: {
        int64_t pc;
        if (xa_num(r, "percent", 50, 0, 100, &pc) < 0)
            return -1;
        v = rng_range(0, 99) < pc;
        break;
    }
    case C_PAYLOAD: {
        size_t pl;
        const char *pat = xa_arg(r, "pattern", &pl);
        if (!pat)
            return -1;
        v = has(p->payload, p->payload_len, pat, pl);
        break;
    }
    case C_TCPTS: v = has_ts(p); break;
    case C_TRIG: v = trigger_match(c->t, p, r->env->xctx, r->env->dir); break;
    default: return -1;
    }
    return v ^ c->neg;
}

/* ---- xwhen ------------------------------------------------------------------------ */

static const char *const k_when[] = {"iff", "neg", "percent", "pattern", NULL};

static int check_when(const xact *a, sbuf *err) { return check_cond(a, 1, err); }

static void run_when(const xact *a, gpkt *p, xrun *r)
{
    int c = cond(a, p, r);
    if (c < 0) {
        pktlist_push(r->env->out, p); /* zapret2's error(): the instances after it do not run */
        return;
    }
    xa_log(r, "condition: %s", c ? "true" : "false");
    strat_xchild(r->env, c ? 0 : 1, p);
}

/* ---- xstop ------------------------------------------------------------------------ */

static void run_stop(const xact *a, gpkt *p, xrun *r)
{
    int c = cond(a, p, r);
    if (c) {
        if (c > 0)
            xa_log(r, "stopif: true");
        pktlist_push(r->env->out, p);
        return;
    }
    xa_log(r, "stopif: false");
    strat_xchild(r->env, 0, p);
}

/* ---- xrepeat ---------------------------------------------------------------------- */

static const char *const k_repeat[] = {"repeats", "iff", "neg", "percent", "pattern", "stop", "clear", NULL};

static int check_repeat(const xact *a, sbuf *err)
{
    if (!xa_has(a, "repeats")) {
        sb_puts(err, "xrepeat: missing repeats");
        return -1;
    }
    if (check_cond(a, 0, err) < 0 || xa_check_num(a, "repeats", 0, 100, err) < 0 ||
        xa_check_flag(a, "stop", err) < 0 || xa_check_flag(a, "clear", err) < 0)
        return -1;
    return 0;
}

/* The body runs on the packet up to repeats times, each time on what the
 * body before made of it (zapret2 runs the instances again on the same
 * dissect): the body's own packets are results, and of the packets that
 * came out of the original the last one goes on (the others are results). */
static void run_repeat(const xact *a, gpkt *p, xrun *r)
{
    pktlist *out = r->env->out;
    gpkt *cur = p;
    int64_t n;
    if (xa_num(r, "repeats", 0, 0, 100, &n) < 0) {
        pktlist_push(out, p);
        return;
    }
    for (int64_t i = 0; i < n; i++) {
        pktlist tmp = {NULL, 0, 0};
        size_t last = SIZE_MAX;
        int c = cond(a, cur, r);
        if (c < 0) {
            pktlist_push(out, cur);
            return;
        }
        if (!c) {
            xa_log(r, "break by iff");
            break;
        }
        xa_log(r, "%lld/%lld", (long long)i + 1, (long long)n);
        r->env->out = &tmp;
        strat_xchild(r->env, 0, cur);
        r->env->out = out;
        cur = NULL;
        for (size_t j = 0; j < tmp.n; j++)
            if (!tmp.v[j]->xgen)
                last = j;
        for (size_t j = 0; j < tmp.n; j++) {
            if (j == last)
                cur = tmp.v[j];
            else
                pktlist_push(out, tmp.v[j]);
        }
        free(tmp.v);
        if (!cur)
            return; /* the body absorbed the packet */
    }
    if (xa_has(a, "stop") || xa_has(a, "clear"))
        pktlist_push(out, cur);
    else
        strat_xchild(r->env, 1, cur);
}

/* ---- xcutoff ---------------------------------------------------------------------- */

static const char *const k_cutoff[] = {"dir", NULL};

static int check_cutoff(const xact *a, sbuf *err)
{
    const char *d = xa_raw(a, "dir");
    if (xa_has(a, "dir") && (!d || (strcmp(d, "in") && strcmp(d, "out") && strcmp(d, "both")))) {
        sb_puts(err, "xcutoff: dir is in, out or both");
        return -1;
    }
    return 0;
}

static void run_cutoff(const xact *a, gpkt *p, xrun *r)
{
    const char *d = xa_raw(a, "dir");
    int ok;
    if (r->pieces && r->piece < r->pieces) {
        /* a reassembled message: cut once its last piece went through, so
         * that the pieces before still meet the actions (replay_drop) */
        xa_pass(r, p);
        return;
    }
    if (!d) {
        ok = xtrig_cut(r->c, r->env->dir, r->env->tree, 0);
    } else {
        ok = 1;
        if (strcmp(d, "out"))
            ok &= xtrig_cut(r->c, DIR_IN, 0, 1);
        if (strcmp(d, "in"))
            ok &= xtrig_cut(r->c, DIR_OUT, 0, 1);
    }
    if (ok)
        xa_log(r, "cutoff %s", d ? d : "tree");
    else
        xa_log(r, "no flow to cut off");
    xa_pass(r, p);
}

const xa_kind xa_when = {"xwhen", 2, 1, 0, k_when, check_when, run_when, cond_prepare, cond_release};
const xa_kind xa_stop = {"xstop", 1, 1, 0, k_when, check_when, run_stop, cond_prepare, cond_release};
const xa_kind xa_repeat = {"xrepeat", 2, 1, 0, k_repeat, check_repeat, run_repeat, cond_prepare, cond_release};
const xa_kind xa_cutoffk = {"xcutoff", 1, 1, 0, k_cutoff, check_cutoff, run_cutoff, NULL, NULL};
