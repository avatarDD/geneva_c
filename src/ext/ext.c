#include "ext.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#  include <net/if.h>
#endif

#include "blob.h"
#include "engine_int.h"
#include "l7.h"
#include "plat.h"
#include "rawsend.h"
#include "xact.h"
#include "xl7.h"
#include "xtrig.h"

/* Grows stage by stage (docs/EXT_ROADMAP.md, section 6.4). */
const char *const ext_features[] = {
    "ext", /* X0: the --ext switch */
#if GENEVA_EXT_CRYPTO
    "ext_crypto", /* X2: AES-GCM, HKDF; QUIC Initial decryption */
#endif
    "ext_ctrack", /* X3: conntrack, FLOW: and META: triggers */
    "ext_l7",     /* X4: L7 recognition, reassembly, L7: triggers */
    "ext_xact",   /* X5: x-actions (xfake, xsplit, ...), blobs */
    0,
};

/* a held packet keeps the backend's whole context */
_Static_assert(XL7_PCTX >= PCTX_MAX, "XL7_PCTX < PCTX_MAX");

static int g_active;
static ct_config g_ct;
static int g_ct_disable;
static xl7_config g_l7;

/* --ext-payload-disable, --ext-reasm-disable: a payload list, "all" for
 * every type */
static int disable_list(const args_t *a, const char *opt, const char *cmd, uint64_t *set)
{
    const char *s = arg_str(a, opt, NULL);
    sbuf err;
    int neg = 0, r;
    *set = 0;
    if (!s)
        return 0;
    sb_init(&err);
    r = l7_payload_list(s, set, &neg, &err);
    if (!r && neg)
        r = -1, sb_printf(&err, "\"~\" makes no sense here");
    if (r < 0)
        fprintf(stderr, "geneva %s: bad --%s: %s\n", cmd, opt, err.data);
    else if (!*set)
        *set = ~0ULL;
    sb_free(&err);
    return r;
}

int ext_activate(const args_t *a, const char *cmd)
{
    const char *s;
    int64_t v;
    ct_config_default(&g_ct);
    g_ct_disable = 0;
    if ((s = arg_str(a, "ext-ctrack-timeouts", NULL)) && ct_timeouts_parse(s, &g_ct) < 0) {
        fprintf(stderr, "geneva %s: bad --ext-ctrack-timeouts %s (S:E:F[:U] in seconds)\n", cmd, s);
        return -1;
    }
    if (arg_has(a, "ext-ctrack-max")) {
        if (arg_int(a, "ext-ctrack-max", CT_DEFAULT_MAX, 16, 1 << 22, &v) < 0)
            return -1;
        g_ct.max = (size_t)v;
    }
    g_ct_disable = arg_has(a, "ext-ctrack-disable");
    if (arg_has(a, "ext-reasm-max")) {
        if (arg_int(a, "ext-reasm-max", XL7_REASM_MAX, 1024, 65536, &v) < 0)
            return -1;
        g_l7.reasm_max = (size_t)v;
    }
    if (disable_list(a, "ext-payload-disable", cmd, &g_l7.payload_disable) < 0 ||
        disable_list(a, "ext-reasm-disable", cmd, &g_l7.reasm_disable) < 0)
        return -1;
    blob_reset();
    {
        int idx = 0;
        const char *b;
        while ((b = arg_next(a, "ext-blob", &idx))) {
            sbuf err;
            sb_init(&err);
            if (blob_opt(b, &err) < 0) {
                fprintf(stderr, "geneva %s: bad --ext-blob: %s\n", cmd, err.data);
                sb_free(&err);
                blob_free_all();
                return -1;
            }
            sb_free(&err);
        }
    }
#ifdef __linux__
    rawsend_set_flags(RAWSEND_EXT | (arg_has(a, "ext-bind-fix4") ? RAWSEND_BIND4 : 0) |
                      (arg_has(a, "ext-bind-fix6") ? RAWSEND_BIND6 : 0));
#endif
    strategy_set_xtrig(&xtrig_ops);
    strategy_set_xact(&xact_ops);
    g_active = 1;
    return 0;
}

void ext_deactivate(void)
{
    strategy_set_xtrig(NULL);
    strategy_set_xact(NULL);
#ifdef __linux__
    rawsend_set_flags(0);
#endif
    blob_free_all();
    g_active = 0;
}

/* ---- the engine hooks ------------------------------------------------------ */

typedef struct {
    uint32_t idx;
    char name[32];
} ifname_slot;

typedef struct {
    ctrack *ct;
    xl7 *l7;
    xpkt_ctx ctx;
    xl7_view view;
    ifname_slot ifn[8]; /* the last interfaces seen */
    unsigned ifn_next;
    int closed; /* the capture is closed: held packets cannot get a verdict */
} xworker;

/* A held packet of a flow the conntrack forgets, or at the end: it goes
 * on as it is (v is NULL) */
static void xw_pass(void *ud, const uint8_t *raw, size_t len, strat_dir dir, const void *pctx, const xl7_view *v)
{
    (void)dir, (void)v;
    engine_verdict(ud, pctx, 1, raw, len, 0);
}

static void xw_clear(ct_flow *f, void *ud)
{
    eng_worker *w = ud;
    xworker *x = w->x;
    xl7_clear(f, x && !x->closed ? xw_pass : NULL, w);
    xact_flow_clear(f);
}

static int xw_open(eng_worker *w, sbuf *err)
{
    xworker *x = xcalloc(1, sizeof(*x));
    ct_config c = g_ct;
    (void)err;
    c.clear = xw_clear;
    c.clear_ud = w;
    w->x = x;
    if (!g_ct_disable)
        x->ct = ctrack_new(&c);
    x->l7 = xl7_new(&g_l7);
    return 0;
}

static void flush_flow(ct_flow *f, void *ud) { xw_clear(f, ud); }

/* Before the capture closes: what is held goes on as it is */
static void xw_flush(eng_worker *w)
{
    xworker *x = w->x;
    if (x && x->ct && !x->closed)
        ctrack_foreach(x->ct, flush_flow, w);
}

static void xw_close(eng_worker *w)
{
    xworker *x = w->x;
    if (!x)
        return;
    x->closed = 1; /* xw_flush gave held packets their verdicts */
    ctrack_free(x->ct);
    xl7_free(x->l7);
    free(x);
    w->x = NULL;
}

static const char *ifname(xworker *x, uint32_t idx)
{
    if (!idx)
        return NULL;
    for (unsigned i = 0; i < 8; i++)
        if (x->ifn[i].idx == idx)
            return x->ifn[i].name;
#ifdef __linux__
    {
        ifname_slot *s = &x->ifn[x->ifn_next++ % 8];
        char b[IF_NAMESIZE + 1];
        if (!if_indextoname(idx, b))
            return NULL;
        s->idx = idx;
        snprintf(s->name, sizeof(s->name), "%s", b);
        return s->name;
    }
#else
    return NULL;
#endif
}

static void meta(xworker *x, eng_worker *w, const void *pctx, xpkt_ctx *c)
{
    uint32_t in = 0, out = 0;
    if (!w->e->be->meta)
        return;
    w->e->be->meta(pctx, &c->mark, &in, &out);
    c->has_meta = 1;
    c->ifin = ifname(x, in);
    c->ifout = ifname(x, out);
}

typedef struct {
    eng_worker *w;
    strategy *st;
    const xpkt_ctx *base;
} xw_replay_ud;

/* A held packet back from xl7: through the strategy, with its verdict */
static void xw_replay(void *ud, const uint8_t *raw, size_t len, strat_dir dir, const void *pctx, const xl7_view *v)
{
    xw_replay_ud *u = ud;
    xpkt_ctx c = *u->base;
    if (!v) {
        xw_pass(u->w, raw, len, dir, pctx, v);
        return;
    }
    c.has_meta = 0;
    c.ifin = c.ifout = NULL;
    c.mark = 0;
    meta(u->w->x, u->w, pctx, &c);
    c.l7 = v;
    engine_replay(u->w, u->st, raw, len, dir, pctx, &c);
}

static int xw_packet(eng_worker *w, strategy *st, gpkt *p, strat_dir dir, const uint8_t *data, size_t len,
                     const void *pctx)
{
    xworker *x = w->x;
    xpkt_ctx *c = &x->ctx;
    xw_replay_ud u;
    int bypass, r;
    memset(c, 0, sizeof(*c));
    c->st = st;
    meta(x, w, pctx, c);
    if (x->ct)
        c->f = ctrack_feed(x->ct, p, plat_now_ms(), &c->reverse);
    /* every tree is behind this flow: it passes by the strategy */
    bypass = st && c->f && !w->e->paused && xtrig_all_cut(st, dir, c->f);
    u.w = w;
    u.st = st;
    u.base = c;
    r = xl7_packet(x->l7, c->f, c->reverse, p, dir, data, len, pctx, w->e->be->pctx_len,
                   st && !w->e->paused && !bypass, xw_replay, &u, &x->view);
    if (r == XL7_HOLD) {
        engine_hold(w);
        return 1;
    }
    if (bypass) {
        engine_verdict(w, pctx, 1, data, len, 0);
        return 1;
    }
    c->l7 = &x->view;
    w->xctx = c;
    return 0;
}

static const ext_hooks hooks = {xw_open, xw_close, xw_packet, xw_flush};

const ext_hooks *ext_engine_hooks(void) { return g_active ? &hooks : NULL; }

/* ---- apply --ext ----------------------------------------------------------- */

struct xoffline {
    ctrack *ct;
    xl7 *l7;
    xpkt_ctx ctx;
    xl7_view view;
    xoff_replay_fn fn; /* where held packets of forgotten flows go */
    void *ud;
};

/* A held packet of a flow the conntrack forgets: it goes as it is */
static void xo_clear(ct_flow *f, void *ud);

xoffline *xoff_new(void)
{
    xoffline *x;
    ct_config c = g_ct;
    if (!g_active)
        return NULL;
    x = xcalloc(1, sizeof(*x));
    c.clear = xo_clear;
    c.clear_ud = x;
    if (!g_ct_disable)
        x->ct = ctrack_new(&c);
    x->l7 = xl7_new(&g_l7);
    return x;
}

void xoff_free(xoffline *x)
{
    if (!x)
        return;
    x->fn = NULL; /* the end: nothing more is written */
    ctrack_free(x->ct);
    xl7_free(x->l7);
    free(x);
}

typedef struct {
    xoff_replay_fn fn;
    void *ud;
    const xpkt_ctx *base;
} xo_replay_ud;

static void xo_replay(void *ud, const uint8_t *raw, size_t len, strat_dir dir, const void *pctx, const xl7_view *v)
{
    xo_replay_ud *u = ud;
    xpkt_ctx c = *u->base;
    (void)pctx;
    c.l7 = v;
    u->fn(u->ud, raw, len, dir, v->piece, v->pieces, &c);
}

static void xo_pass(void *ud, const uint8_t *raw, size_t len, strat_dir dir, const void *pctx, const xl7_view *v)
{
    xoffline *x = ud;
    (void)pctx, (void)v;
    if (x->fn)
        x->fn(x->ud, raw, len, dir, 0, 0, NULL);
}

static void xo_clear(ct_flow *f, void *ud)
{
    xoffline *x = ud;
    xl7_clear(f, x->fn ? xo_pass : NULL, x);
    xact_flow_clear(f);
}

void *xoff_packet(xoffline *x, const strategy *st, const gpkt *p, strat_dir dir, uint64_t now_ms,
                  const uint8_t *raw, size_t rawlen, xoff_replay_fn fn, void *ud, int *verdict)
{
    xpkt_ctx *c = &x->ctx;
    xo_replay_ud u;
    int bypass;
    x->fn = fn;
    x->ud = ud;
    memset(c, 0, sizeof(*c));
    c->st = st;
    if (x->ct)
        c->f = ctrack_feed(x->ct, p, now_ms ? now_ms : 1, &c->reverse);
    bypass = st && c->f && xtrig_all_cut(st, dir, c->f);
    u.fn = fn;
    u.ud = ud;
    u.base = c;
    if (xl7_packet(x->l7, c->f, c->reverse, p, dir, raw, rawlen, NULL, 0, st && !bypass, xo_replay, &u,
                   &x->view) == XL7_HOLD) {
        *verdict = XOFF_HOLD;
        return NULL;
    }
    *verdict = bypass ? XOFF_BYPASS : XOFF_RUN;
    c->l7 = &x->view;
    return c;
}

typedef struct {
    const strategy *st;
    xo_replay_ud *u;
} xo_end_ud;

static void end_flow(ct_flow *f, void *ud)
{
    xo_end_ud *e = ud;
    xpkt_ctx c;
    if (!xl7_held(f))
        return;
    memset(&c, 0, sizeof(c));
    c.st = e->st;
    c.f = f;
    e->u->base = &c;
    xl7_flush(f, xo_replay, e->u);
}

void xoff_end(xoffline *x, const strategy *st, xoff_replay_fn fn, void *ud)
{
    xo_replay_ud u;
    xo_end_ud e;
    if (!x || !x->ct)
        return;
    u.fn = fn;
    u.ud = ud;
    u.base = NULL;
    e.st = st;
    e.u = &u;
    ctrack_foreach(x->ct, end_flow, &e);
}

static void pos_line(const ct_flow *f, const ct_side *s, sbuf *out)
{
    xside_view v;
    ct_view(s, &v);
    if (f->proto != 6)
        v.s = v.p = 0; /* zapret2 reads s and p from TCP flows only */
    sb_printf(out, " n%llu d%llu b%llu s%u p%u", (unsigned long long)v.n, (unsigned long long)v.d,
              (unsigned long long)v.b, v.s, v.p);
}

void xoff_posdebug(const void *xctx, strat_dir dir, const gpkt *p, sbuf *out)
{
    const xpkt_ctx *c = xctx;
    const ct_flow *f = c ? c->f : NULL;
    const ct_side *cli, *srv;
    if (!f || (p->l4 != LAYER_TCP && p->l4 != LAYER_UDP)) {
        sb_puts(out, "posdebug: no track");
        return;
    }
    /* a replayed piece: the sides as they were when it came (nfqws2's
     * tpos of a delayed packet) */
    cli = c->l7 && c->l7->cli ? c->l7->cli : &f->client;
    srv = c->l7 && c->l7->srv ? c->l7->srv : &f->server;
    /* zapret2 picks the sides by the packet's direction (a client) */
    sb_printf(out, "posdebug: %s direct", dir == DIR_IN ? "in" : "out");
    pos_line(f, dir == DIR_IN ? srv : cli, out);
    sb_puts(out, " reverse");
    pos_line(f, dir == DIR_IN ? cli : srv, out);
    sb_printf(out, " payload %zu", p->payload_len);
}
