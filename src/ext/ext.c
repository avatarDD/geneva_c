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
#include "ext_opt.h"
#include "log.h"
#include "plat.h"
#include "profile.h"
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
    "ext_profile", /* X6: profiles, --filter-*, --ext-profile */
    0,
};

/* a held packet keeps the backend's whole context */
_Static_assert(XL7_PCTX >= PCTX_MAX, "XL7_PCTX < PCTX_MAX");

static int g_active;
static ct_config g_ct;
static int g_ct_disable;
static xl7_config g_l7;
static xprofiles g_prof;
static int g_server_side; /* run --server-side: outbound packets come from the server's port */

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
    {
        args_t s0 = ext_cmd_args(a);
        sbuf err;
        sb_init(&err);
        xprof_free(&g_prof);
        if (xprof_build(a, arg_has(&s0, "strategy") || arg_has(&s0, "strategy-file"), &g_prof, &err) < 0) {
            fprintf(stderr, "geneva %s: %s\n", cmd, err.data);
            sb_free(&err);
            ext_deactivate();
            return -1;
        }
        sb_free(&err);
    }
    g_active = 1;
    return 0;
}

size_t ext_profiles(void) { return g_prof.n; }

int ext_profile_capture(fw_config *c, int ports, sbuf *err)
{
    xcapture x;
    if (xprof_capture(&g_prof, ports, &x, err) < 0)
        return -1;
    if (ports) {
        c->ports = x.ports;
        c->tcp = x.tcp;
        c->udp = x.udp;
    }
    c->icmp = x.icmp;
    memcpy(c->ipp, x.ipp, sizeof(x.ipp));
    c->nipp = x.nipp;
    return 0;
}

void ext_profile_list(sbuf *out)
{
    for (size_t i = 0; i < g_prof.n; i++) {
        const xprofile *p = g_prof.v[i];
        sb_puts(out, i ? "; " : "");
        xprof_label(p, out);
        sb_puts(out, p->cmd ? ": the command's strategy" : p->st ? ": its strategy" : ": no strategy");
    }
}

void ext_deactivate(void)
{
    strategy_set_xtrig(NULL);
    strategy_set_xact(NULL);
#ifdef __linux__
    rawsend_set_flags(0);
#endif
    blob_free_all();
    xprof_free(&g_prof);
    g_active = 0;
}

/* ---- profiles ---------------------------------------------------------------- */

/* p may be NULL for a packet of flow f (a replay) */
static void match_of(xmatch *m, const gpkt *p, const ct_flow *f, strat_dir dir, int l7, uint32_t mark)
{
    memset(m, 0, sizeof(*m));
    m->mark = mark;
    m->l7 = l7 ? l7 : L7_UNKNOWN;
    if (!p) {
        m->ver = f->ver;
        m->proto = f->proto;
        m->port = f->sport;
        return;
    }
    m->ver = p->ipver;
    m->proto = p->l4proto;
    if (p->l4 == LAYER_TCP || p->l4 == LAYER_UDP) {
        /* the server's port (zapret2's sdport) */
        m->port = f ? f->sport : (dir == DIR_OUT) != g_server_side ? p->dport : p->sport;
    } else if ((p->l4proto == 1 || p->l4proto == 58) && p->payload_len >= 2) {
        m->icmp_type = p->payload[0];
        m->icmp_code = p->payload[1];
    }
}

static void log_prof(const char *what, int i, const ct_flow *f)
{
    sbuf l;
    if (!log_enabled(LOG_DEBUG))
        return;
    sb_init(&l);
    if (i < 0)
        sb_puts(&l, "none");
    else
        xprof_label(g_prof.v[i], &l);
    LOGD("profile", "%s flow %u->%u: profile %s", what, f->cport, f->sport, l.data);
    sb_free(&l);
}

/* The profile of p (dp_find with dp_rediscovery): its index, -1 for none.
 * A flow keeps its profile and looks again once its L7 protocol is known;
 * an ICMP error goes with its flow's profile when it has one. p is NULL
 * for a replayed packet of flow f. */
static int pick(const gpkt *p, ct_flow *f, strat_dir dir, int l7, uint32_t mark)
{
    xmatch m;
    int i;
    l7 = l7 ? l7 : L7_UNKNOWN;
    if (!p && !f)
        return -1;
    if (f && p && p->l4 != LAYER_TCP && p->l4 != LAYER_UDP) {
        if (f->xprof_done && f->xprof >= 0)
            return f->xprof;
        f = NULL;
    }
    if (!f) {
        match_of(&m, p, NULL, dir, l7, mark);
        return xprof_find(&g_prof, &m, 0);
    }
    if (f->xprof_done && !(f->xprof_l7 == L7_UNKNOWN && l7 != L7_UNKNOWN))
        return f->xprof;
    match_of(&m, p, f, dir, l7, mark);
    i = xprof_find(&g_prof, &m, 0);
    if (!f->xprof_done)
        log_prof("new", i, f);
    else if (i != f->xprof)
        log_prof("L7 known, changed", i, f);
    f->xprof = (int16_t)i;
    f->xprof_l7 = (uint8_t)l7;
    f->xprof_done++;
    return i;
}

/* The strategy of profile i: profile 0 of the command line runs the
 * command's (cmd), the others their own; NULL: none (the packet passes) */
static strategy *prof_st(int i, strategy *cmd)
{
    const xprofile *p = i >= 0 ? g_prof.v[i] : NULL;
    return !p ? NULL : p->cmd ? cmd : p->st;
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
    g_server_side = w->e->o->fw.server_side;
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
    strategy *st; /* the command's (engine's) strategy */
    const xpkt_ctx *base;
} xw_replay_ud;

/* A held packet back from xl7: through its profile's strategy, with its
 * verdict */
static void xw_replay(void *ud, const uint8_t *raw, size_t len, strat_dir dir, const void *pctx, const xl7_view *v)
{
    xw_replay_ud *u = ud;
    xpkt_ctx c = *u->base;
    strategy *st = u->st;
    if (!v) {
        xw_pass(u->w, raw, len, dir, pctx, v);
        return;
    }
    c.has_meta = 0;
    c.ifin = c.ifout = NULL;
    c.mark = 0;
    meta(u->w->x, u->w, pctx, &c);
    c.l7 = v;
    if (g_prof.n)
        st = prof_st(pick(NULL, c.f, dir, v->l7, c.mark), u->st);
    c.st = st;
    engine_replay(u->w, st, raw, len, dir, pctx, &c);
}

/* Could a profile with a strategy take p once its flow's L7 protocol is
 * known? (a reassembly is then worth holding for) */
static int maybe_st(const gpkt *p, const ct_flow *f, strat_dir dir, uint32_t mark, strategy *cmd)
{
    xmatch m;
    match_of(&m, p, f, dir, L7_UNKNOWN, mark);
    for (size_t i = 0; i < g_prof.n; i++)
        if (xprof_match(g_prof.v[i], &m, 1) && prof_st((int)i, cmd))
            return 1;
    return 0;
}

static int xw_packet(eng_worker *w, strategy **stp, gpkt *p, strat_dir dir, const uint8_t *data, size_t len,
                     const void *pctx)
{
    xworker *x = w->x;
    xpkt_ctx *c = &x->ctx;
    xw_replay_ud u;
    strategy *cmd = *stp, *st = cmd;
    int bypass, hold, r;
    memset(c, 0, sizeof(*c));
    meta(x, w, pctx, c);
    if (x->ct)
        c->f = ctrack_feed(x->ct, p, plat_now_ms(), &c->reverse);
    if (g_prof.n)
        st = prof_st(pick(p, c->f, dir, c->f ? c->f->l7proto : 0, c->mark), cmd);
    c->st = st;
    /* every tree is behind this flow: it passes by the strategy */
    bypass = st && c->f && !w->e->paused && xtrig_all_cut(st, dir, c->f);
    hold = !w->e->paused && !bypass &&
           (st || (g_prof.n && !(c->f && c->f->l7proto) && maybe_st(p, c->f, dir, c->mark, cmd)));
    u.w = w;
    u.st = cmd;
    u.base = c;
    r = xl7_packet(x->l7, c->f, c->reverse, p, dir, data, len, pctx, w->e->be->pctx_len, hold, xw_replay, &u,
                   &x->view);
    if (r == XL7_HOLD) {
        engine_hold(w);
        return 1;
    }
    if (g_prof.n) {
        strategy *st2 = prof_st(pick(p, c->f, dir, x->view.l7, c->mark), cmd);
        if (st2 != st) {
            st = c->st = st2;
            bypass = st && c->f && !w->e->paused && xtrig_all_cut(st, dir, c->f);
        }
    }
    if (bypass) {
        engine_verdict(w, pctx, 1, data, len, 0);
        return 1;
    }
    c->l7 = &x->view;
    w->xctx = c;
    *stp = st;
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
    g_server_side = 0;
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
    strategy *cmd; /* the command's strategy */
    const xpkt_ctx *base;
} xo_replay_ud;

static void xo_replay(void *ud, const uint8_t *raw, size_t len, strat_dir dir, const void *pctx, const xl7_view *v)
{
    xo_replay_ud *u = ud;
    xpkt_ctx c = *u->base;
    (void)pctx;
    c.l7 = v;
    if (g_prof.n)
        c.st = prof_st(pick(NULL, c.f, dir, v->l7, 0), u->cmd);
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

void *xoff_packet(xoffline *x, strategy **stp, const gpkt *p, strat_dir dir, uint64_t now_ms, const uint8_t *raw,
                  size_t rawlen, xoff_replay_fn fn, void *ud, int *verdict)
{
    xpkt_ctx *c = &x->ctx;
    xo_replay_ud u;
    strategy *cmd = *stp, *st = cmd;
    int bypass, hold;
    x->fn = fn;
    x->ud = ud;
    memset(c, 0, sizeof(*c));
    if (x->ct)
        c->f = ctrack_feed(x->ct, p, now_ms ? now_ms : 1, &c->reverse);
    if (g_prof.n)
        st = prof_st(pick(p, c->f, dir, c->f ? c->f->l7proto : 0, 0), cmd);
    c->st = st;
    bypass = st && c->f && xtrig_all_cut(st, dir, c->f);
    hold = !bypass && (st || (g_prof.n && !(c->f && c->f->l7proto) && maybe_st(p, c->f, dir, 0, cmd)));
    u.fn = fn;
    u.ud = ud;
    u.cmd = cmd;
    u.base = c;
    if (xl7_packet(x->l7, c->f, c->reverse, p, dir, raw, rawlen, NULL, 0, hold, xo_replay, &u, &x->view) ==
        XL7_HOLD) {
        *verdict = XOFF_HOLD;
        return NULL;
    }
    if (g_prof.n) {
        strategy *st2 = prof_st(pick(p, c->f, dir, x->view.l7, 0), cmd);
        if (st2 != st) {
            st = c->st = st2;
            bypass = st && c->f && xtrig_all_cut(st, dir, c->f);
        }
    }
    *verdict = bypass || !st ? XOFF_BYPASS : XOFF_RUN;
    *stp = st;
    c->l7 = &x->view;
    return c;
}

typedef struct {
    strategy *st;
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

void xoff_end(xoffline *x, strategy *st, xoff_replay_fn fn, void *ud)
{
    xo_replay_ud u;
    xo_end_ud e;
    if (!x || !x->ct)
        return;
    u.fn = fn;
    u.ud = ud;
    u.cmd = st;
    u.base = NULL;
    e.st = st;
    e.u = &u;
    ctrack_foreach(x->ct, end_flow, &e);
}

strategy *xoff_strategy(const void *xctx)
{
    const xpkt_ctx *c = xctx;
    return c ? c->st : NULL;
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
