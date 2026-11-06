#include "ext.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#  include <net/if.h>
#endif

#include "engine_int.h"
#include "plat.h"
#include "xtrig.h"

/* Grows stage by stage (docs/EXT_ROADMAP.md, section 6.4). */
const char *const ext_features[] = {
    "ext", /* X0: the --ext switch */
#if GENEVA_EXT_CRYPTO
    "ext_crypto", /* X2: AES-GCM, HKDF; QUIC Initial decryption */
#endif
    "ext_ctrack", /* X3: conntrack, FLOW: and META: triggers */
    0,
};

static int g_active;
static ct_config g_ct;
static int g_ct_disable;

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
    strategy_set_xtrig(&xtrig_ops);
    g_active = 1;
    return 0;
}

void ext_deactivate(void)
{
    strategy_set_xtrig(NULL);
    g_active = 0;
}

/* ---- the engine hooks ------------------------------------------------------ */

typedef struct {
    uint32_t idx;
    char name[32];
} ifname_slot;

typedef struct {
    ctrack *ct;
    xpkt_ctx ctx;
    ifname_slot ifn[8]; /* the last interfaces seen */
    unsigned ifn_next;
} xworker;

static int xw_open(eng_worker *w, sbuf *err)
{
    xworker *x = xcalloc(1, sizeof(*x));
    (void)err;
    if (!g_ct_disable)
        x->ct = ctrack_new(&g_ct);
    w->x = x;
    return 0;
}

static void xw_close(eng_worker *w)
{
    xworker *x = w->x;
    if (!x)
        return;
    ctrack_free(x->ct);
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

static int xw_packet(eng_worker *w, strategy *st, gpkt *p, strat_dir dir, const uint8_t *data, size_t len,
                     const void *pctx)
{
    xworker *x = w->x;
    xpkt_ctx *c = &x->ctx;
    memset(c, 0, sizeof(*c));
    c->st = st;
    if (w->e->be->meta) {
        uint32_t in = 0, out = 0;
        w->e->be->meta(pctx, &c->mark, &in, &out);
        c->has_meta = 1;
        c->ifin = ifname(x, in);
        c->ifout = ifname(x, out);
    }
    if (x->ct)
        c->f = ctrack_feed(x->ct, p, plat_now_ms(), &c->reverse);
    if (st && c->f && !w->e->paused && xtrig_all_cut(st, dir, c->f)) {
        /* every tree is behind this flow: it passes by the strategy */
        engine_verdict(w, pctx, 1, data, len, 0);
        return 1;
    }
    w->xctx = c;
    return 0;
}

static const ext_hooks hooks = {xw_open, xw_close, xw_packet};

const ext_hooks *ext_engine_hooks(void) { return g_active ? &hooks : NULL; }

/* ---- apply --ext ----------------------------------------------------------- */

struct xoffline {
    ctrack *ct;
    xpkt_ctx ctx;
};

xoffline *xoff_new(void)
{
    xoffline *x;
    if (!g_active)
        return NULL;
    x = xcalloc(1, sizeof(*x));
    if (!g_ct_disable)
        x->ct = ctrack_new(&g_ct);
    return x;
}

void xoff_free(xoffline *x)
{
    if (!x)
        return;
    ctrack_free(x->ct);
    free(x);
}

void *xoff_packet(xoffline *x, const strategy *st, const gpkt *p, strat_dir dir, uint64_t now_ms, int *bypass)
{
    xpkt_ctx *c = &x->ctx;
    memset(c, 0, sizeof(*c));
    c->st = st;
    if (x->ct)
        c->f = ctrack_feed(x->ct, p, now_ms ? now_ms : 1, &c->reverse);
    *bypass = st && c->f && xtrig_all_cut(st, dir, c->f);
    return c;
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

void xoff_posdebug(const xoffline *x, strat_dir dir, const gpkt *p, sbuf *out)
{
    const xpkt_ctx *c = &x->ctx;
    const ct_flow *f = c->f;
    if (!f || (p->l4 != LAYER_TCP && p->l4 != LAYER_UDP)) {
        sb_puts(out, "posdebug: no track");
        return;
    }
    /* zapret2 picks the sides by the packet's direction (a client) */
    sb_printf(out, "posdebug: %s direct", dir == DIR_IN ? "in" : "out");
    pos_line(f, dir == DIR_IN ? &f->server : &f->client, out);
    sb_puts(out, " reverse");
    pos_line(f, dir == DIR_IN ? &f->client : &f->server, out);
    sb_printf(out, " payload %zu", p->payload_len);
}
