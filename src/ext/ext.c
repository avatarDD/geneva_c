#include "ext.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#  include <net/if.h>
#endif

#include "auto.h"
#include "autolist.h"
#include "blob.h"
#include "engine_int.h"
#include "ipcache.h"
#include "l7.h"
#include "lists.h"
#include "ext_opt.h"
#include "json.h"
#include "log.h"
#include "plat.h"
#include "profile.h"
#include "rawsend.h"
#include "seqtrack.h"
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
    "ext_lists",   /* X6b: --hostlist*, --ipset*, gzip, reload_lists */
    "ext_autolist", /* X6c: --hostlist-auto*, --ext-ipcache-* */
    "ext_service",  /* X7a: @FILE, --dry-run, --daemon, --pidfile, --user/--uid, seccomp, syslog, ctl ext_flows/ext_keys */
    "ext_fw",       /* X7b: --ext-first, --ext-wan/--ext-lan, --ext-notrack, --ext-ttl-icmp, --ext-flowoffload, --fw-hook-*, --wf-* */
    "ext_selftest", /* X7c: geneva selftest --ext --fuzz N, fuzz targets for libFuzzer/AFL++ */
    "ext_auto",     /* X9: --ext-auto observe (NFLOG, detector), ext_flow/ext_impaired/ext_class, ext_status */
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
    xipc_reset();
    xah_debug_log(NULL);
    {
        int64_t life;
        int host = 0;
        if (arg_int(a, "ext-ipcache-lifetime", XIPC_LIFETIME, 0, 1 << 30, &life) < 0)
            return -1;
        if ((s = arg_str(a, "ext-ipcache-hostname", NULL))) {
            if (*s && strcmp(s, "0") && strcmp(s, "1")) {
                fprintf(stderr, "geneva %s: bad --ext-ipcache-hostname %s (0 or 1)\n", cmd, s);
                return -1;
            }
            host = strcmp(s, "0") != 0;
        }
        xipc_config((unsigned)life, host);
    }
    if ((s = arg_str(a, "hostlist-auto-debug", NULL)) && xah_debug_log(s) < 0) {
        fprintf(stderr, "geneva %s: cannot write --hostlist-auto-debug %s\n", cmd, s);
        return -1;
    }
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
    xipc_reset();
    xah_debug_log(NULL);
    xauto_reset();
    g_active = 0;
}

/* ---- profiles ---------------------------------------------------------------- */

/* p may be NULL for a packet of flow f (a replay). host: the host name as
 * the L7 found it (NULL: not known); hbuf holds it without its port. */
static void match_of(xmatch *m, const gpkt *p, const ct_flow *f, strat_dir dir, int l7, const char *host,
                     uint32_t mark, char *hbuf, size_t hcap)
{
    int out_server = (dir == DIR_OUT) != g_server_side; /* the packet goes to the server */
    memset(m, 0, sizeof(*m));
    m->mark = mark;
    m->l7 = l7 ? l7 : L7_UNKNOWN;
    if (host && *host) {
        m->host_ip = xhost_norm(host, hbuf, hcap);
        m->host = hbuf;
    }
    if (!p) {
        m->ver = f->ver;
        m->proto = f->proto;
        m->port = f->sport;
        m->ip = f->srv;
        return;
    }
    m->ver = p->ipver;
    m->proto = p->l4proto;
    m->ip = f ? f->srv : out_server ? p->dst : p->src;
    if (p->l4 == LAYER_TCP || p->l4 == LAYER_UDP) {
        /* the server's port (zapret2's sdport) */
        m->port = f ? f->sport : out_server ? p->dport : p->sport;
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

/* zapret2's ctrack->hostname: the host name the L7 found (once; it goes
 * into the ipcache for the server's address) or, for the client's packet
 * before the flow's first search, the one the ipcache has for the server */
static void flow_host(ct_flow *f, int reverse, const char *host, uint64_t now)
{
    char hb[XL7_HOST_MAX];
    int ip = 0;
    if (host && !f->chost_disc) {
        f->chost_ip = (uint8_t)xhost_norm(host, hb, sizeof(hb));
        free(f->chost);
        f->chost = xstrdup(hb);
        f->chost_disc = 1;
        xipc_put_host(f->ver, f->srv, hb, f->chost_ip, now);
    } else if (!host && !f->chost && !f->xprof_done && !reverse &&
               xipc_get_host(f->ver, f->srv, hb, sizeof(hb), &ip)) {
        f->chost = xstrdup(hb);
        f->chost_ip = (uint8_t)ip;
        LOGD("ipcache", "flow %u->%u: the cached host name %s", f->cport, f->sport, hb);
    }
}

/* The hostlist check of dp_rediscovery once the flow's host name is known:
 * a host that does not pass the lists of the flow's profile gets no
 * strategy (the profile stays the flow's: an autolist profile wins without
 * the check, then watches the host) */
static void flow_check(ct_flow *f)
{
    xprofile *P = g_prof.v[f->xprof];
    int excluded = 0;
    if (!f->chost_disc || f->xcheck || xprof_hostlists_empty(P))
        return;
    if (xprof_hosts(P, f->chost, f->chost_ip, &excluded)) {
        f->xcheck = 1;
        if (f->proto == 6 && f->ah_check)
            f->ah_retrans = XAH_RETRANS_STOP;
        return;
    }
    f->xcheck = 2;
    f->ah_check = P->ahl && !excluded;
    if (f->proto == 6 && !f->ah_check)
        f->ah_retrans = XAH_RETRANS_STOP;
    LOGD("profile", "flow %u->%u: %s does not pass the lists of profile %d%s", f->cport, f->sport, f->chost, P->n,
         f->ah_check ? ", the autolist watches it" : "");
}

/* The profile of p (dp_find with dp_rediscovery): its index, -1 for none.
 * A flow keeps its profile and looks again once its L7 protocol is known
 * and once its host name is; an ICMP error goes with its flow's profile
 * when it has one. p is NULL for a replayed packet of flow f; reverse: p
 * comes from the server. The strategy is not run (-1) for a host that
 * fails the lists of its flow's profile (f->xprof stays). */
static int pick(const gpkt *p, ct_flow *f, strat_dir dir, int reverse, int l7, const char *host, uint32_t mark,
                uint64_t now)
{
    xmatch m;
    char hb[XL7_HOST_MAX];
    int i, new_l7, new_host;
    l7 = l7 ? l7 : L7_UNKNOWN;
    if (host && !*host)
        host = NULL;
    if (!p && !f)
        return -1;
    if (f && p && p->l4 != LAYER_TCP && p->l4 != LAYER_UDP) {
        if (f->xprof_done && f->xprof >= 0)
            return f->xprof;
        f = NULL;
    }
    if (!f) {
        char cb[XL7_HOST_MAX];
        int ip;
        /* other IP protocols: the cached name of either address */
        if (!host && p->l4 != LAYER_TCP && p->l4 != LAYER_UDP &&
            (xipc_get_host(p->ipver, p->dst, cb, sizeof(cb), &ip) ||
             xipc_get_host(p->ipver, p->src, cb, sizeof(cb), &ip)))
            host = cb;
        match_of(&m, p, NULL, dir, l7, host, mark, hb, sizeof(hb));
        i = xprof_find(&g_prof, &m, 0);
        /* a name the L7 found is checked (dp_rediscovery), a cached one not */
        if (i >= 0 && host && host != cb && !xprof_hostlists_empty(g_prof.v[i]) &&
            !xprof_hosts(g_prof.v[i], m.host, m.host_ip, NULL))
            return -1;
        return i;
    }
    flow_host(f, reverse, host, now);
    new_l7 = f->xprof_l7 == L7_UNKNOWN && l7 != L7_UNKNOWN;
    new_host = f->chost_disc && !f->xprof_host;
    if (!f->xprof_done || new_l7 || new_host) {
        match_of(&m, p, f, dir, l7, f->chost, mark, hb, sizeof(hb));
        i = xprof_find(&g_prof, &m, 0);
        if (!f->xprof_done)
            log_prof("new", i, f);
        else if (i != f->xprof)
            log_prof(new_host ? "host known, changed" : "L7 known, changed", i, f);
        f->xprof = (int16_t)i;
        f->xprof_l7 = (uint8_t)l7;
        f->xprof_host = f->chost_disc;
        f->xcheck = 0;
        if (f->xprof_done < 255)
            f->xprof_done++;
    }
    if (f->xprof < 0)
        return -1;
    flow_check(f);
    return f->xcheck == 2 ? -1 : f->xprof;
}

/* zapret2's ipcache_update_ttl and ipcache_get_ttl: the TTL of the server's
 * first reply per server and interface, for autottl on the next flow */
static void flow_ttl(ct_flow *f, int reverse, const char *ifin, const char *ifout, uint64_t now)
{
    if (!f || g_server_side || (f->proto != 6 && f->proto != 17))
        return;
    if (reverse) {
        if (f->incoming_ttl)
            xipc_put_ttl(f->ver, f->srv, ifin, f->incoming_ttl, now);
        else
            f->incoming_ttl = xipc_get_ttl(f->ver, f->srv, ifin);
    } else if (!f->incoming_ttl) {
        f->incoming_ttl = xipc_get_ttl(f->ver, f->srv, ifout);
    }
}

/* The autolist's detection for p of flow f (autolist.h): TCP before the
 * second search (tcp = 1), UDP after it */
static void flow_autolist(int tcp, const gpkt *p, ct_flow *f, int reverse, int l7p, uint64_t now,
                          void (*send)(void *, const uint8_t *, size_t), void *ud)
{
    xprofile *P;
    xah_pkt k;
    if (!f || g_server_side || f->xprof < 0 || p->l4 != (tcp ? LAYER_TCP : LAYER_UDP))
        return;
    P = g_prof.v[f->xprof];
    if (!P->ahl)
        return;
    memset(&k, 0, sizeof(k));
    k.p = p;
    k.f = f;
    k.reverse = reverse;
    k.l7p = l7p;
    k.payload = p->payload;
    k.len = p->payload_len;
    k.now_ms = now;
    k.send = send;
    k.ud = ud;
    xah_purge(P, now);
    if (tcp)
        xah_tcp(P, &k);
    else
        xah_udp(P, &k);
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
    eng_worker *w = ud;
    (void)dir, (void)v;
    w->vdata = raw; /* a detached context sends these */
    w->vlen = len;
    engine_verdict(w, pctx, 1, raw, len, 0);
    w->vdata = NULL;
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
    /* one observer for the process, opened before the rules go up */
    return w->id == 0 ? xauto_open(err) : 0;
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
    if (w->id == 0)
        xauto_close();
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
        st = prof_st(pick(NULL, c.f, dir, c.reverse, v->l7, v->host, c.mark, plat_now_ms()), u->st);
    c.st = st;
    engine_replay(u->w, st, raw, len, dir, pctx, &c);
}

/* Could a profile with a strategy take p once its flow's L7 protocol and
 * host name are known? (a reassembly is then worth holding for) */
static int maybe_st(const gpkt *p, const ct_flow *f, strat_dir dir, uint32_t mark, strategy *cmd)
{
    xmatch m;
    char hb[XL7_HOST_MAX];
    match_of(&m, p, f, dir, L7_UNKNOWN, NULL, mark, hb, sizeof(hb));
    for (size_t i = 0; i < g_prof.n; i++)
        if (xprof_match(g_prof.v[i], &m, 1) && prof_st((int)i, cmd))
            return 1;
    return 0;
}

typedef struct {
    eng_worker *w;
    const void *pctx;
} xw_rst_ud;

/* The autolist's RST to the client: back the way the client's packet came
 * (NFQUEUE: the raw socket routes it). WinDivert would send it on in the
 * packet's direction, to the server: none there (docs/EXT.md). */
static void xw_rst(void *ud, const uint8_t *pkt, size_t len)
{
    xw_rst_ud *u = ud;
    if (!strcmp(u->w->e->be->name, "windivert")) {
        LOGD("autolist", "no RST to the client through WinDivert");
        return;
    }
    engine_inject(u->w, u->pctx, pkt, len);
}

/* After the first search: does the packet have a profile (zapret2 goes on
 * only with one)? Without profiles: does it have a strategy? */
static int found(const ct_flow *f, int i, const strategy *st)
{
    return !g_prof.n ? st != NULL : f ? f->xprof >= 0 : i >= 0;
}

typedef struct {
    eng_worker *w;
    const void *pctx;
} xw_emit_ud;

/* seqtrack's retransmission of a grown first message */
static void xw_emit(void *ud, const uint8_t *pkt, size_t len)
{
    xw_emit_ud *u = ud;
    engine_inject(u->w, u->pctx, pkt, len);
}

static int xw_packet(eng_worker *w, strategy **stp, gpkt *p, strat_dir dir, const uint8_t *data, size_t len,
                     const void *pctx)
{
    uint8_t *mb = NULL; /* p as seqtrack changed it */
    size_t ml = 0;
    xworker *x = w->x;
    xpkt_ctx *c = &x->ctx;
    xw_replay_ud u;
    xw_rst_ud ru;
    strategy *cmd = *stp, *st = cmd;
    uint64_t now = plat_now_ms();
    uint8_t kept[PCTX_MAX];
    const void *kp;
    int bypass, hold, r, i = -1, has;
    memset(c, 0, sizeof(*c));
    meta(x, w, pctx, c);
    xipc_purge(now);
    if (x->ct)
        c->f = ctrack_feed(x->ct, p, now, &c->reverse);
    if (c->f && c->f->xseq) {
        xw_emit_ud eu;
        eu.w = w;
        eu.pctx = pctx;
        switch (xseq_packet(c->f, c->reverse, p, ct_mss(c->f), xw_emit, &eu)) {
        case XSEQ_DROP:
            engine_verdict(w, pctx, 0, NULL, 0, 0);
            return 1;
        case XSEQ_MODIFIED:
            mb = pkt_bytes(p, &ml);
            if (ml) {
                data = mb;
                len = ml;
            }
            break;
        }
    }
    if (g_prof.n) {
        xlists_reload(now, 0);
        i = pick(p, c->f, dir, c->reverse, c->f ? c->f->l7proto : 0, c->f ? c->f->host : NULL, c->mark, now);
        st = prof_st(i, cmd);
    }
    c->st = st;
    if ((has = found(c->f, i, st)))
        flow_ttl(c->f, c->reverse, c->ifin, c->ifout, now);
    /* every tree is behind this flow: it passes by the strategy */
    bypass = st && c->f && !w->e->paused && xtrig_all_cut(st, dir, c->f);
    hold = !w->e->paused && !bypass &&
           (st || (g_prof.n && !(c->f && c->f->l7proto && c->f->chost_disc) &&
                   maybe_st(p, c->f, dir, c->mark, cmd)));
    u.w = w;
    u.st = cmd;
    u.base = c;
    /* what is held keeps a detached context: the captured packet goes now
     * and is sent anew later; only outgoing ones (an incoming packet sent
     * through a raw socket would not arrive as it came: --server-side) */
    kp = hold && dir == DIR_OUT ? engine_detach(w, pctx, kept) : pctx;
    r = xl7_packet(x->l7, c->f, c->reverse, p, dir, data, len, kp, w->e->be->pctx_len, hold, xw_replay, &u,
                   &x->view);
    if (has && g_prof.n) {
        ru.w = w;
        ru.pctx = pctx;
        flow_autolist(1, p, c->f, c->reverse, r == XL7_HOLD ? L7P_UNKNOWN : x->view.l7p, now, xw_rst, &ru);
    }
    if (r == XL7_HOLD) {
        engine_held(w, pctx, kp);
        free(mb);
        return 1;
    }
    if (has && x->view.l7p == L7P_DNS_RESPONSE && p->l4 == LAYER_UDP)
        xipc_dns_response(p->payload, p->payload_len, now);
    if (g_prof.n) {
        strategy *st2 = prof_st(pick(p, c->f, dir, c->reverse, x->view.l7, x->view.host, c->mark, now), cmd);
        if (has)
            flow_autolist(0, p, c->f, c->reverse, x->view.l7p, now, NULL, NULL);
        if (st2 != st) {
            st = c->st = st2;
            bypass = st && c->f && !w->e->paused && xtrig_all_cut(st, dir, c->f);
        }
    }
    if (bypass || (mb && ml && (w->e->paused || !st))) {
        /* (the engine would let the packet go as it came) */
        engine_verdict(w, pctx, 1, data, len, mb && ml);
        free(mb);
        return 1;
    }
    free(mb);
    c->l7 = &x->view;
    w->xctx = c;
    *stp = st;
    return 0;
}

/* "reload_lists": every list file read again */
/* ctl ext_flows: zapret2's conntrack dump (SIGUSR1 there) */
typedef struct {
    jw *w;
    uint64_t now;
    int64_t limit, n;
} flows_ud;

static void side_json(jw *w, const char *k, const ct_side *s, int tcp)
{
    jw_key(w, k);
    jw_obj(w);
    jw_kuint(w, "n", s->pcounter);
    jw_kuint(w, "d", s->pdcounter);
    jw_kuint(w, "b", s->pbcounter);
    if (tcp) {
        jw_kuint(w, "s", s->seq_last - s->seq0);
        jw_kuint(w, "win", s->winsize_calc);
        jw_kuint(w, "mss", s->mss);
    }
    jw_obj_end(w);
}

static void flow_json(ct_flow *f, void *ud)
{
    static const char *const st[] = {"syn", "est", "fin"};
    flows_ud *u = ud;
    jw *w = u->w;
    char a[INET6_ADDRSTRLEN];
    const char *l7;
    int af = f->ver == 6 ? AF_INET6 : AF_INET, tcp = f->proto == 6;
    if (u->n++ >= u->limit)
        return;
    jw_obj(w);
    jw_kstr(w, "proto", tcp ? "tcp" : f->proto == 17 ? "udp" : "other");
    inet_ntop(af, f->cli, a, sizeof(a));
    jw_kstr(w, "client", a);
    jw_kint(w, "cport", f->cport);
    inet_ntop(af, f->srv, a, sizeof(a));
    jw_kstr(w, "server", a);
    jw_kint(w, "sport", f->sport);
    if (tcp)
        jw_kstr(w, "state", f->state < 3 ? st[f->state] : "?");
    jw_kuint(w, "age_ms", u->now - f->t_start);
    jw_kuint(w, "idle_ms", u->now - f->t_last);
    if (f->xprof >= 0 && (size_t)f->xprof < g_prof.n && g_prof.v[f->xprof]->name)
        jw_kstr(w, "profile", g_prof.v[f->xprof]->name);
    if (f->xprof >= 0)
        jw_kint(w, "profile_n", f->xprof + 1);
    if (f->l7proto && (l7 = l7_proto_name(f->l7proto)) != NULL)
        jw_kstr(w, "l7", l7);
    if (f->chost)
        jw_kstr(w, "host", f->chost);
    else if (f->host)
        jw_kstr(w, "host", f->host);
    if (f->incoming_ttl)
        jw_kint(w, "incoming_ttl", f->incoming_ttl);
    if (f->ah_check)
        jw_kstr(w, "autolist", f->ah_final ? "decided" : "watched");
    side_json(w, "out", &f->client, tcp);
    side_json(w, "in", &f->server, tcp);
    jw_obj_end(w);
}

static int flows(engine *e, const json_val *req, jw *w, sbuf *err)
{
    flows_ud u;
    size_t total = 0;
    memset(&u, 0, sizeof(u));
    u.w = w;
    u.now = plat_now_ms();
    u.limit = req ? json_get_int(req, "limit", 1000) : 1000;
    if (u.limit < 0) {
        sb_puts(err, "limit must be 0 or more");
        return -1;
    }
    jw_key(w, "flows");
    jw_arr(w);
    for (unsigned i = 0; i < e->nw; i++) {
        xworker *x = e->w[i].x;
        if (x && x->ct) {
            total += ctrack_count(x->ct);
            ctrack_foreach(x->ct, flow_json, &u); /* the least recently active first */
        }
    }
    jw_arr_end(w);
    jw_kuint(w, "total", total);
    jw_kbool(w, "truncated", u.n > u.limit);
    jw_kbool(w, "ctrack", !g_ct_disable);
    return 1;
}

/* ctl ext_keys: what the extensions count per key; for now the autolist's
 * failures per host (zapret2's SIGUSR2 dump) */
static int keys(jw *w)
{
    uint64_t now = plat_now_ms() / 1000;
    jw_key(w, "autolist");
    jw_arr(w);
    for (size_t i = 0; i < g_prof.n; i++) {
        xprofile *p = g_prof.v[i];
        if (!p->ahl)
            continue;
        jw_obj(w);
        jw_kint(w, "profile_n", (int64_t)i + 1);
        if (p->name)
            jw_kstr(w, "profile", p->name);
        jw_kstr(w, "file", p->ahl->name);
        jw_key(w, "fails");
        jw_arr(w);
        for (size_t k = 0; k < p->nfails; k++) {
            jw_obj(w);
            jw_kstr(w, "host", p->fails[k].host);
            jw_kint(w, "count", p->fails[k].counter);
            jw_kint(w, "expire_s", p->fails[k].expire > now ? (int64_t)(p->fails[k].expire - now) : 0);
            jw_obj_end(w);
        }
        jw_arr_end(w);
        jw_obj_end(w);
    }
    jw_arr_end(w);
    return 1;
}

static int xw_control(engine *e, const char *cmd, const json_val *req, jw *w, sbuf *err)
{
    int n;
    if (!strcmp(cmd, "ext_flows"))
        return w ? flows(e, req, w, err) : 1;
    if (!strcmp(cmd, "ext_keys")) {
        if (w) {
            keys(w);
            xauto_keys(w);
        }
        return 1;
    }
    if (!strcmp(cmd, "ext_status")) {
        if (w)
            xauto_status(w);
        return 1;
    }
    if (strcmp(cmd, "reload_lists"))
        return 0;
    n = xlists_reload(plat_now_ms(), 1);
    LOGI("lists", "%d list file(s) read again", n);
    if (w)
        jw_kint(w, "files", n);
    return 1;
}

static size_t xw_pollfds(engine *e, plat_pollfd *fds, size_t max)
{
    (void)e;
    return xauto_pollfds(fds, max);
}

static void xw_ready(engine *e, const plat_pollfd *fds, size_t n)
{
    (void)e;
    xauto_ready(fds, n);
}

static const ext_hooks hooks = {xw_open, xw_close, xw_packet, xw_flush, xw_control, xw_pollfds, xw_ready};

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
    uint64_t now;
} xo_replay_ud;

static void xo_replay(void *ud, const uint8_t *raw, size_t len, strat_dir dir, const void *pctx, const xl7_view *v)
{
    xo_replay_ud *u = ud;
    xpkt_ctx c = *u->base;
    (void)pctx;
    c.l7 = v;
    if (g_prof.n)
        c.st = prof_st(pick(NULL, c.f, dir, c.reverse, v->l7, v->host, 0, u->now), u->cmd);
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

static void *xoff_packet2(xoffline *x, strategy **stp, gpkt *p, strat_dir dir, uint64_t now, const uint8_t *raw,
                          size_t rawlen, xoff_replay_fn fn, void *ud, int *verdict);

/* seqtrack's retransmission of a grown first message: written as it is */
static void xo_emit(void *ud, const uint8_t *pkt, size_t len)
{
    xoffline *x = ud;
    if (x->fn)
        x->fn(x->ud, pkt, len, DIR_OUT, 0, 0, NULL);
}

void *xoff_packet(xoffline *x, strategy **stp, gpkt *p, strat_dir dir, uint64_t now_ms, const uint8_t *raw,
                  size_t rawlen, xoff_replay_fn fn, void *ud, int *verdict)
{
    uint8_t *mb = NULL;
    size_t ml = 0;
    void *rc;
    xpkt_ctx *c = &x->ctx;
    uint64_t now = now_ms ? now_ms : 1;
    x->fn = fn;
    x->ud = ud;
    memset(c, 0, sizeof(*c));
    xipc_purge(now);
    if (x->ct)
        c->f = ctrack_feed(x->ct, p, now, &c->reverse);
    if (c->f && c->f->xseq) {
        switch (xseq_packet(c->f, c->reverse, p, ct_mss(c->f), xo_emit, x)) {
        case XSEQ_DROP:
            *verdict = XOFF_DROP;
            return NULL;
        case XSEQ_MODIFIED:
            mb = pkt_bytes(p, &ml);
            if (ml) {
                raw = mb;
                rawlen = ml;
            }
            break;
        }
    }
    rc = xoff_packet2(x, stp, p, dir, now, raw, rawlen, fn, ud, verdict);
    free(mb);
    return rc;
}

static void *xoff_packet2(xoffline *x, strategy **stp, gpkt *p, strat_dir dir, uint64_t now, const uint8_t *raw,
                          size_t rawlen, xoff_replay_fn fn, void *ud, int *verdict)
{
    xpkt_ctx *c = &x->ctx;
    xo_replay_ud u;
    strategy *cmd = *stp, *st = cmd;
    int bypass, hold, i = -1, has;
    if (g_prof.n) {
        i = pick(p, c->f, dir, c->reverse, c->f ? c->f->l7proto : 0, c->f ? c->f->host : NULL, 0, now);
        st = prof_st(i, cmd);
    }
    c->st = st;
    if ((has = found(c->f, i, st)))
        flow_ttl(c->f, c->reverse, NULL, NULL, now);
    bypass = st && c->f && xtrig_all_cut(st, dir, c->f);
    hold = !bypass && (st || (g_prof.n && !(c->f && c->f->l7proto && c->f->chost_disc) && maybe_st(p, c->f, dir, 0, cmd)));
    u.fn = fn;
    u.ud = ud;
    u.cmd = cmd;
    u.base = c;
    u.now = now;
    if (xl7_packet(x->l7, c->f, c->reverse, p, dir, raw, rawlen, NULL, 0, hold, xo_replay, &u, &x->view) ==
        XL7_HOLD) {
        if (has && g_prof.n)
            flow_autolist(1, p, c->f, c->reverse, L7P_UNKNOWN, now, NULL, NULL);
        *verdict = XOFF_HOLD;
        return NULL;
    }
    if (has && g_prof.n)
        flow_autolist(1, p, c->f, c->reverse, x->view.l7p, now, NULL, NULL);
    if (has && x->view.l7p == L7P_DNS_RESPONSE && p->l4 == LAYER_UDP)
        xipc_dns_response(p->payload, p->payload_len, now);
    if (g_prof.n) {
        strategy *st2 = prof_st(pick(p, c->f, dir, c->reverse, x->view.l7, x->view.host, 0, now), cmd);
        if (has)
            flow_autolist(0, p, c->f, c->reverse, x->view.l7p, now, NULL, NULL);
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
    u.now = 0;
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
