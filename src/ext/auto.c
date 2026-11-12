/*
 * --ext-auto (auto.h).
 */
#include "auto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ctnl.h"
#include "detect.h"
#include "log.h"
#include "policy.h"
#include "treat.h"
#include "nflog.h"
#include "pkt.h"
#include "wdsniff.h"

#ifdef _WIN32
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#endif

#define NFLOG_RANGE 2048 /* bytes of each packet: a ClientHello, a redirect's head */

static struct {
    int on, mode;
    uint16_t group;
    int first;
    xdet_config dc;
    nflog *nl;
    wdsniff *sn;   /* Windows: the SNIFF handle instead of NFLOG */
    int priority;  /* of the engine's WinDivert handle */
    ctnl *cn;      /* the conntrack's counters (NULL: no volume classes) */
    xdet *d;
    uint64_t lost, bad, t_tick;
} g;

int xauto_on(void) { return g.on; }

void xauto_reset(void)
{
    xauto_close();
    xtreat_stop();
    xga_set(NULL, NULL);
    memset(&g, 0, sizeof(g));
}

/* --ext-ga [POP:GEN] */
static int ga_parse(const args_t *a, const fw_config *c, sbuf *err)
{
    xga_config gc;
    const char *v, *sc;
    char *end;
    long pop = 50, gen = 5;
    if (!arg_has(a, "ext-ga"))
        return 0;
    if (g.mode == XTR_OFF) {
        sb_puts(err, "--ext-ga is for --ext-auto propose or apply");
        return -1;
    }
    if (FW_WINDOWS) {
        sb_puts(err, "--ext-ga is Linux-only");
        return -1;
    }
    sc = arg_str(a, "ext-seccomp", NULL);
    if (!sc || strcmp(sc, "0")) {
        sb_puts(err, "--ext-ga starts geneva evolve: it needs --ext-seccomp 0");
        return -1;
    }
    if (arg_has(a, "user") || arg_has(a, "uid")) {
        sb_puts(err, "--ext-ga: the search needs root, not with --user or --uid");
        return -1;
    }
    v = arg_str(a, "ext-ga", "");
    if (*v) {
        pop = strtol(v, &end, 10);
        if (*end == ':')
            gen = strtol(end + 1, &end, 10);
        if (*end || pop < 2 || pop > 1000 || gen < 1 || gen > 100) {
            sb_printf(err, "bad --ext-ga %s (POP:GEN, population 2-1000, generations 1-100)", v);
            return -1;
        }
    }
    if (c->queue > 65535 - 64) {
        sb_puts(err, "--ext-ga takes the queue --queue+64: give a lower --queue");
        return -1;
    }
    memset(&gc, 0, sizeof(gc));
    gc.pop = (int)pop;
    gc.gen = (int)gen;
    gc.queue = (uint16_t)(c->queue + 64);
    gc.mark = c->mark;
    snprintf(gc.firewall, sizeof(gc.firewall), "%s", arg_str(a, "firewall", "auto"));
    snprintf(gc.rng_seed, sizeof(gc.rng_seed), "%s", arg_str(a, "rng-seed", ""));
    if ((v = arg_str(a, "log-file", NULL)) != NULL)
        snprintf(gc.log, sizeof(gc.log), "%s.ga", v);
    return xga_set(&gc, err);
}

int xauto_parse(const args_t *a, fw_config *c, sbuf *err)
{
    const char *s = arg_str(a, "ext-auto", NULL);
    int64_t v;
    xauto_reset();
    if (!s) {
        static const char *const dep[] = {"ext-nflog-group", "ext-observe-first", "ext-ga", "ext-treat-arms"};
        for (size_t i = 0; i < sizeof(dep) / sizeof(*dep); i++)
            if (arg_has(a, dep[i])) {
                sb_printf(err, "--%s is for --ext-auto", dep[i]);
                return -1;
            }
        return 0;
    }
    if (!strcmp(s, "observe"))
        g.mode = XTR_OFF;
    else if (!strcmp(s, "propose"))
        g.mode = XTR_PROPOSE;
    else if (!strcmp(s, "apply"))
        g.mode = XTR_APPLY;
    else {
        sb_printf(err, "bad --ext-auto %s (observe, propose, apply)", s);
        return -1;
    }
    if (c->forward || c->server_side) {
        sb_puts(err, "--ext-auto watches the client side: not with --server-side");
        return -1;
    }
    if (FW_WINDOWS && arg_has(a, "ext-nflog-group")) {
        sb_puts(err, "--ext-nflog-group: Windows observes through WinDivert");
        return -1;
    }
    if (arg_int(a, "ext-nflog-group", c->queue, 0, 65535, &v) < 0)
        return -1;
    g.group = (uint16_t)v;
    if (arg_int(a, "ext-observe-first", XAUTO_FIRST, 4, 1000, &v) < 0)
        return -1;
    g.first = (int)v;
    if (xtreat_start(g.mode, err) < 0 || ga_parse(a, c, err) < 0)
        return -1;
    if (arg_has(a, "ext-treat-arms")) {
        if (g.mode == XTR_OFF) {
            sb_puts(err, "--ext-treat-arms is for --ext-auto propose or apply");
            return -1;
        }
        if (xtreat_allow(arg_str(a, "ext-treat-arms", ""), err) < 0)
            return -1;
    }
    xdet_config_default(&g.dc);
    g.on = 1;
    if (FW_WINDOWS) {
        /* the SNIFF handle sees every packet: no rules, the detector
         * counts the bytes itself */
        g.dc.self_count = 1;
        g.priority = c->priority;
        return 0;
    }
    c->obs = 1;
    c->obs_group = g.group;
    c->obs_first = g.first;
    return 0;
}

/* ---- events ------------------------------------------------------------------ */

static void addr(const ct_flow *f, int srv, char *out, size_t cap)
{
    inet_ntop(f->ver == 6 ? AF_INET6 : AF_INET, srv ? f->srv : f->cli, out, (socklen_t)cap);
}

static void on_flow(void *ud, const xdet_flow_ev *ev)
{
    char c[64], s[64];
    (void)ud;
    xtreat_outcome(ev, plat_now_ms());
    if (ev->ok)
        return;
    addr(ev->f, 0, c, sizeof(c));
    addr(ev->f, 1, s, sizeof(s));
    LOGD("auto", "flow %s %s:%u -> %s:%u%s%s: %s (%s)", ev->f->proto == 6 ? "tcp" : "udp", c, ev->f->cport, s,
         ev->f->sport, ev->host ? " " : "", ev->host ? ev->host : "", xdet_class_name(ev->cls), ev->why);
    if (ev_enabled()) {
        ev_t e;
        ev_begin(&e, "ext_flow");
        jw_kstr(&e.w, "proto", ev->f->proto == 6 ? "tcp" : "udp");
        jw_kstr(&e.w, "client", c);
        jw_kint(&e.w, "cport", ev->f->cport);
        jw_kstr(&e.w, "server", s);
        jw_kint(&e.w, "sport", ev->f->sport);
        if (ev->host)
            jw_kstr(&e.w, "host", ev->host);
        jw_kstr(&e.w, "class", xdet_class_name(ev->cls));
        jw_kstr(&e.w, "why", ev->why);
        ev_emit(&e);
    }
}

static void on_key(void *ud, const xdet_key_ev *ev)
{
    int owned;
    (void)ud;
    /* the treatment first: a key in it stays impaired in the policy */
    owned = xtreat_key(ev, plat_now_ms());
    /* the policy the workers read (surgical path: an impaired key keeps
     * its connections in the queue) */
    if (!ev->class_change) {
        xpol_set(ev->key, ev->impaired || owned ? XPOL_IMPAIRED : XPOL_HEALTHY);
        xpol_publish();
    }
    if (ev->impaired)
        LOGI("auto", "%s %s %s: %s (%u of %u flows failed)", xdet_level_name(ev->level), ev->key,
             ev->class_change ? "changed its class" : "impaired", xdet_class_name(ev->cls), ev->fails, ev->flows);
    else
        LOGI("auto", "%s %s healthy again (%u of %u flows failed)", xdet_level_name(ev->level), ev->key, ev->fails,
             ev->flows);
    if (ev_enabled()) {
        ev_t e;
        ev_begin(&e, ev->class_change ? "ext_class" : "ext_impaired");
        jw_kstr(&e.w, "key", ev->key);
        jw_kstr(&e.w, "level", xdet_level_name(ev->level));
        if (!ev->class_change)
            jw_kbool(&e.w, "impaired", ev->impaired);
        if (ev->impaired)
            jw_kstr(&e.w, "class", xdet_class_name(ev->cls));
        jw_kuint(&e.w, "flows", ev->flows);
        jw_kuint(&e.w, "fails", ev->fails);
        ev_emit(&e);
    }
}

static void on_link(void *ud, int degraded, unsigned bad, unsigned active)
{
    (void)ud;
    if (degraded)
        LOGW("auto", "%u of %u addresses failed lately: the own link is likely degraded", bad, active);
    else
        LOGI("auto", "the link looks fine again (%u of %u addresses failed lately)", bad, active);
    if (ev_enabled()) {
        ev_t e;
        ev_begin(&e, "ext_link");
        jw_kbool(&e.w, "degraded", degraded);
        jw_kuint(&e.w, "bad", bad);
        jw_kuint(&e.w, "active", active);
        ev_emit(&e);
    }
}

/* ---- the observer ------------------------------------------------------------ */

static void ensure_detector(void)
{
    if (!g.d) {
        ct_config ct;
        xdet_sink s = {on_flow, on_key, on_link, NULL};
        ct_config_default(&ct);
        g.d = xdet_new(&g.dc, &ct, &s);
    }
}

/* out: 1 outbound, 0 inbound, -1 as NFLOG gives them (either) */
static void feed(const uint8_t *pkt, size_t len, uint64_t now_ms, int out)
{
    gpkt *p;
    ensure_detector();
    p = pkt_parse(pkt, len);
    if (!p) {
        g.bad++;
        return;
    }
    if (out < 0)
        xdet_packet(g.d, p, now_ms);
    else
        xdet_packet_dir(g.d, p, now_ms, out);
    pkt_free(p);
}

void xauto_feed(const uint8_t *pkt, size_t len, uint64_t now_ms) { feed(pkt, len, now_ms, -1); }

void xauto_feed_dir(const uint8_t *pkt, size_t len, uint64_t now_ms, int out) { feed(pkt, len, now_ms, out); }

int xauto_open(sbuf *err)
{
    if (!g.on || g.nl || g.sn)
        return 0;
    if (FW_WINDOWS) {
        int priv;
        /* above the engine's handle: the packets as they come, before the
         * strategy; its own sends pass under it */
        g.sn = wdsniff_open(g.priority + 1, NFLOG_RANGE, err, &priv);
        if (!g.sn)
            return -1;
        ensure_detector();
        g.t_tick = 0;
        LOGI("auto", "observing every packet through a WinDivert sniff handle");
        return 0;
    }
    g.nl = nflog_open(g.group, NFLOG_RANGE, 1 << 20, err);
    if (!g.nl)
        return -1;
    ensure_detector();
    {
        sbuf e;
        sb_init(&e);
        g.cn = ctnl_open(&e);
        if (!g.cn)
            LOGW("auto", "%s: no FREEZE_N and THROTTLE", e.len ? e.data : "ctnetlink");
        sb_free(&e);
    }
    g.t_tick = 0;
    LOGI("auto", "observing the first %d packets of each flow (NFLOG group %u)", g.first, g.group);
    return 0;
}

void xauto_close(void)
{
    xga_stop(); /* --ext-ga: the search takes its rules down */
    wdsniff_close(g.sn);
    g.sn = NULL;
    if (g.nl)
        nflog_close(g.nl);
    g.nl = NULL;
    ctnl_close(g.cn);
    g.cn = NULL;
    xdet_free(g.d);
    g.d = NULL;
}

size_t xauto_pollfds(plat_pollfd *fds, size_t max)
{
    size_t n = 0;
    if (g.sn && max) {
        memset(fds, 0, sizeof(*fds));
        fds->fd = wdsniff_fd(g.sn);
        fds->events = POLLIN;
        return 1;
    }
    if (!g.nl || !max)
        return 0;
    memset(fds, 0, sizeof(*fds) * (max < 2 ? 1 : 2));
    fds[n].fd = nflog_fd(g.nl);
    fds[n++].events = POLLIN;
    if (g.cn && max >= 2) {
        fds[n].fd = ctnl_fd(g.cn);
        fds[n++].events = POLLIN;
    }
    return n;
}

static void on_msg(const nflog_msg *m, void *ctx)
{
    (void)ctx;
    xauto_feed(m->data, m->len, plat_now_ms());
}

static void on_ctr(const ctnl_entry *e, void *ctx)
{
    xdet_ctr c;
    (void)ctx;
    memset(&c, 0, sizeof(c));
    c.t.ver = e->t.ver;
    c.t.proto = e->t.proto;
    memcpy(c.t.cli, e->t.src, 16);
    memcpy(c.t.srv, e->t.dst, 16);
    c.t.cport = e->t.sport;
    c.t.sport = e->t.dport;
    c.found = e->found;
    c.open = e->found && (e->t.proto != 6 || e->tcp_state == CTNL_TCP_ESTABLISHED);
    c.rbytes = e->rbytes;
    xdet_counters(g.d, &c, plat_now_ms());
}

static void on_req(void *ud, const xdet_tuple *t)
{
    ctnl_tuple c;
    int *full = ud;
    if (*full || !g.cn)
        return;
    memset(&c, 0, sizeof(c));
    c.ver = t->ver;
    c.proto = t->proto;
    memcpy(c.src, t->cli, 16);
    memcpy(c.dst, t->srv, 16);
    c.sport = t->cport;
    c.dport = t->sport;
    if (ctnl_request(g.cn, &c) < 0)
        *full = 1; /* the rest next second */
}

void xauto_tick(uint64_t now)
{
    int full = 0;
    /* the loop wakes at least once a second: a little short of 1000 ms
     * keeps the windows near one second instead of two */
    if (!g.d || (g.t_tick && now - g.t_tick < 950))
        return;
    g.t_tick = now;
    xdet_tick(g.d, now, g.cn ? on_req : NULL, &full);
    xtreat_tick(now);
}

static void read_counters(void)
{
    for (int i = 0; g.cn && i < 64; i++) {
        int r = ctnl_read(g.cn, on_ctr, NULL);
        if (r <= 0) {
            if (r < 0) {
                LOGW("auto", "ctnetlink read failed: no FREEZE_N and THROTTLE from now on");
                ctnl_close(g.cn);
                g.cn = NULL;
            }
            break;
        }
    }
}

static void on_sniff(const uint8_t *data, size_t len, int out, void *ctx)
{
    (void)ctx;
    xauto_feed_dir(data, len, plat_now_ms(), out);
}

static void lost_copies(uint64_t lost)
{
    if (!lost)
        return;
    if (!g.lost)
        LOGW("auto", "observed packets were dropped (a slow reader): detection sees less");
    g.lost += lost;
}

void xauto_ready(const plat_pollfd *fds, size_t n)
{
    uint64_t lost = 0;
    if (g.sn && n) {
        /* a bounded batch, as below: the engine's receiver waits for the
         * lock meanwhile; what is left wakes the loop again */
        if (fds->revents & (POLLIN | POLLERR) && wdsniff_read(g.sn, 256, on_sniff, NULL, &lost) < 0) {
            LOGW("auto", "the WinDivert sniff handle failed: the observation stops");
            wdsniff_close(g.sn);
            g.sn = NULL;
        }
        lost_copies(lost);
        xauto_tick(plat_now_ms());
        return;
    }
    if (!g.nl || !n)
        return;
    if (n > 1 && fds[1].revents & (POLLIN | POLLERR))
        read_counters();
    xauto_tick(plat_now_ms());
    if (!g.nl || !(fds->revents & (POLLIN | POLLERR)))
        return;
    /* a bounded batch: the queue and the control socket wait meanwhile */
    for (int i = 0; i < 64; i++) {
        int r = nflog_read(g.nl, on_msg, NULL, &lost);
        if (r <= 0) {
            if (r < 0)
                LOGW("auto", "NFLOG read failed: the observation stops");
            if (r < 0)
                nflog_close(g.nl), g.nl = NULL;
            break;
        }
    }
    lost_copies(lost);
}

void xauto_status(jw *w)
{
    xdet_stats s;
    static const char *const mode[] = {"observe", "propose", "apply"};
    jw_kstr(w, "auto", g.on ? mode[g.mode] : "off");
    if (!g.on)
        return;
    xtreat_status(w);
    memset(&s, 0, sizeof(s));
    if (g.d)
        xdet_get_stats(g.d, &s);
    jw_kstr(w, "source", FW_WINDOWS ? "windivert" : "nflog");
    if (!FW_WINDOWS)
        jw_kint(w, "nflog_group", g.group);
    jw_kbool(w, "observing", g.nl != NULL || g.sn != NULL);
    jw_kuint(w, "packets", s.packets);
    jw_kuint(w, "lost", g.lost);
    jw_kuint(w, "flows", s.flows);
    jw_kuint(w, "flows_ok", s.flows_ok);
    jw_kuint(w, "flows_failed", s.flows_failed);
    jw_kuint(w, "keys", s.keys);
    jw_kbool(w, "counters", g.cn != NULL || g.dc.self_count);
    jw_kuint(w, "watched", s.watched);
    jw_kuint(w, "capacity", (uint64_t)s.capacity);
    jw_kbool(w, "link_degraded", s.link_degraded);
    jw_key(w, "impaired");
    if (g.d)
        xdet_keys_json(g.d, w, 1);
    else
        jw_arr(w), jw_arr_end(w);
}

void xauto_keys(jw *w)
{
    if (!g.on)
        return;
    jw_key(w, "detect");
    if (g.d)
        xdet_keys_json(g.d, w, 0);
    else
        jw_arr(w), jw_arr_end(w);
    xtreat_keys(w, 256);
}
