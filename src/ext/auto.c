/*
 * --ext-auto (auto.h).
 */
#include "auto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "detect.h"
#include "log.h"
#include "nflog.h"
#include "pkt.h"

#ifdef _WIN32
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#endif

#define NFLOG_RANGE 2048 /* bytes of each packet: a ClientHello, a redirect's head */

static struct {
    int on;
    uint16_t group;
    int first;
    xdet_config dc;
    nflog *nl;
    xdet *d;
    uint64_t lost, bad;
} g;

int xauto_on(void) { return g.on; }

void xauto_reset(void)
{
    xauto_close();
    memset(&g, 0, sizeof(g));
}

int xauto_parse(const args_t *a, fw_config *c, sbuf *err)
{
    const char *s = arg_str(a, "ext-auto", NULL);
    int64_t v;
    xauto_reset();
    if (!s) {
        static const char *const dep[] = {"ext-nflog-group", "ext-observe-first"};
        for (size_t i = 0; i < sizeof(dep) / sizeof(*dep); i++)
            if (arg_has(a, dep[i])) {
                sb_printf(err, "--%s is for --ext-auto", dep[i]);
                return -1;
            }
        return 0;
    }
    if (!strcmp(s, "propose") || !strcmp(s, "apply")) {
        sb_printf(err, "--ext-auto %s is not there yet: observe", s);
        return -1;
    }
    if (strcmp(s, "observe")) {
        sb_printf(err, "bad --ext-auto %s (observe)", s);
        return -1;
    }
    if (FW_WINDOWS) {
        sb_puts(err, "--ext-auto is Linux only for now");
        return -1;
    }
    if (c->forward || c->server_side) {
        sb_puts(err, "--ext-auto watches the client side: not with --server-side");
        return -1;
    }
    if (arg_int(a, "ext-nflog-group", c->queue, 0, 65535, &v) < 0)
        return -1;
    g.group = (uint16_t)v;
    if (arg_int(a, "ext-observe-first", XAUTO_FIRST, 4, 1000, &v) < 0)
        return -1;
    g.first = (int)v;
    xdet_config_default(&g.dc);
    g.on = 1;
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
    (void)ud;
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

/* ---- the observer ------------------------------------------------------------ */

static void ensure_detector(void)
{
    if (!g.d) {
        ct_config ct;
        xdet_sink s = {on_flow, on_key, NULL};
        ct_config_default(&ct);
        g.d = xdet_new(&g.dc, &ct, &s);
    }
}

void xauto_feed(const uint8_t *pkt, size_t len, uint64_t now_ms)
{
    gpkt *p;
    ensure_detector();
    p = pkt_parse(pkt, len);
    if (!p) {
        g.bad++;
        return;
    }
    xdet_packet(g.d, p, now_ms);
    pkt_free(p);
}

int xauto_open(sbuf *err)
{
    if (!g.on || g.nl)
        return 0;
    g.nl = nflog_open(g.group, NFLOG_RANGE, 1 << 20, err);
    if (!g.nl)
        return -1;
    ensure_detector();
    LOGI("auto", "observing the first %d packets of each flow (NFLOG group %u)", g.first, g.group);
    return 0;
}

void xauto_close(void)
{
    if (g.nl)
        nflog_close(g.nl);
    g.nl = NULL;
    xdet_free(g.d);
    g.d = NULL;
}

size_t xauto_pollfds(plat_pollfd *fds, size_t max)
{
    if (!g.nl || !max)
        return 0;
    memset(fds, 0, sizeof(*fds));
    fds->fd = nflog_fd(g.nl);
    fds->events = POLLIN;
    return 1;
}

static void on_msg(const nflog_msg *m, void *ctx)
{
    (void)ctx;
    xauto_feed(m->data, m->len, plat_now_ms());
}

void xauto_ready(const plat_pollfd *fds, size_t n)
{
    uint64_t lost = 0;
    if (!g.nl || !n || !(fds->revents & (POLLIN | POLLERR)))
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
    if (lost) {
        if (!g.lost)
            LOGW("auto", "the kernel dropped observed packets (a slow reader): detection sees less");
        g.lost += lost;
    }
}

void xauto_status(jw *w)
{
    xdet_stats s;
    jw_kstr(w, "auto", g.on ? "observe" : "off");
    if (!g.on)
        return;
    memset(&s, 0, sizeof(s));
    if (g.d)
        xdet_get_stats(g.d, &s);
    jw_kint(w, "nflog_group", g.group);
    jw_kbool(w, "observing", g.nl != NULL);
    jw_kuint(w, "packets", s.packets);
    jw_kuint(w, "lost", g.lost);
    jw_kuint(w, "flows", s.flows);
    jw_kuint(w, "flows_ok", s.flows_ok);
    jw_kuint(w, "flows_failed", s.flows_failed);
    jw_kuint(w, "keys", s.keys);
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
}
