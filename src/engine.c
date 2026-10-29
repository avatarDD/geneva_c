#include "engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "geneva.h"
#include "log.h"
#include "plat.h"
#include "strategy.h"
#include "util.h"

void engine_opts_default(engine_opts *o)
{
    memset(o, 0, sizeof(*o));
    fw_config_default(&o->fw);
    o->apply_fw = 1;
    o->stats_interval = 0;
    o->queue_maxlen = 4096;
    o->fail_open = 1;
    o->max_delayed = 1024;
}

#ifdef __linux__

#include <errno.h>
#include <signal.h>
#include <poll.h>

#include "ctl.h"
#include "nfq.h"
#include "pcap.h"
#include "rawsend.h"

/* A packet waiting for its sleep to end: either a held NFQUEUE packet that
 * gets its verdict then, or bytes for a raw send. */
typedef struct {
    uint64_t due;
    uint64_t order; /* FIFO among equal due times */
    uint8_t *data;
    size_t len;
    int verdict;
    uint32_t id;
} delayed;

typedef struct {
    uint64_t pkts_out, pkts_in, triggered, accepted, modified, dropped;
    uint64_t injected, delayed, send_errors, verdict_errors, parse_errors, overruns;
} counters;

typedef struct {
    engine_opts *o;
    nfq *q;
    rawsend *rs;
    strategy *st;
    pcap_writer *pw;
    counters c;
    delayed *dl; /* min-heap by (due, order) */
    size_t ndl, capdl;
    uint64_t dl_order;
    uint64_t start_ms;
    sbuf line;
    ctl *ctl;
    int paused;       /* packets pass unchanged */
    int stop_request; /* "stop" over the control socket */
} engine;

static volatile sig_atomic_t sig_stop, sig_hup, sig_usr1;

static void on_signal(int sig)
{
    if (sig == SIGHUP)
        sig_hup = 1;
    else if (sig == SIGUSR1)
        sig_usr1 = 1;
    else
        sig_stop = sig;
}

static void install_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal; /* no SA_RESTART: poll returns EINTR */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

/* ---- delayed packets (binary heap) --------------------------------------- */

static int dl_less(const delayed *a, const delayed *b)
{
    return a->due < b->due || (a->due == b->due && a->order < b->order);
}

static void dl_push(engine *e, delayed d)
{
    size_t i;
    if (e->ndl == e->capdl) {
        e->capdl = e->capdl ? e->capdl * 2 : 64;
        e->dl = xrealloc(e->dl, e->capdl * sizeof(*e->dl));
    }
    d.order = e->dl_order++;
    i = e->ndl++;
    while (i && dl_less(&d, &e->dl[(i - 1) / 2])) {
        e->dl[i] = e->dl[(i - 1) / 2];
        i = (i - 1) / 2;
    }
    e->dl[i] = d;
}

static delayed dl_pop(engine *e)
{
    delayed top = e->dl[0], last = e->dl[--e->ndl];
    size_t i = 0;
    for (;;) {
        size_t l = 2 * i + 1, r = l + 1, m = i;
        const delayed *best = &last;
        if (l < e->ndl && dl_less(&e->dl[l], best))
            m = l, best = &e->dl[l];
        if (r < e->ndl && dl_less(&e->dl[r], best))
            m = r;
        if (m == i)
            break;
        e->dl[i] = e->dl[m];
        i = m;
    }
    if (e->ndl)
        e->dl[i] = last;
    return top;
}

/* ---- output -------------------------------------------------------------- */

static void record(engine *e, const uint8_t *data, size_t len)
{
    if (e->pw)
        pcap_write(e->pw, plat_wall_ms() * 1000000ull, data, len);
}

static void give_verdict(engine *e, uint32_t id, int v, const uint8_t *data, size_t len)
{
    if (nfq_verdict(e->q, id, v, data, len, 0, 0) < 0) {
        e->c.verdict_errors++;
        LOGW("engine", "verdict for packet %u failed: %s", id, strerror(errno));
    }
}

static void raw_send(engine *e, const uint8_t *data, size_t len)
{
    if (rawsend_send(e->rs, data, len) < 0) {
        e->c.send_errors++;
        if (e->c.send_errors <= 10 || log_enabled(LOG_DEBUG))
            LOGW("engine", "raw send of %zu bytes failed: %s", len, strerror(errno));
        return;
    }
    e->c.injected++;
    record(e, data, len);
}

static void release(engine *e, delayed *d)
{
    if (d->verdict) {
        give_verdict(e, d->id, NFQ_ACCEPT, d->data, d->len);
        record(e, d->data, d->len);
    } else {
        raw_send(e, d->data, d->len);
    }
    free(d->data);
}

static void run_timers(engine *e, int all)
{
    uint64_t now = plat_now_ms();
    while (e->ndl && (all || e->dl[0].due <= now)) {
        delayed d = dl_pop(e);
        release(e, &d);
    }
}

/* Queues a packet for later, or releases it now when too many wait. */
static void delay(engine *e, uint8_t *data, size_t len, double secs, int verdict, uint32_t id)
{
    delayed d = {.data = data, .len = len, .verdict = verdict, .id = id};
    if (e->ndl >= (size_t)e->o->max_delayed) {
        LOGW("engine", "too many delayed packets (%zu), sending one now", e->ndl);
        release(e, &d);
        return;
    }
    d.due = plat_now_ms() + (uint64_t)(secs * 1000.0 + 0.5);
    e->c.delayed++;
    dl_push(e, d);
}

/* ---- packets ------------------------------------------------------------- */

static void trace_pkt(engine *e, strat_dir dir, const gpkt *p, const pktlist *out, int fired)
{
    sb_reset(&e->line);
    pkt_describe(p, &e->line);
    LOGT("pkt", "%s %s -> %zu packet(s)%s", dir == DIR_OUT ? "out" : "in", e->line.data, out->n,
         fired ? "" : " (no tree fired)");
    for (size_t i = 0; fired && i < out->n; i++) {
        sb_reset(&e->line);
        pkt_describe(out->v[i], &e->line);
        if (out->v[i]->sleep > 0)
            LOGT("pkt", "    -> %s (after %g s)", e->line.data, out->v[i]->sleep);
        else
            LOGT("pkt", "    -> %s", e->line.data);
    }
}

static strat_dir direction(const engine *e, const nfq_msg *m, const gpkt *p)
{
    int to;
    switch (m->hook) {
    case NFQ_HOOK_PRE_ROUTING:
    case NFQ_HOOK_LOCAL_IN:
        return DIR_IN;
    case NFQ_HOOK_LOCAL_OUT:
    case NFQ_HOOK_POST_ROUTING:
        return DIR_OUT;
    }
    /* FORWARD: decide by the ports, like the rules do */
    to = p->l4 != LAYER_NONE && ports_has(&e->o->fw.ports, p->dport);
    return (to != e->o->fw.server_side) ? DIR_OUT : DIR_IN;
}

static void on_packet(const nfq_msg *m, void *ctx)
{
    engine *e = ctx;
    gpkt *p = pkt_parse(m->data, m->len), *orig = NULL;
    pktlist out = {0};
    strat_dir dir;
    int fired;
    size_t first = 0;

    if (!p) {
        e->c.parse_errors++;
        give_verdict(e, m->id, NFQ_ACCEPT, NULL, 0);
        return;
    }
    dir = direction(e, m, p);
    if (dir == DIR_OUT)
        e->c.pkts_out++;
    else
        e->c.pkts_in++;
    if (e->paused) {
        pkt_free(p);
        e->c.accepted++;
        give_verdict(e, m->id, NFQ_ACCEPT, NULL, 0);
        return;
    }
    if (log_enabled(LOG_TRACE))
        orig = pkt_copy(p);
    fired = strategy_apply(e->st, p, dir, &out);
    if (orig) {
        trace_pkt(e, dir, orig, &out, fired);
        pkt_free(orig);
    }
    if (fired)
        e->c.triggered++;
    if (!out.n) {
        e->c.dropped++;
        give_verdict(e, m->id, NFQ_DROP, NULL, 0);
        return;
    }
    if (dir == DIR_IN) {
        /* Geneva's in-path: only the first result goes on, without delay */
        while (out.n > 1)
            pkt_free(out.v[--out.n]);
        out.v[0]->sleep = 0;
    }
    /* The first packet that is not delayed rides on the verdict (its bytes
     * stay exactly as built); with all of them delayed, the first one holds
     * the verdict until its time comes. */
    for (size_t i = 0; i < out.n; i++)
        if (out.v[i]->sleep <= 0) {
            first = i;
            break;
        }
    for (size_t k = 0; k < out.n; k++) {
        size_t i = k == 0 ? first : (k <= first ? k - 1 : k);
        gpkt *r = out.v[i];
        size_t len;
        uint8_t *b = pkt_bytes(r, &len);
        if (!len) {
            e->c.send_errors++;
            LOGW("engine", "cannot build a result packet");
            free(b);
            if (i == first)
                give_verdict(e, m->id, NFQ_DROP, NULL, 0);
            continue;
        }
        if (i == first) {
            int same = len == m->len && !memcmp(b, m->data, len);
            if (!same)
                e->c.modified++;
            if (r->sleep > 0) {
                delay(e, b, len, r->sleep, 1, m->id);
                continue;
            }
            e->c.accepted++;
            give_verdict(e, m->id, NFQ_ACCEPT, same ? NULL : b, len);
            record(e, b, len);
        } else if (r->sleep > 0) {
            delay(e, b, len, r->sleep, 0, 0);
            continue;
        } else {
            raw_send(e, b, len);
        }
        free(b);
    }
    pktlist_free(&out);
}

static void pass_packet(const nfq_msg *m, void *ctx)
{
    give_verdict(ctx, m->id, NFQ_ACCEPT, NULL, 0);
}

/* ---- events -------------------------------------------------------------- */

static void forest_json(jw *w, atree **f, size_t n)
{
    sbuf s;
    sb_init(&s);
    jw_arr(w);
    for (size_t i = 0; i < n; i++) {
        sb_reset(&s);
        tree_print(f[i], &s);
        jw_obj(w);
        jw_kstr(w, "tree", s.data);
        jw_kuint(w, "fired", f[i]->fired);
        jw_obj_end(w);
    }
    jw_arr_end(w);
    sb_free(&s);
}

/* Counters shared by the "stats" event and the "stats" control command. */
static void stats_fields(engine *e, jw *w)
{
    counters *c = &e->c;
    jw_kuint(w, "uptime_ms", plat_now_ms() - e->start_ms);
    jw_kbool(w, "paused", e->paused);
    jw_kuint(w, "pkts_out", c->pkts_out);
    jw_kuint(w, "pkts_in", c->pkts_in);
    jw_kuint(w, "triggered", c->triggered);
    jw_kuint(w, "accepted", c->accepted);
    jw_kuint(w, "modified", c->modified);
    jw_kuint(w, "dropped", c->dropped);
    jw_kuint(w, "injected", c->injected);
    jw_kuint(w, "delayed", c->delayed);
    jw_kuint(w, "pending", e->ndl);
    jw_kuint(w, "send_errors", c->send_errors);
    jw_kuint(w, "verdict_errors", c->verdict_errors);
    jw_kuint(w, "parse_errors", c->parse_errors);
    jw_kuint(w, "overruns", c->overruns);
    jw_key(w, "out_trees");
    forest_json(w, e->st->out, e->st->nout);
    jw_key(w, "in_trees");
    forest_json(w, e->st->in, e->st->nin);
}

static void emit_stats(engine *e)
{
    ev_t ev;
    if (!ev_enabled())
        return;
    ev_begin(&ev, "stats");
    stats_fields(e, &ev.w);
    ev_emit(&ev);
}

static void emit_state(engine *e, const char *state)
{
    ev_t ev;
    LOGI("engine", "%s", state);
    if (!ev_enabled())
        return;
    ev_begin(&ev, "state");
    jw_kstr(&ev.w, "state", state);
    ev_emit(&ev);
}

static void emit_strategy(engine *e)
{
    ev_t ev;
    sbuf s;
    sb_init(&s);
    strategy_print(e->st, &s);
    LOGI("engine", "strategy: %s", s.data);
    if (ev_enabled()) {
        ev_begin(&ev, "strategy");
        jw_kstr(&ev.w, "strategy", s.data);
        ev_emit(&ev);
    }
    sb_free(&s);
}

static void emit_error(const char *where, const char *msg)
{
    ev_t ev;
    if (!ev_enabled())
        return;
    ev_begin(&ev, "error");
    jw_kstr(&ev.w, "where", where);
    jw_kstr(&ev.w, "message", msg);
    ev_emit(&ev);
}

/* ---- strategy loading ---------------------------------------------------- */

static strategy *load_strategy(const engine_opts *o, sbuf *err)
{
    char *text;
    size_t len;
    strategy *s;
    if (o->strategy)
        return strategy_parse(o->strategy, err);
    text = read_file(o->strategy_file, &len);
    if (!text) {
        sb_printf(err, "cannot read %s", o->strategy_file);
        return NULL;
    }
    /* the file may carry comments and blank lines: take the first strategy */
    {
        char *line = text, *next, *found = NULL;
        for (; line && *line && !found; line = next) {
            char *p = line, *end;
            next = strchr(line, '\n');
            if (next)
                *next++ = 0;
            while (*p == ' ' || *p == '\t')
                p++;
            end = p + strlen(p);
            while (end > p && (end[-1] == '\r' || end[-1] == ' ' || end[-1] == '\t'))
                *--end = 0;
            if (*p && *p != '#')
                found = p;
        }
        if (found)
            s = strategy_parse(found, err);
        else {
            sb_printf(err, "no strategy in %s", o->strategy_file);
            s = NULL;
        }
    }
    free(text);
    return s;
}

/* Re-reads --strategy-file. Returns 0, or -1 with a message in err (the
 * current strategy stays). */
static int reload(engine *e, sbuf *err)
{
    strategy *s;
    if (!e->o->strategy_file) {
        sb_puts(err, "no --strategy-file to re-read");
        return -1;
    }
    s = load_strategy(e->o, err);
    if (!s) {
        LOGE("engine", "reload failed, keeping the current strategy: %s", err->data);
        emit_error("reload", err->data);
        return -1;
    }
    strategy_free(e->st);
    e->st = s;
    emit_strategy(e);
    return 0;
}

/* ---- control commands ---------------------------------------------------- */

static int on_control(void *ctx, const char *cmd, const json_val *req, jw *w, sbuf *err)
{
    engine *e = ctx;
    if (!strcmp(cmd, "status")) {
        sbuf s;
        sb_init(&s);
        jw_kstr(w, "mode", "run");
        jw_kstr(w, "state", e->paused ? "paused" : "running");
        jw_kstr(w, "version", GENEVA_VERSION);
        jw_kint(w, "pid", plat_getpid());
        jw_kuint(w, "uptime_ms", plat_now_ms() - e->start_ms);
        jw_kuint(w, "queue", e->o->fw.queue);
        ports_format(&e->o->fw.ports, &s, ",", "-");
        jw_kstr(w, "ports", s.data);
        jw_kbool(w, "server_side", e->o->fw.server_side);
        jw_kstr(w, "firewall", e->o->apply_fw ? fw_backend_name(e->o->fw.backend) : "none");
        jw_kstr(w, "log_level", log_level_name(log_get_level()));
        sb_reset(&s);
        strategy_print(e->st, &s);
        jw_kstr(w, "strategy", s.data);
        if (e->o->strategy_file)
            jw_kstr(w, "strategy_file", e->o->strategy_file);
        sb_free(&s);
        return 0;
    }
    if (!strcmp(cmd, "stats")) {
        stats_fields(e, w);
        return 0;
    }
    if (!strcmp(cmd, "reset_stats")) {
        memset(&e->c, 0, sizeof(e->c));
        strategy_reset(e->st);
        return 0;
    }
    if (!strcmp(cmd, "set_strategy")) {
        const char *text = json_get_str(req, "strategy", NULL);
        strategy *s;
        sbuf out;
        if (!text) {
            sb_puts(err, "set_strategy needs \"strategy\"");
            return -1;
        }
        s = strategy_parse(text, err);
        if (!s)
            return -1;
        strategy_free(e->st);
        e->st = s;
        emit_strategy(e);
        sb_init(&out);
        strategy_print(s, &out);
        jw_kstr(w, "strategy", out.data);
        sb_free(&out);
        return 0;
    }
    if (!strcmp(cmd, "reload")) {
        if (reload(e, err) < 0)
            return -1;
        return 0;
    }
    if (!strcmp(cmd, "pause") || !strcmp(cmd, "resume")) {
        int p = !strcmp(cmd, "pause");
        if (p != e->paused) {
            e->paused = p;
            emit_state(e, p ? "paused" : "running");
        }
        return 0;
    }
    if (!strcmp(cmd, "log_level")) {
        const char *l = json_get_str(req, "level", NULL);
        log_level lvl;
        if (l) {
            if (log_parse_level(l, &lvl) < 0) {
                sb_printf(err, "bad level \"%s\" (error, warn, info, debug, trace)", l);
                return -1;
            }
            log_set_level(lvl);
        }
        jw_kstr(w, "level", log_level_name(log_get_level()));
        return 0;
    }
    if (!strcmp(cmd, "stop")) {
        e->stop_request = 1;
        return 0;
    }
    sb_printf(err, "unknown command \"%s\"", cmd);
    return -1;
}

/* ---- main loop ----------------------------------------------------------- */

static void emit_start(engine *e)
{
    ev_t ev;
    sbuf s;
    if (!ev_enabled())
        return;
    sb_init(&s);
    ports_format(&e->o->fw.ports, &s, ",", "-");
    ev_begin(&ev, "start");
    jw_kint(&ev.w, "proto", GENEVA_PROTO_VERSION);
    jw_kstr(&ev.w, "version", GENEVA_VERSION);
    jw_kstr(&ev.w, "mode", "run");
    jw_kint(&ev.w, "pid", plat_getpid());
    jw_kuint(&ev.w, "queue", e->o->fw.queue);
    jw_kstr(&ev.w, "ports", s.data);
    jw_kbool(&ev.w, "server_side", e->o->fw.server_side);
    ev_emit(&ev);
    sb_free(&s);
}

int engine_run(engine_opts *o)
{
    engine e;
    sbuf err;
    nfq_config qc;
    int rc = EXIT_OK, fw_on = 0, errnum;
    uint64_t next_stats, deadline;
    const char *reason = "signal";

    memset(&e, 0, sizeof(e));
    e.o = o;
    sb_init(&err);
    sb_init(&e.line);
    e.start_ms = plat_now_ms();
    sig_stop = sig_hup = sig_usr1 = 0;

    e.st = load_strategy(o, &err);
    if (!e.st) {
        LOGE("engine", "%s", err.data);
        emit_error("strategy", err.data);
        rc = EXIT_STRATEGY;
        goto out;
    }
    emit_start(&e);
    if (o->pcap) {
        sb_reset(&err);
        e.pw = pcap_open_write(o->pcap, &err);
        if (!e.pw) {
            LOGE("engine", "%s", err.data);
            rc = EXIT_IO;
            goto out;
        }
    }
    install_signals();

    memset(&qc, 0, sizeof(qc));
    qc.queue = o->fw.queue;
    qc.maxlen = o->queue_maxlen;
    qc.fail_open = o->fail_open;
    qc.rcvbuf = 4 << 20;
    sb_reset(&err);
    e.q = nfq_open(&qc, &errnum, &err);
    if (!e.q) {
        LOGE("engine", "%s", err.data);
        emit_error("nfqueue", err.data);
        rc = (errnum == EPERM || errnum == EACCES || errnum == EPROTONOSUPPORT) ? EXIT_PRIV : EXIT_FAIL;
        goto out;
    }
    sb_reset(&err);
    e.rs = rawsend_open(o->fw.mark, &err);
    if (!e.rs) {
        LOGE("engine", "%s", err.data);
        emit_error("rawsend", err.data);
        rc = EXIT_PRIV;
        goto out;
    }
    if (err.len)
        LOGW("engine", "%s", err.data);
    if (o->control) {
        sb_reset(&err);
        e.ctl = ctl_open(o->control, o->control_token, &err);
        if (!e.ctl) {
            LOGE("engine", "%s", err.data);
            emit_error("control", err.data);
            rc = EXIT_IO;
            goto out;
        }
        ev_set_tap(ctl_broadcast, e.ctl);
        LOGI("engine", "control socket %s", o->control);
    }
    if (o->apply_fw) {
        sb_reset(&err);
        if (fw_up(&o->fw, &err) < 0) {
            LOGE("engine", "firewall: %s", err.data);
            emit_error("firewall", err.data);
            rc = EXIT_FIREWALL;
            goto out;
        }
        fw_on = 1;
        LOGI("engine", "firewall rules applied (%s)", fw_backend_name(o->fw.backend));
    }
    emit_strategy(&e);
    if (ev_enabled()) {
        ev_t ev;
        ev_begin(&ev, "ready");
        jw_kstr(&ev.w, "firewall", o->apply_fw ? fw_backend_name(o->fw.backend) : "none");
        ev_emit(&ev);
    }
    LOGI("engine", "listening on NFQUEUE %u", o->fw.queue);

    next_stats = o->stats_interval > 0 ? e.start_ms + (uint64_t)(o->stats_interval * 1000) : 0;
    deadline = o->duration > 0 ? e.start_ms + (uint64_t)(o->duration * 1000) : 0;
    while (!sig_stop && !e.stop_request) {
        struct pollfd pfd[2 + CTL_MAX_CLIENTS];
        size_t nctl;
        uint64_t now = plat_now_ms();
        int timeout = 1000, r;
        pfd[0].fd = nfq_fd(e.q);
        pfd[0].events = POLLIN;
        pfd[0].revents = 0;
        nctl = ctl_pollfds(e.ctl, pfd + 1, ARRAY_LEN(pfd) - 1);
        if (e.ndl)
            timeout = e.dl[0].due <= now ? 0 : (int)MIN(e.dl[0].due - now, 1000);
        if (next_stats && next_stats > now && next_stats - now < (uint64_t)timeout)
            timeout = (int)(next_stats - now);
        if (deadline) {
            if (now >= deadline) {
                reason = "duration";
                break;
            }
            if (deadline - now < (uint64_t)timeout)
                timeout = (int)(deadline - now);
        }
        r = poll(pfd, (nfds_t)(1 + nctl), timeout);
        if (r < 0 && errno != EINTR) {
            LOGE("engine", "poll: %s", strerror(errno));
            rc = EXIT_FAIL;
            reason = "error";
            break;
        }
        if (r > 0 && (pfd[0].revents & POLLIN)) {
            /* drain a batch, but keep timers responsive */
            for (int i = 0; i < 64; i++) {
                int n = nfq_read(e.q, on_packet, &e, &e.c.overruns);
                if (n < 0) {
                    LOGE("engine", "NFQUEUE read: %s", strerror(errno));
                    rc = EXIT_FAIL;
                    reason = "error";
                    sig_stop = -1;
                    break;
                }
                if (n == 0)
                    break;
            }
        }
        if (r > 0 && nctl)
            ctl_dispatch(e.ctl, pfd + 1, nctl, on_control, &e);
        run_timers(&e, 0);
        if (sig_hup) {
            sbuf herr;
            sig_hup = 0;
            sb_init(&herr);
            if (reload(&e, &herr) < 0 && !e.o->strategy_file)
                LOGI("engine", "SIGHUP: %s", herr.data);
            sb_free(&herr);
        }
        now = plat_now_ms();
        if (sig_usr1 || (next_stats && now >= next_stats)) {
            sig_usr1 = 0;
            emit_stats(&e);
            if (next_stats)
                while (next_stats <= now)
                    next_stats += (uint64_t)(o->stats_interval * 1000);
        }
    }
    if (sig_stop > 0)
        LOGI("engine", "stopping (signal %d)", (int)sig_stop);
    if (e.stop_request) {
        reason = "control";
        LOGI("engine", "stopping (stop command)");
    }

out:
    if (fw_on)
        fw_down(&o->fw);
    if (e.q) {
        /* packets queued while the rules came down pass unchanged */
        while (nfq_read(e.q, pass_packet, &e, NULL) > 0)
            ;
        run_timers(&e, 1); /* let held packets go before the queue closes */
        if (e.st)
            emit_stats(&e);
    }
    if (ev_enabled()) {
        ev_t ev;
        ev_begin(&ev, "exit");
        jw_kint(&ev.w, "code", rc);
        jw_kstr(&ev.w, "reason", rc == EXIT_OK ? reason : "error");
        ev_emit(&ev);
    }
    if (e.ctl) {
        ev_set_tap(NULL, NULL);
        ctl_close(e.ctl);
    }
    free(e.dl);
    nfq_close(e.q);
    rawsend_close(e.rs);
    if (e.pw && pcap_close_write(e.pw) < 0 && rc == EXIT_OK)
        rc = EXIT_IO;
    strategy_free(e.st);
    sb_free(&err);
    sb_free(&e.line);
    return rc;
}

#else /* !__linux__ */

int engine_run(engine_opts *o)
{
    LOGE("engine", "the NFQUEUE engine runs on Linux only; the Windows engine comes in stage 5");
    return EXIT_PRIV;
}

#endif
