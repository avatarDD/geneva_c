/*
 * The portable engine core: the strategy, delayed packets (sleep), events,
 * statistics and the control socket. Packets come from a backend (see
 * engine_int.h): NFQUEUE on Linux, WinDivert on Windows.
 */
#include "engine.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "engine_int.h"
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

#if defined(__linux__)
#  define BACKEND (&nfq_backend)
#  define HAVE_BACKEND 1
#elif defined(_WIN32)
#  define BACKEND (&windivert_backend)
#  define HAVE_BACKEND 1
#else
#  define BACKEND NULL
#endif

/* Embedded in the evaluator, the engine emits no events of its own. Only one
 * engine runs per process. */
static int ev_quiet;
#define ev_on() (!ev_quiet && ev_enabled())

/* ---- signals ------------------------------------------------------------- */

static volatile sig_atomic_t sig_stop, sig_hup, sig_usr1;

#ifdef _WIN32
static BOOL WINAPI on_console(DWORD type)
{
    switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        sig_stop = SIGINT;
        /* CTRL_CLOSE gives a few seconds before the process dies: wait for
         * the main loop to take the filter down. */
        if (type == CTRL_CLOSE_EVENT || type == CTRL_SHUTDOWN_EVENT)
            Sleep(3000);
        return TRUE;
    }
    return FALSE;
}

static void install_signals(void) { SetConsoleCtrlHandler(on_console, TRUE); }
static void remove_signals(void) { SetConsoleCtrlHandler(on_console, FALSE); }
#else
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

static void remove_signals(void) {}
#endif

/* ---- delayed packets (binary heap) --------------------------------------- */

static int dl_less(const delayed *a, const delayed *b)
{
    return a->due < b->due || (a->due == b->due && a->order < b->order);
}

static void dl_push(engine *e, const delayed *d)
{
    size_t i;
    if (e->ndl == e->capdl) {
        e->capdl = e->capdl ? e->capdl * 2 : 64;
        e->dl = xrealloc(e->dl, e->capdl * sizeof(*e->dl));
    }
    i = e->ndl++;
    while (i && dl_less(d, &e->dl[(i - 1) / 2])) {
        e->dl[i] = e->dl[(i - 1) / 2];
        i = (i - 1) / 2;
    }
    e->dl[i] = *d;
    e->dl[i].order = e->dl_order++;
}

static void dl_pop(engine *e, delayed *top)
{
    delayed last;
    size_t i = 0;
    *top = e->dl[0];
    last = e->dl[--e->ndl];
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
}

/* ---- output -------------------------------------------------------------- */

static void record(engine *e, const uint8_t *data, size_t len)
{
    if (e->pw)
        pcap_write(e->pw, plat_wall_ms() * 1000000ull, data, len);
}

static void give_verdict(engine *e, const void *pctx, int accept, const uint8_t *data, size_t len)
{
    if (e->be->verdict(e, pctx, accept, data, len) < 0)
        e->c.verdict_errors++;
}

static void inject(engine *e, const void *pctx, const uint8_t *data, size_t len)
{
    if (e->be->inject(e, pctx, data, len) < 0) {
        e->c.send_errors++;
        if (e->c.send_errors <= 10 || log_enabled(LOG_DEBUG))
            LOGW("engine", "sending %zu bytes failed", len);
        return;
    }
    e->c.injected++;
    record(e, data, len);
}

static void release(engine *e, delayed *d)
{
    if (d->verdict) {
        give_verdict(e, d->pctx, 1, d->data, d->len);
        record(e, d->data, d->len);
    } else {
        inject(e, d->pctx, d->data, d->len);
    }
    free(d->data);
}

static void run_timers(engine *e, int all)
{
    uint64_t now = plat_now_ms();
    while (e->ndl && (all || e->dl[0].due <= now)) {
        delayed d;
        dl_pop(e, &d);
        release(e, &d);
    }
}

/* Queues a packet for later, or releases it now when too many wait. */
static void delay(engine *e, uint8_t *data, size_t len, double secs, int verdict, const void *pctx)
{
    delayed d;
    memset(&d, 0, sizeof(d));
    d.data = data;
    d.len = len;
    d.verdict = verdict;
    memcpy(d.pctx, pctx, e->be->pctx_len);
    if (e->ndl >= (size_t)e->o->max_delayed) {
        LOGW("engine", "too many delayed packets (%zu), sending one now", e->ndl);
        release(e, &d);
        return;
    }
    d.due = plat_now_ms() + (uint64_t)(secs * 1000.0 + 0.5);
    e->c.delayed++;
    dl_push(e, &d);
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

/* The slot whose local port the packet uses, or NULL. */
static eng_slot *find_slot(eng_slots *ss, const gpkt *p, strat_dir dir)
{
    uint16_t lport;
    size_t i;
    if (p->l4 == LAYER_NONE)
        return NULL;
    lport = dir == DIR_OUT ? p->sport : p->dport;
    if (lport < ss->base)
        return NULL;
    i = (size_t)(lport - ss->base) / ss->size;
    return i < ss->n ? &ss->v[i] : NULL;
}

static void slot_capture(eng_slot *sl, const gpkt *p)
{
    gpkt *c;
    if (sl->ncap >= ENG_SLOT_CAP_MAX)
        return;
    if (sl->ncap == sl->capcap) {
        size_t nc = sl->capcap ? sl->capcap * 2 : 16;
        gpkt **v = realloc(sl->cap, nc * sizeof(*v));
        if (!v)
            return;
        sl->cap = v;
        sl->capcap = nc;
    }
    c = pkt_copy(p);
    if (c)
        sl->cap[sl->ncap++] = c;
}

static void packet(engine *e, strategy *st, eng_slot *sl, gpkt *p, strat_dir dir, const uint8_t *data,
                   size_t len, const void *pctx);

void engine_packet(engine *e, const uint8_t *data, size_t len, int d, const void *pctx)
{
    gpkt *p = pkt_parse(data, len);
    eng_slots *ss = e->o->slots;
    strat_dir dir;

    if (!p) {
        e->c.parse_errors++;
        give_verdict(e, pctx, 1, NULL, 0);
        return;
    }
    if (d < 0) {
        /* decide by the ports, like the rules do */
        int to = p->l4 != LAYER_NONE && ports_has(&e->o->fw.ports, p->dport);
        dir = (to != e->o->fw.server_side) ? DIR_OUT : DIR_IN;
    } else {
        dir = (strat_dir)d;
    }
    if (dir == DIR_OUT)
        e->c.pkts_out++;
    else
        e->c.pkts_in++;
    if (ss) {
        eng_slot *sl;
        plat_mutex_lock(&ss->lock);
        sl = find_slot(ss, p, dir);
        if (sl) {
            sl->pkts++;
            if (sl->capture)
                slot_capture(sl, p);
        }
        packet(e, sl ? sl->st : NULL, sl, p, dir, data, len, pctx);
        plat_mutex_unlock(&ss->lock);
        return;
    }
    packet(e, e->st, NULL, p, dir, data, len, pctx);
}

/* Runs a parsed packet through st (NULL: it passes) and frees it. */
static void packet(engine *e, strategy *st, eng_slot *sl, gpkt *p, strat_dir dir, const uint8_t *data,
                   size_t len, const void *pctx)
{
    gpkt *orig = NULL;
    pktlist out = {0};
    int fired;
    size_t first = 0;

    if (e->paused || !st) {
        pkt_free(p);
        e->c.accepted++;
        give_verdict(e, pctx, 1, NULL, 0);
        return;
    }
    if (log_enabled(LOG_TRACE))
        orig = pkt_copy(p);
    fired = strategy_apply(st, p, dir, &out);
    if (orig) {
        trace_pkt(e, dir, orig, &out, fired);
        pkt_free(orig);
    }
    if (fired)
        e->c.triggered++;
    if (!out.n) {
        e->c.dropped++;
        give_verdict(e, pctx, 0, NULL, 0);
        return;
    }
    if (sl && dir == DIR_OUT)
        sl->overhead += out.n - 1;
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
        size_t blen;
        uint8_t *b = pkt_bytes(r, &blen);
        if (!blen) {
            e->c.send_errors++;
            LOGW("engine", "cannot build a result packet");
            free(b);
            if (i == first)
                give_verdict(e, pctx, 0, NULL, 0);
            continue;
        }
        if (i == first) {
            int same = blen == len && !memcmp(b, data, blen);
            if (!same)
                e->c.modified++;
            if (r->sleep > 0) {
                delay(e, b, blen, r->sleep, 1, pctx);
                continue;
            }
            e->c.accepted++;
            give_verdict(e, pctx, 1, same ? NULL : b, blen);
            record(e, b, blen);
        } else if (r->sleep > 0) {
            delay(e, b, blen, r->sleep, 0, pctx);
            continue;
        } else {
            inject(e, pctx, b, blen);
        }
        free(b);
    }
    pktlist_free(&out);
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
    if (e->st) {
        jw_key(w, "out_trees");
        forest_json(w, e->st->out, e->st->nout);
        jw_key(w, "in_trees");
        forest_json(w, e->st->in, e->st->nin);
    }
}

static void emit_stats(engine *e)
{
    ev_t ev;
    if (!ev_on())
        return;
    ev_begin(&ev, "stats");
    stats_fields(e, &ev.w);
    ev_emit(&ev);
}

static void emit_state(engine *e, const char *state)
{
    ev_t ev;
    LOGI("engine", "%s", state);
    if (!ev_on())
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
    if (ev_on()) {
        ev_begin(&ev, "strategy");
        jw_kstr(&ev.w, "strategy", s.data);
        ev_emit(&ev);
    }
    sb_free(&s);
}

static void emit_error(const char *where, const char *msg)
{
    ev_t ev;
    if (!ev_on())
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
        jw_kstr(w, "backend", e->be->name);
        jw_kuint(w, "queue", e->o->fw.queue);
        ports_format(&e->o->fw.ports, &s, ",", "-");
        jw_kstr(w, "ports", s.data);
        jw_kbool(w, "server_side", e->o->fw.server_side);
        jw_kstr(w, "firewall", e->fw_name ? e->fw_name : "none");
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
    if (!ev_on())
        return;
    sb_init(&s);
    ports_format(&e->o->fw.ports, &s, ",", "-");
    ev_begin(&ev, "start");
    jw_kint(&ev.w, "proto", GENEVA_PROTO_VERSION);
    jw_kstr(&ev.w, "version", GENEVA_VERSION);
    jw_kstr(&ev.w, "mode", "run");
    jw_kint(&ev.w, "pid", plat_getpid());
    jw_kstr(&ev.w, "backend", e->be->name);
    jw_kuint(&ev.w, "queue", e->o->fw.queue);
    jw_kstr(&ev.w, "ports", s.data);
    jw_kbool(&ev.w, "server_side", e->o->fw.server_side);
    ev_emit(&ev);
    sb_free(&s);
}

#define MAX_POLL (8 + CTL_MAX_CLIENTS + 1)

int engine_run(engine_opts *o)
{
    engine e;
    sbuf err;
    int rc = EXIT_OK, opened = 0, running = 0;
    uint64_t next_stats, deadline;
    const char *reason = "signal";

#ifndef HAVE_BACKEND
    LOGE("engine", "no packet engine on %s: geneva run needs Linux (NFQUEUE) or Windows (WinDivert)",
         plat_os_name());
    return EXIT_PRIV;
#endif
    memset(&e, 0, sizeof(e));
    e.o = o;
    e.be = BACKEND;
    plat_mutex_init(&e.lock);
    sb_init(&err);
    sb_init(&e.line);
    e.start_ms = plat_now_ms();
    sig_stop = sig_hup = sig_usr1 = 0;
    ev_quiet = o->embedded;

    if (!o->slots) {
        e.st = load_strategy(o, &err);
        if (!e.st) {
            LOGE("engine", "%s", err.data);
            emit_error("strategy", err.data);
            rc = EXIT_STRATEGY;
            goto out;
        }
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
    if (!o->embedded)
        install_signals();
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
    sb_reset(&err);
    opened = 1;
    rc = e.be->open(&e, &err);
    if (rc != EXIT_OK) {
        LOGE("engine", "%s", err.data);
        emit_error(e.err_where ? e.err_where : e.be->name, err.data);
        goto out;
    }
    running = 1;
    if (err.len)
        LOGW("engine", "%s", err.data);
    if (o->on_ready) {
        o->on_ready(o->ready_ctx, 0);
        o->on_ready = NULL;
    }
    plat_mutex_lock(&e.lock);
    if (e.st)
        emit_strategy(&e);
    if (ev_on()) {
        ev_t ev;
        ev_begin(&ev, "ready");
        jw_kstr(&ev.w, "backend", e.be->name);
        jw_kstr(&ev.w, "firewall", e.fw_name ? e.fw_name : "none");
        ev_emit(&ev);
    }
    plat_mutex_unlock(&e.lock);

    next_stats = o->stats_interval > 0 ? e.start_ms + (uint64_t)(o->stats_interval * 1000) : 0;
    deadline = o->duration > 0 ? e.start_ms + (uint64_t)(o->duration * 1000) : 0;
    while (!sig_stop && !e.stop_request && !(o->stop && atomic_load_int(o->stop))) {
        plat_pollfd pfd[MAX_POLL];
        size_t nbe, nctl;
        uint64_t now;
        int timeout = 1000, r;

        plat_mutex_lock(&e.lock);
        nbe = e.be->pollfds(&e, pfd, 8);
        nctl = ctl_pollfds(e.ctl, pfd + nbe, MAX_POLL - nbe);
        now = plat_now_ms();
        if (o->stop)
            timeout = 100; /* the stop flag is polled */
        if (e.ndl)
            timeout = e.dl[0].due <= now ? 0 : (int)MIN(e.dl[0].due - now, (uint64_t)timeout);
        plat_mutex_unlock(&e.lock);
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
        r = plat_poll(pfd, (unsigned)(nbe + nctl), timeout);
        if (r < 0) {
#ifdef _WIN32
            int perr = plat_sock_err();
            if (perr != WSAEINTR) {
                LOGE("engine", "poll: %s", plat_sock_strerror(perr));
#else
            if (errno != EINTR) {
                LOGE("engine", "poll: %s", strerror(errno));
#endif
                rc = EXIT_FAIL;
                reason = "error";
                break;
            }
        }
        plat_mutex_lock(&e.lock);
        if (r > 0 && e.be->ready(&e, pfd, nbe) < 0) {
            plat_mutex_unlock(&e.lock);
            rc = EXIT_FAIL;
            reason = "error";
            break;
        }
        if (r > 0 && nctl)
            ctl_dispatch(e.ctl, pfd + nbe, nctl, on_control, &e);
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
        plat_mutex_unlock(&e.lock);
    }
    if (sig_stop > 0)
        LOGI("engine", "stopping (signal %d)", (int)sig_stop);
    if (e.stop_request) {
        reason = "control";
        LOGI("engine", "stopping (stop command)");
    }

out:
    if (opened) {
        e.be->stop(&e);
        plat_mutex_lock(&e.lock);
        run_timers(&e, 1); /* let held packets go before the capture closes */
        if (running)
            emit_stats(&e);
        plat_mutex_unlock(&e.lock);
        e.be->close(&e);
    }
    if (o->on_ready)
        o->on_ready(o->ready_ctx, rc == EXIT_OK ? EXIT_FAIL : rc);
    if (ev_on()) {
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
    if (!o->embedded)
        remove_signals();
    for (size_t i = 0; i < e.ndl; i++)
        free(e.dl[i].data);
    free(e.dl);
    if (e.pw && pcap_close_write(e.pw) < 0 && rc == EXIT_OK)
        rc = EXIT_IO;
    strategy_free(e.st);
    sb_free(&err);
    sb_free(&e.line);
    plat_mutex_destroy(&e.lock);
    return rc;
}
