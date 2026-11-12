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
#include "rng.h"
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

static void dl_push(eng_worker *w, const delayed *d)
{
    size_t i;
    if (w->ndl == w->capdl) {
        w->capdl = w->capdl ? w->capdl * 2 : 64;
        w->dl = xrealloc(w->dl, w->capdl * sizeof(*w->dl));
    }
    i = w->ndl++;
    while (i && dl_less(d, &w->dl[(i - 1) / 2])) {
        w->dl[i] = w->dl[(i - 1) / 2];
        i = (i - 1) / 2;
    }
    w->dl[i] = *d;
    w->dl[i].order = w->dl_order++;
}

static void dl_pop(eng_worker *w, delayed *top)
{
    delayed last;
    size_t i = 0;
    *top = w->dl[0];
    last = w->dl[--w->ndl];
    for (;;) {
        size_t l = 2 * i + 1, r = l + 1, m = i;
        const delayed *best = &last;
        if (l < w->ndl && dl_less(&w->dl[l], best))
            m = l, best = &w->dl[l];
        if (r < w->ndl && dl_less(&w->dl[r], best))
            m = r;
        if (m == i)
            break;
        w->dl[i] = w->dl[m];
        i = m;
    }
    if (w->ndl)
        w->dl[i] = last;
}

/* ---- output -------------------------------------------------------------- */

static void record(eng_worker *w, const uint8_t *data, size_t len)
{
    engine *e = w->e;
    if (e->pw) {
        plat_mutex_lock(&e->pw_lock);
        pcap_write(e->pw, plat_wall_ms() * 1000000ull, data, len);
        plat_mutex_unlock(&e->pw_lock);
    }
}

static void give_verdict(eng_worker *w, const void *pctx, int accept, const uint8_t *data, size_t len)
{
    engine *e = w->e;
    if (accept && !data && w->vdata) {
        data = w->vdata; /* a held packet: a detached verdict sends these */
        len = w->vlen;
    }
    if (e->be->verdict(w, pctx, accept, data, len) < 0)
        w->c.verdict_errors++;
}

static void inject_x(eng_worker *w, const void *pctx, const uint8_t *data, size_t len, uint32_t mark,
                     const char *ifout)
{
    engine *e = w->e;
    int r = (mark || (ifout && *ifout)) && e->be->inject_x ? e->be->inject_x(w, pctx, data, len, mark, ifout)
                                                           : e->be->inject(w, pctx, data, len);
    if (r < 0) {
        w->c.send_errors++;
        if (w->c.send_errors <= 10 || log_enabled(LOG_DEBUG))
            LOGW("engine", "sending %zu bytes failed", len);
        return;
    }
    w->c.injected++;
    record(w, data, len);
}

static void inject(eng_worker *w, const void *pctx, const uint8_t *data, size_t len)
{
    inject_x(w, pctx, data, len, 0, NULL);
}

static void release(eng_worker *w, delayed *d)
{
    if (d->verdict) {
        give_verdict(w, d->pctx, 1, d->data, d->len);
        record(w, d->data, d->len);
    } else {
        inject_x(w, d->pctx, d->data, d->len, d->xmark, d->xifout);
    }
    free(d->data);
}

static void run_timers(eng_worker *w, int all)
{
    uint64_t now = plat_now_ms();
    while (w->ndl && (all || w->dl[0].due <= now)) {
        delayed d;
        dl_pop(w, &d);
        release(w, &d);
    }
}

/* Queues a packet for later, or releases it now when too many wait. x: the
 * x-action's packet it is, or NULL. */
static void delay_x(eng_worker *w, uint8_t *data, size_t len, double secs, int verdict, const void *pctx,
                    const gpkt *x)
{
    engine *e = w->e;
    delayed d;
    memset(&d, 0, sizeof(d));
    d.data = data;
    d.len = len;
    d.verdict = verdict;
    if (x) {
        d.xmark = x->xmark;
        memcpy(d.xifout, x->xifout, sizeof(d.xifout));
    }
    memcpy(d.pctx, pctx, e->be->pctx_len);
    if (w->ndl >= (size_t)e->o->max_delayed) {
        LOGW("engine", "too many delayed packets (%zu), sending one now", w->ndl);
        release(w, &d);
        return;
    }
    d.due = plat_now_ms() + (uint64_t)(secs * 1000.0 + 0.5);
    w->c.delayed++;
    dl_push(w, &d);
}

static void delay(eng_worker *w, uint8_t *data, size_t len, double secs, int verdict, const void *pctx)
{
    delay_x(w, data, len, secs, verdict, pctx, NULL);
}

/* ---- packets ------------------------------------------------------------- */

static void trace_pkt(eng_worker *w, strat_dir dir, const gpkt *p, const pktlist *out, int fired)
{
    sb_reset(&w->line);
    pkt_describe(p, &w->line);
    LOGT("pkt", "%s %s -> %zu packet(s)%s", dir == DIR_OUT ? "out" : "in", w->line.data, out->n,
         fired ? "" : " (no tree fired)");
    for (size_t i = 0; fired && i < out->n; i++) {
        sb_reset(&w->line);
        pkt_describe(out->v[i], &w->line);
        if (out->v[i]->sleep > 0)
            LOGT("pkt", "    -> %s (after %g s)", w->line.data, out->v[i]->sleep);
        else
            LOGT("pkt", "    -> %s", w->line.data);
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

static void packet(eng_worker *w, strategy *st, eng_slot *sl, gpkt *p, strat_dir dir, const uint8_t *data,
                   size_t len, const void *pctx);

void engine_packet(eng_worker *w, const uint8_t *data, size_t len, int d, const void *pctx)
{
    engine *e = w->e;
    gpkt *p = pkt_parse(data, len);
    eng_slots *ss = e->o->slots;
    strat_dir dir;

    if (!p) {
        w->c.parse_errors++;
        give_verdict(w, pctx, 1, NULL, 0);
        return;
    }
    if (d < 0) {
        /* decide by the ports, like the rules do */
        int to = p->l4 != LAYER_NONE && ports_has(&e->o->fw.ports, p->dport);
        dir = (to != e->o->fw.server_side) ? DIR_OUT : DIR_IN;
    } else {
        dir = (strat_dir)d;
    }
    if (w->flows) {
        /* --first N without conntrack: later packets of a flow go on as
         * they are, outside the strategy and the counters */
        int evicted = 0;
        /* --ext: the count of the protocol and direction */
        uint32_t first = (uint32_t)fw_first(&e->o->fw, p->l4 == LAYER_UDP, dir == DIR_IN);
        int in_first = first ? flowtab_packet(w->flows, p, dir, first, plat_now_ms(), &evicted) : 1;
        if (evicted)
            w->c.flow_evictions++;
        if (!in_first) {
            w->c.passed_first++;
            pkt_free(p);
            give_verdict(w, pctx, 1, NULL, 0);
            return;
        }
    }
    if (dir == DIR_OUT)
        w->c.pkts_out++;
    else
        w->c.pkts_in++;
    if (ss) {
        eng_slot *sl;
        plat_mutex_lock(&ss->lock);
        sl = find_slot(ss, p, dir);
        if (sl) {
            sl->pkts++;
            if (sl->capture)
                slot_capture(sl, p);
        }
        packet(w, sl ? sl->st : NULL, sl, p, dir, data, len, pctx);
        plat_mutex_unlock(&ss->lock);
        return;
    }
    packet(w, w->st ? w->st : e->st, NULL, p, dir, data, len, pctx);
}

void engine_verdict(eng_worker *w, const void *pctx, int accept, const uint8_t *data, size_t len, int modified)
{
    if (!accept) {
        w->c.dropped++;
        give_verdict(w, pctx, 0, NULL, 0);
        return;
    }
    w->c.accepted++;
    if (modified)
        w->c.modified++;
    give_verdict(w, pctx, 1, modified ? data : NULL, len);
    record(w, data, len);
}

void engine_inject(eng_worker *w, const void *pctx, const uint8_t *data, size_t len)
{
    inject(w, pctx, data, len);
}

void engine_hold(eng_worker *w) { w->c.held++; }

const void *engine_detach(eng_worker *w, const void *pctx, void *out)
{
    if (!w->e->be->detach)
        return pctx;
    w->e->be->detach(pctx, out);
    return out;
}

void engine_held(eng_worker *w, const void *pctx, const void *kept)
{
    w->c.held++;
    if (kept != pctx && w->e->be->verdict(w, pctx, 0, NULL, 0) < 0)
        w->c.verdict_errors++;
}

int engine_healthy_on(const engine *e) { return e->o->fw.healthy_mark && e->be->healthy && !e->o->slots; }

int engine_healthy(eng_worker *w, const void *pctx, int first)
{
    engine *e = w->e;
    if (!engine_healthy_on(e))
        return 0;
    e->be->healthy(w, pctx);
    if (first)
        w->c.healthy++;
    return 1;
}

int engine_workers_init(engine *e, unsigned nw, sbuf *err)
{
    if (e->w)
        engine_workers_free(e);
    e->w = xcalloc(nw, sizeof(*e->w));
    e->nw = nw;
    /* all workers complete before any extension sees one */
    for (unsigned i = 0; i < nw; i++) {
        eng_worker *w = &e->w[i];
        w->e = e;
        w->id = i;
        plat_mutex_init(&w->lock);
        sb_init(&w->line);
        if (fw_first_any(&e->o->fw) && e->be->engine_first)
            w->flows = flowtab_new(FLOW_MAX);
    }
    for (unsigned i = 0; e->o->ext && e->o->ext->worker_open && i < nw; i++) {
        if (e->o->ext->worker_open(&e->w[i], err) < 0)
            return -1;
        e->w[i].x_open = 1;
    }
    return 0;
}

void engine_workers_free(engine *e)
{
    for (unsigned i = 0; i < e->nw; i++) {
        eng_worker *w = &e->w[i];
        if (w->x_open && e->o->ext->worker_close)
            e->o->ext->worker_close(w);
        for (size_t k = 0; k < w->ndl; k++)
            free(w->dl[k].data);
        free(w->dl);
        flowtab_free(w->flows);
        sb_free(&w->line);
        strategy_free(w->st);
        plat_mutex_destroy(&w->lock);
    }
    free(e->w);
    e->w = NULL;
    e->nw = 0;
}

void engine_lock_workers(engine *e)
{
    for (unsigned i = 0; e->threaded && i < e->nw; i++)
        plat_mutex_lock(&e->w[i].lock);
}

void engine_unlock_workers(engine *e)
{
    for (unsigned i = e->threaded ? e->nw : 0; i-- > 0;)
        plat_mutex_unlock(&e->w[i].lock);
}

/* --ext-workers: each worker runs its own copy of e->st (call with the
 * workers locked). Returns 0, or -1 when a copy cannot be made. */
static int workers_strategy(engine *e)
{
    for (unsigned i = 0; e->threaded && i < e->nw; i++) {
        strategy *c = e->st ? strategy_clone(e->st) : NULL;
        if (e->st && !c)
            return -1;
        strategy_free(e->w[i].st);
        e->w[i].st = c;
    }
    return 0;
}

void engine_run_timers(engine *e, int all)
{
    for (unsigned i = 0; i < e->nw; i++) {
        if (all && e->w[i].x_open && e->o->ext->flush)
            e->o->ext->flush(&e->w[i]);
        run_timers(&e->w[i], all);
    }
}

void engine_counters(const engine *e, counters *sum, size_t *pending)
{
    memset(sum, 0, sizeof(*sum));
    *pending = 0;
    for (unsigned i = 0; i < e->nw; i++) {
        const counters *c = &e->w[i].c;
#define ENG_COUNTER_ADD(n) sum->n += c->n;
        ENG_COUNTERS(ENG_COUNTER_ADD)
#undef ENG_COUNTER_ADD
        *pending += e->w[i].ndl;
    }
}

/* The earliest due time of a delayed packet, 0 when none waits. */
static uint64_t next_due(const engine *e)
{
    uint64_t due = 0;
    for (unsigned i = 0; i < e->nw; i++)
        if (e->w[i].ndl && (!due || e->w[i].dl[0].due < due))
            due = e->w[i].dl[0].due;
    return due;
}

static void run(eng_worker *w, strategy *st, eng_slot *sl, gpkt *p, strat_dir dir, const uint8_t *data,
                size_t len, const void *pctx);

/* Runs a parsed packet through st (NULL: it passes) and frees it. */
static void packet(eng_worker *w, strategy *st, eng_slot *sl, gpkt *p, strat_dir dir, const uint8_t *data,
                   size_t len, const void *pctx)
{
    engine *e = w->e;
    int took;

    w->slot = sl;
    took = e->o->ext && e->o->ext->packet && e->o->ext->packet(w, &st, p, dir, data, len, pctx);
    w->slot = NULL;
    if (took) {
        w->xctx = NULL;
        pkt_free(p); /* the extensions gave the verdict */
        return;
    }
    if (e->paused || !st) {
        w->xctx = NULL;
        pkt_free(p);
        w->c.accepted++;
        give_verdict(w, pctx, 1, NULL, 0);
        return;
    }
    run(w, st, sl, p, dir, data, len, pctx);
}

void engine_replay(eng_worker *w, strategy *st, const uint8_t *data, size_t len, strat_dir dir, const void *pctx,
                   void *xctx)
{
    gpkt *p = pkt_parse(data, len);
    w->vdata = data;
    w->vlen = len;
    if (!p || w->e->paused || !st) {
        if (!p)
            w->c.parse_errors++;
        pkt_free(p);
        w->c.accepted++;
        give_verdict(w, pctx, 1, NULL, 0);
    } else {
        w->xctx = xctx;
        run(w, st, w->slot, p, dir, data, len, pctx);
    }
    w->vdata = NULL;
}

/* The results of a strategy with x-actions (--ext): everything goes in the
 * order of the list, as nfqws2 sends it. The packets an x-action made are
 * injected; the first other one (not delayed, else the first other) rides
 * on the captured packet's verdict at its place in the list, and without
 * such a packet the captured one is dropped (nfqws2's VERDICT_DROP). */
static void send_x(eng_worker *w, pktlist *out, const uint8_t *data, size_t len, const void *pctx)
{
    size_t vi = out->n;
    for (size_t i = 0; i < out->n && vi == out->n; i++)
        if (!out->v[i]->xgen && out->v[i]->sleep <= 0)
            vi = i;
    for (size_t i = 0; i < out->n && vi == out->n; i++)
        if (!out->v[i]->xgen)
            vi = i;
    if (vi == out->n) {
        w->c.dropped++;
        give_verdict(w, pctx, 0, NULL, 0);
    }
    for (size_t i = 0; i < out->n; i++) {
        gpkt *r = out->v[i];
        size_t blen;
        uint8_t *b = pkt_bytes(r, &blen);
        if (!blen) {
            w->c.send_errors++;
            LOGW("engine", "cannot build a result packet");
            free(b);
            if (i == vi)
                give_verdict(w, pctx, 0, NULL, 0);
            continue;
        }
        if (i == vi) {
            int same = blen == len && !memcmp(b, data, blen);
            if (!same)
                w->c.modified++;
            if (r->sleep > 0) {
                delay(w, b, blen, r->sleep, 1, pctx);
                continue;
            }
            w->c.accepted++;
            give_verdict(w, pctx, 1, same ? NULL : b, blen);
            record(w, b, blen);
        } else if (r->sleep > 0) {
            delay_x(w, b, blen, r->sleep, 0, pctx, r);
            continue;
        } else {
            inject_x(w, pctx, b, blen, r->xmark, r->xifout);
        }
        free(b);
    }
}

/* Runs p through st and sends what comes out: the first result rides on
 * the captured packet's verdict, the others are injected. */
static void run(eng_worker *w, strategy *st, eng_slot *sl, gpkt *p, strat_dir dir, const uint8_t *data,
                size_t len, const void *pctx)
{
    gpkt *orig = NULL;
    pktlist out = {0};
    int fired;
    size_t first = 0;

    if (log_enabled(LOG_TRACE))
        orig = pkt_copy(p);
    fired = strategy_apply_x(st, p, dir, &out, w->xctx);
    w->xctx = NULL;
    if (orig) {
        trace_pkt(w, dir, orig, &out, fired);
        pkt_free(orig);
    }
    if (fired)
        w->c.triggered++;
    if (!out.n) {
        w->c.dropped++;
        give_verdict(w, pctx, 0, NULL, 0);
        return;
    }
    if (sl && dir == DIR_OUT)
        sl->overhead += out.n - 1;
    if (dir == DIR_OUT) {
        for (size_t i = 0; i < out.n; i++)
            if (out.v[i]->xgen) {
                send_x(w, &out, data, len, pctx);
                pktlist_free(&out);
                return;
            }
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
        size_t blen;
        uint8_t *b = pkt_bytes(r, &blen);
        if (!blen) {
            w->c.send_errors++;
            LOGW("engine", "cannot build a result packet");
            free(b);
            if (i == first)
                give_verdict(w, pctx, 0, NULL, 0);
            continue;
        }
        if (i == first) {
            int same = blen == len && !memcmp(b, data, blen);
            if (!same)
                w->c.modified++;
            if (r->sleep > 0) {
                delay(w, b, blen, r->sleep, 1, pctx);
                continue;
            }
            w->c.accepted++;
            give_verdict(w, pctx, 1, same ? NULL : b, blen);
            record(w, b, blen);
        } else if (r->sleep > 0) {
            delay(w, b, blen, r->sleep, 0, pctx);
            continue;
        } else {
            inject(w, pctx, b, blen);
        }
        free(b);
    }
    pktlist_free(&out);
}

/* ---- events -------------------------------------------------------------- */

/* the trees of one direction; with --ext-workers their counts are the
 * sums over the workers' copies (the same trees in the same order) */
static void forest_json(jw *w, const engine *e, int in)
{
    atree **f = in ? e->st->in : e->st->out;
    size_t n = in ? e->st->nin : e->st->nout;
    sbuf s;
    sb_init(&s);
    jw_arr(w);
    for (size_t i = 0; i < n; i++) {
        uint64_t fired = 0;
        int copies = 0;
        for (unsigned k = 0; e->threaded && k < e->nw; k++) {
            const strategy *c = e->w[k].st;
            if (c && i < (in ? c->nin : c->nout)) {
                fired += (in ? c->in : c->out)[i]->fired;
                copies = 1;
            }
        }
        sb_reset(&s);
        tree_print(f[i], &s);
        jw_obj(w);
        jw_kstr(w, "tree", s.data);
        jw_kuint(w, "fired", copies ? fired : f[i]->fired);
        jw_obj_end(w);
    }
    jw_arr_end(w);
    sb_free(&s);
}

/* Counters shared by the "stats" event and the "stats" control command. */
static void stats_fields(engine *e, jw *w)
{
    counters sum, *c = &sum;
    size_t pending;
    engine_counters(e, &sum, &pending);
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
    jw_kuint(w, "pending", pending);
    jw_kuint(w, "send_errors", c->send_errors);
    jw_kuint(w, "verdict_errors", c->verdict_errors);
    jw_kuint(w, "parse_errors", c->parse_errors);
    jw_kuint(w, "overruns", c->overruns);
    jw_kuint(w, "passed_first", c->passed_first);
    jw_kuint(w, "flow_evictions", c->flow_evictions);
    jw_kuint(w, "held", c->held);
    if (e->o->fw.healthy_mark)
        jw_kuint(w, "healthy", c->healthy);
    if (e->threaded) {
        /* the packets of each worker: how the rules spread the flows */
        jw_kuint(w, "workers", e->nw);
        jw_key(w, "worker_pkts");
        jw_arr(w);
        for (unsigned i = 0; i < e->nw; i++)
            jw_uint(w, e->w[i].c.pkts_out + e->w[i].c.pkts_in);
        jw_arr_end(w);
    }
    if (e->st) {
        jw_key(w, "out_trees");
        forest_json(w, e, 0);
        jw_key(w, "in_trees");
        forest_json(w, e, 1);
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

/* pos >= 0: where a filter expression stops compiling */
static void emit_error_pos(const char *where, const char *msg, int pos)
{
    ev_t ev;
    if (!ev_on())
        return;
    ev_begin(&ev, "error");
    jw_kstr(&ev.w, "where", where);
    jw_kstr(&ev.w, "message", msg);
    if (pos >= 0)
        jw_kint(&ev.w, "pos", pos);
    ev_emit(&ev);
}

static void emit_error(const char *where, const char *msg) { emit_error_pos(where, msg, -1); }

static void emit_filter(engine *e, const char *source)
{
    ev_t ev;
    const char *f = e->be->filter ? e->be->filter(e) : NULL;
    if (!f)
        return;
    LOGI("engine", "filter (%s): %s", source, f);
    if (!ev_on())
        return;
    ev_begin(&ev, "filter");
    jw_kstr(&ev.w, "filter", f);
    jw_kstr(&ev.w, "source", source);
    ev_emit(&ev);
}

/* set_filter and reload_filter: a new capture filter, or -1 with err (the
 * current one stays). */
static int change_filter(engine *e, const char *expr, const char *source, jw *w, sbuf *err)
{
    sbuf out;
    int pos = -1;
    if (!e->be->set_filter) {
        sb_puts(err, "windows only");
        return -1;
    }
    sb_init(&out);
    if (e->be->set_filter(e, expr, &out, err, &pos) < 0) {
        LOGW("engine", "%s failed, keeping the current filter: %s", source, err->data);
        emit_error_pos("filter", err->data, pos);
        if (pos >= 0)
            jw_kint(w, "pos", pos);
        sb_free(&out);
        return -1;
    }
    jw_kstr(w, "filter", out.data);
    sb_free(&out);
    emit_filter(e, source);
    return 0;
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
    if (workers_strategy(e) < 0)
        LOGE("engine", "cannot copy the strategy for the workers");
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
        if (e->threaded)
            jw_kuint(w, "workers", e->nw);
        ports_format(&e->o->fw.ports, &s, ",", "-");
        jw_kstr(w, "ports", s.data);
        jw_kbool(w, "server_side", e->o->fw.server_side);
        jw_kstr(w, "firewall", e->fw_name ? e->fw_name : "none");
        jw_key(w, "filter");
        if (e->be->filter && e->be->filter(e))
            jw_str(w, e->be->filter(e));
        else
            jw_null(w);
        if (e->o->fw.filter_file)
            jw_kstr(w, "filter_file", e->o->fw.filter_file);
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
        for (unsigned i = 0; i < e->nw; i++) {
            memset(&e->w[i].c, 0, sizeof(e->w[i].c));
            if (e->w[i].st)
                strategy_reset(e->w[i].st);
        }
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
        if (workers_strategy(e) < 0)
            LOGE("engine", "cannot copy the strategy for the workers");
        emit_strategy(e);
        sb_init(&out);
        strategy_print(s, &out);
        jw_kstr(w, "strategy", out.data);
        sb_free(&out);
        return 0;
    }
    if (!strcmp(cmd, "set_filter")) {
        const char *text = json_get_str(req, "filter", NULL);
        if (!text && e->be->set_filter) {
            sb_puts(err, "set_filter needs \"filter\"");
            return -1;
        }
        return change_filter(e, text, "set_filter", w, err);
    }
    if (!strcmp(cmd, "reload_filter")) {
        sbuf text;
        int rc;
        if (!e->be->set_filter) { /* before the file: the platform comes first */
            sb_puts(err, "windows only");
            return -1;
        }
        if (!e->o->fw.filter_file) {
            sb_puts(err, "no --filter-file to re-read");
            return -1;
        }
        sb_init(&text);
        if (fw_read_filter_file(e->o->fw.filter_file, &text, err) < 0) {
            emit_error("filter", err->data);
            sb_free(&text);
            return -1;
        }
        rc = change_filter(e, text.data, "reload_filter", w, err);
        sb_free(&text);
        return rc;
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
    if (e->o->ext && e->o->ext->control) {
        int r = e->o->ext->control(e, cmd, req, w, err);
        if (r)
            return r < 0 ? -1 : 0;
    }
    sb_printf(err, "unknown command \"%s\"", cmd);
    return -1;
}

int engine_check(const engine_opts *o, sbuf *err)
{
    strategy *s = load_strategy(o, err);
    if (!s)
        return -1;
    strategy_free(s);
    return 0;
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

#define MAX_POLL (8 + CTL_MAX_CLIENTS + 1 + 4)

/* ---- --ext-workers --------------------------------------------------------- */

#define WORKER_WAKE_MS 200 /* a worker looks at e->wstop at least this often */

/* A worker's loop: its queue, its delayed packets, under its own lock */
static void worker_main(void *arg)
{
    eng_worker *w = arg;
    engine *e = w->e;
    while (!atomic_load_int(&e->wstop)) {
        plat_pollfd pfd;
        int timeout = WORKER_WAKE_MS, r;
        uint64_t now;
        plat_mutex_lock(&w->lock);
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = e->be->worker_fd(w);
        pfd.events = POLLIN;
        now = plat_now_ms();
        if (w->ndl)
            timeout = w->dl[0].due <= now ? 0 : (int)MIN(w->dl[0].due - now, (uint64_t)timeout);
        plat_mutex_unlock(&w->lock);
        r = plat_poll(&pfd, 1, timeout);
        plat_mutex_lock(&w->lock);
        if (r > 0 && e->be->worker_ready(w) < 0) {
            plat_mutex_unlock(&w->lock);
            atomic_store_int(&e->wfail, 1);
            return;
        }
        run_timers(w, 0);
        if (w->flows && plat_now_ms() >= w->next_expire) {
            flowtab_expire(w->flows, plat_now_ms());
            w->next_expire = plat_now_ms() + 5000;
        }
        plat_mutex_unlock(&w->lock);
    }
}

static int workers_start(engine *e)
{
    (void)rng_u64(); /* the generators' seed is set before the threads draw */
    for (unsigned i = 0; i < e->nw; i++) {
        if (plat_thread_start(&e->w[i].thread, worker_main, &e->w[i]) != 0)
            return -1;
        e->w[i].thread_on = 1;
    }
    return 0;
}

static void workers_stop(engine *e)
{
    atomic_store_int(&e->wstop, 1);
    for (unsigned i = 0; i < e->nw; i++)
        if (e->w[i].thread_on) {
            plat_thread_join(e->w[i].thread);
            e->w[i].thread_on = 0;
        }
}

/* Events reach the control socket's clients through the main loop: the
 * workers emit them on their own threads (the log's lock held) */
static void evq_push(const char *line, size_t len, void *ctx)
{
    engine *e = ctx;
    plat_mutex_lock(&e->evq_lock);
    if (e->evq.len < (8u << 20)) /* a stuck main loop loses events, not memory */
        sb_append(&e->evq, line, len);
    plat_mutex_unlock(&e->evq_lock);
}

static void evq_flush(engine *e)
{
    sbuf q;
    if (!e->threaded || !e->ctl)
        return;
    plat_mutex_lock(&e->evq_lock);
    q = e->evq;
    sb_init(&e->evq);
    plat_mutex_unlock(&e->evq_lock);
    if (q.len)
        ctl_broadcast(q.data, q.len, e->ctl);
    sb_free(&q);
}

int engine_run(engine_opts *o)
{
    engine e;
    sbuf err;
    int rc = EXIT_OK, opened = 0, running = 0;
    uint64_t next_stats, deadline;
    const char *reason = "signal";

#ifndef HAVE_BACKEND
    if (!o->backend) {
        LOGE("engine", "no packet engine on %s: geneva run needs Linux (NFQUEUE) or Windows (WinDivert)",
             plat_os_name());
        return EXIT_PRIV;
    }
#endif
    memset(&e, 0, sizeof(e));
    e.o = o;
    e.be = o->backend ? o->backend : BACKEND;
    plat_mutex_init(&e.lock);
    plat_mutex_init(&e.pw_lock);
    plat_mutex_init(&e.evq_lock);
    sb_init(&e.evq);
    e.threaded = o->workers > 1 && !o->slots && e.be && e.be->worker_fd && e.be->worker_ready;
    sb_init(&err);
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
        if (e.threaded)
            ev_set_tap(evq_push, &e);
        else
            ev_set_tap(ctl_broadcast, e.ctl);
        LOGI("engine", "control socket %s", o->control);
    }
    sb_reset(&err);
    if (engine_workers_init(&e, e.threaded ? o->workers : 1, &err) < 0) {
        LOGE("engine", "%s", err.data);
        emit_error("ext", err.data);
        rc = EXIT_FAIL;
        goto out;
    }
    if (workers_strategy(&e) < 0) {
        LOGE("engine", "cannot copy the strategy for the workers");
        emit_error("strategy", "cannot copy the strategy for the workers");
        rc = EXIT_STRATEGY;
        goto out;
    }
    sb_reset(&err);
    opened = 1;
    e.err_pos = -1;
    rc = e.be->open(&e, &err);
    if (rc != EXIT_OK) {
        LOGE("engine", "%s", err.data);
        emit_error_pos(e.err_where ? e.err_where : e.be->name, err.data, e.err_pos);
        goto out;
    }
    running = 1;
    if (err.len)
        LOGW("engine", "%s", err.data);
    if (e.threaded) {
        if (workers_start(&e) < 0) {
            LOGE("engine", "cannot start the worker threads");
            emit_error("engine", "cannot start the worker threads");
            rc = EXIT_FAIL;
            goto out;
        }
        LOGI("engine", "%u workers on queues %u-%u", e.nw, o->fw.queue, o->fw.queue + e.nw - 1);
    }
    if (o->on_ready) {
        o->on_ready(o->ready_ctx, 0);
        o->on_ready = NULL;
    }
    plat_mutex_lock(&e.lock);
    if (e.st)
        emit_strategy(&e);
    emit_filter(&e, "start");
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
        if (atomic_load_int(&e.wfail)) {
            LOGE("engine", "a worker's queue failed");
            rc = EXIT_FAIL;
            reason = "error";
            break;
        }
        evq_flush(&e);
        plat_pollfd pfd[MAX_POLL];
        size_t nbe, nctl, nx = 0;
        uint64_t now, due;
        int timeout = 1000, r;

        plat_mutex_lock(&e.lock);
        nbe = e.be->pollfds(&e, pfd, 8);
        nctl = ctl_pollfds(e.ctl, pfd + nbe, MAX_POLL - nbe - 4);
        if (e.o->ext && e.o->ext->pollfds)
            nx = e.o->ext->pollfds(&e, pfd + nbe + nctl, 4);
        now = plat_now_ms();
        if (o->stop)
            timeout = 100; /* the stop flag is polled */
        if (e.threaded)
            timeout = MIN(timeout, WORKER_WAKE_MS); /* the workers' events, their failure */
        else if ((due = next_due(&e)) != 0)
            timeout = due <= now ? 0 : (int)MIN(due - now, (uint64_t)timeout);
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
        r = plat_poll(pfd, (unsigned)(nbe + nctl + nx), timeout);
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
        if (r > 0 && nctl) {
            engine_lock_workers(&e);
            ctl_dispatch(e.ctl, pfd + nbe, nctl, on_control, &e);
            engine_unlock_workers(&e);
        }
        /* also without events: their timers (and with --ext-workers the
         * extensions' once a second work, see ext_hooks.ready) */
        if (nx || (e.threaded && e.o->ext && e.o->ext->ready))
            e.o->ext->ready(&e, pfd + nbe + nctl, nx);
        if (!e.threaded) { /* the workers run their own timers */
            engine_run_timers(&e, 0);
            for (unsigned i = 0; i < e.nw; i++) {
                eng_worker *w = &e.w[i];
                if (w->flows && plat_now_ms() >= w->next_expire) {
                    flowtab_expire(w->flows, plat_now_ms());
                    w->next_expire = plat_now_ms() + 5000;
                }
            }
        }
        if (sig_hup) {
            sbuf herr;
            sig_hup = 0;
            sb_init(&herr);
            engine_lock_workers(&e);
            if (reload(&e, &herr) < 0 && !e.o->strategy_file)
                LOGI("engine", "SIGHUP: %s", herr.data);
            sb_reset(&herr);
            if (e.o->ext && e.o->ext->control)
                e.o->ext->control(&e, "reload_lists", NULL, NULL, &herr);
            engine_unlock_workers(&e);
            sb_free(&herr);
        }
        now = plat_now_ms();
        if (sig_usr1 || (next_stats && now >= next_stats)) {
            sig_usr1 = 0;
            engine_lock_workers(&e);
            emit_stats(&e);
            engine_unlock_workers(&e);
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
    workers_stop(&e); /* from here on one thread: no worker locks */
    if (opened) {
        e.be->stop(&e);
        plat_mutex_lock(&e.lock);
        engine_run_timers(&e, 1); /* let held packets go before the capture closes */
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
        evq_flush(&e);
        ev_set_tap(NULL, NULL);
        ctl_close(e.ctl);
    }
    if (!o->embedded)
        remove_signals();
    engine_workers_free(&e);
    if (e.pw && pcap_close_write(e.pw) < 0 && rc == EXIT_OK)
        rc = EXIT_IO;
    strategy_free(e.st);
    sb_free(&err);
    sb_free(&e.evq);
    plat_mutex_destroy(&e.evq_lock);
    plat_mutex_destroy(&e.pw_lock);
    plat_mutex_destroy(&e.lock);
    return rc;
}
