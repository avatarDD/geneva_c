/*
 * The evaluator (see evaluator.h).
 */
#include "evaluator.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "geneva.h"
#include "json.h"
#include "log.h"

struct evaluator {
    eval_opts *o;
    eng_slots slots;
    eng_slot slotv[EVAL_MAX_WORKERS];
    probe_ports ports[EVAL_MAX_WORKERS];
    engine_opts eng;
    plat_thread_t eng_thread;
    int eng_running;
    volatile int eng_stop;
    volatile int eng_state; /* 0 starting, 1 running, else the exit code + 2 */
    int eng_rc;
    uint64_t ext_id;
    plat_mutex_t lock; /* the GA batch: next individual */
};

void eval_opts_default(eval_opts *o)
{
    memset(o, 0, sizeof(*o));
    o->runs = 1;
    o->by = FIT_AVG;
    o->workers = 1;
    o->use_engine = 1;
    fw_config_default(&o->fw);
    o->fw.queue = 301; /* next to geneva run's default 300 */
    o->apply_fw = 1;
    o->port_base = 30000;
    o->ports_per_worker = 64;
    o->skip_empty = 1;
    o->probe.timeout = 5;
}

/* ---- the engine thread --------------------------------------------------- */

static void on_ready(void *ctx, int rc)
{
    evaluator *ev = ctx;
    atomic_store_int(&ev->eng_state, rc == 0 ? 1 : rc + 2);
}

static void engine_thread(void *arg)
{
    evaluator *ev = arg;
    ev->eng_rc = engine_run(&ev->eng);
    /* stopped, by us or by an error: no strategy applies any more */
    atomic_store_int(&ev->eng_state, ev->eng_rc + 2);
}

static int stopped(const evaluator *ev) { return ev->o->stop && *ev->o->stop; }

int evaluator_open(eval_opts *o, evaluator **out, sbuf *err)
{
    evaluator *ev = xcalloc(1, sizeof(*ev));
    size_t nw = (size_t)o->workers;
    ev->o = o;
    plat_mutex_init(&ev->lock);
    plat_mutex_init(&ev->slots.lock);
    ev->slots.base = o->port_base;
    ev->slots.size = o->ports_per_worker;
    ev->slots.n = nw;
    ev->slots.v = ev->slotv;
    for (size_t i = 0; i < nw; i++) {
        ev->ports[i].lo = (uint16_t)(o->port_base + i * o->ports_per_worker);
        ev->ports[i].hi = (uint16_t)(ev->ports[i].lo + o->ports_per_worker - 1);
    }
    *out = ev;
    if (!o->use_engine)
        return EXIT_OK;

    if (!plat_is_privileged()) {
#ifdef _WIN32
        sb_puts(err, "the evaluator runs the engine: start it as Administrator (or use --no-engine)");
#else
        sb_puts(err, "the evaluator runs the engine: run it as root (or use --no-engine)");
#endif
        return EXIT_PRIV;
    }
    engine_opts_default(&ev->eng);
    ev->eng.fw = o->fw;
    ev->eng.apply_fw = o->apply_fw;
    ev->eng.fw.ports.n = 1;
    ev->eng.fw.ports.lo[0] = o->port_base;
    ev->eng.fw.ports.hi[0] = (uint16_t)(o->port_base + nw * o->ports_per_worker - 1);
    ev->eng.fw.server_side = 1; /* outbound packets come from our ports */
    ev->eng.fw.tcp = 1;
    ev->eng.fw.udp = o->probe.kind == PROBE_DNS || o->probe.kind == PROBE_EXEC || o->probe.kind == PROBE_EXTERNAL;
    ev->eng.slots = &ev->slots;
    ev->eng.embedded = 1;
    ev->eng.stop = &ev->eng_stop;
    ev->eng.on_ready = on_ready;
    ev->eng.ready_ctx = ev;
    if (plat_thread_start(&ev->eng_thread, engine_thread, ev) < 0) {
        sb_puts(err, "cannot start the engine thread");
        return EXIT_FAIL;
    }
    ev->eng_running = 1;
    for (int i = 0; i < 3000 && atomic_load_int(&ev->eng_state) == 0; i++)
        plat_sleep_ms(10);
    switch (atomic_load_int(&ev->eng_state)) {
    case 0:
        sb_puts(err, "the engine did not start in 30 s");
        return EXIT_FAIL;
    case 1:
        LOGI("eval", "engine ready: local ports %u-%u, queue %u", (unsigned)ev->eng.fw.ports.lo[0],
             (unsigned)ev->eng.fw.ports.hi[0], (unsigned)ev->eng.fw.queue);
        return EXIT_OK;
    default:
        sb_puts(err, "the engine failed to start (see the log above)");
        return atomic_load_int(&ev->eng_state) - 2;
    }
}

void evaluator_close(evaluator *ev)
{
    if (!ev)
        return;
    if (ev->eng_running) {
        atomic_store_int(&ev->eng_stop, 1);
        plat_thread_join(ev->eng_thread);
    }
    for (size_t i = 0; i < ev->slots.n; i++) {
        eng_slot *sl = &ev->slotv[i];
        for (size_t k = 0; k < sl->ncap; k++)
            pkt_free(sl->cap[k]);
        free(sl->cap);
    }
    plat_mutex_destroy(&ev->slots.lock);
    plat_mutex_destroy(&ev->lock);
    free(ev);
}

static int engine_alive(evaluator *ev)
{
    return !ev->eng_running || atomic_load_int(&ev->eng_state) == 1;
}

/* ---- fitness ------------------------------------------------------------- */

double eval_punish(double fitness, const strategy *s, uint64_t overhead)
{
    size_t unused = 0;
    if (!s)
        return fitness;
    /* punish_complexity: one point per action, only when it worked */
    if (fitness > 0)
        fitness -= (double)strategy_len(s);
    /* punish_unused: ten points for each tree that never fired */
    for (size_t i = 0; i < s->nout; i++)
        unused += s->out[i]->fired == 0;
    for (size_t i = 0; i < s->nin; i++)
        unused += s->in[i]->fired == 0;
    fitness -= 10.0 * (double)unused;
    /* the engine's overhead: half a point per extra packet */
    if (fitness > 0)
        fitness -= (double)(int64_t)(overhead / 2);
    return fitness;
}

static double combine(fitness_by by, const double *v, size_t n, double total)
{
    double r = v[0];
    if (by == FIT_AVG)
        return round(total / (double)n * 100.0) / 100.0;
    for (size_t i = 1; i < n; i++)
        r = by == FIT_MIN ? MIN(r, v[i]) : MAX(r, v[i]);
    return r;
}

/* Waits for the controller's verdict on an external run. Returns 0, or -1
 * when its input closed. */
static int external_run(evaluator *ev, size_t w, const char *text, int run, probe_res *r)
{
    uint64_t id = ++ev->ext_id;
    ev_t e;
    char line[4096];
    memset(r, 0, sizeof(*r));
    ev_begin(&e, "eval_request");
    jw_kuint(&e.w, "id", id);
    jw_kstr(&e.w, "strategy", text ? text : "");
    jw_kint(&e.w, "run", run);
    {
        char lp[16];
        snprintf(lp, sizeof(lp), "%u-%u", (unsigned)ev->ports[w].lo, (unsigned)ev->ports[w].hi);
        jw_kstr(&e.w, "lports", lp);
    }
    ev_emit(&e);
    while (fgets(line, sizeof(line), ev->o->ext_in)) {
        const char *jerr = NULL;
        json_val *v = json_parse(line, &jerr);
        const json_val *fit;
        if (!v) {
            LOGW("eval", "external result: %s", jerr ? jerr : "bad JSON");
            continue;
        }
        if ((uint64_t)json_get_int(v, "id", 0) != id) {
            json_free(v);
            continue;
        }
        fit = json_get(v, "fitness");
        if (fit && fit->type == JSON_NUM) {
            r->fitness = json_get_num(v, "fitness", 0);
            r->outcome = r->fitness > 0 ? PO_OK : PO_FAILED;
        } else {
            r->outcome = json_get_bool(v, "ok", 0) ? PO_OK : PO_FAILED;
            r->fitness = probe_fitness(r->outcome);
        }
        snprintf(r->detail, sizeof(r->detail), "%s", json_get_str(v, "detail", "external"));
        json_free(v);
        return 0;
    }
    LOGE("eval", "the controller closed the input of external results");
    return -1;
}

static void pause_after_failure(evaluator *ev)
{
    uint64_t end = plat_now_ms() + (uint64_t)(ev->o->residual_wait * 1000.0);
    while (plat_now_ms() < end && !stopped(ev))
        plat_sleep_ms(100);
}

/* Evaluates text with worker w. */
static int eval_slot(evaluator *ev, size_t w, const char *text, eval_result *res)
{
    double fits[64] = {0}, total = 0;
    int runs = ev->o->runs;
    memset(res, 0, sizeof(*res));
    if (runs > 64)
        runs = 64;
    for (int run = 0; run < runs; run++) {
        strategy *st = NULL;
        uint64_t overhead = 0;
        probe_res pr;
        double f;
        if (stopped(ev))
            return -1;
        if (!engine_alive(ev)) {
            LOGE("eval", "the engine stopped (exit code %d)", atomic_load_int(&ev->eng_state) - 2);
            return -1;
        }
        if (text && *text) {
            sbuf err;
            sb_init(&err);
            st = strategy_parse(text, &err);
            if (!st) {
                LOGW("eval", "%s: %s", text, err.data);
                sb_free(&err);
                res->fitness = -1000;
                res->runs = 0;
                snprintf(res->last.detail, sizeof(res->last.detail), "bad strategy");
                return 0;
            }
            sb_free(&err);
        }
        if (ev->eng_running) {
            plat_mutex_lock(&ev->slots.lock);
            ev->slotv[w].st = st;
            ev->slotv[w].overhead = 0;
            ev->slotv[w].pkts = 0;
            plat_mutex_unlock(&ev->slots.lock);
        }
        if (ev->o->probe.kind == PROBE_EXTERNAL) {
            if (external_run(ev, w, text, run, &pr) < 0) {
                if (ev->eng_running) {
                    plat_mutex_lock(&ev->slots.lock);
                    ev->slotv[w].st = NULL;
                    plat_mutex_unlock(&ev->slots.lock);
                }
                strategy_free(st);
                return -1;
            }
        } else {
            probe_run(&ev->o->probe, &ev->ports[w], &pr);
        }
        if (ev->eng_running) {
            plat_mutex_lock(&ev->slots.lock);
            ev->slotv[w].st = NULL;
            overhead = ev->slotv[w].overhead;
            plat_mutex_unlock(&ev->slots.lock);
        }
        f = eval_punish(pr.fitness, st, overhead);
        LOGD("eval", "(%d/%d) %s: %s (%s) -> fitness %g", run + 1, runs, text && *text ? text : "(none)",
             probe_outcome_name(pr.outcome), pr.detail, f);
        strategy_free(st);
        fits[run] = f;
        if (run < (int)ARRAY_LEN(res->run_fit))
            res->run_fit[run] = f;
        total += f;
        res->last = pr;
        res->runs = run + 1;
        if (f < 0 && ev->o->residual_wait > 0)
            pause_after_failure(ev);
    }
    res->fitness = combine(ev->o->by, fits, (size_t)res->runs, total);
    return 0;
}

static void emit_eval(const char *text, const eval_result *r)
{
    ev_t e;
    if (!ev_enabled())
        return;
    ev_begin(&e, "eval");
    jw_kstr(&e.w, "strategy", text ? text : "");
    jw_kdbl(&e.w, "fitness", r->fitness);
    jw_kint(&e.w, "runs", r->runs);
    jw_kstr(&e.w, "outcome", probe_outcome_name(r->last.outcome));
    jw_kstr(&e.w, "detail", r->last.detail);
    ev_emit(&e);
}

int evaluator_eval(evaluator *ev, const char *text, eval_result *res)
{
    int rc = eval_slot(ev, 0, text, res);
    if (rc == 0)
        emit_eval(text, res);
    return rc;
}

int evaluator_baseline(evaluator *ev, eval_result *res, int *reachable, gpkt ***env, size_t *nenv)
{
    eng_slot *sl = &ev->slotv[0];
    int rc;
    *reachable = 0;
    if (ev->eng_running && env) {
        plat_mutex_lock(&ev->slots.lock);
        sl->capture = 1;
        plat_mutex_unlock(&ev->slots.lock);
    }
    rc = eval_slot(ev, 0, NULL, res);
    if (ev->eng_running && env) {
        plat_mutex_lock(&ev->slots.lock);
        sl->capture = 0;
        *env = xrealloc(*env, (*nenv + sl->ncap + 1) * sizeof(**env));
        for (size_t i = 0; i < sl->ncap; i++)
            (*env)[(*nenv)++] = sl->cap[i];
        free(sl->cap);
        sl->cap = NULL;
        sl->ncap = sl->capcap = 0;
        plat_mutex_unlock(&ev->slots.lock);
    }
    for (int i = 0; i < res->runs && i < (int)ARRAY_LEN(res->run_fit); i++)
        if (res->run_fit[i] > 0)
            *reachable = 1;
    if (rc == 0)
        emit_eval("", res);
    return rc;
}

/* ---- the GA batch -------------------------------------------------------- */

typedef struct {
    evaluator *ev;
    ga_ind *inds;
    size_t n, next; /* the individual the next free worker takes */
    int failed;
} batch;

typedef struct {
    batch *b;
    size_t w; /* worker = slot */
} worker_arg;

static void eval_ind(evaluator *ev, size_t w, ga_ind *ind, int *failed)
{
    eval_result r;
    if (ev->o->skip_empty && strategy_len(ind->s) == 0) {
        ind->fit = -1000;
        LOGI("eval", "[skipped] Fitness -1000: %s", ind->str);
        return;
    }
    if (eval_slot(ev, w, ind->str, &r) < 0) {
        *failed = 1;
        return;
    }
    ind->fit = r.fitness;
    LOGI("eval", "Fitness %g: %s (%s: %s)", r.fitness, ind->str, probe_outcome_name(r.last.outcome), r.last.detail);
    emit_eval(ind->str, &r);
}

static void worker(void *arg)
{
    worker_arg *a = arg;
    batch *b = a->b;
    evaluator *ev = b->ev;
    for (;;) {
        size_t i;
        int failed = 0;
        plat_mutex_lock(&ev->lock);
        if (b->failed || b->next >= b->n) {
            plat_mutex_unlock(&ev->lock);
            return;
        }
        i = b->next++;
        plat_mutex_unlock(&ev->lock);
        eval_ind(ev, a->w, &b->inds[i], &failed);
        if (failed) {
            plat_mutex_lock(&ev->lock);
            b->failed = 1;
            plat_mutex_unlock(&ev->lock);
        }
    }
}

int evaluator_ga(void *ctx, ga_ind *inds, size_t n)
{
    evaluator *ev = ctx;
    size_t nw = MIN((size_t)ev->o->workers, n);
    batch b = {ev, inds, n, 0, 0};
    worker_arg args[EVAL_MAX_WORKERS];
    plat_thread_t th[EVAL_MAX_WORKERS];
    int started[EVAL_MAX_WORKERS] = {0};

    for (size_t i = 0; i < n; i++)
        inds[i].fit = -1000;
    if (nw <= 1) {
        for (size_t i = 0; i < n && !b.failed; i++)
            eval_ind(ev, 0, &inds[i], &b.failed);
        return b.failed || stopped(ev) ? -1 : 0;
    }
    for (size_t w = 0; w < nw; w++) {
        args[w].b = &b;
        args[w].w = w;
        started[w] = plat_thread_start(&th[w], worker, &args[w]) == 0;
    }
    for (size_t w = 0; w < nw; w++)
        if (started[w])
            plat_thread_join(th[w]);
    if (!started[0] && b.next == 0)
        worker(&args[0]); /* no threads at all: do it here */
    return b.failed || stopped(ev) ? -1 : 0;
}
