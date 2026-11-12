/* The engine core without a capture: a fake backend records verdicts and
 * injections, so the worker context (X1 of docs/EXT_ROADMAP.md) and the
 * extension hooks are tested without NFQUEUE or WinDivert. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "engine_int.h"
#include "ext_opt.h"
#include "strategy.h"
#include "test.h"
#include "util.h"

/* "base" of golden_pkt.h: TCP 10.0.0.1:40000 -> 10.0.0.2:80 [PA] with an HTTP GET */
static const char base_hex[] =
    "4500005500014000400626a00a0000010a0000029c400050000003e8000007d0701801f67cf70000020405b4"
    "01030307474554202f20485454502f312e310d0a486f73743a206578616d706c652e636f6d0d0a0d0a";

static uint8_t pkt_buf[256];
static size_t pkt_len;

typedef struct {
    int verdicts, accepts, drops, injects, verdict_data, last_worker;
} fake_log;
static fake_log flog;

static int fake_verdict(eng_worker *w, const void *pctx, int accept, const uint8_t *data, size_t len)
{
    flog.verdicts++;
    flog.last_worker = (int)w->id;
    if (accept)
        flog.accepts++;
    else
        flog.drops++;
    if (data)
        flog.verdict_data++;
    return 0;
}

static int fake_inject(eng_worker *w, const void *pctx, const uint8_t *data, size_t len)
{
    flog.injects++;
    flog.last_worker = (int)w->id;
    return 0;
}

static const backend fake_backend = {
    "fake", sizeof(uint32_t), NULL, NULL, NULL, NULL, NULL, fake_verdict, fake_inject, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
};

static void load_base(void)
{
    long n = hex_decode(base_hex, pkt_buf, sizeof(pkt_buf));
    CHECK(n > 0);
    pkt_len = n > 0 ? (size_t)n : 0;
}

static void setup(engine *e, engine_opts *o, const char *strategy_text, unsigned nw)
{
    sbuf err;
    engine_opts_default(o);
    memset(e, 0, sizeof(*e));
    e->o = o;
    e->be = &fake_backend;
    plat_mutex_init(&e->lock);
    sb_init(&err);
    e->st = strategy_text ? strategy_parse(strategy_text, &err) : NULL;
    CHECK(!strategy_text || e->st);
    CHECK_INT(engine_workers_init(e, nw, &err), 0);
    sb_free(&err);
    memset(&flog, 0, sizeof(flog));
    load_base();
}

static void teardown(engine *e)
{
    engine_workers_free(e);
    strategy_free(e->st);
    plat_mutex_destroy(&e->lock);
}

static void test_worker_path(void)
{
    engine e;
    engine_opts o;
    uint32_t id = 7;
    counters c;
    size_t pending;

    t_current = "engine worker: duplicate";
    setup(&e, &o, "[TCP:flags:PA]-duplicate-| \\/", 1);
    engine_packet(&e.w[0], pkt_buf, pkt_len, DIR_OUT, &id);
    CHECK_INT(flog.accepts, 1);
    CHECK_INT(flog.verdict_data, 0); /* the first copy is the original: exact verdict */
    CHECK_INT(flog.injects, 1);
    CHECK_INT(e.w[0].c.pkts_out, 1);
    CHECK_INT(e.w[0].c.triggered, 1);
    CHECK_INT(e.w[0].c.injected, 1);
    teardown(&e);

    t_current = "engine worker: drop and pass";
    setup(&e, &o, "[TCP:flags:PA]-drop-| \\/", 1);
    engine_packet(&e.w[0], pkt_buf, pkt_len, DIR_OUT, &id);
    CHECK_INT(flog.drops, 1);
    CHECK_INT(e.w[0].c.dropped, 1);
    engine_packet(&e.w[0], pkt_buf, pkt_len, DIR_IN, &id); /* no inbound tree: passes */
    CHECK_INT(flog.accepts, 1);
    CHECK_INT(e.w[0].c.pkts_in, 1);
    e.paused = 1;
    engine_packet(&e.w[0], pkt_buf, pkt_len, DIR_OUT, &id);
    CHECK_INT(flog.accepts, 2);
    CHECK_INT(e.w[0].c.dropped, 1);
    teardown(&e);

    t_current = "engine worker: delayed packets";
    setup(&e, &o, "[TCP:flags:PA]-sleep{30}-| \\/", 1);
    engine_packet(&e.w[0], pkt_buf, pkt_len, DIR_OUT, &id);
    CHECK_INT(flog.verdicts, 0); /* held */
    CHECK_INT(e.w[0].ndl, 1);
    engine_counters(&e, &c, &pending);
    CHECK_INT(pending, 1);
    CHECK_INT(c.delayed, 1);
    engine_run_timers(&e, 0); /* not due yet */
    CHECK_INT(flog.verdicts, 0);
    engine_run_timers(&e, 1);
    CHECK_INT(flog.accepts, 1);
    CHECK_INT(e.w[0].ndl, 0);
    /* a held packet when the engine stops is dropped by free, not sent */
    engine_packet(&e.w[0], pkt_buf, pkt_len, DIR_OUT, &id);
    teardown(&e);
    CHECK_INT(flog.verdicts, 1);

    t_current = "engine workers: counters add up";
    setup(&e, &o, "[TCP:flags:PA]-duplicate-| \\/", 3);
    engine_packet(&e.w[0], pkt_buf, pkt_len, DIR_OUT, &id);
    engine_packet(&e.w[2], pkt_buf, pkt_len, DIR_OUT, &id);
    CHECK_INT(flog.last_worker, 2); /* the backend answers through the packet's worker */
    engine_packet(&e.w[2], pkt_buf, pkt_len, DIR_IN, &id);
    engine_counters(&e, &c, &pending);
    CHECK_INT(c.pkts_out, 2);
    CHECK_INT(c.pkts_in, 1);
    CHECK_INT(c.injected, 2);
    CHECK_INT(e.w[1].c.pkts_out, 0);
    teardown(&e);

    t_current = "engine worker: parse error";
    setup(&e, &o, "\\/", 1);
    engine_packet(&e.w[0], (const uint8_t *)"\x45\x00", 2, DIR_OUT, &id);
    CHECK_INT(flog.accepts, 1);
    CHECK_INT(e.w[0].c.parse_errors, 1);
    teardown(&e);
}

/* ---- --ext-workers: engine_run with worker threads ------------------------ */

#ifndef _WIN32
#  include <unistd.h>
#  if GENEVA_EXT
#    include "ext/ext.h"
#  endif

#  define TW_N 4      /* workers */
#  define TW_PKTS 400 /* packets per worker */

/* each worker's pipe: one byte is one packet */
static int tw_pipe[TW_N][2];
static int tw_acc[TW_N], tw_inj[TW_N], tw_wrong[TW_N]; /* written by worker i only */
static volatile int tw_done, tw_stop;

static int tw_open(engine *e, sbuf *err) { return 0; }
static void tw_nop(engine *e) {}
static size_t tw_pollfds(engine *e, plat_pollfd *fds, size_t max) { return 0; }
static int tw_ready(engine *e, const plat_pollfd *fds, size_t n) { return 0; }

static int tw_verdict(eng_worker *w, const void *pctx, int accept, const uint8_t *data, size_t len)
{
    uint32_t id;
    memcpy(&id, pctx, sizeof(id));
    if (id != w->id)
        tw_wrong[w->id]++;
    if (accept)
        tw_acc[w->id]++;
    if (atomic_fetch_add_int(&tw_done, 1) + 1 == TW_N * TW_PKTS)
        atomic_store_int(&tw_stop, 1);
    return 0;
}

static int tw_inject(eng_worker *w, const void *pctx, const uint8_t *data, size_t len)
{
    tw_inj[w->id]++;
    return 0;
}

static sock_t tw_fd(eng_worker *w) { return tw_pipe[w->id][0]; }

static int tw_worker_ready(eng_worker *w)
{
    uint8_t b[64];
    ssize_t n = read(tw_pipe[w->id][0], b, sizeof(b));
    uint32_t id = w->id;
    for (ssize_t i = 0; i < n; i++)
        engine_packet(w, pkt_buf, pkt_len, DIR_OUT, &id);
    return n < 0 ? -1 : 0;
}

static const backend tw_backend = {
    "threads", sizeof(uint32_t), tw_open, tw_nop, tw_nop, tw_pollfds, tw_ready, tw_verdict, tw_inject, 0,
    NULL, NULL, NULL, NULL, NULL, tw_fd, tw_worker_ready,
};

#  define TW_STRATEGY "[TCP:flags:PA]-duplicate(tamper{TCP:seq:corrupt},sleep{5})-| \\/"

/* ext: the --ext command line (NULL: without), with_inj: whether the
 * packets get the strategy */
static void test_threads(const char *name, const char **ext, int with_inj)
{
    engine_opts o;
    uint8_t ones[TW_PKTS];
    int acc = 0, inj = 0, wrong = 0, busy = 0;

    t_current = name;
    load_base();
    memset(ones, 1, sizeof(ones));
    memset(tw_acc, 0, sizeof(tw_acc));
    memset(tw_inj, 0, sizeof(tw_inj));
    memset(tw_wrong, 0, sizeof(tw_wrong));
    tw_done = tw_stop = 0;
    for (int i = 0; i < TW_N; i++) {
        CHECK_INT(pipe(tw_pipe[i]), 0);
        CHECK(write(tw_pipe[i][1], ones, sizeof(ones)) == (ssize_t)sizeof(ones));
    }
    engine_opts_default(&o);
    o.apply_fw = 0;
    o.embedded = 1;
    o.stop = &tw_stop;
    o.duration = 30; /* a hang fails the checks below, not the run */
    o.workers = TW_N;
    o.backend = &tw_backend;
    /* the delayed copies go out from the workers' own timers */
    o.strategy = TW_STRATEGY;
#  if GENEVA_EXT
    if (ext) {
        static const optdef defs[] = {{"strategy", 's', 1, "S", ""}, EXT_OPT, EXT_PROFILE_OPTS,
                                      {NULL, 0, 0, NULL, NULL}};
        args_t a;
        char err[128];
        int argc = 0;
        while (ext[argc])
            argc++;
        CHECK_INT(args_parse(&a, argc, (char **)ext, defs, err, sizeof(err)), 0);
        CHECK_INT(ext_parse_args(&a, "test"), 0);
        args_free(&a);
        o.ext = ext_engine_hooks();
        o.strategy = "\\/";
    }
#  endif
    CHECK_INT(engine_run(&o), 0);
#  if GENEVA_EXT
    if (ext)
        ext_deactivate();
#  endif
    for (int i = 0; i < TW_N; i++) {
        acc += tw_acc[i], inj += tw_inj[i], wrong += tw_wrong[i];
        busy += tw_acc[i] == TW_PKTS;
        close(tw_pipe[i][0]);
        close(tw_pipe[i][1]);
    }
    CHECK_INT(acc, TW_N * TW_PKTS);
    CHECK_INT(busy, TW_N); /* every worker its own packets, */
    CHECK_INT(wrong, 0);   /* answered through itself */
    CHECK_INT(inj, with_inj ? TW_N * TW_PKTS : 0);
}
#endif

/* ---- extension hooks ----------------------------------------------------- */

static int hk_opened, hk_closed, hk_packets, hk_verdict, hk_fail_open;

static int hk_open(eng_worker *w, sbuf *err)
{
    CHECK(w->e != NULL); /* every worker is complete before the first open */
    if (hk_fail_open && w->id == 1) {
        sb_puts(err, "no state for worker 1");
        return -1;
    }
    hk_opened++;
    w->x = xcalloc(1, 16);
    return 0;
}

static void hk_close(eng_worker *w)
{
    CHECK(w->e != NULL && w->x != NULL); /* only opened workers are closed */
    hk_closed++;
    free(w->x);
    w->x = NULL;
}

static int hk_packet(eng_worker *w, strategy **st, gpkt *p, strat_dir dir, const uint8_t *data, size_t len, const void *pctx)
{
    (void)st;
    CHECK(w->x != NULL);
    hk_packets++;
    if (hk_verdict == 1) {
        engine_verdict(w, pctx, 0, NULL, 0, 0);
        return 1;
    }
    if (hk_verdict == 2) {
        engine_inject(w, pctx, data, len);
        engine_verdict(w, pctx, 1, data, len, 0);
        return 1;
    }
    return 0;
}

static const ext_hooks hooks = {hk_open, hk_close, hk_packet, NULL, NULL, NULL, NULL};

static void test_hooks(void)
{
    engine e;
    engine_opts o;
    uint32_t id = 1;
    sbuf err;

    t_current = "engine ext hooks";
    hk_opened = hk_closed = hk_packets = hk_verdict = hk_fail_open = 0;
    engine_opts_default(&o);
    CHECK(o.ext == NULL); /* without --ext the engine has no hooks */
    setup(&e, &o, "[TCP:flags:PA]-duplicate-| \\/", 1);
    teardown(&e);
    CHECK_INT(hk_opened, 0);

    memset(&e, 0, sizeof(e));
    engine_opts_default(&o);
    o.ext = &hooks;
    e.o = &o;
    e.be = &fake_backend;
    sb_init(&err);
    e.st = strategy_parse("[TCP:flags:PA]-duplicate-| \\/", &err);
    CHECK_INT(engine_workers_init(&e, 2, &err), 0);
    CHECK_INT(hk_opened, 2);
    memset(&flog, 0, sizeof(flog));
    load_base();
    engine_packet(&e.w[1], pkt_buf, pkt_len, DIR_OUT, &id);
    CHECK_INT(hk_packets, 1);
    CHECK_INT(flog.injects, 1); /* the hook went on to the strategy */
    hk_verdict = 1;
    engine_packet(&e.w[1], pkt_buf, pkt_len, DIR_OUT, &id);
    CHECK_INT(hk_packets, 2);
    CHECK_INT(flog.drops, 1);
    CHECK_INT(flog.injects, 1); /* the strategy did not run */
    CHECK_INT(e.w[1].c.dropped, 1); /* counted as the strategy path counts */
    hk_verdict = 2;
    engine_packet(&e.w[1], pkt_buf, pkt_len, DIR_OUT, &id);
    CHECK_INT(flog.injects, 2);
    CHECK_INT(flog.accepts, 2);
    CHECK_INT(flog.verdict_data, 0); /* unmodified: an exact verdict */
    CHECK_INT(e.w[1].c.injected, 2);
    CHECK_INT(e.w[1].c.accepted, 2);
    CHECK_INT(e.w[1].c.modified, 0);
    /* paused: the hook still sees the packet */
    hk_verdict = 0;
    e.paused = 1;
    engine_packet(&e.w[1], pkt_buf, pkt_len, DIR_OUT, &id);
    CHECK_INT(hk_packets, 4);
    CHECK_INT(flog.injects, 2);
    e.paused = 0;
    engine_workers_free(&e);
    CHECK_INT(hk_closed, 2);

    /* a worker that fails to open: the error comes back, all is freed */
    hk_opened = hk_closed = 0;
    hk_fail_open = 1;
    sb_reset(&err);
    CHECK_INT(engine_workers_init(&e, 3, &err), -1);
    CHECK_STR(err.data, "no state for worker 1");
    engine_workers_free(&e);
    CHECK_INT(hk_closed, hk_opened);
    strategy_free(e.st);
    sb_free(&err);
}

void suite_engine(void)
{
    test_worker_path();
#ifndef _WIN32
    test_threads("engine workers: threads", NULL, 1);
#  if GENEVA_EXT
    {
        /* the hooks share the lists (a read lock); profile 2 has its own
         * strategy (each worker a copy of it), */
        const char *v1[] = {"--ext", "--filter-tcp", "443", "--new", "--filter-tcp", "80", "-s", TW_STRATEGY, NULL};
        /* the autolist takes them one by one (the write lock); the host is
         * not in it: no strategy */
        char f[96];
        snprintf(f, sizeof(f), "geneva-test-tw-%d.txt", (int)getpid());
        remove(f);
        {
            const char *v2[] = {"--ext", "--filter-tcp", "443", "--new", "--filter-tcp", "80", "--hostlist-auto", f,
                                "-s", TW_STRATEGY, NULL};
            test_threads("engine workers: threads, --ext", v1, 1);
            test_threads("engine workers: threads, --ext with an autolist", v2, 0);
        }
        remove(f);
    }
#  endif
#endif
    test_hooks();
}
