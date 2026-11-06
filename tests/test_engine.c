/* The engine core without a capture: a fake backend records verdicts and
 * injections, so the worker context (X1 of docs/EXT_ROADMAP.md) and the
 * extension hooks are tested without NFQUEUE or WinDivert. */
#include <stdlib.h>
#include <string.h>

#include "engine_int.h"
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
    "fake", sizeof(uint32_t), NULL, NULL, NULL, NULL, NULL, fake_verdict, fake_inject, 0, NULL, NULL, NULL,
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

static int hk_packet(eng_worker *w, strategy *st, gpkt *p, strat_dir dir, const uint8_t *data, size_t len, const void *pctx)
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

static const ext_hooks hooks = {hk_open, hk_close, hk_packet};

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
    test_hooks();
}
