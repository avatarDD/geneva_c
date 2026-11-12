/*
 * The strategy engine: captured packets go through the strategy and leave as
 * verdicts (exact bytes, possibly delayed) or extra sends. Packets come from
 * NFQUEUE on Linux and WinDivert on Windows (see engine_int.h).
 *
 * One poll loop serves the capture, the timers of delayed packets (the sleep
 * action), the control socket, signals and periodic statistics.
 */
#ifndef GENEVA_ENGINE_H
#define GENEVA_ENGINE_H

#include <stdint.h>

#include "fw.h"
#include "pkt.h"
#include "plat.h"
#include "strategy.h"

/* Evaluation slots (geneva evolve/eval): each worker of the evaluator owns a
 * block of local ports, and the packets of a block go through that block's
 * strategy, or pass unchanged while it has none. The evaluator changes a
 * slot under the lock; the engine holds it while a packet goes through. */
typedef struct {
    strategy *st;      /* NULL = packets pass */
    uint64_t overhead; /* extra outbound packets the strategy made (Geneva's overhead) */
    uint64_t pkts;     /* packets seen */
    int capture;       /* keep copies of the packets (the canary run) */
    gpkt **cap;
    size_t ncap, capcap;
} eng_slot;

#define ENG_SLOT_CAP_MAX 256 /* captured packets kept per slot */

typedef struct {
    uint16_t base, size; /* slot i owns local ports base + i*size .. base + (i+1)*size - 1 */
    size_t n;
    eng_slot *v;
    plat_mutex_t lock;
} eng_slots;

struct ext_hooks; /* engine_int.h */
struct backend;   /* engine_int.h */

typedef struct {
    fw_config fw;              /* queue, mark, ports, directions */
    int apply_fw;              /* install firewall rules (and remove them on exit) */
    const char *strategy;      /* strategy text, or */
    const char *strategy_file; /* a file, re-read on SIGHUP */
    const char *pcap;          /* write released packets here */
    double stats_interval;     /* seconds between "stats" events, 0 = off */
    uint32_t queue_maxlen;
    int fail_open;
    int max_delayed;           /* pending delayed packets before sending at once */
    double duration;           /* stop after this many seconds, 0 = run until a signal */
    const char *control;       /* control socket spec (unix:/path, tcp:PORT), or NULL */
    const char *control_token; /* required from control clients when set */

    /* Embedded use by the evaluator (strategy and strategy_file unused). */
    eng_slots *slots;
    int embedded;              /* no signal handlers and no events */
    volatile int *stop;        /* stop once this becomes non-zero */
    /* Called once from the engine thread: rc 0 when packets flow, else the
     * exit code of a failed start. */
    void (*on_ready)(void *ctx, int rc);
    void *ready_ctx;

    /* --ext: the extensions' hooks (docs/EXT_ROADMAP.md, 6.4); NULL keeps
     * the engine exactly as without the extensions. */
    const struct ext_hooks *ext;
    /* --ext-workers (docs/EXT.md, X10a): workers with a queue and a thread
     * each (fw.queue .. fw.queue + workers - 1); 0 or 1: the main loop
     * handles the one queue, as without it */
    unsigned workers;
    /* tests: this backend instead of the platform's (NULL) */
    const struct backend *backend;
} engine_opts;

void engine_opts_default(engine_opts *o);
/* Parses the strategy (or its file) as engine_run would: 0, or -1 with
 * the error in err (--dry-run). */
int engine_check(const engine_opts *o, sbuf *err);
/* Runs until SIGINT/SIGTERM (or the duration). Returns an exit code. */
int engine_run(engine_opts *o);

#endif
