/*
 * The strategy engine on Linux: packets from NFQUEUE go through the strategy
 * and leave as verdicts (exact bytes, possibly delayed) or raw sends.
 *
 * Single-threaded: one poll loop serves the queue, the timers of delayed
 * packets (the sleep action), signals and periodic statistics.
 */
#ifndef GENEVA_ENGINE_H
#define GENEVA_ENGINE_H

#include <stdint.h>

#include "fw.h"

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
} engine_opts;

void engine_opts_default(engine_opts *o);
/* Runs until SIGINT/SIGTERM (or the duration). Returns an exit code. */
int engine_run(engine_opts *o);

#endif
