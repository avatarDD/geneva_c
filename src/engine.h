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
} engine_opts;

void engine_opts_default(engine_opts *o);
/* Runs until SIGINT/SIGTERM (or the duration). Returns an exit code. */
int engine_run(engine_opts *o);

#endif
