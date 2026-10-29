/*
 * The evaluator: Geneva's evaluator.py without docker. The engine runs
 * inside the process; each worker owns a block of local ports and its own
 * strategy (eng_slots), runs a probe through it and turns the outcome into
 * a fitness: the probe's score, then Geneva's punishments (punish_fitness:
 * complexity, unused trees, overhead), over --runs runs combined by
 * --fitness-by.
 *
 * Additions: a baseline (the same probe without a strategy) that tells
 * whether the target is blocked at all and captures the canary packets the
 * mutations take values from; a pause after a failure for censors that
 * keep blocking for a while (residual censorship); external probes, where a
 * controller makes the connection and reports the result; server-side
 * evaluation, where a remote agent makes it.
 */
#ifndef GENEVA_EVALUATOR_H
#define GENEVA_EVALUATOR_H

#include <signal.h>
#include <stdio.h>

#include "engine.h"
#include "evolve.h"
#include "probe.h"

#define EVAL_MAX_WORKERS 32

typedef enum { FIT_AVG, FIT_MIN, FIT_MAX } fitness_by;

typedef struct {
    probe_cfg probe;
    int runs;               /* runs per strategy (default 1) */
    fitness_by by;
    int workers;            /* parallel probes (default 1) */
    int use_engine;         /* 0: --no-engine, only probes without strategies */
    fw_config fw;           /* queue, mark, backend; ports are set by the evaluator */
    int apply_fw;
    uint16_t port_base;     /* local ports: worker i uses base + i*ports_per_worker ... */
    uint16_t ports_per_worker;
    double residual_wait;   /* seconds to wait after a failed run */
    int skip_empty;         /* GA: empty strategies get -1000 without a run (Geneva's default) */
    volatile sig_atomic_t *stop;
    FILE *ext_in;           /* external probe: results arrive here (stdin) */
    /* Server-side evaluation (agent.h): the probes run on a remote "geneva
     * agent", and the strategy applies to the service port of this host
     * (port_base = probe.port, one worker of one port). */
    const char *agent;      /* tcp:HOST:PORT of the agent, or the address to listen on */
    int agent_listen;       /* the agent dials in */
    const char *agent_token;
    double agent_wait;      /* agent_listen: seconds to wait for it */
} eval_opts;

void eval_opts_default(eval_opts *o);

typedef struct {
    double fitness;         /* combined over the runs */
    int runs;
    probe_res last;         /* the last run's probe result */
    double run_fit[16];     /* the first runs' fitness */
} eval_result;

typedef struct evaluator evaluator;

/* Starts the engine (unless use_engine is 0). Returns an exit code; on
 * failure err holds the message. */
int evaluator_open(eval_opts *o, evaluator **out, sbuf *err);
void evaluator_close(evaluator *ev);

/* Evaluates one strategy text ("" or NULL: none) with worker slot 0.
 * Returns 0, or -1 when stopped or the external controller went away. */
int evaluator_eval(evaluator *ev, const char *text, eval_result *res);

/* The GA's evaluation function (ga_eval_fn); ctx is the evaluator. */
int evaluator_ga(void *ctx, ga_ind *inds, size_t n);

/* Runs the probe without a strategy. *reachable is set when any run
 * succeeded. With capture, the packets of the runs (as the engine saw them)
 * are appended to *env. Returns 0 or -1 when stopped. */
int evaluator_baseline(evaluator *ev, eval_result *res, int *reachable, gpkt ***env, size_t *nenv);

/* Geneva's punish_fitness() for one run of strategy s. */
double eval_punish(double fitness, const strategy *s, uint64_t overhead);

#endif
