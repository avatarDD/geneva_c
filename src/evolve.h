/*
 * The genetic algorithm of Geneva's evolve.py: a population of strategies
 * goes through crossover, mutation (rejecting individuals the hall of fame
 * says are hopeless), evaluation, tournament selection and elitism, for a
 * number of generations.
 *
 * Additions over Geneva: a checkpoint written atomically before every
 * generation, from which a run resumes exactly where it stopped (same
 * population, hall of fame and random state), and a strategy database that
 * collects every evaluation and seeds new runs with the best known
 * strategies for the same target.
 */
#ifndef GENEVA_EVOLVE_H
#define GENEVA_EVOLVE_H

#include <signal.h>
#include <stddef.h>

#include "mutate.h"
#include "sdb.h"
#include "strategy.h"

typedef struct {
    strategy *s;
    char *str;   /* canonical text */
    double fit;  /* -1000 until evaluated, like Geneva */
    int in_en, out_en; /* forests the GA may change */
} ga_ind;

/* Sets fit of each individual. Returns 0, or -1 to abort the run. */
typedef int (*ga_eval_fn)(void *ctx, ga_ind *inds, size_t n);

typedef struct {
    int population, generations, elite_clones, allowed_retries;
    int in_trees, out_trees, in_actions, out_actions;
    int tournsize;
    int no_reject_empty;
    double mutation_pb, crossover_pb;
    const char *seed;      /* every initial individual is this strategy */
    const char *load_from; /* initial population from a generation file */
    gen_ctx gen;
    const char *params;    /* description of the search space for the checkpoint hash */

    ga_eval_fn eval;       /* NULL = --no-eval: every fitness is 0 */
    void *eval_ctx;

    const char *out_dir;   /* generationN.txt and hallN.txt, like Geneva; NULL = none */
    const char *checkpoint;
    int resume, resume_force;

    sdb *db;               /* record evaluations here; NULL = no database */
    const char *target;    /* target profile for the database */
    int db_seed;           /* seed up to this many individuals from the database */

    volatile sig_atomic_t *stop; /* set by a signal: finish the current step and save */
} ga_opts;

void ga_opts_default(ga_opts *o);

/* A strategy and every fitness it got. */
typedef struct {
    char *str;
    double *fits;
    size_t n, cap;
} hof_entry;

typedef struct {
    hof_entry *v;
    size_t n, cap;
    size_t *idx;
    size_t idx_cap;
} hall_of_fame;

void hof_init(hall_of_fame *h);
void hof_free(hall_of_fame *h);
void hof_add(hall_of_fame *h, const char *str, double fit);
const hof_entry *hof_get(const hall_of_fame *h, const char *str);
/* Geneva's collect_results(): fewest runs and lowest average first. */
void hof_format(const hall_of_fame *h, sbuf *out);
/* Entries sorted best first: highest average, then most runs. */
size_t hof_best(const hall_of_fame *h, const hof_entry **out, size_t max);

/* Runs the GA. The hall of fame is filled (pass an initialized one).
 * Returns an exit code; EXIT_OK also when stopped by o->stop, with the
 * checkpoint saved. */
int ga_run(ga_opts *o, hall_of_fame *hall);

#endif
