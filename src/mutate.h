/*
 * Genetic operators on strategies, after Geneva's actions package:
 * random strategies, trees, actions and triggers (Strategy.initialize,
 * ActionTree.initialize, get_rand_action, Trigger.get_rand_trigger),
 * mutation (Strategy/ActionTree/Action/Trigger.mutate) and crossover
 * (strategy.mate, ActionTree.mate).
 *
 * Values come from "real" packets (Geneva's canary captures) when some are
 * given, otherwise from the field generators (fuzzing). The protocol and
 * field restrictions of fields_restrict() apply.
 *
 * Every operator leaves structurally valid trees (branching, terminal and
 * inbound rules hold); strategy_canon() additionally checks that the text
 * form parses back to the same strategy, which the GA requires of every
 * individual.
 */
#ifndef GENEVA_MUTATE_H
#define GENEVA_MUTATE_H

#include <stddef.h>

#include "pkt.h"
#include "strategy.h"

typedef struct {
    int disabled[ACT_TRACE + 1]; /* --disable-action */
    int no_gas;                  /* --no-gas: triggers never get gas */
    const trigger *fixed;        /* --fix-trigger, or NULL */
    gpkt **env;                  /* real packets to draw values from */
    size_t nenv;
} gen_ctx;

/* Deep copy (through the text form). */
strategy *strategy_copy(const strategy *s);

/* Strategy.initialize(): random trees with random actions. */
strategy *strategy_random(const gen_ctx *g, int in_trees, int out_trees, int in_actions, int out_actions);

/* Strategy.mutate(): changes the enabled forests in place. */
void strategy_mutate(const gen_ctx *g, strategy *s, int in_enabled, int out_enabled);

/* strategy.mate(): uniform crossover of two strategies in place. Returns 1
 * if anything was exchanged. */
int strategy_mate(strategy *a, strategy *b, double indpb, int in_enabled, int out_enabled);

/* Prints the strategy, parses the text back and checks that it prints the
 * same. On success *s is replaced by the parsed copy, *text (if not NULL)
 * gets the canonical string (caller frees) and 0 is returned; otherwise -1
 * and *s is left alone. */
int strategy_canon(strategy **s, char **text);

/* Parses "sleep,trace" style lists into g->disabled. Returns -1 with a
 * message on unknown names. */
int gen_disable_actions(gen_ctx *g, const char *list, sbuf *err);

#endif
