/*
 * Strategy language: triggers, actions, action trees and forests, with the
 * same syntax, printing and run-time semantics as Geneva (the actions package).
 *
 *   strategy := out-forest "\/" in-forest
 *   forest   := { tree " " }
 *   tree     := "[" trigger "]-" [action] "-|"
 *   trigger  := proto ":" field ":" value [":" gas]
 *   action   := name ["{" params "}"] ["(" [action] "," [action] ")"]
 *
 * A strategy keeps run-time state between packets (trigger gas, the "trace
 * ran once" flag, counters); strategy_reset() restores the parsed state.
 */
#ifndef GENEVA_STRATEGY_H
#define GENEVA_STRATEGY_H

#include <stddef.h>
#include <stdint.h>

#include "json.h"
#include "pkt.h"
#include "util.h"

typedef enum { DIR_OUT = 0, DIR_IN = 1 } strat_dir;

typedef enum {
    ACT_TAMPER,
    ACT_DUPLICATE,
    ACT_FRAGMENT,
    ACT_DROP,
    ACT_SLEEP,
    ACT_TRACE,
} act_type;

typedef enum {
    TAMPER_REPLACE,
    TAMPER_CORRUPT,
    TAMPER_ADD,
    TAMPER_COMPRESS,
} tamper_type;

typedef struct action action;
struct action {
    act_type type;
    action *left, *right;

    /* tamper */
    char *proto_str; /* protocol as written ("TCP"); printed back as is */
    layer_id layer;
    char *field;
    tamper_type ttype;
    gval value; /* replace/add value: int, or string like Geneva's */
    int has_value;

    /* fragment */
    int segment; /* 1 = TCP segmentation, 0 = IP fragmentation */
    int fragsize;
    int overlap;
    int in_order;

    /* sleep */
    double time;

    /* trace */
    int start_ttl, end_ttl;
    int ran;

    uint64_t runs; /* times this action ran */
};

typedef struct {
    char *proto_str;
    layer_id layer;
    char *field;
    gval value;
    int wildcard; /* value ended with '*': substring match */
    int has_gas;
    int64_t gas_init;
    int64_t gas;  /* remaining; negative = bomb trigger countdown */
    int bomb;
    uint64_t seen;
} trigger;

typedef struct {
    trigger trig;
    action *root;
    strat_dir dir;
    uint64_t fired;
} atree;

typedef struct {
    atree **out;
    size_t nout;
    atree **in;
    size_t nin;
} strategy;

/* A list of packets produced by a strategy. */
typedef struct {
    gpkt **v;
    size_t n, cap;
} pktlist;

void pktlist_push(pktlist *l, gpkt *p);
/* Frees the packets and the array. */
void pktlist_free(pktlist *l);

/* Parses a strategy. Returns NULL and a message in err on failure.
 * Random parts that Geneva fills in (a fragment without parameters picks
 * its order at random) use the rng module. */
strategy *strategy_parse(const char *text, sbuf *err);
void strategy_free(strategy *s);
/* Geneva's str(strategy).strip(): "[TCP:flags:PA]-drop-| \/". */
void strategy_print(const strategy *s, sbuf *out);
/* Geneva's pretty_print(): one tree per block, drawn with box characters. */
void strategy_pretty(const strategy *s, sbuf *out);
/* Structured form for "geneva check --json". */
void strategy_json(const strategy *s, jw *w);
/* Number of actions in both forests (Geneva's len(strategy)). */
size_t strategy_len(const strategy *s);
void strategy_reset(strategy *s);

void tree_print(const atree *t, sbuf *out);
void trigger_print(const trigger *t, sbuf *out);
void action_print(const action *a, sbuf *out);

/* Runs one packet through the forest of the given direction, like Geneva's
 * Strategy.act_on_packet(). Takes ownership of pkt; the resulting packets
 * (each possibly carrying a sleep delay) are appended to out. Returns the
 * number of trees that fired. */
int strategy_apply(strategy *s, gpkt *pkt, strat_dir dir, pktlist *out);

#endif
