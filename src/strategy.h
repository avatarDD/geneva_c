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
    ACT_X, /* an x-action of the extensions (strat_xact) */
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

    /* ACT_X: the extensions' own action (strat_xact) and how many subtrees
     * it takes (0, 1 or 2) */
    void *x;
    int xkids;
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
    void *x; /* a trigger of the extensions (FLOW:, META:), see strat_xtrig */
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
    /* Different for every strategy made or changed (parse, mutate, mate):
     * what the per-flow state of the extensions is about */
    int serial;
} strategy;

/* A list of packets produced by a strategy. */
typedef struct {
    gpkt **v;
    size_t n, cap;
} pktlist;

void pktlist_push(pktlist *l, gpkt *p);
/* Frees the packets and the array. */
void pktlist_free(pktlist *l);

/* Triggers of the extensions (docs/EXT_ROADMAP.md, 5.1): pseudo-layers that
 * look at the packet's flow (FLOW:n:1-5) or at where it came from
 * (META:ifin:eth0). They exist only once --ext registers them; without, the
 * layer is unknown as before. The value is kept as written, so a strategy
 * prints back unchanged. */
typedef struct {
    /* Returns 1 with *x set (or -1 with err) when layer is one of the
     * extensions', 0 when it is not. */
    int (*parse)(const char *layer, const char *field, const char *value, void **x, sbuf *err);
    /* Does packet p (tree number tree of the forest of direction dir) match?
     * ctx is what the caller passed to strategy_apply_x(), NULL without. */
    int (*match)(const void *x, void *ctx, strat_dir dir, size_t tree, const gpkt *p);
    void *(*dup)(const void *x);
    void (*free)(void *x);
    /* Is tree number tree of the forest of dir cut off for the packet's
     * flow (xcutoff)? NULL: never. */
    int (*cut)(void *ctx, strat_dir dir, size_t tree);
} strat_xtrig;

/* NULL unregisters. */
void strategy_set_xtrig(const strat_xtrig *ops);
/* Does p match trigger t, as a condition of an x-action (xwhen{iff=...})?
 * Gas counts as for a tree's trigger; no tree is ever cut off by it. */
int trigger_match(trigger *t, const gpkt *p, void *xctx, strat_dir dir);

/* x-actions of the extensions (docs/EXT_ROADMAP.md, 5.1): "xfake{blob=...;
 * ttl=3}" and the like, with named parameters separated by ";". They exist
 * only once --ext registers them; while they do, the tree parser skips
 * commas inside "{...}", which x-parameters use for lists. An x-action
 * makes its own packets (fakes, parts) and either hands the packet on to a
 * subtree, possibly changed, or absorbs it. */
typedef struct {
    pktlist *out;    /* the results */
    void *xctx;      /* as given to strategy_apply_x() */
    strat_dir dir;
    size_t tree;     /* the tree of the forest that runs */
    action *a;       /* the x-action running */
    void **dyn;      /* the x-actions' state of this packet, shared by every tree
                      * of one strategy_apply_x() call (zapret2's desync table) */
} strat_xenv;

typedef struct {
    /* Returns 1 with *x and *kids set when name is an x-action (or -1 with
     * err), 0 when it is not one. params: the text between the braces as
     * written (NULL without braces). */
    int (*parse)(const char *name, const char *params, strat_dir dir, void **x, int *kids, sbuf *err);
    /* "xfake{blob=fake_default_tls;ttl=3}", as parsed */
    void (*print)(const void *x, sbuf *out);
    const char *(*name)(const void *x);
    void (*free)(void *x);
    /* Runs p (owned): an x-action ends with strat_xchild() for p (or for
     * packets made from it), or frees it. */
    void (*run)(void *x, gpkt *p, strat_xenv *env);
    /* Frees *env->dyn once the packet went through every tree (NULL: no
     * state); called only when it is not NULL. */
    void (*done)(void *dyn);
} strat_xact;

void strategy_set_xact(const strat_xact *ops);
/* For x-actions: p goes into subtree which (0: left, 1: right); without
 * that subtree it is a result. */
void strat_xchild(strat_xenv *env, int which, gpkt *p);
/* Gives s a new serial (after a change of its trees). */
void strategy_new_serial(strategy *s);

/* Parses a strategy. Returns NULL and a message in err on failure.
 * Random parts that Geneva fills in (a fragment without parameters picks
 * its order at random) use the rng module. */
strategy *strategy_parse(const char *text, sbuf *err);
void strategy_free(strategy *s);
/* A copy with fresh run-time state (gas, counters) and a serial of its
 * own, for one worker of the multi-queue engine; NULL for NULL or when the
 * canonical text does not parse again (never for a parsed strategy). */
strategy *strategy_clone(const strategy *s);
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

/* Building blocks for the genetic operators (mutate.c). */
int trigger_parse(trigger *t, const char *text, sbuf *err);
void trigger_clear(trigger *t);
/* A copy with fresh gas. */
void trigger_copy(trigger *dst, const trigger *src);
void action_free(action *a); /* with its subtrees */
void tree_free(atree *t);
void trigger_print(const trigger *t, sbuf *out);
void action_print(const action *a, sbuf *out);
/* Subtrees an action takes: 0 (drop, trace), 2 (duplicate, fragment), 1. */
int action_kids(const action *a);

/* Runs one packet through the forest of the given direction, like Geneva's
 * Strategy.act_on_packet(). Takes ownership of pkt; the resulting packets
 * (each possibly carrying a sleep delay) are appended to out. Returns the
 * number of trees that fired. */
int strategy_apply(strategy *s, gpkt *pkt, strat_dir dir, pktlist *out);
/* The same with a context for the triggers of the extensions. */
int strategy_apply_x(strategy *s, gpkt *pkt, strat_dir dir, pktlist *out, void *xctx);

#endif
