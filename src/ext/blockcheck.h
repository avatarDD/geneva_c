/*
 * "geneva blockcheck --ext" (X12b): zapret2's blockcheck2.sh with the
 * strategy grid of blockcheck2.d/standard, each line translated into a
 * geneva strategy (z2xlate.h) and probed through the evaluator.
 *
 * The grid is a port of the scripts' control flow: the same tests in the
 * same order, the same scan levels, the same "need_" shortcuts between the
 * scripts. The probing is a callback, so the tests drive the grid with an
 * oracle and without privileges.
 */
#ifndef GENEVA_EXT_BLOCKCHECK_H
#define GENEVA_EXT_BLOCKCHECK_H

#include <stdio.h>

#include "util.h"

enum { BC_VERYQUICK, BC_QUICK, BC_STANDARD, BC_FORCE };
enum { BC_HTTP, BC_TLS12, BC_TLS13, BC_HTTP3, BC_NTESTS };

/* One test of a strategy: 1 it worked, 0 it did not, -1 stop everything.
 * gen is the geneva strategy, NULL when the line has no translation or
 * does not parse (the test fails without a probe, as the zapret2 line
 * fails with a Lua error). */
typedef int (*bc_test_fn)(void *ctx, const char *nfqws2, const char *gen);

typedef struct {
    char *key;     /* "curl_test_http ipv4 : nfqws2 --payload=..." */
    char *line;    /* "curl_test_http ipv4 DOMAIN : nfqws2 --payload=..." */
    char *domain;
    char *test;    /* "curl_test_http ipv4" */
    char *value;   /* "nfqws2 --payload=...", "nfqws2 not working", ... */
    char *gen;     /* the geneva strategy of a working line */
} bc_entry;

typedef struct {
    /* blockcheck2's variables */
    int level;          /* SCANLEVEL (BC_STANDARD) */
    int min_ttl, max_ttl;         /* 1, 12; max 0: no TTL tests */
    int min_autottl, max_autottl; /* 1, 5; max 0: no autottl tests */
    int fake_repeats;   /* FAKE_REPEATS (1) */
    int multidisorder_legacy; /* MULTIDISORDER=multidisorder_legacy */
    unsigned skip;      /* scripts left out: bit i is the i-th (10-http-basic.sh is 0) */
    FILE *log;          /* the progress (stderr), NULL: none */

    bc_test_fn test;
    void *ctx;

    /* the state of a run */
    int ipv;
    const char *testf, *domain;
    char *strategy;     /* the first working line of the current test */
    int stopped;
    int ntests;         /* lines tried */
    /* the scripts' need_ variables across domains: -1 unset, 0, 1 */
    int need_multisplit, need_multidisorder, need_fake, need_fakedsplit, need_fakeddisorder,
        need_hostfakesplit;

    bc_entry *rep;      /* report_append's entries */
    size_t nrep;
} bc_run;

void bc_init(bc_run *b);
void bc_free(bc_run *b);

/* Only the scripts of list ("10,20,90": their numbers); 0, or -1 with err */
int bc_select_scripts(bc_run *b, const char *list, sbuf *err);

/* "curl_test_http", ... */
const char *bc_test_name(int test);

/* Runs every script for test on domain over IP version ipv, then
 * report_strategy: returns 1 when a strategy was found, 0 not, -1 stopped */
int bc_scripts(bc_run *b, int test, const char *domain, int ipv);

/* report_append */
void bc_report(bc_run *b, const char *domain, const char *value, const char *gen);

/* SUMMARY, and with several domains COMMON and COVERAGE, as blockcheck2
 * prints them; each working line is followed by "  geneva: STRATEGY" */
void bc_print(const bc_run *b, int ndomains, FILE *out);
/* the same as one JSON object */
void bc_print_json(const bc_run *b, int ndomains, sbuf *out);

int xcmd_blockcheck(int argc, char **argv);

#endif
