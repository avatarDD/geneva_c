/*
 * The built-in strategy library: Geneva's library.py (WORKING_STRATEGIES,
 * found against real censors, and LAB_STRATEGIES, against the lab censors of
 * "geneva censor"), generated into library_data.h by tools/gen_library.py.
 */
#ifndef GENEVA_LIBRARY_H
#define GENEVA_LIBRARY_H

#include <stddef.h>

typedef struct {
    const char *strategy;
    int rate;               /* success rate in percent, as Geneva measured it */
    const char *country;    /* china, india, kazakhstan, or lab */
    const char *test_type;  /* http, dns, dns_tcp, kazakhstan_injected_https, echo (lab) */
    const char *description;
    int server_side;        /* runs on the server, not the client */
    const char *censors;    /* lab: the censors it beats ("6 7 8"), else NULL */
} lib_entry;

typedef struct {
    const char *country;    /* NULL: any */
    const char *test_type;  /* NULL: any */
    const char *censor;     /* lab entries that beat this censor ("8b") */
    int side;               /* 0 any, 1 client only, 2 server only */
    int min_rate;
    int with_lab;           /* country NULL also lists lab entries when set */
} lib_filter;

const lib_entry *library_entries(size_t *n);

/* Whether e passes f. */
int library_match(const lib_entry *e, const lib_filter *f);

#endif
