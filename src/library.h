/*
 * The built-in strategy library: the strategies geneva_c found against the
 * censor of Russia (tools/library.json) and LAB_STRATEGIES of Geneva's
 * library.py (against the lab censors of "geneva censor"), generated into
 * library_data.h by tools/gen_library.py. Geneva's WORKING_STRATEGIES
 * (China, India, Kazakhstan) are not taken (README, "Отличия от Geneva").
 */
#ifndef GENEVA_LIBRARY_H
#define GENEVA_LIBRARY_H

#include <stddef.h>

typedef struct {
    const char *strategy;
    int rate;               /* geneva eval fitness - 300 (400 = 100); lab: 100 */
    const char *country;    /* russia, or lab */
    const char *test_type;  /* tls, quic, udp; echo (lab) */
    const char *description;
    int server_side;        /* runs on the server, not the client */
    const char *censors;    /* lab: the censors it beats ("6 7 8"), else NULL */
    int ext;                /* needs --ext (x-actions of zapret2) */
} lib_entry;

typedef struct {
    const char *country;    /* NULL: any */
    const char *test_type;  /* NULL: any */
    const char *censor;     /* lab entries that beat this censor ("8b") */
    int side;               /* 0 any, 1 client only, 2 server only */
    int min_rate;
    int with_lab;           /* country NULL also lists lab entries when set */
    int ext;                /* also the entries that need --ext */
} lib_filter;

const lib_entry *library_entries(size_t *n);

/* Whether e passes f. Entries that need --ext pass only with f->ext, and
 * never in a build without the extensions (make EXT=0). */
int library_match(const lib_entry *e, const lib_filter *f);

#endif
