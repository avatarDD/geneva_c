/*
 * Position ranges of zapret2 (nfq2/filter.c packet_range_parse, desync.c
 * check_pos_*): "n2-n5", "d1<d3", "-s100", "<p1000", "b10-", "a", "x".
 *
 * A position is a mode letter and a number: n packets, d packets with data,
 * b bytes of data (with retransmissions), s relative sequence of the last
 * packet, p relative position after its data; "a" is always, "x" never.
 * "-" keeps the upper bound inclusive, "<" makes it exclusive and marks it
 * as an upper cutoff. Semantics, including what happens without a tracked
 * flow and after the 2 GB wrap of s and p, are zapret2's.
 */
#ifndef GENEVA_EXT_RANGE_H
#define GENEVA_EXT_RANGE_H

#include <stdint.h>

#include "util.h"

typedef struct {
    char mode; /* n d b s p a x */
    uint32_t pos;
} xpos;

typedef struct {
    xpos from, to;
    int upper_cutoff; /* "<": the upper bound is exclusive */
} xrange;

/* The counters of one side of a flow that a range looks at. */
typedef struct {
    uint64_t n, d, b; /* packets, packets with data, data bytes */
    uint32_t s, p;    /* relative seq of the last packet, position after its data */
    int over2g;       /* s and p wrapped past 2 GB: they no longer count */
} xside_view;

/* Parses zapret2's form. def_mode, when not 0, is the mode of a bare number
 * ("1-5" with def_mode 'n' is "n1-n5", "5" is "n5-n5"); 0 requires the
 * letters as zapret2 does. Returns 0, or -1 with a message. */
int xrange_parse(const char *s, char def_mode, xrange *r, sbuf *err);
/* Prints the canonical zapret2 form ("n1-n5", "a", "x"). */
void xrange_print(const xrange *r, sbuf *out);

uint64_t xpos_get(const xside_view *v, char mode);
/* v NULL: no tracked flow. */
int xrange_in(const xside_view *v, const xrange *r);
/* 1 when the flow is past the range for good (zapret2's check_pos_cutoff). */
int xrange_cutoff(const xside_view *v, const xrange *r);

#endif
