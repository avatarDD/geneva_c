/*
 * "geneva resolve --ext" and "geneva ip2net --ext" (docs/EXT_ROADMAP.md,
 * P7): zapret2's mdig (a resolver of name lists with threads) and ip2net
 * (addresses into subnets). Only in a build with the extensions.
 */
#ifndef GENEVA_EXT_TOOLS_H
#define GENEVA_EXT_TOOLS_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

/* ip2net: the subnets' search, as zapret2's */
typedef struct {
    int v6;
    uint32_t pctmult, pctdiv; /* v4: at least mul/div of a subnet's addresses */
    uint32_t zct_min, zct_max; /* host bits searched, both families */
    uint32_t v6_threshold;     /* v6: at least N addresses in a subnet */
} xip2net_cfg;

/* plen "MIN[-MAX]", v4thr "MUL/DIV", v6thr "N"; NULL: the defaults */
int xip2net_init(xip2net_cfg *c, int v6, const char *plen, const char *v4thr, const char *v6thr, sbuf *err);
/* the lines of text (n bytes) to out: subnets and ranges given as they are
 * first, then the addresses grouped */
void xip2net(const xip2net_cfg *c, const char *text, size_t n, sbuf *out);

/* mdig --dns-parse-query: the A and AAAA of a DNS answer, a line each;
 * -1 when it is no answer */
int xdns_answer_ips(const uint8_t *a, size_t len, sbuf *out);

int xcmd_resolve(int argc, char **argv);
int xcmd_ip2net(int argc, char **argv);

#endif
