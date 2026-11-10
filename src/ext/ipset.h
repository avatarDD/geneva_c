/*
 * IP sets of the extensions (docs/EXT_ROADMAP.md, C2): zapret2's ipset
 * (nfq2/ipset.c): IPv4 and IPv6 addresses and subnets, kept as sorted,
 * merged intervals and searched by bisection.
 */
#ifndef GENEVA_EXT_IPSET_H
#define GENEVA_EXT_IPSET_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t lo, hi;
} xip4r;
typedef struct {
    uint64_t lo[2], hi[2]; /* [0]: the high half */
} xip6r;

typedef struct {
    xip4r *v4;
    size_t n4, cap4;
    xip6r *v6;
    size_t n6, cap6;
    int sorted;
} xipset;

void xips_free(xipset *s);
/* "1.2.3.4", "10.0.0.0/8", "::1", "2a00::/16" (zapret2's parse_cidr4,
 * parse_cidr6): added, returns 0; -1 when it is none of them */
int xips_add_str(xipset *s, const char *cidr);
/* Lines of a list file (zapret2's addpool): leading spaces and tabs
 * skipped; #, ;, / start a comment; the token ends at a space, tab, CR or
 * LF. Bad tokens are counted in *bad (and the first one is copied to
 * first_bad, cap bytes, when given). Returns the subnets added. */
size_t xips_parse(xipset *s, const char *text, size_t n, size_t *bad, char *first_bad, size_t cap);
/* Sorts and merges: after adding, before searching */
void xips_finish(xipset *s);
int xips_empty(const xipset *s);
/* ver 4: a 4 bytes, ver 6: 16 bytes. 1 when in the set */
int xips_has(const xipset *s, int ver, const uint8_t *a);

#endif
