/*
 * Host lists of the extensions (docs/EXT_ROADMAP.md, C1): zapret2's
 * hostlist pool (nfq2/hostlist.c, nfq2/pools.c). A list is a set of lower
 * case names, each with its flags: "^name" matches the name only, not its
 * subdomains; "!name" exempts the name (and its subdomains) from the list.
 * A name is searched with its parent domains: www.example.com, then
 * example.com, then com; the first entry found decides.
 */
#ifndef GENEVA_EXT_HOSTLIST_H
#define GENEVA_EXT_HOSTLIST_H

#include <stddef.h>
#include <stdint.h>

#define XHL_STRICT 1 /* "^": the full name only */
#define XHL_EXEMPT 2 /* "!": not in the list */

typedef struct {
    char *pool;      /* the names, NUL-terminated, one after another */
    size_t plen, pcap;
    uint32_t *slot;  /* hash table: offset+1 into pool, 0 empty */
    uint8_t *flags;  /* per slot */
    size_t cap, n;   /* cap: a power of two */
} xhostset;

void xhs_free(xhostset *h);
/* Adds the name s (n bytes, lowered here) unless it is there: the first
 * entry of a name keeps its flags, as in zapret2. Returns 0. */
int xhs_add(xhostset *h, const char *s, size_t n, uint8_t flags);
/* The entry of the name s (n bytes, lower case): 1 with its flags, 0 */
int xhs_get(const xhostset *h, const char *s, size_t n, uint8_t *flags);

/* The lines of a list file (zapret2's addpool): leading spaces and tabs
 * skipped; a line starting with #, ; or / is a comment; flags ^ and !
 * before the name; the name ends at a space, tab, CR, LF or NUL. Returns
 * the names added. */
size_t xhs_parse(xhostset *h, const char *text, size_t n);

/* SearchHostList: 1 when host (lower case) is in h. no_subdom: the full
 * name only (the host is an IP address). *exempt: an "!" entry stopped the
 * search. */
int xhs_search(const xhostset *h, const char *host, int no_subdom, int *exempt);

/* zapret2's strip_host_to_ip: host without its port ("name:80", "[v6]")
 * into out (cap bytes); returns 1 when it is an IP address. */
int xhost_norm(const char *host, char *out, size_t cap);

#endif
