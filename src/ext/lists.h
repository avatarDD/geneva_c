/*
 * List files of the profiles (docs/EXT_ROADMAP.md, C1-C4): zapret2's
 * hostlist and ipset files (nfq2/hostlist.c, nfq2/ipset.c). A file named
 * by several profiles is loaded once (by its full path). A list in gzip
 * is inflated (inflate.h). A file is read again when its time or
 * size changes (looked at once a second at most), on SIGHUP and on the
 * "reload_lists" control command; a file that cannot be stat'ed or opened
 * keeps what was loaded, one that fails to load is empty and fails the
 * profiles that use it until it loads again (as in zapret2).
 */
#ifndef GENEVA_EXT_LISTS_H
#define GENEVA_EXT_LISTS_H

#include <stdint.h>

#include "hostlist.h"
#include "ipset.h"
#include "util.h"

typedef struct xlist {
    char *path;  /* the full path, NULL: fixed (--hostlist-domains, --ipset-ip) */
    char *name;  /* the path as given first, for the messages */
    int ip;      /* 1: an IP set, 0: a host list */
    xhostset hs;
    xipset ips;
    int64_t mtime, mtime_ns, size; /* what was loaded */
    int failed;  /* the last load failed: the list is empty */
    int refs;
} xlist;

/* A profile's lists of one kind (zapret2's *_collection) */
typedef struct {
    xlist **v;
    size_t n;
} xlistref;

/* The list of path (a file, loaded now; shared with the profiles that
 * named it before), NULL with err. */
xlist *xlist_file(const char *path, int ip, sbuf *err);
/* A new fixed list */
xlist *xlist_fixed(int ip);
/* Adds l to r (a reference). Returns 0, or -1 when r has it already. */
int xlistref_add(xlistref *r, xlist *l);
/* Drops the references of r */
void xlistref_free(xlistref *r);
/* The lists of from, added to to (--import) */
void xlistref_copy(xlistref *to, const xlistref *from);

/* hostlist_collection_is_empty, ipset_collection_is_empty */
int xlistref_empty(const xlistref *r);
/* No list of r failed to load */
int xlistref_ok(const xlistref *r);

/* HostlistCheck_ (without the reload): 1 to apply. host: lower case,
 * without a port. *excluded: an exclude list has it. */
int xlists_host(const xlistref *inc, const xlistref *exc, const char *host, int no_subdom, int *excluded);
/* IpsetCheck_: 1 to apply */
int xlists_ip(const xlistref *inc, const xlistref *exc, int ver, const uint8_t *ip);

/* Reads again the files that changed (force: every file). now_ms: at most
 * once a second unless force. Returns how many were read. */
int xlists_reload(uint64_t now_ms, int force);
/* How many lists are loaded (files and fixed) */
size_t xlists_count(void);

#endif
