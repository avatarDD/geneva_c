/*
 * Position markers of zapret2 (docs/EXT_ROADMAP.md, F1, F2; nfq2/protocol.c
 * posmarker_*, *Pos, ResolveMultiPos): "5", "-1", "host", "endhost+1",
 * "sld", "midsld", "endsld", "method+2", "extlen", "sniext". The x-actions
 * that split or cut (stage X5) take lists of them.
 */
#ifndef GENEVA_EXT_MARKERS_H
#define GENEVA_EXT_MARKERS_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

enum { PM_ABS = 0, PM_HOST, PM_HOST_END, PM_HOST_SLD, PM_HOST_MIDSLD, PM_HOST_ENDSLD, PM_HTTP_METHOD, PM_EXT_LEN,
       PM_SNI_EXT, PM_LAST };

typedef struct {
    int16_t pos;
    uint8_t marker; /* PM_* */
} xmarker;

#define XMARKER_MAX 32 /* markers in one list */

/* One marker. Returns 0 or -1. */
int xmarker_parse(const char *s, xmarker *m);
/* A comma-separated list (at most max). Returns the count, or -1 with a
 * message in err. */
int xmarker_list_parse(const char *s, xmarker *m, int max, sbuf *err);
void xmarker_print(const xmarker *m, sbuf *out);

/* The offset of a marker in data of payload type l7p (L7P_*: markers
 * other than abs need an HTTP request or a TLS ClientHello), or -1. */
long xmarker_resolve(const uint8_t *data, size_t n, int l7p, const xmarker *m);
/* All markers resolved, sorted, without duplicates and without those not
 * found: the count in pos. */
int xmarker_resolve_list(const uint8_t *data, size_t n, int l7p, const xmarker *m, int nm, long *pos);
/* zapret2's resolve_range: exactly two markers as a range [from, to], both
 * inclusive. One not found falls back to the start (from) or the last byte
 * (to) unless strict. Returns 0, or -1 when it cannot be resolved or from
 * is after to. */
int xmarker_resolve_range(const uint8_t *data, size_t n, int l7p, const xmarker *m, int nm, int strict, long *from,
                          long *to);

#endif
