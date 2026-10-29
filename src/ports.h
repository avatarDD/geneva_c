/* Port sets like "80", "80,443", "8000-8100" (shared by apply, run and fw). */
#ifndef GENEVA_PORTS_H
#define GENEVA_PORTS_H

#include <stdint.h>

#include "util.h"

#define MAX_PORT_RANGES 64

typedef struct {
    uint16_t lo[MAX_PORT_RANGES], hi[MAX_PORT_RANGES];
    int n;
} portset;

/* Accepts "-" or ":" for ranges (iptables uses ":"). Returns 0 or -1. */
int ports_parse(const char *s, portset *ps);
int ports_has(const portset *ps, uint16_t p);
/* sep_list joins items ("," for iptables multiport and nft sets),
 * sep_range joins range ends (":" for iptables, "-" for nft). */
void ports_format(const portset *ps, sbuf *out, const char *sep_list, const char *sep_range);

#endif
