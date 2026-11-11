/*
 * Firewall parity with zapret2 under --ext (docs/EXT_ROADMAP.md, X7b: A2-A4,
 * O2-O8): the options of "geneva run" and "geneva fw" that fill the --ext
 * part of fw_config (the rules themselves are made in src/fw.c), and
 * winws2's --wf-* filter builder for WinDivert.
 */
#ifndef GENEVA_EXT_FWX_H
#define GENEVA_EXT_FWX_H

#include "args.h"
#include "fw.h"
#include "util.h"

/* Reads --ext-first, --ext-wan, --ext-lan, --ext-notrack, --ext-ttl-icmp,
 * --ext-flowoffload, --fw-hook-pre/post and the --wf-* options into c.
 * windows tells the platform (a parameter for tests). A --wf-* filter goes
 * to c->filter (whole, with c->filter_whole) and its text to *owned (free
 * it), --wf-save to *save. Returns 0, or -1 with a message in err. */
int xfw_parse(const args_t *a, int windows, fw_config *c, char **owned, const char **save, sbuf *err);

/* 1 when a --wf-* option that captures something (ports, ICMP, IP
 * protocols, raw parts or a raw filter) is given: then -p is not needed. */
int xfw_wf_captures(const args_t *a);

/* The --wf-* filter alone (zapret2's wf_make_filter, nfqws.c). server
 * swaps the ports as --server-side. Returns 0, or -1 with a message. */
int xfw_wf_filter(const args_t *a, int server, sbuf *out, sbuf *err);

/* --ext-first: "N" or "[tcp-|udp-]out=N,[tcp-|udp-]in=N,..." on top of
 * base (--first); fills c->firstv. Returns 0 or -1. */
int xfw_first(const char *s, int base, fw_config *c);

/* "a,b,c" into at most FW_MAX_IFS interface names (copied into buf, which
 * the names point into). Returns the count, or -1. */
int xfw_iflist(const char *s, char *buf, size_t cap, const char **v);

#endif
