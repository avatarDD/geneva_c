/*
 * Censor models: the lab censors of Geneva (censors/censor*.py) as state
 * machines over raw IP packets, plus a DNS injector. "geneva censor" runs one
 * on a router in front of a test client; the tests drive them directly.
 *
 * Each model is a port of the Python class of the same name, including its
 * quirks (one connection tracked at a time, which flags count as a teardown,
 * whether checksums are checked), because strategies found against Geneva's
 * censors must behave the same against these. docs/CENSOR.md lists them.
 */
#ifndef GENEVA_CENSOR_H
#define GENEVA_CENSOR_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

#define CENSOR_MAX_WORDS 8

typedef struct {
    const char *words[CENSOR_MAX_WORDS]; /* forbidden byte strings */
    int nwords;
    /* Source of the RSTs a censor sends to the server. Geneva uses the
     * censor's own address, and a server ignores those: they match no
     * connection. spoof_client (the default) sends them from the client's
     * address instead, as real injectors do. Otherwise ip4/ip6, or the address
     * that local_addr() finds for the route. */
    int spoof_client;
    int has_ip4, has_ip6;
    uint8_t ip4[4], ip6[16];
    int (*local_addr)(int ipver, const uint8_t *dst, uint8_t *out, void *ctx);
    void *local_ctx;
    /* the dns model answers with these */
    uint8_t dns_a[4], dns_aaaa[16];
    uint32_t dns_ttl;
    int max_tcbs; /* tracked connections of the multi-TCB models (default 4096) */
} censor_cfg;

void censor_cfg_default(censor_cfg *c);

typedef struct censor censor;

typedef struct {
    const char *name, *summary;
    int udp; /* inspects UDP (the dns model) instead of TCP */
} censor_info;

/* All models, NULL-terminated. */
const censor_info *censor_models(size_t *n);

/* Returns NULL with a message for an unknown name ("1", "censor1" and "8b"
 * all work). cfg is copied; the words must outlive the censor. */
censor *censor_new(const char *name, const censor_cfg *cfg, sbuf *err);
void censor_free(censor *c);
const char *censor_name(const censor *c);
/* Back to the state right after start. */
void censor_reset(censor *c);
/* A reset between two evaluation runs, as Geneva's evaluator starts a fresh
 * censor for every strategy: also, packets of TCP connections seen before
 * it (retransmissions, late RSTs of the previous run) pass by unseen from
 * now on, so that they cannot change the new state. A SYN opens such a
 * 4-tuple again. */
void censor_new_run(censor *c);

typedef void (*censor_send_fn)(const uint8_t *pkt, size_t len, void *ctx);

enum {
    CENSOR_PASS = 0,     /* nothing to do with this packet */
    CENSOR_FIRED = 1,    /* forbidden content: the censor acted */
    CENSOR_BLOCKED = 2,  /* earlier censorship still applies to this host */
    CENSOR_CONTROL = 3,  /* Geneva's readiness probe (sport 2222, seq 13337) */
    CENSOR_OLD = 4,      /* a connection from before censor_new_run(): not inspected */
};

typedef struct {
    int accept;  /* verdict for the packet */
    int what;    /* CENSOR_* */
    int sent;    /* packets passed to send() */
    const char *action; /* "drop", "rst" or "dns" when what != PASS */
} censor_result;

/* Runs one IP packet through the censor. Injected packets (RSTs, forged DNS
 * answers) go to send(). */
void censor_packet(censor *c, const uint8_t *pkt, size_t len, censor_send_fn send, void *ctx,
                   censor_result *r);

#endif
