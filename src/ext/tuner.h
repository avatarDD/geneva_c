/*
 * The tuner of the extensions (docs/EXT_ROADMAP.md, 4.7; K1, K2, K9): a
 * profile with arms (--ext-arm STRATEGY, repeatable: arm 1, 2, ...) runs on
 * each key the arm the key is at, and the outcomes of the key's flows move
 * it to another arm.
 *
 *   --ext-tune rr[:fails=3][:time=60][:final=N][:key=NAME][:nld=N][:reqhost]
 *                [:maxseq=32768][:inseq=4096][:retrans=3][:udp_out=4][:udp_in=1]
 *                [:no_rst][:no_http_redirect][:reset]
 *
 * rr is zapret2's circular (lua/zapret-auto.lua) with its arguments: every
 * key starts at arm 1; a flow's packets go through standard_success_detector
 * and standard_failure_detector until one of them decides (one outcome per
 * connection); fails failures of the key with no more than time seconds
 * between them move it to the next arm (after the last, arm 1 again); a
 * success resets the count; at arm final the key stays. The key is
 * standard_hostkey's: the flow's host name (cut to its nld-th level), else
 * the server's address, or none with reqhost (the flow then gets no
 * strategy). key=NAME shares the keys of profiles with the same NAME
 * (zapret2's autostate table; by default each profile has its own).
 *
 * The keys' arms are shared by every worker (a mutex). --ext-state FILE
 * keeps them across restarts: read at the start, written when they change
 * (at most every 10 s) and at the end.
 */
#ifndef GENEVA_EXT_TUNER_H
#define GENEVA_EXT_TUNER_H

#include <stddef.h>
#include <stdint.h>

#include "ctrack.h"
#include "json.h"
#include "pkt.h"
#include "strategy.h"
#include "util.h"

#define XT_MAX_ARMS 64
#define XT_MAX_KEYS 65536

typedef struct xtune xtune;

/* ---- building (profile.c) ---- */

/* --ext-arm STRATEGY: one more arm (the text; parsed by xtune_finish) */
void xtune_add_arm(xtune **t, const char *text);
/* --ext-tune ARGS. 0 or -1 with err. */
int xtune_set(xtune **t, const char *args, sbuf *err);
/* --import of a template with arms: a copy of them and of its --ext-tune,
 * unless the profile has its own */
void xtune_import(xtune **to, const xtune *from);
/* After the options: the arms parsed (the extensions registered), the
 * arguments checked against them. prof: the profile's number (the default
 * key). 0 or -1 with err. */
int xtune_finish(xtune *t, int prof, sbuf *err);
void xtune_free(xtune *t);
size_t xtune_arms(const xtune *t);
/* Arm i (0-based) as parsed */
strategy *xtune_arm(const xtune *t, size_t i);

/* ---- the process (ext.c) ---- */

/* Before the workers start: the keys from FILE (NULL: none). 0 or -1 with
 * err (an unreadable file is an error, a missing one is not). */
int xtune_start(const char *state_file, sbuf *err);
/* After they stop: the state written, everything freed */
void xtune_stop(void);
/* The state written now when it changed (the engine's end) */
void xtune_save(void);
/* From the main loop: the state written when it changed (at most every
 * 10 s) */
void xtune_tick(uint64_t now_ms);

/* The flow's key (standard_hostkey) into out; 0 when it has none
 * (reqhost without a host name). f in the client's orientation. */
int xtune_hostkey(const xtune *t, const ct_flow *f, char *out, size_t cap);

/* What the detectors need about a packet */
typedef struct {
    const gpkt *p;
    ct_flow *f;
    int reverse;      /* from the server */
    int http_reply;   /* the packet is an HTTP reply (zapret2's l7payload) */
    uint64_t now_ms;
    /* sends a RST to the client (reset; NULL: none) */
    void (*send)(void *ud, const uint8_t *pkt, size_t len);
    void *ud;
} xtune_pkt;

/* circular's step on one packet of the flow: the detectors, the count and
 * the rotation. Returns the arm (0-based) the flow's key is at now, -1
 * when the flow has no key (no strategy). */
int xtune_packet(xtune *t, const xtune_pkt *k);
/* The arm of the flow's key without a step (-1: no key) */
int xtune_current(xtune *t, const ct_flow *f);

/* ctl ext_status: "tuner": {...}; ext_keys: "tuner": [...] */
void xtune_status(jw *w);
void xtune_keys(jw *w, size_t max);

/* ctl ext_proposals, ext_approve {"proposal"}, ext_reject {"proposal"}: 1 handled, -1
 * with err, 0 not the tuner's */
int xtune_control(const char *cmd, const json_val *req, jw *w, sbuf *err);

/* A draw of Beta(a, b), a, b >= 1 (the thread's generator) */
double xtune_beta(double a, double b);
/* The next id of a proposal (the tuner's and the treatment's share them) */
uint64_t xtune_new_id(void);

/* For the tests: every key forgotten */
void xtune_reset(void);

#endif
