/*
 * The treatment of --ext-auto propose|apply (docs/EXT_ROADMAP.md, 4.6-4.8;
 * docs/EXT.md, X11c): a key the detector found impaired (its address or
 * host name) gets the arms of a built-in portfolio for its class and
 * Thompson sampling over them (the outcomes are the detector's verdicts on
 * the key's flows).
 *
 *   PROPOSED     (propose) the treatment waits for ctl ext_approve
 *   TRIAL        each new connection of the key runs one draw of the arms
 *   TREAT        an arm is the best with P >= 0.95 and has 3 successes:
 *                every connection runs it; CUSUM on its failures sends the
 *                key back to TRIAL when the censor changes
 *   UNTREATABLE  no arm for the class (BLACKHOLE_SYN, ICMP_PROHIBIT,
 *                DNS_POISON), or every arm failed twice without a success:
 *                tried again after 1, 2, 4 ... 64 minutes
 *
 * A key in treatment stays impaired in the policy (the surgical path keeps
 * its connections in the queue) until the end. The connections must reach
 * the queue (-p, --proto); those of a profile with --ext-arm keep its
 * tuner. Key records under a mutex: the workers draw, the main thread
 * (the detector's events) counts.
 */
#ifndef GENEVA_EXT_TREAT_H
#define GENEVA_EXT_TREAT_H

#include <stddef.h>
#include <stdint.h>

#include "ctrack.h"
#include "detect.h"
#include "json.h"
#include "strategy.h"
#include "util.h"

enum { XTR_OFF = 0, XTR_PROPOSE, XTR_APPLY };
/* the portfolio's arms; the index of a key's arm from --ext-ga */
enum { XTR_NARMS = 7, XTR_GA_ARM = XTR_NARMS };

/* After --ext-auto: the portfolio parsed (the x-actions registered). 0 or
 * -1 with err. */
int xtreat_start(int mode, sbuf *err);
void xtreat_stop(void);
int xtreat_mode(void);
/* --ext-treat-arms N,..: only these arms of the portfolio (after start) */
int xtreat_allow(const char *list, sbuf *err);
/* The portfolio's arms (the workers copy them) */
size_t xtreat_narms(void);
strategy *xtreat_arm(size_t i);

/* A worker: the arm (index) flow f runs, -1 none. host: the L7's (NULL:
 * f->chost). f in the client's orientation. XTR_GA_ARM: the key's arm from
 * the genetic search, *ga its id (xtreat_ga_text; the worker keeps its own
 * copy by id). */
int xtreat_flow(ct_flow *f, const char *host, uint64_t now_ms, uint32_t *ga);
int xtreat_ga_text(uint32_t id, char *out, size_t cap);

/* The main thread, from the detector: a key's state changed (1: the key is
 * in treatment, the policy keeps it impaired) */
int xtreat_key(const xdet_key_ev *ev, uint64_t now_ms);
/* ... a flow's outcome */
void xtreat_outcome(const xdet_flow_ev *ev, uint64_t now_ms);
/* ... once a second: the rechecks of UNTREATABLE keys, the genetic search */
void xtreat_tick(uint64_t now_ms);

/* ctl: ext_status "treat": {...}; ext_keys "treat": [...]; the pending
 * proposals into an open array; ext_approve / ext_reject of proposal id
 * (1 done, 0 no such) */
void xtreat_status(jw *w);
void xtreat_keys(jw *w, size_t max);
void xtreat_proposals(jw *w);
int xtreat_decide(uint64_t id, int approve, jw *w);

/* --ext-ga: the genetic search for a key whose arms all failed ("geneva
 * evolve" as a child, src/ext/treatga.c) */
typedef struct {
    char exe[512];       /* "": /proc/self/exe */
    char firewall[16];   /* --firewall of the run */
    char log[256];       /* the child's --log-file ("" none) */
    char rng_seed[24];   /* the child's --rng-seed ("" none) */
    uint32_t mark;
    uint16_t queue;      /* its own NFQUEUE */
    int pop, gen;
} xga_config;

/* NULL: off; -1 with err */
int xga_set(const xga_config *c, sbuf *err);
int xga_on(void);
int xga_running(void);
/* probe "http" or "tls"; 0 started, -1 with err */
int xga_launch(const char *probe, const char *host, const char *ip, unsigned port, sbuf *err);
/* 1: the search ended; out the best strategy ("" none), fit its fitness */
int xga_poll(char *out, size_t cap, double *fit);
void xga_stop(void);

#endif
