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

/* After --ext-auto: the portfolio parsed (the x-actions registered). 0 or
 * -1 with err. */
int xtreat_start(int mode, sbuf *err);
void xtreat_stop(void);
int xtreat_mode(void);
/* The portfolio's arms (the workers copy them) */
size_t xtreat_narms(void);
strategy *xtreat_arm(size_t i);

/* A worker: the arm (index) flow f runs, -1 none. host: the L7's (NULL:
 * f->chost). f in the client's orientation. */
int xtreat_flow(ct_flow *f, const char *host, uint64_t now_ms);

/* The main thread, from the detector: a key's state changed (1: the key is
 * in treatment, the policy keeps it impaired) */
int xtreat_key(const xdet_key_ev *ev, uint64_t now_ms);
/* ... a flow's outcome */
void xtreat_outcome(const xdet_flow_ev *ev, uint64_t now_ms);
/* ... once a second: the rechecks of UNTREATABLE keys */
void xtreat_tick(uint64_t now_ms);

/* ctl: ext_status "treat": {...}; ext_keys "treat": [...]; the pending
 * proposals into an open array; ext_approve / ext_reject of proposal id
 * (1 done, 0 no such) */
void xtreat_status(jw *w);
void xtreat_keys(jw *w, size_t max);
void xtreat_proposals(jw *w);
int xtreat_decide(uint64_t id, int approve, jw *w);

#endif
