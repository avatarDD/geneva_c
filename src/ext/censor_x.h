/*
 * Lab censors 12-20 (docs/EXT_ROADMAP.md, 7.3): models of the DPI the --ext
 * extensions must detect and get around, beyond Geneva's censors 1-11.
 * censor.c hands them every packet when the model is one of these; they keep
 * their own per-connection table. docs/CENSOR.md describes each one.
 */
#ifndef GENEVA_EXT_CENSOR_X_H
#define GENEVA_EXT_CENSOR_X_H

#include "censor.h"

typedef struct cx cx;

/* The models, NULL-terminated, for censor_models(). */
extern const censor_info cx_models[];

/* NULL for a name that is not one of 12-20. cfg must outlive the state. */
cx *cx_new(const char *name, const censor_cfg *cfg);
void cx_free(cx *x);
/* Forgets every connection (SIGHUP, censor_reset, censor_new_run). */
void cx_reset(cx *x);
void cx_packet(cx *x, const uint8_t *pkt, size_t len, censor_send_fn send, void *ctx, censor_result *r);

#endif
