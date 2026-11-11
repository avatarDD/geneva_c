/*
 * --ext-auto (docs/EXT.md, X9; docs/EXT_ROADMAP.md, 4.4 and 4.8): the
 * observation plane and the detector of the running engine. "observe"
 * watches the first packets of every flow the client starts, on any port,
 * through NFLOG (src/ext/nflog.c), gives each flow an outcome and each key
 * (port, network, address, host name) a state (src/ext/detect.c), and
 * tells of impaired keys with the events ext_impaired and ext_class. It
 * changes no traffic: the profiles and the strategy work as without it.
 *
 * One observer per process, run from the engine's main loop (its lock
 * held); Linux only for now.
 */
#ifndef GENEVA_EXT_AUTO_H
#define GENEVA_EXT_AUTO_H

#include <stddef.h>

#include "args.h"
#include "fw.h"
#include "json.h"
#include "plat.h"
#include "util.h"

#define XAUTO_FIRST 16 /* packets of each direction observed per flow */

/* --ext-auto, --ext-nflog-group, --ext-observe-first: the rules of c get
 * the observation chains. Returns 0, or -1 with a message in err. */
int xauto_parse(const args_t *a, fw_config *c, sbuf *err);
/* --ext-auto is on */
int xauto_on(void);
void xauto_reset(void);

/* Binds the NFLOG group (before the rules go up). Returns 0 or -1 with a
 * message in err. */
int xauto_open(sbuf *err);
void xauto_close(void);
size_t xauto_pollfds(plat_pollfd *fds, size_t max);
void xauto_ready(const plat_pollfd *fds, size_t n);

/* One observed packet (the bytes of an IP packet) at now_ms; for tests and
 * for the NFLOG reader */
void xauto_feed(const uint8_t *pkt, size_t len, uint64_t now_ms);

/* ext_status: the observer's counters and its impaired keys; ext_keys: its
 * keys under "detect" */
void xauto_status(jw *w);
void xauto_keys(jw *w);

#endif
