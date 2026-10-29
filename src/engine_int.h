/*
 * Engine internals shared by the portable core (engine.c) and the packet
 * backends: NFQUEUE on Linux (eng_nfq.c) and WinDivert on Windows
 * (eng_windivert.c).
 *
 * A backend captures packets and hands each one to engine_packet() together
 * with an opaque per-packet context (the NFQUEUE packet id, the WinDivert
 * address). The core runs the strategy and answers through the backend:
 * verdict() releases or drops the captured packet (possibly with new bytes,
 * possibly later), inject() sends an extra packet the same way the captured
 * one was going. Everything that touches the engine state runs under
 * e->lock, so a backend may capture on its own thread.
 */
#ifndef GENEVA_ENGINE_INT_H
#define GENEVA_ENGINE_INT_H

#include <stddef.h>
#include <stdint.h>

#include "ctl.h"
#include "engine.h"
#include "pcap.h"
#include "plat.h"
#include "strategy.h"

#define PCTX_MAX 112 /* bytes of per-packet backend context */

typedef struct engine engine;

typedef struct {
    const char *name;
    size_t pctx_len;
    /* Starts capturing (and installs firewall rules). Returns an exit code;
     * on failure err holds the message and close() is still called. */
    int (*open)(engine *e, sbuf *err);
    /* Stops capturing: rules down, queued packets pass. Called without the
     * lock, before the remaining delayed packets are released. */
    void (*stop)(engine *e);
    /* Frees everything. */
    void (*close)(engine *e);
    /* Descriptors the main loop polls for the backend. */
    size_t (*pollfds)(engine *e, plat_pollfd *fds, size_t max);
    /* Called (locked) after poll; returns -1 on a fatal error. */
    int (*ready)(engine *e, const plat_pollfd *fds, size_t n);
    /* Releases (accept) or drops the captured packet. data == NULL keeps the
     * original bytes. Returns 0 or -1. */
    int (*verdict)(engine *e, const void *pctx, int accept, const uint8_t *data, size_t len);
    /* Sends an extra packet in the captured packet's direction. */
    int (*inject)(engine *e, const void *pctx, const uint8_t *data, size_t len);
} backend;

/* A packet waiting for its sleep to end. */
typedef struct {
    uint64_t due;
    uint64_t order; /* FIFO among equal due times */
    uint8_t *data;
    size_t len;
    int verdict; /* releases the held packet, else an injection */
    uint8_t pctx[PCTX_MAX];
} delayed;

typedef struct {
    uint64_t pkts_out, pkts_in, triggered, accepted, modified, dropped;
    uint64_t injected, delayed, send_errors, verdict_errors, parse_errors, overruns;
} counters;

struct engine {
    engine_opts *o;
    const backend *be;
    void *bs; /* backend state */
    strategy *st;
    pcap_writer *pw;
    counters c;
    delayed *dl; /* min-heap by (due, order) */
    size_t ndl, capdl;
    uint64_t dl_order;
    uint64_t start_ms;
    sbuf line;
    ctl *ctl;
    int paused;       /* packets pass unchanged */
    int stop_request; /* "stop" over the control socket */
    const char *fw_name; /* what installed the rules, for events and status */
    const char *err_where; /* set by a failing open(): "firewall", "nfqueue"... */
    plat_mutex_t lock;
};

/* Runs one captured packet through the strategy (call with e->lock held).
 * dir is DIR_OUT, DIR_IN, or -1 to decide by the ports. */
void engine_packet(engine *e, const uint8_t *data, size_t len, int dir, const void *pctx);

/* Packet backends. */
extern const backend nfq_backend;       /* Linux */
extern const backend windivert_backend; /* Windows */

#endif
