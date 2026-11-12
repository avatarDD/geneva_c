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
 *
 * A packet belongs to a worker (eng_worker): the worker holds what one
 * packet path changes (counters, delayed packets, the --first flow table,
 * the state of the extensions), the engine what all workers share (the
 * strategy, the pcap writer, the control socket). There is one worker for
 * now, and every packet runs under e->lock. Two shared things still change
 * on the packet path: the strategy's trigger counters (gas, fired) and the
 * pcap writer; the multi-queue engine (docs/EXT_ROADMAP.md, X10) has to give
 * each worker its own copy of the former and lock the latter before workers
 * run without e->lock.
 */
#ifndef GENEVA_ENGINE_INT_H
#define GENEVA_ENGINE_INT_H

#include <stddef.h>
#include <stdint.h>

#include "ctl.h"
#include "engine.h"
#include "flowtab.h"
#include "pcap.h"
#include "plat.h"
#include "strategy.h"

#define PCTX_MAX 112 /* bytes of per-packet backend context */

typedef struct engine engine;
typedef struct eng_worker eng_worker;
typedef struct ext_hooks ext_hooks;

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
    int (*verdict)(eng_worker *w, const void *pctx, int accept, const uint8_t *data, size_t len);
    /* Sends an extra packet in the captured packet's direction. */
    int (*inject)(eng_worker *w, const void *pctx, const uint8_t *data, size_t len);
    /* --first N: 1 when the engine counts packets per flow itself (no
     * conntrack rules do it). */
    int engine_first;
    /* The capture filter in use, or NULL when rules capture (Linux). */
    const char *(*filter)(engine *e);
    /* Replaces the capture filter with expr (called locked). Returns 0 with
     * the new filter in out, or -1 with a message in err and, for an
     * expression that does not compile, its position in *pos (else -1).
     * NULL: the backend has no filter. */
    int (*set_filter)(engine *e, const char *expr, sbuf *out, sbuf *err, int *pos);
    /* The mark and the interface indexes (0: unknown) of a captured packet;
     * NULL when the backend has none. */
    void (*meta)(const void *pctx, uint32_t *mark, uint32_t *ifin, uint32_t *ifout);
    /* inject() for a packet of an x-action (--ext): mark is added to the
     * engine's own mark, ifout ("" or NULL: any) is the interface to bind
     * to. NULL: inject() is used. */
    int (*inject_x)(eng_worker *w, const void *pctx, const uint8_t *data, size_t len, uint32_t mark,
                    const char *ifout);
    /* A packet the extensions hold for a while (src/ext/xl7.c): out gets a
     * copy of pctx whose verdict later sends the packet anew (accept, with
     * its bytes) or does nothing (drop), so that the captured one can be
     * dropped at once. NFQUEUE: the kernel keeps the socket's buffer while
     * the verdict is pending, and TCP small queues then hold back the
     * client's next segment, the one the reassembly waits for (zapret2
     * drops and resends too). NULL: the verdict stays pending. */
    void (*detach)(const void *pctx, void *out);
} backend;

/* A packet waiting for its sleep to end. */
typedef struct {
    uint64_t due;
    uint64_t order; /* FIFO among equal due times */
    uint8_t *data;
    size_t len;
    int verdict; /* releases the held packet, else an injection */
    uint8_t pctx[PCTX_MAX];
    uint32_t xmark; /* an x-action's packet: gpkt.xmark, gpkt.xifout */
    char xifout[16];
} delayed;

/* The counters of a worker; engine_counters() sums them over the list, so a
 * new counter goes here and nowhere else (plus its line in "stats").
 * passed_first: --first, packets past the first N of their flow;
 * flow_evictions: --first, live flows pushed out of a full table;
 * held: --ext, packets whose verdict waited for a reassembly. */
#define ENG_COUNTERS(X)                                                             \
    X(pkts_out) X(pkts_in) X(triggered) X(accepted) X(modified) X(dropped)            \
    X(injected) X(delayed) X(send_errors) X(verdict_errors) X(parse_errors) X(overruns) \
    X(passed_first) X(flow_evictions) X(held)

typedef struct {
#define ENG_COUNTER_FIELD(n) uint64_t n;
    ENG_COUNTERS(ENG_COUNTER_FIELD)
#undef ENG_COUNTER_FIELD
} counters;

/* The extensions of --ext reach the engine only through this table
 * (engine_opts.ext, NULL without --ext; docs/EXT_ROADMAP.md, 6.4). */
struct ext_hooks {
    /* Per worker: set up and free w->x. open returns 0 or -1 with err. */
    int (*worker_open)(eng_worker *w, sbuf *err);
    void (*worker_close)(eng_worker *w);
    /* Every packet the engine counts, with the parsed packet, before the
     * strategy; also while paused (e->paused: the hook must then let the
     * packet go on) and when no strategy applies. Returns 0 to go on with
     * the strategy, 1 when the hook gave the verdict itself through
     * engine_verdict()/engine_inject(), which count and record like the
     * strategy path does. p stays the engine's and is freed by it. *st is
     * the strategy that will run (NULL: none); the hook may put another one
     * there (that of the packet's profile, NULL: the packet passes). The
     * hook may set w->xctx for the triggers of the extensions; the engine
     * clears it afterwards. */
    int (*packet)(eng_worker *w, strategy **st, gpkt *p, strat_dir dir, const uint8_t *data, size_t len,
                  const void *pctx);
    /* The capture is about to close (engine_run_timers with all): give
     * every packet whose verdict the hook kept its verdict now. */
    void (*flush)(eng_worker *w);
    /* A control command the engine does not know (w: the reply), and
     * "reload_lists" on SIGHUP (w NULL). Returns 1 when it was the
     * extensions', 0 when not, -1 with err when it failed. */
    int (*control)(engine *e, const char *cmd, const json_val *req, jw *w, sbuf *err);
    /* Sockets of their own (--ext-auto's observation), polled by the main
     * loop with the engine's lock held: pollfds puts up to max of them in
     * fds and returns how many; ready gets them back after every poll
     * (at least once a second, with or without events). */
    size_t (*pollfds)(engine *e, plat_pollfd *fds, size_t max);
    void (*ready)(engine *e, const plat_pollfd *fds, size_t n);
};

struct eng_worker {
    engine *e;
    unsigned id;
    counters c;
    delayed *dl; /* min-heap by (due, order) */
    size_t ndl, capdl;
    uint64_t dl_order;
    sbuf line;          /* trace text */
    flowtab *flows;     /* --first counted by the engine (engine_first) */
    uint64_t next_expire;
    void *x;            /* state of the extensions, NULL without --ext */
    void *xctx;         /* per packet: what the hook found for strat_xtrig */
    eng_slot *slot;     /* per packet: its evaluator slot (NULL: none), for replays */
    int x_open;         /* worker_open succeeded: worker_close is due */
    const uint8_t *vdata; /* a held packet's bytes for an "unmodified" verdict (detach) */
    size_t vlen;
};

struct engine {
    engine_opts *o;
    const backend *be;
    void *bs; /* backend state */
    strategy *st;
    pcap_writer *pw;
    eng_worker *w; /* nw workers */
    unsigned nw;
    uint64_t start_ms;
    ctl *ctl;
    int paused;       /* packets pass unchanged */
    int stop_request; /* "stop" over the control socket */
    const char *fw_name; /* what installed the rules, for events and status */
    const char *err_where; /* set by a failing open(): "firewall", "nfqueue"... */
    int err_pos;      /* set by a failing open(): where the filter does not compile */
    plat_mutex_t lock;
};

/* Sets up nw workers for e (e->o and e->be set): their flow tables for
 * --first and the extensions' state. Returns 0, or -1 with err (then
 * engine_workers_free still frees what was made). */
int engine_workers_init(engine *e, unsigned nw, sbuf *err);
/* Frees the workers; delayed packets still held are dropped, not sent. */
void engine_workers_free(engine *e);
/* Releases the delayed packets that are due (all = every one of them). */
void engine_run_timers(engine *e, int all);
/* Sums the counters of all workers. */
void engine_counters(const engine *e, counters *sum, size_t *pending);

/* For the extensions' packet hook: give the captured packet its verdict or
 * send an extra packet, counted in the worker's counters and written to
 * --pcap like the strategy's. data is the packet as it leaves (the captured
 * bytes when modified is 0; ignored for a drop). */
void engine_verdict(eng_worker *w, const void *pctx, int accept, const uint8_t *data, size_t len, int modified);
void engine_inject(eng_worker *w, const void *pctx, const uint8_t *data, size_t len);
/* The extensions hold the captured packet (a reassembly, src/ext/xl7.c):
 * its verdict waits, like that of a delayed packet, and it is counted as
 * held. The hook keeps pctx and the bytes. */
void engine_hold(eng_worker *w);
/* The context to keep with a packet that is held: pctx itself, or a
 * detached copy in out (PCTX_MAX bytes; see backend.detach) */
const void *engine_detach(eng_worker *w, const void *pctx, void *out);
/* After the hold: the captured packet goes (detached: dropped now) */
void engine_held(eng_worker *w, const void *pctx, const void *kept);
/* A held packet back: runs it through st (NULL, or paused: it goes as it
 * is) with xctx for the triggers of the extensions; the first result rides
 * on its verdict, as for a packet that was never held. */
void engine_replay(eng_worker *w, strategy *st, const uint8_t *data, size_t len, strat_dir dir, const void *pctx,
                   void *xctx);

/* Runs one captured packet through the strategy (call with e->lock held).
 * dir is DIR_OUT, DIR_IN, or -1 to decide by the ports. */
void engine_packet(eng_worker *w, const uint8_t *data, size_t len, int dir, const void *pctx);

/* Packet backends. */
extern const backend nfq_backend;       /* Linux */
extern const backend windivert_backend; /* Windows */

#endif
