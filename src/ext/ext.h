/*
 * Extensions of "geneva ... --ext" (docs/EXT_ROADMAP.md). Everything under
 * src/ext/ is compiled only with EXT=1 (the default); "make EXT=0" leaves
 * the directory out and the switch in src/ext_opt.c refuses --ext.
 */
#ifndef GENEVA_EXT_EXT_H
#define GENEVA_EXT_EXT_H

/* "make EXT_CRYPTO=0": no crypto_*.c (docs/EXT_ROADMAP.md, 6.1), so no QUIC
 * decryption: quic_initial_decrypt() always fails and censor 16 is not
 * there; QUIC is then recognized by its header only. */
#ifndef GENEVA_EXT_CRYPTO
#  define GENEVA_EXT_CRYPTO 1
#endif

/* Names that "version --json" adds to "features" in a build with the
 * extensions; NULL-terminated. Integrators switch on these. */
extern const char *const ext_features[];

#include "args.h"
#include "strategy.h"

struct ext_hooks;

/* Called by ext_parse_args() once a command took --ext: registers the
 * triggers of the extensions and reads the --ext-* options common to the
 * commands (--ext-ctrack-*). Prints "geneva CMD: ..." and returns -1 on a
 * bad value. */
int ext_activate(const args_t *a, const char *cmd);
/* Back to the state before ext_activate() (tests). */
void ext_deactivate(void);

/* The engine hooks of the extensions (conntrack, FLOW and META triggers)
 * for engine_opts.ext; NULL without --ext. */
const struct ext_hooks *ext_engine_hooks(void);

/* The same for "geneva apply --ext" over a capture: the conntrack fed with
 * the capture's times. NULL without --ext. */
typedef struct xoffline xoffline;
xoffline *xoff_new(void);
void xoff_free(xoffline *x);
/* A packet held for a reassembly comes back: run it through the strategy
 * with xctx (piece of pieces; 0 of 0 when the reassembly failed and the
 * packet goes alone). xctx NULL: the conntrack forgot its flow, the packet
 * goes on as it is, outside the strategy. */
typedef void (*xoff_replay_fn)(void *ud, const uint8_t *raw, size_t len, strat_dir dir, unsigned piece,
                               unsigned pieces, void *xctx);
enum { XOFF_RUN = 0, XOFF_BYPASS, XOFF_HOLD };
/* The context for strategy_apply_x() for p (raw: its bytes). *verdict:
 * XOFF_RUN, run the strategy; XOFF_BYPASS, every tree of dir is cut off on
 * its flow, so the packet passes by the strategy; XOFF_HOLD, p is held for
 * a reassembly and leaves later through fn (NULL is returned). fn may be
 * called before the return for packets held earlier, p among them. */
void *xoff_packet(xoffline *x, const strategy *st, const gpkt *p, strat_dir dir, uint64_t now_ms,
                  const uint8_t *raw, size_t rawlen, xoff_replay_fn fn, void *ud, int *verdict);
/* At the end of the capture: packets still held go through fn alone. */
void xoff_end(xoffline *x, const strategy *st, xoff_replay_fn fn, void *ud);
/* zapret2's posdebug line of a packet with its context from xoff_packet()
 * or a replay, without its time ("posdebug: out direct n1 d0 b0 s0 p0
 * reverse n0 ... payload 0"). */
void xoff_posdebug(const void *xctx, strat_dir dir, const gpkt *p, sbuf *out);

#endif
