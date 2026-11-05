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
/* The context for strategy_apply_x() for p; *bypass is 1 when every tree
 * of dir is cut off on its flow (the packet passes by the strategy). */
void *xoff_packet(xoffline *x, const strategy *st, const gpkt *p, strat_dir dir, uint64_t now_ms, int *bypass);
/* zapret2's posdebug line for the packet xoff_packet() just took, without
 * its time ("posdebug: out direct n1 d0 b0 s0 p0 reverse n0 ... payload 0"). */
void xoff_posdebug(const xoffline *x, strat_dir dir, const gpkt *p, sbuf *out);

#endif
