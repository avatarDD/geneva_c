/*
 * The --ext switch (docs/EXT_ROADMAP.md): the extensions for parity with
 * zapret2 live in src/ext/ and work only when a command gets --ext. Without
 * --ext every command behaves exactly as before (tests/golden). A build with
 * "make EXT=0" has no src/ext/ at all and refuses --ext.
 */
#ifndef GENEVA_EXT_OPT_H
#define GENEVA_EXT_OPT_H

#include "args.h"

#ifndef GENEVA_EXT
#  define GENEVA_EXT 1
#endif

/* The option row every command with extensions puts into its table. It has
 * no help text, so --help does not list it: without --ext the output of
 * every command, help included, stays byte for byte as before (X0). The
 * option is documented in docs/EXT_ROADMAP.md (later docs/EXT.md), and
 * integrators find it as the "ext" feature of "version --json". */
#define EXT_OPT {"ext", 0, 0, NULL, NULL}

/* After args_parse: takes --ext and checks that no --ext-* option comes
 * without it. Prints "geneva CMD: ..." and returns -1 on a usage error
 * (exit code 2), 0 otherwise. */
int ext_parse_args(const args_t *a, const char *cmd);

/* 1 once a command took --ext. */
int ext_enabled(void);

/* For tests: forget the switch. */
void ext_reset(void);

#endif
