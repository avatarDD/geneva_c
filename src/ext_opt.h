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

/* Help text of an option that works only with --ext. args_help() lists such
 * options apart, under "Extensions (with --ext):" after the usual ones, so
 * that the legacy part of every help text stays as it was. In a build
 * without src/ext/ (make EXT=0) they have no help and are not listed. */
#define EXT_HELP_MARK "\001"
#if GENEVA_EXT
#  define EXT_HELP(s) EXT_HELP_MARK s
#else
#  define EXT_HELP(s) NULL
#endif

/* The option row every command with extensions puts into its table. The
 * extensions are described in docs/EXT.md, and integrators find them as
 * the "ext" feature of "version --json". */
#define EXT_OPT {"ext", 0, 0, NULL, EXT_HELP("turn on the extensions beyond Geneva (docs/EXT.md)")}

/* After args_parse: takes --ext and checks that no --ext-* option comes
 * without it. Prints "geneva CMD: ..." and returns -1 on a usage error
 * (exit code 2), 0 otherwise. */
int ext_parse_args(const args_t *a, const char *cmd);

/* 1 once a command took --ext. */
int ext_enabled(void);

/* For tests: forget the switch. */
void ext_reset(void);

#endif
