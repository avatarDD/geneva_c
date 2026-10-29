/* Project-wide constants: version, exit codes, subcommand entry points. */
#ifndef GENEVA_GENEVA_H
#define GENEVA_GENEVA_H

#include "args.h"

#ifndef GENEVA_VERSION
#  define GENEVA_VERSION "0.1.0-dev"
#endif

/* Exit codes are part of the integration contract (docs/PROTOCOL.md). */
enum {
    EXIT_OK = 0,
    EXIT_FAIL = 1,      /* generic runtime failure */
    EXIT_USAGE = 2,     /* bad command line */
    EXIT_STRATEGY = 3,  /* strategy failed to parse/validate */
    EXIT_PRIV = 4,      /* missing privileges or packet driver */
    EXIT_FIREWALL = 5,  /* firewall rules could not be applied */
    EXIT_IO = 6,        /* file or socket I/O error */
    EXIT_NOT_BLOCKED = 7, /* evolve: target is reachable without a strategy */
};

int cmd_version(int argc, char **argv);
int cmd_check(int argc, char **argv);
int cmd_apply(int argc, char **argv);
int cmd_run(int argc, char **argv);
int cmd_fw(int argc, char **argv);
int cmd_ctl(int argc, char **argv);
int cmd_censor(int argc, char **argv);
int cmd_eval(int argc, char **argv);
int cmd_evolve(int argc, char **argv);
int cmd_db(int argc, char **argv);

/* Shared handling of --log-level, -v, --log-format, --log-file, --quiet and
 * --events (cmd_run.c). Prints an error and returns -1 on bad values. */
int parse_logging(const args_t *a, const char *cmd);

#endif
