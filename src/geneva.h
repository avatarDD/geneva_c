/* Project-wide constants: version, exit codes, subcommand entry points. */
#ifndef GENEVA_GENEVA_H
#define GENEVA_GENEVA_H

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

#endif
