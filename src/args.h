/* Tiny long-option parser shared by all subcommands. */
#ifndef GENEVA_ARGS_H
#define GENEVA_ARGS_H

#include <stdint.h>

typedef struct {
    const char *name; /* without leading "--"; NULL terminates the table */
    char shortopt;    /* 0 if none */
    int has_arg;      /* 0 = flag, 1 = takes a value */
    const char *meta; /* value placeholder for help, e.g. "PORT" */
    const char *help;
} optdef;

typedef struct {
    const optdef *def;
    const char *value; /* NULL for flags */
} optval;

typedef struct {
    optval *opts;
    int nopts;
    const char **pos;
    int npos;
} args_t;

/* Returns 0 or -1 with a message in err. Options may repeat. */
int args_parse(args_t *a, int argc, char **argv, const optdef *defs, char *err, int errlen);
void args_free(args_t *a);

int arg_has(const args_t *a, const char *name);
const char *arg_str(const args_t *a, const char *name, const char *def);
/* Iterates repeated options: pass *idx = 0 first. Returns NULL at the end. */
const char *arg_next(const args_t *a, const char *name, int *idx);
/* Numeric getters print an error and return -1 on malformed values. */
int arg_int(const args_t *a, const char *name, int64_t def, int64_t lo, int64_t hi, int64_t *out);
int arg_dbl(const args_t *a, const char *name, double def, double lo, double hi, double *out);

void args_help(const char *usage, const optdef *defs);

#endif
