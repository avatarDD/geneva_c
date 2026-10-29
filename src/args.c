#include "args.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

static const optdef *find_long(const optdef *defs, const char *name, size_t n)
{
    for (const optdef *d = defs; d->name; d++)
        if (strlen(d->name) == n && strncmp(d->name, name, n) == 0)
            return d;
    return NULL;
}

static const optdef *find_short(const optdef *defs, char c)
{
    for (const optdef *d = defs; d->name; d++)
        if (d->shortopt && d->shortopt == c)
            return d;
    return NULL;
}

static void add_opt(args_t *a, const optdef *d, const char *v)
{
    a->opts = xrealloc(a->opts, sizeof(*a->opts) * (size_t)(a->nopts + 1));
    a->opts[a->nopts].def = d;
    a->opts[a->nopts].value = v;
    a->nopts++;
}

int args_parse(args_t *a, int argc, char **argv, const optdef *defs, char *err, int errlen)
{
    int only_pos = 0;
    memset(a, 0, sizeof(*a));
    a->pos = xcalloc((size_t)argc + 1, sizeof(char *));
    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];
        const optdef *d;
        if (only_pos || arg[0] != '-' || arg[1] == 0) {
            a->pos[a->npos++] = arg;
            continue;
        }
        if (strcmp(arg, "--") == 0) {
            only_pos = 1;
            continue;
        }
        if (arg[1] == '-') {
            const char *name = arg + 2;
            const char *eq = strchr(name, '=');
            size_t n = eq ? (size_t)(eq - name) : strlen(name);
            d = find_long(defs, name, n);
            if (!d) {
                snprintf(err, (size_t)errlen, "unknown option --%.*s", (int)n, name);
                return -1;
            }
            if (!d->has_arg) {
                if (eq) {
                    snprintf(err, (size_t)errlen, "option --%s takes no value", d->name);
                    return -1;
                }
                add_opt(a, d, NULL);
            } else if (eq) {
                add_opt(a, d, eq + 1);
            } else if (i + 1 < argc) {
                add_opt(a, d, argv[++i]);
            } else {
                snprintf(err, (size_t)errlen, "option --%s needs a value", d->name);
                return -1;
            }
            continue;
        }
        /* short options: -h, -v, -s VALUE, -sVALUE */
        d = find_short(defs, arg[1]);
        if (!d) {
            snprintf(err, (size_t)errlen, "unknown option %s", arg);
            return -1;
        }
        if (!d->has_arg) {
            if (arg[2]) {
                snprintf(err, (size_t)errlen, "unknown option %s", arg);
                return -1;
            }
            add_opt(a, d, NULL);
        } else if (arg[2]) {
            add_opt(a, d, arg + 2);
        } else if (i + 1 < argc) {
            add_opt(a, d, argv[++i]);
        } else {
            snprintf(err, (size_t)errlen, "option -%c needs a value", arg[1]);
            return -1;
        }
    }
    return 0;
}

void args_free(args_t *a)
{
    free(a->opts);
    free(a->pos);
    memset(a, 0, sizeof(*a));
}

int arg_has(const args_t *a, const char *name)
{
    for (int i = 0; i < a->nopts; i++)
        if (strcmp(a->opts[i].def->name, name) == 0)
            return 1;
    return 0;
}

const char *arg_str(const args_t *a, const char *name, const char *def)
{
    const char *v = def;
    for (int i = 0; i < a->nopts; i++)
        if (strcmp(a->opts[i].def->name, name) == 0)
            v = a->opts[i].value ? a->opts[i].value : "";
    return v;
}

const char *arg_next(const args_t *a, const char *name, int *idx)
{
    for (; *idx < a->nopts; (*idx)++) {
        if (strcmp(a->opts[*idx].def->name, name) == 0) {
            const char *v = a->opts[*idx].value;
            (*idx)++;
            return v ? v : "";
        }
    }
    return NULL;
}

int arg_int(const args_t *a, const char *name, int64_t def, int64_t lo, int64_t hi, int64_t *out)
{
    const char *s = arg_str(a, name, NULL);
    int64_t v;
    if (!s) {
        *out = def;
        return 0;
    }
    if (parse_i64(s, &v) < 0) {
        uint64_t u;
        /* accept hex like 0x40000000 for marks */
        if (parse_u64(s, &u) < 0 || u > INT64_MAX) {
            fprintf(stderr, "geneva: --%s: not a number: %s\n", name, s);
            return -1;
        }
        v = (int64_t)u;
    }
    if (v < lo || v > hi) {
        fprintf(stderr, "geneva: --%s: %lld out of range [%lld, %lld]\n", name, (long long)v,
                (long long)lo, (long long)hi);
        return -1;
    }
    *out = v;
    return 0;
}

int arg_dbl(const args_t *a, const char *name, double def, double lo, double hi, double *out)
{
    const char *s = arg_str(a, name, NULL);
    double v;
    if (!s) {
        *out = def;
        return 0;
    }
    if (parse_double(s, &v) < 0 || v < lo || v > hi) {
        fprintf(stderr, "geneva: --%s: bad value %s (expected %g..%g)\n", name, s, lo, hi);
        return -1;
    }
    *out = v;
    return 0;
}

void args_help(const char *usage, const optdef *defs)
{
    printf("%s\n\nOptions:\n", usage);
    for (const optdef *d = defs; d->name; d++) {
        char left[64];
        if (d->shortopt)
            snprintf(left, sizeof(left), "-%c, --%s%s%s", d->shortopt, d->name,
                     d->has_arg ? " " : "", d->has_arg ? (d->meta ? d->meta : "VAL") : "");
        else
            snprintf(left, sizeof(left), "    --%s%s%s", d->name, d->has_arg ? " " : "",
                     d->has_arg ? (d->meta ? d->meta : "VAL") : "");
        if (strlen(left) > 30)
            printf("  %s\n  %-30s %s\n", left, "", d->help ? d->help : "");
        else
            printf("  %-30s %s\n", left, d->help ? d->help : "");
    }
}
