/* nfqws2 desync options into a geneva strategy (z2xlate.h). */
#include "ext/z2xlate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* zapret2's function, geneva's x-action and a flag the action gets */
static const struct {
    const char *z, *g, *flag;
} fmap[] = {
    {"fake", "xfake", NULL},
    {"multisplit", "xsplit", NULL},
    {"multidisorder", "xdisorder", NULL},
    {"multidisorder_legacy", "xdisorder", "legacy"},
    {"fakedsplit", "xfakedsplit", NULL},
    {"fakeddisorder", "xfakeddisorder", NULL},
    {"hostfakesplit", "xhostfake", NULL},
    {"tcpseg", "xtcpseg", NULL},
    {"oob", "xoob", NULL},
    {"syndata", "xsyndata", NULL},
    {"wsize", "xwsize", NULL},
    {"wssize", "xwssize", NULL},
    {"send", "xsend", NULL},
    {"pktmod", "xmod", NULL},
    {"rst", "xrst", NULL},
    {"synack", "xsynack", NULL},
    {"synack_split", "xsynacksplit", NULL},
    {"udplen", "xudplen", NULL},
    {"dht_dn", "xdhtdn", NULL},
    {"wgobfs", "xwgobfs", NULL},
    {"ippxor", "xippxor", NULL},
    {"udp2icmp", "xudp2icmp", NULL},
    {"synhide", "xsynhide", NULL},
    {"http_hostcase", "xhttp", "hostcase"},
    {"http_domcase", "xhttp", "domcase"},
    {"http_methodeol", "xhttp", "methodeol"},
    {"http_unixeol", "xhttp", "unixeol"},
    {"drop", "drop", NULL},
};

typedef struct {
    char *act;           /* "xfake{blob=..;ip_ttl=3}" or "drop" */
    const char *payload; /* NULL: all */
    const char *range;   /* NULL: a */
} inst;

/* strtok_r without POSIX (mingw): the next piece of *p up to a separator
 * of seps, empty pieces skipped when skip_empty */
static char *piece(char **p, const char *seps, int skip_empty)
{
    char *s = *p, *e;
    if (!s)
        return NULL;
    if (skip_empty)
        s += strspn(s, seps);
    if (!*s && skip_empty) {
        *p = NULL;
        return NULL;
    }
    e = s + strcspn(s, seps);
    if (*e)
        *e++ = 0;
    else
        e = NULL;
    *p = e;
    return s;
}

static int same(const char *a, const char *b)
{
    return a == b || (a && b && !strcmp(a, b));
}

/* The instances from i on, as a subtree (empty: none) */
static int tree(inst *v, size_t n, size_t i, sbuf *out, sbuf *err)
{
    size_t j = i;
    sbuf rest, chain;
    int rc = 0;
    if (i >= n)
        return 0;
    while (j < n && same(v[j].payload, v[i].payload) && same(v[j].range, v[i].range))
        j++;
    sb_init(&rest);
    sb_init(&chain);
    if (tree(v, n, j, &rest, err) < 0) {
        rc = -1;
        goto done;
    }
    /* the group's chain: v[i](v[i+1](...(rest,),),) */
    sb_puts(&chain, rest.data ? rest.data : "");
    for (size_t k = j; k-- > i;) {
        sbuf t;
        if (!strcmp(v[k].act, "drop") && chain.len) {
            sb_printf(err, "drop must be the last instance");
            rc = -1;
            goto done;
        }
        sb_init(&t);
        sb_puts(&t, v[k].act);
        if (chain.len)
            sb_printf(&t, "(%s,)", chain.data);
        sb_free(&chain);
        chain = t;
    }
    if (v[i].payload) {
        sbuf t;
        sb_init(&t);
        sb_printf(&t, "xwhen{iff=L7:payload:%s}(%s,%s)", v[i].payload, chain.data, rest.data ? rest.data : "");
        sb_free(&chain);
        chain = t;
    }
    if (v[i].range) {
        sbuf t;
        sb_init(&t);
        sb_printf(&t, "xwhen{iff=FLOW:n:%s}(%s,%s)", v[i].range, chain.data, rest.data ? rest.data : "");
        sb_free(&chain);
        chain = t;
    }
    sb_puts(out, chain.data);
done:
    sb_free(&rest);
    sb_free(&chain);
    return rc;
}

/* zapret2's posmarker_parse() of one marker (fakedsplit, fakeddisorder:
 * resolve_pos): a number or NAME[+-N] read with atoi, so that a list
 * "method+2,midsld" is method+2 and "1,midsld" is 1. NULL: invalid. */
static char *one_marker(const char *v)
{
    char buf[64];
    const char *p;
    if (*v == '+' || *v == '-' || (*v >= '0' && *v <= '9')) {
        snprintf(buf, sizeof(buf), "%d", atoi(v));
        return xstrdup(buf);
    }
    for (p = v; *p && *p != '+' && *p != '-'; p++)
        ;
    if ((size_t)(p - v) >= 32 || memchr(v, ',', (size_t)(p - v)))
        return NULL;
    if (!*p)
        return xstrdup(v);
    snprintf(buf, sizeof(buf), "%.*s%+d", (int)(p - v), v, atoi(p));
    return xstrdup(buf);
}

/* "fake:blob=x:ip_ttl=3" into "xfake{blob=x;ip_ttl=3}" */
static char *action(const char *spec, sbuf *err)
{
    char *s = xstrdup(spec), *save = s, *name, *a;
    size_t f;
    int nparams = 0;
    sbuf o;
    name = piece(&save, ":", 0);
    for (f = 0; name && f < sizeof(fmap) / sizeof(fmap[0]); f++)
        if (!strcmp(fmap[f].z, name))
            break;
    if (!name || f == sizeof(fmap) / sizeof(fmap[0])) {
        sb_printf(err, "no geneva action for --lua-desync=%s", name ? name : "");
        free(s);
        return NULL;
    }
    sb_init(&o);
    sb_puts(&o, fmap[f].g);
    if (fmap[f].flag && strcmp(fmap[f].flag, "hostcase")) {
        sb_printf(&o, "{%s", fmap[f].flag);
        nparams++;
    }
    while ((a = piece(&save, ":", 0)) != NULL) {
        const char *eq = strchr(a, '=');
        size_t kl = eq ? (size_t)(eq - a) : strlen(a);
        if (!strcmp(fmap[f].g, "drop")) {
            sb_printf(err, "drop takes no arguments");
            goto bad;
        }
        if (!kl) {
            sb_printf(err, "an empty argument in --lua-desync=%s", spec);
            goto bad;
        }
        sb_puts(&o, nparams++ ? ";" : "{");
        if (kl == 7 && !strncmp(a, "tls_mod", 7))
            sb_printf(&o, "tlsmod%s", a + kl);
        else if (!strcmp(fmap[f].z, "http_hostcase") && kl == 5 && !strncmp(a, "spell", 5))
            sb_printf(&o, "hostcase%s", a + kl);
        else if (!strncmp(fmap[f].z, "faked", 5) && kl == 3 && !strncmp(a, "pos", 3) && eq) {
            char *m = one_marker(eq + 1);
            if (!m) {
                sb_printf(err, "bad marker %s", eq + 1);
                goto bad;
            }
            sb_printf(&o, "pos=%s", m);
            free(m);
        }
        else
            sb_puts(&o, a);
    }
    if (fmap[f].flag && !strcmp(fmap[f].flag, "hostcase") && !strstr(o.data, "hostcase"))
        sb_puts(&o, nparams++ ? ";hostcase" : "{hostcase");
    if (nparams)
        sb_puts(&o, "}");
    free(s);
    return sb_take(&o);
bad:
    sb_free(&o);
    free(s);
    return NULL;
}

int z2x_translate(const char *args, sbuf *out, sbuf *err)
{
    char *s = xstrdup(args), *save = s, *t;
    const char *payload = NULL, *range = NULL;
    inst *v = NULL;
    size_t n = 0;
    int rc = -1;
    while ((t = piece(&save, " \t", 1)) != NULL) {
        if (!strncmp(t, "--payload=", 10)) {
            payload = !strcmp(t + 10, "all") ? NULL : t + 10;
        } else if (!strncmp(t, "--out-range=", 12)) {
            range = !strcmp(t + 12, "a") ? NULL : t + 12;
        } else if (!strncmp(t, "--in-range=", 11) || !strncmp(t, "--lua-init=", 11)) {
            /* the incoming direction: the x-actions follow the flow
             * themselves; --lua-init: blockcheck2's tls_mod of a pattern */
        } else if (!strncmp(t, "--lua-desync=", 13)) {
            char *act;
            if (range && !strcmp(range, "x"))
                continue; /* never runs */
            if (!(act = action(t + 13, err)))
                goto done;
            v = xrealloc(v, (n + 1) * sizeof(*v));
            v[n].act = act;
            v[n].payload = payload;
            v[n].range = range;
            n++;
        } else {
            sb_printf(err, "no geneva equivalent of %s", t);
            goto done;
        }
    }
    if (!n) {
        sb_printf(err, "no --lua-desync");
        goto done;
    }
    {
        sbuf body;
        sb_init(&body);
        if (tree(v, n, 0, &body, err) == 0) {
            sb_printf(out, "[FLOW:n:a]-%s-| \\/", body.data);
            rc = 0;
        }
        sb_free(&body);
    }
done:
    for (size_t i = 0; i < n; i++)
        free(v[i].act);
    free(v);
    free(s);
    return rc;
}
