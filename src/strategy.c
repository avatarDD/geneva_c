/*
 * Strategy parsing, printing and execution. The parser mirrors Geneva's
 * actions/utils.parse(), ActionTree.parse()/do_parse(), Trigger.parse() and
 * the per-action parse() methods closely enough that every strategy Geneva
 * accepts prints back the same way; it is stricter where Geneva would accept
 * a strategy and then crash or silently do something else at run time.
 */
#include "strategy.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rng.h"

#define MAX_DEPTH 200 /* nesting limit for action trees */

/* ---- packet lists -------------------------------------------------------- */

void pktlist_push(pktlist *l, gpkt *p)
{
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 8;
        l->v = xrealloc(l->v, l->cap * sizeof(*l->v));
    }
    l->v[l->n++] = p;
}

void pktlist_free(pktlist *l)
{
    for (size_t i = 0; i < l->n; i++)
        pkt_free(l->v[i]);
    free(l->v);
    l->v = NULL;
    l->n = l->cap = 0;
}

/* ---- Python-compatible scalars ------------------------------------------- */

/* Python's int(str): surrounding whitespace, a sign, digits with single
 * underscores between them. */
static int py_int(const char *s, int64_t *out)
{
    char buf[32];
    size_t n = 0;
    int digits = 0;
    while (isspace((unsigned char)*s))
        s++;
    if (*s == '+' || *s == '-')
        buf[n++] = *s++;
    for (; *s && !isspace((unsigned char)*s); s++) {
        if (*s == '_') {
            if (!digits || !isdigit((unsigned char)s[1]))
                return -1;
            continue;
        }
        if (!isdigit((unsigned char)*s) || n >= sizeof(buf) - 1)
            return -1;
        buf[n++] = *s;
        digits++;
    }
    while (isspace((unsigned char)*s))
        s++;
    if (*s || !digits)
        return -1;
    buf[n] = 0;
    return parse_i64(buf, out);
}

/* int(text) if that works, else the string itself (Layer.parse()). */
static void py_value(const char *text, gval *out)
{
    int64_t iv;
    if (py_int(text, &iv) == 0)
        gval_int(out, iv);
    else
        gval_str(out, text);
}

static int is_blank(const char *s)
{
    for (; *s; s++)
        if (!isspace((unsigned char)*s))
            return 0;
    return 1;
}

static char *strip_dup(const char *s, size_t n)
{
    while (n && isspace((unsigned char)*s)) {
        s++;
        n--;
    }
    while (n && isspace((unsigned char)s[n - 1]))
        n--;
    return xstrndup(s, n);
}

/* Splits s on sep (a single char); returns the number of parts. */
static size_t split(const char *s, char sep, char ***parts)
{
    size_t n = 1, k = 0;
    const char *p;
    for (p = s; *p; p++)
        if (*p == sep)
            n++;
    *parts = xcalloc(n, sizeof(char *));
    for (p = s;; p++) {
        const char *e = strchr(p, sep);
        size_t len = e ? (size_t)(e - p) : strlen(p);
        (*parts)[k++] = xstrndup(p, len);
        if (!e)
            break;
        p = e;
    }
    return n;
}

static void free_parts(char **parts, size_t n)
{
    for (size_t i = 0; i < n; i++)
        free(parts[i]);
    free(parts);
}

/* ---- triggers ------------------------------------------------------------ */

static void trigger_clear(trigger *t)
{
    free(t->proto_str);
    free(t->field);
    gval_free(&t->value);
    memset(t, 0, sizeof(*t));
}

/* Trigger.parse(): "[proto:field:value(:gas)]". */
static int trigger_parse(trigger *t, const char *text, sbuf *err)
{
    char *s = strip_dup(text, strlen(text));
    char **parts = NULL;
    size_t n, len = strlen(s);
    int rc = -1;
    memset(t, 0, sizeof(*t));
    if (len && s[len - 1] == ']')
        s[--len] = 0;
    n = split(s[0] == '[' ? s + 1 : s, ':', &parts);
    if (n != 3 && n != 4) {
        sb_printf(err, "malformed trigger \"%s\" (expected proto:field:value[:gas])", text);
        goto out;
    }
    t->layer = layer_by_name(parts[0]);
    if (t->layer == LAYER_NONE) {
        sb_printf(err, "unknown protocol \"%s\" in trigger", parts[0]);
        goto out;
    }
    if (!layer_has_field(t->layer, parts[1])) {
        sb_printf(err, "unknown field \"%s\" for %s in trigger", parts[1], layer_name(t->layer));
        goto out;
    }
    t->proto_str = xstrdup(parts[0]);
    t->field = xstrdup(parts[1]);
    py_value(parts[2], &t->value);
    if (t->value.is_str) {
        size_t vl = strlen(t->value.s);
        if (vl && t->value.s[vl - 1] == '*') {
            t->wildcard = 1;
            t->value.s[vl - 1] = 0;
        }
    }
    if (n == 4) {
        if (py_int(parts[3], &t->gas_init) < 0) {
            sb_printf(err, "bad trigger gas \"%s\"", parts[3]);
            goto out;
        }
        t->has_gas = 1;
        t->gas = t->gas_init;
        t->bomb = t->gas_init < 0;
    }
    rc = 0;
out:
    if (parts)
        free_parts(parts, n);
    free(s);
    if (rc < 0)
        trigger_clear(t);
    return rc;
}

void trigger_print(const trigger *t, sbuf *out)
{
    sb_printf(out, "%s:%s:", t->proto_str, t->field);
    gval_print(out, &t->value);
    if (t->wildcard)
        sb_putc(out, '*');
    if (t->has_gas)
        sb_printf(out, ":%lld", (long long)t->gas_init);
}

/* Trigger.is_applicable(), including gas and "bomb" (negative gas). */
static int trigger_applies(trigger *t, const gpkt *p)
{
    gval v;
    int match;
    t->seen++;
    if (!pkt_has_layer(p, t->layer) || pkt_get(p, t->layer, t->field, &v) < 0)
        return 0;
    if (t->wildcard) {
        /* Geneva compares strings only (an int value raised TypeError);
         * integers are matched by their decimal form instead. */
        sbuf b;
        sb_init(&b);
        gval_print(&b, &v);
        match = strstr(b.data, t->value.s) != NULL;
        sb_free(&b);
    } else {
        match = gval_eq(&t->value, &v);
    }
    gval_free(&v);
    if (!match)
        return 0;
    if (!t->has_gas)
        return 1;
    if (t->gas == 0)
        return t->bomb; /* plain trigger out of gas; bomb trigger armed */
    if (t->gas > 0) {
        t->gas--;
        return 1;
    }
    t->gas++; /* bomb countdown */
    return 0;
}

/* ---- actions ------------------------------------------------------------- */

static const char *const act_names[] = {"tamper", "duplicate", "fragment", "drop", "sleep", "trace"};
static const char *const tamper_names[] = {"replace", "corrupt", "add", "compress"};

static int act_is_branching(act_type t) { return t == ACT_DUPLICATE || t == ACT_FRAGMENT; }
static int act_is_terminal(act_type t) { return t == ACT_DROP || t == ACT_TRACE; }
/* Only tamper and drop may run on inbound packets (Action.applies()). */
static int act_allowed_in(act_type t) { return t == ACT_TAMPER || t == ACT_DROP; }

static void action_free(action *a)
{
    if (!a)
        return;
    action_free(a->left);
    action_free(a->right);
    free(a->proto_str);
    free(a->field);
    gval_free(&a->value);
    free(a);
}

static int parse_tamper(action *a, const char *data, sbuf *err)
{
    char **p;
    size_t n = split(data, ':', &p);
    int rc = -1, t;
    if (n != 3 && n != 4) {
        sb_printf(err, "cannot parse tamper action {%s}", data);
        goto out;
    }
    for (t = 0; t < (int)ARRAY_LEN(tamper_names); t++)
        if (!strcmp(p[2], tamper_names[t]))
            break;
    if (t == (int)ARRAY_LEN(tamper_names)) {
        sb_printf(err, "unknown tamper primitive \"%s\"", p[2]);
        goto out;
    }
    a->ttype = (tamper_type)t;
    if (a->ttype == TAMPER_COMPRESS) {
        /* Geneva always prints and runs this as DNS:qd:compress */
        a->proto_str = xstrdup("DNS");
        a->field = xstrdup("qd");
        a->layer = LAYER_DNS;
        rc = 0;
        goto out;
    }
    a->layer = layer_by_name(p[0]);
    if (a->layer == LAYER_NONE) {
        sb_printf(err, "unknown protocol \"%s\" in tamper", p[0]);
        goto out;
    }
    if (!layer_has_field(a->layer, p[1])) {
        sb_printf(err, "unknown field \"%s\" for %s in tamper", p[1], layer_name(a->layer));
        goto out;
    }
    a->proto_str = xstrdup(p[0]);
    a->field = xstrdup(p[1]);
    if (a->ttype == TAMPER_CORRUPT) {
        rc = 0; /* a value after corrupt is ignored, as in Geneva */
        goto out;
    }
    if (n != 4) {
        sb_printf(err, "tamper %s needs a value", p[2]);
        goto out;
    }
    /* TamperAction.parse(): int() unless the field is a load */
    if (strstr(a->field, "load"))
        gval_str(&a->value, p[3]);
    else
        py_value(p[3], &a->value);
    a->has_value = 1;
    if (a->ttype == TAMPER_ADD) {
        int64_t iv;
        if (py_int(p[3], &iv) < 0) {
            sb_printf(err, "tamper add needs an integer, got \"%s\"", p[3]);
            goto out;
        }
    } else {
        /* a value the field can never take would make replace a silent
         * no-op (Geneva raised inside scapy instead) */
        gval chk;
        sbuf txt;
        int bad;
        sb_init(&txt);
        gval_print(&txt, &a->value);
        bad = field_parse(a->layer, a->field, txt.data ? txt.data : "", &chk) < 0;
        gval_free(&chk);
        sb_free(&txt);
        if (bad) {
            sb_printf(err, "bad value \"%s\" for %s:%s", p[3], layer_name(a->layer), a->field);
            goto out;
        }
    }
    rc = 0;
out:
    free_parts(p, n);
    return rc;
}

static int parse_fragment(action *a, const char *data, sbuf *err)
{
    char **p;
    size_t n = split(data, ':', &p);
    int64_t fs, ov = 0;
    int rc = -1;
    if (n != 3 && n != 4) {
        sb_printf(err, "cannot parse fragment action {%s}", data);
        goto out;
    }
    if (py_int(p[1], &fs) < 0 || (n == 4 && py_int(p[3], &ov) < 0) || fs < -65535 ||
        fs > 65535 || ov < -65535 || ov > 65535) {
        sb_printf(err, "cannot parse fragment action {%s}", data);
        goto out;
    }
    /* Geneva: "tcp" anywhere means segmentation, anything else IP
     * fragmentation; the order is True only for a "True..." prefix. */
    a->segment = strstr(p[0], "tcp") != NULL;
    a->fragsize = (int)fs;
    a->overlap = (int)ov;
    a->in_order = str_starts(p[2], "True");
    rc = 0;
out:
    free_parts(p, n);
    return rc;
}

static int parse_sleep(action *a, const char *data, sbuf *err)
{
    char *s = strip_dup(data, strlen(data));
    double v;
    int rc = parse_double(s, &v);
    if (rc < 0 || !isfinite(v) || v < 0 || v > 3600) {
        sb_printf(err, "bad sleep time \"%s\"", data);
        rc = -1;
    } else {
        a->time = v;
    }
    free(s);
    return rc;
}

static int parse_trace(action *a, const char *data, sbuf *err)
{
    char **p;
    size_t n = split(data, ':', &p);
    int64_t s, e;
    int rc = -1;
    if (n != 2 || py_int(p[0], &s) < 0 || py_int(p[1], &e) < 0 || s < 0 || e > 255 || s > e) {
        sb_printf(err, "bad trace range {%s} (expected start_ttl:end_ttl, start <= end)", data);
    } else {
        a->start_ttl = (int)s;
        a->end_ttl = (int)e;
        rc = 0;
    }
    free_parts(p, n);
    return rc;
}

/* Action.parse_action(): "name" or "name{params}". */
static action *action_parse(const char *text, strat_dir dir, sbuf *err)
{
    const char *brace = strchr(text, '{');
    size_t nl = brace ? (size_t)(brace - text) : strlen(text);
    char *name = xstrndup(text, nl), *data = NULL;
    action *a = xcalloc(1, sizeof(*a));
    int t, rc = 0;
    a->layer = LAYER_NONE;
    for (t = 0; t < (int)ARRAY_LEN(act_names); t++)
        if (str_ieq(name, act_names[t]))
            break;
    if (t == (int)ARRAY_LEN(act_names)) {
        sb_printf(err, "unknown action \"%s\"", name);
        goto fail;
    }
    a->type = (act_type)t;
    if (dir == DIR_IN && !act_allowed_in(a->type)) {
        sb_printf(err, "action %s cannot be used in the inbound forest", act_names[t]);
        goto fail;
    }
    if (brace) {
        /* Geneva drops every "}" from the parameters */
        size_t k = 0;
        if (strchr(brace + 1, '{')) {
            sb_printf(err, "malformed action parameters \"%s\"", text);
            goto fail;
        }
        data = xstrdup(brace + 1);
        for (char *c = data; *c; c++)
            if (*c != '}')
                data[k++] = *c;
        data[k] = 0;
    }
    /* defaults of the Geneva constructors */
    a->fragsize = -1;
    a->segment = 1;
    a->time = 1;
    a->start_ttl = 1;
    a->end_ttl = 64;
    if (a->type == ACT_FRAGMENT)
        a->in_order = rng_chance(0.5); /* FragmentAction.get_rand_order() */
    if (data && *data) {
        switch (a->type) {
        case ACT_TAMPER: rc = parse_tamper(a, data, err); break;
        case ACT_FRAGMENT: rc = parse_fragment(a, data, err); break;
        case ACT_SLEEP: rc = parse_sleep(a, data, err); break;
        case ACT_TRACE: rc = parse_trace(a, data, err); break;
        default:
            sb_printf(err, "action %s takes no parameters", act_names[t]);
            rc = -1;
        }
        if (rc < 0)
            goto fail;
    } else if (a->type == ACT_TAMPER) {
        /* Geneva would draw a random tamper here; a strategy to run must
         * say what it does. */
        sb_puts(err, "tamper needs parameters {proto:field:primitive[:value]}");
        goto fail;
    }
    free(name);
    free(data);
    return a;
fail:
    free(name);
    free(data);
    action_free(a);
    return NULL;
}

void action_print(const action *a, sbuf *out)
{
    sb_puts(out, act_names[a->type]);
    switch (a->type) {
    case ACT_TAMPER:
        if (a->ttype == TAMPER_COMPRESS) {
            sb_puts(out, "{DNS:qd:compress}");
        } else if (a->ttype == TAMPER_CORRUPT) {
            sb_printf(out, "{%s:%s:corrupt}", a->proto_str, a->field);
        } else {
            sb_printf(out, "{%s:%s:%s:", a->proto_str, a->field, tamper_names[a->ttype]);
            gval_print(out, &a->value);
            sb_putc(out, '}');
        }
        break;
    case ACT_FRAGMENT:
        sb_printf(out, "{%s:%d:%s", a->segment ? "tcp" : "ip", a->fragsize,
                  a->in_order ? "True" : "False");
        if (a->overlap)
            sb_printf(out, ":%d", a->overlap);
        sb_putc(out, '}');
        break;
    case ACT_SLEEP:
        sb_printf(out, "{%g}", a->time);
        break;
    case ACT_TRACE:
        sb_printf(out, "{%d:%d}", a->start_ttl, a->end_ttl);
        break;
    default:
        break;
    }
}

/* ---- trees --------------------------------------------------------------- */

/* ActionTree.do_parse(). On success *node is the subtree (NULL if empty). */
static int tree_do_parse(const char *s, strat_dir dir, int depth, action **node, sbuf *err)
{
    char *act_str, *left = NULL, *right = NULL;
    const char *paren;
    action *a;
    int rc = -1;
    *node = NULL;
    if (is_blank(s))
        return 0;
    if (depth > MAX_DEPTH) {
        sb_puts(err, "action tree is nested too deeply");
        return -1;
    }
    paren = strchr(s, '(');
    if (!paren) {
        act_str = xstrdup(s);
    } else {
        /* Find the comma that splits this node's subtree: the first point
         * where the commas seen equal the parentheses opened. */
        const char *rest = paren, *c;
        int d = 0, commas = 0;
        size_t rl = strlen(rest);
        for (c = rest; *c; c++) {
            if (*c == '(')
                d++;
            if (*c == ',')
                commas++;
            if (commas == d && d > 0)
                break;
        }
        if (!*c) {
            sb_printf(err, "malformed action tree \"%s\"", s);
            return -1;
        }
        act_str = xstrndup(s, (size_t)(paren - s));
        left = xstrndup(rest + 1, (size_t)(c - rest - 1));
        /* rest[idx+1:-1] */
        {
            size_t from = (size_t)(c - rest) + 1;
            right = from < rl ? xstrndup(rest + from, rl - from - 1) : xstrdup("");
        }
    }
    a = action_parse(act_str, dir, err);
    if (!a)
        goto out;
    if (!act_is_branching(a->type) && right && *right) {
        sb_printf(err, "%s cannot have a right subtree", act_names[a->type]);
        goto fail;
    }
    if (act_is_terminal(a->type) && ((left && *left) || (right && *right))) {
        sb_printf(err, "terminal action %s cannot have children", act_names[a->type]);
        goto fail;
    }
    if (left && *left && tree_do_parse(left, dir, depth + 1, &a->left, err) < 0)
        goto fail;
    if (right && *right && tree_do_parse(right, dir, depth + 1, &a->right, err) < 0)
        goto fail;
    *node = a;
    rc = 0;
    goto out;
fail:
    action_free(a);
out:
    free(act_str);
    free(left);
    free(right);
    return rc;
}

static void tree_free(atree *t)
{
    if (!t)
        return;
    trigger_clear(&t->trig);
    action_free(t->root);
    free(t);
}

/* Removes every occurrence of needle from s in place. */
static void remove_all(char *s, const char *needle)
{
    size_t nl = strlen(needle);
    char *r = s, *w = s;
    while (*r) {
        if (!strncmp(r, needle, nl)) {
            r += nl;
            continue;
        }
        *w++ = *r++;
    }
    *w = 0;
}

/* ActionTree.parse(): "[trigger]-actions-|". */
static atree *tree_parse(const char *text, strat_dir dir, sbuf *err)
{
    char *s = strip_dup(text, strlen(text)), *body = NULL, *trig = NULL;
    size_t len = strlen(s);
    char *sep = NULL;
    atree *t = xcalloc(1, sizeof(*t));
    t->dir = dir;
    if (!len || s[len - 1] != '|') {
        sb_printf(err, "tree \"%s\" does not end with |", s);
        goto fail;
    }
    /* \[(\S*)\]-(\S*): the trigger runs up to the last "]-" */
    if (s[0] == '[')
        for (char *p = strstr(s, "]-"); p; p = strstr(p + 1, "]-"))
            sep = p;
    if (!sep) {
        sb_printf(err, "could not identify the trigger in \"%s\"", s);
        goto fail;
    }
    trig = xstrndup(s + 1, (size_t)(sep - s - 1));
    body = xstrdup(sep + 2);
    if (trigger_parse(&t->trig, trig, err) < 0)
        goto fail;
    len = strlen(body);
    if (len >= 2 && !strcmp(body + len - 2, "-|"))
        remove_all(body, "-|");
    len = strlen(body);
    if (len && body[len - 1] == '|')
        remove_all(body, "|");
    if (tree_do_parse(body, dir, 0, &t->root, err) < 0)
        goto fail;
    free(s);
    free(trig);
    free(body);
    return t;
fail:
    free(s);
    free(trig);
    free(body);
    tree_free(t);
    return NULL;
}

static void action_repr(const action *a, sbuf *out)
{
    if (!a)
        return;
    action_print(a, out);
    if (a->left || a->right) {
        sb_putc(out, '(');
        action_repr(a->left, out);
        sb_putc(out, ',');
        action_repr(a->right, out);
        sb_putc(out, ')');
    }
}

void tree_print(const atree *t, sbuf *out)
{
    sb_putc(out, '[');
    trigger_print(&t->trig, out);
    sb_puts(out, "]-");
    action_repr(t->root, out);
    if (out->len && out->data[out->len - 1] != '-')
        sb_putc(out, '-');
    sb_putc(out, '|');
}

static size_t action_count(const action *a)
{
    return a ? 1 + action_count(a->left) + action_count(a->right) : 0;
}

/* ---- strategies ---------------------------------------------------------- */

static void forest_push(atree ***v, size_t *n, atree *t)
{
    *v = xrealloc(*v, (*n + 1) * sizeof(**v));
    (*v)[(*n)++] = t;
}

void strategy_free(strategy *s)
{
    if (!s)
        return;
    for (size_t i = 0; i < s->nout; i++)
        tree_free(s->out[i]);
    for (size_t i = 0; i < s->nin; i++)
        tree_free(s->in[i]);
    free(s->out);
    free(s->in);
    free(s);
}

strategy *strategy_parse(const char *text, sbuf *err)
{
    char *s = strip_dup(text, strlen(text));
    size_t len = strlen(s);
    const char *part;
    strat_dir dir = DIR_OUT;
    strategy *st = xcalloc(1, sizeof(*st));
    char *body = s;
    /* hanging quotes, as Geneva strips them */
    if (len && body[0] == '"') {
        body++;
        len--;
    }
    if (len && body[len - 1] == '"')
        body[--len] = 0;
    /* forests are separated by "\/"; everything after the first is inbound */
    part = body;
    for (;;) {
        const char *sl = strstr(part, "\\/");
        size_t plen = sl ? (size_t)(sl - part) : strlen(part);
        char *forest = xstrndup(part, plen);
        char **trees;
        size_t nt = split(forest, '|', &trees);
        int bad = 0;
        free(forest);
        for (size_t i = 0; i < nt && !bad; i++) {
            char *tr = strip_dup(trees[i], strlen(trees[i]));
            atree *t;
            if (!*tr) {
                free(tr);
                continue;
            }
            for (char *c = tr; *c; c++) {
                if (isspace((unsigned char)*c)) {
                    sb_printf(err, "strategy includes a space in \"%s\"", tr);
                    bad = 1;
                    break;
                }
            }
            if (!bad) {
                /* the split ate the "|" that closes the tree */
                char *with_bar = xasprintf("%s|", tr);
                t = tree_parse(with_bar, dir, err);
                free(with_bar);
                if (!t)
                    bad = 1;
                else if (dir == DIR_OUT)
                    forest_push(&st->out, &st->nout, t);
                else
                    forest_push(&st->in, &st->nin, t);
            }
            free(tr);
        }
        free_parts(trees, nt);
        if (bad) {
            free(s);
            strategy_free(st);
            return NULL;
        }
        if (!sl)
            break;
        part = sl + 2;
        dir = DIR_IN;
    }
    free(s);
    return st;
}

void strategy_print(const strategy *s, sbuf *out)
{
    size_t start = out->len;
    for (size_t i = 0; i < s->nout; i++) {
        if (i)
            sb_putc(out, ' ');
        tree_print(s->out[i], out);
    }
    if (out->len > start)
        sb_putc(out, ' ');
    sb_puts(out, "\\/");
    for (size_t i = 0; i < s->nin; i++) {
        sb_putc(out, ' ');
        tree_print(s->in[i], out);
    }
}

size_t strategy_len(const strategy *s)
{
    size_t n = 0;
    for (size_t i = 0; i < s->nout; i++)
        n += action_count(s->out[i]->root);
    for (size_t i = 0; i < s->nin; i++)
        n += action_count(s->in[i]->root);
    return n;
}

static void action_reset(action *a)
{
    if (!a)
        return;
    a->ran = 0;
    a->runs = 0;
    action_reset(a->left);
    action_reset(a->right);
}

void strategy_reset(strategy *s)
{
    for (int d = 0; d < 2; d++) {
        atree **f = d ? s->in : s->out;
        size_t n = d ? s->nin : s->nout;
        for (size_t i = 0; i < n; i++) {
            f[i]->trig.gas = f[i]->trig.gas_init;
            f[i]->trig.seen = 0;
            f[i]->fired = 0;
            action_reset(f[i]->root);
        }
    }
}

/* ---- pretty printing (anytree RenderTree, as in Geneva) ------------------- */

static void pretty_node(const action *a, const char *name, const char *prefix, int last,
                        int is_root, sbuf *out)
{
    sbuf child_prefix;
    const char *kids[2] = {NULL, NULL};
    const action *kid_act[2] = {NULL, NULL};
    int nk = 0;
    if (is_root) {
        sb_puts(out, name);
    } else {
        sb_printf(out, "%s%s%s", prefix, last ? "\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 "
                                               : "\xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80 ",
                  name);
    }
    if (!a)
        return;
    if (a->left)
        kid_act[nk] = a->left, kids[nk++] = "";
    else if (!act_is_terminal(a->type))
        kids[nk++] = " ===> ";
    if (a->right)
        kid_act[nk] = a->right, kids[nk++] = "";
    else if (!act_is_terminal(a->type) && act_is_branching(a->type))
        kids[nk++] = " ===> ";
    sb_init(&child_prefix);
    if (!is_root)
        sb_printf(&child_prefix, "%s%s", prefix, last ? "    " : "\xe2\x94\x82   ");
    for (int i = 0; i < nk; i++) {
        sb_putc(out, '\n');
        if (kid_act[i]) {
            sbuf nm;
            sb_init(&nm);
            action_print(kid_act[i], &nm);
            pretty_node(kid_act[i], nm.data, child_prefix.data ? child_prefix.data : "",
                        i == nk - 1, 0, out);
            sb_free(&nm);
        } else {
            pretty_node(NULL, kids[i], child_prefix.data ? child_prefix.data : "", i == nk - 1,
                        0, out);
        }
    }
    sb_free(&child_prefix);
}

static void pretty_forest(atree **f, size_t n, sbuf *out)
{
    for (size_t i = 0; i < n; i++) {
        if (f[i]->root) {
            sbuf nm;
            trigger_print(&f[i]->trig, out);
            sb_putc(out, '\n');
            sb_init(&nm);
            action_print(f[i]->root, &nm);
            pretty_node(f[i]->root, nm.data, "", 1, 1, out);
            sb_free(&nm);
        }
        sb_putc(out, '\n');
    }
}

void strategy_pretty(const strategy *s, sbuf *out)
{
    pretty_forest(s->out, s->nout, out);
    sb_puts(out, " \n \\/ \n ");
    pretty_forest(s->in, s->nin, out);
}

/* ---- JSON ---------------------------------------------------------------- */

static void json_gval(jw *w, const gval *v)
{
    if (v->is_str)
        jw_str(w, v->s ? v->s : "");
    else
        jw_int(w, v->i);
}

static void action_json(const action *a, jw *w)
{
    sbuf s;
    if (!a) {
        jw_null(w);
        return;
    }
    sb_init(&s);
    action_print(a, &s);
    jw_obj(w);
    jw_kstr(w, "action", act_names[a->type]);
    jw_kstr(w, "str", s.data);
    switch (a->type) {
    case ACT_TAMPER:
        jw_kstr(w, "proto", a->proto_str);
        jw_kstr(w, "field", a->field);
        jw_kstr(w, "primitive", tamper_names[a->ttype]);
        if (a->has_value) {
            jw_key(w, "value");
            json_gval(w, &a->value);
        }
        break;
    case ACT_FRAGMENT:
        jw_kstr(w, "mode", a->segment ? "tcp" : "ip");
        jw_kint(w, "fragsize", a->fragsize);
        jw_kbool(w, "in_order", a->in_order);
        jw_kint(w, "overlap", a->overlap);
        break;
    case ACT_SLEEP:
        jw_kdbl(w, "time", a->time);
        break;
    case ACT_TRACE:
        jw_kint(w, "start_ttl", a->start_ttl);
        jw_kint(w, "end_ttl", a->end_ttl);
        break;
    default:
        break;
    }
    if (a->left || a->right) {
        jw_key(w, "left");
        action_json(a->left, w);
        jw_key(w, "right");
        action_json(a->right, w);
    }
    jw_obj_end(w);
    sb_free(&s);
}

static void forest_json(atree **f, size_t n, jw *w)
{
    jw_arr(w);
    for (size_t i = 0; i < n; i++) {
        sbuf s;
        const trigger *t = &f[i]->trig;
        sb_init(&s);
        tree_print(f[i], &s);
        jw_obj(w);
        jw_kstr(w, "str", s.data);
        jw_key(w, "trigger");
        jw_obj(w);
        jw_kstr(w, "proto", t->proto_str);
        jw_kstr(w, "field", t->field);
        jw_key(w, "value");
        json_gval(w, &t->value);
        jw_kbool(w, "wildcard", t->wildcard);
        jw_key(w, "gas");
        if (t->has_gas)
            jw_int(w, t->gas_init);
        else
            jw_null(w);
        jw_obj_end(w);
        jw_key(w, "actions");
        action_json(f[i]->root, w);
        jw_obj_end(w);
        sb_free(&s);
    }
    jw_arr_end(w);
}

void strategy_json(const strategy *s, jw *w)
{
    sbuf str;
    sb_init(&str);
    strategy_print(s, &str);
    jw_obj(w);
    jw_kstr(w, "strategy", str.data);
    jw_kuint(w, "actions", strategy_len(s));
    jw_key(w, "out");
    forest_json(s->out, s->nout, w);
    jw_key(w, "in");
    forest_json(s->in, s->nin, w);
    jw_obj_end(w);
    sb_free(&str);
}

/* ---- execution ----------------------------------------------------------- */

/* Python's Packet.copy(): a fresh wrapper, so no pending sleep. */
static gpkt *fresh_copy(const gpkt *p)
{
    gpkt *c = pkt_copy(p);
    c->sleep = 0;
    return c;
}

static int numeric(const gval *v, int64_t *out)
{
    if (!v->is_str) {
        *out = v->i;
        return 0;
    }
    return py_int(v->s ? v->s : "", out);
}

/* TamperAction.tamper(): failures leave the packet unchanged. */
static void run_tamper(const action *a, gpkt *p)
{
    gval old, nv;
    int64_t x, y;
    if (!pkt_has_layer(p, a->layer))
        return;
    if (a->ttype == TAMPER_COMPRESS) {
        pkt_dns_compress(p);
        return;
    }
    if (pkt_get(p, a->layer, a->field, &old) < 0)
        return;
    switch (a->ttype) {
    case TAMPER_CORRUPT: {
        layer_id gl = a->layer;
        /* IPv4 address fields on an IPv6 packet get IPv6 values */
        if (gl == LAYER_IP && p->ipver == 6 && (!strcmp(a->field, "src") || !strcmp(a->field, "dst")))
            gl = LAYER_IPV6;
        if (field_gen(gl, a->field, &nv) < 0) {
            gval_free(&old);
            return;
        }
        break;
    }
    case TAMPER_ADD:
        if (numeric(&a->value, &x) < 0 || numeric(&old, &y) < 0) {
            gval_free(&old);
            return;
        }
        gval_int(&nv, x + y);
        break;
    default:
        gval_copy(&nv, &a->value);
        break;
    }
    pkt_set(p, a->layer, a->field, &nv);
    gval_free(&nv);
    gval_free(&old);
}

/* Python slice index normalization. */
static size_t py_index(long i, size_t len)
{
    if (i < 0)
        i += (long)len;
    if (i < 0)
        return 0;
    return (size_t)i > len ? len : (size_t)i;
}

static gpkt *segment_part(const gpkt *p, const uint8_t *data, size_t n, uint32_t seq)
{
    gpkt *c = fresh_copy(p);
    pkt_set_payload(c, data, n);
    c->seq = seq;
    c->auto_fields |= AUTO_IP_LEN | AUTO_IP_CSUM | AUTO_TCP_CSUM | AUTO_TCP_DOFS | AUTO_V6_PLEN;
    return c;
}

/* FragmentAction.tcp_segment(). */
static void run_segment(const action *a, gpkt *p, gpkt **l, gpkt **r)
{
    size_t len = p->payload_len, p1_end, p2_start;
    long fs = a->fragsize, ob;
    gpkt *s1, *s2;
    if (p->l4 != LAYER_TCP || !len) {
        *l = p;
        *r = fresh_copy(p);
        return;
    }
    if (fs == -1 || fs > (long)len - 1)
        fs = (long)(len / 2);
    /* ob = min(len(payload[fs:]), overlap); payload[:fs+ob], payload[fs:] */
    p2_start = py_index(fs, len);
    ob = (long)(len - p2_start) < a->overlap ? (long)(len - p2_start) : a->overlap;
    p1_end = py_index(fs + ob, len);
    s1 = segment_part(p, p->payload, p1_end, p->seq);
    s2 = segment_part(p, p->payload + p2_start, len - p2_start, (uint32_t)(p->seq + (uint32_t)fs));
    pkt_free(p);
    *l = a->in_order ? s1 : s2;
    *r = a->in_order ? s2 : s1;
}

/* Builds p and returns the bytes; *hl is the IP header length (with
 * options or extension headers) and *n the length of what follows it. */
static uint8_t *l4_bytes(gpkt *p, size_t *n, size_t *hl)
{
    size_t total;
    uint8_t *b;
    /* rebuild from the fields: the original bytes may carry link padding */
    pkt_mark_dirty(p);
    b = pkt_bytes(p, &total);
    *hl = p->ipver == 6 ? 40 + p->ext_len : 20 + (size_t)p->ipopts_len;
    *n = total > *hl ? total - *hl : 0;
    return b;
}

static gpkt *frag_v4(const gpkt *p, const uint8_t *data, size_t n, size_t off, int more)
{
    gpkt *c = fresh_copy(p);
    c->l4 = LAYER_NONE;
    pkt_set_payload(c, data, n);
    if (more)
        c->ipflags |= 1;
    c->frag = (uint16_t)((c->frag + off / 8) & 0x1fff);
    c->auto_fields |= AUTO_IP_LEN | AUTO_IP_CSUM;
    return c;
}

/* Offset of the next-header byte that points past the extension headers. */
static size_t v6_last_nh(const gpkt *p, int *has_frag)
{
    size_t off = 0, nh_pos = (size_t)-1; /* -1: the fixed header's nh */
    uint8_t nh = p->nh;
    *has_frag = 0;
    while (off < p->ext_len) {
        size_t hlen;
        if (nh == 44) {
            *has_frag = 1;
            hlen = 8;
        } else if (nh == 51) {
            hlen = ((size_t)p->ext[off + 1] + 2) * 4;
        } else {
            hlen = ((size_t)p->ext[off + 1] + 1) * 8;
        }
        nh_pos = off;
        nh = p->ext[off];
        off += hlen;
    }
    return nh_pos;
}

static gpkt *frag_v6(const gpkt *p, const uint8_t *data, size_t n, size_t off, int more,
                     uint32_t ident)
{
    gpkt *c = fresh_copy(p);
    int hf;
    size_t pos = v6_last_nh(p, &hf);
    uint8_t *ext = xmalloc(p->ext_len + 8);
    uint16_t fo = (uint16_t)((off / 8) << 3 | (more ? 1 : 0));
    if (p->ext_len)
        memcpy(ext, p->ext, p->ext_len);
    ext[p->ext_len] = p->l4proto;
    ext[p->ext_len + 1] = 0;
    ext[p->ext_len + 2] = (uint8_t)(fo >> 8);
    ext[p->ext_len + 3] = (uint8_t)fo;
    ext[p->ext_len + 4] = (uint8_t)(ident >> 24);
    ext[p->ext_len + 5] = (uint8_t)(ident >> 16);
    ext[p->ext_len + 6] = (uint8_t)(ident >> 8);
    ext[p->ext_len + 7] = (uint8_t)ident;
    if (pos == (size_t)-1)
        c->nh = 44;
    else
        ext[pos] = 44;
    free(c->ext);
    c->ext = ext;
    c->ext_len = p->ext_len + 8;
    c->l4 = LAYER_NONE;
    pkt_set_payload(c, data, n);
    c->auto_fields |= AUTO_V6_PLEN;
    return c;
}

/* FragmentAction.ip_fragment() on top of scapy's fragment(). */
static void run_ipfrag(const action *a, gpkt *p, gpkt **l, gpkt **r)
{
    size_t n, hl, fs;
    uint8_t *b;
    int has_load, already;
    if (p->l4 == LAYER_NONE)
        has_load = p->payload_len > 0;
    else
        has_load = p->payload_len > 0 && !pkt_has_layer(p, LAYER_DNS);
    if (p->ipver == 6) {
        v6_last_nh(p, &already);
        if (already)
            has_load = 0;
    }
    if (!has_load) {
        *l = p;
        *r = fresh_copy(p);
        return;
    }
    b = l4_bytes(p, &n, &hl);
    if (a->fragsize < 0 || (size_t)a->fragsize * 8 > n || n <= 8)
        fs = n / 2 / 8 * 8;
    else
        fs = (size_t)a->fragsize * 8;
    if (fs == 0) {
        /* scapy is not asked to fragment: two copies of the packet */
        *l = fresh_copy(p);
        *r = fresh_copy(p);
    } else {
        const uint8_t *d = b + hl;
        size_t first = fs < n ? fs : n;
        int two = n > fs; /* more than one fragment */
        gpkt *f1, *f2;
        if (p->ipver == 6) {
            uint32_t ident = rng_u32();
            f1 = frag_v6(p, d, first, 0, two, ident);
            f2 = two ? frag_v6(p, d + fs, n - fs, fs, 0, ident) : fresh_copy(f1);
        } else {
            f1 = frag_v4(p, d, first, 0, two);
            if (two) {
                f2 = frag_v4(p, d + fs, n - fs, fs, 0);
                /* scapy produced more than two fragments: Geneva merges
                 * them and sets the flags to exactly DF */
                if (n - fs > fs)
                    f2->ipflags = 2;
            } else {
                f2 = fresh_copy(f1);
            }
        }
        *l = a->in_order ? f1 : f2;
        *r = a->in_order ? f2 : f1;
    }
    free(b);
    pkt_free(p);
}

static void run_trace(action *a, gpkt *p, pktlist *out)
{
    if (a->ran) {
        pkt_free(p);
        return;
    }
    a->ran = 1;
    /* Geneva sends one copy per TTL in [start, end), a second apart */
    for (int ttl = a->start_ttl; ttl < a->end_ttl; ttl++) {
        gpkt *c = fresh_copy(p);
        gval v;
        gval_int(&v, ttl);
        pkt_set(c, LAYER_IP, "ttl", &v);
        c->sleep = (double)(ttl - a->start_ttl);
        pktlist_push(out, c);
    }
    pkt_free(p);
}

static void do_run(action *a, gpkt *p, pktlist *out)
{
    gpkt *l = NULL, *r = NULL;
    if (!a) {
        pkt_free(p); /* an empty tree yields nothing */
        return;
    }
    a->runs++;
    switch (a->type) {
    case ACT_TAMPER:
        run_tamper(a, p);
        l = p;
        break;
    case ACT_DUPLICATE:
        l = p;
        r = fresh_copy(p);
        break;
    case ACT_FRAGMENT:
        if (a->segment)
            run_segment(a, p, &l, &r);
        else
            run_ipfrag(a, p, &l, &r);
        break;
    case ACT_DROP:
        pkt_free(p);
        break;
    case ACT_SLEEP:
        p->sleep = a->time;
        l = p;
        break;
    case ACT_TRACE:
        run_trace(a, p, out);
        break;
    }
    if (l) {
        if (a->left)
            do_run(a->left, l, out);
        else
            pktlist_push(out, l);
    }
    if (r) {
        if (a->right)
            do_run(a->right, r, out);
        else
            pktlist_push(out, r);
    }
}

int strategy_apply(strategy *s, gpkt *pkt, strat_dir dir, pktlist *out)
{
    atree **f = dir == DIR_IN ? s->in : s->out;
    size_t n = dir == DIR_IN ? s->nin : s->nout;
    int fired = 0;
    for (size_t i = 0; i < n; i++) {
        if (!trigger_applies(&f[i]->trig, pkt))
            continue;
        fired++;
        f[i]->fired++;
        /* each tree starts from a fresh copy of the original packet */
        do_run(f[i]->root, fresh_copy(pkt), out);
    }
    if (fired)
        pkt_free(pkt);
    else
        pktlist_push(out, pkt);
    return fired;
}
