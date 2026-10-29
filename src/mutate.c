#include "mutate.h"

#include <stdlib.h>
#include <string.h>

#include "rng.h"

/* ---- helpers ------------------------------------------------------------- */

static int is_branching(act_type t) { return t == ACT_DUPLICATE || t == ACT_FRAGMENT; }
static int is_terminal(act_type t) { return t == ACT_DROP || t == ACT_TRACE; }

/* Slots (pointers to the pointers that hold each node) in preorder, like
 * iterating an ActionTree. The root slot comes first. */
typedef struct {
    action **v[256];
    size_t n;
} slots;

static void collect(action **slot, slots *s)
{
    if (!*slot || s->n == ARRAY_LEN(s->v))
        return;
    s->v[s->n++] = slot;
    collect(&(*slot)->left, s);
    collect(&(*slot)->right, s);
}

static size_t count_actions(const action *a)
{
    return a ? 1 + count_actions(a->left) + count_actions(a->right) : 0;
}

strategy *strategy_copy(const strategy *s)
{
    sbuf t, err;
    strategy *c;
    sb_init(&t);
    sb_init(&err);
    strategy_print(s, &t);
    c = strategy_parse(t.data, &err);
    sb_free(&t);
    sb_free(&err);
    return c;
}

int strategy_canon(strategy **s, char **text)
{
    sbuf a, b, err;
    strategy *c;
    int rc = -1;
    sb_init(&a);
    sb_init(&b);
    sb_init(&err);
    strategy_print(*s, &a);
    c = strategy_parse(a.data, &err);
    if (c) {
        strategy_print(c, &b);
        if (!strcmp(a.data, b.data)) {
            strategy_free(*s);
            *s = c;
            c = NULL;
            if (text)
                *text = sb_take(&b);
            rc = 0;
        }
        strategy_free(c);
    }
    sb_free(&a);
    sb_free(&b);
    sb_free(&err);
    return rc;
}

int gen_disable_actions(gen_ctx *g, const char *list, sbuf *err)
{
    static const char *const names[] = {"tamper", "duplicate", "fragment", "drop", "sleep", "trace"};
    const char *s = list;
    while (s && *s) {
        const char *c = strchr(s, ',');
        size_t n = c ? (size_t)(c - s) : strlen(s);
        size_t i;
        for (i = 0; i < ARRAY_LEN(names); i++)
            if (strlen(names[i]) == n && str_ieqn(s, names[i], n))
                break;
        if (i == ARRAY_LEN(names)) {
            if (n) {
                sb_printf(err, "unknown action \"%.*s\" (tamper, duplicate, fragment, drop, sleep, trace)",
                          (int)n, s);
                return -1;
            }
        } else {
            g->disabled[i] = 1;
        }
        s = c ? c + 1 : NULL;
    }
    return 0;
}

/* ---- values: real packets or fuzzing ------------------------------------- */

static const layer_id all_layers[] = {LAYER_IP, LAYER_TCP, LAYER_UDP, LAYER_DNS, LAYER_DNSQR, LAYER_IPV6};

/* Layer.gen_random() over a random allowed layer (Packet.gen_random). */
static int fuzzed(layer_id *layer, const char **field, gval *value)
{
    layer_id cand[ARRAY_LEN(all_layers)];
    const char *fields[64];
    size_t nc = 0, nf;
    for (size_t i = 0; i < ARRAY_LEN(all_layers); i++)
        if (layer_is_allowed(all_layers[i]) && layer_allowed_fields(all_layers[i], fields, 64))
            cand[nc++] = all_layers[i];
    if (!nc)
        return -1;
    *layer = cand[rng_index(nc)];
    nf = layer_allowed_fields(*layer, fields, 64);
    *field = fields[rng_index(nf)];
    return field_gen(*layer, *field, value);
}

/* Packet.get_random() on a random captured packet. */
static int real(const gen_ctx *g, layer_id *layer, const char **field, gval *value)
{
    const gpkt *p = g->env[rng_index(g->nenv)];
    layer_id cand[ARRAY_LEN(all_layers)];
    const char *fields[64];
    size_t nc = 0, nf;
    for (size_t i = 0; i < ARRAY_LEN(all_layers); i++)
        if (pkt_has_layer(p, all_layers[i]) && layer_allowed_fields(all_layers[i], fields, 64))
            cand[nc++] = all_layers[i];
    if (!nc)
        return -1;
    *layer = cand[rng_index(nc)];
    nf = layer_allowed_fields(*layer, fields, 64);
    *field = fields[rng_index(nf)];
    return pkt_get(p, *layer, *field, value);
}

/* Whether the strategy language can carry the value: no separators
 * (IPv6 addresses have ':'), no spaces, no trailing '*' (a wildcard). */
static int expressible(const gval *v)
{
    size_t n;
    if (!v->is_str)
        return 1;
    n = strlen(v->s);
    return !strpbrk(v->s, ":,()[]{}|\\ \t\r\n") && !(n && v->s[n - 1] == '*');
}

/* actions.utils.get_from_fuzzed_or_real_packet(), skipping values that
 * cannot be written in a strategy. */
static int pick_value(const gen_ctx *g, double real_pb, layer_id *layer, const char **field, gval *value)
{
    for (int tries = 0; tries < 32; tries++) {
        int rc;
        if (g->nenv && rng_real() < real_pb && real(g, layer, field, value) == 0)
            rc = 0;
        else
            rc = fuzzed(layer, field, value);
        if (rc < 0)
            return -1;
        if (expressible(value))
            return 0;
        gval_free(value);
    }
    return -1;
}

/* ---- triggers ------------------------------------------------------------ */

static void trigger_copy(trigger *dst, const trigger *src)
{
    *dst = *src;
    dst->proto_str = xstrdup(src->proto_str);
    dst->field = xstrdup(src->field);
    gval_copy(&dst->value, &src->value);
    dst->gas = dst->gas_init;
    dst->seen = 0;
}

/* Trigger.get_rand_trigger(). Returns -1 if no field is available. */
static int trigger_random(const gen_ctx *g, trigger *t, double real_pb)
{
    layer_id layer;
    const char *field;
    gval v;
    if (g->fixed) {
        trigger_copy(t, g->fixed);
        return 0;
    }
    if (pick_value(g, real_pb, &layer, &field, &v) < 0)
        return -1;
    memset(t, 0, sizeof(*t));
    t->layer = layer;
    t->proto_str = xstrdup(layer_name(layer));
    t->field = xstrdup(field);
    t->value = v;
    /* Trigger.get_gas(): gas in 20% of triggers, 0-4 */
    if (!g->no_gas && rng_real() < 0.2) {
        t->has_gas = 1;
        t->gas_init = t->gas = (int64_t)(rng_real() * 5);
    }
    return 0;
}

/* ---- actions ------------------------------------------------------------- */

/* TamperAction._mutate(): a new protocol, field and value. */
static int tamper_retarget(const gen_ctx *g, action *a)
{
    layer_id layer;
    const char *field;
    gval v;
    if (pick_value(g, 0.5, &layer, &field, &v) < 0)
        return -1;
    free(a->proto_str);
    free(a->field);
    gval_free(&a->value);
    a->layer = layer;
    a->proto_str = xstrdup(layer_name(layer));
    a->field = xstrdup(field);
    a->value = v;
    a->has_value = 1;
    return 0;
}

/* TamperAction._mutate_tamper_type() over the activated primitives. */
static void tamper_retype(action *a)
{
    a->ttype = rng_chance(0.5) ? TAMPER_REPLACE : TAMPER_CORRUPT;
    if (a->ttype == TAMPER_REPLACE && !a->has_value) {
        /* a parsed corrupt has no value: Geneva would write "None" */
        gval_free(&a->value);
        if (field_gen(a->layer, a->field, &a->value) == 0 && expressible(&a->value))
            a->has_value = 1;
        else
            a->ttype = TAMPER_CORRUPT;
    }
}

/* FragmentAction.mutate(). */
static void fragment_mutate(action *a)
{
    a->in_order = rng_chance(0.5);
    a->segment = rng_index(4) != 0;
    if (a->segment)
        a->fragsize = rng_chance(0.5) ? (int)rng_uniform(1, 60) : -1;
    else
        a->fragsize = rng_real() < 0.2 ? (int)rng_uniform(1, 50) : -1;
    if (rng_chance(0.5)) {
        if (rng_chance(0.5))
            a->overlap = a->fragsize == -1 ? 5 : a->fragsize / 2;
        else
            a->overlap = (int)rng_uniform(1, 50);
    }
}

static void action_mutate(const gen_ctx *g, action *a)
{
    switch (a->type) {
    case ACT_TAMPER:
        if (rng_real() < 0.2)
            tamper_retype(a);
        else
            tamper_retarget(g, a);
        break;
    case ACT_FRAGMENT:
        fragment_mutate(a);
        break;
    default: /* duplicate, drop, sleep and trace have nothing to change */
        break;
    }
}

/* ActionTree.get_rand_action(): weighted by Action.frequency (sleep and
 * trace have 0 and only come from parsed strategies). */
static action *action_random(const gen_ctx *g, strat_dir dir)
{
    static const struct {
        act_type t;
        int freq;
        int in;
    } kinds[] = {
        {ACT_TAMPER, 5, 1},
        {ACT_DUPLICATE, 3, 0},
        {ACT_FRAGMENT, 2, 0},
        {ACT_DROP, 1, 1},
    };
    int total = 0, pick;
    action *a;
    for (size_t i = 0; i < ARRAY_LEN(kinds); i++)
        if (!g->disabled[kinds[i].t] && (dir == DIR_OUT || kinds[i].in))
            total += kinds[i].freq;
    if (!total)
        return NULL;
    pick = (int)rng_index((size_t)total);
    a = xcalloc(1, sizeof(*a));
    a->layer = LAYER_NONE;
    a->fragsize = -1;
    a->segment = 1;
    a->time = 1;
    a->start_ttl = 1;
    a->end_ttl = 64;
    for (size_t i = 0; i < ARRAY_LEN(kinds); i++) {
        if (g->disabled[kinds[i].t] || (dir == DIR_IN && !kinds[i].in))
            continue;
        if (pick < kinds[i].freq) {
            a->type = kinds[i].t;
            break;
        }
        pick -= kinds[i].freq;
    }
    if (a->type == ACT_TAMPER) {
        a->ttype = rng_chance(0.5) ? TAMPER_REPLACE : TAMPER_CORRUPT;
        if (tamper_retarget(g, a) < 0) {
            action_free(a);
            return NULL;
        }
    } else if (a->type == ACT_FRAGMENT) {
        a->in_order = rng_chance(0.5);
    }
    return a;
}

/* ---- trees --------------------------------------------------------------- */

static size_t free_slots(action *root)
{
    slots s = {.n = 0};
    size_t n = 0;
    collect(&root, &s);
    for (size_t i = 0; i < s.n; i++) {
        action *a = *s.v[i];
        if (is_terminal(a->type))
            continue;
        n += !a->left;
        n += !a->right && is_branching(a->type);
    }
    return n;
}

/* ActionTree.add_action(): the root, or a random free slot. */
static int tree_add(atree *t, action *a)
{
    size_t n;
    if (!a)
        return 0;
    if (!t->root) {
        t->root = a;
        return 1;
    }
    n = free_slots(t->root);
    if (!n || count_actions(t->root) >= 64) {
        action_free(a);
        return 0;
    }
    for (;;) {
        slots s = {.n = 0};
        collect(&t->root, &s);
        for (size_t i = 0; i < s.n; i++) {
            action *p = *s.v[i];
            if (!p->left && !is_terminal(p->type) && rng_real() < 1.0 / (double)n) {
                p->left = a;
                return 1;
            }
            if (!p->right && !is_terminal(p->type) && is_branching(p->type) &&
                rng_real() < 1.0 / (double)n) {
                p->right = a;
                return 1;
            }
        }
    }
}

/* ActionTree.remove_action() on a random node: the node gives way to its
 * left child (or, at the root, to whichever child it has). */
static void tree_remove_one(atree *t)
{
    slots s = {.n = 0};
    action **slot, *a, *keep;
    collect(&t->root, &s);
    if (!s.n)
        return;
    slot = s.v[rng_index(s.n)];
    a = *slot;
    if (slot == &t->root)
        keep = a->left ? a->left : a->right;
    else
        keep = a->left;
    if (keep == a->left)
        a->left = NULL;
    else
        a->right = NULL;
    *slot = keep;
    action_free(a);
}

static atree *tree_random(const gen_ctx *g, strat_dir dir, int nactions)
{
    atree *t = xcalloc(1, sizeof(*t));
    t->dir = dir;
    if (trigger_random(g, &t->trig, 1.0) < 0) {
        free(t);
        return NULL;
    }
    for (int i = 0; i < nactions; i++)
        tree_add(t, action_random(g, dir));
    return t;
}

/* ActionTree.mutate(). */
static void tree_mutate(const gen_ctx *g, atree *t)
{
    double pick = rng_real();
    if (pick < 0.20 || !t->root) {
        tree_add(t, action_random(g, t->dir));
    } else if (pick < 0.65) {
        slots s = {.n = 0};
        collect(&t->root, &s);
        action_mutate(g, *s.v[rng_index(s.n)]);
    } else if (pick < 0.80 && g->nenv) {
        trigger tr;
        if (trigger_random(g, &tr, 0.5) == 0) {
            trigger_clear(&t->trig);
            t->trig = tr;
        }
    } else {
        tree_remove_one(t);
    }
}

/* ActionTree.mate(): swaps a random subtree of each (an empty tree offers
 * its root slot). */
static int tree_mate(atree *a, atree *b)
{
    slots sa = {.n = 0}, sb = {.n = 0};
    action **x, **y, *tmp;
    if (!a->root && !b->root)
        return 0;
    collect(&a->root, &sa);
    collect(&b->root, &sb);
    x = sa.n ? sa.v[rng_index(sa.n)] : &a->root;
    y = sb.n ? sb.v[rng_index(sb.n)] : &b->root;
    tmp = *x;
    *x = *y;
    *y = tmp;
    return 1;
}

/* ---- forests and strategies ---------------------------------------------- */

typedef struct {
    atree ***v;
    size_t *n;
} forest;

static void forest_insert(forest f, size_t idx, atree *t)
{
    *f.v = xrealloc(*f.v, (*f.n + 1) * sizeof(**f.v));
    memmove(*f.v + idx + 1, *f.v + idx, (*f.n - idx) * sizeof(**f.v));
    (*f.v)[idx] = t;
    (*f.n)++;
}

static atree *forest_take(forest f, size_t idx)
{
    atree *t = (*f.v)[idx];
    memmove(*f.v + idx, *f.v + idx + 1, (*f.n - idx - 1) * sizeof(**f.v));
    (*f.n)--;
    return t;
}

/* Strategy.mutate_dir(). */
static void forest_mutate(const gen_ctx *g, forest f, strat_dir dir)
{
    double pick = rng_real();
    if (pick < 0.1 || !*f.n) {
        atree *t = tree_random(g, dir, 1);
        if (t)
            forest_insert(f, *f.n, t);
    } else if (pick < 0.2) {
        tree_free(forest_take(f, rng_index(*f.n)));
    } else if (pick < 0.25 && *f.n > 1) {
        rng_shuffle_ptrs((void **)*f.v, *f.n);
    } else {
        for (size_t i = 0; i < *f.n; i++)
            tree_mutate(g, (*f.v)[i]);
    }
}

void strategy_mutate(const gen_ctx *g, strategy *s, int in_enabled, int out_enabled)
{
    if (in_enabled)
        forest_mutate(g, (forest){&s->in, &s->nin}, DIR_IN);
    if (out_enabled)
        forest_mutate(g, (forest){&s->out, &s->nout}, DIR_OUT);
}

/* swap_one(): moves a random tree of each forest to a random place in the
 * other. */
static int swap_one(forest a, forest b)
{
    atree *da = NULL, *db = NULL;
    size_t ia = 0, ib = 0;
    if (*a.n) {
        da = forest_take(a, rng_index(*a.n));
        if (*a.n)
            ia = rng_index(*a.n);
    }
    if (*b.n) {
        db = forest_take(b, rng_index(*b.n));
        if (*b.n)
            ib = rng_index(*b.n);
    }
    if (db)
        forest_insert(a, ia, db);
    if (da)
        forest_insert(b, ib, da);
    return 1;
}

/* do_mate(). */
static int forest_mate(forest a, forest b)
{
    if ((rng_real() < 0.8 && *a.n && *b.n) || (*a.n == 1 && *b.n == 1))
        return tree_mate((*a.v)[rng_index(*a.n)], (*b.v)[rng_index(*b.n)]);
    if (*a.n || *b.n)
        return swap_one(a, b);
    return 0;
}

int strategy_mate(strategy *a, strategy *b, double indpb, int in_enabled, int out_enabled)
{
    int any = 0;
    if (out_enabled && rng_real() < indpb)
        any |= forest_mate((forest){&a->out, &a->nout}, (forest){&b->out, &b->nout});
    if (in_enabled && rng_real() < indpb)
        any |= forest_mate((forest){&a->in, &a->nin}, (forest){&b->in, &b->nin});
    return any;
}

strategy *strategy_random(const gen_ctx *g, int in_trees, int out_trees, int in_actions, int out_actions)
{
    strategy *s = xcalloc(1, sizeof(*s));
    for (int i = 0; i < in_trees; i++) {
        atree *t = tree_random(g, DIR_IN, in_actions);
        if (t)
            forest_insert((forest){&s->in, &s->nin}, s->nin, t);
    }
    for (int i = 0; i < out_trees; i++) {
        atree *t = tree_random(g, DIR_OUT, out_actions);
        if (t)
            forest_insert((forest){&s->out, &s->nout}, s->nout, t);
    }
    return s;
}
