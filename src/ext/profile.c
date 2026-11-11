/*
 * Profiles (profile.h): the options with zapret2's names, the profile file
 * and the search (nfq2/desync.c dp_match, nfq2/filter.c, nfq2/nfqws.c).
 */
#include "profile.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "autolist.h"
#include "l7.h"
#include "util.h"

/* ---- filters (nfq2/filter.c) ----------------------------------------------- */

/* "%u" of sscanf without its leniency: digits only, at most max */
static int num(const char *s, size_t n, unsigned max, unsigned *out)
{
    unsigned v = 0;
    if (!n || n > 10)
        return -1;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return -1;
        v = v * 10 + (unsigned)(s[i] - '0');
        if (v > max)
            return -1;
    }
    *out = v;
    return 0;
}

/* pf_parse */
static int pf_parse(const char *s, size_t n, xpf *pf)
{
    const char *dash;
    unsigned a, b;
    memset(pf, 0, sizeof(*pf));
    if (n == 1 && *s == '*') {
        pf->from = 1;
        pf->to = 0xffff;
        return 0;
    }
    if (n && *s == '~') {
        pf->neg = 1;
        s++, n--;
    }
    dash = memchr(s, '-', n);
    if (dash) {
        if (num(s, (size_t)(dash - s), 65535, &a) < 0 || num(dash + 1, n - (size_t)(dash - s) - 1, 65535, &b) < 0 ||
            a > b)
            return -1;
    } else {
        if (num(s, n, 65535, &a) < 0)
            return -1;
        b = a;
    }
    pf->from = (uint16_t)a;
    pf->to = (uint16_t)b;
    if (!a && !b)
        pf->neg = 1; /* "0": no port at all */
    return 0;
}

static int pf_match(uint16_t port, const xpf *pf)
{
    return port && (((!pf->from && !pf->to) || (port >= pf->from && port <= pf->to)) ^ pf->neg);
}

/* fltmode_parse: "*" any, "-" none; 1 when s was one of them */
static int fltmode(const char *s, size_t n, uint8_t *mode)
{
    if (n == 1 && (*s == '*' || *s == '-')) {
        *mode = *s == '*' ? XF_ANY : XF_SKIP;
        return 1;
    }
    return 0;
}

static int icf_parse(const char *s, size_t n, xicf *f)
{
    const char *colon;
    unsigned t, c;
    memset(f, 0, sizeof(*f));
    if (fltmode(s, n, &f->mode))
        return 0;
    colon = memchr(s, ':', n);
    if (colon) {
        if (num(s, (size_t)(colon - s), 255, &t) < 0 || num(colon + 1, n - (size_t)(colon - s) - 1, 255, &c) < 0)
            return -1;
        f->code = (uint8_t)c;
        f->code_valid = 1;
    } else if (num(s, n, 255, &t) < 0) {
        return -1;
    }
    f->type = (uint8_t)t;
    f->mode = XF_FILTER;
    return 0;
}

static int icf_match(uint8_t type, uint8_t code, const xicf *f)
{
    return f->mode == XF_ANY || (f->mode == XF_FILTER && f->type == type && (!f->code_valid || f->code == code));
}

static int ipp_parse(const char *s, size_t n, xipp *f)
{
    unsigned v;
    memset(f, 0, sizeof(*f));
    f->proto = 0xff;
    if (fltmode(s, n, &f->mode))
        return 0;
    if (num(s, n, 255, &v) < 0)
        return -1;
    f->proto = (uint8_t)v;
    f->mode = XF_FILTER;
    return 0;
}

static int ipp_match(uint8_t proto, const xipp *f)
{
    return f->mode == XF_ANY || (f->mode == XF_FILTER && f->proto == proto);
}

/* a comma list into a growing array: every item is added (zapret2 adds
 * to the profile's list, option after option) */
#define LIST_PARSE(fn, type, parse)                                          \
    int fn(const char *s, type **v, size_t *n)                               \
    {                                                                        \
        for (;;) {                                                           \
            const char *e = strchr(s, ',');                                  \
            size_t l = e ? (size_t)(e - s) : strlen(s);                      \
            type it;                                                         \
            if (parse(s, l, &it) < 0)                                        \
                return -1;                                                   \
            *v = xrealloc(*v, sizeof(**v) * (*n + 1));                       \
            (*v)[(*n)++] = it;                                               \
            if (!e)                                                          \
                return 0;                                                    \
            s = e + 1;                                                       \
        }                                                                    \
    }

LIST_PARSE(xprof_pf_list, xpf, pf_parse)
LIST_PARSE(xprof_icf_list, xicf, icf_parse)
LIST_PARSE(xprof_ipp_list, xipp, ipp_parse)

/* "0x%X" or "%u" (sscanf as in nfqws.c, without trailing junk) */
static int mark_num(const char *s, uint32_t *v)
{
    uint64_t u;
    if (!*s || parse_u64(s, &u) < 0 || u > 0xffffffffULL)
        return -1;
    if (s[0] == '0' && s[1] && s[1] != 'x' && s[1] != 'X') {
        /* parse_u64 may read a leading 0 as octal; zapret2 reads decimal */
        unsigned d;
        if (num(s, strlen(s), 0xffffffffU, &d) < 0)
            return -1;
        u = d;
    }
    *v = (uint32_t)u;
    return 0;
}

int xprof_mark(const char *s, uint32_t *mark, uint32_t *mask)
{
    const char *sl = strchr(s, '/');
    char b[32];
    size_t l = sl ? (size_t)(sl - s) : strlen(s);
    if (l >= sizeof(b))
        return -1;
    memcpy(b, s, l);
    b[l] = 0;
    if (mark_num(b, mark) < 0)
        return -1;
    if (!sl) {
        *mask = 0xffffffffU; /* no mask: the whole value */
        return 0;
    }
    return mark_num(sl + 1, mask);
}

/* ---- profiles ------------------------------------------------------------- */

static xprofile *prof_new(void)
{
    xprofile *p = xcalloc(1, sizeof(*p));
    p->ah_fail_threshold = XAH_FAIL_THRESHOLD;
    p->ah_fail_time = XAH_FAIL_TIME;
    p->ah_retrans_threshold = XAH_RETRANS_THRESHOLD;
    p->ah_retrans_maxseq = XAH_RETRANS_MAXSEQ;
    p->ah_retrans_reset = 1;
    p->ah_incoming_maxseq = XAH_INCOMING_MAXSEQ;
    p->ah_udp_out = XAH_UDP_OUT;
    p->ah_udp_in = XAH_UDP_IN;
    return p;
}

static void prof_free(xprofile *p)
{
    if (!p)
        return;
    free(p->name);
    free(p->tcp);
    free(p->udp);
    free(p->icf);
    free(p->ipp);
    free(p->text);
    free(p->src);
    strategy_free(p->st);
    xlistref_free(&p->hl);
    xlistref_free(&p->hl_ex);
    xlistref_free(&p->ips);
    xlistref_free(&p->ips_ex);
    xah_free(p);
    free(p);
}

static void push(xprofiles *ps, xprofile *p)
{
    ps->v = xrealloc(ps->v, sizeof(*ps->v) * (ps->n + 1));
    ps->v[ps->n++] = p;
}

void xprof_free(xprofiles *ps)
{
    for (size_t i = 0; i < ps->n; i++)
        prof_free(ps->v[i]);
    free(ps->v);
    ps->v = NULL;
    ps->n = 0;
}

static const xprofile *find_name(const xprofiles *ps, const char *name)
{
    for (size_t i = 0; ps && i < ps->n; i++)
        if (ps->v[i]->name && !strcmp(ps->v[i]->name, name))
            return ps->v[i];
    return NULL;
}

#define APPEND(to, nto, from, nfrom)                                             \
    do {                                                                         \
        if (nfrom) {                                                             \
            to = xrealloc(to, sizeof(*(to)) * ((nto) + (nfrom)));                \
            memcpy((to) + (nto), from, sizeof(*(to)) * (nfrom));                 \
            nto += nfrom;                                                        \
        }                                                                        \
    } while (0)

/* dp_copy: L3 is added, L7 replaced, the lists appended (not the mark); the strategy is
 * taken when the profile has none of its own (zapret2 appends the
 * template's functions: a Geneva strategy is one whole) */
static int prof_import(xprofile *to, const xprofile *from, sbuf *err)
{
#define AH_COPY(bit, f)              \
    if (from->ah_set & (bit)) {      \
        to->f = from->f;             \
        to->ah_set |= (bit);         \
    }
    AH_COPY(1, ah_fail_threshold)
    AH_COPY(2, ah_fail_time)
    AH_COPY(4, ah_retrans_threshold)
    AH_COPY(8, ah_retrans_maxseq)
    AH_COPY(16, ah_incoming_maxseq)
    AH_COPY(32, ah_retrans_reset)
    AH_COPY(64, ah_udp_out)
    AH_COPY(128, ah_udp_in)
#undef AH_COPY
    if (from->ahl && from->ahl != to->ahl) {
        if (to->ahl) {
            sb_puts(err, "autohostlist replacement is not supported (one --hostlist-auto per profile)");
            return -1;
        }
        to->ahl = from->ahl;
    }
    if (from->b_l3) {
        to->ipv4 |= from->ipv4;
        to->ipv6 |= from->ipv6;
        to->b_l3 = 1;
    }
    if (from->b_l7) {
        to->l7 = from->l7;
        to->b_l7 = 1;
    }
    APPEND(to->tcp, to->ntcp, from->tcp, from->ntcp);
    APPEND(to->udp, to->nudp, from->udp, from->nudp);
    APPEND(to->icf, to->nicf, from->icf, from->nicf);
    APPEND(to->ipp, to->nipp, from->ipp, from->nipp);
    xlistref_copy(&to->hl, &from->hl);
    xlistref_copy(&to->hl_ex, &from->hl_ex);
    xlistref_copy(&to->ips, &from->ips);
    xlistref_copy(&to->ips_ex, &from->ips_ex);
    if (from->text && !to->text && !to->cmd) {
        to->text = xstrdup(from->text);
        to->src = xstrdup(from->src);
        to->tpl_text = 1;
    }
    return 0;
}

/* --hostlist, --ipset and their -exclude, -domains, -ip forms */
static const struct {
    const char *name;
    int ip, ex, fixed;
} list_opts[] = {
    {"hostlist", 0, 0, 0},       {"hostlist-domains", 0, 0, 1}, {"hostlist-exclude", 0, 1, 0},
    {"hostlist-exclude-domains", 0, 1, 1}, {"ipset", 1, 0, 0},   {"ipset-ip", 1, 0, 1},
    {"ipset-exclude", 1, 1, 0},  {"ipset-exclude-ip", 1, 1, 1},
};

static int list_opt(xprofile *p, int k, const char *value, sbuf *err)
{
    int ip = list_opts[k].ip, ex = list_opts[k].ex;
    xlistref *r = ip ? (ex ? &p->ips_ex : &p->ips) : (ex ? &p->hl_ex : &p->hl);
    if (!list_opts[k].fixed) {
        xlist *l = xlist_file(value, ip, err);
        if (!l)
            return -1;
        if (xlistref_add(r, l) < 0) {
            sb_printf(err, "--%s %s is already in this profile", list_opts[k].name, value);
            return -1;
        }
        return 0;
    }
    {
        xlist **fx = &p->fixed[ip * 2 + ex];
        const char *s = value;
        if (!*fx) {
            *fx = xlist_fixed(ip);
            xlistref_add(r, *fx);
        }
        for (;;) { /* parse_domain_list, parse_ip_list: empty items skipped */
            const char *e = strchr(s, ',');
            size_t l = e ? (size_t)(e - s) : strlen(s);
            if (l) {
                char *it = xstrndup(s, l);
                if (ip) {
                    if (xips_add_str(&(*fx)->ips, it) < 0) {
                        sb_printf(err, "bad --%s item %s (an IPv4 or IPv6 address or subnet)", list_opts[k].name, it);
                        free(it);
                        return -1;
                    }
                } else {
                    xhs_parse(&(*fx)->hs, it, l);
                }
                free(it);
            }
            if (!e)
                break;
            s = e + 1;
        }
        if (ip)
            xips_finish(&(*fx)->ips);
    }
    return 0;
}

/* --hostlist-auto and its parameters */
static const struct {
    const char *name;
    int min, max;
    unsigned bit;
} ah_opts[] = {
    {"hostlist-auto-fail-threshold", 1, 20, 1}, {"hostlist-auto-fail-time", 1, 1 << 30, 2},
    {"hostlist-auto-retrans-threshold", 2, 10, 4}, {"hostlist-auto-retrans-maxseq", 0, 1 << 30, 8},
    {"hostlist-auto-incoming-maxseq", 0, 1 << 30, 16}, {"hostlist-auto-retrans-reset", 0, 1, 32},
    {"hostlist-auto-udp-out", 0, 1 << 30, 64}, {"hostlist-auto-udp-in", 0, 1 << 30, 128},
};

static int ah_opt(xprofile *p, const char *name, const char *value, sbuf *err)
{
    unsigned v;
    size_t k;
    if (!strcmp(name, "hostlist-auto")) {
        xlist *l;
        if (p->ahl) {
            sb_puts(err, "only one --hostlist-auto per profile");
            return -1;
        }
        if (!(l = xlist_auto(value, err)))
            return -1;
        if (xlistref_add(&p->hl, l) < 0) {
            sb_printf(err, "--hostlist-auto %s is already a --hostlist of this profile", value);
            return -1;
        }
        p->ahl = l;
        return 1;
    }
    for (k = 0; k < ARRAY_LEN(ah_opts) && strcmp(name, ah_opts[k].name); k++)
        ;
    if (k == ARRAY_LEN(ah_opts))
        return 0;
    if (ah_opts[k].bit == 32 && !*value)
        value = "1"; /* --hostlist-auto-retrans-reset alone */
    if (num(value, strlen(value), (unsigned)ah_opts[k].max, &v) < 0 || v < (unsigned)ah_opts[k].min) {
        sb_printf(err, "bad --%s %s (%d..%d)", name, value, ah_opts[k].min, ah_opts[k].max);
        return -1;
    }
    switch (ah_opts[k].bit) {
    case 1: p->ah_fail_threshold = (int)v; break;
    case 2: p->ah_fail_time = (int)v; break;
    case 4: p->ah_retrans_threshold = (int)v; break;
    case 8: p->ah_retrans_maxseq = v; break;
    case 16: p->ah_incoming_maxseq = v; break;
    case 32: p->ah_retrans_reset = (int)v; break;
    case 64: p->ah_udp_out = (int)v; break;
    default: p->ah_udp_in = (int)v; break;
    }
    p->ah_set |= ah_opts[k].bit;
    return 1;
}

int xprof_opt(xprofile *p, const char *name, const char *value, const xprofiles *templates, sbuf *err)
{
    int r = 0;
    if (str_starts(name, "hostlist-auto") && strcmp(name, "hostlist-auto-debug"))
        return ah_opt(p, name, value, err);
    for (size_t k = 0; k < ARRAY_LEN(list_opts); k++)
        if (!strcmp(name, list_opts[k].name))
            return list_opt(p, (int)k, value, err) < 0 ? -1 : 1;
    if (!strcmp(name, "filter-l3")) {
        const char *s = value;
        for (;;) {
            const char *e = strchr(s, ',');
            size_t l = e ? (size_t)(e - s) : strlen(s);
            if (l == 4 && !strncmp(s, "ipv4", 4))
                p->ipv4 = 1;
            else if (l == 4 && !strncmp(s, "ipv6", 4))
                p->ipv6 = 1;
            else {
                sb_printf(err, "bad --filter-l3 %s (ipv4, ipv6 or ipv4,ipv6)", value);
                return -1;
            }
            if (!e)
                break;
            s = e + 1;
        }
        p->b_l3 = 1;
    } else if (!strcmp(name, "filter-tcp") || !strcmp(name, "filter-udp")) {
        int tcp = name[7] == 't';
        if (xprof_pf_list(value, tcp ? &p->tcp : &p->udp, tcp ? &p->ntcp : &p->nudp) < 0) {
            sb_printf(err, "bad --%s %s ([~]PORT[-PORT],... or *)", name, value);
            return -1;
        }
    } else if (!strcmp(name, "filter-icmp")) {
        if (xprof_icf_list(value, &p->icf, &p->nicf) < 0) {
            sb_printf(err, "bad --filter-icmp %s (TYPE[:CODE],... or *)", value);
            return -1;
        }
    } else if (!strcmp(name, "filter-ipp")) {
        if (xprof_ipp_list(value, &p->ipp, &p->nipp) < 0) {
            sb_printf(err, "bad --filter-ipp %s (PROTO,... or *)", value);
            return -1;
        }
    } else if (!strcmp(name, "filter-l7")) {
        sbuf e2;
        int neg = 0;
        uint64_t set = 0;
        sb_init(&e2);
        r = l7_proto_list(value, &set, &neg, &e2);
        if (!r && neg)
            r = -1, sb_puts(&e2, "\"~\" is not for --filter-l7");
        if (r < 0)
            sb_printf(err, "bad --filter-l7: %s", e2.data);
        sb_free(&e2);
        if (r < 0)
            return -1;
        if (set & 1ULL << L7_ALL)
            set = 0; /* "all": every protocol */
        p->l7 = set; /* zapret2 replaces the set */
        p->b_l7 = 1;
    } else if (!strcmp(name, "filter-mark")) {
        if (xprof_mark(value, &p->mark, &p->mark_mask) < 0) {
            sb_printf(err, "bad --filter-mark %s (MARK[/MASK], decimal or 0x hex)", value);
            return -1;
        }
    } else if (!strcmp(name, "name")) {
        if (!*value) {
            sb_puts(err, "--name needs a name");
            return -1;
        }
        free(p->name);
        p->name = xstrdup(value);
    } else if (!strcmp(name, "import")) {
        const xprofile *t = find_name(templates, value);
        if (!t) {
            sb_printf(err, "template \"%s\" not found (a --template comes before its --import)", value);
            return -1;
        }
        if (prof_import(p, t, err) < 0)
            return -1;
    } else {
        return 0;
    }
    return 1;
}

/* the strategy of a profile from -s TEXT or -f FILE */
static int prof_strategy(xprofile *p, int file, const char *value, sbuf *err)
{
    char *text;
    if (p->text && !p->tpl_text) {
        sb_puts(err, "two strategies in one profile (-s or -f once per profile)");
        return -1;
    }
    if (file) {
        size_t len;
        text = read_file(value, &len);
        if (!text) {
            sb_printf(err, "cannot read %s", value);
            return -1;
        }
    } else {
        text = xstrdup(value);
    }
    free(p->text);
    free(p->src);
    p->text = text;
    p->src = xstrdup(file ? value : "-s");
    p->tpl_text = 0;
    return 0;
}

static int has_filters(const xprofile *p)
{
    return p->b_l3 || p->b_l7 || p->ntcp || p->nudp || p->nicf || p->nipp || p->mark_mask || p->name || p->text ||
           p->hl.n || p->hl_ex.n || p->ips.n || p->ips_ex.n;
}

/* what is being built: the profiles, the templates, the one in hand */
typedef struct {
    xprofiles *out, tpl;
    xprofile *cur;
    int skip, tmpl;
    sbuf *err;
} builder;

/* the profile in hand goes where it belongs (the end of a segment) */
static int finish(builder *b)
{
    xprofile *p = b->cur;
    b->cur = NULL;
    if (!p)
        return 0;
    if (b->skip) {
        prof_free(p);
    } else if (b->tmpl) {
        if (p->name && find_name(&b->tpl, p->name)) {
            sb_printf(b->err, "template \"%s\" already present", p->name);
            prof_free(p);
            return -1;
        }
        push(&b->tpl, p);
    } else {
        if (b->out->n + b->tpl.n >= XPROF_MAX) {
            sb_printf(b->err, "more than %d profiles", XPROF_MAX);
            prof_free(p);
            return -1;
        }
        push(b->out, p);
    }
    b->skip = b->tmpl = 0;
    return 0;
}

static void start(builder *b, const char *name)
{
    b->cur = prof_new();
    if (name && *name)
        b->cur->name = xstrdup(name);
}

/* one option or file key of a profile; 0 when it is not a profile's */
static int option(builder *b, const char *name, const char *value)
{
    int r;
    if (!strcmp(name, "skip")) {
        b->skip = 1;
        return 1;
    }
    if (!strcmp(name, "template")) {
        b->tmpl = 1;
        if (value && *value) {
            free(b->cur->name);
            b->cur->name = xstrdup(value);
        }
        return 1;
    }
    if (!strcmp(name, "strategy") || !strcmp(name, "strategy-file"))
        return prof_strategy(b->cur, name[8] == '-', value, b->err) < 0 ? -1 : 1;
    if (b->skip && (str_starts(name, "hostlist") || str_starts(name, "ipset")))
        return 1; /* zapret2 does not load the lists of a skipped profile */
    r = xprof_opt(b->cur, name, value ? value : "", &b->tpl, b->err);
    return r;
}

static const char *const prof_opts[] = {"new",       "skip",       "name",        "template",   "import",
                                         "filter-l3", "filter-tcp", "filter-udp",  "filter-icmp", "filter-ipp",
                                         "filter-l7", "filter-mark", "ext-profile", "hostlist",  "hostlist-domains",
                                         "hostlist-exclude", "hostlist-exclude-domains", "ipset", "ipset-ip",
                                         "ipset-exclude", "ipset-exclude-ip"};

int xprof_wanted(const args_t *a)
{
    for (int i = 0; i < a->nopts; i++) {
        const char *n = a->opts[i].def->name;
        if (str_starts(n, "hostlist-auto") && strcmp(n, "hostlist-auto-debug"))
            return 1;
        for (size_t k = 0; k < ARRAY_LEN(prof_opts); k++)
            if (!strcmp(n, prof_opts[k]))
                return 1;
    }
    return 0;
}

/* ---- the profile file --------------------------------------------------------- */

static char *trim(char *s)
{
    char *e;
    while (*s == ' ' || *s == '\t')
        s++;
    e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r'))
        *--e = 0;
    return s;
}

/* "1", "yes", "true", "" (a bare key) or "0", "no", "false" */
static int flag(const char *v)
{
    if (!*v || !strcmp(v, "1") || !strcmp(v, "yes") || !strcmp(v, "true"))
        return 1;
    if (!strcmp(v, "0") || !strcmp(v, "no") || !strcmp(v, "false"))
        return 0;
    return -1;
}

static int load_file(builder *b, const char *path)
{
    size_t len;
    char *text = read_file(path, &len), *line, *next;
    int lineno = 0, rc = 0;
    if (!text) {
        sb_printf(b->err, "cannot read %s", path);
        return -1;
    }
    for (line = text; line && !rc; line = next) {
        char *s, *eq, *key, *val;
        next = strchr(line, '\n');
        if (next)
            *next++ = 0;
        lineno++;
        s = trim(line);
        if (!*s || *s == '#' || *s == ';')
            continue;
        if (*s == '[') {
            char *end = strchr(s, ']'), *kind, *name;
            if (!end || *trim(end + 1)) {
                sb_printf(b->err, "%s:%d: a section is [profile NAME] or [template NAME]", path, lineno);
                rc = -1;
                break;
            }
            *end = 0;
            kind = trim(s + 1);
            name = kind + strcspn(kind, " \t");
            if (*name)
                *name++ = 0;
            name = trim(name);
            if (strcmp(kind, "profile") && strcmp(kind, "template")) {
                sb_printf(b->err, "%s:%d: unknown section [%s] (profile or template)", path, lineno, kind);
                rc = -1;
                break;
            }
            if (finish(b) < 0) {
                rc = -1;
                break;
            }
            start(b, name);
            b->tmpl = kind[0] == 't';
            if (b->tmpl && !*name) {
                sb_printf(b->err, "%s:%d: a template needs a name", path, lineno);
                rc = -1;
            }
            continue;
        }
        if (!b->cur) {
            sb_printf(b->err, "%s:%d: \"%s\" outside of a [profile] section", path, lineno, s);
            rc = -1;
            break;
        }
        /* a comment after a value: " #" */
        for (char *h = s; (h = strchr(h, '#')); h++)
            if (h > s && (h[-1] == ' ' || h[-1] == '\t')) {
                *h = 0;
                break;
            }
        eq = strchr(s, '=');
        if (eq)
            *eq = 0;
        key = trim(s);
        val = eq ? trim(eq + 1) : "";
        if (!strcmp(key, "skip")) {
            int f = flag(val);
            if (f < 0) {
                sb_printf(b->err, "%s:%d: skip is 1 or 0", path, lineno);
                rc = -1;
            } else if (f) {
                b->skip = 1;
            }
            continue;
        }
        if (!strcmp(key, "new") || !strcmp(key, "template") || !strcmp(key, "ext-profile") || !strcmp(key, "name")) {
            sb_printf(b->err, "%s:%d: \"%s\" is not for the file (sections start profiles)", path, lineno, key);
            rc = -1;
            break;
        }
        if (!eq) {
            sb_printf(b->err, "%s:%d: need KEY = VALUE", path, lineno);
            rc = -1;
            break;
        }
        {
            size_t mark = b->err->len;
            int r = option(b, key, val);
            if (r == 0) {
                sb_printf(b->err, "%s:%d: unknown key \"%s\"", path, lineno, key);
                rc = -1;
            } else if (r < 0) {
                /* the message with its place in front */
                char *msg = xstrdup(b->err->data + mark);
                b->err->len = mark;
                b->err->data[mark] = 0;
                sb_printf(b->err, "%s:%d: %s", path, lineno, msg);
                free(msg);
                rc = -1;
            }
        }
    }
    free(text);
    return rc;
}

/* ---- building ------------------------------------------------------------------ */

/* filter_defaults */
static void defaults(xprofile *p)
{
    static const xpf deny_pf = {0, 0, 1};
    static const xicf deny_icf = {XF_SKIP, 0, 0, 0};
    static const xipp deny_ipp = {XF_SKIP, 0xff};
    if (!p->b_l3)
        p->ipv4 = p->ipv6 = 1;
    if (!p->ntcp && !p->nudp && !p->nicf && !p->nipp)
        return;
    if (!p->ntcp)
        APPEND(p->tcp, p->ntcp, &deny_pf, 1);
    if (!p->nudp)
        APPEND(p->udp, p->nudp, &deny_pf, 1);
    if (!p->nicf)
        APPEND(p->icf, p->nicf, &deny_icf, 1);
    if (!p->nipp)
        APPEND(p->ipp, p->nipp, &deny_ipp, 1);
}

/* The end of the options before the first --new: with the command's
 * strategy they are profile 1 running it; with neither that nor a filter
 * they are only the command's options, no profile (one that would take
 * every packet and do nothing) */
static int seg0(builder *b, int has_cmd_st)
{
    if (has_cmd_st && b->tmpl) {
        sb_puts(b->err, "profile 1 has the command's strategy and cannot be a template");
        return -1;
    }
    if (has_cmd_st) {
        b->cur->cmd = 1;
    } else if (!has_filters(b->cur) && !b->skip && !b->tmpl) {
        prof_free(b->cur);
        b->cur = NULL;
    }
    return 0;
}

int xprof_build(const args_t *a, int has_cmd_st, xprofiles *out, sbuf *err)
{
    builder b;
    int seg = 0, rc = 0;
    memset(&b, 0, sizeof(b));
    memset(out, 0, sizeof(*out));
    if (!xprof_wanted(a))
        return 0;
    b.out = out;
    b.err = err;
    start(&b, NULL);
    for (int i = 0; i < a->nopts && !rc; i++) {
        const char *n = a->opts[i].def->name, *v = a->opts[i].value;
        int r;
        if (!strcmp(n, "new")) {
            if ((!seg && seg0(&b, has_cmd_st) < 0) || finish(&b) < 0) {
                rc = -1;
                break;
            }
            seg++;
            start(&b, v);
            continue;
        }
        if (!seg && (!strcmp(n, "strategy") || !strcmp(n, "strategy-file")))
            continue; /* the command's */
        if (!strcmp(n, "ext-profile"))
            continue; /* after the command line */
        r = option(&b, n, v);
        if (r < 0) {
            char *msg = xstrdup(err->data);
            sb_reset(err);
            sb_printf(err, "profile %d: %s", seg + 1, msg);
            free(msg);
            rc = -1;
        }
    }
    if (!rc) {
        if ((!seg && seg0(&b, has_cmd_st) < 0) || finish(&b) < 0)
            rc = -1;
    }
    for (int i = 0; i < a->nopts && !rc; i++)
        if (!strcmp(a->opts[i].def->name, "ext-profile")) {
            if (load_file(&b, a->opts[i].value) < 0 || finish(&b) < 0)
                rc = -1;
        }
    prof_free(b.cur);
    b.cur = NULL;
    for (size_t i = 0; i < out->n && !rc; i++) {
        xprofile *p = out->v[i];
        p->n = (int)i + 1;
        defaults(p);
        if (p->text && !p->cmd) {
            sbuf e2;
            sb_init(&e2);
            p->st = strategy_parse(p->text, &e2);
            if (!p->st) {
                sbuf l;
                sb_init(&l);
                xprof_label(p, &l);
                sb_printf(err, "profile %s: %s", l.data, e2.data);
                sb_free(&l);
                rc = -1;
            }
            sb_free(&e2);
        }
    }
    xprof_free(&b.tpl);
    if (!rc && !out->n) {
        sb_puts(err, "no profile left (every one is skipped or a template)");
        rc = -1;
    }
    if (rc < 0)
        xprof_free(out);
    return rc;
}

/* ---- the search -------------------------------------------------------------- */

#define LIST_MATCH(fn, type, call)                         \
    static int fn(const type *v, size_t n, MATCH_ARGS)     \
    {                                                      \
        if (!n)                                            \
            return 1;                                      \
        for (size_t i = 0; i < n; i++)                     \
            if (call)                                      \
                return 1;                                  \
        return 0;                                          \
    }

#define MATCH_ARGS uint16_t port
LIST_MATCH(pf_list, xpf, pf_match(port, &v[i]))
#undef MATCH_ARGS
#define MATCH_ARGS uint8_t type, uint8_t code
LIST_MATCH(icf_list, xicf, icf_match(type, code, &v[i]))
#undef MATCH_ARGS
#define MATCH_ARGS uint8_t proto
LIST_MATCH(ipp_list, xipp, ipp_match(proto, &v[i]))
#undef MATCH_ARGS

static int l4_match(const xprofile *p, const xmatch *m)
{
    switch (m->proto) {
    case 6: return pf_list(p->tcp, p->ntcp, m->port);
    case 17: return pf_list(p->udp, p->nudp, m->port);
    case 1:
    case 58: return icf_list(p->icf, p->nicf, m->icmp_type, m->icmp_code);
    default: return ipp_list(p->ipp, p->nipp, (uint8_t)m->proto);
    }
}

int xprof_hostlists_empty(const xprofile *p) { return xlistref_empty(&p->hl) && xlistref_empty(&p->hl_ex); }

int xprof_hosts(const xprofile *p, const char *host, int host_ip, int *excluded)
{
    return xlists_host(&p->hl, &p->hl_ex, host, host_ip, excluded);
}

/* dp_match */
int xprof_match(const xprofile *p, const xmatch *m, int any_l7)
{
    int hl_empty;
    if ((m->mark & p->mark_mask) != p->mark)
        return 0;
    if ((m->ver == 4 && !p->ipv4) || (m->ver == 6 && !p->ipv6))
        return 0;
    if (!any_l7 && !l7_proto_match(m->l7, p->l7))
        return 0;
    if (!l4_match(p, m))
        return 0;
    if (!xlistref_ok(&p->hl) || !xlistref_ok(&p->hl_ex))
        return 0; /* a list that failed to load */
    hl_empty = xprof_hostlists_empty(p);
    if (!m->host && !hl_empty && !any_l7)
        return 0; /* host lists, and no host name yet */
    if (p->ips.n || p->ips_ex.n) {
        if (!xlistref_ok(&p->ips) || !xlistref_ok(&p->ips_ex) || !m->ip ||
            !xlists_ip(&p->ips, &p->ips_ex, m->ver, m->ip))
            return 0;
    }
    if (p->ahl && m->host)
        return 1; /* an autolist profile wins once the host is known */
    if (hl_empty || !m->host)
        return 1;
    return xprof_hosts(p, m->host, m->host_ip, NULL);
}

int xprof_find(const xprofiles *ps, const xmatch *m, int any_l7)
{
    for (size_t i = 0; i < ps->n; i++)
        if (xprof_match(ps->v[i], m, any_l7))
            return (int)i;
    return -1;
}

void xprof_label(const xprofile *p, sbuf *out)
{
    sb_printf(out, "%d", p->n);
    if (p->name)
        sb_printf(out, " (%s)", p->name);
}

/* ---- the capture ------------------------------------------------------------- */

static int add_range(portset *ps, uint16_t lo, uint16_t hi, sbuf *err)
{
    for (int i = 0; i < ps->n; i++)
        if (ps->lo[i] == lo && ps->hi[i] == hi)
            return 0;
    if (ps->n >= MAX_PORT_RANGES) {
        sb_printf(err, "the profiles name more than %d port ranges", MAX_PORT_RANGES);
        return -1;
    }
    ps->lo[ps->n] = lo;
    ps->hi[ps->n] = hi;
    ps->n++;
    return 0;
}

static int ports_of(const xpf *v, size_t n, portset *ps, int *any, sbuf *err)
{
    if (!n)
        return 1; /* no filter: every port */
    for (size_t i = 0; i < n; i++) {
        if (v[i].neg && !v[i].from && !v[i].to)
            continue; /* none */
        if (v[i].neg || (v[i].from <= 1 && v[i].to == 0xffff))
            return 1;
        if (add_range(ps, v[i].from, v[i].to, err) < 0)
            return -1;
        *any = 1;
    }
    return 0;
}

int xprof_capture(const xprofiles *ps, int ports, xcapture *c, sbuf *err)
{
    memset(c, 0, sizeof(*c));
    c->ports_ok = 1;
    for (size_t i = 0; i < ps->n; i++) {
        const xprofile *p = ps->v[i];
        int all = 0;
        for (int k = 0; k < 2 && !all; k++) {
            int r = ports_of(k ? p->udp : p->tcp, k ? p->nudp : p->ntcp, &c->ports, k ? &c->udp : &c->tcp, err);
            if (r < 0)
                return -1;
            all = r;
        }
        if (all && c->ports_ok && ports) {
            sbuf l;
            sb_init(&l);
            xprof_label(p, &l);
            sb_printf(err, "profile %s takes every port: give -p (and --proto)", l.data);
            sb_free(&l);
            return -1;
        }
        if (all)
            c->ports_ok = 0;
        for (size_t k = 0; k < p->nicf; k++)
            if (p->icf[k].mode != XF_SKIP)
                c->icmp = 1;
        for (size_t k = 0; k < p->nipp; k++) {
            int dup = 0;
            if (p->ipp[k].mode == XF_SKIP)
                continue;
            if (p->ipp[k].mode == XF_ANY) {
                sb_puts(err, "--filter-ipp=* cannot be captured: name the protocols (or --firewall none and own rules)");
                return -1;
            }
            for (int j = 0; j < c->nipp; j++)
                dup |= c->ipp[j] == p->ipp[k].proto;
            if (dup)
                continue;
            if (c->nipp >= XPROF_IPP_MAX) {
                sb_printf(err, "the profiles name more than %d IP protocols", XPROF_IPP_MAX);
                return -1;
            }
            c->ipp[c->nipp++] = p->ipp[k].proto;
        }
    }
    if (ports && !c->ports.n && !c->icmp && !c->nipp) {
        sb_puts(err, "the profiles name no port or protocol to capture: give -p");
        return -1;
    }
    return 0;
}
