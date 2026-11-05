#include "range.h"

#include <string.h>

static int is_mode(int c) { return c && strchr("ndbspxa", c) != NULL; }

/* one position; *s moves past it */
static int pos_parse(const char **s, char def_mode, xpos *p)
{
    const char *q = *s;
    uint64_t v = 0;
    if (is_mode(*q))
        p->mode = *q++;
    else if (def_mode && *q >= '0' && *q <= '9')
        p->mode = def_mode;
    else
        return -1;
    p->pos = 0;
    if (p->mode == 'x' || p->mode == 'a') {
        *s = q;
        return 0;
    }
    if (*q < '0' || *q > '9')
        return -1;
    while (*q >= '0' && *q <= '9') {
        v = v * 10 + (uint64_t)(*q++ - '0');
        if (v > UINT32_MAX)
            return -1;
    }
    p->pos = (uint32_t)v;
    *s = q;
    return 0;
}

int xrange_parse(const char *s, char def_mode, xrange *r, sbuf *err)
{
    const char *q = s;
    memset(r, 0, sizeof(*r));
    if (*q == '-' || *q == '<') {
        r->from.mode = 'a';
        r->upper_cutoff = *q == '<';
        q++;
    } else {
        if (pos_parse(&q, def_mode, &r->from) < 0)
            goto bad;
        if (r->from.mode == 'x' && !*q) {
            r->to = r->from;
            return 0;
        }
        if (!*q) {
            if (r->from.mode == 'a') {
                r->to = r->from;
                return 0;
            }
            if (!def_mode)
                goto bad; /* zapret2 wants a range */
            r->to = r->from; /* "5": exactly 5 */
            return 0;
        }
        if (*q != '-' && *q != '<')
            goto bad;
        r->upper_cutoff = *q == '<';
        q++;
    }
    if (!*q) {
        r->to.mode = 'a';
        return 0;
    }
    if (pos_parse(&q, def_mode, &r->to) < 0 || *q)
        goto bad;
    return 0;
bad:
    sb_printf(err, "bad range \"%s\" (like n2-n5, d1<d3, -s100, b10-, a or x)", s);
    return -1;
}

static void pos_print(const xpos *p, sbuf *out)
{
    if (p->mode == 'a' || p->mode == 'x')
        sb_putc(out, p->mode);
    else
        sb_printf(out, "%c%u", p->mode, p->pos);
}

void xrange_print(const xrange *r, sbuf *out)
{
    if ((r->from.mode == 'x' && r->to.mode == 'x') || (r->from.mode == 'a' && r->to.mode == 'a' && !r->upper_cutoff)) {
        sb_putc(out, r->from.mode);
        return;
    }
    if (r->from.mode != 'a')
        pos_print(&r->from, out);
    sb_putc(out, r->upper_cutoff ? '<' : '-');
    if (r->to.mode != 'a')
        pos_print(&r->to, out);
}

uint64_t xpos_get(const xside_view *v, char mode)
{
    if (!v)
        return 0;
    switch (mode) {
    case 'n': return v->n;
    case 'd': return v->d;
    case 'b': return v->b;
    case 's': return v->s;
    case 'p': return v->p;
    }
    return 0;
}

static int overflow(const xside_view *v, char mode) { return (mode == 's' || mode == 'p') && v && v->over2g; }

static int check_from(const xside_view *v, const xrange *r)
{
    if (r->from.mode == 'x' || overflow(v, r->from.mode))
        return 0;
    if (r->from.mode == 'a')
        return 1;
    return v && xpos_get(v, r->from.mode) >= r->from.pos;
}

static int check_to(const xside_view *v, const xrange *r)
{
    uint64_t ps;
    if (r->to.mode == 'x' || overflow(v, r->to.mode))
        return 0;
    if (r->to.mode == 'a')
        return 1;
    if (!v)
        return 0;
    ps = xpos_get(v, r->to.mode);
    return ps < r->to.pos || (!r->upper_cutoff && ps == r->to.pos);
}

int xrange_in(const xside_view *v, const xrange *r) { return check_from(v, r) && check_to(v, r); }

int xrange_cutoff(const xside_view *v, const xrange *r)
{
    int bto = check_to(v, r);
    return v ? !bto : (!bto || !check_from(v, r));
}
