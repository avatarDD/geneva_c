/*
 * xhttp: the HTTP request mods of zapret-antidpi.lua (http_domcase,
 * http_hostcase, http_methodeol, http_unixeol) over zapret-lib.lua's
 * http_dissect_req and http_reconstruct_req, ported with their quirks.
 * Positions in the dissector are 1-based, as in Lua.
 */
#include <stdlib.h>
#include <string.h>

#include "markers.h"
#include "xact.h"

/* ---- zapret-lib.lua: find_next_line, http_dissect_req, http_reconstruct_req ---- */

typedef struct {
    size_t pos_start, pos_end, pos_header_end, pos_value_start; /* 1-based */
    const uint8_t *name, *value;
    size_t name_len, value_len;
    char *value_own; /* a value made longer (unixeol): owned */
} hhdr;

typedef struct {
    const uint8_t *method, *uri, *ver;
    size_t method_len, uri_len, ver_len;
    int has_ver;
    hhdr *h;
    size_t nh;
    size_t pos_headers_end; /* 0: none (no empty line) */
    const uint8_t *body;
    size_t body_len;
} hdis;

/* the 1-based byte i of s (0 beyond its end, as string.sub gives "") */
static int at(const uint8_t *s, size_t n, size_t i) { return i >= 1 && i <= n ? s[i - 1] : -1; }

static int is_eol(int c) { return c == '\r' || c == '\n'; }
static int is_sp(int c) { return c == ' ' || c == '\t'; }

/* the end of the line from pos and the start of the next one (0: none) */
static void find_next_line(const uint8_t *s, size_t n, size_t pos, size_t *p1, size_t *p2)
{
    size_t q;
    for (q = pos; q <= n && !is_eol(s[q - 1]); q++)
        ;
    if (q > n) {
        *p1 = n;
        *p2 = 0;
        return;
    }
    *p1 = q - 1;
    if (at(s, n, q) == '\r')
        q++;
    if (at(s, n, q) == '\n')
        q++;
    *p2 = q > n ? 0 : q;
}

static void hdis_free(hdis *d)
{
    for (size_t i = 0; i < d->nh; i++)
        free(d->h[i].value_own);
    free(d->h);
    memset(d, 0, sizeof(*d));
}

static void dissect_headers(const uint8_t *s, size_t n, size_t pos, hdis *d)
{
    while (pos) {
        size_t eol, pnext, hl;
        find_next_line(s, n, pos, &eol, &pnext);
        hl = eol + 1 - pos;
        if (!hl) {
            d->pos_headers_end = pnext;
            break;
        }
        {
            const uint8_t *hd = s + pos - 1;
            size_t c, v;
            for (c = 1; c <= hl && hd[c - 1] != ':'; c++)
                ;
            if (c <= hl) {
                hhdr *e;
                for (v = c + 1; v <= hl && is_sp(hd[v - 1]); v++)
                    ;
                d->h = xrealloc(d->h, (d->nh + 1) * sizeof(*d->h));
                e = &d->h[d->nh++];
                memset(e, 0, sizeof(*e));
                e->name = hd;
                e->name_len = c - 1;
                if (v <= hl) {
                    e->value = hd + v - 1;
                    e->value_len = hl - v + 1;
                } else {
                    e->value = hd;
                    e->value_len = 0;
                    v = hl; /* zapret2: p2 or #header */
                }
                e->pos_start = pos;
                e->pos_end = eol;
                e->pos_header_end = pos + (c - 1) - 1;
                e->pos_value_start = pos + v - 1;
            }
        }
        pos = pnext;
    }
}

static int dissect_req(const uint8_t *s, size_t n, hdis *d)
{
    size_t pos = 1, eol, pnext, rl = 0, m, u, e, v;
    const uint8_t *req = NULL;
    memset(d, 0, sizeof(*d));
    /* skip methodeol empty line(s) */
    while (pos) {
        find_next_line(s, n, pos, &eol, &pnext);
        req = s + pos - 1;
        rl = eol + 1 - pos;
        pos = pnext;
        if (rl)
            break;
    }
    if (!rl)
        return -1;
    for (m = 1; m <= rl && !is_sp(req[m - 1]); m++)
        ;
    if (m > rl)
        return -1;
    d->method = req;
    d->method_len = m - 1;
    for (u = m + 1; u <= rl && is_sp(req[u - 1]); u++)
        ;
    if (u > rl)
        return -1;
    for (e = u + 1; e <= rl && !is_sp(req[e - 1]); e++)
        ;
    d->uri = req + u - 1;
    d->uri_len = e - u;
    for (v = e; v <= rl && is_sp(req[v - 1]); v++)
        ;
    if (v <= rl) {
        d->has_ver = 1;
        d->ver = req + v - 1;
        d->ver_len = rl - v + 1;
    }
    if (pos)
        dissect_headers(s, n, pos, d);
    if (d->pos_headers_end) {
        d->body = s + d->pos_headers_end - 1;
        d->body_len = n - d->pos_headers_end + 1;
    }
    return 0;
}

static void put(sbuf *o, const uint8_t *p, size_t n) { sb_append(o, (const char *)p, n); }

static void reconstruct_req(const hdis *d, int unixeol, sbuf *o)
{
    const char *eol = unixeol ? "\n" : "\r\n";
    put(o, d->method, d->method_len);
    sb_puts(o, " ");
    put(o, d->uri, d->uri_len);
    if (d->has_ver) {
        sb_puts(o, " ");
        put(o, d->ver, d->ver_len);
    }
    sb_puts(o, eol);
    for (size_t i = 0; i < d->nh; i++) {
        put(o, d->h[i].name, d->h[i].name_len);
        sb_puts(o, ": ");
        put(o, d->h[i].value, d->h[i].value_len);
        sb_puts(o, eol);
    }
    sb_puts(o, eol);
    if (d->body)
        put(o, d->body, d->body_len);
}

static int name_is(const hhdr *h, const char *low)
{
    size_t n = strlen(low);
    if (h->name_len != n)
        return 0;
    for (size_t i = 0; i < n; i++) {
        int c = h->name[i];
        if (c >= 'A' && c <= 'Z')
            c += 'a' - 'A';
        if (c != low[i])
            return 0;
    }
    return 1;
}

static hhdr *header(hdis *d, const char *low)
{
    for (size_t i = 0; i < d->nh; i++)
        if (name_is(&d->h[i], low))
            return &d->h[i];
    return NULL;
}

/* ---- the mods: each returns 1 when it changed the payload ------------------------ */

static int domcase(xrun *r, gpkt *p)
{
    xmarker m[2];
    long pos[2];
    xmarker_parse("host", &m[0]);
    xmarker_parse("endhost", &m[1]);
    if (xmarker_resolve_list(p->payload, p->payload_len, r->l7p, m, 2, pos) != 2) {
        xa_log(r, "domcase: cannot find host range");
        return 0;
    }
    for (long i = pos[0]; i < pos[1]; i++) {
        uint8_t c = p->payload[i];
        if ((i - pos[0]) % 2 == 0) {
            if (c >= 'a' && c <= 'z')
                c = (uint8_t)(c - 'a' + 'A');
        } else if (c >= 'A' && c <= 'Z') {
            c = (uint8_t)(c - 'A' + 'a');
        }
        p->payload[i] = c;
    }
    xa_log(r, "domcase: applied");
    return 1;
}

static int hostcase(xrun *r, gpkt *p)
{
    const char *spell = xa_arg(r, "hostcase", NULL);
    hdis d;
    hhdr *h;
    int rc = 0;
    if (!spell || !*spell)
        spell = "host";
    if (strlen(spell) != 4) {
        xa_log(r, "hostcase: invalid host spelling '%s'", spell);
        return 0;
    }
    if (dissect_req(p->payload, p->payload_len, &d) < 0) {
        xa_log(r, "hostcase: http dissect error");
        return 0;
    }
    h = header(&d, "host");
    if (h) {
        /* the name ("Host", 4 bytes) becomes spell */
        sbuf o;
        sb_init(&o);
        put(&o, p->payload, h->pos_start - 1);
        sb_puts(&o, spell);
        put(&o, p->payload + h->pos_header_end, p->payload_len - h->pos_header_end);
        pkt_set_payload(p, (const uint8_t *)o.data, o.len);
        sb_free(&o);
        xa_log(r, "hostcase: 'Host:' => '%s'", spell);
        rc = 1;
    } else {
        xa_log(r, "hostcase: 'Host:' header not found");
    }
    hdis_free(&d);
    return rc;
}

static int methodeol(xrun *r, gpkt *p)
{
    hdis d;
    hhdr *ua;
    int rc = 0;
    if (dissect_req(p->payload, p->payload_len, &d) < 0) {
        xa_log(r, "methodeol: http dissect error");
        return 0;
    }
    ua = header(&d, "user-agent");
    if (!ua) {
        xa_log(r, "methodeol: 'User-Agent:' header not found");
    } else if (ua->pos_end - ua->pos_value_start < 2) {
        xa_log(r, "methodeol: 'User-Agent:' header is too short");
    } else {
        /* "\r\n" in front, the last two bytes of the User-Agent line out */
        sbuf o;
        sb_init(&o);
        sb_puts(&o, "\r\n");
        put(&o, p->payload, ua->pos_end - 2);
        put(&o, p->payload + ua->pos_end, p->payload_len - ua->pos_end);
        pkt_set_payload(p, (const uint8_t *)o.data, o.len);
        sb_free(&o);
        xa_log(r, "methodeol: applied");
        rc = 1;
    }
    hdis_free(&d);
    return rc;
}

static int unixeol(xrun *r, gpkt *p)
{
    hdis d;
    hhdr *ua;
    int rc = 0;
    if (dissect_req(p->payload, p->payload_len, &d) < 0) {
        xa_log(r, "unixeol: could not dissect http");
        return 0;
    }
    ua = header(&d, "user-agent");
    if (!ua) {
        xa_log(r, "unixeol: 'User-Agent:' header absent");
    } else {
        sbuf o;
        sb_init(&o);
        reconstruct_req(&d, 1, &o);
        if (o.len < p->payload_len) {
            /* the User-Agent value takes spaces to keep the length */
            size_t add = p->payload_len - o.len;
            ua->value_own = xmalloc(ua->value_len + add);
            memcpy(ua->value_own, ua->value, ua->value_len);
            memset(ua->value_own + ua->value_len, ' ', add);
            ua->value = (const uint8_t *)ua->value_own;
            ua->value_len += add;
        }
        sb_reset(&o);
        reconstruct_req(&d, 1, &o);
        if (o.len == p->payload_len) {
            pkt_set_payload(p, (const uint8_t *)o.data, o.len);
            xa_log(r, "unixeol: applied");
            rc = 1;
        } else {
            xa_log(r, "unixeol: reconstruct differs in size from original: %zu!=%zu", o.len, p->payload_len);
        }
        sb_free(&o);
    }
    hdis_free(&d);
    return rc;
}

static int check_http(const xact *a, sbuf *err)
{
    const char *sp = xa_raw(a, "hostcase");
    if (!xa_has(a, "domcase") && !xa_has(a, "hostcase") && !xa_has(a, "methodeol") && !xa_has(a, "unixeol")) {
        sb_puts(err, "xhttp: nothing to do (domcase, hostcase, methodeol, unixeol)");
        return -1;
    }
    if (sp && sp[0] != '%' && sp[0] != '#' && strlen(sp[0] == '\\' ? sp + 1 : sp) != 4) {
        sb_printf(err, "xhttp: invalid host spelling '%s'", sp);
        return -1;
    }
    return xa_check_flag(a, "domcase", err) < 0 || xa_check_flag(a, "methodeol", err) < 0 ||
                   xa_check_flag(a, "unixeol", err) < 0
               ? -1
               : 0;
}

/* in zapret2's order of a chain: domcase, hostcase, unixeol, methodeol
 * ("methodeol should be the last") */
static void run_http(const xact *a, gpkt *p, xrun *r)
{
    int ch = 0;
    if (p->l4 != LAYER_TCP) {
        xa_cutoff(r);
        xa_pass(r, p);
        return;
    }
    if (!strcmp(r->l7name, "http_req") && p->payload_len) {
        if (xa_has(a, "domcase"))
            ch |= domcase(r, p);
        if (xa_has(a, "hostcase"))
            ch |= hostcase(r, p);
        if (xa_has(a, "unixeol"))
            ch |= unixeol(r, p);
        if (xa_has(a, "methodeol"))
            ch |= methodeol(r, p);
        if (ch)
            xa_modified(p);
    }
    xa_pass(r, p);
}

static const char *const k_http[] = {"domcase", "hostcase", "methodeol", "unixeol", NULL};

const xa_kind xa_http = {"xhttp", 1, 1, 0, k_http, check_http, run_http};
