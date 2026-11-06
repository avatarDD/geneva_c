/*
 * tls_client_hello_mod of zapret2 (lua/zapret-lib.lua): tls_dissect,
 * tls_dissect_handshake, tls_dissect_ext, the SNI changes and
 * tls_reconstruct, ported with their quirks (docs/EXT_ROADMAP.md, G12, J4).
 * Offsets here are 0-based where Lua counts from 1.
 */
#include <stdlib.h>
#include <string.h>

#include "rng.h"
#include "tls.h"
#include "util.h"

enum { REC_CCS = 0x14, REC_HANDSHAKE = 0x16, HS_CLIENT = 1, HS_SERVER = 2 };

static unsigned u16(const uint8_t *p) { return (unsigned)p[0] << 8 | p[1]; }
static size_t u24(const uint8_t *p) { return (size_t)p[0] << 16 | (size_t)p[1] << 8 | p[2]; }

static void b8(sbuf *o, unsigned v)
{
    uint8_t b = (uint8_t)v;
    sb_append(o, &b, 1);
}
static void b16(sbuf *o, unsigned v)
{
    uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    sb_append(o, b, 2);
}
static void b24(sbuf *o, size_t v)
{
    uint8_t b[3] = {(uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    sb_append(o, b, 3);
}
static void b32(sbuf *o, uint64_t v)
{
    uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    sb_append(o, b, 4);
}

/* ---- records and handshake messages (is_tls_record, is_tls_handshake) ------------- */

static int ver_ok(unsigned v) { return v >= 0x0300 && v <= 0x0303; }

static int is_record(const uint8_t *t, size_t n, size_t off)
{
    return n >= off + 5 && ver_ok(u16(t + off + 1)) && u16(t + off + 3) <= n - off - 5;
}

static int hs_type_known(unsigned t)
{
    return t <= 2 || (t >= 11 && t <= 16) || (t >= 20 && t <= 25);
}

static int is_handshake(const uint8_t *t, size_t n, int htype)
{
    if (n < 4 || (htype >= 0 && t[0] != htype) || !hs_type_known(t[0]))
        return 0;
    if (t[0] == HS_CLIENT || t[0] == HS_SERVER) {
        if (n < 6 || !ver_ok(u16(t + 4)))
            return 0;
    }
    return u24(t + 1) <= n - 4;
}

/* ---- extensions (tls_dissect_ext, tls_reconstruct_ext) ---------------------------- */

typedef struct {
    unsigned type;
    const uint8_t *name;
    size_t len;
} sni_name;

typedef struct {
    unsigned type;
    const uint8_t *raw; /* as it came */
    size_t raw_len;
    int dis;         /* zapret2 dissected it: it goes out as canon */
    sbuf canon;
    sni_name *list;  /* server_name: the names */
    size_t nlist;
} text;

/* the list's bounds behind a 16- or 8-bit length: 0, or -1 */
static int len_header(const text *e, int bits, size_t *left, size_t *off)
{
    size_t hl = bits / 8, l;
    if (e->raw_len < hl)
        return -1;
    l = hl == 2 ? u16(e->raw) : e->raw[0];
    if (l > e->raw_len - hl)
        return -1;
    *left = l;
    *off = hl;
    return 0;
}

/* quic_tvb: a varint at off; 0 with *v and *size, or -1 */
static int quic_tvb(const uint8_t *d, size_t n, size_t off, uint64_t *v, size_t *size)
{
    unsigned s;
    if (off >= n)
        return -1;
    s = d[off] >> 6;
    *size = (size_t)1 << s;
    if (off + *size > n)
        return -1;
    *v = d[off] & 0x3f;
    for (size_t i = 1; i < *size; i++)
        *v = *v << 8 | d[off + i];
    return 0;
}

static void bquic_tvb(sbuf *o, uint64_t v)
{
    if (v < 0x40) {
        b8(o, (unsigned)v);
    } else if (v < 0x4000) {
        b16(o, (unsigned)(v + 0x4000));
    } else if (v < 0x40000000) {
        b32(o, v + 0x80000000u);
    } else {
        b32(o, (v >> 32) + 0xC0000000u);
        b32(o, v & 0xffffffffu);
    }
}

/* server_name from its list */
static void sni_canon(text *e)
{
    sbuf b;
    sb_init(&b);
    for (size_t i = 0; i < e->nlist; i++) {
        b8(&b, e->list[i].type);
        b16(&b, (unsigned)e->list[i].len);
        sb_append(&b, e->list[i].name, e->list[i].len);
    }
    sb_reset(&e->canon);
    b16(&e->canon, (unsigned)b.len);
    sb_append(&e->canon, b.data, b.len);
    sb_free(&b);
}

/* sets e->dis and e->canon when zapret2 dissects the type */
static void dissect_ext(text *e)
{
    const uint8_t *d = e->raw;
    size_t left, off, len;
    sbuf *c = &e->canon;
    sbuf body;
    sb_init(&body);
    switch (e->type) {
    case 0: /* server_name */
        if (len_header(e, 16, &left, &off) < 0)
            break;
        while (left >= 3) {
            len = u16(d + off + 1);
            if (len + 3 > left)
                goto fail;
            e->list = xrealloc(e->list, (e->nlist + 1) * sizeof(*e->list));
            e->list[e->nlist].type = d[off];
            e->list[e->nlist].name = d + off + 3;
            e->list[e->nlist].len = len;
            e->nlist++;
            left -= 3 + len;
            off += 3 + len;
        }
        e->dis = 1;
        sni_canon(e);
        break;
    case 16: /* alpn */
        if (len_header(e, 16, &left, &off) < 0)
            break;
        while (left >= 1) {
            len = d[off];
            if (len + 1 > left)
                goto fail;
            sb_append(&body, d + off, len + 1);
            left -= 1 + len;
            off += 1 + len;
        }
        b16(c, (unsigned)body.len);
        e->dis = 1;
        break;
    case 43: /* supported_versions */
    case 27: /* compress_certificate */
    case 13: /* signature_algorithms */
    case 34: /* delegated_credentials */
    case 10: /* supported_groups */
    {
        int h8 = e->type == 43 || e->type == 27;
        if (len_header(e, h8 ? 8 : 16, &left, &off) < 0)
            break;
        sb_append(&body, d + off, left / 2 * 2); /* an odd byte is lost */
        if (h8)
            b8(c, (unsigned)body.len);
        else
            b16(c, (unsigned)body.len);
        e->dis = 1;
        break;
    }
    case 11: /* ec_point_formats */
    case 45: /* psk_key_exchange_modes */
        if (len_header(e, 8, &left, &off) < 0)
            break;
        sb_append(&body, d + off, left);
        b8(c, (unsigned)body.len);
        e->dis = 1;
        break;
    case 51:    /* key_share */
    case 65445: /* quic_transport_parameters (draft) */
        if (len_header(e, 16, &left, &off) < 0)
            break;
        while (left >= 4) {
            len = u16(d + off + 2);
            if (len + 4 > left)
                goto fail;
            sb_append(&body, d + off, len + 4);
            left -= 4 + len;
            off += 4 + len;
        }
        b16(c, (unsigned)body.len);
        e->dis = 1;
        break;
    case 57: /* quic_transport_parameters */
    {
        long l = (long)e->raw_len;
        off = 0;
        while (l >= 2) {
            uint64_t typ, vl;
            size_t s1, s2;
            if (quic_tvb(d, e->raw_len, off, &typ, &s1) < 0)
                goto fail;
            off += s1;
            l -= (long)s1;
            if (quic_tvb(d, e->raw_len, off, &vl, &s2) < 0)
                goto fail;
            off += s2;
            l -= (long)s2;
            if (l < 0 || vl > (uint64_t)l)
                goto fail;
            bquic_tvb(&body, typ);
            bquic_tvb(&body, vl);
            sb_append(&body, d + off, (size_t)vl);
            l -= (long)vl;
            off += (size_t)vl;
        }
        e->dis = 1;
        break;
    }
    default:
        break;
    }
    if (e->dis && e->type != 0)
        sb_append(c, body.data, body.len);
    sb_free(&body);
    return;
fail:
    free(e->list);
    e->list = NULL;
    e->nlist = 0;
    sb_reset(c);
    sb_free(&body);
}

/* ---- hello messages (tls_dissect_handshake, tls_reconstruct_handshake) ------------- */

typedef struct {
    int ok;
    unsigned type, ver;
    const uint8_t *random, *sid;
    size_t sid_len;
    const uint8_t *cs, *cm; /* client: the lists; server: the one value */
    size_t ncs, ncm;
    text *ext;
    size_t next;
} hello;

static void hello_free(hello *h)
{
    for (size_t i = 0; i < h->next; i++) {
        sb_free(&h->ext[i].canon);
        free(h->ext[i].list);
    }
    free(h->ext);
    memset(h, 0, sizeof(*h));
}

static int dissect_hello(const uint8_t *d, size_t n, hello *h)
{
    size_t hlen, len, left, off;
    long sl;
    memset(h, 0, sizeof(*h));
    if (!is_handshake(d, n, HS_CLIENT) && !is_handshake(d, n, HS_SERVER))
        return -1;
    hlen = u24(d + 1) + 4;
    h->type = d[0];
    h->ver = u16(d + 4);
    if (hlen < 38)
        return -1;
    h->random = d + 6;
    if (hlen < 39)
        return -1;
    len = d[38];
    sl = (long)hlen - 39 - (long)len;
    if (sl < 0)
        return -1;
    left = (size_t)sl;
    h->sid = d + 39;
    h->sid_len = len;
    off = 39 + len;
    if (left < 2)
        return -1;
    if (h->type == HS_CLIENT) {
        len = u16(d + off);
        if (left < 2 + len)
            return -1;
        h->cs = d + off + 2;
        h->ncs = len / 2;
        off += 2 + len;
        left -= 2 + len;
    } else {
        h->cs = d + off;
        off += 2;
        left -= 2;
    }
    if (left < 1)
        return -1;
    if (h->type == HS_CLIENT) {
        len = d[off];
        if (left < 1 + len)
            return -1;
        h->cm = d + off + 1;
        h->ncm = len;
        off += 1 + len;
        left -= 1 + len;
    } else {
        h->cm = d + off;
        off += 1;
        left -= 1;
    }
    if (left < 2)
        return -1;
    len = u16(d + off);
    if (left < 2 + len)
        return -1;
    off += 2;
    left -= 2;
    if (left > len)
        left = len;
    while (left >= 4) {
        text *e;
        len = u16(d + off + 2);
        if (len > left - 4) {
            hello_free(h);
            return -1;
        }
        h->ext = xrealloc(h->ext, (h->next + 1) * sizeof(*h->ext));
        e = &h->ext[h->next++];
        memset(e, 0, sizeof(*e));
        sb_init(&e->canon);
        e->type = u16(d + off);
        e->raw = d + off + 4;
        e->raw_len = len;
        dissect_ext(e);
        left -= 4 + len;
        off += 4 + len;
    }
    h->ok = 1;
    return 0;
}

static int reconstruct_hello(const hello *h, sbuf *o)
{
    sbuf hd, ex;
    int rc = 0;
    sb_init(&hd);
    sb_init(&ex);
    b16(&hd, h->ver);
    sb_append(&hd, h->random, 32);
    b8(&hd, (unsigned)h->sid_len);
    sb_append(&hd, h->sid, h->sid_len);
    if (h->type == HS_CLIENT) {
        b16(&hd, (unsigned)(2 * h->ncs));
        sb_append(&hd, h->cs, 2 * h->ncs);
        b8(&hd, (unsigned)h->ncm);
        sb_append(&hd, h->cm, h->ncm);
    } else {
        sb_append(&hd, h->cs, 2);
        sb_append(&hd, h->cm, 1);
    }
    for (size_t i = 0; i < h->next; i++) {
        const text *e = &h->ext[i];
        const uint8_t *b = e->dis ? (const uint8_t *)e->canon.data : e->raw;
        size_t bl = e->dis ? e->canon.len : e->raw_len;
        if (bl > 0xffff) {
            rc = -1;
            break;
        }
        b16(&ex, e->type);
        b16(&ex, (unsigned)bl);
        sb_append(&ex, b, bl);
    }
    if (!rc && ex.len <= 0xffff && hd.len + 2 + ex.len <= 0xffffff) {
        b8(o, h->type);
        b24(o, hd.len + 2 + ex.len);
        sb_append(o, hd.data, hd.len);
        b16(o, (unsigned)ex.len);
        sb_append(o, ex.data, ex.len);
    } else {
        rc = -1;
    }
    sb_free(&hd);
    sb_free(&ex);
    return rc;
}

/* ---- tls_client_hello_mod ------------------------------------------------------- */

static int mod_sni(hello *h, const tls_cloneopt *o)
{
    size_t idx = h->next;
    text *e;
    if (o->snt < 0 && !o->del_ext && !o->del && !o->first && !o->last)
        return 0;
    for (size_t i = 0; i < h->next; i++)
        if (h->ext[i].type == 0) {
            idx = i;
            break;
        }
    if (idx == h->next) {
        /* no SNI extension: one goes first */
        h->ext = xrealloc(h->ext, (h->next + 1) * sizeof(*h->ext));
        memmove(h->ext + 1, h->ext, h->next * sizeof(*h->ext));
        h->next++;
        idx = 0;
        memset(&h->ext[0], 0, sizeof(h->ext[0]));
        sb_init(&h->ext[0].canon);
        h->ext[0].dis = 1;
    }
    e = &h->ext[idx];
    if (o->del_ext) {
        sb_free(&e->canon);
        free(e->list);
        memmove(h->ext + idx, h->ext + idx + 1, (h->next - idx - 1) * sizeof(*h->ext));
        h->next--;
        return 0;
    }
    if (!e->dis)
        return -1; /* Lua fails indexing the missing dissect */
    if (o->del) {
        e->nlist = 0;
    } else if (o->snt >= 0) {
        for (size_t i = 0; i < e->nlist; i++)
            e->list[i].type = (unsigned)o->snt;
    }
    if (o->first) {
        e->list = xrealloc(e->list, (e->nlist + 1) * sizeof(*e->list));
        memmove(e->list + 1, e->list, e->nlist * sizeof(*e->list));
        e->list[0].type = o->snt_new < 0 ? 0 : (unsigned)o->snt_new;
        e->list[0].name = (const uint8_t *)o->first;
        e->list[0].len = o->first_len;
        e->nlist++;
    }
    if (o->last) {
        e->list = xrealloc(e->list, (e->nlist + 1) * sizeof(*e->list));
        e->list[e->nlist].type = o->snt_new < 0 ? 0 : (unsigned)o->snt_new;
        e->list[e->nlist].name = (const uint8_t *)o->last;
        e->list[e->nlist].len = o->last_len;
        e->nlist++;
    }
    for (size_t i = 0; i < e->nlist; i++)
        if (e->list[i].len > 0xffff)
            return -1;
    sni_canon(e);
    return 0;
}

typedef struct {
    unsigned type, ver;
    int htype; /* -1: none */
    int encrypted;
    const uint8_t *data;
    size_t len;
} rec;

typedef struct {
    int present;
    sbuf data;
} hsmsg;

int tls_ch_clone(const uint8_t *t, size_t n, const tls_cloneopt *o, uint8_t **out, size_t *outlen)
{
    rec *rv = NULL;
    size_t nr = 0, off = 0;
    hsmsg *hs = xcalloc(256, sizeof(*hs));
    hello ch, sh;
    int enc = 0, rc = -1, any_hs = 0;
    sbuf res, newch;
    sb_init(&res);
    sb_init(&newch);
    memset(&ch, 0, sizeof(ch));
    memset(&sh, 0, sizeof(sh));
    /* tls_dissect */
    while (is_record(t, n, off)) {
        size_t len = u16(t + off + 3);
        unsigned typ = t[off];
        rv = xrealloc(rv, (nr + 1) * sizeof(*rv));
        rv[nr] = (rec){typ, u16(t + off + 1), -1, enc, t + off + 5, len};
        nr++;
        if (typ == REC_CCS) {
            enc = 1;
        } else if (typ == REC_HANDSHAKE && !enc) {
            unsigned ht;
            size_t hlen;
            hsmsg *m;
            if (n - off < 9)
                goto end;
            ht = t[off + 5];
            rv[nr - 1].htype = (int)ht;
            hlen = u24(t + off + 6) + 4;
            m = &hs[ht];
            if (m->present)
                sb_reset(&m->data);
            else
                sb_init(&m->data);
            m->present = any_hs = 1;
            for (;;) {
                size_t nx;
                sb_append(&m->data, t + off + 5, len);
                if (m->data.len >= hlen)
                    break;
                nx = off + 5 + len;
                if (!is_record(t, n, nx) || t[nx] != typ)
                    goto end;
                off = nx;
                len = u16(t + off + 3);
                rv = xrealloc(rv, (nr + 1) * sizeof(*rv));
                rv[nr] = (rec){typ, u16(t + off + 1), (int)ht, 0, t + off + 5, len};
                nr++;
            }
        }
        off += 5 + len;
    }
    if (!any_hs) {
        if (nr || !is_handshake(t, n, -1))
            goto end;
        hs[t[0]].present = any_hs = 1;
        sb_init(&hs[t[0]].data);
        sb_append(&hs[t[0]].data, t, n);
    }
    if (!hs[HS_CLIENT].present ||
        dissect_hello((const uint8_t *)hs[HS_CLIENT].data.data, hs[HS_CLIENT].data.len, &ch) < 0 ||
        ch.type != HS_CLIENT)
        goto end;
    if (hs[HS_SERVER].present)
        dissect_hello((const uint8_t *)hs[HS_SERVER].data.data, hs[HS_SERVER].data.len, &sh);
    if (mod_sni(&ch, o) < 0)
        goto end;
    /* tls_reconstruct */
    if (reconstruct_hello(&ch, &newch) < 0)
        goto end;
    sb_reset(&hs[HS_CLIENT].data);
    sb_append(&hs[HS_CLIENT].data, newch.data, newch.len);
    if (sh.ok) {
        sb_reset(&newch);
        if (reconstruct_hello(&sh, &newch) < 0)
            goto end;
        sb_reset(&hs[HS_SERVER].data);
        sb_append(&hs[HS_SERVER].data, newch.data, newch.len);
    }
    if (nr) {
        for (size_t i = 0; i < nr;) {
            rec *r0 = &rv[i];
            if (r0->type == REC_HANDSHAKE && !r0->encrypted && r0->htype >= 0 && hs[r0->htype].present) {
                const sbuf *d = &hs[r0->htype].data;
                size_t j = i + 1, at = 0;
                while (j < nr && rv[j].type == REC_HANDSHAKE && !rv[j].encrypted && rv[j].htype == r0->htype)
                    j++;
                for (size_t k = i; k < j; k++) {
                    size_t chunk = d->len - at;
                    if (k != j - 1 && chunk > rv[k].len)
                        chunk = rv[k].len;
                    rv[k].data = (const uint8_t *)d->data + at;
                    rv[k].len = chunk;
                    at += chunk;
                }
                i = j;
            } else {
                i++;
            }
        }
        for (size_t i = 0; i < nr; i++) {
            if (!rv[i].len)
                continue;
            if (rv[i].len > 0xffff)
                goto end;
            b8(&res, rv[i].type);
            b16(&res, rv[i].ver);
            b16(&res, (unsigned)rv[i].len);
            sb_append(&res, rv[i].data, rv[i].len);
        }
    } else {
        sb_append(&res, hs[HS_CLIENT].data.data, hs[HS_CLIENT].data.len);
    }
    *outlen = res.len;
    *out = xmalloc(res.len ? res.len : 1);
    memcpy(*out, res.data, res.len);
    rc = 0;
end:
    hello_free(&ch);
    hello_free(&sh);
    for (int i = 0; i < 256; i++)
        if (hs[i].present)
            sb_free(&hs[i].data);
    free(hs);
    free(rv);
    sb_free(&res);
    sb_free(&newch);
    return rc;
}
