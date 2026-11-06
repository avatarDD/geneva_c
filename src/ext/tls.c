#include "tls.h"

#include <string.h>

#include "l7.h"
#include "log.h"
#include "rng.h"

typedef struct {
    const uint8_t *p;
    size_t n, off;
    int cut; /* a read went past the end */
} cur;

static int need(cur *c, size_t k)
{
    if (k > c->n - c->off) {
        c->cut = 1;
        return 0;
    }
    return 1;
}

static unsigned rd(cur *c, size_t k)
{
    unsigned v = 0;
    if (!need(c, k))
        return 0;
    for (size_t i = 0; i < k; i++)
        v = v << 8 | c->p[c->off + i];
    c->off += k;
    return v;
}

static int skip(cur *c, size_t k)
{
    if (!need(c, k))
        return 0;
    c->off += k;
    return 1;
}

static int lower_ok(int ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' ||
           ch == '.' || ch == '_' || ch == '*';
}

/* server_name extension body: list length, (type 0, length, name)... */
static int read_sni(const uint8_t *p, size_t n, char *out, size_t cap)
{
    size_t off = 2, ll;
    if (n < 2)
        return TLS_NOT_CH;
    ll = (size_t)p[0] << 8 | p[1];
    if (ll + 2 > n)
        return TLS_NOT_CH;
    while (off + 3 <= 2 + ll) {
        uint8_t type = p[off];
        size_t nl = (size_t)p[off + 1] << 8 | p[off + 2];
        off += 3;
        if (off + nl > 2 + ll)
            return TLS_NOT_CH;
        if (type == 0) {
            if (!nl || nl + 1 > cap)
                return TLS_NOT_CH;
            for (size_t i = 0; i < nl; i++)
                if (!lower_ok(p[off + i]))
                    return TLS_NOT_CH;
            memcpy(out, p + off, nl);
            out[nl] = 0;
            return TLS_SNI;
        }
        off += nl;
    }
    return TLS_NO_SNI;
}

int tls_hs_sni(const uint8_t *p, size_t n, char *out, size_t cap, size_t *msg_len)
{
    cur c = {p, n, 0, 0};
    size_t len, end, ext_end;
    if (cap)
        out[0] = 0;
    if (n < 1 || p[0] != 1)
        return TLS_NOT_CH;
    if (n < 4)
        return TLS_PARTIAL;
    c.off = 1;
    len = rd(&c, 3);
    if (msg_len)
        *msg_len = len + 4;
    if (len < 38)
        return TLS_NOT_CH;
    end = 4 + len;
    /* version, random, session id, cipher suites, compression */
    if (rd(&c, 1) != 3)
        return c.cut ? TLS_PARTIAL : TLS_NOT_CH;
    skip(&c, 1 + 32);
    skip(&c, rd(&c, 1));
    skip(&c, rd(&c, 2));
    skip(&c, rd(&c, 1));
    if (c.cut)
        return TLS_PARTIAL;
    if (c.off == end)
        return TLS_NO_SNI; /* no extensions */
    ext_end = c.off + 2 + rd(&c, 2);
    if (c.cut)
        return TLS_PARTIAL;
    if (ext_end > end)
        return TLS_NOT_CH;
    while (c.off + 4 <= ext_end) {
        unsigned type = rd(&c, 2);
        size_t el = rd(&c, 2);
        if (c.cut)
            return TLS_PARTIAL;
        if (c.off + el > ext_end)
            return TLS_NOT_CH;
        if (type == 0) {
            if (!need(&c, el))
                return TLS_PARTIAL;
            return read_sni(p + c.off, el, out, cap);
        }
        if (!skip(&c, el))
            return TLS_PARTIAL;
    }
    return TLS_NO_SNI; /* every extension seen */
}

int tls_rec_sni(const uint8_t *p, size_t n, char *out, size_t cap, uint8_t *hs, size_t hs_cap)
{
    size_t hn = 0, off = 0;
    if (cap)
        out[0] = 0;
    if (n < 1 || p[0] != 22)
        return TLS_NOT_CH;
    while (off < n) {
        size_t rl, k;
        if (p[off] != 22)
            break;
        if (n - off < 5) {
            if (!hn)
                return TLS_PARTIAL;
            break;
        }
        if (p[off + 1] != 3)
            return TLS_NOT_CH;
        rl = (size_t)p[off + 3] << 8 | p[off + 4];
        if (!rl || rl > 16384 + 256)
            return TLS_NOT_CH;
        off += 5;
        k = rl < n - off ? rl : n - off;
        if (k > hs_cap - hn)
            k = hs_cap - hn;
        memcpy(hs + hn, p + off, k);
        hn += k;
        off += k;
        if (k < rl)
            break; /* the record is cut */
    }
    if (!hn)
        return TLS_PARTIAL; /* a record header and nothing yet */
    return tls_hs_sni(hs, hn, out, cap, NULL);
}

/* ---- tls_mod, genhost ------------------------------------------------------- */

static const char *const tlds[6] = {"com", "org", "net", "edu", "gov", "biz"};

static void rnd_az(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)('a' + rng_index(26));
}

static void rnd_az09(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        size_t r = rng_index(36);
        p[i] = (uint8_t)(r < 10 ? '0' + r : 'a' + r - 10);
    }
}

int tls_mod_parse(const char *list, tls_modspec *m)
{
    const char *p = list;
    m->mod = 0;
    m->sni[0] = 0;
    while (*p) {
        const char *e = strchr(p, ',');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l == 3 && !strncmp(p, "rnd", 3))
            m->mod |= TLSMOD_RND;
        else if (l == 6 && !strncmp(p, "rndsni", 6))
            m->mod |= TLSMOD_RNDSNI;
        else if (l == 6 && !strncmp(p, "dupsid", 6))
            m->mod |= TLSMOD_DUPSID;
        else if (l == 8 && !strncmp(p, "padencap", 8))
            m->mod |= TLSMOD_PADENCAP;
        else if (l > 4 && !strncmp(p, "sni=", 4)) {
            if (l - 4 >= sizeof(m->sni))
                return -1;
            m->mod |= TLSMOD_SNI;
            memcpy(m->sni, p + 4, l - 4);
            m->sni[l - 4] = 0;
        } else if (!(l == 4 && !strncmp(p, "none", 4)))
            return -1;
        if (!e)
            break;
        p = e + 1;
    }
    return 0;
}

static void w16(uint8_t *p, size_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}
static size_t r16(const uint8_t *p) { return (size_t)p[0] << 8 | p[1]; }
static size_t r24(const uint8_t *p) { return (size_t)p[0] << 16 | (size_t)p[1] << 8 | p[2]; }
static void w24(uint8_t *p, size_t v)
{
    p[0] = (uint8_t)(v >> 16);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)v;
}

int tls_mod_apply(const tls_modspec *m, const uint8_t *payload, size_t plen, uint8_t *fake, size_t *len, size_t cap)
{
    const uint8_t *ext;
    size_t extlen, slen, extlen_off = 0, padlen_off = 0;

    if (!l7_is_tls_hello(fake, *len, 1, 0) || *len < 44 || *len < 44 + (size_t)fake[43]) {
        LOGD("xact", "cannot apply tls mod. tls structure invalid");
        return -1;
    }
    if (m->mod & (TLSMOD_RNDSNI | TLSMOD_SNI | TLSMOD_PADENCAP)) {
        if (!l7_tls_ext_len_off(fake, *len, &extlen_off)) {
            LOGD("xact", "cannot apply tls mod. tls structure invalid");
            return -1;
        }
    }
    if (m->mod & (TLSMOD_RNDSNI | TLSMOD_SNI)) {
        uint8_t *sniext, *sni;
        if (!l7_tls_find_ext(fake, *len, 0, &ext, &extlen, 0)) {
            LOGD("xact", "cannot apply tls mod. sni mod is set but tls does not have SNI");
            return -1;
        }
        sniext = fake + (ext - fake);
        if (!l7_tls_sni_host(&ext, &extlen, &slen)) {
            LOGD("xact", "cannot apply tls mod. sni set but tls has invalid SNI structure");
            return -1;
        }
        sni = fake + (ext - fake);
        if (m->mod & TLSMOD_SNI) {
            size_t nl = strlen(m->sni);
            if (nl != slen) {
                long d = (long)nl - (long)slen;
                if ((long)*len + d > (long)cap) {
                    LOGD("xact", "cannot apply sni tls mod. not enough space for new SNI");
                    return -1;
                }
                memmove(sni + nl, sni + slen, (size_t)(fake + *len - (sni + slen)));
                w16(fake + 3, (size_t)((long)r16(fake + 3) + d));
                w24(fake + 6, (size_t)((long)r24(fake + 6) + d));
                w16(fake + extlen_off, (size_t)((long)r16(fake + extlen_off) + d));
                w16(sniext - 2, (size_t)((long)r16(sniext - 2) + d));
                w16(sniext, (size_t)((long)r16(sniext) + d));
                w16(sni - 2, (size_t)((long)r16(sni - 2) + d));
                *len = (size_t)((long)*len + d);
                slen = nl;
            }
            memcpy(sni, m->sni, nl);
        }
        if (m->mod & TLSMOD_RNDSNI) {
            if (!slen) {
                LOGD("xact", "cannot apply rndsni tls mod. tls has zero sized SNI");
                return -1;
            }
            rnd_az(sni, 1);
            if (slen >= 7) {
                rnd_az09(sni + 1, slen - 5);
                sni[slen - 4] = '.';
                memcpy(sni + slen - 3, tlds[rng_index(6)], 3);
            } else {
                rnd_az09(sni + 1, slen - 1);
            }
        }
    }
    if (m->mod & TLSMOD_RND) {
        rng_bytes(fake + 11, 32);
        rng_bytes(fake + 44, fake[43]);
    }
    if (payload) {
        if (m->mod & TLSMOD_DUPSID) {
            if (!l7_is_tls_hello(payload, plen, 1, 1))
                LOGD("xact", "(nonfatal) cannot apply dupsid tls mod. payload is not valid tls.");
            else if (plen < 44)
                LOGD("xact", "(nonfatal) cannot apply dupsid tls mod. data payload is too short.");
            else if (fake[43] != payload[43])
                LOGD("xact", "(nonfatal) cannot apply dupsid tls mod. fake and orig session id length mismatch");
            else if (plen < 44 + (size_t)payload[43])
                LOGD("xact", "(nonfatal) cannot apply dupsid tls mod. data payload is not valid.");
            else
                memcpy(fake + 44, payload + 44, fake[43]);
        }
        if (m->mod & TLSMOD_PADENCAP) {
            size_t sz_rec, sz_hs, sz_ext, sz_pad;
            if (l7_tls_find_ext(fake, *len, 21, &ext, &extlen, 0)) {
                if ((size_t)(ext - fake) + extlen != *len) {
                    LOGD("xact", "cannot apply padencap tls mod. tls padding ext is present but it's not at the end");
                    return -1;
                }
                padlen_off = (size_t)(ext - fake) - 2;
            } else {
                if (*len + 4 > cap) {
                    LOGD("xact", "tls padding is absent and there's no space to add it");
                    return -1;
                }
                w16(fake + *len, 21);
                *len += 2;
                padlen_off = *len;
                w16(fake + *len, 0);
                *len += 2;
                w16(fake + extlen_off, r16(fake + extlen_off) + 4);
                w16(fake + 3, r16(fake + 3) + 4);
                w24(fake + 6, r24(fake + 6) + 4);
            }
            sz_rec = r16(fake + 3) + plen;
            sz_hs = r24(fake + 6) + plen;
            sz_ext = r16(fake + extlen_off) + plen;
            sz_pad = r16(fake + padlen_off) + plen;
            if ((sz_rec & ~(size_t)0xffff) || (sz_hs & ~(size_t)0xffffff) || (sz_ext & ~(size_t)0xffff) ||
                (sz_pad & ~(size_t)0xffff)) {
                LOGD("xact", "(nonfatal) cannot apply padencap tls mod. length overflow.");
            } else {
                w16(fake + 3, sz_rec);
                w24(fake + 6, sz_hs);
                w16(fake + extlen_off, sz_ext);
                w16(fake + padlen_off, sz_pad);
            }
        }
    }
    return 0;
}

void tls_genhost(size_t len, const char *tmpl, char *out)
{
    size_t tl = tmpl ? strlen(tmpl) : 0;
    uint8_t *o = (uint8_t *)out;
    if (tl) {
        if (len <= tl) {
            memcpy(out, tmpl + tl - len, len);
        } else if (len == tl + 1) {
            out[0] = '.';
            memcpy(out + 1, tmpl, tl);
        } else {
            rnd_az(o, 1);
            rnd_az09(o + 1, len - tl - 2);
            out[len - tl - 1] = '.';
            memcpy(out + len - tl, tmpl, tl);
        }
    } else if (len >= 7) {
        const char *tld = tlds[rng_index(6)];
        rnd_az(o, 1);
        rnd_az09(o + 1, len - 5);
        out[len - 4] = '.';
        memcpy(out + len - 3, tld, 3);
    } else if (len) {
        rnd_az(o, 1);
        rnd_az09(o + 1, len - 1);
    }
    out[len] = 0;
}
