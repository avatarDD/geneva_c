/*
 * Ported from zapret2 nfq2/protocol.c (MIT License, Copyright (c) bol-van;
 * the notice is in docs/EXT.md). Same checks; bounds made explicit where
 * the original relied on its callers.
 */
#include "l7.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "ext.h"
#if GENEVA_EXT_CRYPTO
#  include "crypto.h"
#endif

static unsigned be16(const uint8_t *p) { return (unsigned)p[0] << 8 | p[1]; }
static uint32_t be24(const uint8_t *p) { return (uint32_t)p[0] << 16 | (uint32_t)p[1] << 8 | p[2]; }
static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | be24(p + 1); }

static const char *const proto_names[L7_LAST] = {"all", "unknown", "known", "http", "tls", "dtls",
                                                 "quic", "wireguard", "dht", "discord", "stun", "xmpp",
                                                 "dns", "mtproto", "bt", "utp_bt"};
static const char *const payload_names[L7P_LAST] = {
    "all", "unknown", "empty", "known", "ipv4", "ipv6", "icmp", "http_req", "http_reply",
    "tls_client_hello", "tls_server_hello", "dtls_client_hello", "dtls_server_hello", "quic_initial",
    "wireguard_initiation", "wireguard_response", "wireguard_cookie", "wireguard_keepalive", "wireguard_data",
    "dht", "discord_ip_discovery", "stun", "xmpp_stream", "xmpp_starttls", "xmpp_proceed", "xmpp_features",
    "dns_query", "dns_response", "mtproto_initial", "bt_handshake", "utp_bt_handshake"};

const char *l7_proto_name(int l7) { return l7 >= 0 && l7 < L7_LAST ? proto_names[l7] : NULL; }
const char *l7_payload_name(int l7p) { return l7p >= 0 && l7p < L7P_LAST ? payload_names[l7p] : NULL; }

static int by_name(const char *const *names, int n, const char *s, size_t len)
{
    for (int i = 0; i < n; i++)
        if (strlen(names[i]) == len && !memcmp(names[i], s, len))
            return i;
    return -1;
}

int l7_proto_by_name(const char *s) { return by_name(proto_names, L7_LAST, s, strlen(s)); }
int l7_payload_by_name(const char *s) { return by_name(payload_names, L7P_LAST, s, strlen(s)); }

int l7_proto_match(int l7, uint64_t f)
{
    return !f || (f >> l7 & 1) || ((f >> L7_KNOWN & 1) && l7 > L7_KNOWN && l7 < L7_LAST);
}

int l7_payload_match(int l7p, uint64_t f)
{
    return !f || (f >> l7p & 1) || ((f >> L7P_KNOWN & 1) && l7p > L7P_KNOWN && l7p < L7P_LAST);
}

static int name_list(const char *s, const char *const *names, int n, const char *what, uint64_t *set, int *neg,
                     sbuf *err)
{
    const char *p = s;
    *set = 0;
    *neg = 0;
    if (*p == '~') {
        *neg = 1;
        p++;
    }
    for (;;) {
        const char *e = strchr(p, ',');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        int i = by_name(names, n, p, len);
        if (i < 0) {
            sb_printf(err, "unknown %s \"%.*s\" in \"%s\"", what, (int)len, p, s);
            return -1;
        }
        if (i == 0) {
            *set = 0; /* "all" */
            return e ? (sb_printf(err, "\"all\" cannot be listed with others in \"%s\"", s), -1) : 0;
        }
        *set |= 1ULL << i;
        if (!e)
            return 0;
        p = e + 1;
    }
}

int l7_payload_list(const char *s, uint64_t *set, int *neg, sbuf *err)
{
    return name_list(s, payload_names, L7P_LAST, "payload", set, neg, err);
}

int l7_proto_list(const char *s, uint64_t *set, int *neg, sbuf *err)
{
    return name_list(s, proto_names, L7_LAST, "protocol", set, neg, err);
}

/* ---- domains ------------------------------------------------------------- */

int l7_find_nld(const uint8_t *dom, size_t dlen, int level, const uint8_t **p, size_t *len)
{
    const uint8_t *p1, *p2;
    if (level < 1 || !dlen)
        return 0;
    p2 = dom + dlen;
    for (int i = 1; i < level; i++) {
        for (p2--; p2 > dom && *p2 != '.'; p2--)
            ;
        if (p2 <= dom)
            return 0;
    }
    for (p1 = p2 - 1; p1 > dom && *p1 != '.'; p1--)
        ;
    if (*p1 == '.')
        p1++;
    if (p)
        *p = p1;
    if (len)
        *len = (size_t)(p2 - p1);
    return 1;
}

/* ---- HTTP ---------------------------------------------------------------- */

static const char *const methods[] = {"GET ", "POST ", "HEAD ", "OPTIONS ", "PUT ", "DELETE ", "CONNECT ",
                                      "TRACE ", "PATCH ", NULL};

int l7_is_http(const uint8_t *d, size_t n)
{
    int m = 0;
    if (n >= 4)
        for (const char *const *x = methods; *x && !m; x++)
            m = strlen(*x) <= n && !memcmp(d, *x, strlen(*x));
    if (!m)
        return 0;
    for (; n && *d != ' ' && *d != '\t' && *d != '\r' && *d != '\n'; d++, n--)
        ;
    if (!n || (*d != ' ' && *d != '\t'))
        return 0;
    for (; n && (*d == ' ' || *d == '\t'); d++, n--)
        ;
    for (; n && *d != ' ' && *d != '\t' && *d != '\r' && *d != '\n'; d++, n--)
        ;
    if (!n || (*d != ' ' && *d != '\t'))
        return 0;
    for (; n && (*d == ' ' || *d == '\t'); d++, n--)
        ;
    if (n < 10 || *d == '\r' || *d == '\n')
        return 0;
    return !memcmp(d, "HTTP/1.", 7);
}

int l7_is_http_reply(const uint8_t *d, size_t n)
{
    return n > 14 && !memcmp(d, "HTTP/1.", 7) && (d[7] == '0' || d[7] == '1') && d[8] == ' ' && isdigit(d[9]) &&
           isdigit(d[10]) && isdigit(d[11]);
}

int l7_http_reply_code(const uint8_t *d, size_t n)
{
    return l7_is_http_reply(d, n) ? (d[9] - '0') * 100 + (d[10] - '0') * 10 + (d[11] - '0') : -1;
}

static const uint8_t *find_ci(const uint8_t *s, size_t n, const char *x)
{
    size_t k = strlen(x);
    for (size_t i = 0; k && i + k <= n; i++) {
        size_t j = 0;
        while (j < k && toupper(s[i + j]) == toupper((unsigned char)x[j]))
            j++;
        if (j == k)
            return s + i;
    }
    return NULL;
}

int l7_http_header(const uint8_t *d, size_t n, const char *hdr, char *out, size_t cap)
{
    const uint8_t *p = find_ci(d, n, hdr), *e = d + n, *s;
    if (!p)
        return 0;
    p += strlen(hdr);
    while (p < e && (*p == ' ' || *p == '\t'))
        p++;
    for (s = p; s < e && *s != '\r' && *s != '\n' && *s != ' ' && *s != '\t'; s++)
        ;
    if (s == p)
        return 0;
    if (out && cap) {
        size_t l = (size_t)(s - p) < cap ? (size_t)(s - p) : cap - 1;
        for (size_t i = 0; i < l; i++)
            out[i] = (char)tolower(p[i]);
        out[l] = 0;
    }
    return 1;
}

int l7_http_host(const uint8_t *d, size_t n, char *out, size_t cap) { return l7_http_header(d, n, "\nHost:", out, cap); }

int l7_http_dpi_redirect(const uint8_t *d, size_t n, const char *host)
{
    char loc[256], *rh, *p;
    const uint8_t *dh, *drh;
    size_t dl, drl;
    (void)dl;
    (void)drl;
    int code = l7_http_reply_code(d, n);
    if (!host || !*host || (code != 302 && code != 307) || !l7_http_header(d, n, "\nLocation:", loc, sizeof(loc)))
        return 0;
    if (!strncmp(loc, "http://", 7))
        rh = loc + 7;
    else if (!strncmp(loc, "https://", 8))
        rh = loc + 8;
    else
        return 0;
    for (p = rh; *p && *p != '/' && *p != '?' && *p != '#'; p++)
        ;
    *p = 0;
    if (!*rh || !l7_find_nld((const uint8_t *)rh, strlen(rh), 2, &drh, &drl))
        return 0;
    if (!l7_find_nld((const uint8_t *)host, strlen(host), 2, &dh, &dl))
        return 1; /* no SLD redirects to an SLD */
    /* zapret2 compares the strings from the SLD to their ends */
    if (strlen((const char *)dh) != strlen((const char *)drh))
        return 1;
    for (; *dh; dh++, drh++)
        if (tolower(*dh) != tolower(*drh))
            return 1;
    return 0;
}

/* ---- TLS ----------------------------------------------------------------- */

size_t l7_tls_record_len(const uint8_t *d) { return (size_t)be16(d + 3) + 5; }
size_t l7_tls_hs_len(const uint8_t *d) { return (size_t)be24(d + 1) + 4; }

int l7_is_tls_hs_hello(const uint8_t *d, size_t n, uint8_t type, int partial_ok)
{
    return n >= 6 && ((type && d[0] == type) || (!type && (d[0] == 1 || d[0] == 2))) && d[4] == 3 && d[5] <= 3 &&
           (partial_ok || l7_tls_hs_len(d) <= n);
}

int l7_is_tls_hello(const uint8_t *d, size_t n, uint8_t type, int partial_ok)
{
    return n >= 6 && d[0] == 0x16 && d[1] == 3 && d[2] <= 3 && (partial_ok || l7_tls_record_len(d) <= n) &&
           l7_is_tls_hs_hello(d + 5, n - 5, type, partial_ok);
}

static int hs_ext_len_off(const uint8_t *d, size_t n, size_t *off)
{
    size_t l = 1 + 3 + 2 + 32;
    if (n < l + 1)
        return 0;
    l += (size_t)d[l] + 1;
    if (n < l + 2)
        return 0;
    if (d[0] == 1)
        l += be16(d + l);
    l += 2;
    if (n < l + 1)
        return 0;
    if (d[0] == 1)
        l += d[l];
    l++;
    if (n < l + 2)
        return 0;
    *off = l;
    return 1;
}

int l7_tls_ext_len_off(const uint8_t *d, size_t n, size_t *off)
{
    if (n < 5 || !hs_ext_len_off(d + 5, n - 5, off))
        return 0;
    *off += 5;
    return 1;
}

int l7_tls_hs_find_ext(const uint8_t *d, size_t n, uint16_t type, const uint8_t **ext, size_t *len, int partial_ok)
{
    size_t l;
    if (n < 4 || (!partial_ok && l7_tls_hs_len(d) > n) || !hs_ext_len_off(d, n, &l))
        return 0;
    d += l;
    n -= l;
    l = be16(d);
    d += 2;
    n -= 2;
    if (n < l) {
        if (!partial_ok)
            return 0;
        l = n;
    }
    while (l >= 4) {
        unsigned et = be16(d);
        size_t el = be16(d + 2);
        d += 4;
        l -= 4;
        if (l < el)
            break;
        if (et == type) {
            if (ext && len) {
                *ext = d;
                *len = el;
            }
            return 1;
        }
        d += el;
        l -= el;
    }
    return 0;
}

int l7_tls_find_ext(const uint8_t *d, size_t n, uint16_t type, const uint8_t **ext, size_t *len, int partial_ok)
{
    size_t rl;
    if (!l7_is_tls_hello(d, n, 0, partial_ok))
        return 0;
    rl = l7_tls_record_len(d);
    if (rl < n)
        n = rl;
    return l7_tls_hs_find_ext(d + 5, n - 5, type, ext, len, partial_ok);
}

int l7_tls_sni_host(const uint8_t **ext, size_t *elen, size_t *slen)
{
    size_t nll;
    if (*elen < 5 || (*ext)[2] != 0)
        return 0;
    nll = be16(*ext);
    *slen = be16(*ext + 3);
    if (nll < *slen + 3 || nll > *elen - 2)
        return 0;
    *ext += 5;
    *elen -= 5;
    return 1;
}

static int sni_out(const uint8_t *ext, size_t elen, char *out, size_t cap)
{
    size_t sl;
    if (!l7_tls_sni_host(&ext, &elen, &sl))
        return 0;
    if (out && cap) {
        if (sl >= cap)
            sl = cap - 1;
        for (size_t i = 0; i < sl; i++)
            out[i] = (char)tolower(ext[i]);
        out[sl] = 0;
    }
    return 1;
}

int l7_tls_host(const uint8_t *d, size_t n, char *out, size_t cap, int partial_ok)
{
    const uint8_t *e;
    size_t el;
    return l7_tls_find_ext(d, n, 0, &e, &el, partial_ok) && sni_out(e, el, out, cap);
}

int l7_tls_hs_host(const uint8_t *d, size_t n, char *out, size_t cap, int partial_ok)
{
    const uint8_t *e;
    size_t el;
    return l7_tls_hs_find_ext(d, n, 0, &e, &el, partial_ok) && sni_out(e, el, out, cap);
}

/* ---- QUIC ---------------------------------------------------------------- */

static size_t vsize(uint8_t b) { return (size_t)1 << (b >> 6); }

static size_t vget(const uint8_t *p, uint64_t *v)
{
    size_t l = vsize(p[0]);
    *v = p[0] & 0x3f;
    for (size_t i = 1; i < l; i++)
        *v = *v << 8 | p[i];
    return l;
}

static int quic_v2(uint32_t v) { return v == 0x709A50C4u || v == 0x6b3343cfu; }

int l7_quic_draft(uint32_t v)
{
    if (v >> 8 == 0xff0000u)
        return (int)(v & 0xff);
    if (v == 0xfaceb001u)
        return 22;
    if (v == 0xfaceb002u || v == 0xfaceb00eu)
        return 27;
    if (v == 0x51303530u || v == 0x54303530u || v == 0x54303531u)
        return 27;
    if ((v & 0x0F0F0F0Fu) == 0x0a0a0a0au)
        return 29;
    if (v == 1)
        return 34;
    if (quic_v2(v))
        return 100;
    return 0;
}

int l7_is_quic_initial(const uint8_t *d, size_t n)
{
    uint32_t v;
    uint64_t off = 5, sz, sz2;
    if (n < 128 || !(d[0] & 0x80))
        return 0;
    v = be32(d + 1);
    if (l7_quic_draft(v) < 11)
        return 0;
    if ((d[0] & 0xF0) != (quic_v2(v) ? 0xD0 : 0xC0))
        return 0;
    if (d[off] > 20)
        return 0;
    off += 1 + d[off];
    if (off >= n || d[off] > 20)
        return 0;
    off += 1 + d[off];
    if (off >= n || off + vsize(d[off]) > n)
        return 0;
    off += vget(d + off, &sz);
    off += sz;
    if (off >= n)
        return 0;
    sz2 = vsize(d[off]);
    if (off + sz2 > n)
        return 0;
    vget(d + off, &sz);
    off += sz2 + sz;
    return off <= n;
}

int l7_quic_crypto_hello(const uint8_t *d, size_t n, size_t *hoff, size_t *hlen)
{
    size_t off = 1;
    uint64_t coff, clen;
    if (n < 3 || d[0] != 6 || off + vsize(d[off]) >= n)
        return 0;
    off += vget(d + off, &coff);
    if (coff || off + vsize(d[off]) >= n)
        return 0;
    off += vget(d + off, &clen);
    if (clen > n - off || !l7_is_tls_hs_hello(d + off, (size_t)clen, 1, 1))
        return 0;
    if (hoff)
        *hoff = off;
    if (hlen)
        *hlen = (size_t)clen;
    return 1;
}

#define MAX_DEFRAG_PIECES 128

typedef struct {
    uint64_t off, len;
} range64;

static int cmp_range(const void *a, const void *b)
{
    const range64 *x = a, *y = b;
    return x->off < y->off ? -1 : x->off > y->off;
}

int l7_quic_defrag(const uint8_t *clean, size_t n, uint8_t *out, size_t *outlen, int *full)
{
    uint8_t *data;
    size_t dcap, pos = 0;
    uint64_t off, sz, szmax = 0, zeropos = 0;
    int found = 0, nr = 0;
    range64 r[MAX_DEFRAG_PIECES];
    if (*outlen < 10)
        return 0;
    data = out + 10;
    dcap = *outlen - 10;
    while (pos < n) {
        uint8_t ft = clean[pos++];
        if (ft <= 1)
            continue; /* PADDING, PING */
        if (ft != 6 || pos >= n || nr >= MAX_DEFRAG_PIECES)
            return 0;
        if (pos + vsize(clean[pos]) >= n)
            return 0;
        pos += vget(clean + pos, &off);
        if (pos + vsize(clean[pos]) > n)
            return 0;
        pos += vget(clean + pos, &sz);
        if (sz > n - pos || off > dcap || sz > dcap - off)
            return 0;
        for (int i = 0; i < nr; i++)
            if (r[i].off == off && r[i].len == sz)
                goto skip;
        if (zeropos < off)
            memset(data + zeropos, 0, (size_t)(off - zeropos));
        if (off + sz > zeropos)
            zeropos = off + sz;
        found = 1;
        if (off + sz > szmax)
            szmax = off + sz;
        memcpy(data + off, clean + pos, (size_t)sz);
        r[nr].off = off;
        r[nr].len = sz;
        nr++;
    skip:
        pos += (size_t)sz;
    }
    if (!found)
        return 0;
    qsort(r, (size_t)nr, sizeof(*r), cmp_range);
    {
        int j = 0;
        for (int i = 1; i < nr; i++) {
            uint64_t cend = r[j].off + r[j].len, nend = r[i].off + r[i].len;
            if (r[i].off <= cend)
                r[j].len = (nend > cend ? nend : cend) - r[j].off;
            else
                r[++j] = r[i];
        }
        nr = j + 1;
    }
    out[0] = 6;
    out[1] = 0;
    for (int i = 0; i < 8; i++)
        out[2 + i] = (uint8_t)(szmax >> (56 - 8 * i));
    out[2] |= 0xC0;
    *outlen = (size_t)szmax + 10;
    *full = nr == 1 && !r[0].off;
    return 1;
}

/* ---- the small ones -------------------------------------------------------- */

int l7_is_xmpp_stream(const uint8_t *d, size_t n)
{
    if (n >= 16 && !memcmp(d, "<stream:stream ", 15))
        return 1;
    if (n >= 36 && !memcmp(d, "<?xml ", 6))
        for (size_t i = 21; i + 15 <= n; i++)
            if (!memcmp(d + i, "<stream:stream ", 15))
                return 1;
    return 0;
}

static int xmpp_starttls(const uint8_t *d, size_t n) { return n >= 10 && !memcmp(d, "<starttls ", 10); }
static int xmpp_proceed(const uint8_t *d, size_t n) { return n >= 9 && !memcmp(d, "<proceed ", 9); }
static int xmpp_features(const uint8_t *d, size_t n) { return n >= 17 && !memcmp(d, "<stream:features", 16); }

int l7_is_dns_query(const uint8_t *d, size_t n)
{
    return n >= 12 && !(d[2] & 0xFE) && !memcmp(d + 4, "\x00\x01\x00\x00\x00\x00", 6) && be16(d + 10) <= 3;
}

int l7_is_dns_response(const uint8_t *d, size_t n)
{
    return n >= 12 && (d[2] & 0xF8) == 0x80 && be16(d + 4) == 1 && be16(d + 6) <= 100 && be16(d + 8) <= 100 &&
           be16(d + 10) <= 100;
}

static int wg(const uint8_t *d, size_t n, size_t want, uint32_t t) { return n == want && be32(d) == t; }
static int wg_init(const uint8_t *d, size_t n) { return wg(d, n, 148, 0x01000000u); }
static int wg_resp(const uint8_t *d, size_t n) { return wg(d, n, 92, 0x02000000u); }
static int wg_cookie(const uint8_t *d, size_t n) { return wg(d, n, 64, 0x03000000u); }
static int wg_keepalive(const uint8_t *d, size_t n) { return wg(d, n, 32, 0x04000000u); }
static int wg_data(const uint8_t *d, size_t n) { return n >= 52 && be32(d) == 0x04000000u; }

int l7_is_dht(const uint8_t *d, size_t n)
{
    return n >= 5 && d[0] == 'd' && d[2] == ':' && d[n - 1] == 'e' &&
           ((d[1] == '1' && d[3] == 'a' && d[4] == 'd') || (d[1] == '1' && d[3] == 'r' && d[4] == 'd') ||
            (d[1] == '2' && d[3] == 'i' && d[4] == 'p') || (d[1] == '1' && d[3] == 'e' && d[4] == 'l'));
}

static int discord(const uint8_t *d, size_t n)
{
    static const uint8_t zero[64];
    return n == 74 && d[0] == 0 && d[1] == 1 && d[2] == 0 && d[3] == 70 && !memcmp(d + 8, zero, 64);
}

int l7_is_stun(const uint8_t *d, size_t n)
{
    return n >= 20 && !(d[0] & 0xC0) && !(d[3] & 3) && be32(d + 4) == 0x2112A442u && be16(d + 2) <= n - 20;
}

int l7_is_mtproto(const uint8_t *d, size_t n)
{
#if GENEVA_EXT_CRYPTO
    /* the obfuscated2 header: AES-256-CTR, key d[8..40), iv d[40..56);
     * bytes 56..59 decrypt to EF EF EF EF (one block: the 4th of the stream) */
    aes_ctx c;
    uint8_t iv[16], ks[16];
    unsigned carry = 3;
    if (n < 64 || aes_init(&c, d + 8, 32) < 0)
        return 0;
    memcpy(iv, d + 40, 16);
    for (int i = 15; i >= 0 && carry; i--) {
        carry += iv[i];
        iv[i] = (uint8_t)carry;
        carry >>= 8;
    }
    aes_encrypt_block(&c, iv, ks);
    secure_zero(&c, sizeof(c));
    for (int i = 0; i < 4; i++)
        if ((ks[8 + i] ^ d[56 + i]) != 0xEF)
            return 0;
    return 1;
#else
    (void)d;
    (void)n;
    return 0;
#endif
}

int l7_is_dtls(const uint8_t *d, size_t n)
{
    return n > 13 && d[0] >= 0x14 && d[0] <= 0x17 &&
           ((d[1] == 0xfe && (d[2] == 0xff || d[2] == 0xfd || d[2] == 0xfc)) || (d[1] == 1 && d[2] == 0)) &&
           be16(d + 11) + 13 <= n;
}

static int dtls_ch(const uint8_t *d, size_t n) { return l7_is_dtls(d, n) && d[0] == 0x16 && d[13] == 1; }
static int dtls_sh(const uint8_t *d, size_t n) { return l7_is_dtls(d, n) && d[0] == 0x16 && d[13] == 2; }

static int bt(const uint8_t *d, size_t n) { return n >= 68 && !memcmp(d, "\x13" "BitTorrent protocol", 20); }
static int utp_bt(const uint8_t *d, size_t n)
{
    return n >= 88 && d[0] == 1 && !memcmp(d + 20, "\x13" "BitTorrent protocol", 20);
}

static int tls_ch(const uint8_t *d, size_t n) { return l7_is_tls_hello(d, n, 1, 1); }
static int tls_sh(const uint8_t *d, size_t n) { return l7_is_tls_hello(d, n, 2, 1); }

/* ---- probing (desync.c protocol_probe) ------------------------------------- */

typedef struct {
    uint8_t l7p, l7, same_proto; /* same_proto: only when the flow is already l7 */
    int (*check)(const uint8_t *, size_t);
} probe;

static const probe tcp_client[] = {
    {L7P_TLS_CLIENT_HELLO, L7_TLS, 0, tls_ch},   {L7P_HTTP_REQ, L7_HTTP, 0, l7_is_http},
    {L7P_XMPP_STREAM, L7_XMPP, 0, l7_is_xmpp_stream}, {L7P_XMPP_STARTTLS, L7_XMPP, 0, xmpp_starttls},
    {L7P_BT_HANDSHAKE, L7_BT, 0, bt},
};
static const probe tcp_server[] = {
    {L7P_TLS_SERVER_HELLO, L7_TLS, 0, tls_sh},    {L7P_HTTP_REPLY, L7_HTTP, 0, l7_is_http_reply},
    {L7P_XMPP_STREAM, L7_XMPP, 0, l7_is_xmpp_stream}, {L7P_XMPP_PROCEED, L7_XMPP, 0, xmpp_proceed},
    {L7P_XMPP_FEATURES, L7_XMPP, 0, xmpp_features}, {L7P_BT_HANDSHAKE, L7_BT, 0, bt},
};
static const probe mtproto[] = {{L7P_MTPROTO_INITIAL, L7_MTPROTO, 0, l7_is_mtproto}};
static const probe udp[] = {
    {L7P_QUIC_INITIAL, L7_QUIC, 0, l7_is_quic_initial},
    {L7P_DISCORD_IP_DISCOVERY, L7_DISCORD, 0, discord},
    {L7P_STUN, L7_STUN, 0, l7_is_stun},
    {L7P_DNS_QUERY, L7_DNS, 0, l7_is_dns_query},
    {L7P_DNS_RESPONSE, L7_DNS, 0, l7_is_dns_response},
    {L7P_DHT, L7_DHT, 0, l7_is_dht},
    {L7P_DTLS_CLIENT_HELLO, L7_DTLS, 0, dtls_ch},
    {L7P_DTLS_SERVER_HELLO, L7_DTLS, 0, dtls_sh},
    {L7P_UTP_BT_HANDSHAKE, L7_UTP_BT, 0, utp_bt},
    {L7P_WIREGUARD_INITIATION, L7_WIREGUARD, 0, wg_init},
    {L7P_WIREGUARD_RESPONSE, L7_WIREGUARD, 0, wg_resp},
    {L7P_WIREGUARD_COOKIE, L7_WIREGUARD, 0, wg_cookie},
    {L7P_WIREGUARD_KEEPALIVE, L7_WIREGUARD, 0, wg_keepalive},
    {L7P_WIREGUARD_DATA, L7_WIREGUARD, 1, wg_data},
};

static int run_probes(const probe *pr, size_t np, const uint8_t *d, size_t n, uint64_t disable, int *l7)
{
    for (size_t i = 0; i < np; i++) {
        if ((disable && l7_payload_match(pr[i].l7p, disable)) || (pr[i].same_proto && *l7 != pr[i].l7) ||
            !pr[i].check(d, n))
            continue;
        if (*l7 == L7_UNKNOWN)
            *l7 = pr[i].l7;
        return pr[i].l7p;
    }
    return L7P_UNKNOWN;
}

int l7_probe(const uint8_t *d, size_t n, int tcp, int from_server, int first_data, uint64_t disable, int *l7)
{
    int r;
#define NP(a) (sizeof(a) / sizeof(*(a)))
    if (!n)
        return L7P_EMPTY;
    if (!tcp)
        return run_probes(udp, NP(udp), d, n, disable, l7);
    if (from_server)
        return run_probes(tcp_server, NP(tcp_server), d, n, disable, l7);
    r = run_probes(tcp_client, NP(tcp_client), d, n, disable, l7);
    if (r == L7P_UNKNOWN && first_data)
        r = run_probes(mtproto, NP(mtproto), d, n, disable, l7);
    return r;
#undef NP
}
