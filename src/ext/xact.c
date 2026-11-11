/*
 * x-actions: parsing, the common arguments, the per-flow state and the
 * sending path (zapret2's zapret-lib.lua: apply_fooling, apply_ip_id,
 * rawsend_dissect_ipfrag, rawsend_dissect_segmented, ipfrag2).
 */
#include "xact.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blob.h"
#include "l7.h"
#include "log.h"
#include "rng.h"
#include "seqtrack.h"

static const xa_kind *const kinds[] = {
    &xa_send,     &xa_mod,    &xa_fake,  &xa_split,  &xa_disorder, &xa_tcpseg,  &xa_hostfake,
    &xa_fakedsplit, &xa_fakeddisorder, &xa_synacksplit, &xa_synack, &xa_wsize, &xa_wssize, &xa_syndata,
    &xa_rst,      &xa_http,   &xa_tlsclone, &xa_udplen, &xa_dhtdn, &xa_xlog,  &xa_tag,     &xa_pcap,
    &xa_when,     &xa_stop,   &xa_repeat, &xa_cutoffk, &xa_oob,    &xa_tlsrec, &xa_drip,
};

/* ---- keys ------------------------------------------------------------------ */

typedef struct {
    const char *name, *canon;
    int group;
} std_key;

/* the roadmap's names and zapret2's */
static const std_key std_keys[] = {
    {"ttl", "ttl", XS_FOOL},
    {"ip_ttl", "ip_ttl", XS_FOOL},
    {"ip6_ttl", "ip6_ttl", XS_FOOL},
    {"ip_autottl", "ip_autottl", XS_FOOL},
    {"ip6_autottl", "ip6_autottl", XS_FOOL},
    {"ip6ext", "ip6ext", XS_FOOL},
    {"ip6_hopbyhop", "ip6_hopbyhop", XS_FOOL},
    {"ip6_hopbyhop2", "ip6_hopbyhop2", XS_FOOL},
    {"ip6_destopt", "ip6_destopt", XS_FOOL},
    {"ip6_destopt2", "ip6_destopt2", XS_FOOL},
    {"ip6_routing", "ip6_routing", XS_FOOL},
    {"ip6_ah", "ip6_ah", XS_FOOL},
    {"seq", "seq", XS_FOOL},
    {"tcp_seq", "seq", XS_FOOL},
    {"ack", "ack", XS_FOOL},
    {"tcp_ack", "ack", XS_FOOL},
    {"ts", "ts", XS_FOOL},
    {"tcp_ts", "ts", XS_FOOL},
    {"md5", "md5", XS_FOOL},
    {"tcp_md5", "md5", XS_FOOL},
    {"flags+", "flags+", XS_FOOL},
    {"tcp_flags_set", "flags+", XS_FOOL},
    {"flags-", "flags-", XS_FOOL},
    {"tcp_flags_unset", "flags-", XS_FOOL},
    {"tsup", "tsup", XS_FOOL},
    {"tcp_ts_up", "tsup", XS_FOOL},
    {"nopdel", "nopdel", XS_FOOL},
    {"tcp_nop_del", "nopdel", XS_FOOL},
    {"badsum", "badsum", XS_RECON},
    {"repeats", "repeats", XS_SEND},
    {"ifout", "ifout", XS_SEND},
    {"fwmark", "fwmark", XS_SEND},
    {"ipid", "ipid", XS_IPID},
    {"ip_id", "ipid", XS_IPID},
    {"ipid_conn", "ipid_conn", XS_IPID},
    {"ip_id_conn", "ipid_conn", XS_IPID},
    {"ipfrag", "ipfrag", XS_FRAG},
    {"ipfrag_disorder", "ipfrag_disorder", XS_FRAG},
    {"ipfrag_pos_tcp", "ipfrag_pos_tcp", XS_FRAG},
    {"ipfrag_pos_udp", "ipfrag_pos_udp", XS_FRAG},
    {"ipfrag_pos_icmp", "ipfrag_pos_icmp", XS_FRAG},
    {"ipfrag_pos", "ipfrag_pos", XS_FRAG},
    {"ipfrag_next", "ipfrag_next", XS_FRAG},
    {"payload", "payload", XS_PAYLOAD},
};

/* keys that are flags: no value */
static int is_flag_key(const char *k)
{
    static const char *const flags[] = {"tsup", "nopdel", "badsum", "ipid_conn", "ipfrag_disorder", NULL};
    for (int i = 0; flags[i]; i++)
        if (!strcmp(k, flags[i]))
            return 1;
    return 0;
}

static const char *canon_key(const xa_kind *k, const char *name)
{
    for (size_t i = 0; i < ARRAY_LEN(std_keys); i++)
        if (!strcmp(std_keys[i].name, name) && (k->std & std_keys[i].group))
            return std_keys[i].canon;
    for (int i = 0; k->keys && k->keys[i]; i++)
        if (!strcmp(k->keys[i], name))
            return k->keys[i];
    return NULL;
}

static const xparam *find(const xact *a, const char *key)
{
    for (int i = 0; i < a->np; i++)
        if (!strcmp(a->p[i].k, key))
            return &a->p[i];
    return NULL;
}

int xa_has(const xact *a, const char *key) { return find(a, key) != NULL; }

const char *xa_raw(const xact *a, const char *key)
{
    const xparam *p = find(a, key);
    return p ? p->v : NULL;
}

/* ---- the packet's own state --------------------------------------------------- */

typedef struct xdblob {
    struct xdblob *next;
    char name[BLOB_NAME_MAX];
    size_t len;
    uint8_t *data;
} xdblob;

typedef struct {
    xdblob *blobs;
    int tagged;
    char tag[256];
} xa_dyn;

static void dyn_done(void *x)
{
    xa_dyn *d = x;
    while (d->blobs) {
        xdblob *b = d->blobs;
        d->blobs = b->next;
        free(b->data);
        free(b);
    }
    free(d);
}

static xa_dyn *dyn(xrun *r, int create)
{
    void **slot = r->env ? r->env->dyn : NULL;
    if (!slot)
        return NULL;
    if (!*slot && create)
        *slot = xcalloc(1, sizeof(xa_dyn));
    return *slot;
}

static const xdblob *dyn_blob(xrun *r, const char *name)
{
    xa_dyn *d = dyn(r, 0);
    for (const xdblob *b = d ? d->blobs : NULL; b; b = b->next)
        if (!strcmp(b->name, name))
            return b;
    return NULL;
}

int xa_dyn_has(xrun *r, const char *name) { return dyn_blob(r, name) != NULL; }

void xa_dyn_blob_set(xrun *r, const char *name, const uint8_t *data, size_t n)
{
    xa_dyn *d = dyn(r, 1);
    xdblob *b;
    if (!d || strlen(name) >= BLOB_NAME_MAX)
        return;
    for (b = d->blobs; b; b = b->next)
        if (!strcmp(b->name, name))
            break;
    if (!b) {
        b = xcalloc(1, sizeof(*b));
        snprintf(b->name, sizeof(b->name), "%s", name);
        b->next = d->blobs;
        d->blobs = b;
    }
    free(b->data);
    b->data = xmalloc(n ? n : 1);
    if (n)
        memcpy(b->data, data, n);
    b->len = n;
}

void xa_set_tag(xrun *r, const char *label)
{
    xa_dyn *d = dyn(r, 1);
    if (!d)
        return;
    snprintf(d->tag, sizeof(d->tag), "%s", label);
    d->tagged = 1;
    r->l7name = d->tag;
    r->l7p = l7_payload_by_name(label);
    if (r->l7p < 0)
        r->l7p = L7P_UNKNOWN;
}

const uint8_t *xa_blob_named(xrun *r, const char *name, size_t *len)
{
    const xdblob *d = dyn_blob(r, name);
    const xblob *b;
    if (d) {
        *len = d->len;
        return d->data;
    }
    b = blob_find(name);
    if (!b)
        return NULL;
    *len = b->len;
    return b->data;
}

void xa_modified(gpkt *p)
{
    p->auto_fields |= XA_AUTO;
    pkt_mark_dirty(p);
}

/* ---- numbers --------------------------------------------------------------- */

/* Lua's tonumber for integers: an optional sign, decimal or 0x hex */
static int num(const char *s, size_t n, int64_t *v)
{
    int neg = 0, base = 10;
    uint64_t x = 0;
    size_t i = 0;
    if (i < n && (s[i] == '-' || s[i] == '+'))
        neg = s[i++] == '-';
    if (i + 1 < n && s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X'))
        base = 16, i += 2;
    if (i == n)
        return -1;
    for (; i < n; i++) {
        int d;
        char c = s[i];
        if (c >= '0' && c <= '9')
            d = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f')
            d = c - 'a' + 10;
        else if (base == 16 && c >= 'A' && c <= 'F')
            d = c - 'A' + 10;
        else
            return -1;
        if (x > (UINT64_MAX - (uint64_t)d) / (uint64_t)base || x * (uint64_t)base + (uint64_t)d > (uint64_t)INT64_MAX)
            return -1;
        x = x * (uint64_t)base + (uint64_t)d;
    }
    *v = neg ? -(int64_t)x : (int64_t)x;
    return 0;
}

static int numz(const char *s, int64_t *v) { return num(s, strlen(s), v); }

int xa_parse_int(const char *s, int64_t *v) { return numz(s, v); }

/* ---- logging --------------------------------------------------------------- */

void xa_log(const xrun *r, const char *fmt, ...)
{
    char b[512];
    va_list ap;
    if (!log_enabled(LOG_DEBUG))
        return;
    va_start(ap, fmt);
    vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    LOGD("xact", "%s: %s", r->a->kind->name, b);
}

/* ---- argument values ----------------------------------------------------------- */

const char *xa_arg(xrun *r, const char *key, size_t *len)
{
    const xparam *p = find(r->a, key);
    const char *v;
    size_t n = 0;
    if (!p) {
        if (len)
            *len = 0;
        return NULL;
    }
    v = p->v ? p->v : "";
    if (v[0] == '#' || v[0] == '%') {
        const uint8_t *b = xa_blob_named(r, v + 1, &n);
        char *dst;
        if (r->nscratch >= 2)
            r->nscratch = 0; /* two values live at a time at most */
        dst = (char *)r->scratch[r->nscratch++];
        if (!b) {
            xa_log(r, "blob \"%s\" of %s unavailable", v + 1, key);
            return NULL;
        }
        if (v[0] == '#') {
            snprintf(dst, 256, "%zu", n);
            if (len)
                *len = strlen(dst);
            return dst;
        }
        if (n > 255) {
            xa_log(r, "blob \"%s\" is too long for %s", v + 1, key);
            return NULL;
        }
        memcpy(dst, b, n);
        dst[n] = 0;
        if (len)
            *len = n;
        return dst;
    }
    if (v[0] == '\\' && (v[1] == '#' || v[1] == '%'))
        v++;
    if (len)
        *len = strlen(v);
    return v;
}

int xa_num(xrun *r, const char *key, int64_t def, int64_t lo, int64_t hi, int64_t *out)
{
    size_t n;
    const char *v = xa_arg(r, key, &n);
    if (!find(r->a, key)) {
        *out = def;
        return 0;
    }
    if (!v || num(v, n, out) < 0 || *out < lo || *out > hi) {
        LOGW("xact", "%s: bad %s", r->a->kind->name, key);
        return -1;
    }
    return 0;
}

int xa_blob_exists(xrun *r, const char *name)
{
    size_t n;
    return name && ((name[0] == '0' && (name[1] == 'x' || name[1] == 'X')) || xa_blob_named(r, name, &n));
}

const uint8_t *xa_blob(xrun *r, const char *name, size_t *len, int optional)
{
    if (name[0] == '0' && (name[1] == 'x' || name[1] == 'X')) {
        /* checked at parse time; decoded into the scratch */
        uint8_t *b;
        size_t n;
        uint8_t *dst;
        if (blob_hex(name, 255, &b, &n) < 0)
            return NULL;
        if (r->nscratch >= 2)
            r->nscratch = 0;
        dst = r->scratch[r->nscratch++];
        memcpy(dst, b, n);
        free(b);
        *len = n;
        return dst;
    }
    {
        const uint8_t *b = xa_blob_named(r, name, len);
        if (!b && !optional)
            LOGW("xact", "%s: blob \"%s\" unavailable", r->a->kind->name, name);
        return b;
    }
}

void xa_pattern(const uint8_t *pat, size_t plen, size_t offset, uint8_t *out, size_t len)
{
    size_t off = (offset - 1) % plen;
    for (size_t i = 0; i < len; i++)
        out[i] = pat[(off + i) % plen];
}

/* ---- the common arguments ----------------------------------------------------- */

static int ttl_val(const char *s, int *t)
{
    int64_t v;
    if (numz(s, &v) < 0 || v < 0 || v > 255)
        return -1;
    *t = (int)v;
    return 0;
}

/* zapret2's parse_autottl "delta,min-max"; ours "auto:delta:min-max" */
static int attl_val(const char *s, char sep, int *d, int *mn, int *mx)
{
    char b[64];
    char *a, *m;
    int64_t dv, nv, xv;
    if (strlen(s) >= sizeof(b))
        return -1;
    strcpy(b, s);
    if (!(a = strchr(b, sep)) || !(m = strchr(a + 1, '-')))
        return -1;
    *a = 0;
    *m = 0;
    if (numz(b, &dv) < 0 || numz(a + 1, &nv) < 0 || numz(m + 1, &xv) < 0 || dv < -255 || dv > 255 || nv < 0 ||
        xv > 255 || nv > xv)
        return -1;
    *d = (int)dv, *mn = (int)nv, *mx = (int)xv;
    return 0;
}

static int hex_into(const char *s, uint8_t *out, size_t cap, uint8_t *len)
{
    uint8_t *b;
    size_t n;
    if (blob_hex(s, cap, &b, &n) < 0)
        return -1;
    memcpy(out, b, n);
    *len = (uint8_t)n;
    free(b);
    return 0;
}

/* an IPv6 extension header's data: 6+8N bytes, or 6+4N for AH */
static int ext6_data(const char *v, int ah, uint8_t *out, uint8_t *len, int *given)
{
    *given = 0;
    if (!v || !*v)
        return 0;
    if (hex_into(v, out, 62, len) < 0 || *len < 6 || (*len + 2) % (ah ? 4 : 8))
        return -1;
    *given = *len > 0;
    return 0;
}

static int tcp_flag_list(const char *s, uint16_t *out)
{
    static const struct {
        const char *n;
        uint16_t f;
    } fl[] = {{"FIN", 1}, {"SYN", 2}, {"RST", 4}, {"PSH", 8}, {"PUSH", 8}, {"ACK", 16}, {"URG", 32}, {"ECE", 64},
              {"CWR", 128}};
    const char *p = s;
    *out = 0;
    for (;;) {
        const char *e = strchr(p, ',');
        size_t n = e ? (size_t)(e - p) : strlen(p), i;
        for (i = 0; i < ARRAY_LEN(fl); i++)
            if (strlen(fl[i].n) == n && str_ieqn(fl[i].n, p, n))
                break;
        if (i == ARRAY_LEN(fl))
            return -1;
        *out |= fl[i].f;
        if (!e)
            return 0;
        p = e + 1;
    }
}

/* ip6ext=hopbyhop[:HEX],hopbyhop2,destopt,destopt2,routing,ah[:HEX] */
static int ip6ext_list(const char *s, xfool *f)
{
    char b[512];
    char *p = b;
    if (strlen(s) >= sizeof(b))
        return -1;
    strcpy(b, s);
    for (;;) {
        char *e = strchr(p, ','), *hex;
        int given;
        if (e)
            *e = 0;
        hex = strchr(p, ':');
        if (hex)
            *hex++ = 0;
#define EXT6(nm, fl, d, l, ah)                                                                                       \
    if (!strcmp(p, nm)) {                                                                                            \
        f->fl = 1;                                                                                                   \
        if (ext6_data(hex, ah, f->d, &f->l, &given) < 0)                                                             \
            return -1;                                                                                               \
        if (ah)                                                                                                      \
            f->ah_given = given;                                                                                     \
    } else
        EXT6("hopbyhop", hop, hop_d, hop_l, 0)
        EXT6("hopbyhop2", hop2, hop2_d, hop2_l, 0)
        EXT6("destopt", dst, dst_d, dst_l, 0)
        EXT6("destopt2", dst2, dst2_d, dst2_l, 0)
        EXT6("routing", rt, rt_d, rt_l, 0)
        EXT6("ah", ah, ah_d, ah_l, 1)
        return -1;
#undef EXT6
        if (!e)
            return 0;
        p = e + 1;
    }
}

/* One common argument into f and o. r NULL: at parse time, where values
 * with a prefix are left for later. -1 with a message in err. */
static int std_one(xrun *r, const xparam *p, xfool *f, xsendopt *o, sbuf *err)
{
    const char *k = p->k, *v = p->v;
    int64_t n;
    int given;
    if (v && r) {
        v = xa_arg(r, k, NULL);
        if (!v) {
            sb_printf(err, "%s: cannot resolve \"%s\"", k, p->v);
            return -1;
        }
    } else if (v && !r && (v[0] == '#' || v[0] == '%')) {
        return 0;
    } else if (v && v[0] == '\\' && (v[1] == '#' || v[1] == '%')) {
        v++;
    }
    if (is_flag_key(k)) {
        if (v) {
            sb_printf(err, "%s takes no value", k);
            return -1;
        }
    } else if (!v && strcmp(k, "md5") && strcmp(k, "ipfrag") &&
               (strncmp(k, "ip6_", 4) || strstr(k, "ttl"))) {
        sb_printf(err, "%s needs a value", k);
        return -1;
    }
#define BAD(...)                                                                                                     \
    do {                                                                                                             \
        sb_printf(err, __VA_ARGS__);                                                                                 \
        return -1;                                                                                                   \
    } while (0)
    if (!strcmp(k, "ttl")) {
        if (!strncmp(v, "auto:", 5)) {
            if (attl_val(v + 5, ':', &f->ad4, &f->amin4, &f->amax4) < 0)
                BAD("bad ttl \"%s\" (N or auto:DELTA:MIN-MAX)", v);
            f->attl4 = f->attl6 = 1;
            f->ad6 = f->ad4, f->amin6 = f->amin4, f->amax6 = f->amax4;
        } else {
            if (ttl_val(v, &f->ttl4) < 0)
                BAD("bad ttl \"%s\" (N or auto:DELTA:MIN-MAX)", v);
            f->ttl6 = f->ttl4;
        }
    } else if (!strcmp(k, "ip_ttl")) {
        if (ttl_val(v, &f->ttl4) < 0)
            BAD("bad ip_ttl \"%s\"", v);
    } else if (!strcmp(k, "ip6_ttl")) {
        if (ttl_val(v, &f->ttl6) < 0)
            BAD("bad ip6_ttl \"%s\"", v);
    } else if (!strcmp(k, "ip_autottl")) {
        if (attl_val(v, ',', &f->ad4, &f->amin4, &f->amax4) < 0)
            BAD("bad ip_autottl \"%s\" (DELTA,MIN-MAX)", v);
        f->attl4 = 1;
    } else if (!strcmp(k, "ip6_autottl")) {
        if (attl_val(v, ',', &f->ad6, &f->amin6, &f->amax6) < 0)
            BAD("bad ip6_autottl \"%s\" (DELTA,MIN-MAX)", v);
        f->attl6 = 1;
    } else if (!strcmp(k, "ip6ext")) {
        if (ip6ext_list(v, f) < 0)
            BAD("bad ip6ext \"%s\" (hopbyhop,hopbyhop2,destopt,destopt2,routing,ah with :HEX of 6+8N or "
                "6+4N bytes)",
                v);
    } else if (!strncmp(k, "ip6_", 4)) {
        int ah = !strcmp(k, "ip6_ah");
        uint8_t *d = NULL, *l = NULL;
        int *fl = NULL;
        if (!strcmp(k, "ip6_hopbyhop"))
            fl = &f->hop, d = f->hop_d, l = &f->hop_l;
        else if (!strcmp(k, "ip6_hopbyhop2"))
            fl = &f->hop2, d = f->hop2_d, l = &f->hop2_l;
        else if (!strcmp(k, "ip6_destopt"))
            fl = &f->dst, d = f->dst_d, l = &f->dst_l;
        else if (!strcmp(k, "ip6_destopt2"))
            fl = &f->dst2, d = f->dst2_d, l = &f->dst2_l;
        else if (!strcmp(k, "ip6_routing"))
            fl = &f->rt, d = f->rt_d, l = &f->rt_l;
        else
            fl = &f->ah, d = f->ah_d, l = &f->ah_l;
        *fl = 1;
        if (ext6_data(v, ah, d, l, &given) < 0)
            BAD("bad %s \"%s\" (HEX of %s bytes)", k, v, ah ? "6+4N" : "6+8N");
        if (ah)
            f->ah_given = given;
    } else if (!strcmp(k, "seq") || !strcmp(k, "ack") || !strcmp(k, "ts")) {
        if (numz(v, &n) < 0 || n < -(int64_t)0xffffffff || n > 0xffffffff)
            BAD("%s needs a number to add, \"%s\" is not", k, v);
        if (k[0] == 's')
            f->has_seq = 1, f->seq = n;
        else if (k[0] == 'a')
            f->has_ack = 1, f->ack = n;
        else
            f->has_ts = 1, f->ts = n;
    } else if (!strcmp(k, "md5")) {
        f->md5 = 1;
        f->md5_given = 0;
        if (v && *v) {
            uint8_t l;
            if (hex_into(v, f->md5_data, 16, &l) < 0 || l != 16)
                BAD("bad md5 \"%s\" (16 bytes of HEX)", v);
            f->md5_given = 1;
        }
    } else if (!strcmp(k, "flags+") || !strcmp(k, "flags-")) {
        uint16_t fl;
        if (tcp_flag_list(v, &fl) < 0)
            BAD("bad TCP flags \"%s\" (FIN,SYN,RST,PSH,ACK,URG,ECE,CWR)", v);
        if (k[5] == '+')
            f->flags_set = fl;
        else
            f->flags_unset = fl;
    } else if (!strcmp(k, "tsup")) {
        f->tsup = 1;
    } else if (!strcmp(k, "nopdel")) {
        f->nopdel = 1;
    } else if (!strcmp(k, "badsum")) {
        o->badsum = 1;
    } else if (!strcmp(k, "repeats")) {
        if (numz(v, &n) < 0 || n < 0 || n > 1000)
            BAD("bad repeats \"%s\" (0..1000)", v);
        o->repeats = n ? (int)n : 1;
    } else if (!strcmp(k, "ifout")) {
        if (!*v || strlen(v) > 15)
            BAD("bad ifout \"%s\"", v);
        o->ifout = v;
    } else if (!strcmp(k, "fwmark")) {
        if (numz(v, &n) < 0 || n < 0 || n > 0xffffffff)
            BAD("bad fwmark \"%s\"", v);
        o->fwmark = (uint32_t)n;
    } else if (!strcmp(k, "ipid")) {
        if (!strcmp(v, "seq"))
            o->ipid = XIPID_SEQ;
        else if (!strcmp(v, "rnd"))
            o->ipid = XIPID_RND;
        else if (!strcmp(v, "zero"))
            o->ipid = XIPID_ZERO;
        else if (!strcmp(v, "none"))
            o->ipid = XIPID_NONE;
        else
            BAD("bad ipid \"%s\" (seq, rnd, zero, none)", v);
    } else if (!strcmp(k, "ipid_conn")) {
        o->ipid_conn = 1;
    } else if (!strcmp(k, "ipfrag")) {
        if (v && *v && strcmp(v, "ipfrag2"))
            BAD("unknown ipfrag function \"%s\" (ipfrag2)", v);
        o->ipfrag = 1;
    } else if (!strcmp(k, "ipfrag_disorder")) {
        o->ipfrag_disorder = 1;
    } else if (!strncmp(k, "ipfrag_pos", 10)) {
        if (numz(v, &n) < 0 || n < 8 || n > 0xfff8 || n % 8)
            BAD("bad %s \"%s\" (a multiple of 8)", k, v);
        if (!strcmp(k, "ipfrag_pos_tcp"))
            o->pos_tcp = (int)n;
        else if (!strcmp(k, "ipfrag_pos_udp"))
            o->pos_udp = (int)n;
        else if (!strcmp(k, "ipfrag_pos_icmp"))
            o->pos_icmp = (int)n;
        else
            o->pos_other = (int)n;
    } else if (!strcmp(k, "ipfrag_next")) {
        if (numz(v, &n) < 0 || n < 0 || n > 255)
            BAD("bad ipfrag_next \"%s\" (0..255)", v);
        o->ipfrag_next = (int)n;
    } else if (!strcmp(k, "payload")) {
        /* any names: xtag makes its own (zapret2's payload= is a list of
         * strings in Lua) */
        const char *q = v[0] == '~' ? v + 1 : v;
        for (;;) {
            const char *e = strchr(q, ',');
            size_t nl = e ? (size_t)(e - q) : strlen(q);
            char nm[BLOB_NAME_MAX];
            if (!nl || nl >= sizeof(nm))
                BAD("bad payload list \"%s\"", v);
            memcpy(nm, q, nl);
            nm[nl] = 0;
            if (!blob_name_ok(nm))
                BAD("bad payload name \"%s\"", nm);
            if (!e)
                break;
            q = e + 1;
        }
    }
#undef BAD
    return 0;
}

static void std_defaults(xfool *f, xsendopt *o)
{
    memset(f, 0, sizeof(*f));
    memset(o, 0, sizeof(*o));
    f->ttl4 = f->ttl6 = -1;
    o->repeats = 1;
    o->ipid = -1;
    o->pos_tcp = 32;
    o->pos_udp = 8;
    o->pos_icmp = 8;
    o->pos_other = 32;
    o->ipfrag_next = -1;
}

static int std_all(xrun *r, const xact *a, xfool *f, xsendopt *o, sbuf *err)
{
    std_defaults(f, o);
    for (int i = 0; i < a->np; i++) {
        int std = 0;
        for (size_t k = 0; k < ARRAY_LEN(std_keys); k++)
            if (!strcmp(std_keys[k].canon, a->p[i].k) && (a->kind->std & std_keys[k].group))
                std = 1;
        if (std && std_one(r, &a->p[i], f, o, err) < 0)
            return -1;
    }
    o->fool = f;
    return 0;
}

/* ---- parsing --------------------------------------------------------------------- */

static void xact_free(void *x)
{
    xact *a = x;
    if (!a)
        return;
    if (a->kind->release)
        a->kind->release(a);
    for (int i = 0; i < a->np; i++) {
        free(a->p[i].k);
        free(a->p[i].v);
    }
    free(a->p);
    free(a->text);
    free(a);
}

static int op_parse(const char *name, const char *params, strat_dir dir, void **x, int *kids, sbuf *err)
{
    const xa_kind *k = NULL;
    xact *a;
    xfool f;
    xsendopt o;
    for (size_t i = 0; i < ARRAY_LEN(kinds); i++)
        if (!strcmp(kinds[i]->name, name))
            k = kinds[i];
    if (!k)
        return 0;
    if (dir == DIR_IN && !k->in_ok) {
        sb_printf(err, "action %s cannot be used in the inbound forest", name);
        return -1;
    }
    a = xcalloc(1, sizeof(*a));
    a->kind = k;
    if (params) {
        const char *p = params;
        a->text = xstrdup(params);
        for (;;) {
            const char *e = strchr(p, ';'), *eq;
            size_t n = e ? (size_t)(e - p) : strlen(p);
            char *key;
            const char *ck;
            if (!n) {
                sb_printf(err, "%s: empty parameter in \"%s\"", name, params);
                goto fail;
            }
            eq = memchr(p, '=', n);
            key = xstrndup(p, eq ? (size_t)(eq - p) : n);
            ck = canon_key(k, key);
            if (!ck) {
                sb_printf(err, "%s: unknown parameter \"%s\"", name, key);
                free(key);
                goto fail;
            }
            free(key);
            if (find(a, ck)) {
                sb_printf(err, "%s: parameter %s given twice", name, ck);
                goto fail;
            }
            a->p = xrealloc(a->p, (size_t)(a->np + 1) * sizeof(*a->p));
            a->p[a->np].k = xstrdup(ck);
            a->p[a->np].v = eq ? xstrndup(eq + 1, n - (size_t)(eq + 1 - p)) : NULL;
            a->np++;
            if (!e)
                break;
            p = e + 1;
        }
    }
    {
        sbuf e2;
        sb_init(&e2);
        if (std_all(NULL, a, &f, &o, &e2) < 0) {
            sb_printf(err, "%s: %s", name, e2.data);
            sb_free(&e2);
            goto fail;
        }
        sb_free(&e2);
    }
    if (k->check && k->check(a, err) < 0)
        goto fail;
    if (k->prepare && k->prepare(a, err) < 0)
        goto fail;
    *x = a;
    *kids = k->kids;
    return 1;
fail:
    xact_free(a);
    return -1;
}

static void op_print(const void *x, sbuf *out)
{
    const xact *a = x;
    sb_puts(out, a->kind->name);
    if (a->text)
        sb_printf(out, "{%s}", a->text);
}

static const char *op_name(const void *x) { return ((const xact *)x)->kind->name; }

/* ---- per-flow state ----------------------------------------------------------------- */

enum { XF_REPLAY_DROP = 1, XF_ATTL4 = 2, XF_ATTL6 = 4, XF_CUT = 8 };

typedef struct {
    const void *inst;
    uint8_t flags;
    uint8_t attl4, attl6;
} xa_slot;

#define XA_SLOTS 16

typedef struct {
    int serial;
    uint16_t ipid;
    uint8_t has_ipid;
    uint8_t n;
    xa_slot s[XA_SLOTS];
} xa_flow;

void xact_flow_clear(ct_flow *f)
{
    xseq_free(f);
    free(f->xa);
    f->xa = NULL;
}

static xa_flow *flow_state(xrun *r)
{
    xa_flow *s;
    if (!r->f)
        return NULL;
    s = r->f->xa;
    if (!s)
        s = r->f->xa = xcalloc(1, sizeof(*s));
    if (r->c && r->c->st && s->serial != r->c->st->serial) {
        memset(s, 0, sizeof(*s));
        s->serial = r->c->st->serial;
    }
    return s;
}

static xa_slot *slot(xrun *r)
{
    xa_flow *s = flow_state(r);
    if (!s)
        return NULL;
    for (unsigned i = 0; i < s->n; i++)
        if (s->s[i].inst == r->a)
            return &s->s[i];
    if (s->n == XA_SLOTS) {
        xa_log(r, "too many x-actions with per-flow state");
        return NULL;
    }
    s->s[s->n].inst = r->a;
    return &s->s[s->n++];
}

int xa_replay_first(const xrun *r) { return !r->pieces || r->piece == 1; }

void xa_replay_drop_set(xrun *r)
{
    xa_slot *s;
    if (r->pieces && (s = slot(r)))
        s->flags |= XF_REPLAY_DROP;
}

int xa_replay_drop(xrun *r)
{
    xa_slot *s = r->f ? slot(r) : NULL;
    int drop;
    if (!s)
        return 0;
    drop = r->pieces && (s->flags & XF_REPLAY_DROP);
    if (!r->pieces || r->piece >= r->pieces)
        s->flags &= (uint8_t)~XF_REPLAY_DROP;
    if (drop)
        xa_log(r, "dropping replay packet because reasm was already sent");
    return drop;
}

int xa_in_list(const char *list, const char *v)
{
    size_t vl = strlen(v);
    for (;;) {
        const char *e = strchr(list, ',');
        size_t n = e ? (size_t)(e - list) : strlen(list);
        if (n == vl && !memcmp(list, v, n))
            return 1;
        if (!e)
            return 0;
        list = e + 1;
    }
}

int xa_payload_ok(xrun *r, const char *def)
{
    const char *v = xa_arg(r, "payload", NULL), *pl;
    int neg, ok;
    if (!v)
        v = def;
    neg = v[0] == '~';
    pl = neg ? v + 1 : v;
    ok = neg != (xa_in_list(pl, "all") || xa_in_list(pl, r->l7name) ||
                 (xa_in_list(pl, "known") && strcmp(r->l7name, "unknown") && strcmp(r->l7name, "empty")));
    if (!ok)
        xa_log(r, "payload \"%s\" does not pass \"%s\"", r->l7name, v);
    return ok;
}

void xa_cutoff(xrun *r)
{
    xa_slot *s = r->f ? slot(r) : NULL;
    if (s) {
        s->flags |= XF_CUT;
        xa_log(r, "cutoff");
    }
}

int xa_is_cut(xrun *r)
{
    xa_slot *s = r->f ? slot(r) : NULL;
    return s && (s->flags & XF_CUT);
}

/* ---- fooling ---------------------------------------------------------------------- */

/* zapret2's autottl: the hops guessed from the incoming TTL, then delta,
 * clamped; 0 when it cannot be guessed or the fake would reach the server */
static int autottl(int incoming, int delta, int mn, int mx)
{
    int orig, hops, d, fake;
    if (incoming > 223)
        orig = 255;
    else if (incoming <= 128 && incoming > 96)
        orig = 128;
    else if (incoming <= 64 && incoming > 32)
        orig = 64;
    else
        return 0;
    hops = orig - incoming;
    d = hops + delta;
    fake = d < mn ? mn : d > mx ? mx : d;
    if ((delta < 0 && fake >= hops) || (delta >= 0 && fake < hops))
        return 0;
    return fake;
}

static int ttl_discover(xrun *r, int v6, int fixed, int is_auto, int d, int mn, int mx)
{
    if (is_auto && r->f) {
        if (r->f->incoming_ttl) {
            xa_slot *s = slot(r);
            int flag = v6 ? XF_ATTL6 : XF_ATTL4;
            if (s && (s->flags & flag)) {
                xa_log(r, "using cached autottl %d", v6 ? s->attl6 : s->attl4);
                return v6 ? s->attl6 : s->attl4;
            }
            {
                int t = autottl(r->f->incoming_ttl, d, mn, mx);
                if (t) {
                    xa_log(r, "discovered autottl %d", t);
                    if (s) {
                        s->flags |= (uint8_t)flag;
                        if (v6)
                            s->attl6 = (uint8_t)t;
                        else
                            s->attl4 = (uint8_t)t;
                    }
                    return t;
                }
                xa_log(r, "could not discover autottl");
            }
        } else {
            xa_log(r, "cannot apply autottl because incoming ttl unknown");
        }
    }
    return fixed;
}

static int find_opt(const gpkt *p, uint8_t kind)
{
    for (int i = 0; i < p->nopts; i++)
        if (p->opts[i].kind == kind)
            return i;
    return -1;
}

/* walks the extension headers in p->ext: the offset of each and its type */
static int ext6_walk(const gpkt *p, size_t *off, uint8_t *type, int max)
{
    size_t o = 0;
    uint8_t nh = p->nh;
    int n = 0;
    while (o + 2 <= p->ext_len && n < max) {
        size_t l;
        if (nh == 0 || nh == 43 || nh == 60)
            l = ((size_t)p->ext[o + 1] + 1) * 8;
        else if (nh == 51)
            l = ((size_t)p->ext[o + 1] + 2) * 4;
        else if (nh == 44)
            l = 8;
        else
            break;
        if (o + l > p->ext_len)
            break;
        off[n] = o;
        type[n++] = nh;
        nh = p->ext[o];
        o += l;
    }
    return n;
}

/* zapret2's insert_ip6_exthdr: at the front (front) or at the end */
static void ext6_insert(gpkt *p, int front, uint8_t type, const uint8_t *data, size_t dlen)
{
    size_t total = type == 51 ? (2 + dlen + 3) / 4 * 4 : (2 + dlen + 7) / 8 * 8, offs[16];
    uint8_t types[16], *e = xcalloc(1, p->ext_len + total);
    int n = ext6_walk(p, offs, types, 16);
    uint8_t *h;
    if (front || !n) {
        h = e;
        if (p->ext_len)
            memcpy(e + total, p->ext, p->ext_len);
        h[0] = p->nh;
        p->nh = type;
    } else {
        memcpy(e, p->ext, p->ext_len);
        h = e + p->ext_len;
        h[0] = e[offs[n - 1]];
        e[offs[n - 1]] = type;
    }
    h[1] = (uint8_t)(type == 51 ? total / 4 - 2 : total / 8 - 1);
    memcpy(h + 2, data, dlen);
    free(p->ext);
    p->ext = e;
    p->ext_len += total;
}

void xa_fooling(xrun *r, gpkt *p, const xfool *f, int tsup_only)
{
    if (!f)
        return;
    pkt_mark_dirty(p);
    p->auto_fields |= XA_AUTO;
    if (p->l4 == LAYER_TCP) {
        int i;
        if (!tsup_only) {
            if (f->has_seq)
                p->seq = (uint32_t)(p->seq + (uint32_t)f->seq);
            if (f->has_ack)
                p->ack = (uint32_t)(p->ack + (uint32_t)f->ack);
            if (f->flags_unset)
                p->tcpflags &= (uint16_t)~f->flags_unset;
            if (f->flags_set)
                p->tcpflags |= f->flags_set;
            if (f->nopdel) {
                int k = 0;
                for (i = 0; i < p->nopts; i++)
                    if (p->opts[i].kind != 1)
                        p->opts[k++] = p->opts[i];
                p->nopts = k;
            }
            if (f->has_ts) {
                i = find_opt(p, 8);
                if (i >= 0 && p->opts[i].len == 8) {
                    uint8_t *d = p->opts[i].data;
                    uint32_t v = (uint32_t)d[0] << 24 | (uint32_t)d[1] << 16 | (uint32_t)d[2] << 8 | d[3];
                    v += (uint32_t)f->ts;
                    d[0] = (uint8_t)(v >> 24), d[1] = (uint8_t)(v >> 16), d[2] = (uint8_t)(v >> 8), d[3] = (uint8_t)v;
                } else {
                    xa_log(r, "timestamp tcp option not present or invalid");
                }
            }
            if (f->md5) {
                if (find_opt(p, 19) >= 0) {
                    xa_log(r, "md5 option already present");
                } else if (p->nopts < TCP_MAX_OPTS) {
                    tcp_opt *o = &p->opts[p->nopts++];
                    o->kind = 19;
                    o->len = 16;
                    if (f->md5_given)
                        memcpy(o->data, f->md5_data, 16);
                    else
                        rng_bytes(o->data, 16);
                }
            }
        }
        if (f->tsup && (i = find_opt(p, 8)) > 0) {
            tcp_opt t = p->opts[i];
            memmove(&p->opts[1], &p->opts[0], (size_t)i * sizeof(tcp_opt));
            p->opts[0] = t;
        }
    }
    if (tsup_only)
        return;
    if (p->ipver == 6) {
        static const uint8_t z6[6];
        uint8_t ah[6] = {0, 0};
        if (f->hop)
            ext6_insert(p, 1, 0, f->hop_l ? f->hop_d : z6, f->hop_l ? f->hop_l : 6);
        if (f->hop2)
            ext6_insert(p, 1, 0, f->hop2_l ? f->hop2_d : z6, f->hop2_l ? f->hop2_l : 6);
        if (f->dst)
            ext6_insert(p, 0, 60, f->dst_l ? f->dst_d : z6, f->dst_l ? f->dst_l : 6);
        if (f->rt)
            ext6_insert(p, 0, 43, f->rt_l ? f->rt_d : z6, f->rt_l ? f->rt_l : 6);
        if (f->dst2)
            ext6_insert(p, 0, 60, f->dst2_l ? f->dst2_d : z6, f->dst2_l ? f->dst2_l : 6);
        if (f->ah) {
            if (!f->ah_given)
                rng_bytes(ah + 2, 4);
            ext6_insert(p, 0, 51, f->ah_given ? f->ah_d : ah, f->ah_given ? f->ah_l : 6);
        }
        {
            int t = ttl_discover(r, 1, f->ttl6, f->attl6, f->ad6, f->amin6, f->amax6);
            if (t >= 0)
                p->hlim = (uint8_t)t;
        }
    } else {
        int t = ttl_discover(r, 0, f->ttl4, f->attl4, f->ad4, f->amin4, f->amax4);
        if (t >= 0)
            p->ttl = (uint8_t)t;
    }
}

void xa_ipid(xrun *r, gpkt *p, int mode, int conn)
{
    if (p->ipver != 4 || mode == XIPID_NONE)
        return;
    pkt_mark_dirty(p);
    p->auto_fields |= XA_AUTO;
    if (mode == XIPID_SEQ) {
        xa_flow *s = conn ? flow_state(r) : NULL;
        if (s) {
            if (s->has_ipid)
                p->id = s->ipid;
            s->ipid = (uint16_t)(p->id + 1);
            s->has_ipid = 1;
        } else if (r->c) {
            if (r->c->has_ipid)
                p->id = r->c->ipid;
            r->c->ipid = (uint16_t)(p->id + 1);
            r->c->has_ipid = 1;
        }
    } else if (mode == XIPID_ZERO) {
        p->id = 0;
    } else if (mode == XIPID_RND) {
        p->id = (uint16_t)rng_range(1, 0xffff);
    }
}

/* ---- sending ----------------------------------------------------------------------- */

static void push(xrun *r, const uint8_t *b, size_t n, const xsendopt *o)
{
    for (int i = 0; i < (o->repeats > 0 ? o->repeats : 1); i++) {
        gpkt *q = pkt_parse(b, n);
        if (!q)
            return;
        q->xgen = 1;
        q->xmark = o->fwmark ? o->fwmark : (r->c && r->c->has_meta ? r->c->mark : 0);
        if (o->ifout)
            snprintf(q->xifout, sizeof(q->xifout), "%s", o->ifout);
        else if (r->c && r->c->ifout)
            snprintf(q->xifout, sizeof(q->xifout), "%s", r->c->ifout);
        pktlist_push(r->env->out, q);
    }
}

static void wr16(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

/* zapret2's ipfrag2 over the built packet; 0 with the fragments pushed, 1
 * when it does not fragment (the caller sends it whole) */
static int ipfrag2(xrun *r, const gpkt *p, const uint8_t *b, size_t n, const xsendopt *o)
{
    int pos = p->l4 == LAYER_TCP ? o->pos_tcp
              : p->l4 == LAYER_UDP ? o->pos_udp
              : (p->l4proto == 1 || p->l4proto == 58) ? o->pos_icmp
                                                        : o->pos_other;
    uint8_t f1[PKT_MAX], f2[PKT_MAX];
    size_t n1, n2;
    if (p->ipver == 4) {
        size_t l3 = (size_t)(b[0] & 15) * 4;
        uint16_t id = rd16(b + 4);
        if (l3 + (size_t)pos >= n) {
            xa_log(r, "ip frag pos %d exceeds packet length. ipfrag cancelled.", pos);
            return 1;
        }
        if (!id)
            id = (uint16_t)rng_range(1, 0xffff);
        n1 = l3 + (size_t)pos;
        memcpy(f1, b, n1);
        wr16(f1 + 2, (uint32_t)n1);
        wr16(f1 + 4, id);
        wr16(f1 + 6, 0x2000); /* MF, offset 0 */
        n2 = n - (size_t)pos;
        memcpy(f2, b, l3);
        memcpy(f2 + l3, b + l3 + pos, n - l3 - (size_t)pos);
        wr16(f2 + 2, (uint32_t)n2);
        wr16(f2 + 4, id);
        wr16(f2 + 6, (uint32_t)pos >> 3);
        wr16(f1 + 10, 0);
        wr16(f1 + 10, inet_csum(f1, l3, 0));
        wr16(f2 + 10, 0);
        wr16(f2 + 10, inet_csum(f2, l3, 0));
    } else {
        /* the fragment header goes after hop-by-hop, routing and the
         * first destination options (the second may be fragmented) */
        size_t offs[16], before, l3;
        uint8_t types[16], nxt;
        int ne = ext6_walk(p, offs, types, 16), idx = 0, first_dst = -1;
        uint32_t ident = (uint32_t)rng_range(1, 0xffffffffLL);
        for (int i = 0; i < ne; i++)
            if (types[i] == 60) {
                first_dst = i;
                break;
            }
        for (int i = ne - 1; i >= 0; i--)
            if (types[i] == 0 || types[i] == 43 || (types[i] == 60 && i == first_dst)) {
                idx = i + 1;
                break;
            }
        before = idx < ne ? offs[idx] : p->ext_len;
        l3 = 40 + before;
        if (l3 + (size_t)pos >= n) {
            xa_log(r, "ip frag pos %d exceeds packet length. ipfrag cancelled.", pos);
            return 1;
        }
        /* the next header the fragment header takes over */
        nxt = idx == 0 ? b[6] : b[40 + offs[idx - 1]];
        if (n + 8 > sizeof(f1))
            return 1;
        /* first: base, headers before, fragment header, pos bytes */
        memcpy(f1, b, l3);
        if (idx == 0)
            f1[6] = 44;
        else
            f1[40 + offs[idx - 1]] = 44;
        memcpy(f2, f1, l3);
        f1[l3] = nxt;
        f1[l3 + 1] = 0;
        wr16(f1 + l3 + 2, 1); /* offset 0, M */
        f1[l3 + 4] = (uint8_t)(ident >> 24), f1[l3 + 5] = (uint8_t)(ident >> 16);
        f1[l3 + 6] = (uint8_t)(ident >> 8), f1[l3 + 7] = (uint8_t)ident;
        memcpy(f1 + l3 + 8, b + l3, (size_t)pos);
        n1 = l3 + 8 + (size_t)pos;
        wr16(f1 + 4, (uint32_t)(n1 - 40));
        memcpy(f2 + l3, f1 + l3, 8);
        if (o->ipfrag_next >= 0)
            f2[l3] = (uint8_t)o->ipfrag_next;
        wr16(f2 + l3 + 2, (uint32_t)pos); /* offset pos/8 << 3, no M */
        memcpy(f2 + l3 + 8, b + l3 + pos, n - l3 - (size_t)pos);
        n2 = l3 + 8 + n - l3 - (size_t)pos;
        wr16(f2 + 4, (uint32_t)(n2 - 40));
    }
    if (o->ipfrag_disorder) {
        push(r, f2, n2, o);
        push(r, f1, n1, o);
    } else {
        push(r, f1, n1, o);
        push(r, f2, n2, o);
    }
    return 0;
}

static int is_fragment(const gpkt *p)
{
    if (p->ipver == 4)
        return p->frag || (p->ipflags & 1);
    {
        size_t offs[16];
        uint8_t types[16];
        int n = ext6_walk(p, offs, types, 16);
        for (int i = 0; i < n; i++)
            if (types[i] == 44)
                return 1;
    }
    return 0;
}

int xa_send_ipfrag(xrun *r, gpkt *dis, const xsendopt *o)
{
    uint8_t b[PKT_MAX + 64];
    size_t n, ol = 0;
    for (int i = 0; dis->l4 == LAYER_TCP && i < dis->nopts; i++)
        ol += dis->opts[i].kind <= 1 ? 1 : 2 + (size_t)dis->opts[i].len;
    if (ol + dis->opts_tail_len > 40) {
        xa_log(r, "tcp options do not fit");
        return -1;
    }
    dis->auto_fields = XA_AUTO;
    pkt_mark_dirty(dis);
    n = pkt_build(dis, b, sizeof(b));
    if (!n || n > PKT_MAX) {
        xa_log(r, "invalid dissect data");
        return -1;
    }
    if (o->badsum) {
        size_t l3 = dis->ipver == 4 ? (size_t)(b[0] & 15) * 4 : 40 + dis->ext_len;
        size_t at = dis->l4 == LAYER_TCP ? l3 + 16 : dis->l4 == LAYER_UDP ? l3 + 6 : l3 + 2;
        if (at + 2 <= n && !is_fragment(dis)) {
            uint16_t x = (uint16_t)(1 + rng_range(0, 0xfffe));
            b[at] ^= (uint8_t)(x >> 8);
            b[at + 1] ^= (uint8_t)x;
        }
    }
    if (o->ipfrag && !is_fragment(dis) && !ipfrag2(r, dis, b, n, o))
        return 0;
    push(r, b, n, o);
    return 0;
}

/* lengths of the IP options or IPv6 extension headers, and of the TCP
 * options, as zapret2's l3l4_extra_len */
static size_t extra_len(const gpkt *p)
{
    size_t l = p->ipver == 4 ? ((size_t)p->ipopts_len + 3) / 4 * 4 : p->ext_len, t = 0;
    if (p->l4 == LAYER_TCP) {
        for (int i = 0; i < p->nopts; i++)
            t += p->opts[i].kind <= 1 ? 1 : 2 + (size_t)p->opts[i].len;
        l += (t + 3) / 4 * 4;
    }
    return l;
}

int xa_send_segmented(xrun *r, const gpkt *dis, const xsendopt *o)
{
    gpkt *c = pkt_copy(dis);
    int rc = 0;
    c->sleep = 0;
    c->xgen = c->xdrop = 0;
    xa_fooling(r, c, o->fool, o->tsup_only);
    if (c->l4 == LAYER_TCP) {
        size_t extra = extra_len(c), max_data;
        if (extra >= r->mss) {
            pkt_free(c);
            return -1;
        }
        max_data = r->mss - extra;
        if (c->payload_len > max_data) {
            uint8_t *payload = c->payload;
            size_t total = c->payload_len, pos = 0;
            uint16_t urp = dis->urgptr;
            int oob = (dis->tcpflags & 32) != 0;
            c->payload = NULL;
            c->payload_len = 0;
            while (pos < total && !rc) {
                size_t len = total - pos < max_data ? total - pos : max_data;
                if (oob) {
                    if (urp == 0 && pos == 0) {
                        c->tcpflags |= 32;
                    } else if (urp >= pos + 1 && urp < pos + 1 + len) {
                        c->tcpflags |= 32;
                        c->urgptr = (uint16_t)(urp - pos);
                    } else {
                        c->tcpflags &= (uint16_t)~32;
                        c->urgptr = 0;
                    }
                }
                pkt_set_payload(c, payload + pos, len);
                xa_ipid(r, c, o->ipid < 0 ? XIPID_SEQ : o->ipid, o->ipid_conn);
                rc = xa_send_ipfrag(r, c, o);
                c->seq += (uint32_t)len;
                pos += len;
            }
            free(payload);
            pkt_free(c);
            return rc;
        }
    }
    xa_ipid(r, c, o->ipid < 0 ? XIPID_SEQ : o->ipid, o->ipid_conn);
    rc = xa_send_ipfrag(r, c, o);
    pkt_free(c);
    return rc;
}

int xa_send_payload(xrun *r, const gpkt *dis, const uint8_t *payload, size_t len, int64_t seq, const xsendopt *o)
{
    gpkt *c = pkt_copy(dis);
    int rc;
    if (payload)
        pkt_set_payload(c, payload, len);
    if (c->l4 == LAYER_TCP)
        c->seq = (uint32_t)(c->seq + (uint32_t)seq);
    pkt_mark_dirty(c);
    rc = xa_send_segmented(r, c, o);
    pkt_free(c);
    return rc;
}

void xa_opts_fake(const xrun *r, xsendopt *o)
{
    *o = r->opt;
    o->ipfrag = 0;
}

void xa_opts_orig(const xrun *r, xsendopt *o)
{
    *o = r->opt;
    o->ipfrag = 0;
    o->badsum = 0;
    o->repeats = 1;
    o->tsup_only = 1;
}

/* ---- running ---------------------------------------------------------------------- */

static void op_run(void *x, gpkt *p, strat_xenv *env)
{
    const xact *a = x;
    xrun *r = xcalloc(1, sizeof(*r));
    sbuf err;
    r->env = env;
    r->c = env->xctx;
    r->f = r->c ? r->c->f : NULL;
    r->a = a;
    r->l7p = L7P_UNKNOWN;
    r->data = p->payload;
    r->len = p->payload_len;
    if (r->c && r->c->l7) {
        const xl7_view *v = r->c->l7;
        r->l7p = v->l7p;
        if (v->pieces && p->l4 == LAYER_TCP) {
            r->data = v->data;
            r->len = v->len;
            r->piece = v->piece;
            r->pieces = v->pieces;
            r->offset = v->offset;
        } else if (v->pieces) {
            r->piece = v->piece;
            r->pieces = v->pieces;
        }
    }
    {
        xa_dyn *d = dyn(r, 0);
        if (d && d->tagged) {
            r->l7name = d->tag;
            r->l7p = l7_payload_by_name(d->tag);
            if (r->l7p < 0)
                r->l7p = L7P_UNKNOWN;
        } else {
            r->l7name = l7_payload_name(r->l7p);
        }
    }
    r->mss = r->f ? ct_mss(r->f) : CT_DEFAULT_MSS;
    sb_init(&err);
    if (std_all(r, a, &r->fool, &r->opt, &err) < 0) {
        LOGW("xact", "%s: %s", a->kind->name, err.data);
        sb_free(&err);
        free(r);
        strat_xchild(env, 0, p);
        return;
    }
    sb_free(&err);
    a->kind->run(a, p, r);
    free(r);
}

const strat_xact xact_ops = {op_parse, op_print, op_name, xact_free, op_run, dyn_done};
