/*
 * x-actions of zapret2 that change UDP payloads, clone a ClientHello or look
 * at the packet: udplen, dht_dn, tls_client_hello_clone
 * (lua/zapret-antidpi.lua), pass/pktdebug/posdebug and detect_payload_str
 * (lua/zapret-lib.lua), pcap (lua/zapret-pcap.lua).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blob.h"
#include "ext.h"
#include "json.h"
#include "log.h"
#include "plat.h"
#include "xact.h"

static int check_name(const xact *a, const char *key, int required, sbuf *err)
{
    const char *v = xa_raw(a, key);
    if (!xa_has(a, key)) {
        if (required) {
            sb_printf(err, "%s: '%s' arg required", a->kind->name, key);
            return -1;
        }
        return 0;
    }
    if (!v || !blob_name_ok(v)) {
        sb_printf(err, "%s: bad name \"%s\" in %s", a->kind->name, v ? v : "", key);
        return -1;
    }
    return 0;
}

/* ---- udplen ----------------------------------------------------------------------- */

static int check_udplen(const xact *a, sbuf *err)
{
    int64_t inc;
    const char *v = xa_raw(a, "increment");
    if (xa_check_num(a, "min", 0, 65535, err) < 0 || xa_check_num(a, "max", 0, 65535, err) < 0 ||
        xa_check_num(a, "increment", -65535, 65535, err) < 0 ||
        xa_check_num(a, "pattern_offset", 0, 65535, err) < 0 || xa_check_blob(a, "pattern", err) < 0)
        return -1;
    if (v && v[0] != '#' && v[0] != '%' && xa_parse_int(v, &inc) == 0 && !inc) {
        sb_puts(err, "xudplen: increment 0 does nothing");
        return -1;
    }
    return 0;
}

static void run_udplen(const xact *a, gpkt *p, xrun *r)
{
    int64_t mn, mx, inc, po;
    size_t len = p->payload_len;
    (void)a;
    if (p->l4 != LAYER_UDP) {
        xa_cutoff(r);
        xa_pass(r, p);
        return;
    }
    if (!xa_payload_ok(r, "known") || xa_num(r, "min", -1, 0, 65535, &mn) < 0 ||
        xa_num(r, "max", -1, 0, 65535, &mx) < 0 || xa_num(r, "increment", 2, -65535, 65535, &inc) < 0 ||
        xa_num(r, "pattern_offset", 0, 0, 65535, &po) < 0) {
        xa_pass(r, p);
        return;
    }
    if (mn >= 0 && (int64_t)len < mn) {
        xa_log(r, "payload size %zu is less than the minimum size %lld", len, (long long)mn);
    } else if (mx >= 0 && (int64_t)len > mx) {
        xa_log(r, "payload size %zu is more than the maximum size %lld", len, (long long)mx);
    } else if (inc > 0) {
        static const uint8_t zero = 0;
        const uint8_t *pat = &zero;
        size_t pl = 1;
        const char *pn = xa_arg(r, "pattern", NULL);
        if (pn && !(pat = xa_blob(r, pn, &pl, 0))) {
            xa_pass(r, p);
            return;
        }
        if (!pl || len + (size_t)inc > PKT_MAX) {
            xa_log(r, "cannot grow %zu by %lld", len, (long long)inc);
        } else {
            uint8_t *b = xmalloc(len + (size_t)inc);
            if (len)
                memcpy(b, p->payload, len);
            xa_pattern(pat, pl, (size_t)po + 1, b + len, (size_t)inc);
            pkt_set_payload(p, b, len + (size_t)inc);
            free(b);
            xa_modified(p);
            xa_log(r, "%zu => %zu", len, p->payload_len);
        }
    } else if (inc < 0) {
        if ((int64_t)len + inc < 1) {
            xa_log(r, "will not shrink to zero length");
        } else {
            p->payload_len = (size_t)((int64_t)len + inc);
            pkt_mark_dirty(p);
            xa_modified(p);
            xa_log(r, "%zu => %zu", len, p->payload_len);
        }
    }
    xa_pass(r, p);
}

/* ---- dht_dn ----------------------------------------------------------------------- */

static int check_dhtdn(const xact *a, sbuf *err) { return xa_check_num(a, "dn", 0, 1000, err); }

static void run_dhtdn(const xact *a, gpkt *p, xrun *r)
{
    int64_t n;
    (void)a;
    if (p->l4 != LAYER_UDP) {
        xa_cutoff(r);
        xa_pass(r, p);
        return;
    }
    if (!strcmp(r->l7name, "dht") && xa_num(r, "dn", 3, 0, 1000, &n) == 0) {
        /* "d1:" becomes "dN:000...1:x" without breaking bencode */
        sbuf b;
        sb_init(&b);
        sb_printf(&b, "d%lld:", (long long)n);
        for (int64_t i = 0; i < n; i++)
            sb_putc(&b, '0');
        sb_puts(&b, "1:x");
        if (p->payload_len > 1)
            sb_append(&b, p->payload + 1, p->payload_len - 1);
        if (b.len <= PKT_MAX) {
            pkt_set_payload(p, (const uint8_t *)b.data, b.len);
            xa_modified(p);
            xa_log(r, "tampered dht to start with 'd%lld:' instead of 'd1:'", (long long)n);
        }
        sb_free(&b);
    }
    xa_pass(r, p);
}

/* ---- tls_client_hello_clone ---------------------------------------------------------- */

static int check_tlsclone(const xact *a, sbuf *err)
{
    if (check_name(a, "blob", 1, err) < 0 || xa_check_blob(a, "fallback", err) < 0 ||
        xa_check_num(a, "sni_snt", 0, 255, err) < 0 || xa_check_num(a, "sni_snt_new", 0, 255, err) < 0 ||
        xa_check_flag(a, "sni_del_ext", err) < 0 || xa_check_flag(a, "sni_del", err) < 0)
        return -1;
    return 0;
}

static char *dup_arg(xrun *r, const char *key, size_t *len)
{
    const char *v = xa_arg(r, key, len);
    char *c;
    if (!v)
        return NULL;
    c = xmalloc(*len + 1);
    memcpy(c, v, *len);
    c[*len] = 0;
    return c;
}

static void run_tlsclone(const xact *a, gpkt *p, xrun *r)
{
    const char *bn = xa_raw(a, "blob");
    size_t n;
    if (p->l4 != LAYER_TCP) {
        xa_cutoff(r);
        xa_pass(r, p);
        return;
    }
    if (!strcmp(r->l7name, "tls_client_hello")) {
        tls_cloneopt o;
        int64_t snt, sntn;
        uint8_t *out;
        size_t ol;
        char *first, *last;
        memset(&o, 0, sizeof(o));
        if (xa_num(r, "sni_snt", -1, 0, 255, &snt) < 0 || xa_num(r, "sni_snt_new", -1, 0, 255, &sntn) < 0) {
            xa_pass(r, p);
            return;
        }
        o.snt = (int)snt;
        o.snt_new = (int)sntn;
        o.del_ext = xa_has(a, "sni_del_ext");
        o.del = xa_has(a, "sni_del");
        o.first = first = dup_arg(r, "sni_first", &o.first_len);
        o.last = last = dup_arg(r, "sni_last", &o.last_len);
        if (tls_ch_clone(r->data, r->len, &o, &out, &ol) == 0) {
            xa_dyn_blob_set(r, bn, out, ol);
            xa_log(r, "cloned to %s (%zu bytes)", bn, ol);
            free(out);
        } else {
            xa_log(r, "could not dissect tls");
        }
        free(first);
        free(last);
    }
    if (!xa_dyn_has(r, bn) && xa_has(a, "fallback")) {
        const char *fb = xa_raw(a, "fallback");
        const uint8_t *d = fb ? xa_blob(r, fb, &n, 0) : NULL;
        if (d) {
            uint8_t *c = xmalloc(n ? n : 1);
            memcpy(c, d, n);
            xa_dyn_blob_set(r, bn, c, n);
            free(c);
            xa_log(r, "%s=%s", bn, fb);
        }
    }
    xa_pass(r, p);
}

/* ---- xlog: pass, pktdebug, posdebug -------------------------------------------------- */

static void run_xlog(const xact *a, gpkt *p, xrun *r)
{
    const char *msg = xa_arg(r, "msg", NULL);
    sbuf d, pos;
    sb_init(&d);
    sb_init(&pos);
    if (xa_has(a, "pkt"))
        pkt_describe(p, &d);
    if (xa_has(a, "pos"))
        xoff_posdebug(r->env->xctx, r->env->dir, p, &pos);
    LOGI("xlog", "%s%s%s l7=%s len=%zu%s%s%s%s", msg ? msg : "pass", r->env->dir == DIR_IN ? " in" : " out",
         r->pieces ? " piece" : "", r->l7name, p->payload_len, d.len ? " " : "", d.len ? d.data : "",
         pos.len ? " " : "", pos.len ? pos.data : "");
    if (ev_enabled()) {
        ev_t e;
        ev_begin(&e, "ext_pkt");
        if (msg)
            jw_kstr(&e.w, "msg", msg);
        jw_kstr(&e.w, "dir", r->env->dir == DIR_IN ? "in" : "out");
        jw_kuint(&e.w, "tree", r->env->tree);
        jw_kstr(&e.w, "l7payload", r->l7name);
        jw_kuint(&e.w, "len", p->payload_len);
        if (r->pieces) {
            jw_kuint(&e.w, "piece", r->piece);
            jw_kuint(&e.w, "pieces", r->pieces);
        }
        if (d.len)
            jw_kstr(&e.w, "pkt", d.data);
        if (pos.len)
            jw_kstr(&e.w, "pos", pos.data);
        if (xa_has(a, "hex")) {
            static const char hx[] = "0123456789abcdef";
            size_t n = p->payload_len < 2048 ? p->payload_len : 2048;
            sbuf h;
            sb_init(&h);
            for (size_t i = 0; i < n; i++) {
                sb_putc(&h, hx[p->payload[i] >> 4]);
                sb_putc(&h, hx[p->payload[i] & 15]);
            }
            jw_kstr(&e.w, "hex", h.len ? h.data : "");
            sb_free(&h);
        }
        ev_emit(&e);
    }
    sb_free(&d);
    sb_free(&pos);
    xa_pass(r, p);
}

static int check_xlog(const xact *a, sbuf *err)
{
    return xa_check_flag(a, "pkt", err) < 0 || xa_check_flag(a, "pos", err) < 0 || xa_check_flag(a, "hex", err) < 0
               ? -1
               : 0;
}

/* ---- xtag: detect_payload_str --------------------------------------------------------- */

static int check_tag(const xact *a, sbuf *err)
{
    const char *v = xa_raw(a, "pattern");
    if (!xa_has(a, "pattern") || !v || !*v) {
        sb_puts(err, "xtag: missing 'pattern'");
        return -1;
    }
    return check_name(a, "payload", 0, err) < 0 || check_name(a, "undetected", 0, err) < 0 ? -1 : 0;
}

static int find_bytes(const uint8_t *h, size_t hn, const uint8_t *nd, size_t nn)
{
    if (!nn)
        return 1;
    for (size_t i = 0; i + nn <= hn; i++)
        if (h[i] == nd[0] && !memcmp(h + i, nd, nn))
            return 1;
    return 0;
}

static void run_tag(const xact *a, gpkt *p, xrun *r)
{
    size_t pl;
    const char *pat = xa_arg(r, "pattern", &pl), *lbl;
    if (pat && pl && r->data && find_bytes(r->data, r->len, (const uint8_t *)pat, pl)) {
        lbl = xa_raw(a, "payload");
        xa_log(r, "detected '%s'", lbl ? lbl : "?");
    } else {
        lbl = xa_raw(a, "undetected");
        xa_log(r, "not detected '%s'", xa_raw(a, "payload") ? xa_raw(a, "payload") : "?");
    }
    if (lbl)
        xa_set_tag(r, lbl);
    xa_pass(r, p);
}

/* ---- xpcap: pcap ---------------------------------------------------------------------- */

static int check_pcap(const xact *a, sbuf *err)
{
    const char *f = xa_raw(a, "file");
    if (!f || !*f) {
        sb_puts(err, "xpcap requires 'file' parameter");
        return -1;
    }
    return xa_check_flag(a, "keep", err);
}

static void be32(uint8_t *b, uint32_t v)
{
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
}

static void run_pcap(const xact *a, gpkt *p, xrun *r)
{
    /* big endian, nanoseconds, 2.4, snaplen 65535, LINKTYPE_RAW: zapret2's header */
    static const uint8_t hdr[24] = {0xA1, 0xB2, 0x3C, 0x4D, 0, 2, 0, 4, 0, 0, 0, 0,
                                    0,    0,    0,    0,    0, 0, 0xFF, 0xFF, 0, 0, 0, 0x65};
    const char *fn = xa_raw(a, "file");
    gpkt *c = pkt_copy(p);
    size_t n;
    uint8_t *b = pkt_bytes(c, &n);
    FILE *f;
    pkt_free(c);
    if (!((xact *)a)->started) {
        /* the first packet of this instance: the file starts anew unless keep */
        ((xact *)a)->started = 1;
        if (!xa_has(a, "keep"))
            remove(fn);
    }
    f = b ? fopen(fn, "ab") : NULL;
    if (!f) {
        if (b)
            LOGW("xact", "xpcap: could not write to '%s'", fn);
    } else {
        uint8_t rh[16];
        uint64_t ms = plat_wall_ms();
        long at;
        fseek(f, 0, SEEK_END);
        at = ftell(f);
        be32(rh, (uint32_t)(ms / 1000));
        be32(rh + 4, (uint32_t)(ms % 1000 * 1000000));
        be32(rh + 8, (uint32_t)n);
        be32(rh + 12, (uint32_t)n);
        if ((at == 0 && fwrite(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) || fwrite(rh, 1, 16, f) != 16 ||
            fwrite(b, 1, n, f) != n)
            LOGW("xact", "xpcap: could not write to '%s'", fn);
        fclose(f);
    }
    free(b);
    xa_pass(r, p);
}

static const char *const k_udplen[] = {"min", "max", "increment", "pattern", "pattern_offset", NULL};
static const char *const k_dhtdn[] = {"dn", NULL};
static const char *const k_tlsclone[] = {"blob",        "fallback", "sni_snt",   "sni_snt_new",
                                         "sni_del_ext", "sni_del",  "sni_first", "sni_last", NULL};
static const char *const k_xlog[] = {"msg", "pkt", "pos", "hex", NULL};
static const char *const k_tag[] = {"pattern", "payload", "undetected", NULL};
static const char *const k_pcap[] = {"file", "keep", NULL};

const xa_kind xa_udplen = {"xudplen", 1, 1, XS_PAYLOAD, k_udplen, check_udplen, run_udplen};
const xa_kind xa_dhtdn = {"xdhtdn", 1, 1, 0, k_dhtdn, check_dhtdn, run_dhtdn};
const xa_kind xa_tlsclone = {"xtlsclone", 1, 1, 0, k_tlsclone, check_tlsclone, run_tlsclone};
const xa_kind xa_xlog = {"xlog", 1, 1, 0, k_xlog, check_xlog, run_xlog};
const xa_kind xa_tag = {"xtag", 1, 1, 0, k_tag, check_tag, run_tag};
const xa_kind xa_pcap = {"xpcap", 1, 1, 0, k_pcap, check_pcap, run_pcap};
