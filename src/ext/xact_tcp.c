/*
 * The x-actions of zapret-antidpi.lua that send fakes and parts: send,
 * pktmod, fake, multisplit, multidisorder(_legacy), tcpseg, hostfakesplit,
 * fakedsplit, fakeddisorder. Each follows its Lua function step by step;
 * positions here are 0-based offsets where Lua counts from 1.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blob.h"
#include "l7.h"
#include "markers.h"
#include "tls.h"
#include "xact.h"

#define pass xa_pass
#define drop xa_drop

static void verdict_drop(xrun *r, gpkt *p, int nodrop)
{
    if (nodrop)
        pass(r, p);
    else
        drop(r, p);
}

/* marker lists, checked at parse time when they are written out */
int xa_check_markers(const xact *a, const char *key, int range, sbuf *err)
{
    xmarker m[XMARKER_MAX];
    int n;
    const char *v = NULL;
    for (int i = 0; i < a->np; i++)
        if (!strcmp(a->p[i].k, key))
            v = a->p[i].v;
    if (!v || v[0] == '#' || v[0] == '%')
        return 0;
    if (v[0] == '\\')
        v++;
    n = xmarker_list_parse(v, m, XMARKER_MAX, err);
    if (n < 0)
        return -1;
    if (range && n != 2) {
        sb_printf(err, "%s needs two markers (a range)", key);
        return -1;
    }
    return 0;
}

int xa_check_num(const xact *a, const char *key, int64_t lo, int64_t hi, sbuf *err)
{
    const char *v = NULL;
    for (int i = 0; i < a->np; i++)
        if (!strcmp(a->p[i].k, key))
            v = a->p[i].v;
    if (!v)
        return 0;
    if (v[0] == '#' || v[0] == '%')
        return 0;
    {
        int64_t x;
        if (xa_parse_int(v[0] == '\\' ? v + 1 : v, &x) < 0 || x < lo || x > hi) {
            sb_printf(err, "bad %s \"%s\"", key, v);
            return -1;
        }
    }
    return 0;
}

int xa_check_blob(const xact *a, const char *key, sbuf *err)
{
    const char *v = NULL;
    for (int i = 0; i < a->np; i++)
        if (!strcmp(a->p[i].k, key))
            v = a->p[i].v;
    if (!v) {
        if (xa_has(a, key)) {
            sb_printf(err, "%s needs a blob name", key);
            return -1;
        }
        return 0;
    }
    if (v[0] == '0' && (v[1] == 'x' || v[1] == 'X')) {
        uint8_t *b;
        size_t n;
        if (blob_hex(v, 255, &b, &n) < 0 || !n) {
            sb_printf(err, "bad hex in %s (at most 255 bytes)", key);
            return -1;
        }
        free(b);
    } else if (!blob_name_ok(v)) {
        sb_printf(err, "bad blob name \"%s\" in %s", v, key);
        return -1;
    }
    return 0;
}

int xa_check_flag(const xact *a, const char *key, sbuf *err)
{
    for (int i = 0; i < a->np; i++)
        if (!strcmp(a->p[i].k, key) && a->p[i].v) {
            sb_printf(err, "%s takes no value", key);
            return -1;
        }
    return 0;
}

/* The markers of key resolved over the data (0 when absent: def) */
static int markers(xrun *r, const char *key, const char *def, const uint8_t *d, size_t n, xmarker *m)
{
    const char *v = xa_arg(r, key, NULL);
    sbuf err;
    int k;
    if (!v)
        v = def;
    sb_init(&err);
    k = xmarker_list_parse(v, m, XMARKER_MAX, &err);
    if (k < 0)
        xa_log(r, "%s: %s", key, err.data);
    sb_free(&err);
    (void)d, (void)n;
    return k;
}

/* the data an action splits: blob=, else the reassembled message or the
 * payload; NULL when blob is optional and absent */
static const uint8_t *split_data(xrun *r, size_t *len, int *skip)
{
    const char *b = xa_arg(r, "blob", NULL);
    *skip = 0;
    if (b && xa_has(r->a, "optional") && !xa_blob_exists(r, b)) {
        xa_log(r, "blob \"%s\" not found. skipped", b);
        *skip = 1;
        return NULL;
    }
    if (b) {
        const uint8_t *d = xa_blob(r, b, len, 0);
        if (!d)
            *skip = 1;
        return d;
    }
    *len = r->len;
    return r->data;
}

/* seqovl bytes of seqovl_pattern (zeros without it, or when optional and
 * absent) followed by part into out (cap bytes); the length, or 0 */
static size_t ovl_part(xrun *r, size_t ovl, const uint8_t *part, size_t plen, uint8_t *out, size_t cap)
{
    static const uint8_t zero = 0;
    const uint8_t *pat = &zero;
    size_t patl = 1;
    const char *pn = xa_arg(r, "seqovl_pattern", NULL);
    if (ovl + plen > cap)
        return 0;
    if (pn) {
        if (xa_has(r->a, "optional") && !xa_blob_exists(r, pn)) {
            xa_log(r, "blob \"%s\" not found. using zero pattern", pn);
        } else {
            const uint8_t *b = xa_blob(r, pn, &patl, 0);
            if (!b || !patl)
                return 0;
            pat = b;
        }
    }
    xa_pattern(pat, patl, 1, out, ovl);
    memcpy(out + ovl, part, plen);
    return ovl + plen;
}

/* ---- send, pktmod --------------------------------------------------------------- */

static void run_send(const xact *a, gpkt *p, xrun *r)
{
    int64_t delay;
    gpkt *dis;
    size_t from = r->env->out->n;
    (void)a;
    if (xa_num(r, "delay", 0, 0, 3600000, &delay) < 0) {
        pass(r, p);
        return;
    }
    dis = pkt_copy(p);
    dis->sleep = 0;
    dis->xdrop = 0;
    xa_fooling(r, dis, &r->fool, 0);
    xa_ipid(r, dis, r->opt.ipid < 0 ? XIPID_NONE : r->opt.ipid, r->opt.ipid_conn);
    xa_send_ipfrag(r, dis, &r->opt);
    pkt_free(dis);
    for (size_t i = from; delay && i < r->env->out->n; i++)
        r->env->out->v[i]->sleep = (double)delay / 1000.0;
    pass(r, p);
}

static int check_send(const xact *a, sbuf *err) { return xa_check_num(a, "delay", 0, 3600000, err); }

static void run_mod(const xact *a, gpkt *p, xrun *r)
{
    (void)a;
    xa_fooling(r, p, &r->fool, 0);
    xa_ipid(r, p, r->opt.ipid < 0 ? XIPID_NONE : r->opt.ipid, r->opt.ipid_conn);
    pass(r, p);
}

/* ---- fake ----------------------------------------------------------------------- */

static int check_fake(const xact *a, sbuf *err)
{
    if (!xa_has(a, "blob")) {
        sb_puts(err, "xfake: 'blob' arg required");
        return -1;
    }
    if (xa_check_tlsmod(a, "xfake", err) < 0)
        return -1;
    return xa_check_blob(a, "blob", err) < 0 || xa_check_flag(a, "optional", err) < 0 ? -1 : 0;
}

int xa_tlsmod_list(xrun *r, const char *v, tls_modspec *m)
{
    char b[600];
    const char *s = strstr(v, "sni=%");
    if (s) {
        const char *e = strchr(s, ','), *val;
        char name[BLOB_NAME_MAX];
        size_t nl = e ? (size_t)(e - s - 5) : strlen(s + 5), vl;
        if (nl >= sizeof(name))
            return -1;
        memcpy(name, s + 5, nl);
        name[nl] = 0;
        val = (const char *)xa_blob_named(r, name, &vl);
        if (!val || vl > 255) {
            xa_log(r, "tls_mod_shim: non-existent var '%s'", name);
            return -1;
        }
        snprintf(b, sizeof(b), "%.*s%.*s%s", (int)(s + 4 - v), v, (int)vl, val, e ? e : "");
        v = b;
    }
    return tls_mod_parse(v, m);
}

int xa_check_tlsmod(const xact *a, const char *who, sbuf *err)
{
    const char *tm = xa_raw(a, "tlsmod");
    if (tm && tm[0] != '%' && tm[0] != '#') {
        tls_modspec m;
        if (tls_mod_parse(tm, &m) < 0) {
            sb_printf(err, "%s: invalid tls mod list \"%s\"", who, tm);
            return -1;
        }
    }
    return 0;
}

static void run_fake(const xact *a, gpkt *p, xrun *r)
{
    const char *bn;
    const uint8_t *fake;
    size_t flen;
    uint8_t *mod = NULL;
    (void)a;
    if ((p->l4 != LAYER_TCP && p->l4 != LAYER_UDP) || !xa_payload_ok(r, "known")) {
        pass(r, p);
        return;
    }
    if (!xa_replay_first(r)) {
        xa_log(r, "not acting on further replay pieces");
        pass(r, p);
        return;
    }
    bn = xa_arg(r, "blob", NULL);
    if (!bn) {
        pass(r, p);
        return;
    }
    if (xa_has(r->a, "optional") && !xa_blob_exists(r, bn)) {
        xa_log(r, "blob '%s' not found. skipped", bn);
        pass(r, p);
        return;
    }
    fake = xa_blob(r, bn, &flen, 0);
    if (!fake) {
        pass(r, p);
        return;
    }
    {
        const char *tm = xa_arg(r, "tlsmod", NULL);
        /* reasm_data: TCP only in zapret2 */
        if (tm && p->l4 == LAYER_TCP) {
            tls_modspec m;
            if (xa_tlsmod_list(r, tm, &m) == 0 && m.mod) {
                size_t cap = flen + sizeof(m.sni) + 4, nl = flen;
                mod = xmalloc(cap);
                memcpy(mod, fake, flen);
                if (tls_mod_apply(&m, r->data, r->len, mod, &nl, cap) == 0) {
                    fake = mod;
                    flen = nl;
                }
            }
        }
    }
    xa_send_payload(r, p, fake, flen, 0, &r->opt);
    free(mod);
    pass(r, p);
}

/* ---- multisplit ------------------------------------------------------------------- */

static int check_split(const xact *a, sbuf *err)
{
    if (xa_check_markers(a, "pos", 0, err) < 0 || xa_check_num(a, "seqovl", 0, 65535, err) < 0 ||
        xa_check_blob(a, "seqovl_pattern", err) < 0 || xa_check_blob(a, "blob", err) < 0 ||
        xa_check_flag(a, "optional", err) < 0 || xa_check_flag(a, "nodrop", err) < 0 || xa_check_flag(a, "legacy", err) < 0)
        return -1;
    return 0;
}

static void run_split(const xact *a, gpkt *p, xrun *r)
{
    const uint8_t *data;
    size_t len;
    int skip, nodrop = xa_has(a, "nodrop");
    if (p->l4 != LAYER_TCP) {
        pass(r, p);
        return;
    }
    data = split_data(r, &len, &skip);
    if (skip) {
        pass(r, p);
        return;
    }
    if (len && xa_payload_ok(r, "known")) {
        if (xa_replay_first(r)) {
            xmarker m[XMARKER_MAX];
            long pos[XMARKER_MAX];
            int nm = markers(r, "pos", "2", data, len, m), np = 0, k = 0;
            int64_t seqovl;
            if (nm >= 0)
                np = xmarker_resolve_list(data, len, r->l7p, m, nm, pos);
            for (int i = 0; i < np; i++)
                if (pos[i] != 0)
                    pos[k++] = pos[i]; /* cannot split at the first byte */
            np = k;
            if (xa_num(r, "seqovl", 0, 0, 65535, &seqovl) < 0) {
                pass(r, p);
                return;
            }
            if (np > 0) {
                for (int i = 0; i <= np; i++) {
                    size_t start = i ? (size_t)pos[i - 1] : 0, end = i < np ? (size_t)pos[i] : len, n, ovl = 0;
                    uint8_t *buf = xmalloc(65536 + 16);
                    if (i == 0 && seqovl > 0)
                        ovl = (size_t)seqovl;
                    n = ovl_part(r, ovl, data + start, end - start, buf, 65536 + 16);
                    xa_log(r, "sending part %d %zu-%zu len=%zu seqovl=%zu", i + 1, start, end - 1, n, ovl);
                    if ((!n && end > start) || xa_send_payload(r, p, buf, n, (int64_t)start - (int64_t)ovl, &r->opt) < 0) {
                        free(buf);
                        pass(r, p);
                        return;
                    }
                    free(buf);
                }
                xa_replay_drop_set(r);
                verdict_drop(r, p, nodrop);
                return;
            }
            xa_log(r, "no valid split positions");
        } else {
            xa_log(r, "not acting on further replay pieces");
        }
        if (xa_replay_drop(r)) {
            verdict_drop(r, p, nodrop);
            return;
        }
    }
    pass(r, p);
}

/* ---- multidisorder ---------------------------------------------------------------- */

/* multidisorder_send: the parts from the last to the first; ovl >= 0 puts
 * that many pattern bytes before the second part. 0, or -1 (pass). */
static int disorder_send(xrun *r, const gpkt *p, const uint8_t *data, size_t len, long ovl_pos, const long *pos,
                         int np)
{
    for (int i = np; i >= 0; i--) {
        size_t start = i ? (size_t)pos[i - 1] : 0, end = i < np ? (size_t)pos[i] : len, n, ovl = 0;
        uint8_t *buf;
        if (i == 1 && ovl_pos >= 0) {
            if (ovl_pos >= pos[0])
                xa_log(r, "seqovl cancelled because seqovl %ld is not less than the first split pos %ld", ovl_pos,
                       pos[0]);
            else
                ovl = (size_t)ovl_pos;
        }
        buf = xmalloc(65536 + 16);
        n = ovl_part(r, ovl, data + start, end - start, buf, 65536 + 16);
        xa_log(r, "sending part %d %zu-%zu len=%zu seqovl=%zu", i + 1, start, end - 1, n, ovl);
        if ((!n && end > start) || xa_send_payload(r, p, buf, n, (int64_t)start - (int64_t)ovl, &r->opt) < 0) {
            free(buf);
            return -1;
        }
        free(buf);
    }
    return 0;
}

/* a marker (seqovl=) resolved: its offset, -1 when absent or not found */
static long one_marker(xrun *r, const char *key, const uint8_t *data, size_t len)
{
    xmarker m;
    const char *v = xa_arg(r, key, NULL);
    long o;
    if (!v)
        return -1;
    if (xmarker_parse(v, &m) < 0 || (o = xmarker_resolve(data, len, r->l7p, &m)) < 0) {
        xa_log(r, "seqovl cancelled because could not resolve marker '%s'", v);
        return -1;
    }
    return o;
}

static void run_disorder_legacy(const xact *a, gpkt *p, xrun *r)
{
    const uint8_t *data = p->payload, *full = r->data;
    size_t len = p->payload_len, flen = r->len, low = r->pieces ? r->offset : 0, hi = low + len;
    (void)a;
    if (!r->pieces)
        full = p->payload, flen = p->payload_len;
    if (len && xa_payload_ok(r, "known")) {
        xmarker m[XMARKER_MAX];
        long pos[XMARKER_MAX], ovl = -1;
        int nm = markers(r, "pos", "2", full, flen, m), np = 0, k = 0;
        if (nm >= 0)
            np = xmarker_resolve_list(full, flen, r->l7p, m, nm, pos);
        xa_log(r, "reasm piece range: %zu-%zu", low, hi - 1);
        /* only the positions inside this piece, relative to it */
        for (int i = 0; i < np; i++)
            if ((size_t)pos[i] >= low && (size_t)pos[i] < hi && (size_t)pos[i] != low)
                pos[k++] = pos[i] - (long)low;
        np = k;
        if (np > 0) {
            if (xa_has(a, "seqovl")) {
                long s = one_marker(r, "seqovl", full, flen);
                if (s >= 0 && (size_t)s >= low && (size_t)s < hi)
                    ovl = s - (long)low;
                else if (s >= 0)
                    xa_log(r, "normalized seqovl pos is outside of the reasm piece range");
            }
            if (disorder_send(r, p, data, len, ovl, pos, np) < 0)
                pass(r, p);
            else
                drop(r, p);
            return;
        }
        xa_log(r, "no normalized split pos in this packet");
        /* send as is with the options */
        if (xa_send_payload(r, p, NULL, 0, 0, &r->opt) == 0) {
            drop(r, p);
            return;
        }
    }
    pass(r, p);
}

static void run_disorder(const xact *a, gpkt *p, xrun *r)
{
    const uint8_t *data;
    size_t len;
    int skip, nodrop = xa_has(a, "nodrop");
    if (p->l4 != LAYER_TCP) {
        pass(r, p);
        return;
    }
    if (xa_has(a, "legacy")) {
        run_disorder_legacy(a, p, r);
        return;
    }
    data = split_data(r, &len, &skip);
    if (skip) {
        pass(r, p);
        return;
    }
    if (len && xa_payload_ok(r, "known")) {
        if (xa_replay_first(r)) {
            xmarker m[XMARKER_MAX];
            long pos[XMARKER_MAX];
            int nm = markers(r, "pos", "2", data, len, m), np = 0, k = 0;
            if (nm >= 0)
                np = xmarker_resolve_list(data, len, r->l7p, m, nm, pos);
            for (int i = 0; i < np; i++)
                if (pos[i] != 0)
                    pos[k++] = pos[i];
            np = k;
            if (np > 0) {
                long ovl = xa_has(a, "seqovl") ? one_marker(r, "seqovl", data, len) : -1;
                if (disorder_send(r, p, data, len, ovl, pos, np) < 0) {
                    pass(r, p);
                    return;
                }
                xa_replay_drop_set(r);
                verdict_drop(r, p, nodrop);
                return;
            }
            xa_log(r, "no valid split positions");
        } else {
            xa_log(r, "not acting on further replay pieces");
        }
        if (xa_replay_drop(r)) {
            verdict_drop(r, p, nodrop);
            return;
        }
    }
    pass(r, p);
}

static int check_disorder(const xact *a, sbuf *err)
{
    if (xa_check_markers(a, "pos", 0, err) < 0 || xa_check_blob(a, "seqovl_pattern", err) < 0 ||
        xa_check_blob(a, "blob", err) < 0 || xa_check_flag(a, "optional", err) < 0 || xa_check_flag(a, "nodrop", err) < 0 ||
        xa_check_flag(a, "legacy", err) < 0)
        return -1;
    {
        const char *v = NULL;
        xmarker m;
        for (int i = 0; i < a->np; i++)
            if (!strcmp(a->p[i].k, "seqovl"))
                v = a->p[i].v;
        if (v && v[0] != '#' && v[0] != '%' && xmarker_parse(v, &m) < 0) {
            sb_printf(err, "bad seqovl marker \"%s\"", v);
            return -1;
        }
    }
    if (xa_has(a, "legacy") && (xa_has(a, "blob") || xa_has(a, "nodrop") || xa_has(a, "optional"))) {
        sb_puts(err, "xdisorder: legacy takes no blob, optional or nodrop");
        return -1;
    }
    return 0;
}

/* ---- tcpseg ----------------------------------------------------------------------- */

static int check_tcpseg(const xact *a, sbuf *err)
{
    if (!xa_has(a, "pos")) {
        sb_puts(err, "xtcpseg: no pos specified");
        return -1;
    }
    if (xa_check_markers(a, "pos", 1, err) < 0 || xa_check_num(a, "seqovl", 0, 65535, err) < 0 ||
        xa_check_blob(a, "seqovl_pattern", err) < 0 || xa_check_blob(a, "blob", err) < 0 ||
        xa_check_flag(a, "optional", err) < 0)
        return -1;
    return 0;
}

static void run_tcpseg(const xact *a, gpkt *p, xrun *r)
{
    const uint8_t *data;
    size_t len;
    int skip;
    (void)a;
    if (p->l4 != LAYER_TCP) {
        pass(r, p);
        return;
    }
    data = split_data(r, &len, &skip);
    if (skip) {
        pass(r, p);
        return;
    }
    if (len && xa_payload_ok(r, "known")) {
        if (xa_replay_first(r)) {
            xmarker m[XMARKER_MAX];
            long from, to;
            int nm = markers(r, "pos", "", data, len, m);
            int64_t seqovl;
            if (xa_num(r, "seqovl", 0, 0, 65535, &seqovl) < 0) {
                pass(r, p);
                return;
            }
            if (nm == 2 && xmarker_resolve_range(data, len, r->l7p, m, nm, 0, &from, &to) == 0) {
                uint8_t *buf = xmalloc(65536 + 16);
                size_t n = ovl_part(r, (size_t)seqovl, data + from, (size_t)(to - from + 1), buf, 65536 + 16);
                xa_log(r, "sending %ld-%ld len=%zu seqovl=%lld", from, to, n, (long long)seqovl);
                if (n)
                    xa_send_payload(r, p, buf, n, (int64_t)from - seqovl, &r->opt);
                free(buf);
            } else {
                xa_log(r, "range cannot be resolved");
            }
        } else {
            xa_log(r, "not acting on further replay pieces");
        }
    }
    pass(r, p);
}

/* ---- hostfakesplit ---------------------------------------------------------------- */

static int check_hostfake(const xact *a, sbuf *err)
{
    if (xa_check_markers(a, "midhost", 0, err) < 0 || xa_check_markers(a, "disorder_after", 0, err) < 0 ||
        xa_check_blob(a, "blob", err) < 0 || xa_check_flag(a, "optional", err) < 0 || xa_check_flag(a, "nodrop", err) < 0 ||
        xa_check_flag(a, "nofake1", err) < 0 || xa_check_flag(a, "nofake2", err) < 0)
        return -1;
    return 0;
}

static int send_part(xrun *r, const gpkt *p, const uint8_t *d, size_t n, size_t seq, const xsendopt *o)
{
    return xa_send_payload(r, p, d, n, (int64_t)seq, o);
}

static void run_hostfake(const xact *a, gpkt *p, xrun *r)
{
    const uint8_t *data;
    size_t len;
    int skip, nodrop = xa_has(a, "nodrop");
    if (p->l4 != LAYER_TCP) {
        pass(r, p);
        return;
    }
    data = split_data(r, &len, &skip);
    if (skip) {
        pass(r, p);
        return;
    }
    if (len && xa_payload_ok(r, "known")) {
        if (xa_replay_first(r)) {
            xmarker hm[2];
            long h0, h1;
            xmarker_parse("host", &hm[0]);
            xmarker_parse("endhost-1", &hm[1]);
            if (xmarker_resolve_range(data, len, r->l7p, hm, 2, 1, &h0, &h1) == 0) {
                xsendopt orig, fake;
                char fakehost[XL7_HOST_MAX * 2];
                size_t hl = (size_t)(h1 - h0 + 1);
                long mid = -1, da = -1;
                xa_opts_orig(r, &orig);
                xa_opts_fake(r, &fake);
                if (send_part(r, p, data, (size_t)h0, 0, &orig) < 0)
                    goto passp;
                if (hl >= sizeof(fakehost)) {
                    xa_log(r, "host is too long");
                    goto passp;
                }
                tls_genhost(hl, xa_arg(r, "host", NULL), fakehost);
                if (!xa_has(a, "nofake1") &&
                    send_part(r, p, (const uint8_t *)fakehost, hl, (size_t)h0, &fake) < 0)
                    goto passp;
                if (xa_has(a, "midhost")) {
                    xmarker m;
                    const char *v = xa_arg(r, "midhost", NULL);
                    if (v && xmarker_parse(v, &m) == 0 && (mid = xmarker_resolve(data, len, r->l7p, &m)) >= 0) {
                        xa_log(r, "midhost marker resolved to %ld", mid);
                        if (mid <= h0 || mid > h1) {
                            xa_log(r, "midhost is not inside the host range");
                            mid = -1;
                        }
                    } else {
                        xa_log(r, "cannot resolve midhost marker '%s'", v ? v : "");
                        mid = -1;
                    }
                }
                if (mid >= 0) {
                    if (send_part(r, p, data + h0, (size_t)(mid - h0), (size_t)h0, &orig) < 0 ||
                        send_part(r, p, data + mid, (size_t)(h1 - mid + 1), (size_t)mid, &orig) < 0)
                        goto passp;
                } else if (send_part(r, p, data + h0, hl, (size_t)h0, &orig) < 0) {
                    goto passp;
                }
                if (!xa_has(a, "nofake2") &&
                    send_part(r, p, (const uint8_t *)fakehost, hl, (size_t)h0, &fake) < 0)
                    goto passp;
                if (xa_has(a, "disorder_after")) {
                    xmarker m;
                    const char *v = xa_arg(r, "disorder_after", NULL);
                    if (!v || !*v)
                        v = "-1";
                    if (xmarker_parse(v, &m) == 0 && (da = xmarker_resolve(data, len, r->l7p, &m)) >= 0) {
                        if (da <= h1 + 1) {
                            xa_log(r, "disorder_after marker '%ld' resolved to pos not after after_host pos %ld", da,
                                   h1 + 1);
                            da = -1;
                        }
                    } else {
                        xa_log(r, "could not resolve disorder_after marker '%s'", v);
                        da = -1;
                    }
                }
                if (da >= 0) {
                    if (send_part(r, p, data + da, len - (size_t)da, (size_t)da, &orig) < 0 ||
                        send_part(r, p, data + h1 + 1, (size_t)(da - h1 - 1), (size_t)h1 + 1, &orig) < 0)
                        goto passp;
                } else if (send_part(r, p, data + h1 + 1, len - (size_t)h1 - 1, (size_t)h1 + 1, &orig) < 0) {
                    goto passp;
                }
                xa_replay_drop_set(r);
                verdict_drop(r, p, nodrop);
                return;
            }
            xa_log(r, "host range cannot be resolved");
        } else {
            xa_log(r, "not acting on further replay pieces");
        }
        if (xa_replay_drop(r)) {
            verdict_drop(r, p, nodrop);
            return;
        }
    }
passp:
    pass(r, p);
}

/* ---- fakedsplit, fakeddisorder ---------------------------------------------------- */

static int check_faked(const xact *a, sbuf *err)
{
    if (xa_check_markers(a, "pos", 0, err) < 0 || xa_check_blob(a, "pattern", err) < 0 ||
        xa_check_blob(a, "seqovl_pattern", err) < 0 || xa_check_blob(a, "blob", err) < 0 ||
        xa_check_flag(a, "optional", err) < 0 || xa_check_flag(a, "nodrop", err) < 0)
        return -1;
    for (int i = 1; i <= 4; i++) {
        char k[16];
        snprintf(k, sizeof(k), "nofake%d", i);
        if (xa_check_flag(a, k, err) < 0)
            return -1;
    }
    {
        xmarker m[XMARKER_MAX];
        const char *v = NULL;
        for (int i = 0; i < a->np; i++)
            if (!strcmp(a->p[i].k, "pos"))
                v = a->p[i].v;
        if (v && v[0] != '#' && v[0] != '%' && xmarker_list_parse(v, m, XMARKER_MAX, err) != 1) {
            if (!err->len)
                sb_printf(err, "pos takes one marker");
            return -1;
        }
    }
    return 0;
}

static int check_fakedsplit(const xact *a, sbuf *err)
{
    return check_faked(a, err) < 0 || xa_check_num(a, "seqovl", 0, 65535, err) < 0 ? -1 : 0;
}

static int check_fakeddisorder(const xact *a, sbuf *err)
{
    const char *v = NULL;
    xmarker m;
    if (check_faked(a, err) < 0)
        return -1;
    for (int i = 0; i < a->np; i++)
        if (!strcmp(a->p[i].k, "seqovl"))
            v = a->p[i].v;
    if (v && v[0] != '#' && v[0] != '%' && xmarker_parse(v, &m) < 0) {
        sb_printf(err, "bad seqovl marker \"%s\"", v);
        return -1;
    }
    return 0;
}

/* the fake pattern (pattern=, else one zero byte) */
static const uint8_t *fake_pattern(xrun *r, size_t *n)
{
    static const uint8_t zero = 0;
    const char *pn = xa_arg(r, "pattern", NULL);
    if (pn) {
        const uint8_t *b = xa_blob(r, pn, n, 0);
        if (b && *n)
            return b;
    }
    *n = 1;
    return &zero;
}

static void run_faked(const xact *a, gpkt *p, xrun *r, int disorder)
{
    const uint8_t *data;
    size_t len;
    int skip, nodrop = xa_has(a, "nodrop");
    if (p->l4 != LAYER_TCP) {
        pass(r, p);
        return;
    }
    data = split_data(r, &len, &skip);
    if (skip) {
        pass(r, p);
        return;
    }
    if (len && xa_payload_ok(r, "known")) {
        if (xa_replay_first(r)) {
            xmarker m;
            const char *spos = xa_arg(r, "pos", NULL);
            long pos = -1;
            if (!spos)
                spos = "2";
            if (xmarker_parse(spos, &m) == 0)
                pos = xmarker_resolve(data, len, r->l7p, &m);
            if (pos == 0) {
                xa_log(r, "split pos resolved to 0. cannot split.");
            } else if (pos > 0) {
                xsendopt orig, fake;
                size_t patl, p0 = (size_t)pos;
                const uint8_t *pat = fake_pattern(r, &patl);
                uint8_t *f1 = xmalloc(len + 1), *f2 = xmalloc(len + 1), *buf = xmalloc(65536 + 16);
                int fail = 0;
                xa_opts_orig(r, &orig);
                xa_opts_fake(r, &fake);
                xa_pattern(pat, patl, 1, f1, p0);
                xa_pattern(pat, patl, p0 + 1, f2, len - p0);
                if (!disorder) {
                    int64_t seqovl;
                    size_t n;
                    if (xa_num(r, "seqovl", 0, 0, 65535, &seqovl) < 0)
                        fail = 1;
                    if (!fail && !xa_has(a, "nofake1"))
                        fail = send_part(r, p, f1, p0, 0, &fake) < 0;
                    if (!fail) {
                        n = ovl_part(r, (size_t)seqovl, data, p0, buf, 65536 + 16);
                        fail = !n || xa_send_payload(r, p, buf, n, -seqovl, &orig) < 0;
                    }
                    if (!fail && !xa_has(a, "nofake2"))
                        fail = send_part(r, p, f1, p0, 0, &fake) < 0;
                    if (!fail && !xa_has(a, "nofake3"))
                        fail = send_part(r, p, f2, len - p0, p0, &fake) < 0;
                    if (!fail)
                        fail = send_part(r, p, data + p0, len - p0, p0, &orig) < 0;
                    if (!fail && !xa_has(a, "nofake4"))
                        fail = send_part(r, p, f2, len - p0, p0, &fake) < 0;
                } else {
                    long ovl = 0;
                    size_t n;
                    if (!xa_has(a, "nofake1"))
                        fail = send_part(r, p, f2, len - p0, p0, &fake) < 0;
                    if (!fail && xa_has(a, "seqovl")) {
                        ovl = one_marker(r, "seqovl", data, len);
                        if (ovl < 0) {
                            ovl = 0;
                        } else if (ovl >= pos) {
                            xa_log(r, "seqovl cancelled because seqovl %ld is not less than the split pos %ld", ovl,
                                   pos);
                            ovl = 0;
                        }
                    }
                    if (!fail) {
                        n = ovl_part(r, (size_t)ovl, data + p0, len - p0, buf, 65536 + 16);
                        fail = !n || xa_send_payload(r, p, buf, n, (int64_t)p0 - ovl, &orig) < 0;
                    }
                    if (!fail && !xa_has(a, "nofake2"))
                        fail = send_part(r, p, f2, len - p0, p0, &fake) < 0;
                    if (!fail && !xa_has(a, "nofake3"))
                        fail = send_part(r, p, f1, p0, 0, &fake) < 0;
                    if (!fail)
                        fail = send_part(r, p, data, p0, 0, &orig) < 0;
                    if (!fail && !xa_has(a, "nofake4"))
                        fail = send_part(r, p, f1, p0, 0, &fake) < 0;
                }
                free(f1);
                free(f2);
                free(buf);
                if (fail) {
                    pass(r, p);
                    return;
                }
                xa_replay_drop_set(r);
                verdict_drop(r, p, nodrop);
                return;
            } else {
                xa_log(r, "cannot resolve pos '%s'", spos);
            }
        } else {
            xa_log(r, "not acting on further replay pieces");
        }
        if (xa_replay_drop(r)) {
            verdict_drop(r, p, nodrop);
            return;
        }
    }
    pass(r, p);
}

static void run_fakedsplit(const xact *a, gpkt *p, xrun *r) { run_faked(a, p, r, 0); }
static void run_fakeddisorder(const xact *a, gpkt *p, xrun *r) { run_faked(a, p, r, 1); }

/* ---- synack_split, synack, wsize, wssize, syndata, rst (X5b) -------------------- */

enum { XTH_SYN = 2, XTH_RST = 4, XTH_ACK = 16 };

/* a copy of p to send */
static gpkt *dis_copy(const gpkt *p)
{
    gpkt *d = pkt_copy(p);
    d->sleep = 0;
    d->xdrop = 0;
    return d;
}

/* not TCP: zapret2 cuts the instance off (not on ICMP, which we do not
 * get here); 1 when the packet went on */
static int tcp_only(xrun *r, gpkt *p)
{
    if (p->l4 != LAYER_TCP) {
        xa_cutoff(r);
        pass(r, p);
        return 1;
    }
    if (xa_is_cut(r)) {
        pass(r, p);
        return 1;
    }
    return 0;
}

static int check_synacksplit(const xact *a, sbuf *err)
{
    const char *m = xa_raw(a, "mode");
    if (xa_has(a, "mode") && (!m || (strcmp(m, "syn") && strcmp(m, "synack") && strcmp(m, "acksyn")))) {
        sb_printf(err, "xsynacksplit: bad mode '%s'", m ? m : "");
        return -1;
    }
    return 0;
}

static void run_synacksplit(const xact *a, gpkt *p, xrun *r)
{
    const char *mode;
    uint16_t f0 = p->tcpflags;
    gpkt *d;
    int rc;
    (void)a;
    if (tcp_only(r, p))
        return;
    if ((f0 & (XTH_SYN | XTH_ACK)) != (XTH_SYN | XTH_ACK)) {
        xa_cutoff(r); /* mission complete */
        pass(r, p);
        return;
    }
    mode = xa_arg(r, "mode", NULL);
    if (!mode)
        mode = "synack";
    d = dis_copy(p);
    if (!strcmp(mode, "acksyn")) {
        d->tcpflags = (uint16_t)(f0 & ~XTH_SYN);
        xa_log(r, "sending ACK");
        rc = xa_send_ipfrag(r, d, &r->opt);
        d->tcpflags = (uint16_t)(f0 & ~XTH_ACK);
        xa_log(r, "sending SYN");
        rc = rc < 0 ? rc : xa_send_ipfrag(r, d, &r->opt);
    } else {
        d->tcpflags = (uint16_t)(f0 & ~XTH_ACK);
        xa_log(r, "sending SYN");
        rc = xa_send_ipfrag(r, d, &r->opt);
        if (!strcmp(mode, "synack")) {
            d->tcpflags = (uint16_t)(f0 & ~XTH_SYN);
            xa_log(r, "sending ACK");
            rc = rc < 0 ? rc : xa_send_ipfrag(r, d, &r->opt);
        }
    }
    pkt_free(d);
    if (rc < 0)
        pass(r, p);
    else
        drop(r, p);
}

static void run_synack(const xact *a, gpkt *p, xrun *r)
{
    (void)a;
    if (tcp_only(r, p))
        return;
    if ((p->tcpflags & (XTH_SYN | XTH_ACK)) == XTH_SYN) {
        gpkt *d = dis_copy(p);
        d->tcpflags |= XTH_ACK;
        xa_log(r, "sending");
        xa_send_ipfrag(r, d, &r->opt);
        pkt_free(d);
    } else {
        xa_cutoff(r);
    }
    pass(r, p);
}

static int check_wsize(const xact *a, sbuf *err)
{
    return xa_check_num(a, "wsize", 0, 65535, err) < 0 || xa_check_num(a, "scale", 0, 255, err) < 0 ? -1 : 0;
}

/* zapret2's wsize_rewrite: 1 when it changed anything (-1: a bad value) */
static int wsize_rewrite(xrun *r, gpkt *p)
{
    int64_t w, sc;
    int changed = 0;
    if (xa_num(r, "wsize", -1, 0, 65535, &w) < 0 || xa_num(r, "scale", -1, 0, 255, &sc) < 0)
        return -1;
    if (w >= 0) {
        xa_log(r, "window size %u => %u", p->window, (unsigned)w);
        p->window = (uint16_t)w;
        changed = 1;
    }
    if (sc >= 0) {
        for (int i = 0; i < p->nopts; i++) {
            if (p->opts[i].kind != 3)
                continue;
            if (p->opts[i].len >= 1) {
                int old = p->opts[i].data[0];
                if (sc > old) {
                    xa_log(r, "not increasing scale factor");
                } else if (sc < old) {
                    xa_log(r, "scale factor %d => %d", old, (int)sc);
                    p->opts[i].data[0] = (uint8_t)sc;
                    changed = 1;
                }
            }
            break;
        }
    }
    if (changed)
        xa_modified(p);
    return changed;
}

static void run_wsize(const xact *a, gpkt *p, xrun *r)
{
    (void)a;
    if (tcp_only(r, p))
        return;
    if ((p->tcpflags & (XTH_SYN | XTH_ACK)) == (XTH_SYN | XTH_ACK))
        wsize_rewrite(r, p);
    else
        xa_cutoff(r); /* mission complete */
    pass(r, p);
}

static int check_wssize(const xact *a, sbuf *err)
{
    const char *fc = xa_raw(a, "forced_cutoff");
    if (xa_has(a, "forced_cutoff") && (!fc || !*fc)) {
        sb_puts(err, "xwssize: forced_cutoff needs a list of payloads");
        return -1;
    }
    return check_wsize(a, err);
}

static void run_wssize(const xact *a, gpkt *p, xrun *r)
{
    const char *fc;
    (void)a;
    if (tcp_only(r, p))
        return;
    wsize_rewrite(r, p);
    fc = xa_arg(r, "forced_cutoff", NULL);
    if (p->payload_len && (!fc || xa_in_list(fc, r->l7name))) {
        xa_log(r, "forced cutoff");
        xa_cutoff(r);
    }
    pass(r, p);
}

static int check_syndata(const xact *a, sbuf *err)
{
    return xa_check_blob(a, "blob", err) < 0 || xa_check_tlsmod(a, "xsyndata", err) < 0 ? -1 : 0;
}

static void run_syndata(const xact *a, gpkt *p, xrun *r)
{
    static const uint8_t zero16[16];
    const char *bn, *tm;
    const uint8_t *pl = zero16;
    size_t plen = sizeof(zero16);
    uint8_t *mod = NULL;
    gpkt *d;
    int rc;
    (void)a;
    if (tcp_only(r, p))
        return;
    if ((p->tcpflags & (XTH_SYN | XTH_ACK)) != XTH_SYN) {
        xa_cutoff(r); /* mission complete */
        pass(r, p);
        return;
    }
    bn = xa_arg(r, "blob", NULL);
    if (bn && !(pl = xa_blob(r, bn, &plen, 0))) {
        pass(r, p);
        return;
    }
    tm = xa_arg(r, "tlsmod", NULL);
    if (tm) {
        tls_modspec m;
        if (xa_tlsmod_list(r, tm, &m) == 0 && m.mod) {
            size_t cap = plen + sizeof(m.sni) + 4, nl = plen;
            mod = xmalloc(cap);
            memcpy(mod, pl, plen);
            /* no payload to take the session id from (zapret2 passes nil) */
            if (tls_mod_apply(&m, NULL, 0, mod, &nl, cap) == 0) {
                pl = mod;
                plen = nl;
            }
        }
    }
    d = dis_copy(p);
    pkt_set_payload(d, pl, plen);
    xa_fooling(r, d, &r->fool, 0);
    rc = xa_send_ipfrag(r, d, &r->opt);
    pkt_free(d);
    free(mod);
    if (rc < 0)
        pass(r, p);
    else
        drop(r, p);
}

static int check_rst(const xact *a, sbuf *err) { return xa_check_flag(a, "rstack", err); }

static void run_rst(const xact *a, gpkt *p, xrun *r)
{
    if (p->l4 != LAYER_TCP) {
        xa_cutoff(r);
        pass(r, p);
        return;
    }
    if (xa_payload_ok(r, "known")) {
        if (xa_replay_first(r)) {
            gpkt *d = dis_copy(p);
            pkt_set_payload(d, NULL, 0);
            d->tcpflags = (uint16_t)(XTH_RST | (xa_has(a, "rstack") ? XTH_ACK : 0));
            xa_fooling(r, d, &r->fool, 0);
            xa_ipid(r, d, r->opt.ipid < 0 ? XIPID_NONE : r->opt.ipid, r->opt.ipid_conn);
            xa_log(r, "rst");
            xa_send_ipfrag(r, d, &r->opt);
            pkt_free(d);
        } else {
            xa_log(r, "not acting on further replay pieces");
        }
    }
    pass(r, p);
}

/* ---- the table -------------------------------------------------------------------- */

#define STD_ALL (XS_FOOL | XS_RECON | XS_SEND | XS_IPID | XS_FRAG | XS_PAYLOAD)
#define STD_NOFRAG (XS_FOOL | XS_RECON | XS_SEND | XS_IPID | XS_PAYLOAD)

static const char *const k_send[] = {"delay", NULL};
static const char *const k_fake[] = {"blob", "optional", "tlsmod", NULL};
static const char *const k_split[] = {"pos", "seqovl", "seqovl_pattern", "blob", "optional", "nodrop", NULL};
static const char *const k_disorder[] = {"pos", "seqovl", "seqovl_pattern", "blob", "optional", "nodrop", "legacy",
                                         NULL};
static const char *const k_tcpseg[] = {"pos", "seqovl", "seqovl_pattern", "blob", "optional", NULL};
static const char *const k_hostfake[] = {"host", "midhost", "nofake1", "nofake2", "disorder_after", "blob",
                                         "optional", "nodrop", NULL};
static const char *const k_faked[] = {"pos",  "nofake1", "nofake2", "nofake3", "nofake4", "pattern", "seqovl",
                                      "seqovl_pattern", "blob", "optional", "nodrop", NULL};

static const char *const k_synacksplit[] = {"mode", NULL};
static const char *const k_wsize[] = {"wsize", "scale", NULL};
static const char *const k_wssize[] = {"wsize", "scale", "forced_cutoff", NULL};
static const char *const k_syndata[] = {"blob", "tlsmod", NULL};
static const char *const k_rst[] = {"rstack", NULL};

#define STD_RAW (XS_RECON | XS_SEND | XS_FRAG)

const xa_kind xa_synacksplit = {"xsynacksplit", 1, 0, STD_RAW, k_synacksplit, check_synacksplit, run_synacksplit,
                                NULL, NULL};
const xa_kind xa_synack = {"xsynack", 1, 0, STD_RAW, NULL, NULL, run_synack, NULL, NULL};
const xa_kind xa_wsize = {"xwsize", 1, 1, 0, k_wsize, check_wsize, run_wsize, NULL, NULL};
const xa_kind xa_wssize = {"xwssize", 1, 1, 0, k_wssize, check_wssize, run_wssize, NULL, NULL};
const xa_kind xa_syndata = {"xsyndata", 1, 0, XS_FOOL | STD_RAW, k_syndata, check_syndata, run_syndata, NULL,
                             NULL};
const xa_kind xa_rst = {"xrst", 1, 0, STD_ALL, k_rst, check_rst, run_rst, NULL, NULL};
const xa_kind xa_send = {"xsend", 1, 0, XS_FOOL | XS_RECON | XS_SEND | XS_IPID | XS_FRAG, k_send, check_send,
                         run_send, NULL, NULL};
const xa_kind xa_mod = {"xmod", 1, 1, XS_FOOL | XS_IPID, NULL, NULL, run_mod, NULL, NULL};
const xa_kind xa_fake = {"xfake", 1, 0, STD_ALL, k_fake, check_fake, run_fake, NULL, NULL};
const xa_kind xa_split = {"xsplit", 1, 0, STD_ALL, k_split, check_split, run_split, NULL, NULL};
const xa_kind xa_disorder = {"xdisorder", 1, 0, STD_ALL, k_disorder, check_disorder, run_disorder, NULL, NULL};
const xa_kind xa_tcpseg = {"xtcpseg", 1, 0, STD_ALL, k_tcpseg, check_tcpseg, run_tcpseg, NULL, NULL};
const xa_kind xa_hostfake = {"xhostfake", 1, 0, STD_NOFRAG, k_hostfake, check_hostfake, run_hostfake, NULL, NULL};
const xa_kind xa_fakedsplit = {"xfakedsplit", 1, 0, STD_NOFRAG, k_faked, check_fakedsplit, run_fakedsplit, NULL,
                                NULL};
const xa_kind xa_fakeddisorder = {"xfakeddisorder", 1, 0, STD_NOFRAG, k_faked, check_fakeddisorder,
                                  run_fakeddisorder, NULL, NULL};
