/*
 * The x-actions that change the length or the pace of the client's first
 * message (X8; docs/EXT_ROADMAP.md, G23 and 7): xoob (zapret2's oob),
 * xtlsrec (one TLS record cut in two) on seqtrack (seqtrack.h), and xdrip
 * (the first bytes one per segment, with a pause).
 */
#include <stdlib.h>
#include <string.h>

#include "markers.h"
#include "seqtrack.h"
#include "xact.h"

#define pass xa_pass
#define drop xa_drop

enum { TH_SYN = 2, TH_ACK = 16, TH_URG = 32 };

/* ---- the SYN, common to xoob and xtlsrec --------------------------------------- */

/* The part before the first message: on the client's SYN the flow's
 * numbering is shifted by d. 1 when the packet went on; otherwise *out is
 * the flow's state. */
static int seq_begin(const xact *a, gpkt *p, xrun *r, uint32_t d, xseq **out)
{
    xseq *s;
    if (p->l4 != LAYER_TCP) {
        xa_cutoff(r);
        pass(r, p);
        return 1;
    }
    if (xa_is_cut(r)) {
        pass(r, p);
        return 1;
    }
    if (!r->f || (r->c && r->c->reverse)) {
        xa_log(r, "%s", !r->f ? "no flow: seqtrack needs the conntrack" : "not the client's packet");
        xa_cutoff(r);
        pass(r, p);
        return 1;
    }
    s = xseq_of(r->f);
    if ((p->tcpflags & (TH_SYN | TH_ACK)) == TH_SYN) {
        if (!s) {
            xseq_start(r->f, p->seq, d, a->kind);
            xa_log(r, "decreasing outgoing seq : %u => %u", p->seq, p->seq - d);
            p->seq -= d;
            xa_modified(p);
        } else if (s->owner != a->kind) {
            xa_log(r, "another action shifts this flow's seq");
            xa_cutoff(r);
        }
        /* a SYN sent again: the engine shifted it already */
        pass(r, p);
        return 1;
    }
    if (!s || s->owner != a->kind || s->d != d) {
        xa_log(r, "must be applied since the very beginning of the tcp connection - SYN packet");
        xa_cutoff(r);
        pass(r, p);
        return 1;
    }
    if (s->state != XSEQ_SYN) {
        /* the message went out whole: the replay's other pieces go too */
        if (r->pieces) {
            xa_log(r, "dropping replay piece");
            if (r->piece >= r->pieces)
                xa_cutoff(r);
            drop(r, p);
            return 1;
        }
        xa_cutoff(r);
        pass(r, p);
        return 1;
    }
    if (!p->payload_len || p->seq != s->isn + 1) {
        /* no data yet (the engine shifted it), or not the first byte */
        pass(r, p);
        return 1;
    }
    *out = s;
    return 0;
}

/* The changed message goes out in place of the first one: its own seq
 * (d before the client's), segmented as zapret2's rawsend_dissect_segmented */
static void seq_send(xrun *r, gpkt *p, xseq *s, const uint8_t *msg, size_t mlen, uint32_t k, size_t len, int urg,
                     uint16_t urp)
{
    gpkt *dis = pkt_copy(p);
    dis->sleep = 0;
    dis->xdrop = 0;
    pkt_set_payload(dis, msg, mlen);
    dis->seq = s->isn + 1 - s->d;
    if (urg) {
        dis->tcpflags |= TH_URG;
        dis->urgptr = urp;
    }
    xa_modified(dis);
    if (xa_send_segmented(r, dis, &r->opt) < 0)
        xa_log(r, "could not send the changed message: the flow will stall");
    pkt_free(dis);
    xseq_sent(s, k, (uint32_t)len, msg, mlen, urg, urp);
    if (!r->pieces)
        xa_cutoff(r);
    drop(r, p);
}

/* ---- xoob --------------------------------------------------------------------------- */

static int check_oob(const xact *a, sbuf *err)
{
    const char *c = xa_raw(a, "char"), *u = xa_raw(a, "urp");
    xmarker m;
    if (xa_has(a, "char") && (!c || strlen(c) != 1) && !(c && (*c == '%' || *c == '#'))) {
        sb_puts(err, "xoob: char must be exactly one character");
        return -1;
    }
    if (xa_check_num(a, "byte", 0, 255, err) < 0)
        return -1;
    if (xa_has(a, "urp") &&
        (!u || (strcmp(u, "b") && strcmp(u, "e") && *u != '%' && *u != '#' && xmarker_parse(u, &m) < 0))) {
        sb_printf(err, "xoob: urp is b, e or a marker, not '%s'", u ? u : "");
        return -1;
    }
    return 0;
}

static void run_oob(const xact *a, gpkt *p, xrun *r)
{
    xseq *s;
    const char *c, *u;
    uint8_t oob = 0, *msg;
    size_t len = r->len, cl = 0;
    long k;
    uint16_t urp;
    if (seq_begin(a, p, r, 1, &s))
        return;
    if ((c = xa_arg(r, "char", &cl)) != NULL) {
        if (cl != 1)
            xa_log(r, "char must be exactly one byte: using 0");
        else
            oob = (uint8_t)c[0];
    } else if (xa_has(a, "byte")) {
        int64_t b;
        if (xa_num(r, "byte", 0, 0, 255, &b) == 0)
            oob = (uint8_t)b;
    }
    u = xa_arg(r, "urp", NULL);
    /* the OOB byte goes before byte k of the message; th_urp as zapret2 */
    if (!u || !strcmp(u, "b")) {
        k = 0;
        urp = 0;
    } else if (!strcmp(u, "e")) {
        k = (long)len;
        urp = (uint16_t)(len + 1);
    } else {
        xmarker m;
        k = xmarker_parse(u, &m) < 0 ? -1 : xmarker_resolve(r->data, len, r->l7p, &m);
        if (k < 0 || (size_t)k > len)
            xa_log(r, "cannot resolve urp marker '%s': the byte goes first", u);
        urp = (uint16_t)(k + 1);
    }
    if (k < 0 || (size_t)k > len || len + 1 > 65535) {
        /* zapret2 cuts the instance off here and the flow breaks: the SYN
         * is shifted already */
        if (len + 1 > 65535 && k > 0)
            xa_log(r, "the urgent pointer does not reach byte %ld: the byte goes first", k);
        k = 0;
        urp = 0;
    }
    xa_log(r, "th_urp %u", urp);
    msg = xmalloc(len + 1);
    memcpy(msg, r->data, (size_t)k);
    msg[k] = oob;
    memcpy(msg + k + 1, r->data + k, len - (size_t)k);
    xa_log(r, "sending OOB");
    seq_send(r, p, s, msg, len + 1, (uint32_t)k, len, 1, urp);
    free(msg);
}

/* ---- xtlsrec ------------------------------------------------------------------------ */

#define TLSREC_DEF "midsld"

static int check_tlsrec(const xact *a, sbuf *err) { return xa_check_markers(a, "pos", 0, err); }

static void run_tlsrec(const xact *a, gpkt *p, xrun *r)
{
    xseq *s;
    const uint8_t *d;
    const char *v;
    size_t len;
    unsigned reclen, b;
    long o = -1;
    uint8_t *msg;
    if (seq_begin(a, p, r, 5, &s))
        return;
    d = r->data;
    len = r->len;
    if (len < 7 || d[0] < 0x14 || d[0] > 0x18 || d[1] != 3 || (reclen = (unsigned)d[3] << 8 | d[4]) < 2) {
        /* the 5 bytes have no place: the message goes as it is, so that
         * a single request still gets its answer; what follows it stalls */
        xa_log(r, "not a TLS record: the flow will stall after the first message");
        seq_send(r, p, s, d, len, (uint32_t)len, len, 0, 0);
        return;
    }
    v = xa_arg(r, "pos", NULL);
    {
        xmarker m;
        if (xmarker_parse(v ? v : TLSREC_DEF, &m) == 0)
            o = xmarker_resolve(d, len, r->l7p, &m);
    }
    /* a cut inside the first record's body, in the data there is */
    if (o <= 5 || (size_t)o > len || (unsigned long)o >= 5ul + reclen) {
        xa_log(r, "cannot cut the record at '%s': after its first byte", v ? v : TLSREC_DEF);
        o = 6;
    }
    b = (unsigned)o - 5;
    msg = xmalloc(len + 5);
    memcpy(msg, d, (size_t)o);
    msg[3] = (uint8_t)(b >> 8);
    msg[4] = (uint8_t)b;
    msg[o] = d[0];
    msg[o + 1] = d[1];
    msg[o + 2] = d[2];
    msg[o + 3] = (uint8_t)((reclen - b) >> 8);
    msg[o + 4] = (uint8_t)(reclen - b);
    memcpy(msg + o + 5, d + o, len - (size_t)o);
    xa_log(r, "TLS record of %u bytes cut at %u", reclen, b);
    seq_send(r, p, s, msg, len + 5, (uint32_t)o, len, 0, 0);
    free(msg);
}

/* ---- xdrip -------------------------------------------------------------------------- */

static int check_drip(const xact *a, sbuf *err)
{
    return xa_check_num(a, "n", 1, 1000, err) < 0 || xa_check_num(a, "delay", 0, 10000, err) < 0 ? -1 : 0;
}

static void run_drip(const xact *a, gpkt *p, xrun *r)
{
    int64_t n, delay;
    xsendopt o;
    size_t i, from;
    (void)a;
    if (p->l4 != LAYER_TCP) {
        xa_cutoff(r);
        pass(r, p);
        return;
    }
    if (!r->len || !xa_payload_ok(r, "known") || xa_num(r, "n", 8, 1, 1000, &n) < 0 ||
        xa_num(r, "delay", 20, 0, 10000, &delay) < 0) {
        pass(r, p);
        return;
    }
    if (!xa_replay_first(r)) {
        if (xa_replay_drop(r))
            drop(r, p);
        else
            pass(r, p);
        return;
    }
    if (r->len < 2) {
        pass(r, p);
        return;
    }
    if ((size_t)n > r->len)
        n = (int64_t)r->len;
    o = r->opt;
    o.fool = NULL; /* the real data */
    from = r->env->out->n;
    for (i = 0; i < (size_t)n; i++) {
        size_t f0 = r->env->out->n;
        if (xa_send_payload(r, p, r->data + i, 1, (int64_t)i, &o) < 0)
            break;
        for (size_t j = f0; j < r->env->out->n; j++)
            r->env->out->v[j]->sleep = (double)(i * (size_t)delay) / 1000.0;
    }
    if (i == (size_t)n && (size_t)n < r->len) {
        size_t f0 = r->env->out->n;
        if (xa_send_payload(r, p, r->data + n, r->len - (size_t)n, n, &o) < 0)
            i = 0;
        for (size_t j = f0; j < r->env->out->n; j++)
            r->env->out->v[j]->sleep = (double)((size_t)n * (size_t)delay) / 1000.0;
    }
    if (i < (size_t)n) {
        /* nothing more could go: the packet itself goes on */
        xa_log(r, "could not send byte %zu", i);
        for (size_t j = from; j < r->env->out->n; j++)
            pkt_free(r->env->out->v[j]);
        r->env->out->n = from;
        pass(r, p);
        return;
    }
    xa_log(r, "%lld bytes one by one every %lld ms, then %zu", (long long)n, (long long)delay,
           r->len - (size_t)n);
    if (r->pieces)
        xa_replay_drop_set(r);
    drop(r, p);
}

/* ---- the table -------------------------------------------------------------------- */

static const char *const k_oob[] = {"char", "byte", "urp", NULL};
static const char *const k_tlsrec[] = {"pos", NULL};
static const char *const k_drip[] = {"n", "delay", NULL};

#define STD_SEQ (XS_FOOL | XS_RECON | XS_SEND | XS_IPID | XS_FRAG)

const xa_kind xa_oob = {"xoob", 1, 0, STD_SEQ, k_oob, check_oob, run_oob, NULL, NULL};
const xa_kind xa_tlsrec = {"xtlsrec", 1, 0, STD_SEQ, k_tlsrec, check_tlsrec, run_tlsrec, NULL, NULL};
const xa_kind xa_drip = {"xdrip", 1, 0, XS_IPID | XS_PAYLOAD, k_drip, check_drip, run_drip, NULL, NULL};
