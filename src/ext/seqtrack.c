/*
 * Seqtrack: the TCP numbering of a flow whose first message grew
 * (seqtrack.h).
 */
#include "seqtrack.h"

#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "util.h"

enum { TH_FIN = 1, TH_SYN = 2, TH_ACK = 16, TH_URG = 32 };

/* a - b as a signed distance on the 32-bit circle */
static int32_t sdiff(uint32_t a, uint32_t b) { return (int32_t)(a - b); }

xseq *xseq_of(const ct_flow *f) { return f ? f->xseq : NULL; }

xseq *xseq_start(ct_flow *f, uint32_t isn, uint32_t d, const void *owner)
{
    xseq *s;
    if (!f || f->xseq)
        return NULL;
    s = xcalloc(1, sizeof(*s));
    s->isn = isn;
    s->d = d;
    s->owner = owner;
    f->xseq = s;
    return s;
}

void xseq_sent(xseq *s, uint32_t k, uint32_t mlen, const uint8_t *msg, size_t msglen, int urg, uint16_t urp)
{
    s->k = k;
    s->mlen = mlen;
    s->state = XSEQ_SENT;
    free(s->msg);
    s->msg = xmalloc(msglen ? msglen : 1);
    memcpy(s->msg, msg, msglen);
    s->msglen = msglen;
    s->urg = urg;
    s->urp = urp;
}

void xseq_free(ct_flow *f)
{
    xseq *s = f->xseq;
    if (!s)
        return;
    free(s->msg);
    free(s);
    f->xseq = NULL;
}

uint32_t xseq_ack(const xseq *s, uint32_t ack)
{
    uint32_t base = s->isn + 1 - s->d; /* the message's first byte for the server */
    int32_t o = sdiff(ack, base);
    if (s->state == XSEQ_SYN || o <= (int32_t)s->k)
        return ack + s->d;
    if (o < (int32_t)(s->k + s->d))
        return s->isn + 1 + s->k; /* inside the inserted bytes */
    return ack;
}

uint32_t xseq_seq(const xseq *s, uint32_t seq)
{
    if (s->state == XSEQ_SYN || sdiff(seq, s->isn + 1) < (int32_t)s->k)
        return seq - s->d;
    return seq;
}

/* the server's packet: ack and SACK edges */
static int map_in(xseq *s, gpkt *p)
{
    int changed = 0;
    if (!(p->tcpflags & TH_ACK))
        return XSEQ_PASS;
    {
        uint32_t a = xseq_ack(s, p->ack);
        if (a != p->ack) {
            p->ack = a;
            changed = 1;
        }
        if (s->state == XSEQ_SENT && sdiff(a, s->isn + 1 + s->mlen) >= 0) {
            /* the message arrived: no more retransmissions of it */
            s->state = XSEQ_ACKED;
            free(s->msg);
            s->msg = NULL;
            s->msglen = 0;
        }
    }
    for (int i = 0; i < p->nopts; i++) {
        tcp_opt *o = &p->opts[i];
        if (o->kind != 5 || o->len % 8)
            continue;
        for (unsigned j = 0; j + 4 <= o->len; j += 4) {
            uint32_t v = (uint32_t)o->data[j] << 24 | (uint32_t)o->data[j + 1] << 16 | (uint32_t)o->data[j + 2] << 8 |
                         o->data[j + 3];
            uint32_t m = xseq_ack(s, v);
            if (m != v) {
                o->data[j] = (uint8_t)(m >> 24);
                o->data[j + 1] = (uint8_t)(m >> 16);
                o->data[j + 2] = (uint8_t)(m >> 8);
                o->data[j + 3] = (uint8_t)m;
                changed = 1;
            }
        }
    }
    return changed ? XSEQ_MODIFIED : XSEQ_PASS;
}

/* the message again, as the first time, on p's headers (its ack, window,
 * timestamps are the current ones) */
static void resend(xseq *s, const gpkt *p, unsigned mss, xseq_emit_fn emit, void *ud)
{
    gpkt *c = pkt_copy(p);
    size_t hl = (size_t)c->dataofs * 4, max = mss, pos = 0;
    if (hl > 20 && hl - 20 < max)
        max -= hl - 20;
    if (!max)
        max = 1;
    c->tcpflags &= (uint16_t)~(TH_FIN | TH_URG);
    c->urgptr = 0;
    c->sleep = 0;
    c->xgen = c->xdrop = 0;
    c->auto_fields |= AUTO_IP_LEN | AUTO_IP_CSUM | AUTO_TCP_CSUM | AUTO_V6_PLEN;
    while (pos < s->msglen) {
        size_t n = s->msglen - pos < max ? s->msglen - pos : max;
        uint8_t *b;
        size_t bl;
        if (s->urg) {
            /* as zapret2's rawsend_dissect_segmented */
            if (s->urp == 0 && pos == 0) {
                c->tcpflags |= TH_URG;
                c->urgptr = 0;
            } else if (s->urp >= pos + 1 && s->urp < pos + 1 + n) {
                c->tcpflags |= TH_URG;
                c->urgptr = (uint16_t)(s->urp - pos);
            } else {
                c->tcpflags &= (uint16_t)~TH_URG;
                c->urgptr = 0;
            }
        }
        c->seq = s->isn + 1 - s->d + (uint32_t)pos;
        pkt_set_payload(c, s->msg + pos, n);
        b = pkt_bytes(c, &bl);
        if (bl && emit)
            emit(ud, b, bl);
        free(b);
        pos += n;
    }
    pkt_free(c);
}

/* the client's packet */
static int map_out(xseq *s, gpkt *p, unsigned mss, xseq_emit_fn emit, void *ud)
{
    int32_t rel = sdiff(p->seq, s->isn + 1);
    if ((p->tcpflags & TH_SYN) || !p->payload_len) {
        uint32_t q = (p->tcpflags & TH_SYN) ? p->seq - s->d : xseq_seq(s, p->seq);
        if (q == p->seq)
            return XSEQ_PASS;
        p->seq = q;
        return XSEQ_MODIFIED;
    }
    /* data: the first time the action changes it; a retransmission of the
     * message is sent again whole */
    if (s->state != XSEQ_SENT || !s->msg || rel >= (int32_t)s->mlen || rel + (int64_t)p->payload_len <= 0)
        return XSEQ_PASS;
    s->retrans++;
    LOGD("seqtrack", "retransmission of the first message (seq +%d, %zu bytes): sent again changed", rel,
         p->payload_len);
    resend(s, p, mss, emit, ud);
    {
        int64_t past = rel + (int64_t)p->payload_len - (int64_t)s->mlen; /* bytes after the message */
        if (past <= 0 && !(p->tcpflags & TH_FIN))
            return XSEQ_DROP;
        if (past < 0)
            past = 0;
        {
            uint8_t *tail = xmalloc(past ? (size_t)past : 1);
            memcpy(tail, p->payload + p->payload_len - (size_t)past, (size_t)past);
            p->seq = s->isn + 1 + s->mlen;
            p->tcpflags &= (uint16_t)~TH_URG;
            p->urgptr = 0;
            pkt_set_payload(p, tail, (size_t)past);
            free(tail);
        }
    }
    return XSEQ_MODIFIED;
}

int xseq_packet(ct_flow *f, int reverse, gpkt *p, unsigned mss, xseq_emit_fn emit, void *ud)
{
    xseq *s = xseq_of(f);
    int r;
    if (!s || !p || p->l4 != LAYER_TCP)
        return XSEQ_PASS;
    r = reverse ? map_in(s, p) : map_out(s, p, mss, emit, ud);
    if (r == XSEQ_MODIFIED) {
        p->auto_fields |= AUTO_TCP_CSUM | AUTO_IP_LEN | AUTO_IP_CSUM | AUTO_V6_PLEN;
        pkt_mark_dirty(p);
    }
    return r;
}
