/*
 * Seqtrack (docs/EXT_ROADMAP.md, 6.3; G23): the TCP numbering of a flow
 * whose client's first message an x-action made longer (xoob: one urgent
 * byte, xtlsrec: a second TLS record header).
 *
 * As zapret2's oob does, the shift is made on the SYN: the client's ISN
 * goes to the server d less, so the first message, d bytes longer, ends
 * where the client's own numbering goes on and nothing after it needs a
 * change. Until then (and for the first message's retransmissions) the
 * engine's hook fixes what the client and the server send:
 *
 *   - the client's packets without data before the message (the SYN again,
 *     ACK, FIN, RST): seq - d;
 *   - a retransmission of any part of the message: the whole changed
 *     message again (from the copy kept here, without fooling), then what
 *     the packet carries past the message;
 *   - the server's ACK and SACK edges: back to the client's numbering, the
 *     inserted bytes counting as the byte before them (zapret2 adds 1 to
 *     the ack until the client sends more, which is wrong for an ack of the
 *     message itself).
 *
 * The state hangs on the flow (ct_flow.xseq) and outlives a strategy
 * change: the server keeps the numbering it was given. One shifting action
 * per flow.
 */
#ifndef GENEVA_EXT_SEQTRACK_H
#define GENEVA_EXT_SEQTRACK_H

#include <stddef.h>
#include <stdint.h>

#include "ctrack.h"
#include "pkt.h"

enum { XSEQ_SYN = 0, XSEQ_SENT, XSEQ_ACKED };

typedef struct {
    uint32_t isn;  /* the client's ISN, its own numbering */
    uint32_t d;    /* the bytes inserted into the first message */
    uint32_t k;    /* where: after k bytes of the client's message */
    uint32_t mlen; /* the client's message (its length; 0 before XSEQ_SENT) */
    uint8_t state; /* XSEQ_* */
    const void *owner; /* the action kind that shifts (xa_kind) */
    /* the message as sent (mlen + d bytes) and its urgent pointer, for
     * retransmissions; freed once the server acks it */
    uint8_t *msg;
    size_t msglen;
    int urg;
    uint16_t urp;
    uint64_t retrans; /* retransmissions made again */
} xseq;

xseq *xseq_of(const ct_flow *f);
/* The SYN of f's client with ISN isn: the state, or NULL when the flow has
 * one already. */
xseq *xseq_start(ct_flow *f, uint32_t isn, uint32_t d, const void *owner);
/* The first message went out: k, its length, the bytes as sent (copied). */
void xseq_sent(xseq *s, uint32_t k, uint32_t mlen, const uint8_t *msg, size_t msglen, int urg, uint16_t urp);
/* For ct_config.clear (through xact_flow_clear). */
void xseq_free(ct_flow *f);

/* The server's ack (or SACK edge) in the client's numbering. */
uint32_t xseq_ack(const xseq *s, uint32_t ack);
/* The seq of a client packet without data in the server's numbering. */
uint32_t xseq_seq(const xseq *s, uint32_t seq);

enum { XSEQ_PASS = 0, XSEQ_MODIFIED, XSEQ_DROP };

typedef void (*xseq_emit_fn)(void *ud, const uint8_t *pkt, size_t len);

/* A packet of f (reverse: it comes from the server), before everything
 * else of the extensions. XSEQ_PASS: unchanged; XSEQ_MODIFIED: p changed
 * (lengths and checksums to compute again); XSEQ_DROP: p must not go out.
 * A retransmission's segments (at most mss bytes of data each) go to emit
 * first. */
int xseq_packet(ct_flow *f, int reverse, gpkt *p, unsigned mss, xseq_emit_fn emit, void *ud);

#endif
