/*
 * The L7 layer of a tracked flow (docs/EXT_ROADMAP.md, 4.5; E1-E5, C7): what
 * each packet carries, the flow's protocol and host name, and the
 * reassembly of a TLS ClientHello split over TCP segments or of a QUIC
 * ClientHello split over several Initials, as nfqws2 does it
 * (dpi_desync_tcp_packet_play, dpi_desync_udp_packet_play).
 *
 * While a reassembly runs, the client's packets are held: the caller drops
 * them and xl7 keeps copies. When the message is complete, every held
 * packet is replayed through a callback with the whole message as its
 * payload view, so the strategy sees the ClientHello on each piece. When
 * the reassembly fails (a gap, too large, not a ClientHello after all), the
 * held packets are replayed too, each with its own payload and partial set:
 * nfqws2 lets them go past the strategy instead (its "UNSOLVED").
 */
#ifndef GENEVA_EXT_XL7_H
#define GENEVA_EXT_XL7_H

#include <stddef.h>
#include <stdint.h>

#include "ctrack.h"
#include "strategy.h"

#define XL7_REASM_MAX 16384 /* TCP_MAX_REASM, UDP_MAX_REASM: the default of reasm_max */
#define XL7_HELD_MAX 64     /* RAW_PACKET_QUEUE_DELAYED_MAX */
#define XL7_PCTX 112        /* bytes of the caller's packet context kept with a held packet */
#define XL7_HOST_MAX 256

typedef struct {
    uint64_t payload_disable; /* L7P_* bits not to recognize (0: none) */
    uint64_t reasm_disable;   /* L7P_* bits not to reassemble (0: none) */
    size_t reasm_max;         /* the longest message reassembled (0: XL7_REASM_MAX) */
} xl7_config;

/* What the strategy sees of one packet */
typedef struct {
    int l7;                /* L7_* of the flow (or of this packet without one) */
    int l7p;               /* L7P_* */
    const uint8_t *data;   /* the payload; TCP: the whole reassembled message on a replayed piece */
    size_t len;
    const uint8_t *dec;    /* QUIC: the decrypted ClientHello (a bare handshake message), else NULL */
    size_t dec_len;
    const char *host;      /* the flow's host name (lowercase), NULL when not known */
    unsigned piece, pieces; /* a replayed piece: 1..pieces; 0 otherwise */
    size_t offset;          /* TCP: where the piece starts in data */
    int partial;            /* released from a failed reassembly */
    /* a replayed piece: the flow's sides as they were after it came */
    const ct_side *cli, *srv;
} xl7_view;

typedef struct xl7 xl7;

/* Per worker: scratch buffers and the configuration */
xl7 *xl7_new(const xl7_config *c);
void xl7_free(xl7 *x);

/* Replays a held packet (raw IP bytes and the caller's context as given to
 * xl7_packet) with its view; v is NULL when the packet is to go on as it
 * is, outside the strategy (xl7_clear). */
typedef void (*xl7_replay_fn)(void *ud, const uint8_t *raw, size_t len, strat_dir dir, const void *pctx,
                              const xl7_view *v);

enum { XL7_GO = 0, XL7_HOLD = 1 };

/* Looks at p, fed into the conntrack already (f its flow, reverse: from the
 * server; f may be NULL). XL7_GO: run the strategy on p now, with *v (valid
 * until the next call). XL7_HOLD: p is kept (raw, pctx) and the caller
 * drops it. Held packets may have been replayed through fn before the
 * return, p among them. hold = 0 (the engine paused, no strategy): nothing
 * is held, and a reassembly in progress is given back as partial. */
int xl7_packet(xl7 *x, ct_flow *f, int reverse, const gpkt *p, strat_dir dir, const uint8_t *raw, size_t rawlen,
               const void *pctx, size_t pctx_len, int hold, xl7_replay_fn fn, void *ud, xl7_view *v);

/* Gives held packets of f back through fn as partial (the caller ends;
 * nfqws2 would lose them). */
void xl7_flush(ct_flow *f, xl7_replay_fn fn, void *ud);

/* For ct_config.clear: frees the host and the reassembly of f. Held
 * packets go through fn with no view (to pass as they are; nfqws2 loses
 * them), or are freed when fn is NULL. */
void xl7_clear(ct_flow *f, xl7_replay_fn fn, void *ud);

/* Held packets of f (0 when no reassembly runs) */
unsigned xl7_held(const ct_flow *f);

#endif
