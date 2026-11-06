/*
 * Triggers of the extensions (docs/EXT_ROADMAP.md, 5.1): FLOW: (the
 * packet's flow in ctrack), META: (where the packet came from) and L7:
 * (what it carries, src/ext/xl7.c).
 *
 *   FLOW:n|d|b|s|p:RANGE      this side's packets, packets with data, data
 *                             bytes, relative seq, position (zapret2's
 *                             --out-range/--in-range: "1-5", "<10", "3-",
 *                             "5", or with letters, "n1-n5")
 *   FLOW:rn|rd|rb|rs|rp:RANGE the same for the other side
 *   FLOW:state:syn|est|fin    the TCP state of the flow
 *   FLOW:retrans:0|1          the packet repeats data already seen (TCP)
 *   META:ifin|ifout:NAME      the interface the packet came in or goes out
 *   META:mark:N[/MASK]        the firewall mark
 *   L7:proto:LIST             the flow's protocol (tls,quic,...,known,unknown;
 *                             "~" in front negates: zapret2's --filter-l7)
 *   L7:payload:LIST           what the packet carries (tls_client_hello,
 *                             empty, known, ...: zapret2's --payload)
 *   L7:host:LIST              the flow's host name: "example.com" is the name
 *                             and its subdomains, "*cdn.net" any name ending so
 *
 * A tree whose FLOW range (of this side) is behind the packet's flow for
 * good is cut off on that flow (zapret2's instance cutoff, D7): it is not
 * looked at again there. When every tree of a forest is cut off, the flow's
 * packets in that direction pass by the strategy (xtrig_all_cut). The
 * x-action xcutoff cuts trees off the same way (xtrig_cut).
 *
 * Without a flow (no ctrack, or a packet ctrack does not track) a FLOW
 * trigger matches only an "a" range, as in zapret2.
 */
#ifndef GENEVA_EXT_XTRIG_H
#define GENEVA_EXT_XTRIG_H

#include "ctrack.h"
#include "strategy.h"
#include "xl7.h"

/* What strategy_apply_x() gets as its context. */
typedef struct {
    ct_flow *f;     /* NULL: no flow */
    int reverse;    /* the packet comes from the flow's server */
    const strategy *st; /* the strategy running: cut bits are about it */
    const char *ifin, *ifout; /* NULL: unknown */
    uint32_t mark;
    int has_meta;
    const xl7_view *l7; /* NULL: not looked at */
    /* per packet, for the x-actions: zapret2's desync.ip_id ("ipid=seq") */
    uint16_t ipid;
    int has_ipid;
} xpkt_ctx;

extern const strat_xtrig xtrig_ops;

/* Every tree of the forest of dir is cut off on f (for strategy s). */
int xtrig_all_cut(const strategy *s, strat_dir dir, ct_flow *f);
/* xcutoff: cuts tree number tree of the forest of dir (every tree of it
 * when all) off on the packet's flow. 0 when there is no flow to cut. */
int xtrig_cut(void *ctx, strat_dir dir, size_t tree, int all);

#endif
