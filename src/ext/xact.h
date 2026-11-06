/*
 * x-actions of the extensions (docs/EXT_ROADMAP.md 5.1, G, H): the desync
 * functions of zapret2 (lua/zapret-antidpi.lua) with their parameters and
 * behaviour, as actions of a Geneva tree.
 *
 *   xfake{blob=fake_default_tls;tlsmod=rnd,dupsid;ttl=auto:-2:3-20;repeats=2}
 *
 * Parameters are "key=value" or "key" alone, separated by ";". A value may
 * start with "#name" (the length of blob name), "%name" (the bytes of blob
 * name) or "\" (a "#" or "%" meant literally), resolved on every packet as
 * zapret2's apply_arg_prefix does. Keys take the names of the roadmap
 * ("ttl", "seq", "md5", ...) or zapret2's ("ip_ttl", "tcp_seq",
 * "tcp_md5", ...). An x-action makes its own packets (fakes, parts) with
 * their fooling and hands the packet to its subtree or absorbs it
 * (VERDICT_DROP); the forest gives the direction, so zapret2's "dir" has
 * no counterpart.
 *
 * The parts private to this directory: the action table (xact_*.c), the
 * run-time context and the sending path shared by every action.
 */
#ifndef GENEVA_EXT_XACT_H
#define GENEVA_EXT_XACT_H

#include <stddef.h>
#include <stdint.h>

#include "ctrack.h"
#include "strategy.h"
#include "tls.h"
#include "xtrig.h"

extern const strat_xact xact_ops;

/* For ct_config.clear: the per-flow state of the x-actions. */
void xact_flow_clear(ct_flow *f);

/* ---- for the actions (xact_*.c) ------------------------------------------- */

typedef struct {
    char *k; /* the canonical key */
    char *v; /* NULL: a flag */
} xparam;

/* Which common arguments an action takes (zapret2's "standard args") */
enum {
    XS_FOOL = 1,     /* ttl, ip6ext, seq, ack, ts, md5, flags, tsup, nopdel */
    XS_RECON = 2,    /* badsum */
    XS_SEND = 4,     /* repeats, ifout, fwmark */
    XS_IPID = 8,     /* ipid, ipid_conn */
    XS_FRAG = 16,    /* ipfrag and its positions */
    XS_PAYLOAD = 32, /* payload */
};

typedef struct xa_kind xa_kind;

typedef struct {
    const xa_kind *kind;
    char *text; /* the parameters as written, NULL without braces */
    xparam *p;
    int np;
    int started; /* xpcap: the file was started (zapret2's _G cache) */
} xact;

typedef struct xrun xrun;

struct xa_kind {
    const char *name;
    int kids;  /* subtrees: 0, 1 or 2 */
    int in_ok; /* allowed in the inbound forest */
    int std;   /* XS_* */
    const char *const *keys; /* its own keys, NULL-terminated */
    /* checks at parse time (NULL: none); values with a prefix are not known
     * yet and are checked when they are used */
    int (*check)(const xact *a, sbuf *err);
    void (*run)(const xact *a, gpkt *p, xrun *r);
};

/* fooling, as zapret2's apply_fooling reads it */
typedef struct {
    int ttl4, ttl6; /* -1: keep */
    int attl4, attl6; /* auto TTL: */
    int ad4, amin4, amax4, ad6, amin6, amax6;
    int has_seq, has_ack, has_ts;
    int64_t seq, ack, ts;
    int md5;
    uint8_t md5_data[16];
    int md5_given;
    uint16_t flags_set, flags_unset;
    int tsup, nopdel;
    /* IPv6 extension headers in zapret2's order */
    int hop, hop2, dst, dst2, rt, ah;
    uint8_t hop_d[64], hop2_d[64], dst_d[64], dst2_d[64], rt_d[64], ah_d[64];
    uint8_t hop_l, hop2_l, dst_l, dst2_l, rt_l, ah_l;
    int ah_given;
} xfool;

enum { XIPID_SEQ = 0, XIPID_RND, XIPID_ZERO, XIPID_NONE };

/* how a packet is sent (zapret2's desync_opts) */
typedef struct {
    const xfool *fool; /* NULL: no fooling */
    int tsup_only;     /* only fooling's tsup (the real parts of fakedsplit) */
    int badsum;
    int repeats;
    uint32_t fwmark;
    const char *ifout;
    int ipid;      /* XIPID_*, -1: the caller's default */
    int ipid_conn;
    int ipfrag, ipfrag_disorder;
    int pos_tcp, pos_udp, pos_icmp, pos_other;
    int ipfrag_next; /* -1: as the first fragment */
} xsendopt;

struct xrun {
    strat_xenv *env;
    xpkt_ctx *c;        /* NULL: no context (no conntrack, no L7) */
    ct_flow *f;         /* NULL: no flow */
    const xact *a;
    void *fs;           /* the action's per-flow slot (NULL without a flow) */
    const uint8_t *data; /* the payload, or the reassembled message on a replayed piece */
    size_t len;
    int l7p;            /* L7P_*: of the label when xtag set one (L7P_UNKNOWN for its own names) */
    const char *l7name; /* zapret2's desync.l7payload: the name, or xtag's label */
    unsigned piece, pieces;
    size_t offset;
    unsigned mss;
    xfool fool;
    xsendopt opt; /* from the common arguments */
    uint8_t scratch[2][256]; /* resolved "%blob" values */
    int nscratch;
};

/* An argument: NULL when absent, "" for a flag; prefixes resolved (the
 * bytes and their length in *len, which may hold zero bytes). */
const char *xa_arg(xrun *r, const char *key, size_t *len);
int xa_has(const xact *a, const char *key);
/* Lua's tonumber for integers: a sign, decimal or 0x hex. 0 or -1. */
int xa_parse_int(const char *s, int64_t *v);
/* A number argument; def when absent. -1 (logged) when it is not a number
 * in [lo, hi]. */
int xa_num(xrun *r, const char *key, int64_t def, int64_t lo, int64_t hi, int64_t *out);
/* A blob argument by name ("0xHEX" too), or NULL (logged unless optional).
 * The bytes stay valid while r runs. */
const uint8_t *xa_blob(xrun *r, const char *name, size_t *len, int optional);
int xa_blob_exists(xrun *r, const char *name);
/* zapret2's pattern(pat, offset, len): pat repeated, starting at offset
 * (1-based) */
void xa_pattern(const uint8_t *pat, size_t plen, size_t offset, uint8_t *out, size_t len);

/* the payload filter (default def: "known" or "all"), by names as
 * zapret2's payload_match_filter: xtag's own labels match too */
int xa_payload_ok(xrun *r, const char *def);
/* zapret2's in_list: v is one of the comma-separated list */
int xa_in_list(const char *list, const char *v);
/* zapret2's instance cutoff: the action leaves the flow alone from now on
 * (nothing without a flow); xa_is_cut tells */
void xa_cutoff(xrun *r);
int xa_is_cut(xrun *r);

/* The packet's own state (zapret2's desync table): blobs that an action
 * made for the actions after it (xtlsclone) and xtag's label. It lives
 * while the packet goes through the trees. */
void xa_dyn_blob_set(xrun *r, const char *name, const uint8_t *d, size_t n);
int xa_dyn_has(xrun *r, const char *name);
void xa_set_tag(xrun *r, const char *label);
/* a blob by name: the packet's own first, then --ext-blob and the built-in
 * ones (zapret2's blob(): desync, then _G) */
const uint8_t *xa_blob_named(xrun *r, const char *name, size_t *len);

/* tlsmod with "sni=%name" replaced by the blob (zapret2's tls_mod_shim) */
int xa_tlsmod_list(xrun *r, const char *v, tls_modspec *m);

/* checks at parse time, shared by the actions */
int xa_check_markers(const xact *a, const char *key, int range, sbuf *err);
int xa_check_num(const xact *a, const char *key, int64_t lo, int64_t hi, sbuf *err);
int xa_check_blob(const xact *a, const char *key, sbuf *err);
int xa_check_flag(const xact *a, const char *key, sbuf *err);
int xa_check_tlsmod(const xact *a, const char *who, sbuf *err);
/* a parameter's value as written (NULL: absent or a flag) */
const char *xa_raw(const xact *a, const char *key);

/* what every changed packet needs computed again */
#define XA_AUTO                                                                                                    \
    (AUTO_IP_LEN | AUTO_IP_CSUM | AUTO_IP_IHL | AUTO_TCP_DOFS | AUTO_TCP_CSUM | AUTO_UDP_LEN | AUTO_UDP_CSUM |    \
     AUTO_V6_PLEN)

/* VERDICT_PASS: the packet goes on as it is (or as the action changed it:
 * VERDICT_MODIFY); VERDICT_DROP: it goes on marked dropped (later
 * x-actions still see it, as in zapret2) */
static inline void xa_pass(xrun *r, gpkt *p) { strat_xchild(r->env, 0, p); }
static inline void xa_drop(xrun *r, gpkt *p)
{
    p->xdrop = 1;
    strat_xchild(r->env, 0, p);
}
/* the packet changed in place: lengths and checksums are computed again */
void xa_modified(gpkt *p);
/* zapret2's replay_first, replay_drop_set, replay_drop */
int xa_replay_first(const xrun *r);
void xa_replay_drop_set(xrun *r);
int xa_replay_drop(xrun *r);

/* Sending, as zapret2's rawsend_* (results go to the strategy's list as
 * packets of the x-action). 0, or -1 when it failed (nothing more is sent;
 * the action lets the packet pass). */
int xa_send_ipfrag(xrun *r, gpkt *dis, const xsendopt *o);
int xa_send_segmented(xrun *r, const gpkt *dis, const xsendopt *o);
int xa_send_payload(xrun *r, const gpkt *dis, const uint8_t *payload, size_t len, int64_t seq, const xsendopt *o);
void xa_fooling(xrun *r, gpkt *p, const xfool *f, int tsup_only);
void xa_ipid(xrun *r, gpkt *p, int mode, int conn);
/* the options of the fakes and of the real parts (hostfakesplit, fakedsplit) */
void xa_opts_fake(const xrun *r, xsendopt *o);
void xa_opts_orig(const xrun *r, xsendopt *o);

void xa_log(const xrun *r, const char *fmt, ...) PRINTF_LIKE(2, 3);

/* The actions */
extern const xa_kind xa_send, xa_mod, xa_fake, xa_split, xa_disorder, xa_tcpseg, xa_hostfake, xa_fakedsplit,
    xa_fakeddisorder;
extern const xa_kind xa_synacksplit, xa_synack, xa_wsize, xa_wssize, xa_syndata, xa_rst;
extern const xa_kind xa_http, xa_tlsclone, xa_udplen, xa_dhtdn, xa_xlog, xa_tag, xa_pcap;

#endif
