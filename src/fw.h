/*
 * Firewall rules that send the strategy's traffic to NFQUEUE (Linux):
 * iptables/ip6tables or nftables. Rules live in their own chains (or their
 * own nft table) named after the queue number, so several instances can run
 * side by side, "up" is idempotent and "down" removes everything.
 *
 * Packets carrying the engine's mark (the ones it sends itself) are skipped
 * and, optionally, kept out of conntrack so that NAT does not rewrite them
 * and IP fragments are not reassembled.
 */
#ifndef GENEVA_FW_H
#define GENEVA_FW_H

#include <stdint.h>

#include "args.h"
#include "ports.h"
#include "util.h"

typedef enum { FW_AUTO = 0, FW_IPTABLES, FW_NFT } fw_backend;

#define FW_MAX_IFS 8 /* interfaces of --iface LIST and --ext-lan */

typedef struct {
    fw_backend backend;
    uint16_t queue;
    uint32_t mark;
    portset ports;
    int tcp, udp;
    int icmp;        /* --ext profiles: also ICMP and ICMPv6, both directions */
    uint8_t ipp[16]; /* --ext profiles: also these IP protocols */
    int nipp;
    int server_side; /* out = from our ports, in = to them */
    int ipv4, ipv6;
    int out, in;     /* directions to queue */
    const char *iface; /* limit to this (WAN) interface */
    int prenat;      /* nft: queue outgoing packets before SNAT (iptables always does) */
    int notrack;     /* keep our own packets out of conntrack */
    int bypass;      /* accept packets while no program listens on the queue */
    int first;       /* queue only the first N packets of each connection (0 = all) */
    const char *forward_to; /* Geneva's forwarder: DNAT the ports to this address */
    int forward;     /* router: queue forwarded packets from and to the ports, both
                      * directions (geneva censor); out, in and notrack are unused */
    /* Windows (WinDivert) */
    const char *filter;      /* a WinDivert expression: replaces the filter built from the
                              * ports, protocols and directions; with filter_narrow it is
                              * ANDed with that filter instead (evaluator slots) */
    const char *filter_file; /* where filter was read from (reload_filter) */
    int filter_narrow;
    int filter_whole;        /* --ext --wf-*: filter is complete, loopback and all */
    int priority;            /* WinDivert handle priority, -30000..30000 */
    /* --ext (docs/EXT.md, X7b): all zero without it, the rules as before */
    int first_dir;           /* firstv replaces first: per protocol and direction */
    int firstv[2][2];        /* [0 tcp, 1 udp][0 out, 1 in]: first N packets, 0 all */
    const char *ifs[FW_MAX_IFS]; /* --iface LIST: these interfaces (nifs of them) */
    int nifs;
    const char *lan[FW_MAX_IFS]; /* --ext-lan: the flowtable's other devices */
    int nlan;
    int notrack_frag;        /* --ext-notrack frag: of our packets only IP fragments and
                              * TCP without SYN, RST and ACK (zapret2's predefrag) */
    int ttl_icmp;            /* --ext-ttl-icmp: drop ICMP time-exceeded of queued flows */
    int offload;             /* --ext-flowoffload: 0 none, 1 software, 2 hardware (nft) */
    const char *hook_pre, *hook_post; /* --fw-hook-pre/post: run with up|down */
} fw_config;

#define FW_FILTER_FILE_MAX 65536 /* bytes of a --filter-file */
#define FW_PRIORITY_MAX 30000

#ifdef _WIN32
#  define FW_WINDOWS 1
#else
#  define FW_WINDOWS 0
#endif

void fw_config_default(fw_config *c);
const char *fw_backend_name(fw_backend b);
int fw_backend_parse(const char *s, fw_backend *out);

/* The --first count of a protocol (udp: 0 TCP, 1 UDP) and direction (in:
 * 0 out, 1 in); 0: every packet. fw_first_any: some count is set. */
int fw_first(const fw_config *c, int udp, int in);
int fw_first_any(const fw_config *c);

/* Shell commands that apply (up = 1) or remove (up = 0) the rules with the
 * given backend (not FW_AUTO). */
void fw_script(const fw_config *c, fw_backend b, int up, sbuf *out);

/* The WinDivert filter that captures the same traffic as the rules (the
 * Windows engine needs no firewall). iface must be an interface index there.
 * Returns 0, or -1 with a message. */
int fw_windivert_filter(const fw_config *c, sbuf *out, sbuf *err);
/* The same with expr (NULL: none) in place of c->filter: set_filter. */
int fw_windivert_filter_expr(const fw_config *c, const char *expr, sbuf *out, sbuf *err);

/* Reads a --filter-file: at most FW_FILTER_FILE_MAX bytes, its non-empty
 * lines joined by spaces. Returns 0, or -1 with a message. */
int fw_read_filter_file(const char *path, sbuf *out, sbuf *err);

/* --filter, --filter-file and --priority of run, eval, evolve and fw.
 * windows tells the platform (FW_WINDOWS; a parameter so that tests cover
 * both): elsewhere the options are refused. A file's expression goes to
 * *owned (free it). Returns 0, or -1 with a message (a usage error). */
int fw_parse_filter_args(const args_t *a, int windows, fw_config *c, char **owned, sbuf *err);

/* The rules of the evaluator's engine: local ports base .. base + span - 1
 * are the probes' (server_side: outbound packets come from them). */
void fw_eval_slots(fw_config *c, uint16_t base, uint32_t span, int udp);

/* Applies the rules. With FW_AUTO tries nft, then iptables, and stores the
 * backend that worked in c->backend. Returns 0 or -1 with a message. */
int fw_up(fw_config *c, sbuf *err);
/* Removes the rules of c->backend (both backends for FW_AUTO). Errors are
 * ignored: missing rules are fine. */
void fw_down(const fw_config *c);
/* fw_down calls fn instead (NULL: itself), e.g. when the engine dropped its
 * privileges and a root helper keeps the rules (src/ext/svc.c) */
void fw_set_down_hook(void (*fn)(const fw_config *c));

#endif
