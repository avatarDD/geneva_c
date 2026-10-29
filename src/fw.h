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

#include "ports.h"
#include "util.h"

typedef enum { FW_AUTO = 0, FW_IPTABLES, FW_NFT } fw_backend;

typedef struct {
    fw_backend backend;
    uint16_t queue;
    uint32_t mark;
    portset ports;
    int tcp, udp;
    int server_side; /* out = from our ports, in = to them */
    int ipv4, ipv6;
    int out, in;     /* directions to queue */
    const char *iface; /* limit to this (WAN) interface */
    int prenat;      /* nft: queue outgoing packets before SNAT (iptables always does) */
    int notrack;     /* keep our own packets out of conntrack */
    int bypass;      /* accept packets while no program listens on the queue */
    int first;       /* queue only the first N packets of each connection (0 = all) */
    const char *forward_to; /* Geneva's forwarder: DNAT the ports to this address */
} fw_config;

void fw_config_default(fw_config *c);
const char *fw_backend_name(fw_backend b);
int fw_backend_parse(const char *s, fw_backend *out);

/* Shell commands that apply (up = 1) or remove (up = 0) the rules with the
 * given backend (not FW_AUTO). */
void fw_script(const fw_config *c, fw_backend b, int up, sbuf *out);

/* Applies the rules. With FW_AUTO tries nft, then iptables, and stores the
 * backend that worked in c->backend. Returns 0 or -1 with a message. */
int fw_up(fw_config *c, sbuf *err);
/* Removes the rules of c->backend (both backends for FW_AUTO). Errors are
 * ignored: missing rules are fine. */
void fw_down(const fw_config *c);

#endif
