/*
 * Minimal pcap / pcapng support for "geneva apply" and the tests.
 *
 * Reading: classic pcap (both byte orders, micro- and nanosecond stamps) and
 * pcapng (SHB/IDB/EPB/SPB/OPB blocks). Link layers: Ethernet (with 802.1Q/ad
 * tags), raw IP, IPv4, IPv6, Linux cooked v1/v2 and BSD loopback. Records
 * come back as IP packets with link headers and Ethernet padding removed.
 *
 * Writing: classic pcap with nanosecond stamps and LINKTYPE_RAW, so every
 * written record is a bare IPv4 or IPv6 packet.
 */
#ifndef GENEVA_PCAP_H
#define GENEVA_PCAP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "util.h"

#define LINKTYPE_NULL 0
#define LINKTYPE_ETHERNET 1
#define LINKTYPE_RAW 101
#define LINKTYPE_LINUX_SLL 113
#define LINKTYPE_IPV4 228
#define LINKTYPE_IPV6 229
#define LINKTYPE_LINUX_SLL2 276

typedef struct pcap_reader pcap_reader;
typedef struct pcap_writer pcap_writer;

typedef struct {
    uint64_t ts_ns;     /* capture time, ns since the epoch */
    const uint8_t *ip;  /* IP packet, or NULL for a non-IP record */
    size_t ip_len;
    size_t caplen;      /* bytes captured for the whole frame */
    size_t origlen;     /* frame length on the wire */
    int linktype;
} pcap_rec;

/* path "-" means stdin / stdout. Errors are appended to err. */
pcap_reader *pcap_open_read(const char *path, sbuf *err);
/* Takes ownership of f. */
pcap_reader *pcap_read_fp(FILE *f, sbuf *err);
/* Returns 1 with a record, 0 at the end, -1 on a malformed file. The record
 * stays valid until the next call. */
int pcap_next(pcap_reader *r, pcap_rec *rec, sbuf *err);
void pcap_close_read(pcap_reader *r);

pcap_writer *pcap_open_write(const char *path, sbuf *err);
/* Takes ownership of f. */
pcap_writer *pcap_write_fp(FILE *f, sbuf *err);
int pcap_write(pcap_writer *w, uint64_t ts_ns, const uint8_t *ip, size_t len);
/* Returns -1 if a write failed at any point. */
int pcap_close_write(pcap_writer *w);

#endif
