/*
 * Wi-Fi networks for the profile filter --filter-ssid (docs/EXT_ROADMAP.md,
 * B7; zapret2's nfq2/darkmagic.c, HAS_FILTER_SSID).
 *
 * Linux: nl80211 over generic netlink, without libmnl. The interfaces come
 * from NL80211_CMD_GET_INTERFACE (a dump), the SSID of each from its BSS in
 * state associated, authenticated or IBSS joined (NL80211_CMD_GET_SCAN),
 * because since Linux 5.19 GET_INTERFACE no longer gives it; an SSID that
 * GET_INTERFACE does give is kept when the scan has none. As in zapret2, the
 * table is read again at most once a second, on the next packet.
 *
 * The messages are built and parsed on every platform (the tests); the
 * socket is Linux's.
 */
#ifndef GENEVA_EXT_WLAN_H
#define GENEVA_EXT_WLAN_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

#define XWLAN_MAX 16 /* interfaces */

typedef struct {
    uint32_t ifindex;
    char ifname[17];
    char ssid[33]; /* "" when not connected */
} xwlan_if;

typedef struct {
    xwlan_if v[XWLAN_MAX];
    int n;
} xwlan_set;

/* Opens the socket and finds the family nl80211; 0, or -1 with a message */
int xwlan_init(sbuf *err);
void xwlan_free(void);
int xwlan_on(void);
/* Reads the table again when now_ms is in another second than the last
 * read (any thread; one reads, the others go on with the old table) */
void xwlan_refresh(uint64_t now_ms);
/* The SSID of interface ifname into out (33 bytes): 1, or 0 when the
 * interface is not a connected Wi-Fi one */
int xwlan_ssid(const char *ifname, char *out);
/* For tests and "--ext-wlan-list": the table now */
void xwlan_get(xwlan_set *s);

/* ---- messages ---------------------------------------------------------------- */

/* A generic netlink request: CMD of FAMILY, one optional u32 or string
 * attribute (attr 0: none); its length */
size_t xwlan_build(uint8_t *buf, size_t cap, uint16_t family, uint16_t flags, uint32_t seq, uint8_t cmd,
                   uint16_t attr, const void *data, size_t len);
/* Answers of one datagram. Each returns 1 when the dump (or the answer)
 * ended (NLMSG_DONE, or an acknowledgement), 0 when more is to come, -1
 * on an error answer (errno-like code in *err) or a malformed message. */
int xwlan_parse_family(const uint8_t *buf, size_t n, uint32_t seq, uint16_t *id, int *err);
/* GET_INTERFACE: adds the interfaces (with an index and a name) to s */
int xwlan_parse_ifaces(const uint8_t *buf, size_t n, uint32_t seq, xwlan_set *s, int *err);
/* GET_SCAN of one interface: the SSID of its associated BSS into s's entry
 * with that index */
int xwlan_parse_scan(const uint8_t *buf, size_t n, uint32_t seq, xwlan_set *s, int *err);

#endif
