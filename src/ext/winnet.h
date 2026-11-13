/*
 * winws2's --ssid-filter and --nlm-filter (docs/EXT_ROADMAP.md, B7;
 * zapret2's nfq2/darkmagic.c, win_dark_init and logical_net_filter_match):
 * the strategies run only while the computer is connected to one of the
 * Wi-Fi networks (WLAN API) or one of the Network List Manager networks
 * (by name or GUID) given; -neg inverts a filter, and both must hold.
 *
 * winws2 closes WinDivert while the networks are absent; geneva keeps it
 * and lets every packet pass untouched (as "ctl pause" does). A thread
 * checks the networks once a second; wlanapi.dll, ole32.dll and
 * oleaut32.dll are loaded from System32 (LoadLibrary), only when a filter
 * needs them.
 */
#ifndef GENEVA_EXT_WINNET_H
#define GENEVA_EXT_WINNET_H

#include <stddef.h>
#include <stdint.h>

#include "args.h"
#include "util.h"

/* From the options: 0 without filters, 1 with the monitor started, -1 with
 * a message (no filter support here, a library missing) */
int xwinnet_start(const args_t *a, sbuf *err);
void xwinnet_stop(void);
/* The networks the filters ask for are there (1 without filters) */
int xwinnet_ok(void);
/* --nlm-list[=all]: the Network List Manager networks, connected ones (or
 * all) into out; 0, or -1 with a message */
int xwinnet_nlm_list(int all, sbuf *out, sbuf *err);

/* ---- helpers (every platform: the tests) ------------------------------------- */

/* zapret2's str2guid: "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" into the
 * 16 bytes of a GUID in memory order (Data1-3 little endian); 0 or -1 */
int xwinnet_guid(const char *s, uint8_t g[16]);
void xwinnet_guid_str(const uint8_t g[16], char out[37]);
/* a comma-separated list (zapret2's parse_strlist): names of 1..maxlen */
int xwinnet_list_parse(const char *v, size_t maxlen, char ***out, size_t *n);
void xwinnet_list_free(char **v, size_t n);
/* is a network of this name (or GUID, may be NULL) in the list? */
int xwinnet_list_has(char *const *v, size_t n, const char *name, const uint8_t *guid);

#endif
