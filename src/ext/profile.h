/*
 * Profiles of the extensions (docs/EXT_ROADMAP.md, 4.3; B1-B6, B8): several
 * strategies in one process, each for its own traffic, as zapret2's desync
 * profiles (nfq2/desync.c dp_match, dp_find, dp_rediscovery; nfq2/filter.c).
 *
 * A profile has filters and a strategy. The options of a command up to the
 * first --new are profile 0, whose strategy is the command's -s/-f (the one
 * "ctl" and SIGHUP change); every --new[=NAME] starts the next profile with
 * its own -s/-f. Profiles of an --ext-profile FILE come after those of the
 * command line, in the file's order. Options with zapret2's names:
 *
 *   --new[=NAME]        the next profile (NAME: its name)
 *   --name NAME         the name of this profile
 *   --skip              this profile is left out
 *   --template[=NAME]   this profile is a template, not a profile
 *   --import NAME       copy the filters (and the strategy) of a template
 *   --filter-l3 ipv4,ipv6
 *   --filter-tcp, --filter-udp [~]PORT[-PORT],...|*   (the server's port)
 *   --filter-icmp TYPE[:CODE],...|*
 *   --filter-ipp PROTO,...|*          (IP protocols other than TCP, UDP, ICMP)
 *   --filter-l7 PROTO,...             (tls, quic, http, known, unknown, ...)
 *   --filter-mark MARK[/MASK]
 *   --filter-ssid NAME,..., --filter-ssid-neg[=0|1]   (Linux: wlan.h)
 *   --hostlist FILE, --hostlist-domains NAME,...       (the host name)
 *   --hostlist-exclude FILE, --hostlist-exclude-domains NAME,...
 *   --ipset FILE, --ipset-ip CIDR,...                  (the server's address)
 *   --ipset-exclude FILE, --ipset-exclude-ip CIDR,...
 *   --hostlist-auto FILE, --hostlist-auto-fail-threshold N, ...  (autolist.h)
 *   --ext-arm STRATEGY (repeatable), --ext-tune rr:...            (tuner.h)
 *
 * As in zapret2, a profile with any of the tcp, udp, icmp or ipp filters
 * takes none of the protocols it names no filter for; one with none of them
 * takes every packet. A profile with host lists takes a packet only once
 * its host name is known and passes them (lists.h, zapret2's dp_match);
 * one with IP sets only for a server address they pass. Exclude lists come
 * first; include lists that are all empty pass everything. The first
 * profile that matches gets the packet; when
 * none does, the packet passes untouched. A tracked flow keeps its profile;
 * it is looked for again once the flow's L7 protocol is known (and, from
 * X6b, its host name), so a flow changes its profile at most twice. An ICMP
 * error that belongs to a flow goes with that flow's profile.
 */
#ifndef GENEVA_EXT_PROFILE_H
#define GENEVA_EXT_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#include "args.h"
#include "ctrack.h"
#include "lists.h"
#include "pkt.h"
#include "ports.h"
#include "strategy.h"

#define XPROF_MAX 255 /* profiles (and templates) at most */

typedef struct {
    uint16_t from, to;
    uint8_t neg;
} xpf; /* zapret2's port_filter; 0-0 with neg: no port */

enum { XF_SKIP = 0, XF_ANY, XF_FILTER }; /* zapret2's FLTMODE_* */

typedef struct {
    uint8_t mode, type, code, code_valid;
} xicf;

typedef struct {
    uint8_t mode, proto;
} xipp;

typedef struct {
    char *name;
    int n; /* zapret2's profile number: 1, 2, ... (templates their own) */
    int b_l3, ipv4, ipv6;
    xpf *tcp, *udp;
    size_t ntcp, nudp;
    xicf *icf;
    size_t nicf;
    xipp *ipp;
    size_t nipp;
    int b_l7;
    uint64_t l7; /* 0: every protocol */
    uint32_t mark, mark_mask;
    /* --filter-ssid (Linux): the Wi-Fi networks, --filter-ssid-neg */
    char **ssid;
    size_t nssid;
    int ssid_neg, ssid_neg_set;
    /* the strategy: text as given (-s, or the file's text), where it came
     * from ("-s", the file), and the parsed one (NULL for profile 0 of the
     * command line: the command's) */
    char *text, *src;
    strategy *st;
    int cmd; /* profile 0 of the command line: its strategy is the command's */
    int tpl_text; /* text is a template's: the profile's own -s replaces it */
    /* host lists and IP sets, include and exclude; the fixed lists of
     * --hostlist-domains, ... (one of each per profile, zapret2's anon_*) */
    xlistref hl, hl_ex, ips, ips_ex;
    xlist *fixed[4];
    /* --hostlist-auto: the autolist (also in hl), its parameters (set: the
     * ones given, for --import) and the fail counters per host */
    xlist *ahl;
    int ah_fail_threshold, ah_fail_time, ah_retrans_threshold, ah_retrans_reset, ah_udp_out, ah_udp_in;
    uint32_t ah_retrans_maxseq, ah_incoming_maxseq;
    unsigned ah_set;
    struct xahfail *fails;
    size_t nfails;
    uint64_t fails_purged;
    /* --ext-arm, --ext-tune: the tuner's arms replace the strategy (tuner.h) */
    struct xtune *tune;
} xprofile;

typedef struct {
    xprofile **v;
    size_t n;
} xprofiles;

/* What a profile is matched against */
typedef struct {
    int ver;           /* 4 or 6 */
    int proto;         /* IP protocol: 6, 17, 1, 58, ... */
    uint16_t port;     /* TCP, UDP: the server's port */
    uint8_t icmp_type, icmp_code;
    int l7;            /* L7_*: L7_UNKNOWN when not known */
    uint32_t mark;
    const uint8_t *ip; /* the server's address (4 or 16 bytes) */
    const char *host;  /* the host name (lower case, no port), NULL when not known */
    int host_ip;       /* the host name is an IP address: no subdomains */
    const char *ssid;  /* the SSID of the packet's interface, NULL: none (not Wi-Fi) */
} xmatch;

/* A profile with an autolist takes a flow once its host name is known,
 * whether the host is in its lists or not; the strategy then runs only for
 * a host that passes them (xprof_hosts). */
int xprof_hosts(const xprofile *p, const char *host, int host_ip, int *excluded);
int xprof_hostlists_empty(const xprofile *p);

/* Does a profile have --filter-ssid? (the Wi-Fi table is then read) */
int xprof_wants_ssid(const xprofiles *ps);

/* Does a command line use profiles (any profile option)? */
int xprof_wanted(const args_t *a);

/* Builds the profiles of a command line and of its --ext-profile files.
 * The strategies of profiles other than the command's are parsed here
 * (strategy_parse: the extensions must be registered). has_cmd_st: the
 * command got -s or -f before the first --new. Returns 0 (out->n is 0 when
 * no profile option is used), or -1 with a message in err. */
int xprof_build(const args_t *a, int has_cmd_st, xprofiles *out, sbuf *err);
/* The same from the text of a profile file alone (the fuzz target): keys
 * that read or write files (strategy-file, hostlist, ipset and their
 * -exclude forms, hostlist-auto) are refused. */
int xprof_build_text(const char *text, size_t len, xprofiles *out, sbuf *err);
void xprof_free(xprofiles *ps);

/* The first profile that takes m (its index), -1 when none does.
 * any_l7: as if the L7 filters and the host lists took any protocol and
 * host still unknown (could the profile take the flow later?). */
int xprof_find(const xprofiles *ps, const xmatch *m, int any_l7);
int xprof_match(const xprofile *p, const xmatch *m, int any_l7);

/* What the profiles take, for the capture (firewall rules, WinDivert
 * filter) */
#define XPROF_IPP_MAX 16
typedef struct {
    portset ports; /* TCP and UDP ports; with tcp, udp: who has any */
    int tcp, udp;
    int ports_ok;  /* 0: a profile takes every port ("*", "~" or no filter) */
    int icmp;      /* ICMP and ICMPv6 */
    uint8_t ipp[XPROF_IPP_MAX]; /* other IP protocols */
    int nipp;
} xcapture;
/* Returns 0, or -1 with a message when the capture cannot be told: the
 * ports (when ports is set) or the IP protocols ("*", too many). ports: the
 * command has no -p, the ports come from the profiles. */
int xprof_capture(const xprofiles *ps, int ports, xcapture *c, sbuf *err);

/* "1 (tls)" or "2": for the log */
void xprof_label(const xprofile *p, sbuf *out);

/* One option of a profile, by its CLI name (without "--"): for the
 * profile file and the tests. Returns 1 when name is a profile option, 0
 * when it is not, -1 with err on a bad value. */
int xprof_opt(xprofile *p, const char *name, const char *value, const xprofiles *templates, sbuf *err);

/* The parsers of the filters (for the tests). Return 0 or -1. */
int xprof_pf_list(const char *s, xpf **v, size_t *n);
int xprof_icf_list(const char *s, xicf **v, size_t *n);
int xprof_ipp_list(const char *s, xipp **v, size_t *n);
int xprof_mark(const char *s, uint32_t *mark, uint32_t *mask);

#endif
