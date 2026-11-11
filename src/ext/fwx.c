#include "fwx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#  include <unistd.h>
#endif

#include "profile.h"

/* ---- small parsers ------------------------------------------------------- */

static int num(const char *s, size_t n, unsigned max, unsigned *out)
{
    unsigned v = 0;
    if (!n || n > 10)
        return -1;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return -1;
        v = v * 10 + (unsigned)(s[i] - '0');
        if (v > max)
            return -1;
    }
    *out = v;
    return 0;
}

int xfw_first(const char *s, int base, fw_config *c)
{
    unsigned v;
    for (int p = 0; p < 2; p++)
        for (int d = 0; d < 2; d++)
            c->firstv[p][d] = base;
    if (!num(s, strlen(s), 1000000, &v)) {
        for (int p = 0; p < 2; p++)
            for (int d = 0; d < 2; d++)
                c->firstv[p][d] = (int)v;
        c->first_dir = 1;
        return 0;
    }
    for (;;) {
        const char *e = strchr(s, ','), *eq;
        size_t l = e ? (size_t)(e - s) : strlen(s), kl;
        int p0 = 0, p1 = 1, d;
        eq = memchr(s, '=', l);
        if (!eq)
            return -1;
        kl = (size_t)(eq - s);
        if (kl > 4 && (!strncmp(s, "tcp-", 4) || !strncmp(s, "udp-", 4))) {
            p0 = p1 = s[0] == 'u';
            s += 4, kl -= 4, l -= 4;
        }
        if (kl == 3 && !strncmp(s, "out", 3))
            d = 0;
        else if (kl == 2 && !strncmp(s, "in", 2))
            d = 1;
        else
            return -1;
        if (num(s + kl + 1, l - kl - 1, 1000000, &v) < 0)
            return -1;
        for (int p = p0; p <= p1; p++)
            c->firstv[p][d] = (int)v;
        if (!e)
            break;
        s = e + 1;
    }
    c->first_dir = 1;
    return 0;
}

int xfw_iflist(const char *s, char *buf, size_t cap, const char **v)
{
    int n = 0;
    char *p, *e;
    if (strlen(s) >= cap)
        return -1;
    strcpy(buf, s);
    for (p = buf;; p = e + 1) {
        e = strchr(p, ',');
        if (e)
            *e = 0;
        /* as --iface: what the rules can quote */
        if (!*p || strlen(p) >= 16 || strpbrk(p, " \t\"'\\;{}") || n == FW_MAX_IFS)
            return -1;
        v[n++] = p;
        if (!e)
            return n;
    }
}

/* ---- WinDivert: winws2's --wf-* ------------------------------------------ */

static const char *const wf_capture[] = {"wf-tcp-in", "wf-tcp-out", "wf-udp-in", "wf-udp-out", "wf-icmp-in",
                                         "wf-icmp-out", "wf-ipp-in", "wf-ipp-out", "wf-raw", "wf-raw-part"};

int xfw_wf_captures(const args_t *a)
{
    for (size_t i = 0; i < sizeof(wf_capture) / sizeof(*wf_capture); i++)
        if (arg_has(a, wf_capture[i]))
            return 1;
    return 0;
}

/* wf_make_pf: "(tcp.DstPort == 443 or (tcp.DstPort >= 80 and ...))" */
static int wf_pf(const char *opt, const char *l4, const char *field, sbuf *out)
{
    xpf *v = NULL;
    size_t n = 0;
    if (xprof_pf_list(opt, &v, &n) < 0) {
        free(v);
        return -1;
    }
    sb_putc(out, '(');
    for (size_t i = 0; i < n; i++) {
        if (i)
            sb_puts(out, " or ");
        if (v[i].from == v[i].to)
            sb_printf(out, "(%s.%s %s %u)", l4, field, v[i].neg ? "!=" : "==", v[i].from);
        else
            sb_printf(out, "(%s.%s %s %u %s %s.%s %s %u)", l4, field, v[i].neg ? "<" : ">=", v[i].from,
                      v[i].neg ? "or" : "and", l4, field, v[i].neg ? ">" : "<=", v[i].to);
    }
    sb_putc(out, ')');
    free(v);
    return 0;
}

/* wf_make_icf and wf_make_ipf */
static int wf_icf(const char *opt, sbuf *out)
{
    xicf *v = NULL;
    size_t n = 0, k = 0;
    if (xprof_icf_list(opt, &v, &n) < 0) {
        free(v);
        return -1;
    }
    sb_putc(out, '(');
    for (size_t i = 0; i < n; i++) {
        if (v[i].mode == XF_SKIP)
            continue;
        if (k++)
            sb_puts(out, " or ");
        if (v[i].mode == XF_ANY)
            sb_puts(out, "icmp or icmpv6");
        else if (v[i].code_valid)
            sb_printf(out, "icmp.Type==%u and icmp.Code==%u or icmpv6.Type==%u and icmpv6.Code==%u", v[i].type,
                      v[i].code, v[i].type, v[i].code);
        else
            sb_printf(out, "icmp.Type==%u or icmpv6.Type==%u", v[i].type, v[i].type);
    }
    sb_putc(out, ')');
    free(v);
    return k ? 0 : -1; /* nothing added */
}

static int wf_ipf(const char *opt, sbuf *out)
{
    xipp *v = NULL;
    size_t n = 0, k = 0;
    if (xprof_ipp_list(opt, &v, &n) < 0) {
        free(v);
        return -1;
    }
    sb_putc(out, '(');
    for (size_t i = 0; i < n; i++) {
        if (v[i].mode == XF_SKIP)
            continue;
        if (k++)
            sb_puts(out, " or ");
        if (v[i].mode == XF_ANY)
            sb_puts(out, "ip or ipv6");
        else /* WinDivert does not walk IPv6 extension headers: the first one is matched */
            sb_printf(out, "ip.Protocol==%u or ipv6.NextHdr==%u", v[i].proto, v[i].proto);
    }
    sb_putc(out, ')');
    free(v);
    return k ? 0 : -1;
}

/* FILTER or @FILE (its lines joined) */
static int wf_text(const char *opt, const char *v, sbuf *out, sbuf *err)
{
    if (*v == '@') {
        sbuf e;
        int r;
        sb_init(&e);
        r = fw_read_filter_file(v + 1, out, &e);
        if (r < 0)
            sb_printf(err, "--%s: %s", opt, e.data);
        sb_free(&e);
        return r;
    }
    if (!*v) {
        sb_printf(err, "--%s: empty filter", opt);
        return -1;
    }
    sb_puts(out, v);
    return 0;
}

static int wf_bool(const args_t *a, const char *name, int def, int *out, sbuf *err)
{
    const char *v = arg_str(a, name, NULL);
    if (!v) {
        *out = def;
        return 0;
    }
    if (!*v && def < 0) { /* --wf-tcp-empty alone: on */
        *out = 1;
        return 0;
    }
    if (strcmp(v, "0") && strcmp(v, "1")) {
        sb_printf(err, "--%s must be 0 or 1", name);
        return -1;
    }
    *out = *v == '1';
    return 0;
}

#define NO_LAN4(F)                                                                                             \
    "((ip." F " < 10.0.0.0 or ip." F " > 10.255.255.255) and (ip." F " < 192.168.0.0 or ip." F                     \
    " > 192.168.255.255) and (ip." F " < 172.16.0.0 or ip." F " > 172.31.255.255) and (ip." F                       \
    " < 169.254.0.0 or ip." F " > 169.254.255.255))"
#define NO_LAN6(F)                                                                                             \
    "((ipv6." F " < 2001::0 or ipv6." F " >= 2001:1::0) and (ipv6." F " < fc00::0 or ipv6." F                       \
    " >= fe00::0) and (ipv6." F " < fe80::0 or ipv6." F " >= fec0::0) and (ipv6." F " < ff00::0 or ipv6." F       \
    " >= ffff::0))"
#define TCP_NOT_EMPTY "(!tcp or tcp.Syn or tcp.Rst or tcp.Fin or tcp.PayloadLength>0)"
#define TCP_ALWAYS "(tcp.Syn or tcp.Rst or tcp.Fin)"
/* HTTP/1.? 30(2|7): an autolist's redirect check */
#define HTTP_REDIRECT                                                                                          \
    "tcp.PayloadLength>=12 and tcp.Payload32[0]==0x48545450 and tcp.Payload16[2]==0x2F31 and "                  \
    "tcp.Payload[6]==0x2E and tcp.Payload16[4]==0x2033 and tcp.Payload[10]==0x30 and (tcp.Payload[11]==0x32 "    \
    "or tcp.Payload[11]==0x37)"

int xfw_wf_filter(const args_t *a, int server, sbuf *out, sbuf *err)
{
    /* the port filters of each option against SrcPort [0] and DstPort [1] */
    static const char *const popt[4] = {"wf-tcp-out", "wf-tcp-in", "wf-udp-out", "wf-udp-in"};
    sbuf pf[4][2], icf[2], ipf[2], rawf;
    const char *s, *v;
    unsigned ifidx = 0, subidx = 0;
    int ipv4 = 1, ipv6 = 1, tcp_empty, lan, loopback, rc = -1, idx = 0, have_tcp;
    const sbuf *tcp_src_out, *tcp_dst_out, *tcp_src_in, *tcp_dst_in, *udp_src_in, *udp_dst_out;

    for (int i = 0; i < 4; i++)
        sb_init(&pf[i][0]), sb_init(&pf[i][1]);
    sb_init(&icf[0]), sb_init(&icf[1]), sb_init(&ipf[0]), sb_init(&ipf[1]), sb_init(&rawf);

    if ((s = arg_str(a, "wf-raw", NULL)) != NULL) {
        /* the whole filter: the other --wf-* that capture make no sense */
        for (size_t i = 0; i < sizeof(wf_capture) / sizeof(*wf_capture) - 2; i++)
            if (arg_has(a, wf_capture[i])) {
                sb_printf(err, "--wf-raw replaces the filter: no --%s with it", wf_capture[i]);
                goto done;
            }
        if (arg_has(a, "wf-raw-part") || arg_has(a, "wf-raw-filter")) {
            sb_puts(err, "--wf-raw replaces the filter: no --wf-raw-part or --wf-raw-filter with it");
            goto done;
        }
        rc = wf_text("wf-raw", s, out, err);
        goto done;
    }
    if ((s = arg_str(a, "wf-iface", NULL)) != NULL) {
        const char *dot = strchr(s, '.');
        if (num(s, dot ? (size_t)(dot - s) : strlen(s), 0xffffffffu, &ifidx) < 0 ||
            (dot && num(dot + 1, strlen(dot + 1), 0xffffffffu, &subidx) < 0)) {
            sb_puts(err, "--wf-iface takes IFIDX[.SUBIFIDX]");
            goto done;
        }
    }
    if ((s = arg_str(a, "wf-l3", NULL)) != NULL) {
        ipv4 = ipv6 = 0;
        for (;;) {
            const char *e = strchr(s, ',');
            size_t l = e ? (size_t)(e - s) : strlen(s);
            if (l == 4 && !strncmp(s, "ipv4", 4))
                ipv4 = 1;
            else if (l == 4 && !strncmp(s, "ipv6", 4))
                ipv6 = 1;
            else {
                sb_puts(err, "--wf-l3 takes ipv4, ipv6 or ipv4,ipv6");
                goto done;
            }
            if (!e)
                break;
            s = e + 1;
        }
    }
    for (int i = 0; i < 4; i++)
        if ((s = arg_str(a, popt[i], NULL)) != NULL &&
            (wf_pf(s, i < 2 ? "tcp" : "udp", "SrcPort", &pf[i][0]) < 0 ||
             wf_pf(s, i < 2 ? "tcp" : "udp", "DstPort", &pf[i][1]) < 0)) {
            sb_printf(err, "--%s takes [~]PORT[-PORT],...", popt[i]);
            goto done;
        }
    for (int d = 0; d < 2; d++) {
        if ((s = arg_str(a, d ? "wf-icmp-in" : "wf-icmp-out", NULL)) != NULL && wf_icf(s, &icf[d]) < 0) {
            sb_printf(err, "--wf-icmp-%s takes TYPE[:CODE],... or *", d ? "in" : "out");
            goto done;
        }
        if ((s = arg_str(a, d ? "wf-ipp-in" : "wf-ipp-out", NULL)) != NULL && wf_ipf(s, &ipf[d]) < 0) {
            sb_printf(err, "--wf-ipp-%s takes PROTO,... or *", d ? "in" : "out");
            goto done;
        }
    }
    if ((s = arg_str(a, "wf-raw-filter", NULL)) != NULL && wf_text("wf-raw-filter", s, &rawf, err) < 0)
        goto done;
    if (wf_bool(a, "wf-tcp-empty", -1, &tcp_empty, err) < 0 || wf_bool(a, "wf-filter-lan", 1, &lan, err) < 0 ||
        wf_bool(a, "wf-filter-loopback", 1, &loopback, err) < 0)
        goto done;
    if (tcp_empty < 0)
        tcp_empty = 0;
    if (!pf[0][0].len && !pf[1][0].len && !pf[2][0].len && !pf[3][0].len && !icf[0].len && !icf[1].len &&
        !ipf[0].len && !ipf[1].len && !arg_has(a, "wf-raw-part")) {
        sb_puts(err, "the --wf-* filter needs ports, ICMP, IP protocols or --wf-raw-part");
        goto done;
    }
    /* the arguments of wf_make_filter, client or server (nfqws.c) */
    tcp_src_out = &pf[0][server ? 1 : 0];
    tcp_dst_out = &pf[0][server ? 0 : 1];
    tcp_src_in = &pf[1][server ? 1 : 0];
    tcp_dst_in = &pf[1][server ? 0 : 1];
    udp_src_in = &pf[3][server ? 1 : 0];
    udp_dst_out = &pf[2][server ? 0 : 1];
    have_tcp = tcp_src_in->len || tcp_dst_out->len;

    sb_puts(out, "!impostor");
    if (loopback)
        sb_puts(out, "\nand !loopback");
    if (ifidx)
        sb_printf(out, "\nand ifIdx=%u and subIfIdx=%u", ifidx, subidx);
    if (ipv4 ^ ipv6)
        sb_printf(out, "\nand %s", ipv4 ? "ip" : "ipv6");
    if (have_tcp && !tcp_empty)
        sb_puts(out, "\nand " TCP_NOT_EMPTY);
    if (rawf.len)
        sb_printf(out, "\nand\n(\n%s\n)", rawf.data);
    sb_puts(out, "\nand\n(\n false");
    if (have_tcp)
        sb_puts(out, " or\n " HTTP_REDIRECT);
    while ((v = arg_next(a, "wf-raw-part", &idx)) != NULL) {
        sbuf part;
        int r;
        sb_init(&part);
        r = wf_text("wf-raw-part", v, &part, err);
        if (!r)
            sb_printf(out, " or\n (\n%s\n )", part.data);
        sb_free(&part);
        if (r < 0)
            goto done;
    }
    if (tcp_dst_out->len) {
        sb_printf(out, " or\n outbound and %s", tcp_dst_out->data);
        /* the opposite SYN, FIN and RST always, for the conntrack */
        sb_printf(out, " or\n inbound and " TCP_ALWAYS " and %s", tcp_src_out->data);
    }
    if (tcp_src_in->len) {
        sb_printf(out, " or\n inbound and %s", tcp_src_in->data);
        sb_printf(out, " or\n outbound and " TCP_ALWAYS " and %s", tcp_dst_in->data);
    }
    if (udp_dst_out->len)
        sb_printf(out, " or\n outbound and %s", udp_dst_out->data);
    if (udp_src_in->len)
        sb_printf(out, " or\n inbound and %s", udp_src_in->data);
    if (icf[1].len)
        sb_printf(out, " or\n inbound and %s", icf[1].data);
    if (icf[0].len)
        sb_printf(out, " or\n outbound and %s", icf[0].data);
    if (ipf[1].len)
        sb_printf(out, " or\n inbound and %s", ipf[1].data);
    if (ipf[0].len)
        sb_printf(out, " or\n outbound and %s", ipf[0].data);
    sb_puts(out, "\n)");
    if (lan) {
        const char *dst = ipv4 ? ipv6 ? "(" NO_LAN4("DstAddr") " or " NO_LAN6("DstAddr") ")" : NO_LAN4("DstAddr")
                               : NO_LAN6("DstAddr");
        const char *src = ipv4 ? ipv6 ? "(" NO_LAN4("SrcAddr") " or " NO_LAN6("SrcAddr") ")" : NO_LAN4("SrcAddr")
                               : NO_LAN6("SrcAddr");
        sb_printf(out, "\nand\n(\n outbound and %s\n or\n inbound and %s\n)\n", dst, src);
    }
    rc = 0;
done:
    for (int i = 0; i < 4; i++)
        sb_free(&pf[i][0]), sb_free(&pf[i][1]);
    sb_free(&icf[0]), sb_free(&icf[1]), sb_free(&ipf[0]), sb_free(&ipf[1]), sb_free(&rawf);
    return rc;
}

/* ---- the options ----------------------------------------------------------- */

static char g_ifbuf[2][FW_MAX_IFS * 17 + 1]; /* the names of --ext-wan and --ext-lan */

static int hook_path(const char *opt, const char *v, sbuf *err)
{
    if (*v != '/' || strchr(v, '\'')) {
        sb_printf(err, "--%s needs an absolute path without quotes", opt);
        return -1;
    }
#ifndef _WIN32
    if (access(v, X_OK) < 0) {
        sb_printf(err, "--%s: %s is not an executable file", opt, v);
        return -1;
    }
#endif
    return 0;
}

int xfw_parse(const args_t *a, int windows, fw_config *c, char **owned, const char **save, sbuf *err)
{
    const char *s;
    *save = arg_str(a, "wf-save", NULL);
    if ((s = arg_str(a, "ext-first", NULL)) != NULL && xfw_first(s, c->first, c) < 0) {
        sb_puts(err, "--ext-first takes N or [tcp-|udp-]out=N,[tcp-|udp-]in=N,...");
        return -1;
    }
    if ((s = arg_str(a, "ext-wan", NULL)) != NULL) {
        if (c->iface) {
            sb_puts(err, "--ext-wan and --iface exclude each other");
            return -1;
        }
        c->nifs = xfw_iflist(s, g_ifbuf[0], sizeof(g_ifbuf[0]), c->ifs);
        if (c->nifs < 0) {
            c->nifs = 0;
            sb_printf(err, "--ext-wan takes up to %d interface names separated by commas", FW_MAX_IFS);
            return -1;
        }
        c->iface = c->ifs[0];
    }
    if ((s = arg_str(a, "ext-lan", NULL)) != NULL) {
        c->nlan = xfw_iflist(s, g_ifbuf[1], sizeof(g_ifbuf[1]), c->lan);
        if (c->nlan < 0) {
            c->nlan = 0;
            sb_printf(err, "--ext-lan takes up to %d interface names separated by commas", FW_MAX_IFS);
            return -1;
        }
    }
    if ((s = arg_str(a, "ext-notrack", NULL)) != NULL) {
        if (!strcmp(s, "none"))
            c->notrack = 0;
        else if (!strcmp(s, "frag"))
            c->notrack = c->notrack_frag = 1;
        else if (!strcmp(s, "all"))
            c->notrack = 1;
        else {
            sb_puts(err, "--ext-notrack must be all, frag or none");
            return -1;
        }
        if (arg_has(a, "no-notrack") && c->notrack) {
            sb_puts(err, "--no-notrack and --ext-notrack all|frag exclude each other");
            return -1;
        }
    }
    c->ttl_icmp = arg_has(a, "ext-ttl-icmp");
    if ((s = arg_str(a, "ext-flowoffload", NULL)) != NULL) {
        if (!strcmp(s, "none"))
            c->offload = 0;
        else if (!strcmp(s, "software"))
            c->offload = 1;
        else if (!strcmp(s, "hardware"))
            c->offload = 2;
        else {
            sb_puts(err, "--ext-flowoffload must be none, software or hardware");
            return -1;
        }
        if (c->offload && (!c->iface || !c->nlan)) {
            sb_puts(err, "--ext-flowoffload needs the WAN (--iface or --ext-wan) and the LAN (--ext-lan) "
                         "interfaces");
            return -1;
        }
        if (c->offload && c->backend == FW_IPTABLES) {
            sb_puts(err, "--ext-flowoffload works with nft only");
            return -1;
        }
    } else if (c->nlan) {
        sb_puts(err, "--ext-lan is for --ext-flowoffload");
        return -1;
    }
    c->hook_pre = arg_str(a, "fw-hook-pre", NULL);
    c->hook_post = arg_str(a, "fw-hook-post", NULL);
    if ((c->hook_pre && hook_path("fw-hook-pre", c->hook_pre, err) < 0) ||
        (c->hook_post && hook_path("fw-hook-post", c->hook_post, err) < 0))
        return -1;
    if (windows) {
        static const char *const linux_only[] = {"ext-lan", "ext-notrack", "ext-ttl-icmp",
                                                 "ext-flowoffload", "fw-hook-pre", "fw-hook-post"};
        for (size_t i = 0; i < sizeof(linux_only) / sizeof(*linux_only); i++)
            if (arg_has(a, linux_only[i])) {
                sb_printf(err, "--%s is Linux only", linux_only[i]);
                return -1;
            }
    }
    if ((s = arg_str(a, "wf-priority", NULL)) != NULL) {
        int64_t v;
        if (arg_has(a, "priority")) {
            sb_puts(err, "--wf-priority and --priority exclude each other");
            return -1;
        }
        if (parse_i64(s, &v) < 0 || v < -FW_PRIORITY_MAX || v > FW_PRIORITY_MAX) {
            sb_printf(err, "--wf-priority must be a number from %d to %d", -FW_PRIORITY_MAX, FW_PRIORITY_MAX);
            return -1;
        }
        c->priority = (int)v;
    }
    if (xfw_wf_captures(a) || arg_has(a, "wf-raw-filter") || *save) {
        sbuf f;
        if (c->filter) {
            sb_puts(err, "the --wf-* filter and --filter/--filter-file exclude each other");
            return -1;
        }
        sb_init(&f);
        if (xfw_wf_filter(a, c->server_side, &f, err) < 0) {
            sb_free(&f);
            return -1;
        }
        *owned = sb_take(&f);
        c->filter = *owned;
        c->filter_whole = 1;
    }
    return 0;
}
