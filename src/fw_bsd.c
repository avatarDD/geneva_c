/*
 * Firewall rules for the BSD divert backend (src/eng_divert.c):
 *
 *   FreeBSD  ipfw: "divert PORT" rules, one rule number of their own (the
 *            lowest one without rules from FW_IPFW_FIRST), every rule with
 *            the comment "geneva PORT"; "not diverted" lets the packets the
 *            engine writes back go on
 *   OpenBSD  pf: "pass ... divert-packet port PORT" rules in the anchor
 *            "geneva/PORT", which pf.conf must call (the line: anchor, then
 *            "geneva/" and an asterisk in quotes)
 *
 * The divert port is fw_config.queue. The scripts are plain text so that
 * "geneva fw print" shows them on any platform and the tests check them;
 * applying them needs the BSD in question.
 */
#include "fw.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fw_int.h"
#include "log.h"

/* what the divert backend cannot do; 0, or -1 with a message */
int fw_bsd_check(const fw_config *c, fw_backend b, sbuf *err)
{
    const char *what = NULL;
    if (c->forward || c->forward_to)
        what = "router mode (geneva censor, the forwarder)";
    else if (c->obs)
        what = "--ext-auto observation (NFLOG)";
    else if (c->healthy_mark)
        what = "--ext-healthy-mark (the surgical path)";
    else if (c->offload || c->nlan)
        what = "--ext-flowoffload and --ext-lan";
    else if (c->nqueues > 1)
        what = "--ext-workers";
    else if (c->ttl_icmp)
        what = "--ext-ttl-icmp";
    if (what) {
        sb_printf(err, "%s needs Linux; %s rules cannot express it", what, fw_backend_name(b));
        return -1;
    }
    return 0;
}

/* ports as ipfw ("80,443,1000-2000") or pf ("{ 80 443 1000:2000 }") lists */
static void bsd_ports(const portset *ps, int pf, sbuf *out)
{
    if (pf && ps->n > 1)
        sb_puts(out, "{ ");
    for (int i = 0; i < ps->n; i++) {
        if (i)
            sb_puts(out, pf ? " " : ",");
        sb_printf(out, "%u", ps->lo[i]);
        if (ps->hi[i] != ps->lo[i])
            sb_printf(out, "%s%u", pf ? ":" : "-", ps->hi[i]);
    }
    if (pf && ps->n > 1)
        sb_puts(out, " }");
}

/* ---- ipfw ---------------------------------------------------------------- */

/* one rule: "PROTO from any [port] to any [port] DIR [IFACE]" */
static void ipfw_rule(const fw_config *c, sbuf *out, const char *rule, const char *proto, int fam, int outdir,
                      const char *ifname, int ports)
{
    /* client side: outgoing packets go to the ports, incoming come from them */
    int src = outdir ? c->server_side : !c->server_side;
    sb_printf(out, "ipfw -q add %s divert %u %s from any", rule, c->queue, proto);
    if (ports && src) {
        sb_putc(out, ' ');
        bsd_ports(&c->ports, 0, out);
    }
    sb_puts(out, " to any");
    if (ports && !src) {
        sb_putc(out, ' ');
        bsd_ports(&c->ports, 0, out);
    }
    sb_printf(out, " %s", outdir ? "out" : "in");
    if (ifname)
        sb_printf(out, " %s %s", outdir ? "xmit" : "recv", ifname);
    if (fam == 4)
        sb_puts(out, " ip4");
    else if (fam == 6)
        sb_puts(out, " ip6");
    sb_printf(out, " not diverted // geneva %u\n", c->queue);
}

void fw_ipfw_rules(const fw_config *c, const char *rule, sbuf *out)
{
    const char *ifv[FW_MAX_IFS];
    int nif = fw_ifaces(c, ifv);
    /* both families: no ip4/ip6 option */
    int fam = c->ipv4 && c->ipv6 ? 0 : c->ipv4 ? 4 : 6;
    char p[8];
    for (int d = 0; d < 2; d++) {
        int outdir = d == 0;
        if (outdir ? !c->out : !c->in)
            continue;
        for (int k = 0; k < (nif ? nif : 1); k++) {
            const char *ifname = nif ? ifv[k] : NULL;
            if (c->ports.n) {
                if (c->tcp)
                    ipfw_rule(c, out, rule, "tcp", fam, outdir, ifname, 1);
                if (c->udp)
                    ipfw_rule(c, out, rule, "udp", fam, outdir, ifname, 1);
            }
            /* --ext profiles: ICMP and other IP protocols, whatever the ports */
            if (c->icmp && c->ipv4)
                ipfw_rule(c, out, rule, "icmp", fam ? 4 : 0, outdir, ifname, 0);
            if (c->icmp && c->ipv6)
                ipfw_rule(c, out, rule, "ipv6-icmp", fam ? 6 : 0, outdir, ifname, 0);
            for (int i = 0; i < c->nipp; i++) {
                snprintf(p, sizeof(p), "%u", c->ipp[i]);
                ipfw_rule(c, out, rule, p, fam, outdir, ifname, 0);
            }
        }
    }
}

/* ---- pf ------------------------------------------------------------------ */

static void pf_rule(const fw_config *c, sbuf *out, const char *proto, const char *fam, int outdir,
                    const char *ifname, int ports)
{
    int src = outdir ? c->server_side : !c->server_side;
    sb_printf(out, "pass %s quick", outdir ? "out" : "in");
    if (ifname)
        sb_printf(out, " on %s", ifname);
    if (*fam)
        sb_printf(out, " %s", fam);
    sb_printf(out, " proto %s from any", proto);
    if (ports && src) {
        sb_puts(out, " port ");
        bsd_ports(&c->ports, 1, out);
    }
    sb_puts(out, " to any");
    if (ports && !src) {
        sb_puts(out, " port ");
        bsd_ports(&c->ports, 1, out);
    }
    sb_printf(out, " divert-packet port %u\n", c->queue);
}

void fw_pf_rules(const fw_config *c, sbuf *out)
{
    const char *ifv[FW_MAX_IFS];
    int nif = fw_ifaces(c, ifv);
    const char *fam = c->ipv4 && c->ipv6 ? "" : c->ipv4 ? "inet" : "inet6";
    char p[8];
    for (int d = 0; d < 2; d++) {
        int outdir = d == 0;
        if (outdir ? !c->out : !c->in)
            continue;
        for (int k = 0; k < (nif ? nif : 1); k++) {
            const char *ifname = nif ? ifv[k] : NULL;
            if (c->ports.n) {
                if (c->tcp)
                    pf_rule(c, out, "tcp", fam, outdir, ifname, 1);
                if (c->udp)
                    pf_rule(c, out, "udp", fam, outdir, ifname, 1);
            }
            if (c->icmp && c->ipv4)
                pf_rule(c, out, "icmp", "inet", outdir, ifname, 0);
            if (c->icmp && c->ipv6)
                pf_rule(c, out, "icmp6", "inet6", outdir, ifname, 0);
            for (int i = 0; i < c->nipp; i++) {
                snprintf(p, sizeof(p), "%u", c->ipp[i]);
                pf_rule(c, out, p, fam, outdir, ifname, 0);
            }
        }
    }
}

/* ---- printing ------------------------------------------------------------ */

void fw_bsd_script(const fw_config *c, fw_backend b, int up, sbuf *out)
{
    sbuf e;
    sb_init(&e);
    if (fw_bsd_check(c, b, &e) < 0) {
        sb_printf(out, "# %s\n", e.data);
        sb_free(&e);
        return;
    }
    sb_free(&e);
    if (b == FW_IPFW) {
        if (up) {
            sb_printf(out, "# R: the lowest rule number from %u that has no rules (geneva picks it)\n", FW_IPFW_FIRST);
            fw_ipfw_rules(c, "$R", out);
        } else {
            sb_printf(out, "# every rule number whose rules all have the comment \"geneva %u\"\n", c->queue);
            sb_puts(out, "ipfw -q delete $R\n");
        }
    } else if (up) {
        sb_printf(out, "pfctl -a geneva/%u -f - <<'EOF'\n", c->queue);
        fw_pf_rules(c, out);
        sb_puts(out, "EOF\n");
    } else {
        sb_printf(out, "pfctl -a geneva/%u -F rules\n", c->queue);
    }
}

/* ---- applying ------------------------------------------------------------ */

#if defined(__FreeBSD__) || defined(__OpenBSD__)

/* "00100 ..." lines of "ipfw list": the rule number, and whether the rule
 * is ours (its comment) */
typedef struct {
    unsigned char other[65536 / 8], ours[65536 / 8];
} ipfw_nums;

#  define BIT_SET(a, n) ((a)[(n) >> 3] |= (unsigned char)(1u << ((n)&7)))
#  define BIT_GET(a, n) (((a)[(n) >> 3] >> ((n)&7)) & 1)

static int ipfw_list(const char *bin, uint16_t port, ipfw_nums *nums, sbuf *err)
{
    char *argv[] = {(char *)bin, "list", NULL}, tag[32];
    sbuf out;
    int rc;
    const char *p;
    memset(nums, 0, sizeof(*nums));
    snprintf(tag, sizeof(tag), "// geneva %u", port);
    sb_init(&out);
    rc = fw_run_argv(argv, NULL, &out);
    if (rc != 0) {
        fw_trim(&out);
        sb_printf(err, "ipfw list: %s (the ipfw module must be loaded: kenv net.inet.ip.fw.default_to_accept=1; "
                       "kldload ipfw ipdivert)",
                  out.len ? out.data : "failed");
        sb_free(&out);
        return -1;
    }
    for (p = out.data; p && *p;) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[1024];
        unsigned long num;
        char *end;
        if (n >= sizeof(line))
            n = sizeof(line) - 1;
        memcpy(line, p, n);
        line[n] = 0;
        num = strtoul(line, &end, 10);
        if (end != line && num < 65536) {
            /* the comment ends the line: "// geneva 310" and not 3100 */
            size_t tl = strlen(tag), ll = strlen(line);
            int mine = ll >= tl && !strcmp(line + ll - tl, tag);
            if (mine)
                BIT_SET(nums->ours, num);
            else
                BIT_SET(nums->other, num);
        }
        p = nl ? nl + 1 : NULL;
    }
    sb_free(&out);
    return 0;
}

/* deletes the numbers that hold our rules and nothing else */
static void ipfw_delete_ours(const char *bin, const ipfw_nums *nums, uint16_t port)
{
    for (unsigned n = 1; n < 65535; n++) {
        char num[8], *argv[] = {(char *)bin, "-q", "delete", num, NULL};
        if (!BIT_GET(nums->ours, n))
            continue;
        if (BIT_GET(nums->other, n)) {
            LOGW("fw", "ipfw rule %u has rules of geneva %u and others: left alone", n, port);
            continue;
        }
        snprintf(num, sizeof(num), "%u", n);
        if (fw_run_argv(argv, NULL, NULL) != 0)
            LOGW("fw", "ipfw delete %u failed", n);
    }
}

/* runs the "ipfw -q add ..." lines of a script */
static int ipfw_run_script(const char *bin, const char *script, sbuf *err)
{
    char *copy = xstrdup(script), *line, *save = NULL;
    int rc = 0;
    for (line = strtok_r(copy, "\n", &save); line && !rc; line = strtok_r(NULL, "\n", &save)) {
        char *argv[64], *tok, *s2 = NULL, *cm;
        int argc = 0;
        sbuf out;
        cm = strstr(line, " // ");
        if (cm)
            *cm = 0;
        for (tok = strtok_r(line, " ", &s2); tok && argc < 60; tok = strtok_r(NULL, " ", &s2))
            argv[argc] = argc ? tok : (char *)bin, argc++;
        /* the comment as ipfw takes it: "//" and its words */
        if (cm) {
            argv[argc++] = "//";
            for (tok = strtok_r(cm + 4, " ", &s2); tok && argc < 62; tok = strtok_r(NULL, " ", &s2))
                argv[argc++] = tok;
        }
        argv[argc] = NULL;
        sb_init(&out);
        if (fw_run_argv(argv, NULL, &out) != 0) {
            fw_trim(&out);
            sb_printf(err, "ipfw add: %s", out.len ? out.data : "failed");
            rc = -1;
        }
        sb_free(&out);
    }
    free(copy);
    return rc;
}

static int ipfw_up(fw_config *c, sbuf *err)
{
    char bin[256], num[8];
    ipfw_nums *nums;
    sbuf s;
    unsigned n;
    int rc;
    if (fw_find_bin("ipfw", bin, sizeof(bin)) < 0) {
        sb_puts(err, "ipfw not found");
        return -1;
    }
    nums = xmalloc(sizeof(*nums));
    if (ipfw_list(bin, c->queue, nums, err) < 0) {
        free(nums);
        return -1;
    }
    ipfw_delete_ours(bin, nums, c->queue); /* left by a run that was killed */
    for (n = FW_IPFW_FIRST; n < 65535 && BIT_GET(nums->other, n); n++)
        ;
    free(nums);
    if (n >= 65535) {
        sb_puts(err, "ipfw: no free rule number");
        return -1;
    }
    snprintf(num, sizeof(num), "%u", n);
    sb_init(&s);
    fw_ipfw_rules(c, num, &s);
    rc = ipfw_run_script(bin, s.data, err);
    sb_free(&s);
    if (rc < 0) {
        char *argv[] = {bin, "-q", "delete", num, NULL};
        fw_run_argv(argv, NULL, NULL);
        return -1;
    }
    LOGD("fw", "ipfw rule %u, divert port %u", n, c->queue);
    return 0;
}

static void ipfw_down(const fw_config *c)
{
    char bin[256];
    ipfw_nums *nums;
    sbuf e;
    if (fw_find_bin("ipfw", bin, sizeof(bin)) < 0)
        return;
    nums = xmalloc(sizeof(*nums));
    sb_init(&e);
    if (ipfw_list(bin, c->queue, nums, &e) == 0)
        ipfw_delete_ours(bin, nums, c->queue);
    sb_free(&e);
    free(nums);
}

static int pf_up(fw_config *c, sbuf *err)
{
    char bin[256], anchor[32];
    char *show[] = {bin, "-s", "rules", NULL}, *load[] = {bin, "-a", anchor, "-f", "-", NULL};
    sbuf out, rules;
    int rc;
    if (fw_find_bin("pfctl", bin, sizeof(bin)) < 0) {
        sb_puts(err, "pfctl not found");
        return -1;
    }
    snprintf(anchor, sizeof(anchor), "geneva/%u", c->queue);
    {
        char *info[] = {bin, "-s", "info", NULL};
        sb_init(&out);
        if (fw_run_argv(info, NULL, &out) == 0 && strstr(out.data ? out.data : "", "Status: Disabled")) {
            sb_puts(err, "pf is disabled (pfctl -e enables it)");
            sb_free(&out);
            return -1;
        }
        sb_free(&out);
    }
    /* the anchor's rules run only where the main ruleset calls them */
    sb_init(&out);
    rc = fw_run_argv(show, NULL, &out);
    if (rc != 0 || !strstr(out.data ? out.data : "", "anchor \"geneva/*\"")) {
        fw_trim(&out);
        if (rc != 0)
            sb_printf(err, "pfctl -s rules: %s", out.len ? out.data : "failed");
        else
            sb_puts(err, "pf does not call geneva's anchors: add the line anchor \"geneva/*\" to /etc/pf.conf "
                         "(before the rules that pass the traffic) and run pfctl -f /etc/pf.conf");
        sb_free(&out);
        return -1;
    }
    sb_free(&out);
    sb_init(&rules);
    sb_init(&out);
    fw_pf_rules(c, &rules);
    rc = fw_run_argv(load, rules.data ? rules.data : "", &out);
    if (rc != 0) {
        fw_trim(&out);
        sb_printf(err, "pfctl -a %s -f -: %s", anchor, out.len ? out.data : "failed");
    }
    sb_free(&rules);
    sb_free(&out);
    return rc ? -1 : 0;
}

static void pf_down(const fw_config *c)
{
    char bin[256], anchor[32];
    char *argv[] = {bin, "-a", anchor, "-F", "rules", NULL};
    if (fw_find_bin("pfctl", bin, sizeof(bin)) < 0)
        return;
    snprintf(anchor, sizeof(anchor), "geneva/%u", c->queue);
    fw_run_argv(argv, NULL, NULL);
}

int fw_bsd_up(fw_config *c, sbuf *err)
{
#  ifdef __FreeBSD__
    fw_backend want = FW_IPFW;
#  else
    fw_backend want = FW_PF;
#  endif
    if (c->backend == FW_AUTO)
        c->backend = want;
    if (c->backend != want) {
        sb_printf(err, "the %s backend is not available here (%s is)", fw_backend_name(c->backend),
                  fw_backend_name(want));
        return -1;
    }
    if (fw_bsd_check(c, c->backend, err) < 0)
        return -1;
    return want == FW_IPFW ? ipfw_up(c, err) : pf_up(c, err);
}

void fw_bsd_down(const fw_config *c)
{
#  ifdef __FreeBSD__
    int pf = c->backend == FW_PF;
#  else
    int pf = c->backend != FW_IPFW;
#  endif
    if (pf)
        pf_down(c);
    else
        ipfw_down(c);
}

#endif
