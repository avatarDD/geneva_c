#include "fw.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

#ifdef __linux__
#  include <fcntl.h>
#  include <signal.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

void fw_config_default(fw_config *c)
{
    memset(c, 0, sizeof(*c));
    c->backend = FW_AUTO;
    c->queue = 310; /* zapret-gui runs nfqws2 on 300-303 */
    c->mark = 0x20000000;
    c->tcp = 1;
    c->ipv4 = c->ipv6 = 1;
    c->out = c->in = 1;
    c->notrack = 1;
    c->bypass = 1;
}

const char *fw_backend_name(fw_backend b)
{
    return b == FW_NFT ? "nft" : b == FW_IPTABLES ? "iptables" : "auto";
}

int fw_backend_parse(const char *s, fw_backend *out)
{
    if (!strcmp(s, "auto"))
        *out = FW_AUTO;
    else if (!strcmp(s, "iptables"))
        *out = FW_IPTABLES;
    else if (!strcmp(s, "nft") || !strcmp(s, "nftables"))
        *out = FW_NFT;
    else
        return -1;
    return 0;
}

/* ---- command lists ------------------------------------------------------- */

enum {
    K_REQ,    /* must succeed */
    K_OPT,    /* may fail: warn once and skip the rest of the optional group */
    K_IGN,    /* failure is expected and fine (removing absent rules) */
    K_DEL,    /* like K_IGN, repeated until it fails (duplicate jumps) */
    K_NFT,    /* nft script fed to "nft -f -" */
};

typedef struct {
    int kind;
    int v6; /* the command is for ip6tables */
    char *text;
} fwcmd;

typedef struct {
    fwcmd *v;
    size_t n, cap;
} fwlist;

static void add(fwlist *l, int kind, int v6, char *text)
{
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 32;
        l->v = xrealloc(l->v, l->cap * sizeof(*l->v));
    }
    l->v[l->n].kind = kind;
    l->v[l->n].v6 = v6;
    l->v[l->n++].text = text;
}

static void ipt(fwlist *l, int kind, int v6, const char *fmt, ...) PRINTF_LIKE(4, 5);
static void ipt(fwlist *l, int kind, int v6, const char *fmt, ...)
{
    sbuf sb;
    va_list ap;
    sb_init(&sb);
    sb_puts(&sb, v6 ? "ip6tables " : "iptables ");
    va_start(ap, fmt);
    sb_vprintf(&sb, fmt, ap);
    va_end(ap);
    add(l, kind, v6, sb_take(&sb));
}

static void fwlist_free(fwlist *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->v[i].text);
    free(l->v);
    l->v = NULL;
    l->n = l->cap = 0;
}

/* ---- iptables ------------------------------------------------------------ */

typedef struct {
    char out[32], in[32], nt[32], dnat[32], snat[32], fwd[32];
} chains;

static void chain_names(const fw_config *c, chains *ch)
{
    snprintf(ch->out, sizeof(ch->out), "GENEVA_%u_OUT", c->queue);
    snprintf(ch->in, sizeof(ch->in), "GENEVA_%u_IN", c->queue);
    snprintf(ch->nt, sizeof(ch->nt), "GENEVA_%u_NT", c->queue);
    snprintf(ch->dnat, sizeof(ch->dnat), "GENEVA_%u_DNAT", c->queue);
    snprintf(ch->snat, sizeof(ch->snat), "GENEVA_%u_SNAT", c->queue);
    snprintf(ch->fwd, sizeof(ch->fwd), "GENEVA_%u_FWD", c->queue);
}

/* Splits the port set into iptables port matches: multiport takes up to 15
 * ports, a range counting as two. */
static size_t port_matches(const portset *ps, int src, char out[][400], size_t max)
{
    size_t n = 0;
    int i = 0;
    while (i < ps->n && n < max) {
        int slots = 0, first = i, cnt = 0;
        sbuf sb;
        while (i < ps->n && slots + (ps->lo[i] != ps->hi[i] ? 2 : 1) <= 15) {
            slots += ps->lo[i] != ps->hi[i] ? 2 : 1;
            i++;
            cnt++;
        }
        sb_init(&sb);
        if (cnt == 1) {
            sb_printf(&sb, "--%s %u", src ? "sport" : "dport", ps->lo[first]);
            if (ps->lo[first] != ps->hi[first])
                sb_printf(&sb, ":%u", ps->hi[first]);
        } else {
            portset part = {.n = cnt};
            memcpy(part.lo, ps->lo + first, (size_t)cnt * sizeof(part.lo[0]));
            memcpy(part.hi, ps->hi + first, (size_t)cnt * sizeof(part.hi[0]));
            sb_printf(&sb, "-m multiport --%s ", src ? "sports" : "dports");
            ports_format(&part, &sb, ",", ":");
        }
        snprintf(out[n++], 400, "%s", sb.data);
        sb_free(&sb);
    }
    return n;
}

static void gen_ipt_queue(const fw_config *c, fwlist *l, int v6, const char *chain, int outdir)
{
    const char *protos[2] = {c->tcp ? "tcp" : NULL, c->udp ? "udp" : NULL};
    /* client side: outgoing packets go to the ports, incoming come from them */
    int src = outdir ? c->server_side : !c->server_side;
    char m[MAX_PORT_RANGES][400];
    size_t nm = port_matches(&c->ports, src, m, MAX_PORT_RANGES);
    char ifm[64] = "", cb[96] = "", bypass[24] = "";
    if (c->iface)
        snprintf(ifm, sizeof(ifm), "%s %s ", outdir ? "-o" : "-i", c->iface);
    if (c->first > 0)
        snprintf(cb, sizeof(cb), "-m connbytes --connbytes 1:%d --connbytes-dir %s --connbytes-mode packets ",
                 c->first, outdir ? "original" : "reply");
    if (c->bypass)
        snprintf(bypass, sizeof(bypass), " --queue-bypass");
    ipt(l, K_REQ, v6, "-t mangle -N %s", chain);
    ipt(l, K_REQ, v6, "-t mangle -A %s -m mark --mark 0x%x/0x%x -j RETURN", chain, c->mark, c->mark);
    for (int p = 0; p < 2; p++) {
        if (!protos[p])
            continue;
        for (size_t i = 0; i < nm; i++)
            ipt(l, K_REQ, v6, "-t mangle -A %s %s-p %s %s %s-j NFQUEUE --queue-num %u%s", chain, ifm,
                protos[p], m[i], cb, c->queue, bypass);
    }
    ipt(l, K_REQ, v6, "-t mangle -I %s -j %s", outdir ? "POSTROUTING" : "PREROUTING", chain);
}

/* Router mode: forwarded packets of either direction, matched by source or
 * destination port. */
static void gen_ipt_forward(const fw_config *c, fwlist *l, int v6, const char *chain)
{
    const char *protos[2] = {c->tcp ? "tcp" : NULL, c->udp ? "udp" : NULL};
    char m[2][MAX_PORT_RANGES][400];
    size_t nm[2];
    char ifm[64] = "", bypass[24] = "";
    nm[0] = port_matches(&c->ports, 0, m[0], MAX_PORT_RANGES);
    nm[1] = port_matches(&c->ports, 1, m[1], MAX_PORT_RANGES);
    if (c->iface)
        snprintf(ifm, sizeof(ifm), "-i %s ", c->iface);
    if (c->bypass)
        snprintf(bypass, sizeof(bypass), " --queue-bypass");
    ipt(l, K_REQ, v6, "-t mangle -N %s", chain);
    ipt(l, K_REQ, v6, "-t mangle -A %s -m mark --mark 0x%x/0x%x -j RETURN", chain, c->mark, c->mark);
    for (int p = 0; p < 2; p++)
        for (int src = 0; protos[p] && src < 2; src++)
            for (size_t i = 0; i < nm[src]; i++)
                ipt(l, K_REQ, v6, "-t mangle -A %s %s-p %s %s -j NFQUEUE --queue-num %u%s", chain, ifm,
                    protos[p], m[src][i], c->queue, bypass);
    ipt(l, K_REQ, v6, "-t mangle -I FORWARD -j %s", chain);
}

static int addr_is_v6(const char *a) { return strchr(a, ':') != NULL; }

static void gen_ipt(const fw_config *c, fwlist *l, int v6, int up)
{
    chains ch;
    struct {
        const char *table, *hook, *chain;
    } all[6];
    chain_names(c, &ch);
    all[0].table = "mangle", all[0].hook = "POSTROUTING", all[0].chain = ch.out;
    all[1].table = "mangle", all[1].hook = "PREROUTING", all[1].chain = ch.in;
    all[2].table = "raw", all[2].hook = "OUTPUT", all[2].chain = ch.nt;
    all[3].table = "nat", all[3].hook = "PREROUTING", all[3].chain = ch.dnat;
    all[4].table = "nat", all[4].hook = "POSTROUTING", all[4].chain = ch.snat;
    all[5].table = "mangle", all[5].hook = "FORWARD", all[5].chain = ch.fwd;
    for (int i = 0; i < 6; i++) {
        ipt(l, K_DEL, v6, "-t %s -D %s -j %s", all[i].table, all[i].hook, all[i].chain);
        ipt(l, K_IGN, v6, "-t %s -F %s", all[i].table, all[i].chain);
        ipt(l, K_IGN, v6, "-t %s -X %s", all[i].table, all[i].chain);
    }
    if (!up)
        return;
    if (c->forward) {
        gen_ipt_forward(c, l, v6, ch.fwd);
        return;
    }
    if (c->out)
        gen_ipt_queue(c, l, v6, ch.out, 1);
    if (c->in)
        gen_ipt_queue(c, l, v6, ch.in, 0);
    if (c->notrack) {
        ipt(l, K_OPT, v6, "-t raw -N %s", ch.nt);
        ipt(l, K_OPT, v6, "-t raw -A %s -m mark --mark 0x%x/0x%x -j CT --notrack", ch.nt, c->mark, c->mark);
        ipt(l, K_OPT, v6, "-t raw -I OUTPUT -j %s", ch.nt);
    }
    if (c->forward_to && addr_is_v6(c->forward_to) == v6) {
        char m[MAX_PORT_RANGES][400];
        size_t nm = port_matches(&c->ports, 0, m, MAX_PORT_RANGES);
        const char *protos[2] = {c->tcp ? "tcp" : NULL, c->udp ? "udp" : NULL};
        ipt(l, K_REQ, v6, "-t nat -N %s", ch.dnat);
        ipt(l, K_REQ, v6, "-t nat -N %s", ch.snat);
        for (int p = 0; p < 2; p++)
            for (size_t i = 0; protos[p] && i < nm; i++) {
                ipt(l, K_REQ, v6, "-t nat -A %s -p %s %s -j DNAT --to-destination %s", ch.dnat,
                    protos[p], m[i], c->forward_to);
                ipt(l, K_REQ, v6, "-t nat -A %s -d %s -p %s %s -j MASQUERADE", ch.snat, c->forward_to,
                    protos[p], m[i]);
            }
        ipt(l, K_REQ, v6, "-t nat -I PREROUTING -j %s", ch.dnat);
        ipt(l, K_REQ, v6, "-t nat -I POSTROUTING -j %s", ch.snat);
    }
}

/* ---- nftables ------------------------------------------------------------ */

static void nft_queue_chain(const fw_config *c, sbuf *s, int outdir)
{
    const char *protos[2] = {c->tcp ? "tcp" : NULL, c->udp ? "udp" : NULL};
    int src = outdir ? c->server_side : !c->server_side;
    int prio = outdir ? (c->prenat ? -150 : 101) : -150;
    sb_printf(s, "\tchain %s {\n\t\ttype filter hook %s priority %d; policy accept;\n",
              outdir ? "out" : "in", outdir ? "postrouting" : "prerouting", prio);
    sb_printf(s, "\t\tmeta mark & 0x%x == 0x%x return\n", c->mark, c->mark);
    for (int p = 0; p < 2; p++) {
        if (!protos[p])
            continue;
        sb_puts(s, "\t\t");
        if (c->ipv4 != c->ipv6)
            sb_printf(s, "meta nfproto %s ", c->ipv4 ? "ipv4" : "ipv6");
        if (c->iface)
            sb_printf(s, "%s \"%s\" ", outdir ? "oifname" : "iifname", c->iface);
        sb_printf(s, "%s %s { ", protos[p], src ? "sport" : "dport");
        ports_format(&c->ports, s, ", ", "-");
        sb_puts(s, " } ");
        if (c->first > 0)
            sb_printf(s, "ct %s packets 1-%d ", outdir ? "original" : "reply", c->first);
        sb_printf(s, "queue num %u%s\n", c->queue, c->bypass ? " bypass" : "");
    }
    sb_puts(s, "\t}\n");
}

static void nft_forward_chain(const fw_config *c, sbuf *s)
{
    const char *protos[2] = {c->tcp ? "tcp" : NULL, c->udp ? "udp" : NULL};
    sb_puts(s, "\tchain routed {\n\t\ttype filter hook forward priority -150; policy accept;\n");
    sb_printf(s, "\t\tmeta mark & 0x%x == 0x%x return\n", c->mark, c->mark);
    for (int p = 0; p < 2; p++)
        for (int src = 0; protos[p] && src < 2; src++) {
            sb_puts(s, "\t\t");
            if (c->ipv4 != c->ipv6)
                sb_printf(s, "meta nfproto %s ", c->ipv4 ? "ipv4" : "ipv6");
            if (c->iface)
                sb_printf(s, "iifname \"%s\" ", c->iface);
            sb_printf(s, "%s %s { ", protos[p], src ? "sport" : "dport");
            ports_format(&c->ports, s, ", ", "-");
            sb_printf(s, " } queue num %u%s\n", c->queue, c->bypass ? " bypass" : "");
        }
    sb_puts(s, "\t}\n");
}

static char *gen_nft_script(const fw_config *c, int up, int notrack)
{
    sbuf s;
    sb_init(&s);
    /* "add" first so that "delete" never fails: up is idempotent */
    sb_printf(&s, "add table inet geneva_%u\ndelete table inet geneva_%u\n", c->queue, c->queue);
    if (!up)
        return sb_take(&s);
    sb_printf(&s, "table inet geneva_%u {\n", c->queue);
    if (c->forward) {
        nft_forward_chain(c, &s);
        sb_puts(&s, "}\n");
        return sb_take(&s);
    }
    if (c->out)
        nft_queue_chain(c, &s, 1);
    if (c->in)
        nft_queue_chain(c, &s, 0);
    if (notrack)
        /* before conntrack defrag (-400): fragments we send stay fragments */
        sb_printf(&s,
                  "\tchain predefrag {\n\t\ttype filter hook output priority -401; policy accept;\n"
                  "\t\tmeta mark & 0x%x == 0x%x notrack\n\t}\n",
                  c->mark, c->mark);
    if (c->forward_to) {
        const char *fam = addr_is_v6(c->forward_to) ? "ip6" : "ip";
        const char *protos[2] = {c->tcp ? "tcp" : NULL, c->udp ? "udp" : NULL};
        sb_puts(&s, "\tchain dnat {\n\t\ttype nat hook prerouting priority -100; policy accept;\n");
        for (int p = 0; p < 2; p++)
            if (protos[p]) {
                sb_printf(&s, "\t\t%s dport { ", protos[p]);
                ports_format(&c->ports, &s, ", ", "-");
                sb_printf(&s, " } dnat %s to %s\n", fam, c->forward_to);
            }
        sb_puts(&s, "\t}\n\tchain snat {\n\t\ttype nat hook postrouting priority 100; policy accept;\n");
        for (int p = 0; p < 2; p++)
            if (protos[p]) {
                sb_printf(&s, "\t\t%s daddr %s %s dport { ", fam, c->forward_to, protos[p]);
                ports_format(&c->ports, &s, ", ", "-");
                sb_puts(&s, " } masquerade\n");
            }
        sb_puts(&s, "\t}\n");
    }
    sb_puts(&s, "}\n");
    return sb_take(&s);
}

/* ---- printing ------------------------------------------------------------ */

void fw_script(const fw_config *c, fw_backend b, int up, sbuf *out)
{
    if (b == FW_NFT) {
        char *s = gen_nft_script(c, up, c->notrack);
        sb_printf(out, "nft -f - <<'EOF'\n%sEOF\n", s);
        free(s);
        return;
    }
    fwlist l = {0};
    if (c->ipv4)
        gen_ipt(c, &l, 0, up);
    if (c->ipv6)
        gen_ipt(c, &l, 1, up);
    for (size_t i = 0; i < l.n; i++) {
        /* removal commands fail harmlessly when nothing is installed */
        int quiet = l.v[i].kind == K_IGN || l.v[i].kind == K_DEL;
        sb_printf(out, "%s%s\n", l.v[i].text, quiet ? " 2>/dev/null" : "");
    }
    fwlist_free(&l);
}

/* ---- WinDivert ----------------------------------------------------------- */

static void wd_ports(const fw_config *c, sbuf *out, const char *field)
{
    int nproto = 0;
    sb_putc(out, '(');
    for (int pr = 0; pr < 2; pr++) {
        const char *proto = pr ? "udp" : "tcp";
        if (!(pr ? c->udp : c->tcp))
            continue;
        for (int i = 0; i < c->ports.n; i++) {
            if (nproto++)
                sb_puts(out, " or ");
            if (c->ports.lo[i] == c->ports.hi[i])
                sb_printf(out, "%s.%s == %u", proto, field, c->ports.lo[i]);
            else
                sb_printf(out, "(%s.%s >= %u and %s.%s <= %u)", proto, field, c->ports.lo[i], proto,
                          field, c->ports.hi[i]);
        }
    }
    sb_putc(out, ')');
}

int fw_windivert_filter(const fw_config *c, sbuf *out, sbuf *err)
{
    /* client side: out to the ports, in from them; server side: the reverse */
    const char *out_field = c->server_side ? "SrcPort" : "DstPort";
    const char *in_field = c->server_side ? "DstPort" : "SrcPort";
    if (c->forward) {
        sb_puts(err, "forwarded traffic is only captured on Linux");
        return -1;
    }
    if (!c->tcp && !c->udp) {
        sb_puts(err, "no protocol to capture");
        return -1;
    }
    if (!c->ports.n) {
        sb_puts(err, "no ports to capture");
        return -1;
    }
    if (!c->out && !c->in) {
        sb_puts(err, "no direction to capture");
        return -1;
    }
    if (!c->ipv4 && !c->ipv6) {
        sb_puts(err, "neither IPv4 nor IPv6");
        return -1;
    }
    sb_puts(out, "!loopback");
    if (!c->ipv4 || !c->ipv6)
        sb_puts(out, c->ipv4 ? " and ip" : " and ipv6");
    if (c->iface) {
        char *end;
        unsigned long idx = strtoul(c->iface, &end, 10);
        if (!*c->iface || *end || !idx || idx > 0xffffffffUL) {
            sb_printf(err, "on Windows --iface takes an interface index (see \"netsh interface ipv4 show interfaces\"), not \"%s\"",
                      c->iface);
            return -1;
        }
        sb_printf(out, " and ifIdx == %lu", idx);
    }
    sb_puts(out, " and (");
    if (c->out) {
        sb_puts(out, "(outbound and ");
        wd_ports(c, out, out_field);
        sb_putc(out, ')');
    }
    if (c->in) {
        if (c->out)
            sb_puts(out, " or ");
        sb_puts(out, "(inbound and ");
        wd_ports(c, out, in_field);
        sb_putc(out, ')');
    }
    sb_putc(out, ')');
    return 0;
}

/* ---- execution ----------------------------------------------------------- */

#ifdef __linux__

static int find_bin(const char *name, char *out, size_t cap)
{
    static const char *const extra = "/usr/sbin:/sbin:/usr/bin:/bin:/opt/sbin:/opt/bin";
    const char *path = getenv("PATH");
    for (int pass = 0; pass < 2; pass++) {
        const char *p = pass ? extra : path;
        while (p && *p) {
            const char *e = strchr(p, ':');
            size_t n = e ? (size_t)(e - p) : strlen(p);
            if (n && n + strlen(name) + 2 <= cap) {
                memcpy(out, p, n);
                out[n] = '/';
                strcpy(out + n + 1, name);
                if (access(out, X_OK) == 0)
                    return 0;
            }
            p = e ? e + 1 : NULL;
        }
    }
    return -1;
}

/* Runs argv with optional stdin, collecting stdout+stderr. Returns the exit
 * status, or -1 if the program could not be started. */
static int run_argv(char *const argv[], const char *input, sbuf *output)
{
    int in[2] = {-1, -1}, outp[2];
    pid_t pid;
    int st;
    char buf[1024];
    ssize_t n;
    if (pipe(outp) < 0)
        return -1;
    if (input && pipe(in) < 0) {
        close(outp[0]);
        close(outp[1]);
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        close(outp[0]);
        close(outp[1]);
        if (input) {
            close(in[0]);
            close(in[1]);
        }
        return -1;
    }
    if (pid == 0) {
        int devnull;
        if (input) {
            dup2(in[0], 0);
            close(in[0]);
            close(in[1]);
        } else if ((devnull = open("/dev/null", 0)) >= 0) {
            dup2(devnull, 0);
            close(devnull);
        }
        dup2(outp[1], 1);
        dup2(outp[1], 2);
        close(outp[0]);
        close(outp[1]);
        execv(argv[0], argv);
        _exit(127);
    }
    close(outp[1]);
    if (input) {
        size_t len = strlen(input), off = 0;
        void (*old)(int) = signal(SIGPIPE, SIG_IGN);
        close(in[0]);
        while (off < len) {
            n = write(in[1], input + off, len - off);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                break;
            off += (size_t)n;
        }
        close(in[1]);
        signal(SIGPIPE, old);
    }
    while ((n = read(outp[0], buf, sizeof(buf))) != 0) {
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (output)
            sb_append(output, buf, (size_t)n);
    }
    close(outp[0]);
    while (waitpid(pid, &st, 0) < 0)
        if (errno != EINTR)
            return -1;
    if (!WIFEXITED(st))
        return -1;
    return WEXITSTATUS(st) == 127 ? -1 : WEXITSTATUS(st);
}

/* Runs one iptables command line (space separated, no quoting needed). */
typedef struct {
    char bin[2][256]; /* resolved iptables / ip6tables */
    int wait[2];      /* the binary accepts -w */
} ipt_env;

static int run_line(ipt_env *env, const fwcmd *c, sbuf *output)
{
    char *copy = xstrdup(c->text), *argv[64], *tok, *save = NULL;
    int argc = 0, rc;
    for (tok = strtok_r(copy, " ", &save); tok && argc < 60; tok = strtok_r(NULL, " ", &save)) {
        if (argc == 0) {
            argv[argc++] = env->bin[c->v6];
            if (env->wait[c->v6])
                argv[argc++] = "-w";
            continue;
        }
        argv[argc++] = tok;
    }
    argv[argc] = NULL;
    rc = run_argv(argv, NULL, output);
    free(copy);
    return rc;
}

static void trim(sbuf *s)
{
    while (s->len && (s->data[s->len - 1] == '\n' || s->data[s->len - 1] == ' '))
        s->data[--s->len] = 0;
}

static int ipt_env_init(ipt_env *env, int v6)
{
    char *argv[4];
    if (find_bin(v6 ? "ip6tables" : "iptables", env->bin[v6], sizeof(env->bin[v6])) < 0)
        return -1;
    /* -w (wait for the xtables lock) exists since iptables 1.4.20 */
    argv[0] = env->bin[v6];
    argv[1] = "-w";
    argv[2] = "-V";
    argv[3] = NULL;
    env->wait[v6] = run_argv(argv, NULL, NULL) == 0;
    return 0;
}

/* Runs the commands of one family. Returns 0, or -1 after rolling back. */
static int ipt_apply(const fw_config *c, ipt_env *env, int v6, sbuf *err)
{
    fwlist l = {0};
    int rc = 0, opt_failed = 0;
    sbuf out;
    sb_init(&out);
    gen_ipt(c, &l, v6, 1);
    for (size_t i = 0; i < l.n && !rc; i++) {
        fwcmd *cmd = &l.v[i];
        int r;
        if (cmd->kind == K_OPT && opt_failed)
            continue;
        sb_reset(&out);
        if (cmd->kind == K_DEL) {
            for (int k = 0; k < 16 && run_line(env, cmd, NULL) == 0; k++)
                ;
            continue;
        }
        r = run_line(env, cmd, &out);
        LOGD("fw", "%s -> %d", cmd->text, r);
        if (r != 0 && cmd->kind == K_OPT && strstr(cmd->text, "-j CT --notrack")) {
            /* kernels and iptables before CT target: the old NOTRACK target */
            fwcmd alt = *cmd;
            char *p;
            alt.text = xstrdup(cmd->text);
            p = strstr(alt.text, "-j CT --notrack");
            strcpy(p, "-j NOTRACK");
            sb_reset(&out);
            r = run_line(env, &alt, &out);
            free(alt.text);
        }
        if (r == 0 || cmd->kind == K_IGN)
            continue;
        trim(&out);
        if (cmd->kind == K_OPT) {
            LOGW("fw", "%s failed (%s); our packets stay tracked by conntrack", cmd->text,
                 out.len ? out.data : "no output");
            opt_failed = 1;
            continue;
        }
        sb_printf(err, "%s: %s", cmd->text, r < 0 ? "cannot run" : out.len ? out.data : "failed");
        rc = -1;
    }
    if (rc) {
        fwlist dl = {0};
        gen_ipt(c, &dl, v6, 0);
        for (size_t i = 0; i < dl.n; i++)
            for (int k = 0; k < (dl.v[i].kind == K_DEL ? 16 : 1) && run_line(env, &dl.v[i], NULL) == 0;
                 k++)
                ;
        fwlist_free(&dl);
    }
    fwlist_free(&l);
    sb_free(&out);
    return rc;
}

static int iptables_up(const fw_config *c, sbuf *err)
{
    ipt_env env;
    memset(&env, 0, sizeof(env));
    int want4 = c->ipv4, want6 = c->ipv6;
    if (want4 && ipt_env_init(&env, 0) < 0) {
        sb_puts(err, "iptables not found");
        return -1;
    }
    if (want4 && ipt_apply(c, &env, 0, err) < 0)
        return -1;
    if (want6) {
        sbuf e6;
        int rc;
        sb_init(&e6);
        if (ipt_env_init(&env, 1) < 0) {
            sb_puts(&e6, "ip6tables not found");
            rc = -1;
        } else {
            rc = ipt_apply(c, &env, 1, &e6);
        }
        if (rc < 0) {
            if (!want4) {
                sb_puts(err, e6.data);
                sb_free(&e6);
                return -1;
            }
            LOGW("fw", "IPv6 rules not applied, IPv6 traffic is not handled: %s", e6.data);
        }
        sb_free(&e6);
    }
    return 0;
}

static void iptables_down(const fw_config *c)
{
    ipt_env env;
    memset(&env, 0, sizeof(env));
    for (int v6 = 0; v6 < 2; v6++) {
        fwlist l = {0};
        if (ipt_env_init(&env, v6) < 0)
            continue;
        gen_ipt(c, &l, v6, 0);
        for (size_t i = 0; i < l.n; i++)
            for (int k = 0; k < (l.v[i].kind == K_DEL ? 16 : 1) && run_line(&env, &l.v[i], NULL) == 0; k++)
                ;
        fwlist_free(&l);
    }
}

static int nft_run(const char *script, sbuf *out)
{
    char bin[256];
    char *argv[] = {bin, "-f", "-", NULL};
    if (find_bin("nft", bin, sizeof(bin)) < 0) {
        sb_puts(out, "nft not found");
        return -1;
    }
    return run_argv(argv, script, out);
}

static int nft_up(const fw_config *c, sbuf *err)
{
    sbuf out;
    char *s = gen_nft_script(c, 1, c->notrack);
    int r;
    sb_init(&out);
    r = nft_run(s, &out);
    LOGD("fw", "nft -f - <<EOF\n%sEOF -> %d", s, r);
    free(s);
    if (r != 0 && c->notrack) {
        /* kernels without the nft notrack expression */
        sbuf o2;
        sb_init(&o2);
        s = gen_nft_script(c, 1, 0);
        if (nft_run(s, &o2) == 0) {
            trim(&out);
            LOGW("fw", "nft notrack failed (%s); our packets stay tracked by conntrack", out.data);
            r = 0;
        }
        free(s);
        sb_free(&o2);
    }
    if (r != 0) {
        trim(&out);
        sb_printf(err, "nft: %s", out.len ? out.data : "cannot run");
        s = gen_nft_script(c, 0, 0);
        nft_run(s, NULL);
        free(s);
    }
    sb_free(&out);
    return r ? -1 : 0;
}

static void nft_down(const fw_config *c)
{
    char *s = gen_nft_script(c, 0, 0);
    nft_run(s, NULL);
    free(s);
}

int fw_up(fw_config *c, sbuf *err)
{
    char bin[256];
    if (c->backend == FW_NFT)
        return nft_up(c, err);
    if (c->backend == FW_IPTABLES)
        return iptables_up(c, err);
    if (find_bin("nft", bin, sizeof(bin)) == 0) {
        sbuf e;
        sb_init(&e);
        if (nft_up(c, &e) == 0) {
            c->backend = FW_NFT;
            sb_free(&e);
            return 0;
        }
        LOGI("fw", "nftables did not work (%s), trying iptables", e.data);
        sb_free(&e);
    }
    if (iptables_up(c, err) < 0)
        return -1;
    c->backend = FW_IPTABLES;
    return 0;
}

void fw_down(const fw_config *c)
{
    char bin[256];
    if (c->backend != FW_IPTABLES && find_bin("nft", bin, sizeof(bin)) == 0)
        nft_down(c);
    if (c->backend != FW_NFT)
        iptables_down(c);
}

#else /* !__linux__ */

int fw_up(fw_config *c, sbuf *err)
{
    sb_puts(err, "firewall rules are only supported on Linux");
    return -1;
}

void fw_down(const fw_config *c) {}

#endif
