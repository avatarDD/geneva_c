/* Stage X7b: firewall parity with zapret2 under --ext (src/ext/fwx.c and
 * the --ext part of src/fw.c): --ext-first, --ext-wan/--ext-lan,
 * --ext-notrack frag, --ext-ttl-icmp, --ext-flowoffload, the hooks and
 * winws2's --wf-* filter. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "ext_opt.h"
#include "fw.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/fwx.h"

#  ifdef __linux__
#    include <signal.h>
#    include <sys/stat.h>
#    include <unistd.h>
#  endif

static int count(const char *hay, const char *needle)
{
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p++)
        n++;
    return n;
}

static const optdef g_defs[] = {
    {"iface", 'i', 1, "IF", NULL},
    {"no-notrack", 0, 0, NULL, NULL},
    {"priority", 0, 1, "N", NULL},
    EXT_FW_OPTS,
    {NULL, 0, 0, NULL, NULL},
};

/* xfw_parse of up to 8 words on top of fw_config_default (and c0's
 * backend, iface and first): 0 or -1 with the message in err */
static int parse(fw_config *c, int windows, char **owned, const char *save_want, sbuf *err, const char *w0,
                 const char *w1, const char *w2, const char *w3, const char *w4, const char *w5)
{
    const char *words[] = {"x", w0, w1, w2, w3, w4, w5};
    char *argv[8];
    int argc = 1, r;
    char e[128];
    args_t a;
    const char *save = NULL;
    argv[0] = (char *)words[0];
    for (int i = 1; i < 7 && words[i]; i++)
        argv[argc++] = (char *)words[i];
    argv[argc] = NULL;
    *owned = NULL;
    sb_reset(err);
    if (args_parse(&a, argc, argv, g_defs, e, sizeof(e)) < 0) {
        sb_puts(err, e);
        return -1;
    }
    c->iface = arg_str(&a, "iface", c->iface);
    r = xfw_parse(&a, windows, c, owned, &save, err);
    if (!r && save_want)
        CHECK_STR(save ? save : "", save_want);
    args_free(&a);
    return r;
}

#  define P0(c, ...) parse(c, 0, &owned, NULL, &err, __VA_ARGS__)

TEST(fwx_first)
{
    fw_config c;
    fw_config_default(&c);
    CHECK_INT(fw_first_any(&c), 0);
    c.first = 6;
    CHECK_INT(fw_first(&c, 1, 1), 6);
    CHECK_INT(fw_first_any(&c), 1);
    CHECK_INT(xfw_first("tcp-out=20,tcp-in=10,udp-out=5,udp-in=3", 0, &c), 0);
    CHECK_INT(c.first_dir, 1);
    CHECK_INT(fw_first(&c, 0, 0), 20);
    CHECK_INT(fw_first(&c, 0, 1), 10);
    CHECK_INT(fw_first(&c, 1, 0), 5);
    CHECK_INT(fw_first(&c, 1, 1), 3);
    /* on top of --first; the later item wins */
    CHECK_INT(xfw_first("in=0,udp-in=2", 4, &c), 0);
    CHECK_INT(fw_first(&c, 0, 0), 4);
    CHECK_INT(fw_first(&c, 0, 1), 0);
    CHECK_INT(fw_first(&c, 1, 1), 2);
    CHECK_INT(fw_first_any(&c), 1);
    CHECK_INT(xfw_first("0", 4, &c), 0);
    CHECK_INT(fw_first_any(&c), 0);
    CHECK_INT(xfw_first("7", 0, &c), 0);
    CHECK_INT(fw_first(&c, 1, 0), 7);
    CHECK_INT(xfw_first("", 0, &c), -1);
    CHECK_INT(xfw_first("out", 0, &c), -1);
    CHECK_INT(xfw_first("out=", 0, &c), -1);
    CHECK_INT(xfw_first("both=1", 0, &c), -1);
    CHECK_INT(xfw_first("icmp-out=1", 0, &c), -1);
    CHECK_INT(xfw_first("out=1,", 0, &c), -1);
    CHECK_INT(xfw_first("out=1000001", 0, &c), -1);
    CHECK_INT(xfw_first("out=-1", 0, &c), -1);
}

TEST(fwx_iflist)
{
    char buf[200];
    const char *v[FW_MAX_IFS];
    CHECK_INT(xfw_iflist("eth0", buf, sizeof(buf), v), 1);
    CHECK_STR(v[0], "eth0");
    CHECK_INT(xfw_iflist("eth0,ppp0,br-lan", buf, sizeof(buf), v), 3);
    CHECK_STR(v[2], "br-lan");
    CHECK_INT(xfw_iflist("a,b,c,d,e,f,g,h", buf, sizeof(buf), v), 8);
    CHECK_INT(xfw_iflist("a,b,c,d,e,f,g,h,i", buf, sizeof(buf), v), -1);
    CHECK_INT(xfw_iflist("", buf, sizeof(buf), v), -1);
    CHECK_INT(xfw_iflist("eth0,", buf, sizeof(buf), v), -1);
    CHECK_INT(xfw_iflist("0123456789abcdef", buf, sizeof(buf), v), -1);
    CHECK_INT(xfw_iflist("a\"b", buf, sizeof(buf), v), -1);
    CHECK_INT(xfw_iflist("a}", buf, sizeof(buf), v), -1);
}

TEST(fwx_nft)
{
    fw_config c;
    sbuf s;
    sb_init(&s);
    fw_config_default(&c);
    ports_parse("443", &c.ports);
    c.udp = 1;
    c.nifs = 2;
    c.ifs[0] = c.iface = "eth0";
    c.ifs[1] = "ppp0";
    xfw_first("tcp-out=20,tcp-in=10,udp-out=5,udp-in=3", 0, &c);
    c.ttl_icmp = 1;
    c.notrack_frag = 1;
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT(count(s.data, "oifname { \"eth0\", \"ppp0\" } tcp dport { 443 } ct original packets 1-20 ct mark set ct "
                            "mark or 0x20000000 queue num 310 bypass\n"),
              1);
    CHECK_INT(count(s.data, "iifname { \"eth0\", \"ppp0\" } udp sport { 443 } ct reply packets 1-3 ct mark set ct "
                            "mark or 0x20000000 queue num 310 bypass\n"),
              1);
    CHECK_INT(count(s.data, "type filter hook prerouting priority -160;"), 1);
    CHECK_INT(count(s.data, "\t\ticmp type time-exceeded ct mark & 0x20000000 == 0x20000000 counter drop\n"), 1);
    CHECK_INT(count(s.data, "\t\ticmpv6 type time-exceeded ct mark & 0x20000000 == 0x20000000 counter drop\n"), 1);
    CHECK_INT(count(s.data, "ip frag-off & 0x1fff != 0 notrack\n"), 1);
    CHECK_INT(count(s.data, "exthdr frag exists notrack\n"), 1);
    CHECK_INT(count(s.data, "tcp flags & (syn | rst | ack) == 0 notrack\n"), 1);
    CHECK_INT(count(s.data, "0x20000000 notrack\n"), 0); /* not all of ours */
    CHECK_INT(count(s.data, "flowtable"), 0);

    /* one family: the ICMP of the other is left alone */
    sb_reset(&s);
    c.ipv6 = 0;
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT(count(s.data, "icmpv6 type"), 0);
    CHECK_INT(count(s.data, "\t\ticmp type time-exceeded"), 1);

    /* flow offload: the WAN and LAN devices; queued flows exempt while queued */
    sb_reset(&s);
    c.ipv6 = 1;
    c.offload = 2;
    c.nlan = 1;
    c.lan[0] = "br-lan";
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT(count(s.data, "\tflowtable ft {\n\t\thook ingress priority 0; devices = { \"eth0\", \"ppp0\", \"br-lan\" "
                            "};\n\t\tflags offload;\n\t}\n"),
              1);
    CHECK_INT(count(s.data, "type filter hook forward priority -1; policy accept;\n\t\tmeta l4proto { tcp, udp } "
                            "oifname { \"eth0\", \"ppp0\" } jump flow_offload\n"),
              1);
    CHECK_INT(count(s.data, "\t\ttcp dport { 443 } ct original packets 1-20 return\n"), 1);
    CHECK_INT(count(s.data, "\t\ttcp dport { 443 } ct reply packets 1-10 return\n"), 1);
    CHECK_INT(count(s.data, "\t\tudp dport { 443 } ct original packets 1-5 return\n"), 1);
    CHECK_INT(count(s.data, "\t\tflow add @ft\n"), 1);

    /* software; a direction without a limit: the flow never offloads */
    sb_reset(&s);
    c.offload = 1;
    c.firstv[0][1] = 0;
    c.udp = 0;
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT(count(s.data, "flags offload"), 0);
    CHECK_INT(count(s.data, "\t\ttcp dport { 443 } return\n"), 1);
    CHECK_INT(count(s.data, "ct original packets 1-20 return"), 0);
    CHECK_INT(count(s.data, "udp dport"), 0);
    /* ... unless that direction is not queued */
    sb_reset(&s);
    c.in = 0;
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT(count(s.data, "\t\ttcp dport { 443 } ct original packets 1-20 return\n"), 1);
    CHECK_INT(count(s.data, "ct reply packets"), 0);
    /* server side: the ports are the source, the original direction in */
    sb_reset(&s);
    c.in = 1;
    c.firstv[0][1] = 9;
    c.server_side = 1;
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT(count(s.data, "\t\ttcp sport { 443 } ct reply packets 1-20 return\n"), 1);
    CHECK_INT(count(s.data, "\t\ttcp sport { 443 } ct original packets 1-9 return\n"), 1);

    /* the hooks around the script, up and down */
    sb_reset(&s);
    c.hook_pre = "/opt/pre";
    c.hook_post = "/opt/post";
    fw_script(&c, FW_NFT, 0, &s);
    CHECK_STR(s.data, "'/opt/pre' down nft 310\nnft -f - <<'EOF'\nadd table inet geneva_310\ndelete table inet "
                      "geneva_310\nEOF\n'/opt/post' down nft 310\n");
    sb_reset(&s);
    fw_script(&c, FW_IPTABLES, 1, &s);
    CHECK_STR(s.data, "'/opt/pre' up iptables 310\n# --ext-flowoffload works with nft only\n'/opt/post' up iptables 310\n");
    sb_free(&s);
}

TEST(fwx_iptables)
{
    fw_config c;
    sbuf s;
    sb_init(&s);
    fw_config_default(&c);
    ports_parse("443", &c.ports);
    c.ipv6 = 0;
    c.nifs = 2;
    c.ifs[0] = c.iface = "eth0";
    c.ifs[1] = "ppp0";
    xfw_first("out=4,in=2", 0, &c);
    c.ttl_icmp = 1;
    c.notrack_frag = 1;
    fw_script(&c, FW_IPTABLES, 1, &s);
    CHECK_INT(count(s.data, "iptables -t mangle -A GENEVA_310_OUT -o ppp0 -p tcp --dport 443 -m connbytes --connbytes "
                            "1:4 --connbytes-dir original --connbytes-mode packets -j CONNMARK --or-mark 0x20000000\n"),
              1);
    CHECK_INT(count(s.data, "-j NFQUEUE"), 4);
    CHECK_INT(count(s.data, "-j CONNMARK"), 4);
    CHECK_INT(count(s.data, "-i eth0 -p tcp --sport 443 -m connbytes --connbytes 1:2 --connbytes-dir reply"), 2);
    /* the time-exceeded drop comes first in the IN chain */
    CHECK(strstr(s.data, "-A GENEVA_310_IN -p icmp -m icmp --icmp-type time-exceeded -m connmark --mark "
                         "0x20000000/0x20000000 -j DROP\niptables -t mangle -A GENEVA_310_IN -m mark") != NULL);
    CHECK_INT(count(s.data, "-m mark --mark 0x20000000/0x20000000 -f -j CT --notrack\n"), 1);
    CHECK_INT(count(s.data, "-p tcp --tcp-flags SYN,RST,ACK NONE -j CT --notrack\n"), 1);
    CHECK_INT(count(s.data, "-j CT --notrack"), 2);

    /* IPv6; only out queued: the IN chain holds the drop alone */
    sb_reset(&s);
    c.ipv4 = 0, c.ipv6 = 1;
    c.in = 0;
    c.nifs = 0;
    c.iface = NULL;
    fw_script(&c, FW_IPTABLES, 1, &s);
    CHECK_INT(count(s.data, "ip6tables -t mangle -A GENEVA_310_IN -p ipv6-icmp -m icmp6 --icmpv6-type time-exceeded "
                            "-m connmark --mark 0x20000000/0x20000000 -j DROP\nip6tables -t mangle -I PREROUTING -j "
                            "GENEVA_310_IN\n"),
              1);
    CHECK_INT(count(s.data, "GENEVA_310_IN -m mark"), 0);
    CHECK_INT(count(s.data, "-m frag -j CT --notrack"), 1);
    sb_free(&s);
}

TEST(fwx_windivert_ifaces)
{
    fw_config c;
    sbuf s, e;
    sb_init(&s);
    sb_init(&e);
    fw_config_default(&c);
    ports_parse("443", &c.ports);
    c.nifs = 2;
    c.ifs[0] = c.iface = "5";
    c.ifs[1] = "12";
    CHECK_INT(fw_windivert_filter(&c, &s, &e), 0);
    CHECK(strstr(s.data, "!loopback and (ifIdx == 5 or ifIdx == 12) and (") != NULL);
    c.ifs[1] = "eth0";
    sb_reset(&s);
    CHECK_INT(fw_windivert_filter(&c, &s, &e), -1);
    CHECK(strstr(e.data, "\"eth0\"") != NULL);
    /* a whole --wf-* filter: as it is */
    c.filter = "tcp";
    c.filter_whole = 1;
    sb_reset(&s);
    CHECK_INT(fw_windivert_filter(&c, &s, &e), 0);
    CHECK_STR(s.data, "tcp");
    sb_free(&s);
    sb_free(&e);
}

TEST(fwx_options)
{
    fw_config c;
    sbuf err;
    char *owned = NULL;
    sb_init(&err);

    fw_config_default(&c);
    c.first = 3;
    CHECK_INT(P0(&c, "--ext-first", "udp-in=1", "--ext-wan", "eth0,ppp0", "--ext-notrack", "frag"), 0);
    CHECK_INT(fw_first(&c, 0, 0), 3);
    CHECK_INT(fw_first(&c, 1, 1), 1);
    CHECK_INT(c.nifs, 2);
    CHECK_STR(c.iface, "eth0");
    CHECK_STR(c.ifs[1], "ppp0");
    CHECK_INT(c.notrack, 1);
    CHECK_INT(c.notrack_frag, 1);
    CHECK_INT(c.ttl_icmp, 0);
    CHECK(c.filter == NULL && owned == NULL);

    fw_config_default(&c);
    CHECK_INT(P0(&c, "--ext-notrack", "none", "--ext-ttl-icmp", NULL, NULL, NULL), 0);
    CHECK_INT(c.notrack, 0);
    CHECK_INT(c.ttl_icmp, 1);
    fw_config_default(&c);
    CHECK_INT(P0(&c, "--ext-notrack", "none", "--no-notrack", NULL, NULL, NULL), 0);
    CHECK_INT(P0(&c, "--ext-notrack", "all", "--no-notrack", NULL, NULL, NULL), -1);
    CHECK(strstr(err.data, "exclude each other") != NULL);
    CHECK_INT(P0(&c, "--ext-notrack", "some", NULL, NULL, NULL, NULL), -1);
    CHECK_INT(P0(&c, "--ext-first", "x", NULL, NULL, NULL, NULL), -1);
    CHECK(strstr(err.data, "--ext-first") != NULL);

    fw_config_default(&c);
    CHECK_INT(P0(&c, "-i", "eth0", "--ext-wan", "ppp0", NULL, NULL), -1);
    CHECK(strstr(err.data, "--ext-wan and --iface") != NULL);
    fw_config_default(&c);
    CHECK_INT(P0(&c, "--ext-wan", "a,b,c,d,e,f,g,h,i", NULL, NULL, NULL, NULL), -1);
    CHECK_INT(c.nifs, 0);

    /* flow offload needs both sides, and nft */
    fw_config_default(&c);
    CHECK_INT(P0(&c, "--ext-flowoffload", "software", "-i", "eth0", NULL, NULL), -1);
    CHECK(strstr(err.data, "--ext-lan") != NULL);
    fw_config_default(&c);
    CHECK_INT(P0(&c, "--ext-lan", "br-lan", NULL, NULL, NULL, NULL), -1);
    CHECK(strstr(err.data, "is for --ext-flowoffload") != NULL);
    fw_config_default(&c);
    CHECK_INT(P0(&c, "--ext-flowoffload", "hardware", "-i", "eth0", "--ext-lan", "br-lan,wlan0"), 0);
    CHECK_INT(c.offload, 2);
    CHECK_INT(c.nlan, 2);
    CHECK_STR(c.lan[1], "wlan0");
    fw_config_default(&c);
    CHECK_INT(P0(&c, "--ext-flowoffload", "none", NULL, NULL, NULL, NULL), 0);
    CHECK_INT(c.offload, 0);
    fw_config_default(&c);
    c.backend = FW_IPTABLES;
    CHECK_INT(P0(&c, "--ext-flowoffload", "software", "-i", "eth0", "--ext-lan", "br-lan"), -1);
    CHECK(strstr(err.data, "nft only") != NULL);
    fw_config_default(&c);
    CHECK_INT(P0(&c, "--ext-flowoffload", "fast", NULL, NULL, NULL, NULL), -1);

    /* hooks: absolute, executable */
    fw_config_default(&c);
    CHECK_INT(P0(&c, "--fw-hook-pre", "hook.sh", NULL, NULL, NULL, NULL), -1);
    CHECK(strstr(err.data, "absolute path") != NULL);
    CHECK_INT(P0(&c, "--fw-hook-pre", "/a'b", NULL, NULL, NULL, NULL), -1);
#  ifndef _WIN32
    CHECK_INT(P0(&c, "--fw-hook-post", "/nonexistent/hook", NULL, NULL, NULL, NULL), -1);
    CHECK(strstr(err.data, "not an executable") != NULL);
    CHECK_INT(P0(&c, "--fw-hook-pre", "/bin/sh", "--fw-hook-post", "/bin/sh", NULL, NULL), 0);
    CHECK_STR(c.hook_pre, "/bin/sh");
    CHECK_STR(c.hook_post, "/bin/sh");
#  endif

    /* Windows: the Linux rules' options are refused */
    fw_config_default(&c);
    CHECK_INT(parse(&c, 1, &owned, NULL, &err, "--ext-ttl-icmp", NULL, NULL, NULL, NULL, NULL), -1);
    CHECK(strstr(err.data, "--ext-ttl-icmp is Linux only") != NULL);
    fw_config_default(&c);
    CHECK_INT(parse(&c, 1, &owned, NULL, &err, "--ext-first", "out=2", NULL, NULL, NULL, NULL), 0);

    /* --wf-*: the filter, whole; --wf-priority */
    fw_config_default(&c);
    CHECK_INT(parse(&c, 1, &owned, "", &err, "--wf-tcp-out", "443", "--wf-priority", "-5", NULL, NULL), 0);
    CHECK(owned != NULL && c.filter == owned && c.filter_whole);
    CHECK_INT(c.priority, -5);
    free(owned);
    fw_config_default(&c);
    CHECK_INT(parse(&c, 1, &owned, NULL, &err, "--wf-priority", "30001", NULL, NULL, NULL, NULL), -1);
    CHECK_INT(parse(&c, 1, &owned, NULL, &err, "--wf-priority", "1", "--priority", "1", NULL, NULL), -1);
    fw_config_default(&c);
    c.filter = "tcp";
    CHECK_INT(parse(&c, 1, &owned, NULL, &err, "--wf-udp-out", "53", NULL, NULL, NULL, NULL), -1);
    CHECK(strstr(err.data, "--filter") != NULL);
    fw_config_default(&c);
    CHECK_INT(parse(&c, 0, &owned, "f.txt", &err, "--wf-udp-out", "53", "--wf-save", "f.txt", NULL, NULL), 0);
    CHECK(c.filter_whole);
    free(owned);
    sb_free(&err);
}

/* the --wf-* filter of these words */
static int wf(int server, sbuf *out, sbuf *err, const char *w0, const char *w1, const char *w2, const char *w3)
{
    const char *words[] = {"x", w0, w1, w2, w3};
    char *argv[6];
    int argc = 1, r;
    char e[128];
    args_t a;
    argv[0] = (char *)words[0];
    for (int i = 1; i < 5 && words[i]; i++)
        argv[argc++] = (char *)words[i];
    sb_reset(out);
    sb_reset(err);
    if (args_parse(&a, argc, argv, g_defs, e, sizeof(e)) < 0) {
        sb_puts(err, e);
        return -1;
    }
    r = xfw_wf_filter(&a, server, out, err);
    args_free(&a);
    return r;
}

#  define REDIRECT                                                                                             \
      "tcp.PayloadLength>=12 and tcp.Payload32[0]==0x48545450 and tcp.Payload16[2]==0x2F31 and "                \
      "tcp.Payload[6]==0x2E and tcp.Payload16[4]==0x2033 and tcp.Payload[10]==0x30 and (tcp.Payload[11]==0x32 " \
      "or tcp.Payload[11]==0x37)"

TEST(fwx_wf)
{
    sbuf s, e;
    sb_init(&s);
    sb_init(&e);
    /* the filter of "winws2 --wf-tcp-out=80,443 --wf-filter-lan=0" */
    CHECK_INT(wf(0, &s, &e, "--wf-tcp-out", "80,443", "--wf-filter-lan", "0"), 0);
    CHECK_STR(s.data, "!impostor\nand !loopback\nand (!tcp or tcp.Syn or tcp.Rst or tcp.Fin or tcp.PayloadLength>0)"
                      "\nand\n(\n false or\n " REDIRECT " or\n outbound and ((tcp.DstPort == 80) or (tcp.DstPort == "
                      "443)) or\n inbound and (tcp.Syn or tcp.Rst or tcp.Fin) and ((tcp.SrcPort == 80) or "
                      "(tcp.SrcPort == 443))\n)");
    /* server: the ports swap */
    CHECK_INT(wf(1, &s, &e, "--wf-tcp-out", "80", "--wf-filter-lan", "0"), 0);
    CHECK(strstr(s.data, " outbound and ((tcp.SrcPort == 80)) or\n inbound and (tcp.Syn or tcp.Rst or tcp.Fin) and "
                         "((tcp.DstPort == 80))\n)") != NULL);
    /* UDP, ranges and negation, ICMP, IP protocols, one family, no loopback filter */
    CHECK_INT(wf(0, &s, &e, "--wf-udp-out", "443,~50000-50100", "--wf-l3", "ipv6"), 0);
    CHECK(strstr(s.data, " outbound and ((udp.DstPort == 443) or (udp.DstPort < 50000 or udp.DstPort > 50100))\n)") !=
          NULL);
    CHECK(strstr(s.data, "\nand ipv6\n") != NULL);
    CHECK(strstr(s.data, REDIRECT) == NULL); /* no TCP: no redirect check, no empty TCP filter */
    CHECK(strstr(s.data, "PayloadLength>0") == NULL);
    CHECK(strstr(s.data, " outbound and ((ipv6.DstAddr < 2001::0") != NULL); /* LAN: IPv6 only */
    CHECK(strstr(s.data, "ip.DstAddr") == NULL);
    CHECK_INT(wf(0, &s, &e, "--wf-icmp-in", "11,3:4", "--wf-ipp-out", "47,*"), 0);
    CHECK(strstr(s.data, " inbound and (icmp.Type==11 or icmpv6.Type==11 or icmp.Type==3 and icmp.Code==4 or "
                         "icmpv6.Type==3 and icmpv6.Code==4)") != NULL);
    CHECK(strstr(s.data, " outbound and (ip.Protocol==47 or ipv6.NextHdr==47 or ip or ipv6)") != NULL);
    CHECK(strstr(s.data, "\nand\n(\n outbound and (((ip.DstAddr < 10.0.0.0") != NULL); /* both families */
    CHECK_INT(wf(0, &s, &e, "--wf-tcp-in", "443", "--wf-filter-loopback", "0"), 0);
    CHECK(strstr(s.data, "loopback") == NULL);
    CHECK(strstr(s.data, " inbound and ((tcp.SrcPort == 443)) or\n outbound and (tcp.Syn or tcp.Rst or tcp.Fin) and "
                         "((tcp.DstPort == 443))") != NULL);
    /* --wf-tcp-empty, --wf-iface, raw parts and filter */
    CHECK_INT(wf(0, &s, &e, "--wf-tcp-out", "443", "--wf-tcp-empty", NULL), 0);
    CHECK(strstr(s.data, "PayloadLength>0") == NULL);
    CHECK_INT(wf(0, &s, &e, "--wf-iface", "7.1", "--wf-raw-part", "udp.DstPort == 53"), 0);
    CHECK(strstr(s.data, "\nand ifIdx=7 and subIfIdx=1\n") != NULL);
    CHECK(strstr(s.data, " false or\n (\nudp.DstPort == 53\n )\n)") != NULL);
    CHECK_INT(wf(0, &s, &e, "--wf-raw-filter", "ip.TTL > 1", "--wf-udp-in", "53"), 0);
    CHECK(strstr(s.data, "\nand\n(\nip.TTL > 1\n)\nand\n(\n false") != NULL);
    CHECK(strstr(s.data, " inbound and ((udp.SrcPort == 53))") != NULL);
    /* --wf-raw: as it is */
    CHECK_INT(wf(0, &s, &e, "--wf-raw", "tcp and outbound", NULL, NULL), 0);
    CHECK_STR(s.data, "tcp and outbound");

    /* errors */
    CHECK_INT(wf(0, &s, &e, "--wf-raw", "tcp", "--wf-udp-in", "53"), -1);
    CHECK(strstr(e.data, "--wf-raw replaces") != NULL);
    CHECK_INT(wf(0, &s, &e, "--wf-raw", "tcp", "--wf-raw-part", "udp"), -1);
    CHECK_INT(wf(0, &s, &e, "--wf-l3", "ipv4", NULL, NULL), -1);
    CHECK(strstr(e.data, "needs ports") != NULL);
    CHECK_INT(wf(0, &s, &e, "--wf-l3", "ip", "--wf-udp-in", "53"), -1);
    CHECK_INT(wf(0, &s, &e, "--wf-iface", "x", "--wf-udp-in", "53"), -1);
    CHECK_INT(wf(0, &s, &e, "--wf-tcp-out", "70000", NULL, NULL), -1);
    CHECK(strstr(e.data, "--wf-tcp-out") != NULL);
    CHECK_INT(wf(0, &s, &e, "--wf-icmp-in", "-", NULL, NULL), -1); /* nothing added */
    CHECK_INT(wf(0, &s, &e, "--wf-ipp-out", "300", NULL, NULL), -1);
    CHECK_INT(wf(0, &s, &e, "--wf-filter-lan", "2", "--wf-udp-in", "53"), -1);
    CHECK_INT(wf(0, &s, &e, "--wf-raw-part", "", NULL, NULL), -1);
    CHECK_INT(wf(0, &s, &e, "--wf-raw-part", "@/nonexistent/f", NULL, NULL), -1);
    CHECK(strstr(e.data, "cannot read") != NULL);
    sb_free(&s);
    sb_free(&e);
}

#  ifdef __linux__
static void write_exe(const char *path, const char *body)
{
    FILE *f = fopen(path, "w");
    if (f) {
        fputs(body, f);
        fclose(f);
    }
    chmod(path, 0755);
}

/* The hooks run around the rules, through a fake iptables on PATH. */
TEST(fwx_hooks)
{
    char dir[] = "/tmp/geneva-fwx-XXXXXX", bin[300], hook[300], log[300], body[400];
    const char *old = getenv("PATH");
    char *saved = old ? xstrdup(old) : NULL;
    fw_config c;
    sbuf e, s;
    FILE *f;
    if (!mkdtemp(dir)) {
        CHECK(0);
        free(saved);
        return;
    }
    snprintf(bin, sizeof(bin), "%s/iptables", dir);
    snprintf(hook, sizeof(hook), "%s/hook", dir);
    snprintf(log, sizeof(log), "%s/log", dir);
    snprintf(body, sizeof(body), "#!/bin/sh\necho \"iptables $3\" >> %s\nexit 0\n", log);
    write_exe(bin, body);
    snprintf(body, sizeof(body), "#!/bin/sh\necho \"hook $*\" >> %s\nexit 1\n", log);
    write_exe(hook, body);
    setenv("PATH", dir, 1);
    sb_init(&e);
    sb_init(&s);
    fw_config_default(&c);
    ports_parse("443", &c.ports);
    c.backend = FW_IPTABLES;
    c.ipv6 = 0;
    c.notrack = 0;
    c.hook_pre = c.hook_post = hook;
    CHECK_INT(fw_up(&c, &e), 0); /* a failing hook is only a warning */
    fw_down(&c);
    if ((f = fopen(log, "r")) != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), f))
            sb_puts(&s, line);
        fclose(f);
    }
    /* the hooks once each, the rules between them */
    CHECK(s.data && !strncmp(s.data, "hook up iptables 310\n", 21));
    CHECK_INT(count(s.data ? s.data : "", "hook up iptables 310\n"), 2);
    CHECK_INT(count(s.data ? s.data : "", "hook down iptables 310\n"), 2);
    CHECK(s.data && strstr(s.data, "hook up iptables 310\nhook down iptables 310\n") != NULL);
    CHECK(s.data && strstr(s.data, "hook up iptables 310\niptables ") == s.data); /* pre, then the rules */
    {
        const char *p = s.data ? s.data : "";
        size_t n = strlen(p);
        CHECK(n > 23 && !strcmp(p + n - 23, "hook down iptables 310\n"));
    }

    /* flow offload: iptables refuses */
    c.offload = 1;
    sb_reset(&e);
    CHECK_INT(fw_up(&c, &e), -1);
    CHECK(strstr(e.data, "nft only") != NULL);

    remove(bin);
    remove(hook);
    remove(log);
    rmdir(dir);
    if (saved)
        setenv("PATH", saved, 1);
    else
        unsetenv("PATH");
    free(saved);
    sb_free(&e);
    sb_free(&s);
}
#  endif

void suite_fwx(void)
{
    RUN(fwx_first);
    RUN(fwx_iflist);
    RUN(fwx_nft);
    RUN(fwx_iptables);
    RUN(fwx_windivert_ifaces);
    RUN(fwx_options);
    RUN(fwx_wf);
#  ifdef __linux__
    RUN(fwx_hooks);
#  endif
}

#else
void suite_fwx(void) {}
#endif
