/* Port sets and firewall rule generation. */
#include <stdlib.h>
#include <string.h>

#include "fw.h"
#include "fw_int.h"
#include "ports.h"
#include "test.h"
#include "util.h"

static void test_ports(void)
{
    portset ps;
    sbuf s;
    t_current = "ports";
    sb_init(&s);
    CHECK_INT(ports_parse("80,443,8000-8100,9000:9001", &ps), 0);
    CHECK_INT(ps.n, 4);
    CHECK(ports_has(&ps, 80) && ports_has(&ps, 8050) && ports_has(&ps, 9001));
    CHECK(!ports_has(&ps, 81) && !ports_has(&ps, 9002));
    ports_format(&ps, &s, ",", ":");
    CHECK_STR(s.data, "80,443,8000:8100,9000:9001");
    CHECK_INT(ports_parse("", &ps), -1);
    CHECK_INT(ports_parse("80,", &ps), 0);
    CHECK_INT(ports_parse("70000", &ps), -1);
    CHECK_INT(ports_parse("90-80", &ps), -1);
    CHECK_INT(ports_parse("80;443", &ps), -1);
    CHECK_INT(ports_parse("a", &ps), -1);
    sb_free(&s);
}

static int count(const char *hay, const char *needle)
{
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p++)
        n++;
    return n;
}

static void test_iptables(void)
{
    fw_config c;
    sbuf s;
    t_current = "fw iptables";
    sb_init(&s);
    fw_config_default(&c);
    c.ipv6 = 0;
    ports_parse("1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17", &c.ports);
    fw_script(&c, FW_IPTABLES, 1, &s);
    /* 17 ports: multiport takes 15, the rest go to a second rule */
    CHECK_INT(count(s.data, "-m multiport --dports 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 -j NFQUEUE"), 1);
    CHECK_INT(count(s.data, "-m multiport --dports 16,17 -j NFQUEUE"), 1);
    CHECK_INT(count(s.data, "-m multiport --sports 16,17 -j NFQUEUE"), 1);
    CHECK_INT(count(s.data, "--queue-num 310 --queue-bypass"), 4);
    CHECK_INT(count(s.data, "-I POSTROUTING -j GENEVA_310_OUT"), 1);
    CHECK_INT(count(s.data, "-I PREROUTING -j GENEVA_310_IN"), 1);
    CHECK_INT(count(s.data, "-j CT --notrack"), 1);
    CHECK_INT(count(s.data, "ip6tables"), 0);
    CHECK_INT(count(s.data, "-p udp"), 0);

    sb_reset(&s);
    c.server_side = 1;
    c.tcp = 0, c.udp = 1;
    c.ipv4 = 0, c.ipv6 = 1;
    c.notrack = 0, c.bypass = 0, c.in = 0;
    c.queue = 7;
    ports_parse("53", &c.ports);
    fw_script(&c, FW_IPTABLES, 1, &s);
    CHECK_INT(count(s.data, "ip6tables -t mangle -A GENEVA_7_OUT -p udp --sport 53 -j NFQUEUE --queue-num 7\n"), 1);
    CHECK_INT(count(s.data, "GENEVA_7_IN -p"), 0);
    CHECK_INT(count(s.data, "notrack"), 0);
    CHECK_INT(count(s.data, "iptables -t"), 0);

    sb_reset(&s);
    fw_script(&c, FW_IPTABLES, 0, &s);
    CHECK_INT(count(s.data, " -A "), 0);
    CHECK_INT(count(s.data, "-X GENEVA_7_OUT"), 1);
    sb_free(&s);
}

static void test_nft(void)
{
    fw_config c;
    sbuf s;
    t_current = "fw nft";
    sb_init(&s);
    fw_config_default(&c);
    ports_parse("80,8000-8100", &c.ports);
    c.udp = 1;
    c.iface = "wan";
    c.first = 6;
    c.forward_to = "10.0.0.5";
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT(count(s.data, "type filter hook postrouting priority 101;"), 1);
    CHECK_INT(count(s.data, "oifname \"wan\" tcp dport { 80, 8000-8100 } ct original packets 1-6 queue num 310 bypass\n"), 1);
    CHECK_INT(count(s.data, "iifname \"wan\" udp sport { 80, 8000-8100 } ct reply packets 1-6 queue num 310 bypass\n"), 1);
    CHECK_INT(count(s.data, "meta mark & 0x20000000 == 0x20000000 notrack"), 1);
    CHECK_INT(count(s.data, "dnat ip to 10.0.0.5"), 2);
    CHECK_INT(count(s.data, "ip daddr 10.0.0.5 tcp dport { 80, 8000-8100 } masquerade"), 1);
    CHECK_INT(count(s.data, "meta nfproto"), 0);

    sb_reset(&s);
    c.prenat = 1;
    c.ipv6 = 0;
    c.forward_to = NULL;
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT(count(s.data, "type filter hook postrouting priority -150;"), 1);
    CHECK_INT(count(s.data, "meta nfproto ipv4 "), 4);

    sb_reset(&s);
    fw_script(&c, FW_NFT, 0, &s);
    CHECK_STR(s.data, "nft -f - <<'EOF'\nadd table inet geneva_310\ndelete table inet geneva_310\nEOF\n");
    sb_free(&s);
}

/* --ext profiles: ICMP and other IP protocols besides the ports */
static void test_protocols(void)
{
    fw_config c;
    sbuf s, e;
    t_current = "fw protocols";
    sb_init(&s);
    sb_init(&e);
    fw_config_default(&c);
    ports_parse("443", &c.ports);
    c.icmp = 1;
    c.ipp[0] = 47, c.ipp[1] = 50, c.nipp = 2;
    fw_script(&c, FW_IPTABLES, 1, &s);
    CHECK_INT(count(s.data, "iptables -t mangle -A GENEVA_310_OUT -p icmp -j NFQUEUE --queue-num 310 --queue-bypass\n"), 1);
    CHECK_INT(count(s.data, "ip6tables -t mangle -A GENEVA_310_IN -p ipv6-icmp -j NFQUEUE"), 1);
    CHECK_INT(count(s.data, "-A GENEVA_310_IN -p 47 -j NFQUEUE"), 2);
    CHECK_INT(count(s.data, "-p 50 -j NFQUEUE"), 4);
    sb_reset(&s);
    c.iface = "wan";
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT(count(s.data, "oifname \"wan\" meta l4proto { icmp, ipv6-icmp } queue num 310 bypass\n"), 1);
    CHECK_INT(count(s.data, "iifname \"wan\" meta l4proto { 47, 50 } queue num 310 bypass\n"), 1);
    sb_reset(&s);
    c.iface = NULL;
    c.in = 0;
    c.nipp = 1;
    CHECK_INT(fw_windivert_filter(&c, &s, &e), 0);
    CHECK_STR(s.data, "!loopback and ((outbound and (tcp.DstPort == 443 or icmp or icmpv6 or ip.Protocol == 47 or "
                      "ipv6.NextHdr == 47)))");
    /* only ICMP */
    sb_reset(&s);
    c.ports.n = 0;
    c.tcp = 0;
    c.nipp = 0;
    CHECK_INT(fw_windivert_filter(&c, &s, &e), 0);
    CHECK_STR(s.data, "!loopback and ((outbound and (icmp or icmpv6)))");
    sb_free(&s);
    sb_free(&e);
}

/* --ext-workers: the rules balance the flows over the workers' queues */
static void test_nqueues(void)
{
    fw_config c;
    sbuf s;
    t_current = "fw nqueues";
    sb_init(&s);
    fw_config_default(&c);
    c.ipv6 = 0;
    c.nqueues = 4;
    ports_parse("443", &c.ports);
    fw_script(&c, FW_IPTABLES, 1, &s);
    CHECK_INT(count(s.data, "-j NFQUEUE --queue-balance 310:313 --queue-bypass\n"), 2);
    CHECK_INT(count(s.data, "--queue-num"), 0);
    CHECK(count(s.data, "GENEVA_310_OUT") > 0); /* the chains keep the first queue's name */
    CHECK_INT(count(s.data, "GENEVA_311"), 0);
    sb_reset(&s);
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT(count(s.data, "queue num 310-313 bypass\n"), 2);
    CHECK(count(s.data, "table inet geneva_310") > 0);
    CHECK_INT(count(s.data, "geneva_311"), 0);
    sb_reset(&s);
    c.bypass = 0;
    c.forward = 1;
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT(count(s.data, "queue num 310-313\n"), 2);
    sb_reset(&s);
    fw_script(&c, FW_IPTABLES, 1, &s);
    CHECK_INT(count(s.data, "-j NFQUEUE --queue-balance 310:313\n"), 2);
    sb_reset(&s);
    c.nqueues = 1; /* one queue: as before */
    fw_script(&c, FW_IPTABLES, 1, &s);
    CHECK_INT(count(s.data, "--queue-balance"), 0);
    CHECK_INT(count(s.data, "--queue-num 310\n"), 2);
    sb_free(&s);
}

/* Router mode (geneva censor): forwarded packets of both directions. */
static void test_forward(void)
{
    fw_config c;
    sbuf s, e;
    t_current = "fw forward";
    sb_init(&s);
    sb_init(&e);
    fw_config_default(&c);
    c.forward = 1;
    c.queue = 400;
    c.ipv6 = 0;
    ports_parse("80", &c.ports);
    fw_script(&c, FW_IPTABLES, 1, &s);
    CHECK_INT(count(s.data, "iptables -t mangle -A GENEVA_400_FWD -p tcp --dport 80 -j NFQUEUE --queue-num 400 --queue-bypass\n"), 1);
    CHECK_INT(count(s.data, "iptables -t mangle -A GENEVA_400_FWD -p tcp --sport 80 -j NFQUEUE --queue-num 400 --queue-bypass\n"), 1);
    CHECK_INT(count(s.data, "-A GENEVA_400_FWD -m mark --mark 0x20000000/0x20000000 -j RETURN"), 1);
    CHECK_INT(count(s.data, "-I FORWARD -j GENEVA_400_FWD"), 1);
    CHECK_INT(count(s.data, "-I POSTROUTING"), 0);
    CHECK_INT(count(s.data, "-I PREROUTING"), 0);
    CHECK_INT(count(s.data, "notrack"), 0);
    sb_reset(&s);
    fw_script(&c, FW_IPTABLES, 0, &s);
    CHECK_INT(count(s.data, "-D FORWARD -j GENEVA_400_FWD"), 1);
    CHECK_INT(count(s.data, " -A "), 0);

    sb_reset(&s);
    c.tcp = 0, c.udp = 1;
    c.iface = "lan";
    ports_parse("53", &c.ports);
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT(count(s.data, "type filter hook forward priority -150;"), 1);
    CHECK_INT(count(s.data, "meta nfproto ipv4 iifname \"lan\" udp dport { 53 } queue num 400 bypass\n"), 1);
    CHECK_INT(count(s.data, "meta nfproto ipv4 iifname \"lan\" udp sport { 53 } queue num 400 bypass\n"), 1);
    CHECK_INT(count(s.data, "hook postrouting"), 0);
    CHECK_INT(count(s.data, "notrack"), 0);
    CHECK_INT(fw_windivert_filter(&c, &s, &e), -1);
    sb_free(&s);
    sb_free(&e);
}

static void test_windivert(void)
{
    fw_config c;
    sbuf s, e;
    t_current = "fw windivert";
    sb_init(&s);
    sb_init(&e);
    fw_config_default(&c);
    ports_parse("80,8000-8100", &c.ports);
    CHECK_INT(fw_windivert_filter(&c, &s, &e), 0);
    CHECK_STR(s.data, "!loopback and ((outbound and (tcp.DstPort == 80 or (tcp.DstPort >= 8000 and "
                      "tcp.DstPort <= 8100))) or (inbound and (tcp.SrcPort == 80 or (tcp.SrcPort >= "
                      "8000 and tcp.SrcPort <= 8100))))");

    sb_reset(&s);
    ports_parse("53", &c.ports);
    c.udp = 1;
    c.server_side = 1;
    c.in = 0;
    c.ipv6 = 0;
    c.iface = "12";
    CHECK_INT(fw_windivert_filter(&c, &s, &e), 0);
    CHECK_STR(s.data, "!loopback and ip and ifIdx == 12 and ((outbound and (tcp.SrcPort == 53 or "
                      "udp.SrcPort == 53)))");

    sb_reset(&s);
    c.tcp = 0;
    c.ipv4 = 0;
    c.ipv6 = 1;
    c.out = 0;
    c.in = 1;
    c.iface = NULL;
    CHECK_INT(fw_windivert_filter(&c, &s, &e), 0);
    CHECK_STR(s.data, "!loopback and ipv6 and ((inbound and (udp.DstPort == 53)))");

    c.iface = "Ethernet";
    CHECK_INT(fw_windivert_filter(&c, &s, &e), -1);
    CHECK(strstr(e.data, "interface index") != NULL);
    c.iface = NULL;
    c.in = 0;
    CHECK_INT(fw_windivert_filter(&c, &s, &e), -1);
    sb_free(&s);
    sb_free(&e);
}

#ifdef __linux__
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static void write_exe(const char *path, const char *body)
{
    FILE *f = fopen(path, "w");
    if (f) {
        fputs(body, f);
        fclose(f);
    }
    chmod(path, 0755);
}

/* Applies iptables rules through a fake iptables on PATH. */
static void test_exec(void)
{
    char dir[] = "/tmp/geneva-fw-XXXXXX", bin[300], log[300], body[400];
    const char *old = getenv("PATH");
    char *saved = old ? xstrdup(old) : NULL;
    fw_config c;
    sbuf e, s;
    FILE *f;
    t_current = "fw exec";
    if (!mkdtemp(dir)) {
        CHECK(0);
        free(saved);
        return;
    }
    snprintf(bin, sizeof(bin), "%s/iptables", dir);
    snprintf(log, sizeof(log), "%s/log", dir);
    snprintf(body, sizeof(body), "#!/bin/sh\necho \"$*\" >> %s\nexit 0\n", log);
    write_exe(bin, body);
    setenv("PATH", dir, 1);
    sb_init(&e);
    sb_init(&s);
    fw_config_default(&c);
    CHECK_INT(ports_parse("443", &c.ports), 0);
    c.backend = FW_IPTABLES;
    c.ipv6 = 0;

    /* Keenetic starts services with SIGCHLD ignored; children are then
     * reaped by the kernel and waitpid() cannot report their status. */
    signal(SIGCHLD, SIG_IGN);
    CHECK_INT(fw_up(&c, &e), 0);
    CHECK_INT((int)e.len, 0);
    CHECK(signal(SIGCHLD, SIG_DFL) == SIG_IGN); /* the disposition is restored */
    if ((f = fopen(log, "r")) != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), f))
            sb_puts(&s, line);
        fclose(f);
    }
    CHECK(strstr(s.data, "-t mangle -N GENEVA_") != NULL);
    fw_down(&c);

    /* a binary that cannot be executed: the reason is reported */
    write_exe(bin, "#!/nonexistent/interpreter\n");
    sb_reset(&e);
    CHECK_INT(fw_up(&c, &e), -1);
    CHECK(strstr(e.data, "cannot run") != NULL);
    CHECK(strstr(e.data, "No such file") != NULL);

    remove(bin);
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
#endif

/* X13b: ipfw (FreeBSD) and pf (OpenBSD) rules for the divert backend */
static void test_bsd(void)
{
    fw_config c;
    sbuf s, e;
    t_current = "fw ipfw";
    sb_init(&s);
    sb_init(&e);
    fw_config_default(&c);
    ports_parse("443,8000-8100", &c.ports);
    fw_ipfw_rules(&c, "77", &s);
    CHECK_STR(s.data, "ipfw -q add 77 divert 310 tcp from any to any 443,8000-8100 out not diverted // geneva 310\n"
                      "ipfw -q add 77 divert 310 tcp from any 443,8000-8100 to any in not diverted // geneva 310\n");
    /* server side, UDP, IPv4, one interface, outbound only */
    sb_reset(&s);
    c.server_side = 1, c.tcp = 0, c.udp = 1, c.ipv6 = 0, c.in = 0, c.queue = 5;
    c.iface = "em0";
    fw_ipfw_rules(&c, "50", &s);
    CHECK_STR(s.data, "ipfw -q add 50 divert 5 udp from any 443,8000-8100 to any out xmit em0 ip4 not diverted // geneva 5\n");
    /* --ext profiles: ICMP of both families, other protocols, no ports */
    sb_reset(&s);
    fw_config_default(&c);
    c.icmp = 1, c.nipp = 1, c.ipp[0] = 47, c.out = 0;
    fw_ipfw_rules(&c, "60", &s);
    CHECK_STR(s.data, "ipfw -q add 60 divert 310 icmp from any to any in not diverted // geneva 310\n"
                      "ipfw -q add 60 divert 310 ipv6-icmp from any to any in not diverted // geneva 310\n"
                      "ipfw -q add 60 divert 310 47 from any to any in not diverted // geneva 310\n");
    /* a list of interfaces: the rules once for each */
    sb_reset(&s);
    fw_config_default(&c);
    ports_parse("80", &c.ports);
    c.nifs = 2, c.ifs[0] = "em0", c.ifs[1] = "em1", c.in = 0;
    fw_ipfw_rules(&c, "50", &s);
    CHECK_INT(count(s.data, "out xmit em0 not diverted"), 1);
    CHECK_INT(count(s.data, "out xmit em1 not diverted"), 1);

    t_current = "fw pf";
    sb_reset(&s);
    fw_config_default(&c);
    ports_parse("80,443,1000-2000", &c.ports);
    c.udp = 1, c.ipv6 = 0;
    fw_pf_rules(&c, &s);
    CHECK_STR(s.data,
              "pass out quick inet proto tcp from any to any port { 80 443 1000:2000 } divert-packet port 310\n"
              "pass out quick inet proto udp from any to any port { 80 443 1000:2000 } divert-packet port 310\n"
              "pass in quick inet proto tcp from any port { 80 443 1000:2000 } to any divert-packet port 310\n"
              "pass in quick inet proto udp from any port { 80 443 1000:2000 } to any divert-packet port 310\n");
    sb_reset(&s);
    fw_config_default(&c);
    ports_parse("443", &c.ports);
    c.server_side = 1, c.out = 0, c.ipv4 = 0, c.icmp = 1;
    c.iface = "vio0";
    fw_pf_rules(&c, &s);
    CHECK_STR(s.data, "pass in quick on vio0 inet6 proto tcp from any to any port 443 divert-packet port 310\n"
                      "pass in quick on vio0 inet6 proto icmp6 from any to any divert-packet port 310\n");

    /* what only Linux rules can do is refused, and the script says why */
    t_current = "fw bsd limits";
    fw_config_default(&c);
    CHECK_INT(fw_bsd_check(&c, FW_IPFW, &e), 0);
    c.forward_to = "10.0.0.2";
    CHECK_INT(fw_bsd_check(&c, FW_PF, &e), -1);
    CHECK(strstr(e.data, "router mode") && strstr(e.data, "pf rules"));
    sb_reset(&s);
    fw_script(&c, FW_IPFW, 1, &s);
    CHECK(strstr(s.data, "# router mode") && !strstr(s.data, "divert 310"));
    fw_config_default(&c);
    c.healthy_mark = 0x40;
    sb_reset(&e);
    CHECK_INT(fw_bsd_check(&c, FW_IPFW, &e), -1);
    c.healthy_mark = 0, c.nqueues = 4;
    CHECK_INT(fw_bsd_check(&c, FW_IPFW, &e), -1);
    c.nqueues = 0, c.obs = 1;
    CHECK_INT(fw_bsd_check(&c, FW_IPFW, &e), -1);

    /* the names */
    {
        fw_backend b;
        CHECK_INT(fw_backend_parse("ipfw", &b), 0);
        CHECK_INT(b, FW_IPFW);
        CHECK_INT(fw_backend_parse("pf", &b), 0);
        CHECK_INT(b, FW_PF);
        CHECK_STR(fw_backend_name(FW_IPFW), "ipfw");
        CHECK_STR(fw_backend_name(FW_PF), "pf");
    }
    sb_free(&s);
    sb_free(&e);
}

void suite_fw(void)
{
    test_bsd();
    test_ports();
    test_iptables();
    test_nft();
    test_forward();
    test_nqueues();
    test_windivert();
    test_protocols();
#ifdef __linux__
    test_exec();
#endif
}
