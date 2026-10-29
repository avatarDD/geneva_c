/* Port sets and firewall rule generation. */
#include <stdlib.h>
#include <string.h>

#include "fw.h"
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

void suite_fw(void)
{
    test_ports();
    test_iptables();
    test_nft();
    test_forward();
    test_windivert();
}
