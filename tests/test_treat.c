/* The treatment of --ext-auto propose|apply (X11c, src/ext/treat.c): the
 * detector's key and flow events by hand, the arms the connections draw,
 * TREAT, CUSUM, UNTREATABLE and its rechecks, the proposals and ctl. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "log.h"
#include "rng.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/ctrack.h"
#  include "ext/detect.h"
#  include "ext/treat.h"
#  include "ext/tuner.h"
#  include "ext/xact.h"

static sbuf g_ev;
#  define EV (g_ev.data ? g_ev.data : "")

static void tap(const char *line, size_t len, void *ctx)
{
    (void)ctx;
    sb_append(&g_ev, line, len);
    sb_putc(&g_ev, '\n');
}

/* a TCP or UDP connection 10.0.0.1:cport -> 10.9.<srv>.2:443 */
static void mkflow(ct_flow *f, int udp, unsigned srv, unsigned cport)
{
    memset(f, 0, sizeof(*f));
    f->ver = 4;
    f->proto = udp ? 17 : 6;
    f->cli[0] = 10, f->cli[3] = 1;
    f->srv[0] = 10, f->srv[1] = 9, f->srv[2] = (uint8_t)srv, f->srv[3] = 2;
    f->cport = (uint16_t)cport;
    f->sport = 443;
}

static int key(const char *k, int level, int impaired, int cls, uint64_t now)
{
    xdet_key_ev ev;
    memset(&ev, 0, sizeof(ev));
    ev.key = k;
    ev.level = level;
    ev.impaired = impaired;
    ev.cls = cls;
    return xtreat_key(&ev, now);
}

static void outcome(const ct_flow *f, int ok, uint64_t now)
{
    xdet_flow_ev ev;
    memset(&ev, 0, sizeof(ev));
    ev.f = f;
    ev.ok = ok;
    ev.cls = ok ? XC_NONE : XC_RST_INJECT;
    xtreat_outcome(&ev, now);
}

/* n connections to 10.9.<srv>.2; the arms of mask good (bit 0: arm 1)
 * succeed, the others fail; the connections until the key's state
 * changes to want ("ext_treat ... want"), 0: it did not */
static int connections(unsigned srv, int udp, unsigned good, int n, unsigned *port, uint64_t *now, const char *want)
{
    char pat[64];
    snprintf(pat, sizeof(pat), "\"state\":\"%s\"", want);
    for (int i = 1; i <= n; i++) {
        ct_flow f;
        int a;
        mkflow(&f, udp, srv, (*port)++);
        a = xtreat_flow(&f, NULL, *now, NULL);
        if (a < 0)
            return -1;
        CHECK_INT(xtreat_flow(&f, NULL, *now, NULL), a); /* the connection keeps it */
        *now += 100;
        outcome(&f, good >> a & 1, *now);
        if (strstr(EV, pat))
            return i;
    }
    return 0;
}

static void text(void (*fn)(jw *, size_t), char *out, size_t cap)
{
    sbuf s;
    jw w;
    sb_init(&s);
    jw_init(&w, &s);
    jw_obj(&w);
    fn(&w, 100);
    jw_obj_end(&w);
    snprintf(out, cap, "%s", s.data);
    sb_free(&s);
}

static void status(jw *w, size_t max)
{
    (void)max;
    xtreat_status(w);
}

TEST(treat_apply)
{
    sbuf e;
    unsigned port = 40000;
    uint64_t now = 1000000;
    char out[4000];
    ct_flow f;
    int n;
    sb_init(&e);
    sb_init(&g_ev);
    rng_global_seed(1);
    ev_set_tap(tap, NULL);
    strategy_set_xact(&xact_ops); /* the arms' x-actions */
    CHECK_INT(xtreat_start(XTR_APPLY, &e), 0);
    CHECK_INT((int)xtreat_narms(), 7);
    CHECK(xtreat_arm(0) != NULL);

    /* a port or a network is not treated; an unknown address is not */
    CHECK_INT(key("tcp/443", XK_PORT, 1, XC_RST_INJECT, now), 0);
    mkflow(&f, 0, 1, port);
    CHECK_INT(xtreat_flow(&f, NULL, now, NULL), -1);

    /* RST_INJECT: the TCP arms in turn; arm 3 works and is kept */
    CHECK_INT(key("10.9.1.2", XK_IP, 1, XC_RST_INJECT, now), 1);
    CHECK(strstr(EV, "\"ev\":\"ext_treat\",\"key\":\"10.9.1.2\",\"state\":\"trial\",\"class\":\"RST_INJECT\"") !=
          NULL);
    n = connections(1, 0, 1u << 2, 60, &port, &now, "treat");
    CHECK(n >= 3 && n <= 40);
    CHECK(strstr(EV, "\"state\":\"treat\",\"class\":\"RST_INJECT\",\"arm\":3,"
                            "\"strategy\":\"[TCP:flags:PA]-xsplit{pos=method+2}-| \\\\/\"") != NULL);
    /* every connection runs it now, the UDP ones nothing */
    for (int i = 0; i < 5; i++) {
        mkflow(&f, 0, 1, port++);
        CHECK_INT(xtreat_flow(&f, NULL, now, NULL), 2);
        outcome(&f, 1, now);
    }
    mkflow(&f, 1, 1, port++);
    CHECK_INT(xtreat_flow(&f, NULL, now, NULL), -1);
    /* healthy again: still in treatment (the policy keeps it impaired) */
    CHECK_INT(key("10.9.1.2", XK_IP, 0, XC_NONE, now), 1);
    /* another TCP class: the same arms, the arm stays */
    CHECK_INT(key("10.9.1.2", XK_IP, 1, XC_RETRANS, now), 1);
    mkflow(&f, 0, 1, port++);
    CHECK_INT(xtreat_flow(&f, NULL, now, NULL), 2);
    outcome(&f, 1, now);
    text(status, out, sizeof(out));
    CHECK_STR(out, "{\"treat\":{\"mode\":\"apply\",\"arms\":7,\"proposed\":0,\"trial\":0,\"treat\":1,"
                   "\"untreatable\":0,\"search\":0,\"ga\":false}}");
    text(xtreat_keys, out, sizeof(out));
    CHECK(strstr(out, "{\"key\":\"10.9.1.2\",\"level\":\"ip\",\"state\":\"treat\",\"class\":\"RETRANS\",\"arm\":3,") !=
          NULL);

    /* the censor changes: CUSUM sends it back to the trial within 3
     * failures */
    sb_reset(&g_ev);
    n = connections(1, 0, 0, 10, &port, &now, "trial");
    CHECK_INT(n, 3);
    CHECK(strstr(EV, "CUSUM") != NULL);

    /* every arm fails: UNTREATABLE once each arm failed twice, again
     * after 60 s, 120 s ... */
    sb_reset(&g_ev);
    n = connections(1, 0, 0, 60, &port, &now, "untreatable");
    CHECK(n >= 10 && n <= 40);
    CHECK(strstr(EV, "\"retry_s\":60,\"why\":\"every arm failed\"") != NULL);
    mkflow(&f, 0, 1, port++);
    CHECK_INT(xtreat_flow(&f, NULL, now, NULL), -1);
    CHECK_INT(key("10.9.1.2", XK_IP, 1, XC_RST_INJECT, now), 1); /* owned */
    sb_reset(&g_ev);
    xtreat_tick(now + 59000);
    CHECK_STR(EV, "");
    now += 60000;
    xtreat_tick(now);
    CHECK(strstr(EV, "\"state\":\"trial\",\"class\":\"RST_INJECT\",\"why\":\"the recheck\"") != NULL);
    sb_reset(&g_ev);
    n = connections(1, 0, 0, 60, &port, &now, "untreatable");
    CHECK(n >= 10);
    CHECK(strstr(EV, "\"retry_s\":120,") != NULL);
    /* a success resets the backoff */
    now += 120000;
    xtreat_tick(now);
    n = connections(1, 0, 1, 60, &port, &now, "treat");
    CHECK(n > 0);

    /* four arms work as well: P(best) stays low, the posterior mean decides */
    sb_reset(&g_ev);
    CHECK_INT(key("10.9.7.2", XK_IP, 1, XC_RST_INJECT, now), 1);
    n = connections(7, 0, 0x1b, 60, &port, &now, "treat");
    CHECK(n >= 3 && n <= 12);

    /* no arm for the class: UNTREATABLE at once; healthy: forgotten */
    sb_reset(&g_ev);
    CHECK_INT(key("10.9.2.2", XK_IP, 1, XC_BLACKHOLE_SYN, now), 1);
    CHECK(strstr(EV, "\"key\":\"10.9.2.2\",\"state\":\"untreatable\",\"class\":\"BLACKHOLE_SYN\","
                            "\"retry_s\":60,\"why\":\"no arm for the class\"") != NULL);
    sb_reset(&g_ev);
    xtreat_tick(now + 60000);
    CHECK(strstr(EV, "\"retry_s\":120,\"why\":\"still no arm for the class\"") != NULL);
    CHECK_INT(key("10.9.2.2", XK_IP, 0, XC_NONE, now), 0);
    /* impaired again: anew */
    sb_reset(&g_ev);
    CHECK_INT(key("10.9.2.2", XK_IP, 1, XC_ICMP_PROHIBIT, now), 1);
    CHECK(strstr(EV, "\"retry_s\":60,") != NULL);

    /* QUIC: the UDP arms; a host name's record before its address's */
    sb_reset(&g_ev);
    CHECK_INT(key("quic.example", XK_HOST, 1, XC_UDP_NOANSWER, now), 1);
    mkflow(&f, 1, 3, port++);
    CHECK_INT(xtreat_flow(&f, "other.example", now, NULL), -1);
    n = xtreat_flow(&f, "quic.example", now, NULL);
    CHECK(n == 5 || n == 6);
    mkflow(&f, 0, 3, port++);
    CHECK_INT(xtreat_flow(&f, "quic.example", now, NULL), -1); /* TCP: no arm */

    xtreat_stop();
    CHECK_INT(xtreat_mode(), XTR_OFF);
    CHECK_INT((int)xtreat_narms(), 0);
    ev_set_tap(NULL, NULL);
    strategy_set_xact(NULL);
    sb_free(&g_ev);
    sb_free(&e);
}

/* --ext-treat-arms: only these arms */
TEST(treat_allow)
{
    sbuf e;
    char out[2000];
    ct_flow f;
    sb_init(&e);
    strategy_set_xact(&xact_ops);
    CHECK_INT(xtreat_start(XTR_APPLY, &e), 0);
    CHECK_INT(xtreat_allow("0", &e), -1);
    CHECK_STR(e.data, "bad --ext-treat-arms 0 (arm numbers 1-7, comma-separated)");
    CHECK_INT(xtreat_allow("8", &e), -1);
    CHECK_INT(xtreat_allow("1,,2", &e), -1);
    CHECK_INT(xtreat_allow("1x", &e), -1);
    CHECK_INT(xtreat_allow("", &e), -1);
    CHECK_INT(xtreat_allow("3,1,6", &e), 0);
    CHECK_INT(key("10.9.12.2", XK_IP, 1, XC_RETRANS, 1000), 1);
    for (unsigned p = 52000; p < 52020; p++) {
        int a;
        mkflow(&f, 0, 12, p);
        a = xtreat_flow(&f, NULL, 1000, NULL);
        CHECK(a == 0 || a == 2);
    }
    text(xtreat_keys, out, sizeof(out));
    CHECK(strstr(out, "\"arms\":[{\"arm\":1,") != NULL);
    CHECK(strstr(out, "{\"arm\":2,") == NULL);
    CHECK(strstr(out, "{\"arm\":3,") != NULL);
    /* UDP: arm 6 only; a class whose arms are all left out has none */
    CHECK_INT(xtreat_allow("1", &e), 0);
    CHECK_INT(key("10.9.13.2", XK_IP, 1, XC_UDP_NOANSWER, 1000), 1);
    text(xtreat_keys, out, sizeof(out));
    CHECK(strstr(out, "{\"key\":\"10.9.13.2\",\"level\":\"ip\",\"state\":\"untreatable\"") != NULL);
    xtreat_stop();
    strategy_set_xact(NULL);
    sb_free(&e);
}

/* FREEZE_N: a provisional success waits for the flow's next event */
TEST(treat_provisional)
{
    sbuf e;
    ct_flow f;
    xdet_flow_ev ev;
    char out[2000], want[64];
    int a;
    sb_init(&e);
    strategy_set_xact(&xact_ops);
    CHECK_INT(xtreat_start(XTR_APPLY, &e), 0);
    CHECK_INT(key("10.9.9.2", XK_IP, 1, XC_FREEZE, 1000), 1);
    mkflow(&f, 0, 9, 50000);
    a = xtreat_flow(&f, NULL, 1000, NULL);
    CHECK(a >= 0 && a < 5);
    memset(&ev, 0, sizeof(ev));
    ev.f = &f;
    ev.ok = 1;
    ev.provisional = 1;
    xtreat_outcome(&ev, 1100);
    snprintf(want, sizeof(want), "{\"arm\":%d,\"tries\":0,\"ok\":0}", a + 1);
    text(xtreat_keys, out, sizeof(out));
    CHECK(strstr(out, want) != NULL);
    ev.provisional = 0; /* "the stricter success" */
    xtreat_outcome(&ev, 1200);
    snprintf(want, sizeof(want), "{\"arm\":%d,\"tries\":1,\"ok\":1}", a + 1);
    text(xtreat_keys, out, sizeof(out));
    CHECK(strstr(out, want) != NULL);
    xtreat_stop();
    strategy_set_xact(NULL);
    sb_free(&e);
}

#  ifndef _WIN32
#    include <sys/stat.h>
#    include <unistd.h>

/* --ext-ga with a stand-in for geneva evolve: a script printing its line */
static void fake_evolve(const char *path, const char *line)
{
    FILE *fp = fopen(path, "w");
    fprintf(fp, "#!/bin/sh\nprintf '%%s\\n' '%s'\n", line);
    fclose(fp);
    chmod(path, 0755);
}

/* ticks until the search ends (its event) */
static int ga_wait(uint64_t *now, const char *want)
{
    for (int i = 0; i < 500; i++) {
        xtreat_tick(*now);
        *now += 1000;
        if (strstr(EV, want))
            return 1;
        usleep(10000);
    }
    return 0;
}

TEST(treat_ga)
{
    sbuf e;
    xga_config gc;
    char exe[64], text[256];
    unsigned port = 51000;
    uint64_t now = 1000000;
    uint32_t ga = 0;
    ct_flow f;
    int n, fd;
    sb_init(&e);
    sb_init(&g_ev);
    rng_global_seed(5);
    ev_set_tap(tap, NULL);
    strategy_set_xact(&xact_ops);
    snprintf(exe, sizeof(exe), "/tmp/geneva-test-ga-XXXXXX");
    fd = mkstemp(exe);
    CHECK(fd >= 0);
    close(fd);
    fake_evolve(exe, "12.5\t1\t\\/ [TCP:flags:R]-drop-|");
    CHECK_INT(xtreat_start(XTR_APPLY, &e), 0);
    memset(&gc, 0, sizeof(gc));
    snprintf(gc.exe, sizeof(gc.exe), "%s", exe);
    gc.pop = 4, gc.gen = 1, gc.queue = 375;
    CHECK_INT(xga_set(&gc, &e), 0);
    CHECK_INT(xga_on(), 1);

    /* every arm fails: the search instead of UNTREATABLE */
    CHECK_INT(key("10.9.10.2", XK_IP, 1, XC_RETRANS, now), 1);
    n = connections(10, 0, 0, 60, &port, &now, "search");
    CHECK(n >= 10 && n <= 40);
    CHECK(strstr(EV, "\"state\":\"search\",\"class\":\"RETRANS\",\"why\":\"every arm failed: the genetic") != NULL);
    mkflow(&f, 0, 10, port++);
    CHECK_INT(xtreat_flow(&f, NULL, now, NULL), -1); /* no arm meanwhile */
    CHECK(ga_wait(&now, "the genetic search found an arm"));
    CHECK(strstr(EV, "\"state\":\"trial\",\"class\":\"RETRANS\",\"why\":\"the genetic search found an arm\"") != NULL);
    /* the found arm alone: the connections run it, it works, TREAT */
    mkflow(&f, 0, 10, port++);
    CHECK_INT(xtreat_flow(&f, NULL, now, &ga), XTR_GA_ARM);
    CHECK(ga != 0);
    CHECK_INT(xtreat_ga_text(ga, text, sizeof(text)), 1);
    CHECK_STR(text, "\\/ [TCP:flags:R]-drop-|");
    CHECK_INT(xtreat_ga_text(ga + 100, text, sizeof(text)), 0);
    sb_reset(&g_ev);
    n = connections(10, 0, 1u << XTR_GA_ARM, 10, &port, &now, "treat");
    CHECK(n >= 3 && n <= 4);
    CHECK(strstr(EV, "\"arm\":8,\"strategy\":\"\\\\/ [TCP:flags:R]-drop-|\"") != NULL);

    /* a search that finds nothing: UNTREATABLE */
    fake_evolve(exe, "-400\t1\t\\/");
    sb_reset(&g_ev);
    CHECK_INT(key("10.9.11.2", XK_IP, 1, XC_RETRANS, now), 1);
    n = connections(11, 0, 0, 60, &port, &now, "search");
    CHECK(n > 0);
    CHECK(ga_wait(&now, "the genetic search found nothing"));
    CHECK(strstr(EV, "\"state\":\"untreatable\",\"class\":\"RETRANS\",\"retry_s\":60,\"why\":\"the genetic search found nothing\"") != NULL);

    /* propose: the found arm is a new proposal, nothing runs before ext_approve */
    xtreat_stop();
    CHECK_INT(xtreat_start(XTR_PROPOSE, &e), 0);
    CHECK_INT(xga_set(&gc, &e), 0);
    fake_evolve(exe, "12.5\t1\t\\/ [TCP:flags:R]-drop-|");
    sb_reset(&g_ev);
    CHECK_INT(key("10.9.12.2", XK_IP, 1, XC_RETRANS, now), 1);
    {
        const char *p = strstr(EV, "\"ev\":\"ext_proposal\"");
        unsigned long long id = 0;
        CHECK(p && (p = strstr(p, "\"id\":")) && sscanf(p + 5, "%llu", &id) == 1);
        CHECK_INT(xtreat_decide(id, 1, NULL), 1);
    }
    n = connections(12, 0, 0, 60, &port, &now, "search");
    CHECK(n > 0);
    sb_reset(&g_ev);
    CHECK(ga_wait(&now, "the genetic search found an arm: waits for ext_approve"));
    CHECK(strstr(EV, "\"kind\":\"treat\",\"class\":\"RETRANS\",\"arms\":1,\"strategy\":\"\\\\/ [TCP:flags:R]-drop-|\"") != NULL);
    mkflow(&f, 0, 12, port++);
    CHECK_INT(xtreat_flow(&f, NULL, now, NULL), -1); /* not before the consent */
    {
        const char *p = strstr(EV, "\"ev\":\"ext_proposal\"");
        unsigned long long id = 0;
        CHECK(p && (p = strstr(p, "\"id\":")) && sscanf(p + 5, "%llu", &id) == 1);
        CHECK_INT(xtreat_decide(id, 1, NULL), 1);
    }
    mkflow(&f, 0, 12, port++);
    CHECK_INT(xtreat_flow(&f, NULL, now, &ga), XTR_GA_ARM);

    xtreat_stop();
    xga_set(NULL, NULL);
    CHECK_INT(xga_on(), 0);
    unlink(exe);
    ev_set_tap(NULL, NULL);
    strategy_set_xact(NULL);
    sb_free(&g_ev);
    sb_free(&e);
}
#  endif

/* 4096 keys: no more until one is healthy again (its record makes room) */
TEST(treat_full)
{
    sbuf e;
    char k[32];
    sb_init(&e);
    strategy_set_xact(&xact_ops);
    CHECK_INT(xtreat_start(XTR_APPLY, &e), 0);
    for (int i = 0; i < 4096; i++) {
        snprintf(k, sizeof(k), "10.8.%d.%d", i / 256, i % 256);
        CHECK_INT(key(k, XK_IP, 1, XC_BLACKHOLE_SYN, 1000), 1);
    }
    CHECK_INT(key("10.7.0.1", XK_IP, 1, XC_BLACKHOLE_SYN, 1000), 0);
    CHECK_INT(key("10.8.3.3", XK_IP, 0, XC_NONE, 1000), 0);
    CHECK_INT(key("10.7.0.1", XK_IP, 1, XC_BLACKHOLE_SYN, 1000), 1);
    CHECK_INT(key("10.7.0.2", XK_IP, 1, XC_BLACKHOLE_SYN, 1000), 0);
    xtreat_stop();
    strategy_set_xact(NULL);
    sb_free(&e);
}

/* ctl: the reply's text */
static int tctl(const char *cmd, const char *req, char *out, size_t cap)
{
    sbuf sb, e;
    jw w;
    json_val *v = json_parse(req, NULL);
    int r;
    sb_init(&sb);
    sb_init(&e);
    jw_init(&w, &sb);
    jw_obj(&w);
    r = xtune_control(cmd, v, &w, &e);
    jw_obj_end(&w);
    snprintf(out, cap, "%s", r < 0 ? e.data : sb.data);
    json_free(v);
    sb_free(&sb);
    sb_free(&e);
    return r;
}

TEST(treat_propose)
{
    sbuf e;
    unsigned port = 42000;
    uint64_t now = 1000000;
    char out[2000], req[64];
    const char *p;
    long id1, id2;
    ct_flow f;
    sb_init(&e);
    sb_init(&g_ev);
    rng_global_seed(2);
    ev_set_tap(tap, NULL);
    strategy_set_xact(&xact_ops); /* the arms' x-actions */
    CHECK_INT(xtreat_start(XTR_PROPOSE, &e), 0);

    /* a proposal: nothing runs until it is approved */
    CHECK_INT(key("10.9.4.2", XK_IP, 1, XC_RETRANS, now), 1);
    CHECK((p = strstr(EV, "\"ev\":\"ext_proposal\",\"id\":")) != NULL);
    id1 = strtol(p + strlen("\"ev\":\"ext_proposal\",\"id\":"), NULL, 10);
    CHECK(strstr(EV, "\"key\":\"10.9.4.2\",\"kind\":\"treat\",\"class\":\"RETRANS\",\"arms\":5}") != NULL);
    CHECK(strstr(EV, "\"state\":\"proposed\"") != NULL);
    mkflow(&f, 0, 4, port++);
    CHECK_INT(xtreat_flow(&f, NULL, now, NULL), -1);
    /* a TCP class again: the same proposal */
    sb_reset(&g_ev);
    CHECK_INT(key("10.9.4.2", XK_IP, 1, XC_RST_IN, now), 1);
    CHECK_STR(EV, "");
    CHECK_INT(key("10.9.5.2", XK_IP, 1, XC_RST_IN, now), 1);
    CHECK((p = strstr(EV, "\"ev\":\"ext_proposal\",\"id\":")) != NULL);
    id2 = strtol(p + strlen("\"ev\":\"ext_proposal\",\"id\":"), NULL, 10);
    CHECK(id2 > id1);

    /* the tuner is off: ctl still lists and decides them */
    CHECK_INT(tctl("ext_proposals", "{}", out, sizeof(out)), 1);
    CHECK(strstr(out, "\"proposals\":[") != NULL);
    CHECK(strstr(out, "\"key\":\"10.9.4.2\",\"kind\":\"treat\",\"class\":\"RST_IN\",\"arms\":5}") != NULL);
    CHECK(strstr(out, "\"key\":\"10.9.5.2\"") != NULL);
    snprintf(req, sizeof(req), "{\"proposal\":\"%ld\"}", id1);
    CHECK_INT(tctl("ext_approve", req, out, sizeof(out)), 1);
    CHECK_STR(out, "{\"key\":\"10.9.4.2\",\"state\":\"trial\"}");
    CHECK_INT(tctl("ext_approve", req, out, sizeof(out)), -1);
    CHECK(strstr(out, "no proposal") != NULL);
    snprintf(req, sizeof(req), "{\"proposal\":%ld}", id2);
    CHECK_INT(tctl("ext_reject", req, out, sizeof(out)), 1);
    CHECK_STR(out, "{\"key\":\"10.9.5.2\",\"state\":\"untreatable\"}");
    CHECK_INT(tctl("ext_proposals", "{}", out, sizeof(out)), 1);
    CHECK_STR(out, "{\"proposals\":[]}");

    /* approved: the connections draw */
    mkflow(&f, 0, 4, port++);
    CHECK(xtreat_flow(&f, NULL, now, NULL) >= 0);
    /* refused: no recheck, no new proposal for another class */
    sb_reset(&g_ev);
    xtreat_tick(now + 10000000);
    CHECK_INT(key("10.9.5.2", XK_IP, 1, XC_UDP_NOANSWER, now), 1);
    CHECK_STR(EV, "");
    mkflow(&f, 0, 5, port++);
    CHECK_INT(xtreat_flow(&f, NULL, now, NULL), -1);
    /* ... until healthy and impaired again */
    CHECK_INT(key("10.9.5.2", XK_IP, 0, XC_NONE, now), 0);
    CHECK_INT(key("10.9.5.2", XK_IP, 1, XC_RST_IN, now), 1);
    CHECK(strstr(EV, "\"ev\":\"ext_proposal\"") != NULL);

    xtreat_stop();
    /* off: no proposals of the treatment */
    CHECK_INT(tctl("ext_proposals", "{}", out, sizeof(out)), 1);
    CHECK_STR(out, "{\"proposals\":[]}");
    ev_set_tap(NULL, NULL);
    strategy_set_xact(NULL);
    sb_free(&g_ev);
    sb_free(&e);
}

void suite_treat(void);
void suite_treat(void)
{
    RUN(treat_apply);
    RUN(treat_propose);
    RUN(treat_allow);
    RUN(treat_provisional);
#  ifndef _WIN32
    RUN(treat_ga);
#  endif
    RUN(treat_full);
}

#else
void suite_treat(void);
void suite_treat(void) {}
#endif
