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
        a = xtreat_flow(&f, NULL, *now);
        if (a < 0)
            return -1;
        CHECK_INT(xtreat_flow(&f, NULL, *now), a); /* the connection keeps it */
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
    CHECK_INT(xtreat_flow(&f, NULL, now), -1);

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
        CHECK_INT(xtreat_flow(&f, NULL, now), 2);
        outcome(&f, 1, now);
    }
    mkflow(&f, 1, 1, port++);
    CHECK_INT(xtreat_flow(&f, NULL, now), -1);
    /* healthy again: still in treatment (the policy keeps it impaired) */
    CHECK_INT(key("10.9.1.2", XK_IP, 0, XC_NONE, now), 1);
    /* another TCP class: the same arms, the arm stays */
    CHECK_INT(key("10.9.1.2", XK_IP, 1, XC_RETRANS, now), 1);
    mkflow(&f, 0, 1, port++);
    CHECK_INT(xtreat_flow(&f, NULL, now), 2);
    outcome(&f, 1, now);
    text(status, out, sizeof(out));
    CHECK_STR(out, "{\"treat\":{\"mode\":\"apply\",\"arms\":7,\"proposed\":0,\"trial\":0,\"treat\":1,"
                   "\"untreatable\":0}}");
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
    CHECK_INT(xtreat_flow(&f, NULL, now), -1);
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
    CHECK_INT(xtreat_flow(&f, "other.example", now), -1);
    n = xtreat_flow(&f, "quic.example", now);
    CHECK(n == 5 || n == 6);
    mkflow(&f, 0, 3, port++);
    CHECK_INT(xtreat_flow(&f, "quic.example", now), -1); /* TCP: no arm */

    xtreat_stop();
    CHECK_INT(xtreat_mode(), XTR_OFF);
    CHECK_INT((int)xtreat_narms(), 0);
    ev_set_tap(NULL, NULL);
    strategy_set_xact(NULL);
    sb_free(&g_ev);
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
    CHECK_INT(xtreat_flow(&f, NULL, now), -1);
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
    CHECK(xtreat_flow(&f, NULL, now) >= 0);
    /* refused: no recheck, no new proposal for another class */
    sb_reset(&g_ev);
    xtreat_tick(now + 10000000);
    CHECK_INT(key("10.9.5.2", XK_IP, 1, XC_UDP_NOANSWER, now), 1);
    CHECK_STR(EV, "");
    mkflow(&f, 0, 5, port++);
    CHECK_INT(xtreat_flow(&f, NULL, now), -1);
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
}

#else
void suite_treat(void);
void suite_treat(void) {}
#endif
