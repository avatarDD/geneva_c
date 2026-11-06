/*
 * What geneva's L7 code says of one buffer, in the line format of
 * tests/fuzz/zapret2_ref.c (zapret2's code over the same buffer):
 * tests/test_l7.c compares the two over tests/data, tests/fuzz/l7_diff.sh
 * over mutated inputs. Included by tests/test_l7.c; with L7_LINE_MAIN it
 * is a program taking file paths ("path@N": the first N bytes).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ext/ext.h"
#include "ext/l7.h"
#include "ext/markers.h"
#include "ext/quic.h"
#include "util.h"

static const char *const l7_line_markers[] = {"5", "-1", "host", "host+1", "endhost", "endhost-1", "sld",
                                              "midsld", "endsld", "endsld+2", "method", "method+2", "extlen",
                                              "sniext", "sniext+1", "0", "-200", NULL};

static void l7_line(const uint8_t *d, size_t n, sbuf *o)
{
    char h[256];
    int l7 = L7_UNKNOWN;
    uint64_t only_wg = ~((1ULL << L7P_WIREGUARD_DATA) | (1ULL << L7P_KNOWN) | 1ULL);
    sb_printf(o, "tcp_client=%s", l7_payload_name(l7_probe(d, n, 1, 0, 1, 0, &l7)));
    l7 = L7_UNKNOWN;
    sb_printf(o, " tcp_server=%s", l7_payload_name(l7_probe(d, n, 1, 1, 0, 0, &l7)));
    l7 = L7_UNKNOWN;
    sb_printf(o, " udp=%s", l7_payload_name(l7_probe(d, n, 0, 0, 0, 0, &l7)));
    l7 = L7_WIREGUARD;
    sb_printf(o, " wg_data=%d", n && l7_probe(d, n, 0, 0, 0, only_wg, &l7) == L7P_WIREGUARD_DATA);
    sb_printf(o, " tls_host=%s", n && l7_tls_host(d, n, h, sizeof(h), 1) ? h : "-");
    sb_printf(o, " tls_host_full=%s", n && l7_tls_host(d, n, h, sizeof(h), 0) ? h : "-");
    sb_printf(o, " http_host=%s", n && l7_http_host(d, n, h, sizeof(h)) ? h : "-");
    sb_printf(o, " hs_host=%s", n && l7_tls_hs_host(d, n, h, sizeof(h), 1) ? h : "-");
    if (n >= 5)
        sb_printf(o, " reclen=%zu full=%d", l7_tls_record_len(d), l7_tls_record_len(d) <= n);
    for (int k = 0; k < 3; k++) {
        int l7p = k == 0 ? L7P_TLS_CLIENT_HELLO : k == 1 ? L7P_HTTP_REQ : L7P_UNKNOWN;
        sb_printf(o, " %s:", l7_payload_name(l7p));
        for (int i = 0; l7_line_markers[i]; i++) {
            xmarker m;
            if (xmarker_parse(l7_line_markers[i], &m) < 0)
                sb_printf(o, " %s=BAD", l7_line_markers[i]);
            else
                sb_printf(o, " %s=%ld", l7_line_markers[i], xmarker_resolve(d, n, l7p, &m));
        }
    }
    {
        static uint8_t clean[16384], defrag[16384];
        size_t dl = sizeof(defrag), ho, hl;
        int full;
        quic_initial qh;
        long cl = n ? quic_initial_decrypt(d, n, &qh, clean, sizeof(clean)) : -1;
        if (cl >= 0) {
            sb_printf(o, " quic_dec=%ld", cl);
            if (l7_quic_defrag(clean, (size_t)cl, defrag, &dl, &full)) {
                sb_printf(o, " defrag=%zu full=%d", dl, full);
                if (full && l7_quic_crypto_hello(defrag, dl, &ho, &hl))
                    sb_printf(o, " hello=%zu,%zu hsfull=%d host=%s", ho, hl,
                              hl >= 4 && l7_tls_hs_len(defrag + ho) <= hl,
                              l7_tls_hs_host(defrag + ho, hl, h, sizeof(h), 1) ? h : "-");
            } else {
                sb_puts(o, " defrag=-");
            }
        } else {
            sb_puts(o, " quic_dec=-");
        }
        /* the buffer as decrypted Initial frames */
        dl = sizeof(defrag);
        if (l7_quic_defrag(d, n, defrag, &dl, &full)) {
            sb_printf(o, " rawdefrag=%zu full=%d", dl, full);
            if (l7_quic_crypto_hello(defrag, dl, &ho, &hl))
                sb_printf(o, " hello=%zu,%zu", ho, hl);
        } else {
            sb_puts(o, " rawdefrag=-");
        }
    }
}

#ifdef L7_LINE_MAIN
int main(int argc, char **argv)
{
    sbuf o;
    sb_init(&o);
    for (int i = 1; i < argc; i++) {
        char path[512], *at;
        size_t n, cut = 0;
        uint8_t *b;
        const char *s = strrchr(argv[i], '/');
        snprintf(path, sizeof(path), "%s", argv[i]);
        if ((at = strchr(path, '@')))
            *at = 0, cut = (size_t)atoi(at + 1);
        b = (uint8_t *)read_file(path, &n);
        if (!b)
            return 1;
        if (at && cut < n)
            n = cut;
        sb_reset(&o);
        l7_line(b, n, &o);
        printf("%s %s\n", s ? s + 1 : argv[i], o.data);
        free(b);
    }
    sb_free(&o);
    return 0;
}
#endif
