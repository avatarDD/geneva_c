/* zapret2's nfq2/protocol.c over buffers, in the line format of
 * tests/fuzz/l7_line.c (built by tests/fuzz/l7_diff.sh against a zapret2
 * tree; MIT code of bol-van, see docs/EXT.md). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "protocol.h"
#include "crypto/aes.h"

typedef bool (*chk)(const uint8_t *, size_t);
typedef struct { int l7p; chk f; int l7match; int l7; } tst;
static int probe(const tst *t, int n, const uint8_t *d, size_t len)
{
    for (int i = 0; i < n; i++)
        if (!t[i].l7match && t[i].f(d, len)) return t[i].l7p;
    return L7P_UNKNOWN;
}
static const char *mk[] = {"5", "-1", "host", "host+1", "endhost", "endhost-1", "sld", "midsld", "endsld", "endsld+2",
                           "method", "method+2", "extlen", "sniext", "sniext+1", "0", "-200", NULL};
void line(const uint8_t *d, size_t n)
{
    tst tc[] = {{L7P_TLS_CLIENT_HELLO, IsTLSClientHelloPartial}, {L7P_HTTP_REQ, IsHttp}, {L7P_XMPP_STREAM, IsXMPPStream},
                {L7P_XMPP_STARTTLS, IsXMPPStartTLS}, {L7P_BT_HANDSHAKE, IsBTHandshake}};
    tst ts[] = {{L7P_TLS_SERVER_HELLO, IsTLSServerHelloPartial}, {L7P_HTTP_REPLY, IsHttpReply},
                {L7P_XMPP_STREAM, IsXMPPStream}, {L7P_XMPP_PROCEED, IsXMPPProceedTLS},
                {L7P_XMPP_FEATURES, IsXMPPFeatures}, {L7P_BT_HANDSHAKE, IsBTHandshake}};
    tst tu[] = {{L7P_QUIC_INITIAL, IsQUICInitial}, {L7P_DISCORD_IP_DISCOVERY, IsDiscordIpDiscoveryRequest},
                {L7P_STUN, IsStunMessage}, {L7P_DNS_QUERY, IsDNSQuery}, {L7P_DNS_RESPONSE, IsDNSResponse},
                {L7P_DHT, IsDht}, {L7P_DTLS_CLIENT_HELLO, IsDTLSClientHello}, {L7P_DTLS_SERVER_HELLO, IsDTLSServerHello},
                {L7P_UTP_BT_HANDSHAKE, IsUTP_BTHandshake}, {L7P_WIREGUARD_INITIATION, IsWireguardHandshakeInitiation},
                {L7P_WIREGUARD_RESPONSE, IsWireguardHandshakeResponse}, {L7P_WIREGUARD_COOKIE, IsWireguardHandshakeCookie},
                {L7P_WIREGUARD_KEEPALIVE, IsWireguardKeepalive}, {L7P_WIREGUARD_DATA, IsWireguardData, 1}};
    char h[256];
    int c = n ? probe(tc, 5, d, n) : L7P_EMPTY;
    if (c == L7P_UNKNOWN && IsMTProto(d, n)) c = L7P_MTPROTO_INITIAL;
    printf("tcp_client=%s", l7payload_str(c));
    printf(" tcp_server=%s", l7payload_str(n ? probe(ts, 6, d, n) : L7P_EMPTY));
    printf(" udp=%s", l7payload_str(n ? probe(tu, 14, d, n) : L7P_EMPTY));
    printf(" wg_data=%d", n ? IsWireguardData(d, n) : 0);
    printf(" tls_host=%s", n && TLSHelloExtractHost(d, n, h, sizeof(h), true) ? h : "-");
    printf(" tls_host_full=%s", n && TLSHelloExtractHost(d, n, h, sizeof(h), false) ? h : "-");
    printf(" http_host=%s", n && HttpExtractHost(d, n, h, sizeof(h)) ? h : "-");
    printf(" hs_host=%s", n && TLSHelloExtractHostFromHandshake(d, n, h, sizeof(h), true) ? h : "-");
    if (n >= 5) printf(" reclen=%zu full=%d", TLSRecordLen(d), IsTLSRecordFull(d, n));
    for (int k = 0; k < 3; k++) {
        int l7p = k == 0 ? L7P_TLS_CLIENT_HELLO : k == 1 ? L7P_HTTP_REQ : L7P_UNKNOWN;
        printf(" %s:", l7payload_str(l7p));
        for (int i = 0; mk[i]; i++) {
            struct proto_pos m;
            if (!posmarker_parse(mk[i], &m)) { printf(" %s=BAD", mk[i]); continue; }
            printf(" %s=%zd", mk[i], ResolvePos(d, n, l7p, &m));
        }
    }
    {
        uint8_t clean[16384], defrag[16384];
        size_t cl = sizeof(clean), dl = sizeof(defrag), ho, hl;
        bool full;
        if (n && QUICDecryptInitial(d, n, clean, &cl)) {
            printf(" quic_dec=%zu", cl);
            if (QUICDefragCrypto(clean, cl, defrag, &dl, &full)) {
                printf(" defrag=%zu full=%d", dl, full);
                if (full && IsQUICCryptoHello(defrag, dl, &ho, &hl))
                    printf(" hello=%zu,%zu hsfull=%d host=%s", ho, hl, IsTLSHandshakeFull(defrag + ho, hl),
                           TLSHelloExtractHostFromHandshake(defrag + ho, hl, h, sizeof(h), true) ? h : "-");
            } else printf(" defrag=-");
        } else printf(" quic_dec=-");
    }
    {
        /* the buffer as decrypted Initial frames */
        static uint8_t defrag[16384];
        size_t dl = sizeof(defrag), ho, hl;
        bool full;
        if (QUICDefragCrypto(d, n, defrag, &dl, &full)) {
            printf(" rawdefrag=%zu full=%d", dl, full);
            if (IsQUICCryptoHello(defrag, dl, &ho, &hl))
                printf(" hello=%zu,%zu", ho, hl);
        } else printf(" rawdefrag=-");
    }
    printf("\n");
}
int main(int argc, char **argv)
{
    static uint8_t b[70000];
    aes_init_keygen_tables();
    for (int i = 1; i < argc; i++) {
        char path[512], *at;
        FILE *f;
        size_t n, cut = 0;
        snprintf(path, sizeof(path), "%s", argv[i]);
        if ((at = strchr(path, '@'))) *at = 0, cut = (size_t)atoi(at + 1);
        f = fopen(path, "rb");
        if (!f) return 1;
        n = fread(b, 1, sizeof(b), f);
        fclose(f);
        if (at && cut < n) n = cut;
        { const char *s = strrchr(argv[i], '/'); printf("%s ", s ? s + 1 : argv[i]); }
        line(b, n);
    }
    return 0;
}
