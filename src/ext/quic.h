/*
 * QUIC Initial packets of a client (RFC 9000 17.2.2, RFC 9001 5, RFC 9369):
 * header parsing, removal of the Initial protection and the CRYPTO stream.
 * Versions: those zapret2 knows (l7_quic_draft): 1, 2, drafts 11-34, mvfst, Q050, T05x. Pure functions over caller buffers,
 * no allocation; every length from the network is checked.
 */
#ifndef GENEVA_EXT_QUIC_H
#define GENEVA_EXT_QUIC_H

#include <stddef.h>
#include <stdint.h>

#define QUIC_V1 0x00000001u
#define QUIC_V2 0x6b3343cfu

typedef struct {
    uint32_t version;
    uint8_t dcid[20], scid[20];
    uint8_t dcid_len, scid_len;
    size_t pn_off;   /* where the (protected) packet number starts */
    size_t pkt_len;  /* bytes of this packet in the datagram (coalesced ones follow) */
    uint64_t pn;     /* after decryption */
} quic_initial;

/* RFC 9000 16: a variable-length integer at *off, advanced. Returns 0 or
 * -1 when it does not fit. */
int quic_varint(const uint8_t *p, size_t n, size_t *off, uint64_t *v);

/* 1 when the datagram starts with a long header Initial of a known version
 * (no decryption), filling h; 0 otherwise. */
int quic_is_initial(const uint8_t *p, size_t n, quic_initial *h);

/* Removes the client Initial protection: the plaintext frames go to out
 * (cap >= the packet's payload). Returns their length, or -1 when the packet
 * is not a client Initial of a known version or does not authenticate. */
long quic_initial_decrypt(const uint8_t *p, size_t n, quic_initial *h, uint8_t *out, size_t cap);

/* The CRYPTO frames of decrypted Initial frames as one stream: bytes
 * [0, *len) land in out (cap bytes), in offset order; *len stops at the
 * first gap. Returns 0, or -1 for malformed frames. PADDING, PING, ACK
 * and CONNECTION_CLOSE are skipped. */
int quic_crypto_stream(const uint8_t *f, size_t n, uint8_t *out, size_t cap, size_t *len);

#endif
