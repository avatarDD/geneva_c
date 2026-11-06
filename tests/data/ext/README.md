# Client hellos captured for the tests

Captured by us against a local listener with the name `example.com`
(no third-party content):

- `tls_clienthello_curl_openssl3.bin` — curl 8.5.0, OpenSSL 3.0.13
  (X25519, no post-quantum key share), one 517-byte record;
- `tls_clienthello_chromium_mlkem.bin` — Chromium 153 (Playwright),
  X25519MLKEM768 key share, a 1825-byte record with the SNI at the end;
- `quic_chromium_0.bin` … `quic_chromium_3.bin` — the first four QUIC v1
  Initial datagrams of the same Chromium with `--origin-to-force-quic-on`:
  the ClientHello does not fit one Initial.

Firefox is not in the test environment; its hellos are covered by the
zapret2 files (`tests/data/zapret2`).

Made up for the probes (no capture):

- `mtproto_obfuscated2.bin` — an MTProto obfuscated2 header (random key
  and IV, bytes 56..59 decrypt to `EF EF EF EF`) and 41 random bytes;
- `http_*`, `xmpp_*`, `bt_handshake.bin`, `utp_bt_handshake.bin`,
  `dht_ping.bin`, `wireguard_*`, `dns_response.bin` — one message each.

`../l7_expected.txt` is what zapret2's own code (nfq2/protocol.c) says of
every file here and in `../zapret2`, whole and cut: see
`tests/fuzz/README.md`.

`frames_*.bin` are the decrypted frames of QUIC Initials (of the zapret2
files and of `quic_chromium_0.bin`): seeds for the fuzzing of the CRYPTO
defragmentation.
