# Фейки из zapret2

Четыре файла из `files/fake/` zapret2 (https://github.com/bol-van/zapret2,
коммит `038c97e` = v1.0.7, лицензия MIT, см. `LICENSE`): то, что сложно
синтезировать самим (решение 11.3 в `docs/EXT_ROADMAP.md`).

| Файл | Что это |
|---|---|
| `bgp_open.bin` | сообщение BGP OPEN |
| `bitcoin.bin` | сообщение version протокола Bitcoin |
| `isakmp_initiator_request.bin` | первый пакет ISAKMP (IKE) инициатора |
| `rdp.bin` | запрос соединения RDP (X.224) |

В бинарник они не встроены. Подключаются опцией `--ext-blob`:

    geneva run --ext --ext-blob rdp:@/opt/geneva/fake/rdp.bin \
        -s '[TCP:dport:3389]-xfake{blob=rdp;ttl=3;payload=all}-| \/' ...

Встроенные `fake_default_tls`, `fake_default_http`, `fake_default_quic` и
`fake_quic_initial` geneva собирает сама (`src/ext/blob.c`).

---

Four files from zapret2's `files/fake/` (commit `038c97e` = v1.0.7, MIT, see
`LICENSE`): the payloads that are hard to synthesize. Not built in; load
them with `--ext-blob NAME:@FILE`.
