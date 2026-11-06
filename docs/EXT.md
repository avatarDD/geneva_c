# Расширения `--ext`

`geneva` — порт Geneva, и без `--ext` каждая команда ведёт себя как
раньше. Ключ `--ext` сразу после команды включает расширения, которых в
Geneva нет: они нужны для паритета с zapret2. План и порядок этапов —
`docs/EXT_ROADMAP.md`; здесь описано то, что уже сделано.

```
geneva censor --ext --list
geneva run --ext -s '...'
```

- Без `--ext` опции расширений — ошибка 2 (`--rate needs --ext`).
- `--help` каждой команды описывает расширения в разделе
  «Extensions (with --ext):» в конце справки.
- Сборка `make EXT=0` не содержит `src/ext/`: в ней `--ext` — ошибка 2,
  раздела расширений в справке нет.
- Сборка `make EXT_CRYPTO=0` — расширения без криптографии (меньше на
  роутере): QUIC не расшифровывается, цензора 16 нет, фичи `ext_crypto`
  нет.
- Интеграции узнают о расширениях по фичам `ext*` в
  `geneva version --json`.

## Что уже есть

| Этап | Что | Где описано |
|---|---|---|
| X0 | ключ `--ext`, сборка `EXT=0`, golden-снимки прежнего вывода | этот файл |
| X1 | контекст воркера движка и точка расширения (внутреннее, поведение прежнее) | `src/engine_int.h` |
| X2 | разбор TLS ClientHello и QUIC Initial (с расшифровкой), криптография; лабораторные цензоры 12–20 | `docs/CENSOR.md` |
| X3 | conntrack, позиции и диапазоны zapret2, триггеры `FLOW:` и `META:`, отсечка деревьев на поток | ниже |
| X4 | распознавание L7 как в zapret2, сборка ClientHello из нескольких пакетов, имя хоста, триггеры `L7:`, маркеры позиций | ниже |

## Conntrack и триггеры `FLOW:`, `META:` (X3)

С `--ext` движок (`run`, `eval`, `evolve`) и `apply` ведут таблицу потоков
так же, как nfqws2 (`nfq2/conntrack.c`), и стратегия может спрашивать о
положении пакета в потоке. Без `--ext` протоколов `FLOW` и `META` нет, как
в Geneva («unknown protocol»).

**Поток.** Ключ — адреса и порты в том виде, как их отправил клиент.
Клиент — сторона SYN (или получатель SYN+ACK, если он пришёл первым), для
UDP — сторона первой датаграммы. Новый поток открывают только SYN, SYN+ACK
и UDP. SYN на потоке, который прошёл стадию SYN, начинает поток заново (как
в zapret2, сам этот SYN тоже стирается), SYN+ACK с другим ISN — тоже.
ICMP-ошибки (unreachable, time exceeded, parameter problem, too big,
redirect) относятся к потоку вложенного пакета и ничего не считают.

**Счётчики стороны** (режимы диапазонов zapret2):

| Режим | Что |
|---|---|
| `n` | пакеты |
| `d` | пакеты с данными |
| `b` | байты данных, с ретрансмиссиями |
| `s` | относительный seq последнего пакета (TCP) |
| `p` | относительная позиция после его данных (TCP) |
| `a` / `x` | всегда / никогда |

После 2 ГБ `s` и `p` больше не считаются (как в zapret2): диапазон по ним
не совпадает и отсекается.

**Триггеры:**

```
[FLOW:n:1-3]        пакеты 1–3 этой стороны (то же, что n1-n3)
[FLOW:d:2]          ровно второй пакет с данными
[FLOW:b:<1000]      пока отправлено меньше 1000 байт (верхняя граница — отсечка)
[FLOW:p:p100-]      позиция от 100
[FLOW:rn:1-1]       то же по счётчикам другой стороны (rn rd rb rs rp)
[FLOW:state:est]    состояние TCP: syn, est, fin
[FLOW:retrans:1]    пакет повторяет уже отправленные данные (TCP)
[META:ifin:eth0]    интерфейс, на который пакет пришёл (Linux, NFQUEUE)
[META:ifout:ppp0]   интерфейс, через который уходит
[META:mark:0x10/0xf0]  метка firewall (N или N/MASK)
```

Диапазон записывается как `--in-range`/`--out-range` zapret2:
`n2-n5`, `d1<d3`, `-s100`, `<p1000`, `b10-`, `a`, `x`; голое число берёт
режим поля (`FLOW:n:1-5` — это `n1-n5`, `FLOW:d:5` — `d5-d5`).

**Отсечка (D7).** Если диапазон своей стороны уже позади (`n:1-3` на
четвёртом пакете), дерево отсекается на этом потоке и больше не
проверяется. Когда отсечены все деревья направления, пакеты потока в этом
направлении проходят мимо стратегии, как в nfqws2 после отсечки всех
инстансов. Диапазоны по другой стороне (`rn` и т.д.) не отсекают.

**Без потока** (conntrack выключен или пакет не отслеживается) триггер
`FLOW` совпадает только с диапазоном `a`, как в zapret2.

**`META`.** Метка и интерфейсы есть только у NFQUEUE (Linux). На Windows
(WinDivert) и в `apply` их нет, и `META` не совпадает; `META:mark:0` тоже
не совпадает, если метки нет. Метка zapret2 `0x40000000` (свои пакеты
nfqws2) не зарезервирована: geneva лишь предупредит о пересечении, когда
появятся действия, ставящие метку (решение 11.5).

**Опции:**

| Опция | Что |
|---|---|
| `--ext-ctrack-timeouts S:E:F[:U]` | таймауты в секундах: SYN, ESTABLISHED, FIN, UDP (60:300:60:60, как `--ctrack-timeouts` zapret2) |
| `--ext-ctrack-max N` | сколько потоков держит воркер (16384); при переполнении вытесняется давно молчащий |
| `--ext-ctrack-disable` | без conntrack: `FLOW` совпадает только с `a` |
| `apply --ext-posdebug` | на каждый пакет — строка `posdebug` zapret2 в stderr |

Отличие от zapret2: таблица ограничена `--ext-ctrack-max` (в zapret2
предела нет). Направление пакета (какая сторона «своя») берётся из самого
потока: это совпадает с nfqws2 в режиме клиента.

**Проверка паритета.** `geneva apply --ext --ext-posdebug` печатает те же
строки, что функция `posdebug` из `zapret-lib.lua` (без времени):

```
geneva apply --ext --ext-posdebug -s '\/' -i capture.pcap -p 80,443
posdebug: out direct n3 d1 b74 s1 p75 reverse n1 d0 b0 s1 p1 payload 74
```

В CI (`tests/e2e/censors_x.sh posdebug`) официальный nfqws2 с
`--lua-desync=posdebug` и tcpdump смотрят на одни и те же пакеты, и
счётчики geneva сравниваются со счётчиками nfqws2 по каждому направлению.

## L7: протокол, payload, имя хоста (X4)

С `--ext` каждый пакет TCP и UDP проходит то же распознавание, что в
nfqws2 (`nfq2/desync.c`, `protocol.c`): те же 16 протоколов, 31 тип
payload, те же проверки и тот же порядок. Стратегия спрашивает о нём
триггерами `L7:`.

**Триггеры:**

```
[L7:payload:tls_client_hello]   что несёт пакет (как --payload zapret2)
[L7:payload:~known]             "~" впереди отрицает весь список
[L7:proto:tls,quic]             протокол потока (как --filter-l7)
[L7:host:example.com]           имя хоста потока: сам домен и поддомены
[L7:host:*cdn.net,example.org]  "*" впереди — любое имя с таким концом
```

Списки — через запятую; `all`, `known`, `unknown`, `empty` значат то же,
что в zapret2. Протоколы: `http tls dtls quic wireguard dht discord stun
xmpp dns mtproto bt utp_bt`. Типы payload: `http_req http_reply
tls_client_hello tls_server_hello dtls_client_hello dtls_server_hello
quic_initial wireguard_initiation wireguard_response wireguard_cookie
wireguard_keepalive wireguard_data dht discord_ip_discovery stun
xmpp_stream xmpp_starttls xmpp_proceed xmpp_features dns_query
dns_response mtproto_initial bt_handshake utp_bt_handshake` и `empty`,
`unknown`. Имя хоста сравнивается без учёта регистра.

**Поток.** Протокол потока — первый распознанный и дальше не меняется.
Имя хоста берётся из HTTP `Host:`, SNI TLS ClientHello или ClientHello в
QUIC Initial (расшифровка, как в nfqws2) и тоже закрепляется за потоком:
`L7:host` совпадает и с пакетами после ClientHello. MTProto ищется только
в первом пакете клиента с данными (одно AES).

**Сборка ClientHello.** ClientHello с ML-KEM (Chrome, Firefox) не
помещается в один пакет, а SNI может оказаться во втором куске. Как
nfqws2, geneva собирает его:

- TCP: если ClientHello неполон, это не ретрансмиссия и окно сервера не
  меньше длины записи TLS, пакеты держатся, пока запись не соберётся
  (до `--ext-reasm-max`, 16384 байта). Затем каждый кусок проходит
  стратегию со всем ClientHello: `L7:host` срабатывает уже на первом
  куске. Перекрытия заменяют старые данные, дыра отменяет сборку.
- QUIC: Initial расшифровывается, фреймы CRYPTO собираются из нескольких
  Initial (Chrome перемешивает их по двум датаграммам), пока ClientHello
  не станет полным.
- Удерживается не больше 64 пакетов. Вердикт удержанного пакета ждёт, как
  у `sleep`: в NFQUEUE пакет остаётся в очереди ядра, на WinDivert —
  копия. В `stats` это счётчик `held`.

Отличия от nfqws2 (`docs/EXT_ROADMAP.md`, 3.4):

- Отменённая сборка (дыра, переполнение, не ClientHello, 65-й пакет)
  отпускает удержанные пакеты **через стратегию**, каждый со своим
  payload; nfqws2 отправляет их мимо стратегии («UNSOLVED»).
- Когда conntrack забывает поток со сборкой (таймаут, вытеснение, новый
  SYN) или движок останавливается, удержанные пакеты уходят как есть;
  nfqws2 их теряет.
- Маркеры позиций разбираются строго: `5x` или `host+` — ошибка, а не 5
  и `host` (в zapret2 `atoi`).

**Опции:**

| Опция | Что |
|---|---|
| `--ext-payload-disable LIST` | не распознавать эти типы payload (`all` — ничего), как `--payload-disable` |
| `--ext-reasm-disable LIST` | не собирать: `tls_client_hello`, `quic_initial` или `all`, как `--reasm-disable` |
| `--ext-reasm-max BYTES` | самый длинный собираемый ClientHello, 1024–65536 (16384) |

`apply --ext -v` показывает удержание и куски:

```
#4 out TCP ... len=1000 ... -> held
#6 out piece 1/2 TCP ... len=1000 ... -> 1 packet(s)
#6 out piece 2/2 TCP ... len=825 ... -> 1 packet(s)
```

**Маркеры позиций** (для действий этапа X5): `5`, `-1` (от конца),
`host`, `endhost`, `sld`, `midsld`, `endsld` (HTTP и TLS), `method` (HTTP,
с пропуском ведущих `\r\n`), `extlen`, `sniext` (TLS), со смещением
`+N`/`-N`; списки сортируются, повторы и ненайденные убираются.

**Проверка паритета.** `tests/data/l7_expected.txt` — то, что сам код
zapret2 (`nfq2/protocol.c` v1.0.7) говорит о каждом файле
`tests/data/zapret2/` (все `files/fake/*.bin`) и `tests/data/ext/`
(ClientHello Chromium с ML-KEM и curl, QUIC Initial Chromium, синтетика),
целиком и обрезанном: тип payload для клиента, сервера и UDP, имя хоста,
все маркеры, расшифровка и дефрагментация QUIC. Юнит-тест сравнивает
вывод geneva построчно. `tests/fuzz/l7_diff.sh ZAPRET2_DIR СЕКУНДЫ` —
дифференциальный фаззинг: мутации этих файлов идут в код zapret2 и в код
geneva, и вывод должен совпасть (перед выпуском этапа — час, под ASan).

## Код zapret2

Распознавание L7, маркеры, сборка и conntrack (`src/ext/l7.c`,
`markers.c`, `xl7.c`, `ctrack.c`) перенесены из zapret2
(https://github.com/bol-van/zapret2) и распространяются на условиях его
лицензии:

```
MIT License

Copyright (c) 2016-2026 bol-van

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
