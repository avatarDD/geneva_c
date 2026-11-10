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
| X5a | x-действия по функциям zapret2: `xfake`, `xsplit`, `xdisorder`, `xtcpseg`, `xhostfake`, `xfakedsplit`, `xfakeddisorder`, `xsend`, `xmod`; общие аргументы (fooling, ipfrag, repeats…), блобы, `tls_mod` | ниже |
| X5b | остальные функции zapret2: `xsynacksplit`, `xsynack`, `xwsize`, `xwssize`, `xsyndata`, `xrst`, `xhttp`, `xudplen`, `xdhtdn`, `xtlsclone`, `xtag`, `xlog`, `xpcap`; состояние пакета (блобы `xtlsclone`, метка `xtag`) | ниже |
| X5c | комбинаторы `xwhen`, `xstop`, `xrepeat`, `xcutoff` (оркестраторы zapret2) с условиями zapret2 и триггерными выражениями; обход цензоров 14, 15, 18–20 и сверка пакетов с nfqws2 в e2e | ниже |
| X6a | профили zapret2 (`--new`, `--name`, `--skip`, `--template`, `--import`), фильтры `--filter-l3/tcp/udp/icmp/ipp/l7/mark`, файл профилей `--ext-profile`, повторный поиск профиля по L7, перехват ICMP и других IP-протоколов | ниже |
| X6b | списки профилей: `--hostlist*` (имена хостов с поддоменами, `^`, `!`), `--ipset*` (подсети IPv4/IPv6), gzip, перечитывание по изменению файла, SIGHUP и `reload_lists`; повторный поиск профиля по имени хоста | ниже |

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

## x-действия (X5a)

С `--ext` в дереве Geneva можно писать действия, повторяющие функции
`lua/zapret-antidpi.lua` zapret2 с их параметрами и поведением. Без
`--ext` таких действий нет («unknown action»).

```
[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=3;md5}(xdisorder{pos=1,midsld},)-| \/
[TCP:flags:PA]-xhostfake{ttl=auto:-2:3-20;host=google.com}-| \/
[UDP:dport:443]-xfake{blob=fake_quic_initial;repeats=3;ip_ttl=4}-| \/
\/ [TCP:flags:SA]-xmod{ttl=5}-|
```

**Синтаксис.** `имя{ключ=значение;ключ;...}`: параметры через `;`,
флаг — ключ без значения, списки внутри значения — через `,` (запятая в
`{}` не делит поддеревья). Значение может начинаться с префикса, как в
`apply_arg_prefix` zapret2: `#имя` — длина блоба, `%имя` — его байты,
`\` — буквальные `#` или `%`. Ключи — имена дорожной карты (`ttl`, `seq`,
`md5`…) или zapret2 (`ip_ttl`, `tcp_seq`, `tcp_md5`, `tcp_flags_set`,
`tcp_ts_up`, `ip_id`…). У каждого x-действия одно поддерево: туда идёт
пакет, когда действие его пропускает (VERDICT_PASS) или «отбрасывает»
(VERDICT_DROP: пакет помечен и идёт дальше по дереву, как в цепочке
zapret2 следующие функции видят отброшенный пакет, но результатом не
становится). Пакеты, которые действие сделало (фейки, части), уходят
сразу, в порядке, в каком их сделал zapret2.

**Действия.**

| Действие | Функция zapret2 | Свои параметры |
|---|---|---|
| `xfake` | `fake` | `blob` (обязателен), `optional`, `tlsmod=rnd,rndsni,sni=ИМЯ,dupsid,padencap,none` (`sni=%блоб` тоже) |
| `xsplit` | `multisplit` | `pos` (`2`), `seqovl=N`, `seqovl_pattern`, `blob`, `optional`, `nodrop` |
| `xdisorder` | `multidisorder`, `multidisorder_legacy` | `pos` (`2`), `seqovl=маркер`, `seqovl_pattern`, `blob`, `optional`, `nodrop`, `legacy` |
| `xtcpseg` | `tcpseg` | `pos=от,до` (обязателен), `seqovl`, `seqovl_pattern`, `blob`, `optional` |
| `xhostfake` | `hostfakesplit` | `host=шаблон`, `midhost`, `nofake1`, `nofake2`, `disorder_after`, `blob`, `optional`, `nodrop` |
| `xfakedsplit` | `fakedsplit` | `pos` (`2`), `pattern`, `seqovl=N`, `seqovl_pattern`, `nofake1`…`nofake4`, `blob`, `optional`, `nodrop` |
| `xfakeddisorder` | `fakeddisorder` | то же, `seqovl=маркер` |
| `xsend` | `send` | `delay=мс` (0–3600000) |
| `xmod` | `pktmod` | — (только fooling и `ipid`; можно во входящем лесу) |

Позиции — маркеры X4 (`host`, `midsld`, `sniext+1`, `-1`…).

**Общие аргументы** («standard args» zapret2; у `xmod` только fooling и
`ipid`, у `xsend` всё, кроме `payload`, у `xhostfake`, `xfakedsplit`,
`xfakeddisorder` всё, кроме ipfrag):

| Аргумент | Что |
|---|---|
| `ttl=N` или `ttl=auto:Δ:MIN-MAX` | TTL/hop limit (IPv4 и IPv6); `auto` — autottl zapret2 по TTL ответа сервера (`ip_autottl=Δ,MIN-MAX`, `ip6_autottl`, `ip_ttl`, `ip6_ttl` — отдельно) |
| `seq=±N`, `ack=±N`, `ts=±N` | прибавить к seq, ack, TCP timestamp |
| `md5[=HEX16]` | опция TCP MD5 (19), случайная или заданная |
| `flags+=СПИСОК`, `flags-=СПИСОК` | поставить, снять флаги TCP (`FIN,SYN,RST,PSH,ACK,URG,ECE,CWR`) |
| `tsup`, `nopdel` | timestamp первой опцией; убрать NOP |
| `ip6ext=hopbyhop,hopbyhop2,destopt,destopt2,routing,ah` | заголовки расширения IPv6 (`:HEX` — свои данные, 6+8N или 6+4N байт для AH); `ip6_hopbyhop[=HEX]`… — то же по отдельности |
| `badsum` | испортить контрольную сумму L4 |
| `repeats=N` | каждый сделанный пакет N раз (1) |
| `fwmark=N`, `ifout=ИМЯ` | метка и интерфейс отправки (по умолчанию — метка и интерфейс исходного пакета) |
| `ipid=seq\|rnd\|zero\|none`, `ipid_conn` | IP ID: подряд от исходного (по умолчанию), случайный, ноль, как есть; `ipid_conn` — счётчик на поток |
| `ipfrag[=ipfrag2]`, `ipfrag_pos_tcp=32`, `ipfrag_pos_udp=8`, `ipfrag_pos_icmp=8`, `ipfrag_pos=32`, `ipfrag_disorder`, `ipfrag_next=N` | IP-фрагментация сделанных пакетов (`ipfrag2` zapret2; в IPv6 заголовок фрагмента после hop-by-hop, routing и первого destopt) |
| `payload=СПИСОК` | на каких payload действовать (по умолчанию `known`, у `xsend`/`xmod` — всегда) |

Части длиннее MSS потока (меньшее из MSS сторон, 1220 без conntrack)
минус IP- и TCP-опции уходят несколькими сегментами, URG — по сегменту
с указателем. На собранном ClientHello (X4) действие работает с целым
сообщением на первом куске, остальные куски отбрасываются, если сообщение
уже отправлено (`replay_drop` zapret2).

**Блобы.** Встроенные — свои, не из zapret2 (решение 11.3):

| Имя | Что |
|---|---|
| `fake_default_tls` | TLS 1.3 ClientHello для www.iana.org, 680 байт, с padding в конце (его растит `tlsmod=padencap`) |
| `fake_default_http` | `GET /` для www.iana.org |
| `fake_default_quic` | 620 байт: `0x40` и нули, как в zapret2 |
| `fake_quic_initial` | зашифрованный QUIC v1 Initial для www.iana.org, 1200 байт (только в сборке с криптографией) |

Свои — опцией `--ext-blob ИМЯ:0xHEX` (до 16 КБ) или
`--ext-blob ИМЯ:[+СМЕЩЕНИЕ]@ФАЙЛ` (до 1 МБ), повторяемой. Фейки BGP,
ISAKMP, RDP и Bitcoin из zapret2 лежат в `files/fake/` с лицензией MIT.
В параметре вместо имени можно написать байты: `blob=0x1603`.

**Отправка.** Сделанные пакеты идут через raw-сокет с меткой движка
(`--mark`) и меткой `fwmark`, `SO_PRIORITY 6` и `IP_FREEBIND` (Linux).
`--ext-bind-fix4`, `--ext-bind-fix6` — отправлять через интерфейс
исходного пакета (`SO_BINDTODEVICE`, как `--bind-fix4/6` nfqws2). Пакет,
на котором сработала стратегия, уходит вердиктом на своём месте среди
сделанных; если его отбросили, вердикт — drop, и все пакеты уходят
raw-сокетом. На Windows метки и интерфейса нет.

`apply --ext -v` показывает сделанные пакеты:

```
#10 out TCP ... len=45 ... GET / HTTP/1.1\x0d\x0aHost: Blocked.Example.ORG... -> 5 packet(s)
    -> TCP ... seq=501 len=22 ttl=64 GET / HTTP/1.1\x0d\x0aHost: 
    -> TCP ... seq=523 len=19 ttl=2 ge64wtg.example.net
    -> TCP ... seq=523 len=19 ttl=64 Blocked.Example.ORG
    -> TCP ... seq=523 len=19 ttl=2 ge64wtg.example.net
    -> TCP ... seq=542 len=4 ttl=64 \x0d\x0a\x0d\x0a
```

Отличия от zapret2 (`docs/EXT_ROADMAP.md`, 3.4):

- Нет `dir`: направление задаёт лес (`\/` делит исходящий и входящий).
  Во входящем лесу из x-действий можно только `xmod`; остальные там —
  ошибка разбора. Это и `xsend`, хотя `send` zapret2 по умолчанию
  работает в обе стороны: копий входящих пакетов движок не отправляет.
- Значения проверяются при разборе: неизвестный ключ, `ttl=300`,
  `md5=0x01`, плохой маркер, два одинаковых ключа (`ttl` и `ip_ttl` —
  разные ключи, `seq` и `tcp_seq` — один) — ошибка стратегии, а не
  ошибка Lua на первом пакете или молчаливый `nil`. Значения с префиксом
  `#`/`%` проверяются на пакете: плохое — действие пропускает пакет и
  пишет предупреждение.
- `xhostfake` не берёт `ipfrag`: в коде `hostfakesplit` v1.0.7 опции
  частей хоста задают пустой `ipfrag`, хотя комментарий обещает
  фрагментацию настоящего хоста.
- `tlsmod` работает только на TCP: на UDP у zapret2 нет `reasm_data`.

## x-действия (X5b)

Остальные функции `zapret-antidpi.lua`, `zapret-lib.lua` и
`zapret-pcap.lua`. Синтаксис, общие аргументы и отправка — как в X5a.

```
[TCP:flags:S]-xsyndata{blob=fake_default_tls;tlsmod=rnd}-| \/
[TCP:flags:PA]-xhttp{domcase;hostcase=hoSt}-| \/
[TCP:flags:PA]-xtlsclone{blob=c;sni_first=allowed.example}(xfake{blob=c;ttl=3},)-| \/
[TCP:flags:PA]-xtag{pattern=Blocked;payload=blk}(xfake{blob=fake_default_http;payload=blk;ttl=2},)-| \/
\/ [TCP:flags:SA]-xwsize{wsize=1;scale=6}-|
```

| Действие | Функция zapret2 | Свои параметры | Общие | Входящий лес |
|---|---|---|---|---|
| `xsynacksplit` | `synack_split` | `mode=syn\|synack\|acksyn` (`synack`) | `badsum`, `repeats`, `fwmark`, `ifout`, ipfrag | нет |
| `xsynack` | `synack` | — | то же | нет |
| `xwsize` | `wsize` | `wsize=N`, `scale=N` | — | да |
| `xwssize` | `wssize` | `wsize`, `scale`, `forced_cutoff=СПИСОК` | — | да |
| `xsyndata` | `syndata` | `blob` (16 нулей), `tlsmod` | fooling, `badsum`, `repeats`, `fwmark`, `ifout`, ipfrag | нет |
| `xrst` | `rst` | `rstack` | все | нет |
| `xhttp` | `http_domcase`, `http_hostcase`, `http_methodeol`, `http_unixeol` | флаги `domcase`, `methodeol`, `unixeol`, `hostcase[=ЧЕТЫРЕ]` (`host`) | — | да |
| `xudplen` | `udplen` | `min`, `max`, `increment` (2; меньше нуля — укоротить), `pattern`, `pattern_offset` | `payload` | да |
| `xdhtdn` | `dht_dn` | `dn=N` (3) | — | да |
| `xtlsclone` | `tls_client_hello_clone` | `blob` (обязателен), `fallback`, `sni_snt`, `sni_snt_new`, `sni_del_ext`, `sni_del`, `sni_first`, `sni_last` | — | да |
| `xtag` | `detect_payload_str` | `pattern` (обязателен), `payload=МЕТКА`, `undetected=МЕТКА` | — | да |
| `xlog` | `pass`, `pktdebug`, `posdebug` | `msg=ТЕКСТ`, флаги `pkt` (пакет), `pos` (строка posdebug), `hex` (payload, до 2048 байт) | — | да |
| `xpcap` | `pcap` | `file=ПУТЬ` (обязателен), `keep` | — | да |

**Что делают.** `xsynacksplit` на SYN,ACK шлёт вместо него SYN и ACK
(`synack`), только SYN (`syn`) или ACK и SYN (`acksyn`). `xsynack` перед
SYN шлёт его копию с ACK. `xwsize` на SYN,ACK ставит окно и уменьшает
(никогда не увеличивает) масштаб окна; `xwssize` делает то же со всеми
пакетами направления, пока не уйдёт первый payload (или payload из
`forced_cutoff`). `xsyndata` шлёт вместо SYN его копию с данными блоба.
`xrst` перед пакетом шлёт его копию без данных с RST (`rstack` — RST,ACK);
IP ID по умолчанию не меняет. `xhttp` правит HTTP-запрос: регистр имени
хоста через букву (`domcase`), написание заголовка `Host` (`hostcase`),
`\r\n` перед методом за счёт двух байт User-Agent (`methodeol`), `\n`
вместо `\r\n` с той же длиной за счёт пробелов в User-Agent (`unixeol`).
Несколько правок идут в порядке `domcase`, `hostcase`, `unixeol`,
`methodeol` («methodeol должен быть последним» в zapret2). `xudplen`
удлиняет UDP-payload шаблоном или укорачивает (не до нуля). `xdhtdn`
заменяет начало `d1:` DHT-сообщения на `dN:000…1:x`.

**Состояние пакета.** Как таблица `desync` у zapret2, оно живёт, пока пакет
идёт по всем деревьям леса. `xtlsclone` на ClientHello (собранном, если он
пришёл кусками) кладёт в блоб `blob` его изменённую копию: SNI-расширение
удаляется (`sni_del_ext`), список имён очищается (`sni_del`), у имён
меняется тип (`sni_snt`), имя добавляется в начало или в конец
(`sni_first`, `sni_last`, тип `sni_snt_new`, иначе 0); без SNI-расширения
оно добавляется первым. Если клонировать нечего, блобом становится
`fallback`. Этот блоб видят действия после `xtlsclone` в его поддереве и в
следующих деревьях — по имени (`blob=c`, `%c`, `#c`, `tlsmod=sni=%c`), раньше
встроенных и `--ext-blob`; у следующего пакета его нет. `xtag` ищет строку
`pattern` в payload (в собранном сообщении) и ставит метку `payload`, если
нашёл, или `undetected`, если нет; метку видят фильтры `payload=` следующих
действий (`known` — всё, кроме `unknown` и `empty`). Триггеры `L7:payload`
метку не видят: они смотрят на распознанный тип.

**Разбор и сборка TLS.** `xtlsclone` повторяет `tls_dissect` и
`tls_reconstruct` zapret2, с их особенностями: записи TLS собираются в
сообщения, сообщение после правки снова режется по прежним длинам записей
(последняя берёт остаток), расширения, которые zapret2 разбирает
(`server_name`, `alpn`, `supported_versions`, `supported_groups`,
`signature_algorithms`, `key_share`, `ec_point_formats`,
`psk_key_exchange_modes`, `compress_certificate`, `delegated_credentials`,
`quic_transport_parameters`), выходят в канонической форме: байты после
списка и нечётный байт списка пар пропадают, varint QUIC — кратчайшей
длины. Остальные расширения идут как есть.

**События и файлы.** `xlog` пишет строку лога (уровень info) и событие
`ext_pkt`: `msg`, `dir`, `tree`, `l7payload`, `len`, `piece`/`pieces`
у куска собранного сообщения, `pkt`, `pos`, `hex` по флагам. `xpcap`
дописывает пакет — каким он стал к этому месту дерева — в pcap того же
формата, что `pcap` zapret2 (big endian, наносекунды, `LINKTYPE_RAW`);
первый пакет экземпляра стратегии начинает файл заново, `keep` — дописывать
к прежнему. Путь берётся как есть (от текущего каталога движка).

Отличия от zapret2:

- `xsynacksplit`, `xsynack`, `xsyndata`, `xrst` шлют копии и потому, как
  `xsend`, только в исходящем лесу (`rst` у zapret2 по умолчанию в обе
  стороны). `xwsize` и правки пакета (`xhttp`, `xudplen`, `xdhtdn`,
  `xwssize`) можно и во входящем лесу.
- Отсечка экземпляра (`instance_cutoff`): у `xwsize`, `xwssize`, `xsynack`,
  `xsynacksplit`, `xsyndata` — на потоке, как в zapret2 (после неё действие
  пропускает пакеты потока как есть); у остальных отсечка лишь экономит
  время zapret2 и не нужна.
- `pass`, `pktdebug`, `argdebug`, `posdebug` — одно `xlog`; дамп всей
  таблицы `desync` и аргументов заменён полями события.
- `xpcap` пишет пакет в его состоянии в этом месте дерева, а не исходный
  пакет из очереди, и без `--writable` (путь как есть).
- `payload=` принимает любые имена (из букв, цифр и `_`), как строковый
  фильтр Lua: свои метки `xtag` должны проходить. Опечатка в имени тоже
  пройдёт разбор и просто не совпадёт.
- `xtlsclone` пишет varint QUIC в кратчайшей форме, как Lua 5.3+; LuaJIT
  оставляет большие значения как были.

## Комбинаторы (X5c)

Оркестраторы `zapret-auto.lua` как x-действия, которые ведут пакет по своим
поддеревьям. Вместо очереди экземпляров zapret2 (`execution plan`) —
поддеревья, вложенные комбинаторы — вложенные деревья.

```
[TCP:flags:PA]-xwhen{iff=L7:payload:tls_client_hello}(xsplit{pos=1},xsplit{pos=method+2})-| \/
[TCP:flags:PA]-xrepeat{repeats=2}(xfake{blob=fake_default_http;ttl=3},xsplit{pos=2})-| \/
[TCP:flags:PA]-xfake{blob=0x41;ttl=1}(xstop{iff=cond_payload_str;pattern=GET}(xsplit{pos=3},),)-| \/
[TCP:flags:PA]-xrepeat{repeats=3}(xrst{payload=all;badsum},xcutoff)-| \/
```

| Действие | Оркестратор zapret2 | Параметры | Поддеревья |
|---|---|---|---|
| `xwhen` | `condition`, `per_instance_condition` | `iff=УСЛОВИЕ` (обязателен), `neg` | (тогда, иначе) |
| `xstop` | `stopif` | `iff=УСЛОВИЕ` (обязателен), `neg` | (дальше) |
| `xrepeat` | `repeater` | `repeats=N` (0–100, обязателен), `iff` (`cond_true`), `neg`, `stop`, `clear` | (тело, остаток) |
| `xcutoff` | `instance_cutoff` | `dir=in\|out\|both` | (дальше) |

**Условия** (`iff`) — функции zapret2 и триггерные выражения:

| Условие | Истинно, когда |
|---|---|
| `cond_true`, `cond_false` | всегда, никогда |
| `cond_random` | с вероятностью `percent` % (50; `percent=0..100`), по `--rng-seed` |
| `cond_payload_str` | в payload пакета есть строка `pattern` (обязателен; `%блоб` — байты блоба) |
| `cond_tcp_has_ts` | у пакета TCP есть опция timestamp |
| `СЛОЙ:поле:значение` | пакет подходит под триггер: `TCP:flags:PA`, `IP:ttl:64`, `FLOW:n:<5`, `L7:payload:http_req`, `L7:host:example.com` |

`neg` обращает условие. Триггер в условии считается на текущем пакете —
таком, каким его сделали действия перед комбинатором; газа у него нет, и
диапазон `FLOW:` в условии никогда не отсекает дерево. `cond_lua` не
переносится (решение 11.1): нужные проверки — триггерные выражения.

**Что делают.** `xwhen` отдаёт пакет в левое поддерево, если условие
истинно, иначе в правое (без поддерева пакет — результат как есть).
`xstop` при истинном условии отдаёт пакет как есть, пропуская поддерево.
`xrepeat` до `repeats` раз прогоняет пакет через тело, проверяя условие
перед каждым повтором (ложно — выход из цикла); каждый повтор получает то,
что сделал из пакета предыдущий (zapret2 повторяет экземпляры на той же
таблице `desync`): свои пакеты тела (фейки, части) — результаты, из пакетов,
вышедших из исходного, дальше идёт последний, остальные — результаты. Потом
пакет идёт в остаток; `stop` или `clear` — остаток не выполняется. Тело,
поглотившее пакет (`drop`), заканчивает и остаток. `xcutoff` отсекает на
потоке своё дерево (без `dir`) или все деревья леса `in`, `out` или обоих
(`dir`): на следующих пакетах потока их триггеры не проверяются, а когда
отсечены все деревья леса, поток идёт мимо стратегии, как при отсечке
диапазоном `FLOW:` (X3). Текущий пакет идёт дальше в поддерево. На
собранном сообщении (ClientHello из нескольких сегментов) отсечка
наступает после его последнего куска: куски до него ещё проходят дерево,
и действия отбрасывают их как уже отправленные (`replay_drop`).

**Сверка с zapret2.** e2e `tests/e2e/censors_x.sh` (раздел `diff`, нужен
официальный zapret2: `NFQWS2_DIR`) запускает одну и ту же десинхронизацию
в nfqws2 и в geneva на одном запросе и сравнивает пакеты клиента на
проводе: позиции, длины, флаги, TTL, содержимое. Сверены `multisplit`
(TLS и HTTP), `multidisorder`, `fake` с fooling, `fakedsplit`,
`fakeddisorder`, `multisplit` с `seqovl`, `tcpseg`, `send:ipfrag` и `drop`,
`repeater`, `condition` (с `neg`), `stopif`. Раздел `xact` проходит x-действиями
цензоры 14, 15, 18, 19 и 20 стратегиями, эквивалентными эталонным строкам
nfqws2 (`docs/CENSOR.md`), и теми же с комбинаторами.

Отличия от zapret2:

- Имена параметров — как у zapret2 (`iff`, `neg`, `repeats`, `stop`,
  `clear`), а не `n=`/`until=` из наброска в `EXT_ROADMAP.md`; `instances`
  не нужен: сколько экземпляров зависит от условия, решает поддерево.
- `per_instance_condition` (`cond`/`cond_neg` у каждого экземпляра) — это
  `xwhen` перед каждым действием.
- `xstop` при ложном условии выполняет своё поддерево. `stopif` zapret2
  только забирает очередь для внешнего оркестратора: без него (первым в
  профиле) экземпляры после `stopif` не выполняются ни при каком условии.
  `xstop` ведёт себя как `stopif` внутри другого оркестратора — так его и
  используют.
- `stop` и `clear` у `xrepeat` одинаковы: внешней очереди, которую `clear`
  чистит в zapret2, у дерева нет — внешние комбинаторы решают сами.
- Флаги (`neg`, `stop`, `clear`) без значения; в Lua любая строка, даже
  `0`, — истина.
- Условие, которое нельзя вычислить (нет блоба из `pattern=%имя`), — как
  `error()` в zapret2: пакет уходит как есть, поддеревья не выполняются.
- `xcutoff` отсекает дерево, а не одно действие: экземпляр zapret2 и дерево
  geneva соответствуют друг другу, когда в дереве одна функция.

## Профили (X6a)

Несколько стратегий в одном процессе, каждая для своего трафика, как
профили nfqws2. Опции — с именами zapret2; работают в `run`, `apply` и
`fw` (там — для правил).

```
geneva run --ext \
  --filter-tcp 80 --filter-l7 http -s '[TCP:flags:PA]-xsplit{pos=method+2}-| \/' \
  --new=tls --filter-tcp 443 --filter-l7 tls -s '[TCP:flags:PA]-xdisorder{pos=1,midsld}-| \/' \
  --new=quic --filter-udp 443 --filter-l7 quic -f /opt/geneva/quic.txt
```

Опции до первого `--new` — профиль 1, и его стратегия — `-s`/`-f` самой
команды (её меняют `ctl` и SIGHUP). Каждый `--new[=ИМЯ]` начинает
следующий профиль со своими `-s`/`-f` и фильтрами. Общие опции команды
(`-p`, `--queue`, `--log-file`…) можно писать где угодно. Если до первого
`--new` нет ни стратегии, ни фильтра, это не профиль, а только опции
команды.

| Опция | Что |
|---|---|
| `--new[=ИМЯ]` | следующий профиль (с именем) |
| `--name ИМЯ` | имя профиля (в логе: «profile 2 (tls)») |
| `--skip` | профиль выбрасывается целиком |
| `--template[=ИМЯ]` | это шаблон, а не профиль |
| `--import ИМЯ` | взять у шаблона фильтры и стратегию |
| `--filter-l3 ipv4,ipv6` | версии IP |
| `--filter-tcp`, `--filter-udp` `[~]ПОРТ[-ПОРТ],...\|*` | порт сервера; `~` — все, кроме; `0` — ни одного |
| `--filter-icmp ТИП[:КОД],...\|*` | ICMP и ICMPv6 |
| `--filter-ipp ПРОТО,...\|*` | другие протоколы IP (47 — GRE, 50 — ESP…) |
| `--filter-l7 СПИСОК` | протокол потока: `tls`, `quic`, `http`, `known`, `unknown`… (как `L7:proto`) |
| `--filter-mark МЕТКА[/МАСКА]` | fwmark пакета (десятичная или `0x`; без маски — все 32 бита) |

**Поиск** — как `dp_match` zapret2: метка, версия IP, протокол L7, затем
порт (TCP, UDP), тип и код (ICMP) или протокол (прочие). Пакет берёт
первый подошедший профиль; не подошёл ни один — пакет проходит без
изменений. Профиль, где есть хоть один из фильтров `tcp`, `udp`, `icmp`,
`ipp`, не берёт протоколы, для которых фильтра нет; профиль без них берёт
всё. Отслеживаемый поток помнит свой профиль и ищет его снова, когда
становится известен протокол L7 (ClientHello, HTTP-запрос, QUIC Initial):
SYN порта 443 ещё не знает, что это TLS, и его берёт следующий подходящий
профиль. При смене профиля отсечки деревьев потока сбрасываются (они
относятся к стратегии). Сообщение, которое собирается из нескольких
пакетов, держится, если его может взять профиль со стратегией, когда
протокол станет известен. Связанный ICMP (ошибка о пакете потока) идёт с
профилем своего потока; ICMP без потока ищет профиль по типу и коду.

**Шаблоны.** `--template=ИМЯ` до следующего `--new` собирает шаблон; его
`--import ИМЯ` в профиле добавляет версии IP, дописывает списки портов,
ICMP и протоколов, заменяет L7 и метку и даёт стратегию, если своей у
профиля нет (своя `-s`/`-f` важнее, где бы ни стояла).

**Файл профилей** `--ext-profile ФАЙЛ` (можно несколько): профили файла
идут после профилей командной строки, в порядке файла.

```
# профили geneva
[template web]
filter-tcp = 80,443

[profile tls]
import    = web
filter-l7 = tls
strategy  = [TCP:flags:PA]-xdisorder{pos=1,midsld}-| \/

[profile quic]
filter-udp    = 443
filter-l7     = quic
strategy-file = /opt/geneva/quic.txt   # комментарий после пробела

[profile old]
skip
filter-tcp = 8080
```

Секции `[profile ИМЯ]` (имя необязательно) и `[template ИМЯ]`; ключи — те
же опции без `--` (`strategy` — это `-s`, `strategy-file` — `-f`), `skip`
можно без значения. Строки `#` и `;` — комментарии. Ошибка указывает
`файл:строка`.

**Перехват.** Без `-p` порты и протоколы для правил берутся из
`--filter-tcp`/`--filter-udp` профилей (если профиль берёт все порты —
`*`, `~` или без фильтра — нужен `-p`). ICMP и протоколы `--filter-ipp`
добавляются в правила (iptables, nft, фильтр WinDivert) всегда, в обе
стороны. `geneva fw print --ext ...` показывает эти правила. При старте
лог перечисляет профили.

Отличия от zapret2:

- Профиль 1 без стратегии и фильтров (только опции команды) не создаётся:
  в zapret2 он брал бы все пакеты и ничего не делал.
- Стратегия шаблона не дописывается к стратегии профиля (в zapret2
  функции шаблона добавляются к своим): стратегия geneva — одно целое,
  своя заменяет шаблонную.
- `--cookie` не переносится: он для Lua (решение 11.1).
- `--filter-ssid` — этап X13; списки — X6b (ниже), автосписок
  `--hostlist-auto` — X6c.
- `--filter-l7` без `~` (как в zapret2); `L7:proto:~...` — в триггерах.
- `--filter-mark` работает везде, где метку отдаёт перехват (NFQUEUE); у
  WinDivert метки нет, она 0.
- `--filter-ipp=*` в правила не превращается: нужно назвать протоколы или
  поставить свои правила (`--firewall none`).
- Порты в правилах общие для TCP и UDP (как у `-p`): лишние пакеты
  проходят мимо профилей без изменений.
- Стратегии профилей кроме первого читаются при старте; SIGHUP и
  `ctl` меняют стратегию профиля 1.
- `--new` и `--template` берут имя только через `=` (`--new=tls`), как
  необязательный аргумент getopt.

**Сверка с zapret2.** e2e `censors_x.sh` (раздел `diff`) сверяет два
профиля — HTTP на 80 и TLS на 443 — с теми же профилями nfqws2 на двух
запросах подряд: пакеты на проводе одинаковы. `run.sh` проверяет смену
профиля по L7 на живом трафике.

## Списки (X6b)

Профиль может брать трафик только для имён хостов из списка и только для
адресов серверов из набора подсетей — опции и форматы zapret2:

```
geneva run --ext \
  --filter-tcp 443 --filter-l7 tls --hostlist /opt/geneva/lists/blocked.txt.gz \
    --hostlist-exclude-domains ok.example -s '[TCP:flags:PA]-xdisorder{pos=1,midsld}-| \/' \
  --new=ip --filter-tcp 80,443 --ipset /opt/geneva/lists/ips.txt -s '[TCP:flags:PA]-xsplit{pos=2}-| \/'
```

| Опция (повторяемая) | Что |
|---|---|
| `--hostlist ФАЙЛ` | профиль берёт хосты из файла и их поддомены |
| `--hostlist-domains ИМЯ,...` | то же для имён в самой опции |
| `--hostlist-exclude ФАЙЛ`, `--hostlist-exclude-domains ИМЯ,...` | профиль не берёт эти хосты |
| `--ipset ФАЙЛ` | профиль берёт серверы из файла (адреса и подсети IPv4/IPv6) |
| `--ipset-ip CIDR,...` | то же для подсетей в самой опции |
| `--ipset-exclude ФАЙЛ`, `--ipset-exclude-ip CIDR,...` | профиль не берёт эти серверы |

В файле профилей — те же ключи без `--` (`hostlist = /путь`).

**Формат файлов** — как в zapret2: по одному имени или подсети в строке,
ведущие пробелы и табуляции пропускаются, строки на `#`, `;`, `/` и пустые
— комментарии, всё после имени через пробел игнорируется. Имена
приводятся к нижнему регистру. Перед именем — флаги: `^имя` — только само
имя, без поддоменов; `!имя` — исключение: имя и его поддомены в список не
входят. Файл в gzip распознаётся по сигнатуре `1f 8b` и
распаковывается своим inflate (без zlib, до 1 ГБ текста); обычный файл
читается кусками, без копии целиком в памяти. Неверные
адреса пропускаются с предупреждением в логе.

**Проверка** идёт в порядке `dp_match` zapret2 после фильтров L3, L4 и L7:
профиль со списками хостов берёт пакет, только когда имя хоста известно
(SNI, Host, QUIC); тогда сначала списки исключений, затем включений.
Наборы IP проверяют адрес сервера: исключения, затем включения. Если все
списки включений профиля пусты (например, пустой файл), проверка
проходит. Имя ищется вместе с родителями: `www.a.example` → `a.example`
→ `example`; первая найденная запись решает. Имя-адрес (`Host:
1.2.3.4:80`, `[::1]`) ищется только целиком, порт отбрасывается. Поток
ищет профиль заново, когда узнаёт имя хоста (как и протокол L7): SYN без
имени берёт следующий подходящий профиль, ClientHello с именем из списка
переводит поток в профиль со списком. Сообщение, которое собирается из
нескольких пакетов, держится, если профиль со списками может взять поток,
когда имя станет известно.

**Перечитывание.** Файл, указанный в нескольких профилях, загружается
один раз. Раз в секунду (по первому пакету после неё) проверяются время
изменения и размер файлов; изменившийся файл перечитывается. SIGHUP и
команда управления `reload_lists` перечитывают все файлы сразу. Файл,
который нельзя открыть, оставляет загруженное; файл, который не удалось
разобрать (битый gzip), опустошает список, и профили с ним ничего не берут,
пока он не загрузится (как в zapret2).

Отличия от zapret2:

- zapret2 проверяет время файла на каждом пакете; geneva — не чаще раза в
  секунду (изменение замечается с задержкой до секунды).
- Загрузка синхронная (как в zapret2), в потоке обработки пакетов: пока
  читается большой список, пакеты ждут.
- Подсеть с мусором после длины (`1.2.3.4/8x`) — ошибка; zapret2 читает
  длину через `sscanf` и мусор не замечает.
- ICMP без потока проверяется по адресу сервера самого пакета (zapret2 —
  ещё и по адресу вложенного пакета).
- `--hostlist-auto` и кэш имён из DNS (`ipcache`) — этап X6c.

Распаковка (`src/ext/inflate.c`) сделана по puff Марка Адлера (zlib,
`contrib/puff`, лицензия zlib; уведомление — в начале файла). Фича
`ext_lists` в `geneva version --json`.

**Сверка с zapret2.** e2e `censors_x.sh` (раздел `diff`, случай `lists`)
сверяет профиль TLS со списком хостов (родительский домен и исключение) и
профиль HTTP с набором подсетей с теми же профилями nfqws2 на трёх
запросах: пакеты на проводе одинаковы. `run.sh` проверяет смену профиля
по списку из gzip и его перечитывание по SIGHUP.

## Код zapret2

Распознавание L7, маркеры, сборка, conntrack и x-действия
(`src/ext/l7.c`, `markers.c`, `xl7.c`, `ctrack.c`, `xact.c`, `xact_tcp.c`,
`xact_http.c`, `xact_misc.c`, `xact_comb.c`, `profile.c`, `hostlist.c`, `ipset.c`, `lists.c`, `tls.c` — `tls_mod`, `genhost`, `tls_clone.c`) перенесены из zapret2
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
