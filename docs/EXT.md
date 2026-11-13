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
| X6c | автосписок `--hostlist-auto*` (неудачи TCP и UDP, RST клиенту, журнал решений), кэш адресов `ipcache`: имена из DNS-ответов и потоков, TTL первого ответа сервера для autottl | ниже |
| X7a | эксплуатация: опции из файла `@FILE`, `--comment`, `--dry-run`, `--daemon`, `--pidfile`, `--user`/`--uid` (сброс root), seccomp, `sd_notify`, syslog, команды `ext_flows` и `ext_keys`, предупреждение о метке | ниже |
| X7b | правила firewall как у zapret2: `--ext-first` по протоколам и направлениям, `--ext-wan`/`--ext-lan`, `--ext-notrack frag` (predefrag), `--ext-ttl-icmp`, `--ext-flowoffload`, хуки `--fw-hook-pre/post`; фильтр WinDivert winws2 `--wf-*` | ниже |
| X7c | фаззинг: цели для каждого разборщика (пакеты, pcap, стратегии с x-действиями, JSON, L7, TLS, QUIC, gzip, списки, профили, значения опций), `geneva selftest --ext --fuzz N`, libFuzzer и AFL++ (`tests/fuzz/run.sh`) | ниже |
| X8 | seqtrack: `xoob` (байт OOB, функция `oob` zapret2), `xtlsrec` (запись TLS разрезана на две), сдвиг нумерации на SYN, ответные ack и SACK, повтор первого сообщения при потерях; `xdrip` (первые байты по одному с паузой) | ниже |
| X9a | наблюдение `--ext-auto observe`: первые пакеты каждого потока через NFLOG, детектор блокировок (классы zapret2 `RETRANS`, `RST_IN`, `REDIRECT`, `UDP_NOANSWER` и свои `RST_INJECT`, `BLACKHOLE_SYN`, `ICMP_PROHIBIT`), ключи порт → сеть → адрес → имя с тестом Вальда, события `ext_flow`, `ext_impaired`, `ext_class`, команда `ext_status` | ниже |
| X9b | счётчики потоков через ctnetlink раз в секунду, классы `FREEZE_N`, `THROTTLE`, `DNS_POISON`, строгий успех заблокированного ключа, событие `ext_link` (`LINK_DEGRADED`) | ниже |
| X9c | `--ext-auto observe` на Windows (SNIFF-хэндл WinDivert, детектор сам считает байты), `THROTTLE` не ставится при такой же полке у параллельного потока к другой сети, синтетика без цензора на 30 минут | ниже |
| X10a | многоочередной движок `--ext-workers N\|auto` (Linux): поток, очередь NFQUEUE и raw-сокет на воркер, правила раскладывают потоки по очередям | ниже |
| X10b | хирургический путь (Linux): соединение, с которым движок закончил, получает метку в conntrack и дальше идёт мимо очереди; политика ключей снапшотами с QSBR | ниже |
| X11a | автотюнер: руки профиля `--ext-arm`, селектор `rr` (семантика `circular` zapret2), `--ext-state` | ниже |
| X11b | селектор `ts` (Thompson sampling), согласие `propose`, команды `ext_approve`, `ext_reject`, `ext_proposals` | ниже |
| X11c | лечение `--ext-auto propose\|apply`: портфель рук по классу блокировки, Thompson sampling по соединениям ключа, CUSUM, `UNTREATABLE` с перепроверкой | ниже |
| X11d | лечение `FREEZE_N` и `THROTTLE` (строгий успех), генетический поиск `--ext-ga` для ключей без рабочей руки, `--ext-treat-arms` | ниже |
| X12a | `geneva resolve` (mdig zapret2) и `geneva ip2net` (ip2net zapret2) | ниже |
| X12b | `geneva blockcheck`: `blockcheck2.sh` zapret2 со всей сеткой `blockcheck2.d/standard`, строки nfqws2 переведены в стратегии geneva; уровни, повторы, отчёт SUMMARY/COMMON/COVERAGE | ниже |
| X13a | двусторонняя обфускация `zapret-obfs.lua`: `xwgobfs`, `xippxor`, `xudp2icmp`, `xsynhide` | ниже |
| X12c | `geneva blockcheck`: проверка DNS (системный резолвер против публичных DNS, UDP против TCP), DoH через curl при подмене, тесты блокировки по порту и по IP | ниже |

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
- На NFQUEUE удержанный пакет сразу получает DROP, а его копия потом
  отправляется заново сырым сокетом (с меткой обхода), как в nfqws2:
  пока ядро ждёт вердикт, буфер сокета занят и TCP small queues не
  выпускают следующий сегмент клиента — сборка стоит до таймаута. На
  WinDivert и для входящих пакетов (`--server-side`) пакет удерживается
  как раньше.
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
- `--filter-ssid` — этап X13; списки — X6b, автосписок
  `--hostlist-auto` — X6c (ниже).
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
- `--hostlist-auto` и кэш имён из DNS (`ipcache`) — этап X6c (ниже).

Распаковка (`src/ext/inflate.c`) сделана по puff Марка Адлера (zlib,
`contrib/puff`, лицензия zlib; уведомление — в начале файла). Фича
`ext_lists` в `geneva version --json`.

**Сверка с zapret2.** e2e `censors_x.sh` (раздел `diff`, случай `lists`)
сверяет профиль TLS со списком хостов (родительский домен и исключение) и
профиль HTTP с набором подсетей с теми же профилями nfqws2 на трёх
запросах: пакеты на проводе одинаковы. `run.sh` проверяет смену профиля
по списку из gzip и его перечитывание по SIGHUP.

## Автосписок и кэш адресов (X6c)

Автосписок собирает сам те хосты, которые без обхода не открываются, —
как `--hostlist-auto` zapret2. Профиль с автосписком смотрит за потоками
к хостам, которых в его списках ещё нет, и после нескольких неудач
дописывает хост в файл; дальше стратегия профиля работает для него:

```
geneva run --ext \
  --filter-tcp 80,443 --filter-l7 http,tls --hostlist /opt/geneva/lists/blocked.txt \
    --hostlist-auto /opt/geneva/lists/auto.txt --hostlist-auto-debug /tmp/auto.log \
    -s '[TCP:flags:PA]-xdisorder{pos=1,midsld}-| \/'
```

| Опция профиля | По умолчанию | Что |
|---|---|---|
| `--hostlist-auto ФАЙЛ` | — | автосписок: файл создаётся, если его нет; он же — `--hostlist` профиля; один на профиль |
| `--hostlist-auto-fail-threshold N` | 3 (1–20) | столько неудач добавляют хост… |
| `--hostlist-auto-fail-time СЕК` | 60 | …за столько секунд с первой |
| `--hostlist-auto-retrans-threshold N` | 3 (2–10) | TCP: столько повторов запроса клиента — неудача |
| `--hostlist-auto-retrans-maxseq БАЙТ` | 32768 | повторы считаются в первых БАЙТ клиента; дальше — сайт работает |
| `--hostlist-auto-retrans-reset[=0\|1]` | 1 | после неудачи по повторам послать клиенту RST, чтобы он не ждал |
| `--hostlist-auto-incoming-maxseq БАЙТ` | 4096 | TCP: RST сервера или HTTP-редирект на другой домен в первых БАЙТ ответа — неудача, данные дальше — успех (0 — не смотреть) |
| `--hostlist-auto-udp-out N` | 4 | UDP: N пакетов клиента при не более `udp-in` ответах — неудача (0 — не смотреть) |
| `--hostlist-auto-udp-in N` | 1 | больше N ответов — успех |

Общие опции (для всех профилей): `--hostlist-auto-debug ФАЙЛ` — журнал
решений в формате zapret2 (`дд.мм.гггг чч:мм:сс : хост : profile N (имя)
: client адрес:порт : proto tls : ...`); `--ext-ipcache-hostname[=0|1]` —
кэшировать имена хостов по адресам; `--ext-ipcache-lifetime СЕК` — время
жизни записи кэша (7200, 0 — вечно). В файле профилей — те же ключи без
`--`; `--import` копирует автосписок шаблона и заданные в нём параметры.

**Как работает** (порядок zapret2, `desync.c`). Профиль с автосписком
берёт поток, как только известно имя хоста, есть ли оно в его списках
или нет. Если имя списки профиля проходит — стратегия работает. Если нет
— поток остаётся в профиле, но без стратегии (пакеты идут как есть), и
профиль за ним следит (кроме имён из списков исключений и записей `!имя`
самого автосписка):

- TCP, клиент: повтор того же запроса (ретрансмиссия) в первых
  `retrans-maxseq` байтах увеличивает счётчик потока; на пороге — неудача
  и, с `retrans-reset`, RST клиенту от имени сервера. Клиент ушёл дальше
  `retrans-maxseq` — сайт работает.
- TCP, сервер: RST или ответ HTTP 302/307 на другой домен второго уровня в
  первых `incoming-maxseq` байтах — неудача; ответ дальше — сайт работает.
- UDP: больше `udp-in` пакетов от сервера — работает; `udp-out` пакетов
  клиента без них — неудача.

Неудачи считаются по хосту в профиле; счётчик живёт `fail-time` секунд с
первой неудачи, «сайт работает» его сбрасывает. На пороге хост ещё раз
проверяется по спискам (его мог добавить другой поток) и дописывается в
память и строкой в файл. Пустой автосписок не пуст: в нём невозможное имя
`@&()`, поэтому профиль не берёт всё подряд, пока список пуст. В gzip
автосписок быть не может. Свои дописанные строки не перечитываются;
изменения файла снаружи подхватываются, как у `--hostlist`. С
`--server-side` автосписок не работает (как в серверном режиме zapret2).

**Кэш адресов** (`ipcache` zapret2) держит по адресу (и интерфейсу):

- имя хоста — из DNS-ответов (A, AAAA; один вопрос) в перехваченном
  трафике и из потоков, чьё имя стало известно. Новый поток к этому
  адресу берёт имя из кэша на первом пакете клиента, и профиль со списком
  выбирается уже по SYN. Имя из кэша не проверяется по спискам и не
  запускает автосписок: проверка — когда имя придёт в самом потоке (SNI,
  Host). ICMP и другие IP-протоколы ищут имя по адресу назначения, затем
  источника. Включается `--ext-ipcache-hostname`;
- TTL первого ответа сервера по интерфейсу входа: следующий поток к этому
  серверу знает его с первого пакета (`autottl` x-действий). Работает
  всегда, кроме `--server-side`.

DNS-ответы и TTL учитываются только для пакетов, которые попали в профиль
(без профилей — когда есть стратегия), как в zapret2.

Отличия от zapret2:

- RST клиенту отправляется только через NFQUEUE (Linux): WinDivert
  отправил бы его в сторону сервера, поэтому на Windows RST не шлётся
  (неудача считается). `apply` RST не пишет.
- Профиля «no_action» в конце списка, как в zapret2, нет: поток без
  профиля всё равно ищет его заново, когда узнаёт протокол и имя. Поэтому
  ClientHello из нескольких пакетов держится до имени и тогда, когда
  стратегия может появиться только у профиля со списками.
- Время в счётчиках неудач — время пакета (в `apply` — из pcap).
- Окно в RST клиенту — окно сервера в сетевом порядке байт (zapret2
  записывает его без `htons`, на little-endian байты переставлены).
- Таблица кэша адресов растёт вдвое, когда записей вдвое больше корзин
  (у zapret2 — uthash); записи живут `--ext-ipcache-lifetime`, как там.
- Один журнал `--hostlist-auto-debug` на процесс; журнал открывается на
  каждую запись, как в zapret2.

Фича `ext_autolist` в `geneva version --json`.

**Проверка.** e2e `run.sh`: цензор с `iptables -m string` сбрасывает
ClientHello с example.com; две неудачи — хост в файле, третий поток идёт
через стратегию; цензор, который молча выбрасывает пакет, — неудача по
повторам, клиент получает RST сразу (а не по своему таймауту).

## Эксплуатация (X7a)

То, что в zapret2 есть у `nfqws2` для работы службой. Всё — только с
`--ext`.

**Опции из файла.** Первый аргумент команды `@FILE` (или `$FILE`, как в
zapret2) заменяется словами файла:

```
# /etc/geneva/run.conf
--ext --comment="обход для example.com"
--hostlist-domains example.com --filter-tcp 443
-s '[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=3}-| \/'
--pidfile /var/run/geneva.pid --user nobody --log-target syslog
```

`geneva run @/etc/geneva/run.conf`. Слова разделяются пробелами и
переводами строк; `'...'` — как есть, `"..."` — с пробелами и `\"`, `\\`,
`\$`; `\` экранирует следующий символ; `$NAME` и `${NAME}` берутся из
окружения; `#` в начале слова — комментарий до конца строки. `$(...)` и
`` `...` `` — ошибка (zapret2 тоже не запускает команды). В словах файла
или после него должен быть `--ext`, иначе ошибка 2. `--comment[=TEXT]`
ничего не делает — это заметка.

**Проверка без запуска.** `run --dry-run` разбирает все опции,
стратегии профилей, загружает списки и выходит: 0 — всё в порядке,
2 — ошибка в опциях, 3 — в стратегии. Правила firewall и NFQUEUE не
трогаются, root не нужен.

**Служба.**

| Опция | Что |
|---|---|
| `--daemon` | Linux: уйти в фон (своя сессия, stdin/stdout — `/dev/null`, stderr — когда пакеты пошли). Родитель ждёт запуска и выходит с его кодом: 0 — работает, иначе код ошибки запуска |
| `--pidfile FILE` | записать PID (после `--daemon` — PID демона); удаляется при выходе |
| `--user NAME`, `--uid UID[:GID,…]` | Linux: когда пакеты пошли, стать этим пользователем; остаются только `CAP_NET_ADMIN` и `CAP_NET_RAW` (как `dropcaps` zapret2). Нужен root |
| `--ext-seccomp[=0\|1]` | Linux: когда пакеты пошли, запретить `exec*`, `kill`, `tgkill`, `ptrace`, `process_vm_*`, создание и смену прав файлов, `getdents` — список `sec_harden` zapret2; нарушение — SIGSYS. По умолчанию 1 |
| `--log-target syslog` | ещё и в syslog (`/dev/log`, facility daemon, `geneva[PID]`) |

Под systemd (`Type=notify`) движок шлёт `READY=1` в `$NOTIFY_SOCKET`, когда
пакеты пошли, и `STOPPING=1` при выходе (без libsystemd).

**Правила снимаются всегда.** Без root и с seccomp движок не может
запустить `nft`/`iptables`. Поэтому перед сбросом прав он запускает
помощника: тот остаётся root, без фильтра, ждёт на канале и снимает
правила (и pidfile), когда движок попросит при выходе или когда канал
закроется — то есть и после SIGKILL или падения движка. SIGINT, SIGTERM и
SIGHUP помощник не слушает (Ctrl-C в терминале уходит всей группе).

После `--user` файлы, которые движок читает и пишет на ходу
(`--strategy-file` по SIGHUP, списки, автосписок, `--hostlist-auto-debug`,
`xpcap`), должны быть доступны этому пользователю. Сокет управления, лог и
`--pcap` открываются до сброса.

**Метка.** Метка geneva по умолчанию `0x20000000` совпадает с
`DESYNC_MARK_POSTNAT` zapret2 (решение 11.5: метку не меняем). `run --ext`
предупреждает, если `--mark` задевает `0x20000000` или `0x40000000`
(`DESYNC_MARK`): при nfqws2 на том же узле дайте одному из них другую
метку.

**Дампы.** Сигналы SIGUSR1/SIGUSR2 у geneva заняты, поэтому дампы zapret2
— команды управления (`docs/PROTOCOL.md`):

- `ext_flows [limit=N]` — потоки conntrack (по умолчанию первые 1000,
  сначала давно не активные): адреса и порты, состояние TCP, возраст,
  профиль, L7, имя хоста, счётчики `n`/`d`/`b`/`s`, окно и MSS в обе
  стороны; `total`, `truncated`;
- `ext_keys` — счётчики неудач автосписка по хостам и профилям (на этапе
  X11 сюда добавятся ключи автотюнера).

Отличия от zapret2:

- `@FILE` можно дополнить опциями после него (zapret2 их не читает);
  нет подстановки шаблонов файлов и `~`, есть `#`-комментарии.
- Права сбрасываются, когда пакеты пошли (zapret2 — до открытия очереди,
  потому что правила ему ставят скрипты); правила снимает root-помощник.
- `--daemon` ждёт запуска и возвращает его код; без `--chdir`: рабочий
  каталог не меняется, относительные пути остаются верными.
- seccomp убивает весь процесс (`KILL_PROCESS`), а не поток; отключается
  `--ext-seccomp=0`.
- Нет Android logcat (решение 11.4) и `--debug=@file` (есть `--log-file`).

Фича `ext_service` в `geneva version --json`.

**Проверка.** Юнит-тесты: разбор файла, `--uid`, строки syslog,
`sd_notify` на свой сокет, программа seccomp и её действие в дочернем
процессе (`exec`, `kill`, `mkdir` → SIGSYS). e2e `run.sh`: движок от
`nobody` с двумя capability и seccomp обходит, `ext_flows` видит поток,
после SIGKILL правила и pidfile сняты; `--daemon` возвращает 0, когда
работает, и код ошибки запуска, если нет.

## Правила firewall (X7b)

Правила, которые в zapret2 ставят скрипты (`common/nft.sh`, `ipt.sh`), и
фильтр WinDivert winws2. Всё — только с `--ext`, у `run` и `fw`; `geneva
fw print --ext ...` показывает, что получится. Без этих опций правила
прежние.

| Опция | zapret2 | Что |
|---|---|---|
| `--ext-first SPEC` | `NFQWS2_TCP_PKT_OUT/IN`, `NFQWS2_UDP_PKT_OUT/IN` | `--first` отдельно по протоколам и направлениям: `tcp-out=20,tcp-in=10,udp-out=5,udp-in=3` (значения zapret2), `out=N`/`in=N` — оба протокола, просто `N` — всё; что не задано, берётся из `--first`. 0 — все пакеты. В правилах — connbytes/`ct packets`, на Windows считает движок |
| `--ext-wan IF,..` | `IFACE_WAN` | как `--iface`, до 8 интерфейсов (в nft — множество, в iptables — правило на каждый; на Windows — индексы интерфейсов) |
| `--ext-notrack all\|frag\|none` | predefrag (−401) | какие наши пакеты не попадают в conntrack: `all` — все (по умолчанию, как без `--ext`), `frag` — только IP-фрагменты и TCP без SYN, RST и ACK (`datanoack`), как с `DESYNC_MARK` у zapret2; `none` — как `--no-notrack` |
| `--ext-ttl-icmp` | `FILTER_TTL_EXPIRED_ICMP=1` | фейк с малым TTL вызывает ICMP time-exceeded от роутеров по пути, и сокет клиента видит ошибку. Потоки, пакеты которых идут в очередь, получают ct mark (бит `--mark`), а входящие time-exceeded таких потоков отбрасываются (со счётчиком в nft) |
| `--ext-flowoffload software\|hardware` | `FLOWOFFLOAD=software\|hardware` | nft: свой flowtable на устройствах `--iface`/`--ext-wan` и `--ext-lan` (`flags offload` у hardware); потоки к портам не выгружаются, пока очереди нужны их пакеты (все или первые N из `--ext-first`). Свой offload системы (fw4, `flow_offloading`) надо выключить: иначе он выгрузит поток раньше |
| `--ext-lan IF,..` | `IFACE_LAN` | LAN-устройства flowtable |
| `--fw-hook-pre FILE`, `--fw-hook-post FILE` | `INIT_FW_PRE/POST_UP/DOWN_HOOK` | Linux: запустить `FILE up\|down BACKEND QUEUE` до и после установки и снятия правил (абсолютный путь; ненулевой код — только предупреждение). Таблица nft `inet geneva_QUEUE` удаляется целиком, так что правила хука в ней снимаются сами |

**WinDivert.** Опции winws2 `--wf-tcp-in/out`, `--wf-udp-in/out`,
`--wf-icmp-in/out`, `--wf-ipp-in/out`, `--wf-iface`, `--wf-l3`,
`--wf-tcp-empty`, `--wf-raw-part` (OR, повторяемая), `--wf-raw-filter`
(AND), `--wf-filter-lan`, `--wf-filter-loopback`, `--wf-raw` (фильтр
целиком), `--wf-priority` (= `--priority`), `--wf-save FILE` строят тот же
фильтр, что `wf_make_filter` в `nfqws.c` (порты меняются местами с
`--server-side`), и он заменяет фильтр из `-p/--proto/--dir`. `-p` тогда не
нужен: направление пакета даёт WinDivert. `EXPR` можно взять из файла:
`@FILE`. `--wf-save` пишет фильтр в файл и выходит с 0 на любой платформе;
`geneva fw print --ext --wf-...` на Linux показывает фильтр. `run` с
`--wf-*` на Linux — ошибка 2.

Отличия от zapret2:

- ct mark для `--ext-ttl-icmp` ставится на все пакеты, которые идут в
  очередь (zapret2 — на пакеты, которые nfqws2 отправил сам): наши пакеты
  по умолчанию не попадают в conntrack и не могут пометить поток. Поэтому
  отбрасываются time-exceeded всех обрабатываемых потоков, а не только
  тех, где был фейк. Если на узле что-то копирует ct mark в метку пакета
  (`CONNMARK --restore-mark` без маски), выберите `--mark`, который не
  задевает.
- Отбрасывание в iptables — в цепочке `mangle PREROUTING` (zapret2 —
  `INPUT` и `FORWARD`).
- В iptables `raw` идёт после дефрагментации conntrack, поэтому
  `--ext-notrack frag` там не мешает ядру собрать наши фрагменты (как и
  у zapret2, у которого predefrag есть только в nft).
- Один список интерфейсов на IPv4 и IPv6 (у zapret2 есть отдельный
  `IFACE_WAN6`): перечислите в `--ext-wan` оба устройства.
- `--ext-flowoffload` только в nft; `donttouch` — это просто без опции.
- Хуки получают аргументы, а не переменные окружения, и запускаются
  движком (zapret2 — скриптом запуска).
- `--wf-dup-check` принимается и ничего не делает: WinDivert позволяет
  несколько дескрипторов с одним фильтром, а geneva не проверяет дубли.
- `--ext-lan`, `--fw-hook-*`, `--ext-notrack`, `--ext-ttl-icmp`,
  `--ext-flowoffload` на Windows — ошибка 2.

`geneva fw down` снимает правила с теми же опциями, что `up`: в iptables
цепочки `--ext-ttl-icmp` живут в `GENEVA_Q_IN`, которая снимается всегда.

Фича `ext_fw` в `geneva version --json`.

**Проверка.** Юнит-тесты: разбор `--ext-first` и списков интерфейсов,
правила nft и iptables для каждой опции, порядок хуков вокруг правил
через подставной `iptables`, фильтр `--wf-*` по образцу winws2 (клиент и
сервер, порты с `~` и диапазонами, ICMP, IP-протоколы, LAN, loopback,
raw-части). Golden: `fw print` с опциями X7b для nft, iptables и
WinDivert, ошибки. e2e `run.sh` (auto, iptables, nft): `--ext-notrack frag`
с IP-фрагментацией, time-exceeded потока из очереди отброшен, чужого —
нет, `--ext-first out=4` — движок видел не больше 4 исходящих пакетов,
хуки до и после в нужном порядке, правила сняты. `--ext-flowoffload`
живьём не проверяется: в ядре контейнеров разработки нет
`nf_flow_table`; синтаксис flowtable проверен `nft`, правила — юнит- и
golden-тестами, e2e на образе OpenWrt — на этапе X10 (zapret-gui).

## Фаззинг (X7c)

Всё, что читает чужие байты или текст, вынесено в цели фаззинга
(`src/ext/fuzz.c`): функция над буфером, свои начальные входы (seeds) и
свои проверки. Список — `geneva selftest --ext --list`:

| Цель | Что читает |
|---|---|
| `pkt` | пакет Geneva: разбор, все поля, tamper со случайными значениями, сборка |
| `strategy` | язык стратегий с x-действиями; напечатанная стратегия читается обратно в тот же текст |
| `apply` | пакеты через стратегии библиотеки и x-действий с conntrack и сборкой, как `geneva apply --ext`; вход: номер стратегии, затем пакеты `[флаги][длина: 2 байта][байты]` |
| `pcap` | pcap и pcapng (из памяти) |
| `json` | JSON сокета управления и строки базы стратегий (строка, записанная обратно, читается) |
| `l7` | распознавание payload, имена хостов, маркеры позиций |
| `tls` | SNI, `tls_mod`, клон ClientHello (`xtlsclone`) |
| `quic` | заголовок Initial, расшифровка, кадры CRYPTO |
| `inflate` | gzip, zlib и raw DEFLATE списков |
| `lists` | списки хостов и IP-адресов |
| `profile` | файл профилей `--ext-profile` (ключи с файлами отклоняются) |
| `spec` | значения опций: маркеры, диапазоны, порты, фильтры, `tls_mod`, `--ext-first`, слова `@FILE` |
| `observe` | датаграммы NFLOG, счётчики ctnetlink и детектор `--ext-auto` (X9a, X9b) |
| `ctnl` | ответы ctnetlink со счётчиками потока (X9b) |

Цель не ходит в сеть и не трогает файлы. Нарушенная проверка — `abort()`
с сообщением, для фаззера это падение.

**`geneva selftest --ext [--fuzz N]`** прогоняет цели в самом бинарнике
(подходит для роутера): сначала все seeds, потом N случайных изменений
каждой цели. Входы зависят только от `--seed` (по умолчанию от часов,
печатается), так что падение повторяется той же командой — она
печатается рядом с результатом. На POSIX каждая цель идёт в дочернем
процессе: падение (сигнал или выход санитайзера) и зависание дольше
`--timeout` секунд (по умолчанию 10) отмечаются с номером входа, а
`--crash-dir DIR` сохраняет сам вход. На Windows цели идут в самом
процессе, и падение его завершает. Опции: `--target LIST`, `--max-len`
(длина случайного входа, 4096), `--json`, `--seeds-out DIR` (seeds в
`DIR/ЦЕЛЬ/` для внешнего фаззера). Код выхода 0 — все цели прошли, 1 —
какая-то упала. Без `--ext` — ошибка 2; в сборке `EXT=0` команды нет.
Фича `ext_selftest`.

**libFuzzer и AFL++.** `tests/fuzz/fuzz_target.c` собирает одну цель
(`-DFUZZ_TARGET='"l7"'`); с `-DFUZZ_STANDALONE` это программа, которая
читает входы из файлов (повтор найденного). `tests/fuzz/run.sh [СЕКУНДЫ]
[ЦЕЛЬ...]` собирает `build-fuzz/` с ASan и UBSan, берёт seeds из
`selftest --seeds-out` и образцы из `tests/data` и `tests/golden` и
гоняет каждую цель (по умолчанию 60 с, libFuzzer; `FUZZER=afl` — AFL++).
CI: libFuzzer по 60 с на цель и `selftest --fuzz` под санитайзерами;
перед выпуском — долго.

**Что нашёл фаззинг** (исправлено, тесты в `tests/test_fuzz.c`):
число JSON вне диапазона `int64` в `json_get_int` и в записи чисел
(неопределённое поведение C; теперь ближайший край и запись как
дробного), ICMP без данных в распознавании L7 (`xl7.c`), утечка пустого
блоба `0x` (`--ext-blob имя:0x`, `pattern=0x` и т.п.).

Отличие от плана: целей `nflog` и `ctnl` пока нет — их разборщики
появятся на этапе X9 вместе со своими целями.

## Seqtrack: `xoob`, `xtlsrec`, `xdrip` (X8)

```
[FLOW:n:1-]-xoob{urp=e;char=Z}-| \/
[FLOW:n:1-]-xtlsrec{pos=sniext+1}-| \/
[TCP:flags:PA]-xdrip{n=4;delay=30}-| \/
```

| Действие | Функция zapret2 | Свои параметры | Общие | Входящий лес |
|---|---|---|---|---|
| `xoob` | `oob` | `char=СИМВОЛ` или `byte=N` (байт OOB, по умолчанию 0), `urp=b\|e\|МАРКЕР` (`b`) | fooling, `badsum`, `repeats`, `fwmark`, `ifout`, `ipid`, ipfrag | нет |
| `xtlsrec` | — | `pos=МАРКЕР` (`midsld`) | то же | нет |
| `xdrip` | — | `n=N` (8, до 1000), `delay=МС` (20, до 10000) | `ipid`, `payload` (`known`) | нет |

**`xoob`** делает то же, что `oob` zapret2: на SYN клиента уменьшает seq
на 1, а в первое сообщение клиента вставляет один срочный байт (флаг URG):
в начало (`urp=b`, указатель 0), в конец (`urp=e`) или перед байтом,
на который указывает маркер. Сервер с обычным сокетом (без
`SO_OOBINLINE`) вынимает этот байт из потока, а DPI видит лишний байт.
**`xtlsrec`** режет первую запись TLS первого сообщения на две в точке
маркера (заголовок второй записи — 5 байт) и сдвигает SYN на 5. Записи
TLS не входят в хэш рукопожатия, поэтому сервер принимает такой
ClientHello. Если точка вне тела первой записи или маркер не найден, разрез
идёт после первого байта тела. Сообщение, собранное из нескольких
сегментов, меняется целиком и уходит заново сегментами по MSS, остальные
куски сборки отбрасываются.

**Seqtrack** (`src/ext/seqtrack.c`). Сдвиг делается на SYN, поэтому
удлинённое сообщение кончается там же, где своя нумерация клиента, и
после него ничего менять не нужно. Пока сервер не подтвердил сообщение,
движок сам правит пакеты потока до стратегии, даже если все деревья
отсечены или работа на паузе:

- пакеты клиента без данных до сообщения (повтор SYN, ACK, FIN, RST) —
  seq минус сдвиг;
- повтор любой части первого сообщения (потеря) — снова всё изменённое
  сообщение (из копии, без fooling), затем то, что пакет несёт после
  него;
- ack и края SACK сервера — обратно в нумерацию клиента; вставленные
  байты считаются байтом перед ними.

Условия: действие должно видеть SYN потока (иначе отсечка, как в
zapret2) и первое сообщение, поэтому нужен триггер, который их
пропускает (`[FLOW:n:1-]`, а не `[TCP:flags:PA]`), conntrack (без него
действие ничего не делает) и входящие пакеты в очереди до подтверждения
сообщения (по умолчанию так и есть; при `--first`/`--ext-first` число
входящих должно это покрывать). На поток — одно сдвигающее действие:
второе пропускает поток. Состояние живёт на потоке и переживает смену
стратегии.
Если первое сообщение до действия не дошло, поток встанет: сервер ждёт
сдвинутую нумерацию. Так бывает, когда движок поставлен на паузу между SYN
и первым сообщением или когда профиль потока после распознавания L7
сменился на профиль без этого действия. Поэтому `xoob`/`xtlsrec` ставят в
профиль, который выбирается уже на SYN.

**`xdrip`** (у zapret2 нет): первые `n` байт payload (собранного
сообщения) уходят по одному в сегменте с паузой `delay` мс между ними,
остаток — после ещё одной паузы, сегментами по MSS; исходный пакет
отбрасывается. Нумерацию не меняет. Против DPI с таймаутом сборки.

Отличия от zapret2:

- `oob` у zapret2 прибавляет 1 к ack сервера, пока клиент не отправит
  данные дальше первого сообщения. Подтверждение самого сообщения
  получает лишний 1, и клиент видит ack за пределами отправленного.
  Seqtrack переводит ack точно.
- zapret2 после первого сообщения отсекает функцию, и повтор сообщения при
  потере уходит без изменений. Сервер получает байты не на своих местах, и
  поток встаёт. Seqtrack повторяет изменённое сообщение.
- Маркер `urp`, который не нашёлся: zapret2 отсекает функцию, хотя SYN
  уже сдвинут, и поток рвётся. `xoob` ставит байт в начало.
- `xtlsrec` на сообщении, которое не запись TLS, отправляет его без
  изменений со сдвигом. Первый запрос получает ответ, но всё, что клиент
  пошлёт дальше, сервер ждёт с дырой в 5 байт. Используйте его на портах
  TLS.
- `urp=e` ставит срочный байт последним. Сервер, который закрывает
  соединение, не прочитав ничего дальше, оставляет этот байт
  непрочитанным, и Linux отвечает RST вместо FIN. Так же ведёт себя
  zapret2.

e2e `tests/e2e/seqtrack.sh`: загрузка 100 МБ после `xoob` и `xtlsrec`
со сверкой SHA-256 запроса (тела записей TLS) и ответа, потеря 30 %
пакетов к серверу (первое сообщение уходит повторно), `xdrip`. Юнит-тесты
`tests/test_xseq.c` проходят нумерацию около 2^32.

## Наблюдение и детектор: `--ext-auto observe` (X9a)

```
sudo geneva run --ext --ext-auto observe -s '\/' -p 443 --events -
```

`--ext-auto observe` ничего не меняет в трафике: профили и стратегия
работают как без него. Дополнительно firewall копирует в группу NFLOG
первые пакеты каждого потока, который начал клиент (TCP и UDP на любых
портах), и ICMP destination-unreachable. Ядро не ждёт geneva: если она не
успевает читать, теряются копии, а не трафик (`lost` в `ext_status` —
сколько раз ядро сообщило о потере).

| Опция | Что | По умолчанию |
|---|---|---|
| `--ext-auto observe` | наблюдение и детектор; `propose` и `apply` появятся на этапе X11 | нет |
| `--ext-nflog-group N` | группа NFLOG | номер очереди (`--queue`, 310) |
| `--ext-observe-first N` | сколько пакетов каждого направления потока копировать (4–1000) | 16 |

Правила (снимаются при выходе вместе с остальными) видят адреса клиента
до NAT, так что на роутере потоки клиентов LAN сходятся в обе стороны: nft
— цепочки `obs_out` (postrouting, приоритет 99: перед очередью и SNAT) и
`obs_in` (prerouting, −99: после обратного NAT, то есть уже после
очереди); iptables — `GENEVA_<очередь>_OBO` в `mangle POSTROUTING`
(первой) и `GENEVA_<очередь>_OBI` в `mangle INPUT` и `FORWARD`. Пакеты с
меткой движка и интерфейс `lo` не копируются. `--iface`/`--ext-wan` ограничивают наблюдение этими
интерфейсами. Только Linux; режим `--server-side` не поддерживается.
Счётчики пакетов conntrack (`ct packets`, `connbytes`) ядро включает само.

**Исход потока.** Детектор (`src/ext/detect.c`) ведёт свой conntrack и
даёт потоку один исход — первый, который сработал:

| Класс | Условие | Откуда |
|---|---|---|
| `RETRANS` | клиент повторил данные 3 раза в первых 32768 байтах | zapret2 (`retrans`, `maxseq`) |
| `RST_IN` | RST от сервера в первых 4096 байтах, до данных сервера | zapret2 (`inseq`), см. отличия |
| `RST_INJECT` | RST в первых 4096 байтах, TTL которого отличается от TTL SYN,ACK на 2 и больше | свой |
| `REDIRECT` | HTTP 302/307 на другой домен второго уровня в первых 4096 байтах | zapret2 |
| `UDP_NOANSWER` | клиент отправил 4 датаграммы, а пришло не больше 1 | zapret2 (`udp_out`, `udp_in`) |
| `BLACKHOLE_SYN` | 2 SYN без SYN,ACK | свой |
| `ICMP_PROHIBIT` | ICMP unreachable с кодом 9, 10 или 13 (ICMPv6 1/1) о пакете потока | свой |

Успех: клиент ушёл дальше 32768 байт или сервер дальше 4096 байт; в UDP
пришло больше одной датаграммы. Поток без исхода (короткий обмен,
закрытый раньше порогов) ничего не меняет.

**Ключи.** Исход потока идёт в четыре ключа: протокол и порт сервера
(`tcp/443`), сеть сервера (`/24`, IPv6 `/48`), адрес и имя хоста (SNI
или `Host:` первого сообщения, иначе имя из кэша адресов, если он
запоминает имена: `--ext-ipcache-hostname 1`). Детектор кэш только читает,
чтобы профили видели те же имена, что и без `--ext-auto`. Потоки к
multicast, broadcast и link-local адресам исхода не получают (mDNS, SSDP
ответа на своём потоке не ждут). На каждом ключе идёт последовательный тест Вальда: неудача
сдвигает его к «заблокирован» (доля неудач 0.6), успех — к «здоров»
(0.1), ошибки α = β = 0.05. Логарифм отношения правдоподобия ограничен
порогами, поэтому две неудачи подряд решают свежий ключ, а заблокированному
нужно 8 успехов подряд, чтобы стать здоровым. Класс ключа — самый частый
класс его неудач. Ключ, о котором час нет вестей, забывается; ключей не
больше 4096.

**События** (`docs/PROTOCOL.md`):

```
{"ev":"ext_flow","proto":"tcp","client":"10.81.1.2","cport":60346,"server":"10.81.2.2","sport":443,"host":"ultrasurf.example","class":"RST_INJECT","why":"a RST with another TTL than the SYN,ACK's"}
{"ev":"ext_impaired","key":"ultrasurf.example","level":"host","impaired":true,"class":"RST_INJECT","flows":2,"fails":2}
{"ev":"ext_class","key":"tcp/443","level":"port","class":"RETRANS","flows":9,"fails":5}
{"ev":"ext_impaired","key":"tcp/443","level":"port","impaired":false,"flows":20,"fails":5}
```

`ext_flow` — поток с неудачей, `ext_impaired` — ключ стал заблокированным
(`impaired: true`) или снова здоровым, `ext_class` — у заблокированного
ключа сменился класс. Команда `ext_status` отдаёт счётчики наблюдения
(`packets`, `lost`, `flows`, `flows_ok`, `flows_failed`, `keys`) и
заблокированные ключи, `ext_keys` — ещё и все ключи детектора (`detect`).

Отличия от zapret2:

- zapret2 считает неудачей любой RST сервера в первых 4096 байтах. Сервер,
  который ответил и оборвал соединение RST (так закрываются многие
  короткие обмены), дал бы ложный класс. Здесь RST после данных сервера —
  неудача только с чужим TTL (`RST_INJECT`).
- `--hostlist-auto` (X6c) работает по-прежнему, по правилам и порогам
  zapret2, на потоках своих профилей; детектор — отдельный и смотрит на
  все потоки.

Наблюдение на Windows — ниже, X9c.

e2e (`tests/e2e/censors_x.sh auto`): против цензоров 14 (RST с TTL 50),
15, 16, 17 и 18 нужный класс ставится за 2 потока, других классов нет;
без цензора (загрузки, HTTPS, UDP, DNS, медленная загрузка) классов нет;
правила снимаются. Юнит-тесты `tests/test_detect.c`.

## Заморозка, замедление, подмена DNS (X9b)

Первые пакеты потока не говорят, что сервер замолчал на 20-м килобайте
или что загрузка идёт в десять раз медленнее канала. Для этого
`--ext-auto observe` раз в секунду спрашивает у conntrack ядра
(ctnetlink, запрос `GET` одного потока) счётчики каждого TCP-потока,
получившего SYN,ACK: сколько байт пришло от сервера и открыт ли поток.
Следит не дольше 120 секунд и не больше чем за 512 потоками сразу.
Счётчики байт ядро ведёт при `nf_conntrack_acct`, который включают те же
правила наблюдения. Если сокет ctnetlink не открылся (нет модуля
`nf_conntrack_netlink`), остальные классы работают, а `counters` в
`ext_status` — `false`.

| Класс | Поток | Ключ |
|---|---|---|
| `FREEZE_N` | от сервера пришло от 8 до 64 КБ, и больше ничего уже max(4 RTT, 3 с), а поток в conntrack всё ещё открыт | 3 таких потока за 10 минут, межквартильный размах их объёмов меньше 4 КБ: цензор замораживает на одном и том же счёте. Тогда ключ сразу заблокирован с этим классом |
| `THROTTLE` | в последних 5 секундных окнах с данными (первое окно потока не считается) медиана скорости меньше четверти ёмкости канала C, коэффициент вариации меньше 0.3, ни одно окно не быстрее двух медиан, всего 64 КБ и больше: ровная полка полисера. Но не тогда, когда у потока к другой сети (другой /24 или /48), живого в последние 2 с, такая же полка (медиана от половины до двух наших, тоже ниже C/4; хватает его двух окон): общая полка — это свой канал (X9c) | как обычная неудача |
| `DNS_POISON` | ответ DNS с адресом-заглушкой (0.0.0.0, 127/8, ::, ::1) или два ответа на один запрос (тот же id), первый — с другим TTL IP: его вставили по пути | как обычная неудача; заглушка — только у ключа имени, потому что так же отвечают резолверы с блокировкой рекламы |

C — самое быстрое секундное окно любого потока; через 10 минут без
нового рекорда C берётся заново. Пока C неизвестна, `THROTTLE` нет.

Успех, который потом оказался ложным, пересматривается: поток с
`THROTTLE` или `DNS_POISON` становится этой неудачей, а заморозка
забирает успех назад и идёт в учёт заморозок ключа. Ключ, заблокированный
с `FREEZE_N` или `THROTTLE`, засчитывает успех строже: поток TCP должен
получить больше двух медиан заморозки или идти быстрее трёх полок; до тех
пор (и если так и не дошло) успех ему не засчитывается.

**`LINK_DEGRADED`.** Если за последние 30 секунд неудачи были у 30 % и
больше адресов с потоками (хотя бы у 5 адресов из всех), это скорее
сбой своего канала, а не блокировка: событие
`{"ev":"ext_link","degraded":true,"bad":3,"active":7}`, и ещё одно с
`degraded: false`, когда это прошло. Ключи считаются как обычно; решать,
что делать с такими неудачами, будет `propose` (X11).

`ext_status` получает поля `counters` (ctnetlink работает), `watched`
(потоков под счётчиками), `capacity` (C, байт/с, 0 — неизвестна) и
`link_degraded`.

Ограничения. Со стороны клиента заморозка неотличима от соединения
keep-alive, которое после ответа в 8–64 КБ просто молчит: такой поток
получит `ext_flow` с `FREEZE_N`. Класс ключа требует трёх заморозок
одного размера, а подтверждать блокировку пробой будет `propose` (X11).
Так же ровный поток постоянной скорости (интернет-радио) после быстрой
загрузки похож на полку полисера.

e2e (`tests/e2e/censors_x.sh auto12 auto13 autodns`): цензор 12
(`--freeze-bytes 20000`) — `FREEZE_N` у адреса сервера за 3 потока;
цензор 13 (полка в восьмую часть того, что пропускает лабораторный цензор; сначала быстрая загрузка до 1 МБ/с для C) —
`THROTTLE`; цензор `dns` (поддельный ответ первым) — `DNS_POISON` у
`udp/53` за 2 запроса; других классов нет.

## Наблюдение на Windows и синтетика без цензора (X9c)

На Windows `--ext-auto observe` открывает второй хэндл WinDivert с
флагами `SNIFF` и `RECV_ONLY` и фильтром
`!loopback and (tcp or udp or icmp or icmpv6)`: копия каждого пакета ПК,
ничего не перехватывается и не задерживается. Приоритет хэндла на 1 выше,
чем у движка (`--priority`), поэтому он видит пакеты такими, какими они
пришли и ушли до стратегии, как цепочки NFLOG на Linux. Поток отдельный:
пакеты (первые 2048 байт каждого) идут в кольцо на 2048 пакетов, главный
цикл забирает их через петлевой UDP-сокет. Переполнение кольца теряет
копии, а не трафик (`lost` в `ext_status`). Правил firewall нет, снимать
нечего. `--ext-nflog-group` на Windows — ошибка 2, `--ext-observe-first`
не действует: хэндл видит все пакеты.

Отличия от Linux:

- Пакеты всех потоков, а не первые 16: ctnetlink нет, детектор сам
  считает байты IP от сервера у каждого потока под наблюдением и сам
  отвечает себе раз в секунду (`counters: true`). Поток считается
  закрытым с первым FIN или RST. Классы те же, X9a и X9b.
- Направление conntrack (`ctdir original`) WinDivert не знает: поток
  начинают только исходящие пакеты, кроме SYN,ACK. Входящие соединения к
  серверам на ПК и входящие датаграммы без своего потока детектор не
  считает.
- `source` в `ext_status` — `windivert`, поля `nflog_group` нет.

e2e на Windows (`tests/windows/smoke.ps1`, CI `windows`): HTTP и HTTPS к
example.com — успешные потоки, два соединения к 192.0.2.1 (TEST-NET-1,
никто не отвечает) — его ключ заблокирован (`BLACKHOLE_SYN`), других
заблокированных ключей нет, `source: windivert`, `counters: true`.

Синтетика без цензора (`tests/e2e/auto_synth.sh`, критерий X9 из
`docs/EXT_ROADMAP.md`): клиент и сервер в двух пространствах имён,
канал 50 Мбит/с (`tc tbf`). Long-poll к двум адресам (ответ через 20 с),
соединения WebSocket (апгрейд и по сообщению в обе стороны раз в 4–7 с,
минута на соединение), загрузка 50 МБ раз в минуту и мелкие страницы
каждые 2 с. Проверки: ни одного `ext_impaired`, ни одного `ext_link`, ни
одного неудачного потока, ёмкость C — у канала, проверки скорости
(`THROTTLE`) шли, правила сняты. 30 минут (`DURATION=1800`, по
умолчанию) проходит без единого класса; CI гоняет 5 минут.

Ограничение остаётся (X9b): ровный поток постоянной скорости больше
64 КБ за наблюдение (интернет-радио, тикер котировок) ниже C/4 похож на
полку полисера, если в то же время нет такой же полки к другой сети.

## Многоочередной движок: `--ext-workers` (X10a)

```
sudo geneva run --ext --ext-workers 4 -p 80,443 -s '[TCP:flags:PA]-duplicate-| \/'
```

| Опция | Смысл | По умолчанию |
|---|---|---|
| `--ext-workers N\|auto` | Linux: N воркеров (1–64), у каждого свой поток, своя очередь NFQUEUE (`--queue` .. `--queue + N - 1`), свой raw-сокет, своя копия стратегии, свой conntrack расширений и свои отложенные пакеты; `auto` — число CPU, но не больше 4 | 1 |

Правила раскладывают пакеты по очередям: iptables `-j NFQUEUE
--queue-balance 310:313`, nft `queue num 310-313`. Ядро выбирает очередь
по хэшу адресов, и хэш симметричный: оба направления потока попадают в
одну очередь, к одному воркеру. Потоки к одному серверу тоже идут к
одному воркеру. Имена цепочек и таблиц — по первой очереди
(`GENEVA_310_*`, `geneva_310`), снятие правил прежнее.

Главный поток держит управляющий сокет, сигналы, `stats`, наблюдение
`--ext-auto` и перечитывание файлов списков; пакеты он не трогает.
Команды управления, SIGHUP и `stats` выполняются, пока все воркеры стоят
(их блокировки берутся по порядку), поэтому `set_strategy`, `pause`,
`reset_stats` и `reload_lists` видят согласованное состояние. События
воркеров идут подписчикам через очередь главного цикла (не реже раза в
200 мс). Ошибка чтения очереди у любого воркера останавливает движок с
кодом 1.

В `stats` с `--ext-workers` больше 1 есть `workers` и `worker_pkts`
(пакеты каждого воркера), в `status` — `workers`; `fired` деревьев —
сумма по копиям стратегии.

Расширения: профили со списками читают общие списки под разделяемой
блокировкой, а перечитывание файлов (раз в секунду из главного цикла)
берёт её исключительно. С автосписком (`--hostlist-auto`) счётчики
неудач общие, и хук пакета берёт блокировку исключительно — воркеры с
автосписком идут по одному. Без профилей блокировки нет. Кэш адресов
(`ipcache`) общий под мьютексом; его чистка и запись TTL — не чаще раза
в секунду на поток.

Отличия от раздела 6.2 `docs/EXT_ROADMAP.md` (выбор реализации, раздел
11, п. 2):

- По умолчанию 1 воркер, а не `min(ncpu, 4)`: zapret-gui и AutoTuner
  раздают номера очередей сами, и лишние очереди без их ведома заняли бы
  чужие номера. `auto` даёт `min(ncpu, 4)`.
- Очередь выбирается хэшем адресов (`--queue-balance`, без
  `--queue-cpu-fanout` и `fanout`): с fanout ядро выбирает очередь по
  CPU, на котором пришёл пакет, и направления одного потока могут
  попасть к разным воркерам.
- Общие данные расширений (списки, автосписок, кэш адресов) под rwlock,
  а не снапшоты с QSBR; снапшоты с QSBR — у политики ключей (X10b).
- Gas триггеров (`[TCP:flags:PA:2]`) у каждого воркера свой: стратегия
  сработает до N раз на каждом воркере.
- Пакетных вердиктов (`NFQNL_MSG_VERDICT_BATCH`) и арены пакетов пока нет.
- Windows: `--ext-workers` больше 1 — ошибка 2 («Linux only for now»).

Проверки: юнит-тест движка с 4 потоками на поддельном бэкенде (с `--ext`,
с профилем и с автосписком; ThreadSanitizer в CI) и e2e
`tests/e2e/workers.sh`: 32 адреса сервера, 4 воркера, iptables и nft —
правила с диапазоном очередей, пакеты у каждого воркера, 32 загрузки по
5 МБ целиком, правила сняты. `BENCH=1` ещё меряет пропускную способность
1 и 4 воркеров (32 потока по 20 МБ) и время CPU движка. Критерий «≥ 3×
на 4 воркерах» проверяется только на машине с 8 CPU и больше: на 4 CPU
загрузки, сервер и стек ядра (вердикт отправляет пакет дальше в своём
системном вызове, и это время считается движку) съедают CPU раньше, чем
движок упирается в себя. На стенде с 4 vCPU: 1 воркер — 0.8–2.5 Гбит/с
при 0.7–1.0 CPU движка, 4 воркера — 1.7–2.6 Гбит/с при 1.7–2.0 CPU.

## Хирургический путь и политика (X10b)

```
sudo geneva run --ext --ext-healthy-mark on -p 443 -s '[FLOW:n:1-6]-xfake{blob=fake_tls}-| \/'
```

| Опция | Смысл | По умолчанию |
|---|---|---|
| `--ext-healthy-mark on\|MASK\|0` | Linux: бит(ы) метки conntrack у соединений, с которыми движок закончил (`on` — `0x10000000`); `0` — выключить | выключено |

Путь включается только явно: он меняет правила (а `--ext` сам по себе
правил прежних стратегий не меняет), и нескольким запускам geneva на
одном трафике нужны разные биты (см. ниже). С `--firewall none` правила
с переносом метки делает `geneva fw up --ext` с тем же
`--ext-healthy-mark` (или свои правила, повторяющие показанные ниже).
С `--forward` опция ничего не делает.

С `--ext-healthy-mark` движок отпускает соединение, когда больше ничего не
может в нём поменять:

- стратегия не сработает на нём ни в одну сторону: каждое дерево
  отрезано диапазоном (`[FLOW:n:1-6]`, `xcutoff`) или деревьев этой
  стороны нет, либо пакетам соединения стратегия не положена вовсе;
- с профилями: L7 известен, имя хоста тоже (для HTTP, TLS и QUIC), и
  профиль выбран уже с ними; профиль без автосписка (`--hostlist-auto`
  считает неудачи по всему соединению);
- соединение не под seqtrack (`xoob`, `xtlsrec`), движок не на паузе, не
  `--server-side`;
- ни один ключ соединения (порт, /24 или /48, адрес, имя) не помечен
  детектором `--ext-auto` как заблокированный.

Тогда вердикт пакета — `NF_REPEAT` с меткой пакета `исходная | MASK`:
ядро проводит пакет по хуку заново, и первые правила цепочки очереди
переносят бит в метку conntrack, снимают его с пакета и отпускают пакет:

```
iptables -t mangle -A GENEVA_310_OUT -m mark --mark 0x10000000/0x10000000 -j CONNMARK --or-mark 0x10000000
iptables -t mangle -A GENEVA_310_OUT -m mark --mark 0x10000000/0x10000000 -j MARK --and-mark 0xefffffff
iptables -t mangle -A GENEVA_310_OUT -m connmark --mark 0x10000000/0x10000000 -j RETURN
nft: meta mark & 0x10000000 == 0x10000000 ct mark set ct mark or 0x10000000 meta mark set meta mark and 0xefffffff return
nft: ct mark & 0x10000000 == 0x10000000 return
```

Следующие пакеты соединения (в обе стороны) идут мимо очереди по метке
conntrack. Пакеты, что успели попасть в очередь до правила, метят
соединение ещё раз, но не больше 4 вердиктов на соединение: пакет без
conntrack (свой `NOTRACK` у пользователя) иначе возвращался бы в очередь
после каждого повтора. В `stats` соединение считается один раз. С
`--ext-flowoffload` помеченное соединение уходит в flow offload сразу.
Цепочки наблюдения `--ext-auto` пропускают второй проход пакета.

На стенде (veth, загрузка 20 МБ, `[FLOW:n:1-3]`): движок видит 7
пакетов вместо ~20 000, с 1 и с 4 воркерами.

**Политика.** Состояние ключей (`IMPAIRED` — по событиям детектора
`--ext-auto`, `TRIAL`/`TREAT` подборщика — этап X11) хранится
неизменяемыми снапшотами: отсортированный массив ключей. Пишет один
главный поток (события детектора): меняет ключи и публикует новый
снапшот с номером поколения на 1 больше. Воркеры читают без блокировок:
на входе в хук пакета воркер объявляет поколение, с которым вошёл, на
выходе — что он вне снапшота. Заменённый снапшот освобождается, когда
каждый воркер вне снапшота или объявил поколение новее (QSBR по
поколениям); проверка — при публикации и раз за цикл главного потока.
Живых снапшотов не больше 4: если медленный воркер держит старый, новая
публикация ждёт следующего вызова. Воркер не ждёт никогда.

В `ext_status`: `policy` — `{gen, keys, retired}` (поколение, ключей в
политике, заменённых снапшотов ещё не освобождено) и `surgical` (путь
включён). В `stats` — `healthy` (отпущенных соединений).

Отличия от раздела 4.9 `docs/EXT_ROADMAP.md`:

- Метка ставится через `NF_REPEAT` и правила `CONNMARK`, а не через
  `NFQA_CT` вердикта: ядро меняет ct mark из вердикта только с
  `CONFIG_NETFILTER_NETLINK_GLUE_CT`, которого нет во многих ядрах (нет и
  на стенде CI). Плата — пакет, на котором соединение отпущено, второй
  раз проходит ту же точку хука: у iptables всю таблицу `mangle` этого
  хука (чужие правила `mangle` раньше нашей цепочки увидят его дважды), у
  nft — только нашу цепочку. Цепочки наблюдения `--ext-auto` второй
  проход пропускают.
- Метки «лечить» нет: лечимое соединение остаётся в очереди, пока
  стратегия не отрезана (`--ext-first` и `--first` — как прежде).
- Отпущенное соединение остаётся мимо очереди до своего конца: новая
  стратегия (`set_strategy`), ключ, помеченный заблокированным позже, и
  перезапуск geneva (метка conntrack переживает снятие правил) его не
  возвращают. Новые соединения решаются заново.
- Ключ, который детектор забыл заблокированным (вытеснен из таблицы),
  остаётся в политике до события, что он здоров, или до перезапуска.
- Windows не поддерживается (активный хэндл с фильтром по ключам — с
  X11). `--forward` (роутер) пока тоже: путь не проверен e2e на
  транзитном трафике.
- По умолчанию путь выключен (в плане — включён): см. выше.
- Метка conntrack общая для всех, кто её проверяет: несколько `geneva run
  --ext` на пересекающемся трафике (например, общий обход на очереди 310
  и отдельные запуски на 340+ только для адресов сервиса) должны брать
  разные биты `--ext-healthy-mark` (или его не давать), иначе соединение, отпущенное
  одним, пройдёт мимо очереди и другого.
- Пересечение `--ext-healthy-mark` с `--mark` — ошибка (код 2).
  Пересечение с меткой zapret2 (`0x40000000`) не проверяется.
- Без conntrack расширений (`--ext-ctrack-disable`) соединение не
  отпускается; в `eval` и `evolve` (свои очереди на каждый слот) путь
  выключен.

Проверки: юнит-тесты политики (снапшоты, освобождение, три потока-читателя
под ThreadSanitizer), правил (iptables и nft, разбор опции, пересечение
меток) и решения движка на поддельном бэкенде (стратегия без отсечки,
отсечка, пауза, профиль, автосписок, заблокированный ключ, выключенная
метка); e2e `tests/e2e/surgical.sh` (iptables и nft, 1 и 4 воркера: метка
в conntrack, загрузка 20 МБ целиком, движок видел меньше 500 пакетов;
стратегия без отсечки и запуск без `--ext-healthy-mark` — все пакеты в очереди;
правила сняты).

## Автотюнер: руки и селектор `rr` (X11a)

```
sudo geneva run --ext -p 443 --filter-tcp 443 \
    --ext-arm '\/' \
    --ext-arm '[TCP:flags:PA]-xsplit{pos=1}-| \/' \
    --ext-arm '[TCP:flags:PA]-xdisorder{pos=1,midsld}-| \/' \
    --ext-tune rr:fails=3:time=60 --ext-state /opt/var/geneva/tune.jsonl
```

| Опция | Смысл | По умолчанию |
|---|---|---|
| `--ext-arm STRATEGY` | (в профиле) ещё одна рука: рука 1, 2, … по порядку; повторяется. Профиль с руками своей `-s`/`-f` не имеет | — |
| `--ext-tune rr[:АРГ..]` | (в профиле) как ключи переходят между руками | `rr` |
| `--ext-state FILE` | ключи и их руки на диске между перезапусками: читаются при старте, пишутся при изменении (не чаще раза в 10 с) и при выходе | — |

Руки и `--ext-tune` шаблона (`--template`) переходят в профиль с его
`--import`; свои `--ext-arm` профиля добавляются к ним, своё `--ext-tune`
заменяет аргументы шаблона.

`rr` — оркестратор `circular` zapret2 (`lua/zapret-auto.lua`) с его
аргументами и умолчаниями:

| Аргумент | Смысл (как у zapret2) | По умолчанию |
|---|---|---|
| `fails=N` | столько неудач ключа, не дальше `time` секунд друг от друга, переводят его на следующую руку (после последней — снова на 1) | 3 |
| `time=S` | окно между неудачами | 60 |
| `final=N` | на руке N ключ остаётся (у zapret2 — аргумент `final` у экземпляра со `strategy=N`) | — |
| `key=NAME` | общая таблица ключей у профилей с одним `NAME` (`key` у zapret2) | своя у профиля (`p<номер>`) |
| `nld=N`, `reqhost` | ключ `standard_hostkey`: имя хоста потока, обрезанное до N-го уровня (`nld=2`: `static.intranet.microsoft.com` → `microsoft.com`), иначе адрес сервера; с `reqhost` поток без имени ключа не получает и идёт без стратегии | — |
| `maxseq`, `inseq`, `retrans`, `udp_out`, `udp_in`, `no_rst`, `no_http_redirect`, `reset` | детекторы `standard_success_detector` и `standard_failure_detector` | 32768, 4096, 3, 4, 1 |

Детекторы смотрят пакеты потока в очереди (как `circular` в nfqws2) до
первого решения, одно решение на соединение:

- неудача: `retrans` ретрансмиссий клиента с данными до `maxseq`
  (с `reset` — ещё RST клиенту); входящий RST с относительным `seq` от 1
  до `inseq` (без `no_rst`); HTTP-ответ 302/307 на сайт другого домена
  второго уровня (без `no_http_redirect`); UDP — `udp_out` датаграмм
  клиента и не больше `udp_in` ответных;
- успех: клиент отправил больше `maxseq` или сервер больше `inseq`; UDP —
  больше `udp_in` ответных. Успех сбрасывает счётчик неудач ключа.

Ключ хранится в таблице `ИМЯ_ТАБЛИЦЫ/КЛЮЧ` (`p1/ultrasurf.example`),
общей для всех воркеров (`--ext-workers`, под мьютексом); руку потока
берёт каждый его пакет, поэтому SYN (имени ещё нет) идёт по ключу адреса,
а пакеты после ClientHello — по ключу имени. В событиях — `ext_arm`
(`key`, `arm`, `arms`, `final`) при каждой смене руки; в `ext_status` —
`tuner` (`keys`, `rotations`, `state`), в `ext_keys` — `tuner`, массив
`{key, arm, fails}` (до 1000). `--ext-state` — строки JSON
`{"key":"p1/ultrasurf.example","arm":2}`.

Отличия от `circular` zapret2:

- Руки — стратегии Geneva (с x-действиями), а не экземпляры
  `--lua-desync` со `strategy=N`; `final` — аргумент селектора.
- Таблица ключей по умолчанию — `p<номер профиля>` (у zapret2 — имя
  экземпляра `circular`); память не ограничена у zapret2 и ограничена
  65 536 ключами здесь: ключ сверх предела идёт по руке 1 без подсчёта.
- `--ext-state` — нового нет у zapret2 (его `autostate` живёт до
  перезапуска). Ключ из файла с рукой больше числа рук профиля начинает с
  руки 1.
- С `--server-side` тюнер ничего не считает (все потоки на руке 1).
- `apply --ext` (захват с диска) делает тот же шаг, но RST по `reset` не
  отправляет.
- Хирургический путь (`--ext-healthy-mark`, X10b) не отпускает поток
  профиля с руками, пока детекторы не решили.
- Как и у zapret2, маленький ответ HTTPS, который сервер заканчивает RST
  (стенд: ~2 КБ), — неудача при `inseq` по умолчанию: для таких сайтов
  `inseq` меньше их ответа.

Проверки: юнит-тесты (`tests/test_tuner.c`: разбор аргументов, ротация,
одна неудача на соединение, окно `time`, `final`, ретрансмиссии, RST,
редирект, UDP, ключи `nld` и `reqhost`, `--ext-state`, движок на
поддельном бэкенде; `tests/test_autolist.c`: `apply`); e2e
`tests/e2e/censors_x.sh tune`: против цензоров 14 (RST) и 18 (302) первая
попытка на руке 1 заблокирована, ключ переходит на руку 2, вторая
проходит; после перезапуска с `--ext-state` (и двумя воркерами) рука 2
сразу; с `NFQWS2_DIR` то же самое делает `circular` официального nfqws2.
Thompson sampling, предложения и подтверждение — X11b (ниже); GA в
фоне и CUSUM — X11c.

## Автотюнер: Thompson sampling и согласие (X11b)

```
sudo geneva run --ext -p 443 --filter-tcp 443 \
    --ext-arm '\/' \
    --ext-arm '[TCP:flags:PA]-xsplit{pos=1}-| \/' \
    --ext-arm '[TCP:flags:PA]-xdisorder{pos=1,midsld}-| \/' \
    --ext-tune ts --ext-state /opt/var/geneva/tune.jsonl
```

`--ext-tune ts[:АРГ..]` — второй селектор. Те же детекторы и тот же ключ,
что у `rr` (X11a), но вместо ротации по счётчику у каждого ключа и каждой
руки — апостериорное распределение Beta(1 + A, 1 + B), где A и B —
успехи и неудачи руки с дисконтом: при каждом исходе ключа старые
умножаются на `gamma`. Каждое соединение ключа берёт руку
одной выборкой Томпсона (у руки с лучшим распределением шанс выше) и
держит её до конца, а исход соединения (одно решение детекторов на
соединение) идёт в распределение этой руки. Соединение, чей ключ сменился
с адреса на имя (после ClientHello), выбирает руку заново, для ключа
имени.

| Аргумент | Смысл | По умолчанию |
|---|---|---|
| `gamma=X` | дисконт старых исходов (0.5–1; 1 — без забывания) | 0.98 |
| `p=X` | ключ оседает на руке, когда она лучшая с вероятностью ≥ X (200 выборок)… | 0.95 |
| `min_succ=N` | …и у неё не меньше N успехов (с дисконтом) | 5 |
| `propose` | (и у `rr`) смена руки ждёт согласия | — |

Осевший ключ (событие `ext_tuned` с рукой) отдаёт её всем соединениям,
исходы по-прежнему считаются; если рука перестала быть самой вероятной
лучшей или эта вероятность упала ниже 0.5, ключ снова перебирает
(`ext_tuned` с `arm` 0). `fails`, `time` и `final` — аргументы `rr`, с
`ts` они ошибка.

**Согласие (`propose`).** Ключ с `propose` работает на одобренной руке
(сначала 1). Там, где без `propose` рука сменилась бы (`rr` — `fails`
неудач; `ts` — неудача одобренной руки: следующая рука — выборка
Томпсона среди остальных), тюнер присылает событие `ext_proposal` (`id`,
`key`, `from`, `to`) и ничего не меняет. Команда `ext_approve
{"proposal": id}` (или `geneva ctl ext_approve proposal=ID`) переводит
ключ на руку `to` (событие `ext_arm`), `ext_reject` оставляет ключ на
месте и больше эту руку ему не предлагает; `ext_proposals` их
перечисляет. У ключа одно предложение за раз. Так zapret-gui и AutoTuner
показывают предложение пользователю, прежде чем трафик пойдёт по новой
стратегии (раздел 4.8 плана).

`--ext-state` хранит у ключей `ts` ещё `a`, `b` (A и B рук), `treat`
(рука, на которой ключ осел) и `rejected` (отклонённые руки). В
`ext_keys` — `mean` (средняя апостериорная доля успеха рук), `settled`,
`proposal`, `rejected`; в `ext_status` — `proposals` и `settled`.

Отличия от раздела 4.7 плана:

- Априори — Beta(1, 1) у всех рук: базы оценок (`sdb`) и иерархии ключей
  (родительские /24, домен) у тюнера пока нет.
- Нет `--ext-replay` (повтор первого payload через слот оценщика): руку
  испытывают живые соединения ключа.
- Тюнер работает только на ключах профилей с `--ext-arm`; любой ключ,
  найденный `--ext-auto`, лечит X11c (ниже), GA при плохих руках — X11d.
- Выборка Томпсона берёт случайные числа из генератора потока (`--rng-seed`
  делает её воспроизводимой на одном воркере).

Проверки: юнит-тесты (`tests/test_tuner.c`: аргументы, `ts` находит
единственную рабочую из 4 рук и оседает на ней, затем рука ломается и
ключ переходит на другую; `propose` у `rr` и `ts` с `ext_approve`,
`ext_reject` и пропуском отклонённой руки; `--ext-state` с `a`, `b`,
`rejected`); e2e `tests/e2e/censors_x.sh tunets` (три руки против
цензора 14: ключ оседает на рабочей, после чего проходят 3 из 3) и
`tunepropose` (блокировка, `ext_proposal`, до согласия рука прежняя,
`geneva ctl ext_approve`, запрос проходит).

## Лечение: `--ext-auto propose|apply` (X11c)

```
sudo geneva run --ext --ext-auto apply -s '\/' -p 80,443 --proto tcp,udp \
    --events /tmp/geneva.jsonl --control unix:/tmp/geneva.sock
```

`observe` (X9) только сообщает о блокировках. `apply` их ещё и лечит:
адрес или имя хоста, который детектор признал заблокированным
(`ext_impaired`, уровни `ip` и `host`), получает руки встроенного
портфеля для своего класса, и его новые соединения перебирают их.

| Классы | Руки (по порядку номеров) |
|---|---|
| `RETRANS`, `RST_IN`, `RST_INJECT`, `REDIRECT`, `FREEZE_N`, `THROTTLE` (TCP) | 1 `[TCP:flags:PA]-xsplit{pos=1}-\| \/`; 2 `[TCP:flags:PA]-xdisorder{pos=1,midsld}-\| \/`; 3 `[TCP:flags:PA]-xsplit{pos=method+2}-\| \/`; 4 `[TCP:flags:PA]-xsplit{pos=2,6,10,14,18,22,26,30}-\| \/`; 5 `[TCP:flags:PA]-xsend{ipfrag;ipfrag_pos_tcp=24}(drop,)-\| \/` |
| `UDP_NOANSWER` (QUIC) | 6 `[UDP:dport:443]-xfake{blob=fake_quic_initial;repeats=2}-\| \/`; 7 `[UDP:dport:443]-xsend{ipfrag;ipfrag_pos_udp=8}(drop,)-\| \/` |
| `BLACKHOLE_SYN`, `ICMP_PROHIBIT`, `DNS_POISON` | нет: стратегия на пакетах соединения тут не поможет |

Состояния ключа (событие `ext_treat`):

- `trial` — каждое новое соединение ключа берёт руку одной выборкой
  Томпсона из Beta(1 + A, 1 + B) (успехи и неудачи руки с дисконтом
  0.98) и держит её до конца; исход соединения по детектору (`ext_flow`
  или успех) идёт в её распределение. Соединение с именем хоста, у
  которого своё лечение, берёт руку заново после ClientHello или
  `Host:`, для имени.
- `treat` — рука лучшая с вероятностью ≥ 0.95 (200 выборок) или, когда
  несколько рук работают одинаково и эта вероятность не растёт, её
  апостериорное среднее ≥ 0.75; в обоих случаях у руки ≥ 3 успеха. Её
  получают все соединения ключа. CUSUM по её неудачам (k = 0.3, h = 2:
  три неудачи подряд) значит, что цензор изменился: ключ снова в `trial`
  с чистой статистикой.
- `untreatable` — рук для класса нет, или каждая рука провалилась дважды
  без единого успеха. Соединения идут без лечения; перепроверка (`trial`)
  через 1, 2, 4 … 64 минуты (`retry_s`), успех сбрасывает интервал.

Ключ на лечении остаётся заблокированным в политике хирургического пути
(X10b), даже когда детектор видит его здоровым: так его соединения
по-прежнему проходят через очередь. Ключ в `untreatable` или в ожидании
согласия, ставший здоровым, лечение забывает.

**`propose`.** То же, но ключ сначала в `proposed`: событие
`ext_proposal` (`id`, `key`, `kind: "treat"`, `class`, `arms`), и ничего
не меняется до `ext_approve {"proposal": id}` (`geneva ctl ext_approve
proposal=ID`), после которого ключ в `trial`. `ext_reject` оставляет ключ
без лечения (`untreatable` без перепроверки), пока он не станет здоровым и
снова заблокированным. Номера предложений у тюнера (X11b) и лечения общие,
`ext_proposals` перечисляет и те, и другие.

Что видно: `ext_status` — `treat` (`mode`, `arms`, сколько ключей в каждом
состоянии), `ext_keys` — `treat` (ключи с состоянием, классом, рукой и
`arms`: попытки и успехи каждой руки).

Условия:

- Лечатся только соединения, которые попадают в очередь: порты `-p`,
  протоколы `--proto` (для QUIC — `udp`). У соединения должна быть
  стратегия: `-s` (подойдёт пустая `\/`) или профиль; профиль со своими
  руками `--ext-arm` лечение не трогает — у него свой тюнер.
- Соединения другого протокола того же адреса не лечатся (у класса руки
  одного протокола).
- Лечение живёт в памяти процесса: в `--ext-state` оно не пишется, в
  конфиги zapret-gui и на роутер ничего не сохраняется.
- Ключей на лечении — до 4096; место освобождает ключ, ставший здоровым
  без лечения. Исход соединения, начатого до смены состояния ключа
  (`treat`, возврат к перебору), не считается.

Изменение детектора (X9a): короткий ответ сервера (меньше
`incoming_maxseq`), после которого сервер закрыл соединение FIN или RST
со своим TTL, — успех. Раньше такой поток оставался без исхода, а лечению
нужны и успехи. У zapret2 (`standard_failure_detector`) RST в пределах
`inseq` — неудача.

Отличия от разделов 4.7 и 4.8 плана:

- Портфель — 7 рук выше, а не вся сетка `blockcheck2`; априори Beta(1, 1),
  без `sdb` и родительских ключей.
- Ключи — только адрес и имя (не порт и не /24): стратегия на всём порту
  задела бы здоровые адреса.
- `treat` уже при 3 успехах (в плане 5), и есть второе условие
  (апостериорное среднее): против лабораторных цензоров работают сразу
  несколько рук, и P(лучшая) между ними не доходит до 0.95.
- Все руки плохи — `untreatable`, а с `--ext-ga` — генетический поиск (X11d, ниже).
- CUSUM возвращает ключ к перебору, но вредную руку (хуже, чем без
  лечения) не исключает: исхода без лечения для сравнения нет.
- Нет `--ext-scope` и `--ext-replay`: лечатся все ключи, руки испытывают
  живые соединения.

Проверки: юнит-тесты (`tests/test_treat.c`: из пяти рук работает одна —
ключ находит её; четыре одинаково хороших; CUSUM; `untreatable` с
перепроверками 60 и 120 с; классы без рук; QUIC; имя раньше адреса;
`propose` с `ext_approve`, `ext_reject` и `ext_proposals` без тюнера;
`tests/test_detect.c`: успех по FIN и RST); e2e `tests/e2e/censors_x.sh
treat` (`--ext-auto apply` против цензоров 14, 15, 16, 18, 19, 20: ключ
доходит до `treat` за 5–10 запросов, затем проходят 3 из 3; 17 —
`untreatable` за 2 соединения) и `treatpropose` (до согласия запрос
блокируется, после `geneva ctl ext_approve` ключ лечится).

## Строгий успех и генетический поиск: `--ext-ga` (X11d)

```
sudo geneva run --ext --ext-auto apply --ext-ga --ext-seccomp=0 -s '\/' -p 80,443 \
    --events /tmp/geneva.jsonl
```

**FREEZE_N и THROTTLE.** Соединение заблокированного так ключа сначала
выглядит удачным: ответ пришёл, а заморозка или замедление наступают
позже. Поэтому у ключа в одном из этих классов успех соединения
предварительный (`provisional` во внутреннем событии детектора), и
лечение его не считает. Засчитывается только «строгий» успех: поток
передал больше `--freeze-bytes` (FREEZE_N) или шёл быстрее порога
замедления (THROTTLE) — тогда детектор сообщает об успехе ещё раз, один
раз на поток. Поток, закрытый раньше первого окна скорости, судится по
средней скорости за всю жизнь. Неудача (заморозка, замедление)
считается как раньше. e2e: цензоры 12 и 13 лечатся (`censors_x.sh
treat`).

**`--ext-ga[=POP:GEN]`** (Linux, с `--ext-auto propose|apply`). Ключ,
у которого провалились все руки портфеля, не сразу `untreatable`, а
переходит в `search`: ему ищет стратегию `geneva evolve`, запущенный
дочерним процессом (сам бинарник, `/proc/self/exe`). Поиск:

- один за раз; остальные ключи в `search` ждут очереди;
- популяция и поколения — `POP:GEN` (по умолчанию `50:5`; 2–1000 и
  1–100);
- проба — `tls` для порта 443, иначе `http`, на адрес ключа (`--ip`) с
  его именем (`--host`, если ключ — имя), таймаут 2 с;
- начальная популяция — клиентские TCP-стратегии библиотеки Geneva
  (`--load-from`, вместе с лабораторными), одно дерево (`--in-trees 1`);
- своя очередь `--queue` + 64, та же метка `--mark` и тот же firewall;
  свои правила evolve снимает сам при выходе, а `geneva run` при выходе
  посылает ему SIGTERM и ждёт;
- лог — `<--log-file>.ga`, если `--log-file` задан; `--rng-seed`
  передаётся.

Найденная стратегия (фитнес > 0) — рука 8 этого ключа: ключ снова в
`trial`, но перебирает только её (`ext_keys`: `ga` — её текст). Дальше
как обычно: `treat` после 3 успехов или `untreatable` после двух неудач.
С `propose` найденная стратегия — новое предложение (`ext_proposal` с
`arms: 1` и `strategy`, ключ в `proposed`): её соединения ключа получат
только после `ext_approve`. Ничего не найдено, evolve не запустился или упал — `untreatable` с
перепроверкой. Поиск у ключа один, пока тот не станет здоровым;
перепроверка возвращает весь портфель вместе с рукой 8.

**`--ext-treat-arms N,..`** (с `--ext-auto propose|apply`) — номера рук
портфеля (1–7), которые лечение использует; остальные пропускаются.

Что видно: `ext_status` — `treat.search` (ключей в поиске) и `treat.ga`
(включён ли поиск); событие `ext_treat` с `state: "search"` («every arm
failed: the genetic search waits its turn», «the genetic search runs»),
затем `trial` («the genetic search found an arm») или `untreatable`
(«found nothing», «did not start»).

Условия:

- `--ext-seccomp=0`: seccomp запрещает `fork`/`execve`. Без `--user` и
  `--uid`: evolve ставит правила и нужен root.
- Нужна свободная очередь `--queue` + 64 (до 65535).
- Пробы evolve идут на заблокированный адрес из того же хоста; на
  роутере это соединения самого роутера, а не клиентов.
- В конфиги zapret-gui и на роутер найденное не сохраняется.

Отличия от раздела 4.8 плана: поиск — не в фоне по `sdb`, а отдельным
процессом на ключ; найденная рука не идёт в портфель других ключей;
пробник — встроенный `tls`/`http`, а не повтор соединений клиентов.

Проверки: юнит-тесты (`tests/test_treat.c`: `treat_provisional`,
`treat_allow`, `treat_ga` — поддельный evolve: найденная рука ведёт ключ
в `treat`, отрицательный фитнес — в `untreatable`, с `propose` — новое
предложение; `tests/test_detect.c`:
предварительные и строгие успехи FREEZE_N, быстрый поток THROTTLE,
ошибки `--ext-ga` и `--ext-treat-arms`); e2e `censors_x.sh treat`
(цензоры 12 и 13 лечатся) и `treatga` (цензор 19 со словом `/`, руки
1,3,4: все проваливаются, ключ в `search`, `--ext-ga=4:1` находит руку,
после выхода ни evolve, ни правил).

## Списки адресов: `geneva resolve`, `geneva ip2net` (X12a)

```
geneva resolve --ext --family 46 --threads 20 < domains.txt > ips.txt
geneva ip2net --ext -4 < ips.txt > nets4.txt
```

Перенос `mdig` и `ip2net` zapret2: тот же ввод, тот же вывод, те же
умолчания. Скрипты загрузки списков (antifilter, antizapret и т.п.)
остаются в zapret-gui (решение 11.6).

**`geneva resolve --ext`** читает имена со stdin, по одному в строке, и
печатает их адреса системным резолвером (`getaddrinfo`), по строке на
адрес. Адрес или подсеть нужного семейства из списка выводится как есть
(`/32` и `/128` отбрасываются), неверное имя пропускается.

| Опция | Что | По умолчанию |
|---|---|---|
| `--family 4\|6\|46` | адреса IPv4, IPv6 или оба | `4` |
| `--threads N` | потоков, 1–100 (порядок строк тогда произвольный) | 1 |
| `--eagain N`, `--eagain-delay MS` | повторы при `EAI_AGAIN` и пауза | 10, 500 |
| `--verbose` | ход работы в stderr | — |
| `--stats N` | счётчики в stderr каждые N имён и в конце | — |
| `--log-resolved FILE`, `--log-failed FILE` | имена, которые разрешились и нет | — |
| `--dns-make-query NAME` | вывести DNS-запрос A (с `--family 6` — AAAA) в двоичном виде | — |
| `--dns-parse-query` | прочитать двоичный DNS-ответ со stdin и вывести его адреса A и AAAA | — |

**`geneva ip2net --ext`** читает адреса со stdin и сворачивает их в
подсети: для каждого адреса берётся самая маленькая подсеть в диапазоне
длин префикса, где адресов достаточно. Подсети (`A/N`) и диапазоны
(`A-B`) из ввода выводятся как есть и первыми.

| Опция | Что | По умолчанию |
|---|---|---|
| `-4`, `-6` | список IPv4 или IPv6 | `-4` |
| `--prefix-length MIN[-MAX]` | длины префикса | 22–30 (IPv4), 56–64 (IPv6) |
| `--v4-threshold MUL/DIV` | IPv4: подсеть, если в ней не меньше MUL/DIV её адресов | 3/4 |
| `--v6-threshold N` | IPv6: подсеть, если в ней не меньше N адресов | 5 |

Отличия от zapret2: опции в форме geneva (`--family 4` и `--family=4`;
однодефисные `-family=4` не принимаются) и коды выхода geneva (2 — опции,
6 — ввод-вывод, 1 — ответ DNS не разобран). Нужен `--ext`. Имена
разрешает libc сборки, и ответы разных libc расходятся: статический
бинарник релиза zapret2 (musl) на раннере CI не разрешает даже
`localhost`, а сборка geneva с glibc разрешает. Поэтому `tools.sh`
сверяет с `mdig` адреса, подсети и неверные имена, а разрешение имён
проверяет отдельно.

Проверки: юнит-тесты (`tests/test_tools.c`: ожидаемые строки получены
самими `ip2net` и `mdig` zapret2); `tests/e2e/tools.sh` (без root, с
`NFQWS2_DIR`) сравнивает вывод с бинарниками официального релиза zapret2
на 100 случайных списках каждого семейства с разными опциями, на списке
имён и адресов (`--family 4`, `6`, `46`, журналы) и на DNS-запросах.

## Проверка блокировок: `geneva blockcheck` (X12b)

```
sudo geneva blockcheck --ext rutracker.org
sudo geneva blockcheck --ext --test http,tls12,tls13 --level quick -d a.example,b.example
sudo geneva blockcheck --ext --test http3 --curl /opt/curl/bin/curl rutracker.org
geneva blockcheck --ext --print-grid --test tls12 > grid.tsv
```

Перенос `blockcheck2.sh` zapret2 с его сеткой стратегий
`blockcheck2.d/standard`: для каждого домена, версии IP и теста (HTTP,
TLS 1.2, TLS 1.3, HTTP/3) сначала проверка без обхода, затем все скрипты
по порядку — 10 (`http_*`), 15 (`tcpseg` с повторами), 17 (`oob`), 20
(`multisplit`, `multidisorder`), 23 (`seqovl`), 24 (`syndata`), 25
(`fake` с TTL 1–12, autottl 1–5 и fooling), 30 (`fakedsplit`,
`fakeddisorder`), 35 (`hostfakesplit`), 50, 55, 60 (фейк перед
разрезами), 90 (QUIC: фейки, фрагменты). Каждая строка nfqws2 переводится
в стратегию geneva и проверяется через вычислитель (как `geneva eval`):
пробы `http`, `tls` с версией 1.2 или 1.3, для HTTP/3 — `exec` с curl
`--http3-only`. Управление скриптов перенесено строка в строку: те же
циклы и выходы из них, переменные `need_*` между скриптами (фейк с
разрезом не пробуется, если разрез сработал и без фейка), второй проход
TLS 1.2 с `wssize`, если первый ничего не нашёл.

**Перевод.** Каждый `--lua-desync` — x-действие (X5a–X5c), следующие
вкладываются в его поддерево, как в цепочке nfqws2, где следующий
экземпляр видит и отброшенный пакет. Фильтры `--payload` и `--out-range`
перед экземплярами — `xwhen` вокруг тех, что их делят; «иначе» — то, что
после них:

```
--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:ip_ttl=3 --lua-desync=multisplit:pos=2
  [FLOW:n:a]-xwhen{iff=L7:payload:tls_client_hello}(xfake{blob=fake_default_tls;ip_ttl=3}(xsplit{pos=2},),)-| \/
--payload=quic_initial --lua-desync=send:ipfrag:ipfrag_pos_udp=8 --lua-desync=drop
  [FLOW:n:a]-xwhen{iff=L7:payload:quic_initial}(xsend{ipfrag;ipfrag_pos_udp=8}(drop,),)-| \/
--payload=empty --out-range=<s1 --lua-desync=send:tcp_md5
  [FLOW:n:a]-xwhen{iff=FLOW:n:<s1}(xwhen{iff=L7:payload:empty}(xsend{tcp_md5},),)-| \/
```

Функции: `fake`→`xfake`, `multisplit`→`xsplit`,
`multidisorder[_legacy]`→`xdisorder[{legacy}]`, `fakedsplit`,
`fakeddisorder`, `hostfakesplit`→`xhostfake`, `tcpseg`, `oob`, `syndata`,
`wssize`, `send`, `pktmod`→`xmod`, `http_hostcase`/`domcase`/
`methodeol`/`unixeol`→`xhttp{...}` (`spell=` — значение `hostcase`),
`drop`. Аргументы переносятся как есть, `tls_mod` становится `tlsmod`.

**Отчёт** — как у `blockcheck2.sh`: SUMMARY (все сработавшие строки
каждого теста, «not working», «working without bypass»), а для нескольких
доменов COMMON (строки, сработавшие на всех) и COVERAGE (на скольких
доменах). Под каждой рабочей строкой nfqws2 — её стратегия geneva
(`  geneva: ...`). Ход проверки (строки, исходы проб) — в stderr.
`--json` — отчёт одним объектом: `summary` (`domain`, `test`, `nfqws2` и
`strategy` или `result`), `common`, `coverage` (`count`). Код выхода 0,
если что-то работает (стратегия или сайт без обхода), 1 — нет.

| Опция | Что | По умолчанию |
|---|---|---|
| `-d`, `--domain ИМЯ,..` или имена в конце | домены | `rutracker.org` |
| `--test СПИСОК` | `http`, `tls12`, `tls13`, `http3` | `http,tls12` |
| `--ipv 4\|6\|46` | версии IP | `4` |
| `--level` | `veryquick`, `quick`, `standard`, `force` (SCANLEVEL) | `standard` |
| `--repeats N` | попыток каждой строки, нужны все (REPEATS); `quick` и `veryquick` бросают после первой неудачи | 1 |
| `--min-ttl`, `--max-ttl` | TTL фейков (0 — без тестов TTL) | 1, 12 |
| `--min-autottl-delta`, `--max-autottl-delta` | autottl (0 — без них) | 1, 5 |
| `--fake-repeats N` | FAKE_REPEATS | 1 |
| `--multidisorder-legacy` | MULTIDISORDER=multidisorder_legacy | — |
| `--scripts N,..` | только эти скрипты (как NOTEST_* наоборот) | все |
| `--ip АДРЕС` | соединяться с этим адресом, а не с адресом домена (curl `--connect-to`) | — |
| `--timeout СЕК` | тайм-аут пробы (CURL_MAX_TIME) | 2 |
| `--curl ПУТЬ` | curl для `http3` (с HTTP/3) и для DoH | `curl` |
| `--skip-dnscheck` | без проверки DNS (SKIP_DNSCHECK) | — |
| `--dns-servers IP,..` | публичные DNS проверки (DNSCHECK_DNS) | `8.8.8.8,1.1.1.1,77.88.8.1` |
| `--dns-domains ИМЯ,..` | домены проверки (DNSCHECK_DOM) | `pornhub.com,ej.ru,rutracker.org,www.torproject.org,bbc.com` |
| `--secure-dns 0\|1` | имена тестов через DoH: 1 — всегда, 0 — никогда (SECURE_DNS) | при подмене DNS |
| `--doh URL` | этот DoH без поиска (DOH_SERVER) | — |
| `--doh-servers URL,..` | DoH для поиска рабочего (DOH_SERVERS) | cloudflare, google, quad9, adguard, yandex |
| `--skip-ipblock` | без тестов блокировки по порту и IP (SKIP_IPBLOCK) | — |
| `--unblocked-domain ИМЯ` | незаблокированный домен тестов по IP (UNBLOCKED_DOM) | `iana.org` |
| `--print-grid` | без проб: строки сетки (`nfqws2<TAB>geneva`) так, будто ничего не сработало; без root | — |
| `--grid-ok ФАЙЛ` | с `--print-grid`: эти строки nfqws2 «работают» (для сверки с zapret2) | — |
| `--queue`, `--mark`, `--firewall`, `--local-ports` | как у `geneva eval` | 311, … |

**Проверки вокруг стратегий (X12c)** — как в `blockcheck2.sh`:

- **DNS** (`check_dns`), до всех тестов: системный резолвер должен
  отвечать (`iana.org`); первый ответивший публичный DNS из
  `--dns-servers` сравнивается с системным по доменам `--dns-domains`
  (адрес системного, которого нет у публичного, — MISMATCH); без
  публичного DNS — только системный. Затем адреса всех доменов должны
  быть разными (цензор часто отдаёт один адрес заглушки). Итог — «DNS
  looks good» или «POSSIBLE DNS HIJACK DETECTED».
- **DoH** (`SECURE_DNS`): при подмене DNS (или `--secure-dns 1`) ищется
  рабочий сервер из `--doh-servers` (запрос `iana.org`), и все имена
  тестов разрешаются через него: curl, RFC 8484 GET
  (`URL?dns=BASE64URL`, `accept: application/dns-message`). Нет рабочего —
  выход с кодом 1, как `exitp 7` у zapret2. Имена кешируются на весь
  прогон (`mdig_cache`).
- **Порт** (`check_domain_port_block`): перед тестом `http` — соединение
  TCP с каждым адресом домена на порт 80, перед первым тестом TLS — на
  443 (2 с, как `nc -z -w 2`): «connects» или «does not connect».
- **IP** (`check_dpi_ip_block`), для `http`, `tls12`, `tls13`, когда домен
  без обхода не открылся: незаблокированный домен на своём адресе, затем
  проверяемый домен на адресе незаблокированного и незаблокированный на
  каждом адресе проверяемого. Ответ HTTP здесь не оценивается (как
  `detail` у zapret2): нужен любой целый ответ.

В `--json` — `dns` (`system`, `public`, `spoofed`), `doh` (сервер или
`null`) и `checks`: `kind` (`port` или `ip`), `test`, `ipv`, `domain`
(какое имя), `ip`, `on` (чей это адрес), `port`, `ok`, `detail`.

Проба HTTP проверяет ответ как `curl_test_http`: код 400 («сервер
получил фейки») — неудача, перенаправление 301/302/307/308 на чужой
домен — подмена цензором; относительное и на тот же домен (с поддоменами)
— успех. Опции `--ext-blob` и прочие X3–X4 работают как у `eval`.

Отличия от zapret2:

- Проверка DNS без `ping` и `nslookup`: публичный DNS «работает», если
  ответил на `iana.org` (UDP, свой клиент DNS); адреса сравниваются
  целиком, а не подстрокой (`grep -F` у zapret2 считает `1.2.3.4` частью
  `11.2.3.45`).
- Сверх zapret2: публичный DNS спрашивается и по TCP; если у ответов UDP и
  TCP нет ни одного общего адреса — это подмена на пути (DPI отвечает на
  UDP раньше сервера), DNS считается подменённым. Один общий адрес —
  балансировщик, не подмена.
- Сверх zapret2: тесты по IP читаются за пользователя — строки
  «geneva: ... the block is by its IP» (домен прошёл на чужом адресе),
  «... by its name (DPI)» (не прошёл и там), «... the address is
  blocked» (адрес домена не пропускает и чужое имя). Решение остаётся за
  человеком: тест «requires manual interpretation», как и у zapret2.
- Адрес теста — первый из ответа DNS, а не случайный (`mdig_resolve`
  берёт случайный); `--ip` задаёт его явно и для тестов порта и IP.
- Нет рабочего DoH — код 1, а не 7 (7 у geneva — «цель доступна без
  стратегии» у `evolve`).
- Строки с Lua-кодом (`luaexec`: шаблон seqovl `padencap` в 23-seqovl,
  3 строки на каждый проход TLS) перевести нельзя (решение 11.1): они
  считаются неудачными, в ходе проверки — «geneva: none». `--lua-init` с
  `tls_mod(..., 'rnd')` для шаблона seqovl опускается: шаблон — блоб
  `fake_default_tls` как есть.
- Список маркеров в `pos` у `fakedsplit` и `fakeddisorder`
  (`method+2,midsld`) zapret2 читает как первый маркер (`atoi` в
  `posmarker_parse`); перевод делает так же, хотя в стратегии geneva
  такой `pos` — ошибка разбора.
- Фейки — свои блобы geneva (решение 11.3), а не `fake_default_*` zapret2;
  `--blob=` файлов (FAKE_HTTP и т.п.) нет, свой блоб — `--ext-blob` с
  тем же именем.
- Успех — проба geneva: целый ответ HTTP, полёт сервера после ServerHello
  в TLS (без проверки сертификата), код 0 у curl для HTTP/3. Попытки
  (`--repeats`) идут одна за другой (PARALLEL нет).
- Порт-фильтр, ipset и прочее окружение nfqws2 не нужны: вычислитель
  перехватывает только соединения пробы (локальные порты). Правила
  снимаются после каждого теста.
- Опции — в форме geneva, а не переменные окружения.

Проверки: юнит-тесты (`tests/test_blockcheck.c`: перевод строк, каждая
строка сетки на всех уровнях переводится и разбирается, ярлыки `need_`,
уровни, отчёт); `tests/e2e/blockcheck_grid.sh` (без root, с `NFQWS2_DIR`)
запускает сами скрипты `blockcheck2.d/standard` релиза zapret2 с
заглушкой `pktws_curl_test_update` и сравнивает последовательность строк
с `--print-grid` на всех уровнях, IPv4 и IPv6, когда ничего не работает
и когда работает каждая 7-я, 61-я или 397-я строка; раздел `blockcheck`
`tests/e2e/censors_x.sh` прогоняет `geneva blockcheck` против цензоров 18
(HTTP, перенаправление) и 14 (SNI) и без цензора, а проверки X12c — против
цензора 17 (блокировка по IP): DNS стенда даёт всем именам один адрес
(подмена), DoH-сервер стенда (Python, https) — настоящие, через curl.

## Двусторонняя обфускация (X13a)

Функции `zapret-obfs.lua` zapret2 как x-действия. Обфускация нужна с
обеих сторон: одно и то же действие стоит в исходящем лесу одного конца
и во входящем лесу другого (на другом конце может быть и nfqws2 с теми же
функциями Lua — e2e проверяет оба варианта).

```
# клиент WireGuard (порт сервера 51820)
geneva run --ext -p 51820 --proto udp \
  -s '[UDP:dport:51820]-xwgobfs{secret=пароль}-| \/ [UDP:sport:51820]-xwgobfs{secret=пароль}-|'
# сервер
geneva run --ext --server-side -p 51820 --proto udp \
  -s '[UDP:sport:51820]-xwgobfs{secret=пароль}-| \/ [UDP:dport:51820]-xwgobfs{secret=пароль}-|'
```

| Действие | Функция zapret2 | Параметры | Что делает |
|---|---|---|---|
| `xwgobfs` | `wgobfs` | `secret` (обязателен), `padmin` (0), `padmax` (16) | рукопожатия WireGuard (initiation, response, cookie) шифруются AES-128-GCM с ключом HKDF-SHA256(соль `wgobfs_salt`, `secret`) и случайной добивкой: `iv(12) tag(16) E(длина(2) сообщение добивка)`; входящий UDP подходящего размера расшифровывается, если сходится тег. Данные и keepalive идут как есть. Нужна сборка с криптографией (не `EXT_CRYPTO=0`) |
| `xippxor` | `ippxor` | `ippxor=N` (0–255, обязателен), `dataxor=БЛОБ`, `rebuild` | номер протокола IP XOR N, payload TCP, UDP или ICMP XOR блоб (с начала); пакет, ставший TCP, UDP или ICMP, разбирается заново как он (всегда, `rebuild` принимается для совместимости) |
| `xudp2icmp` | `udp2icmp` | `server=0\|1` (0), `ctype`, `stype`, `ccode`, `scode` (парами), `dataxor` | датаграмма UDP уходит сообщением ICMP того же размера: от клиента — `ctype` (echo request), от сервера — `stype` (echo reply); в слове данных ICMP — `sport^dport` и порт другой стороны; принятое ICMP своего типа и кода становится UDP |
| `xsynhide` | `synhide` | `magic=x2\|urp\|opt\|tsecr` (`x2`), `x2` (1), `kind` (172), `opt=HEX`, `xorseq=HEX4`, `ghost`, `ghost6`, `synack` | SYN клиента уходит как ACK с меткой (бит `x2`, `urgptr`, опция TCP или младшие байты `tsecr`), сервер возвращает SYN; с `synack` так же SYN,ACK сервера идёт как RST,ACK; `ghost` — сначала копия SYN с этим TTL (пробить NAT) |

Чтобы пакеты другого протокола дошли до движка, профиль берёт их
фильтрами: `--filter-ipp 209` для `xippxor` (UDP 17 XOR 192),
`--filter-icmp 0` (клиент) или `8` (сервер) для `xudp2icmp`. Триггер
входящего дерева — по тому, что придёт: `[IP:proto:209]`,
`[IP:proto:1]`, `[TCP:dport:8080]` (у `xsynhide` метка `x2=1` — флаг NS,
триггер `[TCP:flags:A]` его не примет).

Отличия от zapret2:

- Режима сервера у `xudp2icmp` по умолчанию из `--server` nfqws2 нет:
  сторона задаётся параметром `server`.
- Пакет с новым протоколом собирается заново из байтов: длины и
  контрольные суммы (TCP, UDP, ICMP, ICMPv6 — с псевдозаголовком) считаются
  для нового протокола. `xippxor` перед сменой номера считает сумму TCP,
  UDP или ICMP по их правилам, так что другой конец получает пакет с
  верной суммой и без `dataxor`.
- `xsynhide` не перекармливает conntrack geneva восстановленным SYN
  (zapret2 вызывает `conntrack_feed`): conntrack видит пакет таким, каким
  он пришёл.
- IV для `xwgobfs` — из системного генератора (`/dev/urandom`, на
  Windows `RtlGenRandom`), как `bcryptorandom` у zapret2; если он
  недоступен, сообщение уходит незашифрованным (повтор IV ломает AES-GCM).
- `xsynhide{magic=opt}`: если опция не помещается в 40 байт опций TCP,
  SYN уходит как есть и в журнал пишется `no room for the option`
  (иначе ушёл бы ACK без метки).

Проверки: юнит-тесты (`tests/test_obfs.c`: каждое действие туда и
обратно для IPv4 и IPv6, неверный ключ, свои типы ICMP, все режимы метки
`xsynhide`, `synack`, `ghost`); `tests/e2e/obfs.sh` (в CI с официальным
nfqws2): эхо UDP через `xwgobfs`, `xippxor`, `xudp2icmp` и HTTP через
`xsynhide` между двумя geneva и между geneva и nfqws2 с функциями Lua
zapret2; счётчики на сервере до очереди показывают на проводе только
обфусцированные пакеты.

## Код zapret2

Распознавание L7, маркеры, сборка, conntrack и x-действия
(`src/ext/l7.c`, `markers.c`, `xl7.c`, `ctrack.c`, `xact.c`, `xact_tcp.c`,
`xact_http.c`, `xact_misc.c`, `xact_comb.c`, `xact_seq.c` (функция `oob`), `profile.c`, `hostlist.c`, `ipset.c`, `lists.c`, `autolist.c`, `ipcache.c`, список системных вызовов seccomp в `svc.c`, `tls.c` — `tls_mod`, `genhost`, `tls_clone.c`, `tools.c` — `mdig` и `ip2net`, `blockcheck.c` — сетка `blockcheck2.d/standard`, `xact_obfs.c` — `zapret-obfs.lua`) перенесены из zapret2
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
