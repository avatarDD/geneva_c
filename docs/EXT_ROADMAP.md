# geneva_c `--ext`: паритет с zapret2 и автономная адаптация

Статус: **в работе**, редакция 2. Решения раздела 11 приняты (11.7);
этапы реализуются по порядку раздела 8, ход — в `CHANGELOG.md`; сделанное
описано в `docs/EXT.md` (готовы X0–X3).

Редакция 1 опиралась на README, мануал и начало `zapret-antidpi.lua`. Эта
редакция построена на **полном чтении исходников** zapret2
([bol-van/zapret2](https://github.com/bol-van/zapret2), коммит `038c97e`,
5 ноября 2026, лицензия MIT):

- все Lua-файлы: `zapret-lib.lua` (2739 строк), `zapret-antidpi.lua` (1250),
  `zapret-auto.lua` (577), `zapret-obfs.lua` (552), `zapret-pcap.lua`,
  `zapret-tests.lua`;
- C-ядро `nfq2/`: `nfqws.c` (опции, главный цикл), `desync.c` (конвейер
  пакета), `protocol.c` (L7, маркеры, TLS-моды, QUIC), `conntrack.c`,
  `lua.c` (C API для Lua), `darkmagic.c` (raw-отправка, WinDivert, SSID),
  `hostlist.c`, `ipset.c`, `filter.c`, `pools.c`, `timer.c`, `sec.c`,
  `packet_queue.c`, `crypto/`;
- `blockcheck2.sh` и все тесты `blockcheck2.d/standard/*`;
- правила firewall и конфиг: `common/nft.sh`, `common/ipt.sh`,
  `config.default`, `ipset/`, `init.d/`, `files/fake/`.

**Главное требование этой редакции: функциональность geneva_c с `--ext`
не хуже zapret2.** Поэтому раздел 3 — построчная матрица паритета: каждая
возможность zapret2 из исходников, её состояние в geneva_c и этап, который
её закрывает. Строка закрыта, только когда на неё есть тест (раздел 7.4).
Если возможность заменяется другой, а не повторяется, замена
обосновывается и выносится на решение (раздел 11).

Содержание:

1. [Рамки и ограничения](#1-рамки-и-ограничения)
2. [Теоретическая база](#2-теоретическая-база)
3. [Фаза 1. Полная инвентаризация zapret2 и матрица паритета](#3-фаза-1-полная-инвентаризация-zapret2-и-матрица-паритета)
4. [Фаза 2. Архитектура `--ext`](#4-фаза-2-архитектура---ext)
5. [Расширение языка стратегий и алгоритмы](#5-расширение-языка-стратегий-и-алгоритмы)
6. [Фаза 3. Реализация](#6-фаза-3-реализация)
7. [Фаза 4. Конвейер качества](#7-фаза-4-конвейер-качества)
8. [Поэтапный план](#8-поэтапный-план)
9. [Метрики](#9-метрики)
10. [Риски](#10-риски)
11. [Решения, которые нужны от владельца проекта](#11-решения-которые-нужны-от-владельца-проекта)
12. [Литература](#12-литература)

---

## 1. Рамки и ограничения

Правила `AGENTS.md` действуют без исключений. Что из них следует для
паритета:

| Правило | Следствие |
|---|---|
| C11 и только libc | zapret2 тянет libnetfilter_queue, libmnl, zlib и Lua/LuaJIT. В geneva_c всё это пишется своё: NFLOG, ctnetlink, nl80211 поверх уже существующего netlink-кода; inflate (RFC 1951/1952) для `.gz`-списков; AES-128/256 (ECB/CTR/GCM; QUIC и `wgobfs` — 128, MTProto — 256-битный CTR), SHA-256, HMAC, HKDF для QUIC Initial, MTProto и обфускации. Атомики — только `<stdatomic.h>` размера указателя. |
| Geneva — эталон | Без `--ext` вывод всех команд байт-в-байт прежний, кроме раздела «Extensions (with --ext):» в конце `--help` (решение 11.7.7; golden-тест, этап X0); дифференциальный тест против Python-Geneva остаётся зелёным. |
| Сторонние бинарники только из официальных релизов | Дифференциальные e2e против `nfqws2` используют только бинарники из официальных релизов zapret2 и запускаются в CI-стенде, не на роутере пользователя. |
| Ничего не применяется без подтверждения | Автотюнер по умолчанию только наблюдает (раздел 4.8). Автосписки, как `--hostlist-auto` zapret2, пишутся в файл только по явно указанному пути. |
| Правила firewall снимаются при выходе | Это относится и к новым правилам (NFLOG, ct mark, отказ от ICMP time-exceeded, исключение из flow offload), и к sysctl (`nf_conntrack_acct`): всё возвращается при выходе. |
| Юнит-тесты и e2e | Тест на каждую строку матрицы паритета, раздел 7.4. |
| Документация пользователя на русском | `docs/EXT.md` и README (RU/EN) — на этапе X14. |

---

## 2. Теоретическая база

### 2.1. Модель DPI

DPI — посредник, который восстанавливает состояние потока независимо от
конечных узлов и при этом ограничен (Ptacek & Newsham, 1998; Wang et al.,
2017; Bock et al., 2019):

1. по ресурсам: смотрит первые пакеты или байты, собирает сегменты и
   фрагменты ограниченно, вытесняет TCB по времени;
2. по точности: не повторяет стек получателя (суммы, окно seq, PAWS,
   TCP-MD5, достижимость по TTL, порядок сегментов, расширения IPv6);
3. по решению: сигнатура (SNI, Host), статистика потока, адрес назначения.

Классы атак:

- **insertion** — DPI видит пакет, сервер его отбрасывает: фейк с малым TTL,
  с плохой суммой, с seq/ack вне окна, со старым timestamp, с MD5-опцией,
  без флага ACK. Так работают `fake`, `fakedsplit`, `fakeddisorder`,
  `hostfakesplit`, `syndata`, `rst` в zapret2 и `duplicate`+`tamper` в Geneva;
- **evasion** — сервер принимает, DPI не понимает: сегментация по
  смысловым позициям, обратный порядок, перекрытие seq (`seqovl`),
  IP-фрагментация с разрезом внутри транспортного заголовка, расширения
  IPv6, OOB, мелкое окно (`wsize`/`wssize`), правки HTTP;
- **TCB desync/teardown** (Geneva): ложный RST/FIN/SYN сносит или сбивает
  состояние у DPI.

Ни Geneva, ни zapret2 не выходят за эти классы. Разница — в способе поиска
(GA или ручная сетка `blockcheck2`) и в точности позиционирования (байты
или маркеры L7).

### 2.2. Что видит клиент

| Вмешательство | Наблюдаемый признак | Нужен L7 |
|---|---|---|
| блокировка IP/порта | SYN без SYN-ACK; UDP без ответа | нет |
| отбрасывание по содержимому | первый payload ретранслируется без ACK | нет |
| инъекция RST | RST вскоре после первого payload; TTL и IP ID не как у SYN-ACK | нет |
| редирект на страницу блокировки | HTTP 302/307 на домен с другим SLD (так считает и zapret2: `HttpReplyLooksLikeDPIRedirect`) | HTTP |
| подмена DNS | первый ответ с другим TTL, второй позже, адрес-заглушка | DNS |
| заморозка после N байт | входящий поток стоит на узкой полосе объёма (≈14–24 КБ у части ТСПУ, по наблюдениям сообщества), соединение не закрыто | нет |
| замедление | устойчивое плато скорости при здоровых параллельных потоках | нет |
| UDP-блокировка | `out ≥ k`, `in ≤ 1` (порог zapret2: 4 и 1) | нет |

Детекторы zapret2 (`standard_failure_detector`, autohostlist) покрывают
первые четыре строки и UDP. **Заморозку и замедление zapret2 не
распознаёт**: успехом считается входящий относительный seq больше 4096
(`inseq`), и поток, замёрзший на 16 КБ, засчитывается как успешный. Это
главная точка, где geneva_c может быть сильнее (разделы 4.4 и 5.4).

### 2.3. Что лечится

Лечатся решения DPI, зависящие от содержимого и реконструкции потока.
Блокировка по адресу назначения без учёта содержимого и шейпинг по
AS/подсети не лечатся. Детектор помечает такие ключи `untreatable`, а не
перебирает стратегии вечно (это и есть «ручная интерпретация» IP-block
тестов `blockcheck2`, только автоматическая).

### 2.4. Адаптация

zapret2 адаптируется так: `circular` перебирает стратегии одного хоста по
кругу при достижении порога неудач (`fails=3` за `time=60` с). Состояние
`autostate` живёт в памяти процесса, обучения между хостами нет.
geneva_c ставит задачу как нестационарный многорукий бандит: Thompson
sampling с дисконтом, априори из базы стратегий, иерархическое объединение
по ключам, CUSUM для обнаружения смены поведения DPI, генетический поиск
новых «рук», когда старые исчерпаны (Russo et al., 2018; Page, 1954).
Режим `circular` zapret2 остаётся как один из селекторов (`select=rr`).

---

## 3. Фаза 1. Полная инвентаризация zapret2 и матрица паритета

### 3.1. Конвейер пакета nfqws2 (по `desync.c`)

1. **Перехват**: NFQUEUE (`--qnum`, libnetfilter_queue, `FAIL_OPEN`,
   `Q_MAXLEN=4096`, буфер 1 МБ), divert-сокет на FreeBSD/OpenBSD, WinDivert
   на Windows. Сгенерированные пакеты (`mark & desync_fwmark`, по умолчанию
   `0x40000000`) пропускаются сразу.
2. **Разбор**: IPv4/IPv6 с цепочкой расширений, TCP, UDP, ICMP, прочие IP.
   Если ОС передала неверную сумму (WinDivert, FreeBSD), неизменённый пакет
   получает исправленную сумму.
3. **Conntrack в userspace** (uthash, таймауты SYN 60, EST 300, FIN 60,
   UDP 60 с; `--ctrack-timeouts`). На каждую сторону: счётчики пакетов,
   пакетов с данными и байт, seq0, последний seq, позиция, максимум
   позиции (по нему ищутся ретрансмиссии), окно, масштаб, MSS,
   флаг переполнения 2 ГБ. Без conntrack направление угадывается по
   наличию `ifin`/`ifout`; `--server` переворачивает роли.
4. **Профиль**: первый подходящий по `fwmark/mask`, L3, L7, портам/ICMP/
   протоколу, SSID, hostlist, ipset. Профиль кэшируется в conntrack и
   ищется заново, когда становятся известны L7-протокол или имя хоста;
   при смене профиля сбрасываются отсечки.
5. **Имя хоста**: SNI, HTTP Host; для потоков без имени — из `ipcache`,
   который пополняется разбором DNS-ответов (`--ipcache-hostname`).
6. **L7**: в исходящих — TLS ClientHello (и частичный), HTTP-запрос, XMPP,
   BitTorrent, MTProto (только первый пакет с данными, проверка через
   AES-CTR); во входящих — TLS ServerHello, HTTP-ответ, XMPP, BT. UDP — QUIC
   Initial (с расшифровкой), Discord IP discovery, STUN, DNS, DHT, DTLS,
   uTP, WireGuard (5 типов).
7. **Сборка (reasm)**: многопакетный TLS ClientHello (до `TCP_MAX_REASM` =
   16 КБ) и несколько QUIC Initial (до `UDP_MAX_REASM` = 16 КБ) с фрагментами CRYPTO (`QUICDefragCrypto`).
   Пакеты удерживаются в очереди `delayed` (до 64), после сборки
   проигрываются через стратегию: первый кусок получает собранные данные
   (`reasm_data`), остальные отбрасываются (`replay_drop`). Сборка
   отменяется, если окно сервера меньше ожидаемого размера.
8. **Цепочка Lua-инстансов** профиля: у каждого свой диапазон
   `--in-range/--out-range` и фильтр `--payload`. Инстансы видят общую
   таблицу `desync`, каждый может отправить свои пакеты и вернуть вердикт
   PASS, MODIFY или DROP (агрегация DROP > MODIFY > PASS). Инстанс может
   отключить себя для потока (`instance_cutoff`); когда отключены все,
   поток больше не попадает в Lua. Оркестраторы читают и отменяют план
   выполнения (`execution_plan`, `execution_plan_cancel`).
9. **Postnat-обход**: отбросить первый пакет соединения в postnat-цепочке
   значит сломать conntrack. Поэтому вместо DROP пакет уходит с
   `ip proto 255, ttl 1`.
10. **Автосписок**: ретрансмиссии запроса (в первых `retrans_maxseq` байтах),
    RST или DPI-редирект в первых `incoming_maxseq` входящих байтах, UDP
    `out ≥ udp_out` при `in ≤ udp_in`. После `fail_threshold` неудач за
    `fail_time` хост дописывается в файл; ретранслирующему клиенту можно
    послать RST, чтобы не ждать таймаута.

Однопоточный цикл `select` по сокету очереди и таймерам Lua; вердикт
синхронный (отложенных вердиктов нет, задержка только через
`send:delay=` и таймеры).

### 3.2. Матрица паритета

Обозначения: **есть** — равноценно уже в geneva_c; **частично** —
возможность есть, но слабее; **нет**. Колонка «Этап» — этап раздела 8,
который закрывает строку. ID строк используются в тестах (раздел 7.4).

#### A. Перехват и платформы

| ID | zapret2 | geneva_c сейчас | План `--ext` | Этап |
|---|---|---|---|---|
| A1 | NFQUEUE, `--qnum`, `FAIL_OPEN`, `NETLINK_NO_ENOBUFS` | есть (свой netlink, `--queue`, `--queue-maxlen`, bypass) | многоочередной режим (раздел 6.2) | X10 |
| A2 | WinDivert, `--wf-iface`, `--wf-l3`, `--wf-tcp-in/out`, `--wf-udp-in/out`, `--wf-icmp-in/out`, `--wf-ipp-in/out` | частично: фильтр строится из `-p/--proto/--dir/-4/-6`, есть `--filter` | генератор фильтра с теми же опциями (имена `--wf-*` принимаются под `--ext`) | X7 |
| A3 | `--wf-raw`, `--wf-raw-part` (OR), `--wf-raw-filter` (AND) | частично: `--filter`, `--filter-file` | `--wf-raw-part`, `--wf-raw-filter` как сборка выражения | X7 |
| A4 | `--wf-tcp-empty` (пустые ACK не перехватываются), `--wf-filter-lan`, `--wf-filter-loopback`, `--wf-priority`, `--wf-dup-check`, `--wf-save` | частично: loopback исключён всегда, `--priority` есть | остальные флаги; `--wf-save` = `geneva fw print` в файл | X7 |
| A5 | BSD: divert-сокет FreeBSD (PF_DIVERT в 14+), OpenBSD pf `divert-packet`, `--port`, `--sockarg` | нет | бэкенд `eng_divert.c` | X13 |
| A6 | Android-сборка, вывод лога в logcat | нет (Linux-сборка запускается, но без logcat) | статическая сборка под Android (zig), лог в stderr/файл; logcat — по решению 11.4 | X13 |
| A7 | raw-отправка: `IPPROTO_RAW`, `SO_MARK`, `IP_NODEFRAG`, `IP_FREEBIND`/`IPV6_FREEBIND`, `SO_PRIORITY 6`, `--bind-fix4/6` (`SO_BINDTODEVICE` на `ifout`), `--fwmark` | частично: raw, `SO_MARK`, `IP_NODEFRAG`, `--mark` | `FREEBIND`, `SO_PRIORITY`, `--bind-fix4/6`, выбор `ifout` из исходного пакета | X5 |
| A8 | Linux: `ifin/ifout` из NFQUEUE (ioctl `SIOCGIFNAME` через один сокет) | нет в стратегии | `ifin/ifout` доступны в условиях и для `bind-fix` | X3 |

#### B. Профили и фильтры

| ID | zapret2 | geneva_c сейчас | План | Этап |
|---|---|---|---|---|
| B1 | несколько профилей в одном процессе: `--new[=name]`, `--skip`, `--name`, `--template`, `--import`, `--cookie` | нет: одна стратегия на процесс (на Windows — несколько процессов с `--priority`) | профили `--ext-profile` в файле или те же опции CLI под `--ext` (4.3) | X6 |
| B2 | `--filter-l3=ipv4,ipv6` | частично: `-4`/`-6` на процесс | на профиль | X6 |
| B3 | `--filter-tcp/udp=[~]p1-p2,...\|*` | частично: `-p` на процесс | на профиль, с отрицанием `~` и `*` | X6 |
| B4 | `--filter-icmp=type[:code]\|*`, `--filter-ipp=proto` | нет | на профиль; перехват ICMP и прочих IP-протоколов | X6 |
| B5 | `--filter-l7=proto,...` (16 протоколов) | нет | на профиль (зависит от E) | X6 |
| B6 | `--filter-mark=mark[/mask]` (Linux) | нет | на профиль | X6 |
| B7 | `--filter-ssid`, `--filter-ssid-neg` (Linux nl80211, Windows WLAN API); `--ssid-filter`, `--nlm-filter` (Windows NLM) | нет | `ext/wlan.c`: nl80211 по netlink без libmnl; Windows WLAN API и NLM через `LoadLibrary` | X13 |
| B8 | повторный поиск профиля при обнаружении L7 или имени хоста (не больше двух смен) | нет | то же, в `ext/profile.c` | X6 |
| B9 | `@config` / `$config` — опции из файла; `--comment`; `--dry-run` | нет | `@FILE`, `--dry-run` (проверка и выход), `--comment` | X7 |

#### C. Списки и кэши

| ID | zapret2 | geneva_c сейчас | План | Этап |
|---|---|---|---|---|
| C1 | `--hostlist`, `--hostlist-domains`, `--hostlist-exclude`, `--hostlist-exclude-domains`; поддомены автоматически | нет | `ext/hostlist.c`: хэш по суффиксам домена | X6 |
| C2 | `--ipset`, `--ipset-ip`, `--ipset-exclude`, `--ipset-exclude-ip`; CIDR v4/v6 | нет | `ext/ipset.c`: отсортированные интервалы, двоичный поиск | X6 |
| C3 | списки в gzip | нет | свой inflate (`ext/inflate.c`, RFC 1951/1952) | X6 |
| C4 | перечитывание списков по изменению файла и по SIGHUP | частично: SIGHUP перечитывает стратегию | то же для списков; команда `reload_lists` | X6 |
| C5 | `--hostlist-auto` + `fail-threshold` (3), `fail-time` (60), `retrans-threshold` (3), `retrans-maxseq` (32768), `retrans-reset` (1), `incoming-maxseq` (4096), `udp-out` (4), `udp-in` (1), `--hostlist-auto-debug` | нет | те же параметры; детекторы раздела 4.4 их расширяют | X6, X9 |
| C6 | `ipcache`: ip→имя хоста из DNS-ответов, ip+интерфейс→TTL для autottl на первом пакете; `--ipcache-lifetime` (7200), `--ipcache-hostname` | нет | `ext/ipcache.c`, те же опции | X6 |
| C7 | `--payload-disable`, `--reasm-disable` | нет | те же опции | X4 |

#### D. Conntrack, позиции, диапазоны

| ID | zapret2 | geneva_c сейчас | План | Этап |
|---|---|---|---|---|
| D1 | userspace conntrack с ролями и таймаутами `--ctrack-timeouts=S:E:F[:U]`, `--ctrack-disable` | частично: `flowtab` только для `--first` на Windows | `ext/ctrack.c` для обеих ОС (раздел 4.2) | X3 |
| D2 | счётчики режимов `n` (пакеты), `d` (пакеты с данными), `b` (байты), `s` (отн. seq), `p` (позиция данных), `a`, `x` — в обе стороны | нет (`--first N` — только пакеты, одно значение) | поля триггера `FLOW:` (5.1) | X3 |
| D3 | `--in-range`, `--out-range` на каждый инстанс: `mX-mY`, `mX<mY`, `-mY`, `<mY`, `mX-` | нет | диапазоны в триггерах и в комбинаторе `xwhen` | X3, X5 |
| D4 | обнаружение ретрансмиссий (`uppos_prev ≥ pos`) | нет | в `ctrack` | X3 |
| D5 | MSS обеих сторон → `tcp_mss` для собственной сегментации (минимум из двух; 1220 по умолчанию для v6) | нет | в `ctrack`; все x-действия режут по нему | X3 |
| D6 | входящий TTL сервера на поток (`incoming_ttl`) | нет | в `ctrack` + `ipcache` | X3 |
| D7 | отсечка инстанса и всей цепочки на поток (`instance_cutoff`, `lua_cutoff`, флаги `b_lua_in/out_cutoff`) | нет (gas общий на стратегию, не на поток) | отсечка поддерева на поток; при отсечке всех — поток мимо стратегии | X3 |
| D8 | состояние на поток для функций (`track.lua_state`) | нет | слот состояния x-действия на поток (фиксированный размер, без кучи) | X3 |
| D9 | дамп conntrack по SIGUSR1, счётчики неудач по SIGUSR2 | нет | команды `ext_flows`, `ext_keys` управляющего сокета (сигналы заняты: SIGUSR1 — `stats`) | X7 |

#### E. L7-распознавание и сборка

| ID | zapret2 | geneva_c сейчас | План | Этап |
|---|---|---|---|---|
| E1 | 16 L7-протоколов: `http tls dtls quic wireguard dht discord stun xmpp dns mtproto bt utp_bt` + `all unknown known` | нет (только поля DNS) | `ext/l7_*.c`, те же имена | X4 |
| E2 | 31 тип payload (`http_req … utp_bt_handshake`, `empty`, `unknown`, `known`, `ipv4/ipv6/icmp`) и фильтр `--payload` с отрицанием `~` | нет | `L7:payload:` в триггерах | X4 |
| E3 | частичный TLS ClientHello; сборка многопакетного CH (Kyber), удержание пакетов, проигрывание кусков | нет | `ext/reasm.c` (6.3) | X4 |
| E4 | расшифровка QUIC Initial (v1, v2, черновики), дефрагментация CRYPTO, сборка нескольких Initial, извлечение SNI | нет | `ext/quic.c` + `ext/crypto/*` | X4 |
| E5 | MTProto по первому пакету (AES-256-CTR) | нет | `ext/l7_mtproto.c` | X4 |
| E6 | разбор DNS-ответов в `ipcache` | нет | `ext/l7_dns.c` → C6 | X6 |
| E7 | распознавание DPI-редиректа (302/307 на другой SLD) | нет | детектор `REDIRECT` (4.4) | X9 |
| E8 | связанные ICMP (unreachable, time exceeded, redirect, too big) относятся к потоку вложенного пакета | нет | в `ctrack` | X3 |

#### F. Маркеры позиций

| ID | zapret2 | geneva_c сейчас | План | Этап |
|---|---|---|---|---|
| F1 | `abs` (N, отрицательные — от конца), `host`, `endhost`, `sld`, `midsld`, `endsld` (HTTP и TLS), `method` (HTTP, с пропуском ведущих `\r\n`), `extlen`, `sniext` (TLS); смещения `±N`; списки сортируются, повторы убираются; позиция 0 удаляется | нет (`fragment{tcp:N}`, `-1` — пополам) | `ext/markers.c`, те же имена и семантика | X4 |
| F2 | `resolve_range` (две позиции) для `tcpseg`, `hostfakesplit` | нет | то же | X4 |

#### G. Функции десинхронизации (`zapret-antidpi.lua`)

Каждая функция получает x-действие с тем же поведением и параметрами
(синтаксис — раздел 5.1). Отличия заданы по ссылке на исходник.

| ID | Функция zapret2 и параметры | geneva_c сейчас | x-действие | Этап |
|---|---|---|---|---|
| G1 | `drop` | есть (`drop`) | `drop` + условия | — |
| G2 | `send` (`delay=` мс; копия с fooling, ip_id, ipfrag, repeats) | частично: `duplicate`, `sleep` | `xsend{delay,…std}` | X5 |
| G3 | `pktmod` (fooling на текущий пакет) | частично: `tamper` по полям | `xmod{…fooling}` | X5 |
| G4 | `http_domcase` (чередование регистра в Host) | нет | `xhttp{domcase}` | X5 |
| G5 | `http_hostcase` (`spell=` 4 символа) | нет | `xhttp{hostcase=hoSt}` | X5 |
| G6 | `http_methodeol` (`\r\n` перед методом, укорачивает User-Agent) | нет | `xhttp{methodeol}` | X5 |
| G7 | `http_unixeol` (`\n` вместо `\r\n`, длина сохраняется через UA) | нет | `xhttp{unixeol}` | X5 |
| G8 | `synack_split` (`mode=syn\|synack\|acksyn`) | частично: собирается из `duplicate`+`tamper` | `xsynacksplit{mode}` | X5 |
| G9 | `synack` (в ответ на SYN шлёт SYN,ACK) | частично: так же | `xsynack` | X5 |
| G10 | `wsize` (`wsize=`, `scale=` на SYN,ACK; масштаб только уменьшается) | частично: входящий `tamper{TCP:window}` | `xwsize{wsize,scale}` | X5 |
| G11 | `wssize` (то же на исходящих до первого payload, `forced_cutoff=`) | нет | `xwssize{…}` | X5 |
| G12 | `tls_client_hello_clone` (`blob, fallback, sni_snt, sni_snt_new, sni_del_ext, sni_del, sni_first, sni_last`) | нет | `xtlsclone{…}` на `ext/tls.c` (полный разбор и сборка) | X5 |
| G13 | `syndata` (`blob` по умолчанию 16 нулей, `tls_mod`) | частично: `tamper{TCP:load}` на SYN | `xsyndata{blob,tls_mod}` | X5 |
| G14 | `rst` (`rstack`) | частично: `duplicate`+`tamper{TCP:flags:R}` | `xrst{rstack,…std}` | X5 |
| G15 | `fake` (`blob, optional, tls_mod=rnd,rndsni,sni=,dupsid,padencap`; сегментация по MSS) | частично: `duplicate`+`tamper{load}` без блобов | `xfake{…}` | X5 |
| G16 | `multisplit` (`pos` по умолчанию `2`, `seqovl=N`, `seqovl_pattern`, `blob`, `optional`, `nodrop`) | частично: `fragment` на 2 части, абсолютные позиции | `xsplit{…}` | X5 |
| G17 | `multidisorder` (обратный порядок; `seqovl` — маркер, меньше первой позиции) | частично: `fragment{…:False}` | `xdisorder{…}` | X5 |
| G18 | `multidisorder_legacy` (порядок nfqws1 по кускам сборки) | нет | `xdisorder{legacy}` | X5 |
| G19 | `hostfakesplit` (`host=` шаблон, `midhost`, `nofake1/2`, `disorder_after`; fooling только на фейки, ipfrag только на настоящий хост) | нет | `xhostfake{…}` | X5 |
| G20 | `fakedsplit` (`pos, nofake1..4, pattern, seqovl, seqovl_pattern`; порядок fake1 real1 fake1 fake2 real2 fake2) | нет | `xfakedsplit{…}` | X5 |
| G21 | `fakeddisorder` (обратный порядок) | нет | `xfakeddisorder{…}` | X5 |
| G22 | `tcpseg` (`pos` — диапазон, `seqovl`; дополнительный сегмент без отбрасывания оригинала) | нет | `xtcpseg{…}` | X5 |
| G23 | `oob` (`char/byte`, `urp=b\|e\|маркер`; с SYN: исходящий seq−1 на весь поток, входящий ack+1) | частично: `tamper{TCP:urgptr}` без сдвига seq | `xoob{…}` на seqtrack (6.3) | X8 |
| G24 | `udplen` (`min, max, increment` ±, `pattern, pattern_offset`) | частично: `tamper{UDP:load}` без длины | `xudplen{…}` | X5 |
| G25 | `dht_dn` (`dn=N`, правка bencode) | нет | `xdhtdn{dn}` | X5 |
| G26 | вспомогательные: `pass`, `luaexec`, `pktdebug`, `argdebug`, `posdebug`, `detect_payload_str` | частично: `trace`, лог `-v` | `xlog{…}` (события `ext_pkt`), `xtag{pattern,payload}` (своя метка payload); `luaexec` — решение 11.1 | X5 |

#### H. Стандартные аргументы (fooling, отправка, ip_id, ipfrag)

| ID | zapret2 | geneva_c сейчас | План | Этап |
|---|---|---|---|---|
| H1 | `dir=in\|out\|any` (по умолчанию out); `payload=` (по умолчанию `known`) | частично: направление леса | общие аргументы x-действий | X5 |
| H2 | `ip_ttl`, `ip6_ttl` | есть (`tamper{IP:ttl}`, IPv6 `hlim`) | плюс аргумент `ttl=` | X5 |
| H3 | `ip_autottl=delta,min-max` (исходный TTL 64/128/255 по порогам 33–64, 97–128, >223; кэш на поток; отказ, если фейк дошёл бы до сервера) | нет | `ttl=auto:delta:min-max`, тот же алгоритм | X5 |
| H4 | `ip6_hopbyhop[=hex]`, `ip6_hopbyhop2`, `ip6_destopt`, `ip6_destopt2`, `ip6_routing`, `ip6_ah` (6+8N / 6+4N байт) | нет | `ip6ext=` с теми же правилами размещения | X5 |
| H5 | `tcp_seq=N`, `tcp_ack=N` (прибавить к текущему) | частично: `tamper{…:add:N}` | аргументы `seq=`, `ack=` | X5 |
| H6 | `tcp_ts=N` (сдвиг TSval) | частично: `tamper{TCP:options-timestamp}` (замена) | `ts=` (сдвиг) | X5 |
| H7 | `tcp_md5[=hex]` (16 байт; по умолчанию случайные) | частично: `options-md5header` | `md5[=hex]` | X5 |
| H8 | `tcp_flags_set/unset=` | частично: `tamper{TCP:flags:replace}` | `flags+=`, `flags-=` | X5 |
| H9 | `tcp_ts_up` (TS-опция первой; «badack без badseq») | нет | `tsup` | X5 |
| H10 | `tcp_nop_del` (убрать NOP ради места под MD5) | нет | `nopdel` | X5 |
| H11 | `badsum` | есть (`tamper{TCP:chksum:corrupt}`) | плюс аргумент `badsum` | X5 |
| H12 | `fool=функция` (свой fooling) | нет | — (решение 11.1); набор встроенных fooling расширяемый | — |
| H13 | `repeats`, `ifout`, `fwmark` (бит десинхронизации ставится всегда) | нет | общие аргументы | X5 |
| H14 | `ip_id=seq\|rnd\|zero\|none`, `ip_id_conn` (непрерывный seq на поток) | частично: `tamper{IP:id}` | `ipid=` | X5 |
| H15 | `ipfrag[=функция]`, `ipfrag_disorder`, `ipfrag_pos_tcp` (32), `_udp` (8), `_icmp` (8), `ipfrag_pos` (32), `ipfrag_next` (иной next-header второго фрагмента v6) | частично: `fragment{ip:…}` (позиция в блоках по 8 байт, overlap) | `ipfrag=` с теми же параметрами | X5 |
| H16 | сегментация любого отправляемого payload по `tcp_mss` с сохранением URG/`urp` | нет | общая функция отправки | X5 |
| H17 | префиксы аргументов `#blob` (длина), `%blob` (значение), `\` (экранирование) | нет | те же префиксы в параметрах x-действий | X5 |

#### J. Блобы и TLS-модификации

| ID | zapret2 | geneva_c сейчас | План | Этап |
|---|---|---|---|---|
| J1 | `--blob=name:[+ofs]@file\|0xHEX` (до 16 КБ) | нет | то же | X5 |
| J2 | встроенные `fake_default_tls` (680 байт), `fake_default_http`, `fake_default_quic`; файлы `files/fake/*.bin` (QUIC разных клиентов, DTLS, DHT, Discord, STUN, WireGuard, RDP, NTP, ISAKMP, BGP, bitcoin…) | частично: в `probe.c` есть сборщик ClientHello | свои генераторы блобов (TLS CH, HTTP, QUIC Initial с шифрованием); набор `.bin` — данные, не код: брать файлы zapret2 (MIT) или генерировать (решение 11.3) | X5 |
| J3 | `tls_mod`: `rnd`, `rndsni`, `sni=`, `dupsid`, `padencap`, `none` | нет | `tlsmod=` в `xfake`, `xsyndata` | X5 |
| J4 | полный разбор и сборка TLS (записи, многозаписные handshake, расширения SNI/ALPN/versions/groups/sigalgs/key_share/psk_modes/QUIC TP) | нет | `ext/tls.c` | X5 |
| J5 | `genhost(len, шаблон)` — случайное имя той же длины | нет | в `ext/tls.c` / `xhostfake` | X5 |

#### K. Оркестрация и автоматика (`zapret-auto.lua`)

| ID | zapret2 | geneva_c сейчас | План | Этап |
|---|---|---|---|---|
| K1 | `circular`: стратегии с тегом `strategy=N`, ротация по хосту при `fails` (3) за `time` (60), `final` останавливает ротацию; `key`, `hostkey` | нет | селектор `select=rr` автотюнера с теми же параметрами (4.7) | X11 |
| K2 | `standard_hostkey`: имя хоста, `nld=N` (обрезать до N-го уровня), `reqhost`, иначе IP | нет | ключ политики (4.6): `key=host[:nld=N]\|ip\|ip24\|…` | X11 |
| K3 | `standard_failure_detector`: ретрансмиссии (`retrans`, `maxseq`), RST в `inseq`, DPI-редирект, UDP `udp_out/udp_in`, `reset` (RST ретранслятору), `no_rst`, `no_http_redirect` | нет | детекторы 4.4 (включают эти и добавляют заморозку, замедление, инъекцию с отпечатком TTL) | X9 |
| K4 | `standard_success_detector`: исходящий seq > `maxseq`, входящий > `inseq`, UDP `in > udp_in` | нет | критерии успеха класса (4.7), с поправкой на заморозку | X9 |
| K5 | пользовательские детекторы по имени функции | нет | — (решение 11.1); набор детекторов параметризуется | — |
| K6 | `condition` (`iff, neg, instances`), `per_instance_condition` (`cond, cond_neg`), `stopif`, `repeater` (`repeats, instances, iff, neg, stop, clear`) | нет | комбинаторы `xwhen`, `xstop`, `xrepeat` (5.1) | X5 |
| K7 | условия `cond_true/false`, `cond_random` (`percent`), `cond_payload_str` (`pattern`), `cond_tcp_has_ts`, `cond_lua` | нет | условия `rnd:P`, `has:строка`, `tcpts`, триггерные выражения; `cond_lua` — решение 11.1 | X5 |
| K8 | вложенные оркестраторы, `execution_plan` | нет | вложенные комбинаторы в дереве | X5 |
| K9 | состояние хостов `autostate` в памяти процесса | частично: `sdb` (JSONL на диске) | политика + `sdb` + `--ext-state FILE` | X11 |

#### L. Двусторонняя обфускация (`zapret-obfs.lua`)

Нужен такой же процесс на другом конце.

| ID | zapret2 | geneva_c сейчас | План | Этап |
|---|---|---|---|---|
| L1 | `wgobfs` (`secret, padmin, padmax`): AES-GCM с ключом HKDF шифрует рукопожатия WireGuard и меняет их размер | нет | `xwgobfs{…}` на `ext/crypto` | X13 |
| L2 | `ippxor` (`ippxor, dataxor, rebuild`): XOR номера протокола и payload | нет | `xippxor{…}` | X13 |
| L3 | `udp2icmp` (`ctype, ccode, stype, scode, dataxor, server, cgnat, id_lifetime`): UDP внутри ICMP echo того же размера | нет | `xudp2icmp{…}` | X13 |
| L4 | `synhide` (`ghost, ghost6, synack, magic=x2\|urp\|opt\|tsecr, x2, kind, opt, xorseq`): SYN идёт как ACK с меткой и восстанавливается на сервере | нет | `xsynhide{…}` | X13 |

#### M. Служебное

| ID | zapret2 | geneva_c сейчас | План | Этап |
|---|---|---|---|---|
| M1 | `pcap` (`file, keep`) — запись пакетов функцией | частично: `--pcap` пишет выпущенные пакеты | `xpcap{file}` в любой точке дерева | X5 |
| M2 | таймеры Lua (`timer_set/del/info/enum`), `--intercept=0` (только Lua и таймеры) | частично: `sleep`, отложенные вердикты | не переносится: таймеры нужны отложенной отправке, а она есть | — |
| M3 | Lua C API: dissect/reconstruct, rawsend, csum, crypto, gzip, resolve_pos, get_source_ip, get_ifaddrs, time | — | не переносится как API; возможности доступны через x-действия (решение 11.1) | — |
| M4 | `zapret-tests.lua` — самопроверка C API | частично: `make test` | юнит-тесты на каждый модуль | все |

#### N. Безопасность и эксплуатация

| ID | zapret2 | geneva_c сейчас | План | Этап |
|---|---|---|---|---|
| N1 | `--user`, `--uid=uid[:gid,…]` (сброс root), сброс capabilities | нет | `--user/--uid`, сохранить только `CAP_NET_ADMIN`, `CAP_NET_RAW` (через syscall, без libcap) | X7 |
| N2 | seccomp-фильтр (`sec_harden`, таблица архитектур включая mips, arm, ppc, riscv64, loongarch) | нет | `ext/sec.c`; Linux, отключаемо | X7 |
| N3 | Windows: low-integrity песочница, удаление привилегий токена | нет | `ext/sec_win.c` после открытия хэндла | X13 |
| N4 | `--daemon`, `--pidfile`, `--chdir`, systemd `sd_notify` | нет: демонизацию делают init-скрипты | `--pidfile`; `READY=1` в `$NOTIFY_SOCKET` (unix-датаграмма, без libsystemd); `--daemon` | X7 |
| N5 | `--debug=0\|1\|syslog\|android\|@file` | частично: `--log-file`, уровни | `--log-target syslog` (датаграммы в `/dev/log`) | X7 |
| N6 | `--fuzz=N` — встроенный фаззер обработки пакетов | нет | цели libFuzzer/AFL++ в `tests/fuzz/` (7.2) и `geneva selftest --fuzz N` | X7 |
| N7 | `--writable[=dir]` (каталог для скриптов) | — | не нужен (скриптов нет); пути файлов задаются явно | — |
| N8 | `--lua-gc` | — | не нужен (нет Lua; память фиксированная) | — |

#### O. Правила firewall (`common/nft.sh`, `common/ipt.sh`, `config.default`)

| ID | zapret2 | geneva_c сейчас | План | Этап |
|---|---|---|---|---|
| O1 | postnat (приоритет 101) и prenat (−101) | есть (`--prenat`, по умолчанию после NAT) | — | — |
| O2 | `predefrag` (−401): notrack своих пакетов, IP-фрагментов, `datanoack` (пакетов без SYN/RST/ACK) | частично: notrack своих пакетов до defrag (−400) | notrack фрагментов и datanoack | X7 |
| O3 | connbytes отдельно по направлениям: `TCP_PKT_OUT=20`, `TCP_PKT_IN=10`, `UDP_PKT_OUT=5`, `UDP_PKT_IN=3` | частично: `--first N` одно значение на обе стороны | `--first out=N,in=M` по протоколам | X7 |
| O4 | `FILTER_TTL_EXPIRED_ICMP`: ct mark на потоках с фейками и отбрасывание входящих ICMP time-exceeded по нему (иначе фейк с малым TTL вызывает ошибку сокета у клиента) | нет | то же, снимается при выходе | X7 |
| O5 | `FLOWOFFLOAD=donttouch\|none\|software\|hardware`: исключение потоков из flowtable, пока они нужны очереди | нет: при включённом offload на OpenWrt пакеты потока минуют очередь | исключение из offload через ct mark; e2e с flowtable | X7 |
| O6 | метки `DESYNC_MARK=0x40000000`, `DESYNC_MARK_POSTNAT=0x20000000` | **конфликт**: метка geneva по умолчанию `0x20000000` совпадает с postnat-меткой zapret2 | метка не меняется; предупреждение о пересечении при старте (решение 11.5) | X7 |
| O7 | LAN/WAN-интерфейсы (`IFACE_LAN/WAN/WAN6`, `OPENWRT_LAN/WAN4/WAN6`) | частично: `-i` один интерфейс | список интерфейсов | X7 |
| O8 | хуки до и после правил (`INIT_FW_*_HOOK`), `DISABLE_IPV4/6` | частично: `--firewall none`, `-4/-6` | `--fw-hook-pre/post` (только с `--ext`, команда — путь к файлу) | X7 |

#### P. `blockcheck2` и инструменты

| ID | zapret2 | geneva_c сейчас | План | Этап |
|---|---|---|---|---|
| P1 | проверка без обхода (curl, полный ответ), прекращение при кодах curl 1, 2, 3, 4, 6, 27 | есть (baseline, коды результата проб) | — | — |
| P2 | проверка подмены DNS через DoH | частично: проба `dns` с `--dns-bad/--dns-expect` | сравнение UDP, TCP и нескольких резолверов; DoH — через `--probe exec` с curl (11.2) | X12 |
| P3 | тесты блокировки по IP (заблокированный домен на чужом IP и наоборот) и порта (netcat) | нет | автоматическая классификация `untreatable` (4.4) + команда `geneva blockcheck` с теми же тестами | X12 |
| P4 | сетка стратегий `blockcheck2.d/standard`: http-моды; multisplit/multidisorder по `method+2, midsld` (HTTP) и `2, 1, sniext+1, sniext+4, host+1, midsld, 1,midsld, 1,midsld,1220, 1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1` (TLS); всё то же с `wssize:wsize=1:scale=6`; `tcpseg` с `repeats` 1/20/100/260; `oob urp=b,0,2,midsld`; seqovl с `padencap`; `syndata`; `fake` с TTL 1–12, autottl delta 1–5 (3–20), fooling `tcp_md5`, `badsum`, `tcp_seq=-3000`, `tcp_seq=1000000`, `tcp_ack=-66000:tcp_ts_up`, `tcp_ts=-1000`, `tcp_flags_unset=ACK`, `tcp_flags_set=SYN` (+ IPv6 расширения); «ttl=1 у пустого ACK после SYN,ACK»; «дубль SYN с MD5»; faked/hostfake; комбинации с фейком только если без него не вышло; QUIC: `fake` repeats 1–20, IPv6 расширения, `ipfrag_pos_udp` 8–64 | частично: GA (`evolve`) и библиотека Geneva | библиотека классов (5.3) включает **всю** сетку как готовые руки; `geneva blockcheck --ext` прогоняет её детерминированно | X12 |
| P5 | уровни `quick/standard/force/veryquick`, `REPEATS`, `PARALLEL`, IPv4/IPv6, HTTP / TLS 1.2 / TLS 1.3 / HTTP3 | частично: `--runs`, `--workers`, пробы `http`, `tls`, `exec` | уровни, параллельность — есть; HTTP3-проба через `exec` (curl `--http3`) | X12 |
| P6 | отчёт: стратегии по доменам, пересечение по всем доменам, покрытие (сколько доменов закрывает стратегия) | частично: `sdb top` | `geneva blockcheck --report`: те же три вида | X12 |
| P7 | `mdig` (многопоточный резолвер списков), `ip2net` (свёртка IP в подсети), скрипты загрузки списков (antifilter, antizapret, reestr, refilter, ipban) | нет | `geneva resolve`, `geneva ip2net` (C, без зависимостей); загрузчики списков — вне бинарника (решение 11.6) | X12 |
| P8 | установщики и init-скрипты: openrc, openwrt, pfsense, runit, s6, systemd, sysv | частично: procd, Entware, systemd | openrc, runit, s6, sysv | X14 |

### 3.3. Где zapret2 сейчас эффективнее (по исходникам)

1. **Многопакетный ClientHello** (X25519MLKEM768): nfqws2 собирает CH
   (E3), находит SNI и режет по маркеру (F1) на собранных данных, затем
   отбрасывает исходные куски (`replay_drop`). geneva_c видит пакеты по
   одному.
2. **QUIC**: расшифровка Initial и извлечение SNI (E4) дают и профиль по
   имени хоста для HTTP/3, и фейки, похожие на настоящие.
3. **Точечность**: hostlist/ipset/`--filter-l7`/`--filter-mark`/SSID на
   профиль (B, C); geneva_c применяет одну стратегию ко всем потокам на
   портах.
4. **Фейки под маршрут**: `ip_autottl` с кэшем TTL по IP и интерфейсу
   (C6, H3) работает уже на SYN.
5. **Богатый fooling** (H4–H10): MD5, PAWS, `tcp_ts_up`, IPv6-расширения,
   `ipfrag_next`.
6. **Отсечки и диапазоны на функцию** (D3, D7): модификация только
   начала потока, остальное без затрат.
7. **Автосписок и ротация стратегий по хосту** (C5, K1).
8. **Эксплуатация**: сброс root, seccomp, flow offload, отбрасывание ICMP
   time-exceeded, профили для многих протоколов в одном процессе.
9. **Двусторонние туннели** (L1–L4).

### 3.4. Ограничения самого zapret2 (видны в исходниках)

- Однопоточный: весь трафик и все Lua-функции в одном потоке; на
  многоядерном роутере упор в одно ядро.
- Вердикт синхронный: задержка возможна только отправкой копии позже
  (`send:delay`) с отбрасыванием оригинала.
- Детекторы не видят заморозку и замедление (2.2): успех — входящий seq
  больше 4096.
- `circular` — перебор по кругу без обучения; память только в процессе;
  обобщения между хостами нет.
- В коде отмечено `UNSOLVED`: при отмене сборки все пакеты, кроме
  последнего, уходят без десинхронизации.
- `blockcheck2` — фиксированная сетка, растущая комбинаторно; новые
  приёмы надо дописывать руками.
- Зависимости: libnetfilter_queue, libmnl, zlib, Lua/LuaJIT.
- Метка `0x20000000` у zapret2 занята postnat — пересечение с geneva_c
  (O6).

### 3.5. Где geneva_c уже сильнее

- Генетический поиск с фитнесом, baseline, canary, повторами, базой
  стратегий и checkpoint.
- Формальный язык с канонической печатью: стратегия — данные (GA мутирует,
  `sdb` хранит, `check` проверяет).
- Отложенные вердикты и `sleep` без копирования.
- Лабораторные цензоры и e2e в network namespace.
- Server-side оценка (`geneva agent`).
- Ноль зависимостей.

### 3.6. Вывод

Паритет = все строки A–P закрыты тестами. Превосходство — то, чего нет в
zapret2 по 3.4: многопоточность, детекция заморозки и замедления,
бандит с обучением и обобщением, GA для поиска новых приёмов, `untreatable`
вместо бесконечного перебора, хирургический путь данных (4.9).

---

## 4. Фаза 2. Архитектура `--ext`

### 4.1. Схема

```
                ┌──────────────────────────── geneva run --ext ───────────────────────────────┐
                │                                                                             │
 kernel         │  наблюдение (без задержки)              путь данных (только нужные потоки)   │
 ────────────── │  ─────────────────────────────          ───────────────────────────────────  │
 NFLOG ────────►│  obs: заголовки, seq, TTL, ICMP ──┐     NFQUEUE 310..310+W−1 (fanout) ──┐    │
 ctnetlink ────►│  счётчики conntrack               │     WinDivert active / divert (BSD) │    │
 WinDivert SNIFF│                                   ▼                                     ▼    │
 / FLOW ───────►│                         ┌──────────────────┐    ┌── воркер 0..W−1 ─────────┐ │
                │                         │ detect (поток,   │    │ ctrack (шард) → reasm →  │ │
                │                         │ ключ: SPRT)      │    │ L7 → профиль/политика →  │ │
                │                         └────────┬─────────┘    │ стратегия (Geneva + x) → │ │
                │                                  ▼              │ verdict/inject/delay     │ │
                │                         ┌──────────────────┐    └───────────▲──────────────┘ │
                │  hostlist, ipset, ─────►│ profile + policy │─── снапшот ────┘                │
                │  ipcache, sdb           │ autotune (rr/ts, │   (атомарный указатель, QSBR)   │
                │                         │ GA, replay)      │──► события, ctl, автосписок     │
                │                         └──────────────────┘                                 │
                └─────────────────────────────────────────────────────────────────────────────┘
```

Три плоскости, как в редакции 1, плюс подсистемы паритета (профили, списки,
conntrack, сборка, L7) внутри воркера. Без `--ext-auto` (4.8)
`geneva run --ext` — это «nfqws2 без Lua»: профили, списки, x-действия,
автосписок, `circular`.

### 4.2. Conntrack (D)

`ext/ctrack.c`, по таблице на воркер. Ключ — 5-кортеж, нормализованный как
в `flowtab.c`. Запись фиксированного размера, без указателей в куче, кроме
буфера сборки:

```c
typedef struct {
    uint64_t pkts, dpkts, bytes;          /* n, d, b; bytes с ретрансмиссиями, как в zapret2 */
    uint32_t seq0, seq_last, pos, uppos, uppos_prev;
    uint32_t win_calc; uint16_t win, mss; uint8_t scale, over2g;
    uint32_t ip6flow;
} xside;

typedef struct {
    xside cli, srv;
    uint64_t t_start, t_last;
    uint8_t state;                        /* SYN, EST, FIN */
    uint8_t srv_ttl;                      /* incoming_ttl */
    uint8_t l7proto, l7payload_last;
    uint16_t profile;                     /* индекс профиля, 0xFFFF = не найден */
    uint8_t profile_changes, flags;       /* cutoff in/out, hostname_discovered, … */
    uint32_t key_id;                      /* ключ политики (4.6) */
    uint32_t host_off;                    /* имя хоста в пуле строк воркера */
    uint8_t xstate[XSTATE_BYTES];         /* состояние x-действий на поток (D8) */
    uint16_t reasm;                       /* индекс буфера сборки, 0 = нет */
} xflow;
```

Таймауты `--ctrack-timeouts=S:E:F[:U]` (60:300:60:60), `--ctrack-disable`.
Связанные ICMP находят поток по вложенному пакету (E8). Те же структуры
питают детекторы (4.4), поэтому учёт на потоке один.

### 4.3. Профили (B, C)

Профиль = фильтры + списки + стратегия (или набор кандидатов для
автотюнера) + параметры автосписка. Два равноценных способа задать:

1. **Опции CLI с именами zapret2** (только под `--ext`): `--new`, `--name`,
   `--skip`, `--template`, `--import`, `--cookie`, `--filter-l3`,
   `--filter-tcp`, `--filter-udp`, `--filter-icmp`, `--filter-ipp`,
   `--filter-l7`, `--filter-mark`, `--filter-ssid[-neg]`, `--hostlist*`,
   `--ipset*`, `--hostlist-auto*`; стратегия — `-s`/`-f` внутри профиля.
   Это упрощает перенос конфигов, но **не делает geneva совместимой с
   `--lua-desync`**: стратегии пишутся на языке Geneva (раздел 5).
2. **Файл** `--ext-profile FILE`:

```
[profile tls]
filter-tcp = 443
filter-l7  = tls
hostlist   = /opt/lists/tls.txt.gz
strategy   = [L7:payload:tls_client_hello]-xfake{blob=fake_tls;tlsmod=rnd,dupsid;ttl=auto:-2:3-20}(xdisorder{pos=1,midsld},)-| \/
candidates = /opt/geneva/tls-candidates.txt   # руки автотюнера
select     = ts                                 # rr = как circular zapret2
hostlist-auto = /opt/lists/auto.txt

[profile quic]
filter-udp = 443
filter-l7  = quic
strategy   = [L7:payload:quic_initial]-xfake{blob=fake_quic;repeats=6}-| \/
```

Поиск профиля — первый подходящий, порядок проверок как в `dp_match`:
метка, L3, L7, порты/ICMP/протокол, SSID, затем дорогие (hostlist,
ipset). Повторный поиск при обнаружении L7 или имени (не больше двух смен
на поток), при смене сбрасываются отсечки (B8).

Списки (C1–C4): `ext/hostlist.c` (суффиксная хэш-таблица; исключения
важнее включений), `ext/ipset.c` (интервалы v4/v6, двоичный поиск),
`ext/inflate.c` для `.gz`. Перечитывание по изменению mtime при проверке
и по SIGHUP/`reload_lists`; новые списки готовятся в фоне и подменяются
снапшотом. Автосписок (C5) пишется дозаписью с `fsync` только по пути из
`--hostlist-auto`, с проверкой на повтор и на исключения, как в
`auto_hostlist_failed`.

### 4.4. Детектор

Плоскость наблюдения — как в редакции 1: NFLOG с `snaplen` на заголовки
для начала потока на любых портах, выборка 1/64 для длинных потоков,
ctnetlink для счётчиков (требует `nf_conntrack_acct=1`: включается и
возвращается при выходе), на Windows — SNIFF-хэндл и слой FLOW.

Детекторы потока — чистые функции от `xflow` и времени. Базовый набор
**включает детекторы zapret2 с теми же параметрами и порогами по
умолчанию** (K3, C5), остальное — расширение:

| Класс | Правило | Источник |
|---|---|---|
| `RETRANS` | ретрансмиссии исходящего payload в первых `retrans_maxseq` (32768) байтах ≥ `retrans` (3); по желанию RST ретранслятору (`retrans_reset`) | zapret2 |
| `RST_IN` | входящий RST при отн. seq 1…`incoming_maxseq` (4096) | zapret2 |
| `REDIRECT` | HTTP 302/307 на другой SLD в первых `incoming_maxseq` байтах | zapret2 |
| `UDP_NOANSWER` | исходящих ≥ `udp_out` (4), входящих ≤ `udp_in` (1) | zapret2 |
| `BLACKHOLE_SYN` | ≥ 2 SYN без SYN,ACK за 3 с | ext |
| `RST_INJECT` | `RST_IN` + отпечаток: \|TTL RST − TTL SYN,ACK\| ≥ 2 или IP ID вне окна сервера | ext |
| `FREEZE_N` | входящие данные остановились на `B ∈ [8 КБ, 64 КБ]`, поток не закрыт, тишина ≥ max(4·SRTT, 3 с); решение по ключу: межквартильный размах `B` по потокам ключа < 4 КБ при ≥ 3 потоках | ext |
| `THROTTLE` | медиана скорости на окнах 1 с < ρ·C (ρ = 0.25), коэффициент вариации < 0.3 на ≥ 5 окнах, у параллельных потоков к другим ключам плато нет | ext |
| `ICMP_PROHIBIT` | ICMP unreachable 9/10/13 на поток | ext |
| `DNS_POISON` | два ответа на один id, первый с другим TTL, или адрес-заглушка | ext |

Успех (K4): исходящий отн. seq > `retrans_maxseq` или входящий >
`incoming_maxseq`, UDP входящих > `udp_in` — **но не для ключа, у
которого уже подтверждён `FREEZE_N` или `THROTTLE`**: там критерий успеха
— входящих байт больше 2·B или скорость больше 3× плато. Так geneva_c не
считает замёрзший поток успешным (недостаток 3.4).

Решение на уровне ключа — последовательный тест Вальда (α = β = 0.05).
Если за окно ≥ 30 % активных ключей получили признаки `THROTTLE` или
блокировки, это сбой своего канала: состояние `LINK_DEGRADED`, лечение
приостанавливается.

### 4.5. L7 и сборка (E, F)

`ext/l7_*.c` — чистые разборщики с проверкой границ, без аллокаций, тем
же набором протоколов и payload (E1, E2). Маркеры (F) — `ext/markers.c`.
Сборка (E3, E4):

- TCP: если CH неполон и это не ретрансмиссия, а окно сервера не меньше
  ожидаемой длины, начинается сборка до `--ext-reasm-max` (по умолчанию
  16 КБ, как `TCP_MAX_REASM`). Пакеты удерживаются: в NFQUEUE — **отложенным
  вердиктом** (механизм `sleep` уже есть, копировать не нужно); на
  WinDivert — копией. Когда сборка полна, стратегия видит собранный
  payload; первый кусок несёт его, остальные отбрасываются, если действие
  отправило payload целиком (семантика `replay_drop`).
- Отмена сборки отпускает удержанные пакеты **через стратегию** с флагом
  «неполный payload», а не мимо неё (исправление `UNSOLVED` из 3.4).
- QUIC: расшифровка Initial (RFC 9001; v1, v2 — RFC 9369, черновики),
  дефрагментация CRYPTO, сборка нескольких Initial; SNI → имя хоста →
  профиль, `ipcache`.

### 4.6. Ключи и политика

Ключ — иерархия: `proto/dport` → `dst/24` (v6: `/48`) → `dst` → имя хоста
(в том числе обрезанное до N-го уровня, как `nld` в zapret2). Политика —
неизменяемый снапшот (хэш ключ → состояние, рука, срок), замена атомарным
указателем, освобождение по QSBR. Состояния ключа: `HEALTHY → IMPAIRED →
TRIAL → TREAT`, `UNTREATABLE`, переходы как в редакции 1.

### 4.7. Автотюнер (K)

Для ключа в `IMPAIRED` с классом K:

1. **Кандидаты**: руки профиля (`candidates`), портфель класса (5.3,
   включает всю сетку `blockcheck2`), удачные стратегии из `sdb` для
   похожих ключей.
2. **Селектор**:
   - `select=rr` — точная семантика `circular`: номер текущей стратегии на
     ключ, ротация при `fails` неудачах за `time` секунд (одна неудача на
     соединение), `final` останавливает ротацию;
   - `select=ts` (по умолчанию в режиме `apply`) — Thompson sampling с
     Beta-апостериорами, дисконт γ ≈ 0.98, априори из `sdb`, иерархическое
     объединение по родительским ключам.
3. **Испытание**: следующий поток ключа идёт через руку; исход — по
   детекторам и критериям успеха 4.4. При желании (`--ext-replay`)
   тюнер сам повторяет первый payload поражённого потока к тому же
   адресату через слот оценщика; по умолчанию повторяются только
   идемпотентные рукопожатия (TLS CH, QUIC Initial, HTTP GET без
   `Cookie`/`Authorization`).
4. **Завершение**: вероятность «лучшая рука» > 0.95 при ≥ 5 успехах →
   `TREAT`. Все руки плохи → GA в фоне с засевом лучшими руками. Без
   улучшения за G поколений → `UNTREATABLE` с перепроверкой по
   экспоненциальному расписанию.
5. **Сопровождение**: CUSUM по исходам в `TREAT`; вредная рука (хуже, чем
   без обработки) исключается.

### 4.8. Согласие пользователя

| `--ext-auto` | Поведение |
|---|---|
| не задан | профили и стратегии работают, как у nfqws2 (явная конфигурация — это и есть согласие); автосписок пишется, только если указан путь |
| `observe` | плюс детекция и события `ext_impaired`, `ext_class`; трафик сверх заданного профилями не трогается |
| `propose` | тюнер готовит руки (replay — только с `--ext-replay`), событие `ext_proposal`; применение — `ext_approve` по управляющему сокету |
| `apply` | автоматическое применение к ключам в `--ext-scope` на время работы процесса; в конфиги zapret-gui и на роутер ничего не сохраняется без подтверждения |

### 4.9. Хирургический путь данных

Linux: первые пакеты потока (до решения) приходят в очередь; воркер
вердиктом ставит метку «здоров» или «лечить», метка переносится в ct
mark; дальше поток здорового ключа идёт мимо очереди совсем, лечимый — в
пределах диапазона стратегии (`--first`-подобная отсечка, D3/D7) или
целиком, если нужен seqtrack. Правила, проверка пересечения меток (O6) и
запасной вариант на iptables `CONNMARK` — как в редакции 1 (уточнение
синтаксиса nft — этап X10). Исключение из flow offload (O5) использует тот
же ct mark. Windows: активный хэндл с фильтром по ключам в `TRIAL/TREAT`
через существующий `set_filter`.

---

## 5. Расширение языка стратегий и алгоритмы

### 5.1. Синтаксис (только с `--ext`)

Без `--ext` всё ниже — ошибка разбора (код 3), канонический вид прежних
стратегий не меняется.

**Новые псевдо-слои в триггерах:**

| Слой:поле | Значения | Аналог zapret2 |
|---|---|---|
| `L7:proto` | `tls`, `quic`, … `known`, `unknown` | `--filter-l7` |
| `L7:payload` | `tls_client_hello`, `empty`, `known`, `~tls_server_hello` | `--payload` |
| `L7:host` | `example.com` (с поддоменами), `*.cdn` | hostlist внутри стратегии |
| `FLOW:n`, `FLOW:d`, `FLOW:b`, `FLOW:s`, `FLOW:p` | `1-5`, `<10`, `-s1`, `3-` | `--out-range` (для текущего направления) |
| `FLOW:rn`, `FLOW:rd`, … | то же для обратного направления | `pos_get(…, reverse)` |
| `FLOW:state` | `syn`, `est`, `fin` | `track.pos.state` |
| `FLOW:retrans` | `0`, `1` | `is_retransmission` |
| `META:ifin`, `META:ifout`, `META:mark` | имя, маска | `--filter-mark`, `desync.ifin` |

Значения-диапазоны и ведущая `*` у `L7:host` допустимы только в этих
слоях; у обычных полей Geneva остаётся прежняя семантика (`*` в конце —
подстрока).

**x-действия** имеют именованные параметры через `;`:
`xfake{blob=fake_tls;tlsmod=rnd,dupsid;ttl=auto:-2:3-20;repeats=2}`.
Семантика — как цепочка инстансов zapret2: действие делает свои отправки
(фейки и части — с собственными fooling, с меткой «сгенерировано») и либо
передаёт исходный пакет левому потомку (возможно, изменённым), либо
поглощает его (как `VERDICT_DROP`, в том числе через `nodrop`).

```
[L7:payload:tls_client_hello]-xfake{blob=fake_tls;md5;seq=-10000}(xdisorder{pos=1,midsld},)-| \/
```

то же, что дефолтная строка zapret2 `--payload=tls_client_hello
--lua-desync=fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000
--lua-desync=multidisorder:pos=1,midsld`.

**Комбинаторы** (K6–K8):

- `xwhen{УСЛОВИЕ}(тогда,иначе)` — условие: триггерное выражение
  (`FLOW:n:<5`, `L7:payload:empty`), `rnd:P`, `has:строка`, `tcpts`;
  `xwhen{… ;neg}` инвертирует. Это `condition`/`per_instance_condition` и
  диапазоны на инстанс.
- `xrepeat{n=N;until=УСЛОВИЕ}(тело,остаток)` — `repeater`.
- `xstop{УСЛОВИЕ}` — `stopif`.
- `xcutoff{dir=in|out|both}` — добровольная отсечка поддерева на поток
  (`instance_cutoff`).

**Общие аргументы** любого x-действия (H): `dir`, `payload`, `ttl`
(`N` или `auto:delta:min-max`), `ip6ext`, `seq`, `ack`, `ts`, `md5[=hex]`,
`flags+=`, `flags-=`, `tsup`, `nopdel`, `badsum`, `repeats`, `ifout`,
`fwmark`, `ipid`, `ipfrag`, `ipfrag_pos*`, `ipfrag_disorder`,
`ipfrag_next`, префиксы `#`/`%`/`\`. Все действия, кроме аналога
`pktmod`, применяют fooling только к своим фейкам, как в zapret2.

Полное соответствие функций — таблица G; все x-действия детерминированы
при `--rng-seed` и работают в `geneva apply` (офлайн по pcap), что даёт
golden-тесты.

### 5.2. Fooling: когда ломается

| Fooling | Сервер отбрасывает, потому что | Ломается, когда |
|---|---|---|
| TTL = хопы − δ (`ttl=auto`) | не доходит | DPI ближе δ хопов; балансировщик пересчитывает TTL |
| `badsum` | неверная сумма | NAT/offload пересчитывает сумму |
| `seq`/`ack` вне окна | RFC 9293 | DPI проверяет окно |
| `md5` | нет согласованного TCP-MD5 | сервер с MD5 или middlebox режет опцию; на OpenBSD нет места в опциях SYN (`nopdel`) |
| `ts` в прошлом (PAWS) | RFC 7323 | сервер без timestamps |
| `flags-=ACK` | данные без ACK | стек принимает такие пакеты |
| `tsup` + `ack` | Linux отбрасывает badack при TS первой опцией | только Linux-серверы |
| IPv6 `hopbyhop2`, `destopt2`, `ah` | некорректная цепочка расширений | промежуточные узлы отбрасывают такие пакеты раньше DPI |

Тюнер помнит, какой fooling сработал на ключе, и сужает портфель.

### 5.3. Портфели по классам

Портфель класса = соответствующая часть сетки `blockcheck2` (P4) +
библиотека Geneva + удачные руки из `sdb`:

- `RST_INJECT`, `RETRANS`, `REDIRECT` (решение по содержимому): http-моды
  (G4–G7); `xsplit`/`xdisorder` по позициям P4; с `xwssize{wsize=1;scale=6}`;
  `xtcpseg` с повторами; `xoob`; `xseqovl` и `padencap`; `xsyndata`;
  `xfake` с TTL 1–12, `auto:-1…-5:3-20` и fooling P4; `xfakedsplit`,
  `xfakeddisorder`, `xhostfake`; TCB teardown из библиотеки Geneva.
- `FREEZE_N`, `THROTTLE`: то же для CH, плюс `xtlsrec` (разрез записи TLS,
  6.3) и фейк перед CH; если точка заморозки не меняется ни от одной руки
  — гипотеза «по адресу», `UNTREATABLE`.
- `UDP_NOANSWER` для QUIC: `xfake{blob=fake_quic;repeats=1…20}`, IPv6
  расширения + `drop`, `ipfrag_pos_udp` 8–64, фейк + ipfrag, `xudplen`.
- WireGuard/STUN/Discord: фейки соответствующих блобов, `xudplen`; при
  двусторонней установке — `xwgobfs`, `xudp2icmp`.
- `BLACKHOLE_SYN`: `xsynhide` (только при двусторонней установке), иначе
  `UNTREATABLE`.
- `DNS_POISON`: событие с рекомендацией DoH/DoT; geneva сама настройки DNS
  не меняет.

### 5.4. Алгоритмы сверх zapret2

| Алгоритм | Зачем |
|---|---|
| детекция заморозки по кучности точки остановки | zapret2 считает такие потоки успешными |
| детекция замедления с контрольной группой | у zapret2 нет |
| Thompson sampling + дисконт + иерархия ключей | `circular` перебирает без обучения |
| CUSUM на вылеченных ключах | обнаружить обновление DPI раньше `fails` подряд |
| GA (существующий `evolve`) по расширенному языку с ограничением по классу | новые приёмы без ручного дописывания сетки |
| `untreatable` по эксперименту | вместо ручной интерпретации IP-block тестов |
| отложенный вердикт для сборки | без копирования пакетов (zapret2 копирует в очередь `delayed`) |
| многопоточность | zapret2 однопоточный |
| `xtlsrec` с seqtrack | разрез записи TLS на две; у zapret2 есть только переразбиение в `tls_reconstruct` без сдвига seq |
| `xdrip` (первые n байт по одному сегменту с паузой) | DPI с таймаутом сборки |
| `xrstdrop` (во входящем лесе отбросить RST с чужим TTL/IP ID) | мягкая инъекция RST |

---

## 6. Фаза 3. Реализация

### 6.1. Всё в бинарнике

Детекция, классификация, L7, сборка, криптография, списки, профили,
бандит, replay-пробы, GA, netlink (NFQUEUE, NFLOG, ctnetlink, nl80211,
позже nftables) — в C. Внешние команды остаются только `nft`/`iptables`
для установки правил, как сейчас. Сборочные флаги: `make EXT=0` (без
`src/ext/`), `EXT_CRYPTO=0` (без QUIC-расшифровки и обфускации; L7 QUIC
тогда только по заголовку). Бюджет размера `STATIC=1 SMALL=1` на mipsel:
+180 КБ с криптографией, +100 КБ без неё; проверяется в CI.

### 6.2. Параллельность

- Шардирование по очередям: `queue num 310-31N fanout` (nft) /
  `--queue-balance --queue-cpu-fanout` (iptables) — пакеты потока всегда в
  одной очереди, у воркера своя таблица `xflow`, своя куча отложенных
  пакетов, свой пул сборки; общих блокировок нет.
- Воркер = поток + свой netlink-сокет + арена пакетов (в горячем пути нет
  `malloc`); пакетные вердикты `NFQNL_MSG_VERDICT_BATCH`,
  `NFQA_CFG_F_GSO`, `NFQNL_COPY_META` где можно.
- Общие данные только для чтения: снапшоты профилей, списков, политики
  (атомарный указатель + QSBR). Счётчики на воркер.
- Плоскость управления — отдельный поток: NFLOG, ctnetlink, детектор,
  тюнер, управляющий сокет, загрузка списков, автосписок. Связь с
  воркерами — SPSC-кольца фиксированного размера; переполнение считается,
  а не блокирует.
- Windows: несколько потоков на одном хэндле (`WinDivertRecvEx` пачками),
  таблица `xflow` шардирована по хэшу с мьютексом на шард.
- По умолчанию `min(ncpu, 4)` воркеров, на одноядерном роутере 1.
  `--ext-workers N`.

### 6.3. Seqtrack и сборка

`xoob` и `xtlsrec` меняют длину потока: `ext/seqtrack.c` держит дельту seq
и ack на поток и применяет её к каждому пакету потока, пока тот в `TREAT`
(такие потоки идут через очередь целиком; тюнер штрафует руки с seqtrack
за накладные). Сборка — 4.5.

### 6.4. Совместимость: `--ext`

- Без `--ext`: никаких новых правил, потоков, сокетов, полей событий;
  x-действия и псевдо-слои — ошибка разбора; golden-снимки всех команд
  совпадают.
- `--ext-*` и опции профилей без `--ext` — ошибка 2.
- Протокол событий только расширяется (`proto` остаётся 1): `ext_flow`,
  `ext_impaired`, `ext_class`, `ext_proposal`, `ext_trial`, `ext_treat`,
  `ext_untreatable`, `ext_link_degraded`, `ext_hostlist_auto`, `ext_pkt`.
  Команды: `ext_status`, `ext_flows`, `ext_keys`, `ext_profiles`,
  `ext_approve`, `ext_reject`, `ext_forget`, `reload_lists`. `version
  --json`: `ext`, `ext_profiles`, `ext_lists`, `ext_l7`, `ext_quic`,
  `ext_reasm`, `ext_auto`, `ext_obfs`, `ext_workers`.
- В движке одна точка расширения — указатель `const ext_hooks *` (NULL без
  `--ext`).

### 6.5. Модули

| Файл | Назначение | Строки матрицы |
|---|---|---|
| `src/ext/ctrack.c` | conntrack, позиции, ретрансмиссии, MSS, TTL, связанные ICMP | D1–D8, E8 |
| `src/ext/profile.c`, `profile_parse.c` | профили, опции CLI с именами zapret2, файл профилей, повторный поиск | B1–B6, B8, B9 |
| `src/ext/hostlist.c`, `ipset.c`, `inflate.c`, `ipcache.c` | списки, gzip, кэши, автосписок | C1–C7 |
| `src/ext/l7_*.c`, `markers.c`, `reasm.c` | распознавание, маркеры, сборка | E1–E3, E5–E7, F |
| `src/ext/quic.c`, `src/ext/crypto/{aes,gcm,sha256,hmac,hkdf}.c` | QUIC Initial, криптография | E4, L1 |
| `src/ext/tls.c`, `blob.c` | TLS разбор и сборка, `tls_mod`, `genhost`, блобы | J |
| `src/ext/xact_split.c`, `xact_fake.c`, `xact_tcp.c`, `xact_udp.c`, `xact_http.c`, `xact_comb.c`, `fool.c`, `xsend.c` | x-действия, fooling, отправка | G, H, K6–K8, M1 |
| `src/ext/seqtrack.c` | сдвиг seq/ack | G23, `xtlsrec` |
| `src/ext/obfs.c` | `wgobfs`, `ippxor`, `udp2icmp`, `synhide` | L |
| `src/ext/nflog.c`, `ctnl.c`, `wlan.c` | наблюдение, ctnetlink, SSID | B7, 4.4 |
| `src/ext/detect.c`, `policy.c`, `bandit.c`, `autotune.c`, `replay.c` | детекция, политика, тюнер | C5, K1–K4, K9 |
| `src/ext/fw_ext.c` | правила наблюдения, ct mark, notrack фрагментов, ICMP, offload, connbytes по направлениям | O2–O8 |
| `src/ext/sec.c`, `sec_win.c` | сброс прав, seccomp, песочница | N1–N3 |
| `src/eng_mq.c`, `src/eng_divert.c` | многоочередной NFQUEUE, BSD divert | A1, A5 |
| `src/cmd_blockcheck.c`, `cmd_resolve.c`, `cmd_ip2net.c` | blockcheck и инструменты | P2–P7 |
| `src/censor.c` | цензоры 12–20 (7.3) | тесты |

---

## 7. Фаза 4. Конвейер качества

### 7.1. Цикл этапа

```
спецификация (раздел docs/, русский) → .h с владением памяти
  → юнит-тесты (таблицы истинности, pcap-корпус) → реализация
  → make test + ASan/UBSan + TSan (многопоточные модули) + кросс-сборка zig -Werror
  → e2e в netns против лабораторного цензора
  → дифференциальный e2e против nfqws2 (если строка из матрицы)
  → КОД-РЕВЬЮ по чек-листу 7.2 → исправления → повторный прогон → коммит, CHANGELOG
```

Следующий этап не начинается, пока у предыдущего есть открытые замечания
уровня «корректность» или «безопасность памяти».

### 7.2. Чек-лист ревью

**Память и границы**: чтение пакета только через курсор с проверкой
остатка; длины `size_t` со сложением через проверку переполнения; длины из
сети (TLS `uint16/uint24`, QUIC varint) не смешиваются со знаковыми; нет
VLA и `alloca`; стек ≤ 4 КБ на функцию; в горячем пути нет `malloc`;
владение каждого указателя описано в `.h`; каждый путь ошибки освобождает
своё (ASan + LeakSanitizer на отказных тестах).

**Криптография**: тестовые векторы NIST (AES, GCM), RFC 6234 (SHA-256,
HMAC, HKDF), RFC 9001 Приложение A (QUIC v1 Initial), RFC 9369 (v2);
сравнение тегов за постоянное время; ключи обнуляются после
использования; случайность — `getrandom`/`BCryptGenRandom`.

**Конкурентность**: единый задокументированный порядок блокировок; горячий
путь без блокировок; `memory_order` каждой атомарной операции объяснён
комментарием; QSBR — ни один воркер не держит снапшот после точки покоя;
обработчики сигналов только с `sig_atomic_t` и `write`.

**Алгоритмы**: таблицы истинности детекторов, граничные значения, wrap seq
2³², переполнение 2 ГБ (`rseq_over_2G`), повторное использование
5-кортежа; бандит — статистические тесты на фиксированном seed;
x-действия — golden pcap и совпадение с nfqws2 (7.4).

**Правила**: golden legacy и дифференциальный тест с Geneva зелёные;
сборки gcc, clang, mingw, zig (все цели) с `-Werror`, `make EXT=0` и
`EXT_CRYPTO=0`; правила, sysctl и очереди сняты на каждом пути выхода
(e2e смотрит `nft list ruleset`, `iptables-save` и sysctl после SIGINT,
SIGTERM, ошибки старта, `stop`); никаких сетевых обращений, кроме проб к
адресатам пользователя.

**Инструменты** (только для разработки): `gcc -fanalyzer`,
`clang --analyze`, `cppcheck`, фаззинг libFuzzer/AFL++ для каждого
разборщика (`l7_*`, `tls`, `quic`, `inflate`, `nflog`, `ctnl`,
`pkt_parse`, `strategy_parse` с x-действиями, профили, списки) в
`tests/fuzz/`: в CI по 60 с на цель, перед релизом — долго.

### 7.3. Лабораторные цензоры

| № | Модель | Проверяет |
|---|---|---|
| 12 | заморозка: после N байт к клиенту — drop | `FREEZE_N`, критерий успеха |
| 13 | policer: token bucket для SNI из списка | `THROTTLE`, контрольная группа |
| 14 | SNI в CH без сборки → RST с TTL 64 | `RST_INJECT`, `xsplit`, `xrstdrop` |
| 15 | SNI со сборкой ≤ 2 сегментов по порядку → drop | `xdisorder`, `xseqovl`, Kyber-CH, сборка |
| 16 | QUIC Initial с SNI (с расшифровкой) → drop UDP | QUIC, `xfake{fake_quic}`, ipfrag |
| 17 | блокировка по IP (SYN drop) | `BLACKHOLE_SYN` → `UNTREATABLE` |
| 18 | HTTP Host → 302 на страницу блокировки | `REDIRECT`, http-моды |
| 19 | DPI с проверкой TTL ≥ порога и PAWS | выбор fooling, `ttl=auto` |
| 20 | DPI, видящий только первый IP-фрагмент | `ipfrag`, `ipfrag_next` |

### 7.4. Тесты паритета

Каждая строка A–P матрицы получает тест с её ID (`tests/parity/A7.sh`,
`test_parity.c: G16_*`):

1. **Юнит/golden**: x-действие на эталонном входе (`geneva apply`) даёт
   ожидаемые пакеты (с `--rng-seed`).
2. **Дифференциальный e2e против nfqws2** (официальный релиз zapret2,
   только в CI): один и тот же трафик в netns проходит через `nfqws2
   --lua-desync=…` и через `geneva run --ext` с эквивалентной стратегией;
   захваты tcpdump сравниваются по структуре (последовательность сегментов,
   флаги, seq-смещения, длины, TTL, опции), случайные поля маскируются.
3. **Функциональный e2e**: цензор раздела 7.3 блокирует без стратегии и
   пропускает с ней — и для nfqws2, и для geneva.

Отчёт `tests/parity/report.md` генерируется в CI: строка → тесты →
результат. Релиз `--ext` невозможен, пока в отчёте есть незакрытые строки
без решения раздела 11.

---

## 8. Поэтапный план

Каждый этап — отдельный PR с ревью по 7.2. В скобках — строки матрицы.

| Этап | Содержание | Готово, когда |
|---|---|---|
| **X0** | golden-снимки legacy; флаг `--ext`, `make EXT=0`, `features.ext` | без `--ext` всё совпадает; бинарник +< 2 КБ |
| **X1** | контекст воркера в движке без изменения поведения | все e2e, TSan чистый |
| **X2** | лабораторные цензоры 12–20; CI-стенд с официальным nfqws2 | каждый цензор блокирует свой сценарий; nfqws2 с эталонной стратегией его обходит |
| **X3** | conntrack, позиции, диапазоны, отсечки, состояние на поток, связанные ICMP, `ifin/ifout` (A8, D1–D8, E8) | юнит-тесты позиций против таблиц, снятых с nfqws2 `posdebug` на одном pcap |
| **X4** | L7 (16/31), маркеры, сборка CH и QUIC, криптография, MTProto, `--payload-disable`, `--reasm-disable` (C7, E1–E5, F) | корпус CH (Chrome/Firefox/curl, с Kyber и без), QUIC v1/v2, `files/fake/*.bin` разбирается как у nfqws2; векторы RFC 9001; 1 ч фаззинга |
| **X5** | x-действия G1–G22, G24–G26, общие аргументы H, блобы и TLS J, комбинаторы K6–K8, `xpcap` M1, raw-отправка A7 | golden pcap + дифференциальный e2e на каждую функцию; цензоры 14, 15, 18–20 обходятся |
| **X6** | профили, фильтры, списки, gzip, автосписок, ipcache, DNS → ipcache (B1–B6, B8, C1–C6, E6) | дефолтный `NFQWS2_OPT` zapret2, переписанный на профили geneva, ведёт себя так же на стенде |
| **X7** | firewall-паритет и эксплуатация: генератор WinDivert, `@config`, `--dry-run`, сброс прав, seccomp, `sd_notify`, syslog, notrack фрагментов, connbytes по направлениям, ICMP time-exceeded, flow offload, метки, LAN/WAN, хуки, дампы через ctl, фаззинг (A2–A4, B9, D9, N1, N2, N4–N6, O2–O8) | правила и sysctl сняты на всех путях выхода; e2e с flowtable на OpenWrt-образе |
| **X8** | seqtrack, `xoob`, `xtlsrec`, `xdrip` (G23) | загрузка 100 МБ через `xoob`/`xtlsrec` с проверкой хэша; wrap seq покрыт |
| **X9** | наблюдение (NFLOG, ctnetlink, SNIFF) и детекторы, включая детекторы zapret2 (C5, E7, K3, K4) | на цензорах 12–18 класс за ≤ 5 потоков; на синтетике без цензора (long-poll, WebSocket, загрузка 50 МБ) ноль ложных классов за 30 мин; поведение `--hostlist-auto` совпадает с nfqws2 |
| **X10** | многоочередной движок, хирургический путь, политика с QSBR (A1) | здоровые потоки после решения не попадают в очередь; ≥ 3× пропускной способности на 4 воркерах против 1 |
| **X11** | автотюнер: `select=rr` (точная семантика `circular`) и `ts`, ключи, `--ext-state`, режимы согласия (K1, K2, K9) | на цензорах 12–16, 18–20 связь восстанавливается сама; 17 → `UNTREATABLE` за ≤ 10 потоков; `rr` совпадает с `circular` nfqws2 на одном сценарии |
| **X12** | `geneva blockcheck` (сетка P4 целиком, уровни, отчёты), DNS-проверка, IP/порт-тесты, `resolve`, `ip2net` (P2–P7) | отчёт по тем же доменам на стенде совпадает по найденным классам стратегий с `blockcheck2.sh` |
| **X13** | BSD divert, Android-сборка, SSID/NLM, обфускация, Windows-песочница (A5, A6, B7, L1–L4, N3) | e2e на FreeBSD-раннере; обфускация совместима сама с собой с обеих сторон |
| **X14** | документация (`docs/EXT.md`, README RU/EN, PROTOCOL, INTEGRATION), init-скрипты openrc/runit/s6/sysv (P8), отчёт паритета, релиз | отчёт паритета без незакрытых строк; долгий фаззинг; все цели собраны; размер в бюджете |

Зависимости: X0 → X1 → X2 → X3 → X4 → X5 → X6 → X7 → X8; X9 после X3;
X10 после X7; X11 после X9 и X10; X12 после X5; X13 после X5 (обфускация —
после X4, криптография); X14 последний. X2 можно вести параллельно с X1.

---

## 9. Метрики

| Метрика | Определение | Цель |
|---|---|---|
| Паритет | доля закрытых строк матрицы | 100 % (кроме решённых в разделе 11) |
| TTD | от первого поражённого потока ключа до события класса | ≤ 5 потоков / ≤ 60 с |
| TTR | до первого вылеченного потока | ≤ 3 мин на цензорах 12–16 |
| FPR | доля здоровых ключей, получивших `TREAT` | 0 на синтетике |
| Хирургичность | доля байт здоровых потоков через userspace | < 0.5 % |
| Задержка | добавленная задержка лечимого потока, p50/p99 | p99 < 1 мс (ПК), < 5 мс (роутер) |
| Масштабирование | пропускная способность 4 воркеров к 1 | ≥ 3× |
| Legacy | расхождения golden и diff-тестов | 0 |

---

## 10. Риски

- **Объём.** Паритет — это порт заметной части nfqws2 (около 25 тыс. строк
  C без сторонних uthash/kavl и 6 тыс. строк Lua) без Lua и без
  библиотек. Смягчение: этапы X3–X7 независимы от автотюнера и сами по
  себе дают «nfqws2 без Lua»; порядок выбран так, чтобы польза появлялась
  с X5–X6.
- **Размер бинарника на роутере.** Криптография и QUIC отключаемы
  (`EXT_CRYPTO=0`), бюджет проверяется в CI.
- **Ложные срабатывания детекторов** на «молчаливых» протоколах: решение
  по ключу, кучность, контрольная группа, `observe` по умолчанию.
- **Расхождение с nfqws2 в мелочах** (порядок сегментов при сборке,
  `multidisorder` против `multidisorder_legacy`): дифференциальные e2e и
  отдельные действия под обе семантики.
- **Метка 0x20000000** (O6): при совместной работе с zapret2 нужна другая
  метка geneva.
- **Нестационарность DPI**: дисконт, CUSUM, перепроверка `UNTREATABLE`.

---

## 11. Решения, которые нужны от владельца проекта

1. **Скрипты пользователя (Lua).** zapret2 позволяет писать свои функции
   (`--lua-desync=моя_функция`, `luaexec`, `cond_lua`, `fool=`, свои
   детекторы и `hostkey`). Правило «C11 и только libc» исключает
   встраивание Lua. Варианты: (а) не повторять — язык Geneva + x-действия
   + комбинаторы покрывают все функции стандартной библиотеки zapret2, а
   внешнюю логику даёт управляющий сокет (`set_strategy`, `ext_approve`);
   (б) свой маленький безопасный язык условий и выражений; (в) снять
   правило ради опционального Lua в отдельной сборке. **Предлагается (а)**,
   с (б) только для условий, если понадобится.
2. **DoH в `blockcheck`.** Полный TLS-клиент с проверкой сертификата без
   библиотек — отдельный большой проект. Предлагается: сравнение
   нескольких резолверов по UDP и TCP внутри бинарника и DoH через
   `--probe exec` с curl, если он есть.
3. **Фейковые блобы.** Взять `.bin` из `files/fake/` zapret2 (MIT,
   с указанием авторства) или генерировать свои. Предлагается генерировать
   TLS/HTTP/QUIC и брать из zapret2 только то, что сложно синтезировать
   (BGP, ISAKMP, RDP, bitcoin), с файлом лицензии.
4. **Android logcat.** Без `liblog` возможна запись в `/dev/socket/logdw`;
   предлагается отложить и писать лог в stderr/файл.
5. **Метка по умолчанию.** Сменить `0x20000000` под `--ext` (например на
   `0x10000000`) или только предупреждать о пересечении с zapret2 —
   смена значения по умолчанию затрагивает интеграции.
6. **Загрузчики списков** (antifilter, antizapret, reestr, refilter):
   внешние сервисы; встраивание в бинарник означает сетевые обращения не
   к адресатам пользователя. Предлагается оставить их скриптам zapret-gui.

### 11.7. Принятые решения (5 ноября 2026)

| № | Решение | Что это значит для плана |
|---|---|---|
| 1 | (а); (б) — только для условий и только если понадобится | Lua не встраивается. `luaexec`, `cond_lua`, `fool=`, свои детекторы и `hostkey` не переносятся (строки G26, H12, K5, K7, M3 закрыты этим решением); внешняя логика — через управляющий сокет |
| 2 | на усмотрение исполнителя | принято предложение: сравнение резолверов по UDP и TCP в бинарнике, DoH через `--probe exec` с curl (P2) |
| 3 | генерировать TLS/HTTP/QUIC; из zapret2 брать только то, что сложно синтезировать (BGP, ISAKMP, RDP, bitcoin), с файлом лицензии | свои генераторы в `ext/blob.c`; взятые `.bin` лежат отдельно с `LICENSE` zapret2 (MIT) и указанием коммита (J2) |
| 4 | logcat отложить, лог в stderr/файл | A6 закрывается без logcat |
| 5 | метку не менять, только предупреждать о пересечении с zapret2 | `0x20000000` остаётся по умолчанию и под `--ext`; при старте `run --ext` — предупреждение, если метка пересекается с `0x40000000`/`0x20000000` zapret2 (O6) |
| 6 | загрузчики списков оставить скриптам zapret-gui | P7: в бинарнике только `resolve` и `ip2net` |
| 7 | в `--help` описывать новые возможности | опции расширений (справка через `EXT_HELP()`) выводятся в конце справки, в разделе «Extensions (with --ext):»; часть справки до него не меняется и сверяется с прежним golden-снимком, раздел — со своим (`expected-ext.txt`); сборка `EXT=0` его не выводит |

Порядок работы: этапы раздела 8 по очереди; после каждого этапа —
код-ревью по чек-листу 7.2 и исправления, только потом следующий этап.

---

## 12. Литература

1. T. Ptacek, T. Newsham. *Insertion, Evasion, and Denial of Service:
   Eluding Network Intrusion Detection.* Secure Networks, 1998.
2. Z. Wang, Y. Cao, Z. Qian, C. Song, S. Krishnamurthy. *Your State is Not
   Mine: A Closer Look at Evading Stateful Internet Censorship.* IMC 2017.
3. K. Bock, G. Hughey, X. Qiang, D. Levin. *Geneva: Evolving Censorship
   Evasion Strategies.* ACM CCS 2019.
4. K. Bock, G. Hughey, L.-H. Merino, T. Arya, D. Liscinsky, R. Pogosian,
   D. Levin. *Come as You Are: Helping Unmodified Clients Bypass Censorship
   with Server-side Evasion.* ACM SIGCOMM 2020.
5. D. Xue, R. Ramesh, ValdikSS, L. Evdokimov, A. Viktorov, A. Jain,
   E. Wustrow, S. Basso, R. Ensafi. *Throttling Twitter: An Emerging
   Censorship Technique in Russia.* IMC 2021.
6. D. Xue, B. Mixon-Baca, ValdikSS, A. Ablove, B. Kujath, J. R. Crandall,
   R. Ensafi. *TSPU: Russia's Decentralized Censorship System.* IMC 2022.
7. F. Li, A. Razaghpanah, A. Molavi Kakhki, A. Akhavan Niaki, D. Choffnes,
   P. Gill, A. Mislove. *lib•erate: (Mostly) Automated Detection and
   Remediation of Differentiation.* IMC 2017.
8. D. Russo, B. Van Roy, A. Kazerouni, I. Osband, Z. Wen. *A Tutorial on
   Thompson Sampling.* Foundations and Trends in ML, 2018.
9. E. S. Page. *Continuous Inspection Schemes.* Biometrika, 1954.
10. A. Wald. *Sequential Tests of Statistical Hypotheses.* Ann. Math.
    Stat., 1945.
11. RFC 9293 (TCP), RFC 7323 (timestamps, PAWS), RFC 2385 (TCP MD5),
    RFC 8200 (IPv6, расширения), RFC 9000/9001 (QUIC, защита Initial),
    RFC 9369 (QUIC v2), RFC 8446 (TLS 1.3), RFC 1951/1952 (DEFLATE, gzip),
    RFC 6234 (SHA, HMAC, HKDF), NIST SP 800-38D (GCM).
12. bol-van/zapret2, коммит `038c97e`: `nfq2/*.c`, `lua/*.lua`,
    `blockcheck2.sh`, `blockcheck2.d/standard/*`, `common/nft.sh`,
    `common/ipt.sh`, `config.default`, `docs/manual.md` —
    https://github.com/bol-van/zapret2
