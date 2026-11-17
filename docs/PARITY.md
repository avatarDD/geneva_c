# Паритет с zapret2

Итог плана `docs/EXT_ROADMAP.md` (этапы X0–X14) к выпуску 2.0: каждая
строка матрицы паритета (раздел 3.2 плана, 132 строки) — что из неё есть
в geneva_c 2.0. Всё перечисленное работает только с `--ext`; без него
geneva ведёт себя как 1.x.

Статусы:

- **есть** — равноценно zapret2 (nfqws2, winws2, dvtws2 и скрипты 1.0.6);
- **есть (до 2.0)** — было и без `--ext`;
- **с отличием** — есть, но поведение расходится; главное отличие указано
  в строке, полный список — в абзаце «Отличия» раздела;
- **не переносится** — решение владельца проекта (раздел 11 плана): без
  Lua (11.1) переносить нечего или незачем.

Итого: 88 строк «есть» (из них 3 — до 2.0), 38 «с отличием», 6 «не
переносится».

«Раздел» — этап в заголовке раздела `docs/EXT.md` (например, «x-действия
(X5a)»), где описаны опции и отличия. README — таблица служебных
скриптов в `README.md`.

## A. Перехват и платформы

| ID | zapret2 | geneva_c 2.0 | Статус | Раздел |
|---|---|---|---|---|
| A1 | NFQUEUE, `--qnum`, `FAIL_OPEN`, `NETLINK_NO_ENOBUFS` | NFQUEUE (свой netlink), `--queue`, `--queue-maxlen`, `--queue-bypass`; несколько очередей — `--ext-workers` | с отличием: `NETLINK_NO_ENOBUFS` не ставится: потери ядра считаются (ENOBUFS) | X10a |
| A2 | WinDivert, `--wf-iface`, `--wf-l3`, `--wf-tcp-in/out`, `--wf-udp-in/out`, `--wf-icmp-in/out`, `--wf-ipp-in/out` | `--wf-tcp-in/out`, `--wf-udp-in/out`, `--wf-icmp-in/out`, `--wf-ipp-in/out`, `--wf-iface`, `--wf-l3` под `--ext` | есть | X7b |
| A3 | `--wf-raw`, `--wf-raw-part` (OR), `--wf-raw-filter` (AND) | `--wf-raw`, `--wf-raw-part`, `--wf-raw-filter` (сборка выражения), прежние `--filter`, `--filter-file` | есть | X7b |
| A4 | `--wf-tcp-empty` (пустые ACK не перехватываются), `--wf-filter-lan`, `--wf-filter-loopback`, `--wf-priority`, `--wf-dup-check`, `--wf-save` | `--wf-tcp-empty`, `--wf-filter-lan`, `--wf-filter-loopback`, `--wf-priority`, `--wf-save`; `--wf-dup-check` принимается и ничего не делает | с отличием: `--wf-dup-check` ничего не делает | X7b |
| A5 | BSD: divert-сокет FreeBSD (PF_DIVERT в 14+), OpenBSD pf `divert-packet`, `--port`, `--sockarg` | `eng_divert.c`: FreeBSD (ipfw, pf) и OpenBSD (pf `divert-packet`), `--firewall ipfw\|pf`; порт — `-q`, без `--port` и `--sockarg` | с отличием: нет `--port`, `--sockarg`; часть `--ext` только на Linux | X13b |
| A6 | Android-сборка, вывод лога в logcat | статические сборки Linux работают на Android (`--log-file`, stderr); без logcat (решение 11.4) | с отличием: нет logcat (11.4) | X13c |
| A7 | raw-отправка: `IPPROTO_RAW`, `SO_MARK`, `IP_NODEFRAG`, `IP_FREEBIND`/`IPV6_FREEBIND`, `SO_PRIORITY 6`, `--bind-fix4/6` (`SO_BINDTODEVICE` на `ifout`), `--fwmark` | `IP_FREEBIND`/`IPV6_FREEBIND`, `SO_PRIORITY`, `--ext-bind-fix4/6`, `ifout` из исходного пакета, `--mark` | есть | X5a |
| A8 | Linux: `ifin/ifout` из NFQUEUE (ioctl `SIOCGIFNAME` через один сокет) | `ifin/ifout` доступны в условиях и для `bind-fix` | есть | X3 |

## B. Профили и фильтры

| ID | zapret2 | geneva_c 2.0 | Статус | Раздел |
|---|---|---|---|---|
| B1 | несколько профилей в одном процессе: `--new[=name]`, `--skip`, `--name`, `--template`, `--import`, `--cookie` | профили `--new`, `--name`, `--skip`, `--template`, `--import` в CLI и в `--ext-profile FILE`; без `--cookie` (решение 11.1) | с отличием: нет `--cookie`; стратегия шаблона заменяется, а не дописывается | X6a |
| B2 | `--filter-l3=ipv4,ipv6` | `--filter-l3` на профиль | есть | X6a |
| B3 | `--filter-tcp/udp=[~]p1-p2,...\|*` | `--filter-tcp`, `--filter-udp` на профиль, с `~` и `*` | есть | X6a |
| B4 | `--filter-icmp=type[:code]\|*`, `--filter-ipp=proto` | `--filter-icmp`, `--filter-ipp` на профиль | есть | X6a |
| B5 | `--filter-l7=proto,...` (16 протоколов) | `--filter-l7` на профиль | есть | X6a |
| B6 | `--filter-mark=mark[/mask]` (Linux) | `--filter-mark` на профиль | есть | X6a |
| B7 | `--filter-ssid`, `--filter-ssid-neg` (Linux nl80211, Windows WLAN API); `--ssid-filter`, `--nlm-filter` (Windows NLM) | `--filter-ssid` (Linux, nl80211), `--ssid-filter`, `--nlm-filter`, `--nlm-list` (Windows) | с отличием: профиль выбирается в начале потока, смена сети его не меняет | X13c |
| B8 | повторный поиск профиля при обнаружении L7 или имени хоста (не больше двух смен) | выбор профиля по фильтрам и спискам, повторный — когда стали известны L7 и имя | есть | X6a |
| B9 | `@config` / `$config` — опции из файла; `--comment`; `--dry-run` | `@FILE` (с `#`-комментариями), `--dry-run`, `--comment` | есть | X7a |

## C. Списки и кэши

| ID | zapret2 | geneva_c 2.0 | Статус | Раздел |
|---|---|---|---|---|
| C1 | `--hostlist`, `--hostlist-domains`, `--hostlist-exclude`, `--hostlist-exclude-domains`; поддомены автоматически | `--hostlist`, `--hostlist-domains`, `--hostlist-exclude[-domains]`: хэш по суффиксам домена | есть | X6b |
| C2 | `--ipset`, `--ipset-ip`, `--ipset-exclude`, `--ipset-exclude-ip`; CIDR v4/v6 | `--ipset`, `--ipset-ip`, `--ipset-exclude[-ip]`: отсортированные интервалы, двоичный поиск | с отличием: ICMP без потока — только по адресу пакета | X6b |
| C3 | списки в gzip | свой inflate (gzip, RFC 1951/1952) | есть | X6b |
| C4 | перечитывание списков по изменению файла и по SIGHUP | перечитывание по времени файла (не чаще раза в секунду); команда `reload_lists` | с отличием: проверка времени файла раз в секунду | X6b |
| C5 | `--hostlist-auto` + `fail-threshold` (3), `fail-time` (60), `retrans-threshold` (3), `retrans-maxseq` (32768), `retrans-reset` (1), `incoming-maxseq` (4096), `udp-out` (4), `udp-in` (1), `--hostlist-auto-debug` | `--hostlist-auto` и его пороги, `--hostlist-auto-debug`; детекторы `--ext-auto` их дополняют | с отличием: RST клиенту — только на NFQUEUE | X6c |
| C6 | `ipcache`: ip→имя хоста из DNS-ответов, ip+интерфейс→TTL для autottl на первом пакете; `--ipcache-lifetime` (7200), `--ipcache-hostname` | `--ext-ipcache-lifetime`, `--ext-ipcache-hostname` | есть | X6c |
| C7 | `--payload-disable`, `--reasm-disable` | `--ext-reasm-disable`, `--ext-reasm-max`, `--ext-payload-disable` | есть | X4 |

## D. Conntrack, позиции, диапазоны

| ID | zapret2 | geneva_c 2.0 | Статус | Раздел |
|---|---|---|---|---|
| D1 | userspace conntrack с ролями и таймаутами `--ctrack-timeouts=S:E:F[:U]`, `--ctrack-disable` | conntrack `--ext` для всех платформ, `--ext-ctrack-max`, `--ext-ctrack-timeouts`, `--ext-ctrack-disable` | с отличием: размер таблицы ограничен | X3 |
| D2 | счётчики режимов `n` (пакеты), `d` (пакеты с данными), `b` (байты), `s` (отн. seq), `p` (позиция данных), `a`, `x` — в обе стороны | поля триггера `FLOW:` (5.1) | есть | X3 |
| D3 | `--in-range`, `--out-range` на каждый инстанс: `mX-mY`, `mX<mY`, `-mY`, `<mY`, `mX-` | диапазоны в триггерах и в комбинаторе `xwhen` | есть | X3, X5c |
| D4 | обнаружение ретрансмиссий (`uppos_prev ≥ pos`) | в `ctrack` | есть | X3 |
| D5 | MSS обеих сторон → `tcp_mss` для собственной сегментации (минимум из двух; 1220 по умолчанию для v6) | в `ctrack`; все x-действия режут по нему | есть | X3 |
| D6 | входящий TTL сервера на поток (`incoming_ttl`) | в `ctrack` + `ipcache` | есть | X3 |
| D7 | отсечка инстанса и всей цепочки на поток (`instance_cutoff`, `lua_cutoff`, флаги `b_lua_in/out_cutoff`) | отсечка поддерева на поток; при отсечке всех — поток мимо стратегии | есть | X3 |
| D8 | состояние на поток для функций (`track.lua_state`) | слот состояния x-действия на поток (фиксированный размер, без кучи) | есть | X3 |
| D9 | дамп conntrack по SIGUSR1, счётчики неудач по SIGUSR2 | команды `ext_flows`, `ext_keys` управляющего сокета (`geneva ctl`) | есть | X7a |

## E. L7-распознавание и сборка

| ID | zapret2 | geneva_c 2.0 | Статус | Раздел |
|---|---|---|---|---|
| E1 | 16 L7-протоколов: `http tls dtls quic wireguard dht discord stun xmpp dns mtproto bt utp_bt` + `all unknown known` | распознавание L7 с теми же именами протоколов и payload | есть | X4 |
| E2 | 31 тип payload (`http_req … utp_bt_handshake`, `empty`, `unknown`, `known`, `ipv4/ipv6/icmp`) и фильтр `--payload` с отрицанием `~` | `L7:payload:` в триггерах | есть | X4 |
| E3 | частичный TLS ClientHello; сборка многопакетного CH (Kyber), удержание пакетов, проигрывание кусков | сборка многопакетного ClientHello (TCP) и QUIC Initial | с отличием: отменённая сборка идёт через стратегию | X4 |
| E4 | расшифровка QUIC Initial (v1, v2, черновики), дефрагментация CRYPTO, сборка нескольких Initial, извлечение SNI | разбор QUIC Initial с расшифровкой (свои AES-GCM, HKDF) | есть | X4 |
| E5 | MTProto по первому пакету (AES-256-CTR) | распознавание MTProto | есть | X4 |
| E6 | разбор DNS-ответов в `ipcache` | разбор ответов DNS → кэш адресов (C6) | есть | X6c |
| E7 | распознавание DPI-редиректа (302/307 на другой SLD) | класс `REDIRECT` детектора `--ext-auto` | есть | X9a |
| E8 | связанные ICMP (unreachable, time exceeded, redirect, too big) относятся к потоку вложенного пакета | в `ctrack` | есть | X3 |

## F. Маркеры позиций

| ID | zapret2 | geneva_c 2.0 | Статус | Раздел |
|---|---|---|---|---|
| F1 | `abs` (N, отрицательные — от конца), `host`, `endhost`, `sld`, `midsld`, `endsld` (HTTP и TLS), `method` (HTTP, с пропуском ведущих `\r\n`), `extlen`, `sniext` (TLS); смещения `±N`; списки сортируются, повторы убираются; позиция 0 удаляется | маркеры позиций с теми же именами; разбор строже | с отличием: `5x`, `host+` — ошибка, а не `atoi` | X4 |
| F2 | `resolve_range` (две позиции) для `tcpseg`, `hostfakesplit` | то же | есть | X4 |

## G. Функции десинхронизации (`zapret-antidpi.lua`)

| ID | zapret2 | geneva_c 2.0 | Статус | Раздел |
|---|---|---|---|---|
| G1 | `drop` | `drop` + условия | есть (до 2.0) | X5c |
| G2 | `send` (`delay=` мс; копия с fooling, ip_id, ipfrag, repeats) | `xsend{delay,…std}` | с отличием: `xsend` только в исходящем лесу | X5a |
| G3 | `pktmod` (fooling на текущий пакет) | `xmod{…fooling}` | есть | X5a |
| G4 | `http_domcase` (чередование регистра в Host) | `xhttp{domcase}` | есть | X5b |
| G5 | `http_hostcase` (`spell=` 4 символа) | `xhttp{hostcase=hoSt}` | есть | X5b |
| G6 | `http_methodeol` (`\r\n` перед методом, укорачивает User-Agent) | `xhttp{methodeol}` | есть | X5b |
| G7 | `http_unixeol` (`\n` вместо `\r\n`, длина сохраняется через UA) | `xhttp{unixeol}` | есть | X5b |
| G8 | `synack_split` (`mode=syn\|synack\|acksyn`) | `xsynacksplit{mode}` | есть | X5b |
| G9 | `synack` (в ответ на SYN шлёт SYN,ACK) | `xsynack` | есть | X5b |
| G10 | `wsize` (`wsize=`, `scale=` на SYN,ACK; масштаб только уменьшается) | `xwsize{wsize,scale}` | есть | X5b |
| G11 | `wssize` (то же на исходящих до первого payload, `forced_cutoff=`) | `xwssize{…}` | есть | X5b |
| G12 | `tls_client_hello_clone` (`blob, fallback, sni_snt, sni_snt_new, sni_del_ext, sni_del, sni_first, sni_last`) | `xtlsclone{…}` на `ext/tls.c` (полный разбор и сборка) | есть | X5b |
| G13 | `syndata` (`blob` по умолчанию 16 нулей, `tls_mod`) | `xsyndata{blob,tls_mod}` | есть | X5b |
| G14 | `rst` (`rstack`) | `xrst{rstack,…std}` | с отличием: `xrst` только в исходящем лесу | X5b |
| G15 | `fake` (`blob, optional, tls_mod=rnd,rndsni,sni=,dupsid,padencap`; сегментация по MSS) | `xfake{…}` | есть | X5a |
| G16 | `multisplit` (`pos` по умолчанию `2`, `seqovl=N`, `seqovl_pattern`, `blob`, `optional`, `nodrop`) | `xsplit{…}` | есть | X5a |
| G17 | `multidisorder` (обратный порядок; `seqovl` — маркер, меньше первой позиции) | `xdisorder{…}` | есть | X5a |
| G18 | `multidisorder_legacy` (порядок nfqws1 по кускам сборки) | `xdisorder{legacy}` | есть | X5a |
| G19 | `hostfakesplit` (`host=` шаблон, `midhost`, `nofake1/2`, `disorder_after`; fooling только на фейки, ipfrag только на настоящий хост) | `xhostfake{…}` | с отличием: `xhostfake` без `ipfrag` (как фактически в zapret2 1.0.7) | X5a |
| G20 | `fakedsplit` (`pos, nofake1..4, pattern, seqovl, seqovl_pattern`; порядок fake1 real1 fake1 fake2 real2 fake2) | `xfakedsplit{…}` | есть | X5a |
| G21 | `fakeddisorder` (обратный порядок) | `xfakeddisorder{…}` | есть | X5a |
| G22 | `tcpseg` (`pos` — диапазон, `seqovl`; дополнительный сегмент без отбрасывания оригинала) | `xtcpseg{…}` | есть | X5a |
| G23 | `oob` (`char/byte`, `urp=b\|e\|маркер`; с SYN: исходящий seq−1 на весь поток, входящий ack+1) | `xoob{…}` на seqtrack | с отличием: ack переводится точно, повтор сообщения изменён | X8 |
| G24 | `udplen` (`min, max, increment` ±, `pattern, pattern_offset`) | `xudplen{…}` | есть | X5b |
| G25 | `dht_dn` (`dn=N`, правка bencode) | `xdhtdn{dn}` | есть | X5b |
| G26 | вспомогательные: `pass`, `luaexec`, `pktdebug`, `argdebug`, `posdebug`, `detect_payload_str` | `xlog{…}` (события `ext_pkt`), `xtag{pattern,payload}`; без `luaexec` (решение 11.1) | с отличием: нет `luaexec` (11.1) | X5b |

## H. Стандартные аргументы (fooling, отправка, ip_id, ipfrag)

| ID | zapret2 | geneva_c 2.0 | Статус | Раздел |
|---|---|---|---|---|
| H1 | `dir=in\|out\|any` (по умолчанию out); `payload=` (по умолчанию `known`) | общие аргументы x-действий; направление — лесом (`\/`), `payload=` | с отличием: нет `dir`: направление задаёт лес | X5a |
| H2 | `ip_ttl`, `ip6_ttl` | плюс аргумент `ttl=` | есть | X5a |
| H3 | `ip_autottl=delta,min-max` (исходный TTL 64/128/255 по порогам 33–64, 97–128, >223; кэш на поток; отказ, если фейк дошёл бы до сервера) | `ttl=auto:delta:min-max`, тот же алгоритм | есть | X5a |
| H4 | `ip6_hopbyhop[=hex]`, `ip6_hopbyhop2`, `ip6_destopt`, `ip6_destopt2`, `ip6_routing`, `ip6_ah` (6+8N / 6+4N байт) | `ip6ext=` с теми же правилами размещения | есть | X5a |
| H5 | `tcp_seq=N`, `tcp_ack=N` (прибавить к текущему) | аргументы `seq=`, `ack=` | есть | X5a |
| H6 | `tcp_ts=N` (сдвиг TSval) | `ts=` (сдвиг) | есть | X5a |
| H7 | `tcp_md5[=hex]` (16 байт; по умолчанию случайные) | `md5[=hex]` | есть | X5a |
| H8 | `tcp_flags_set/unset=` | `flags+=`, `flags-=` | есть | X5a |
| H9 | `tcp_ts_up` (TS-опция первой; «badack без badseq») | `tsup` | есть | X5a |
| H10 | `tcp_nop_del` (убрать NOP ради места под MD5) | `nopdel` | есть | X5a |
| H11 | `badsum` | плюс аргумент `badsum` | есть | X5a |
| H12 | `fool=функция` (свой fooling) | не переносится (решение 11.1); встроенный набор fooling | не переносится | — |
| H13 | `repeats`, `ifout`, `fwmark` (бит десинхронизации ставится всегда) | общие аргументы | есть | X5a |
| H14 | `ip_id=seq\|rnd\|zero\|none`, `ip_id_conn` (непрерывный seq на поток) | `ipid=` | есть | X5a |
| H15 | `ipfrag[=функция]`, `ipfrag_disorder`, `ipfrag_pos_tcp` (32), `_udp` (8), `_icmp` (8), `ipfrag_pos` (32), `ipfrag_next` (иной next-header второго фрагмента v6) | `ipfrag=` с теми же параметрами | есть | X5a |
| H16 | сегментация любого отправляемого payload по `tcp_mss` с сохранением URG/`urp` | общая функция отправки | есть | X5a |
| H17 | префиксы аргументов `#blob` (длина), `%blob` (значение), `\` (экранирование) | те же префиксы в параметрах x-действий | есть | X5a |

## J. Блобы и TLS-модификации

| ID | zapret2 | geneva_c 2.0 | Статус | Раздел |
|---|---|---|---|---|
| J1 | `--blob=name:[+ofs]@file\|0xHEX` (до 16 КБ) | `--ext-blob ИМЯ:0xHEX` (до 16 КБ), `--ext-blob ИМЯ:[+ofs]@FILE` (до 1 МБ); байты прямо в параметре (`blob=0x…`) | с отличием: имя опции `--ext-blob`; из файла до 1 МБ | X5a |
| J2 | встроенные `fake_default_tls` (680 байт), `fake_default_http`, `fake_default_quic`; файлы `files/fake/*.bin` (QUIC разных клиентов, DTLS, DHT, Discord, STUN, WireGuard, RDP, NTP, ISAKMP, BGP, bitcoin…) | свои генераторы (TLS ClientHello, HTTP, QUIC Initial с шифрованием); фейки BGP, ISAKMP, RDP, bitcoin — файлы zapret2 в `files/fake` (решение 11.3) | есть | X5a |
| J3 | `tls_mod`: `rnd`, `rndsni`, `sni=`, `dupsid`, `padencap`, `none` | `tlsmod=` в `xfake`, `xsyndata` | с отличием: `tlsmod` только на TCP | X5a |
| J4 | полный разбор и сборка TLS (записи, многозаписные handshake, расширения SNI/ALPN/versions/groups/sigalgs/key_share/psk_modes/QUIC TP) | `ext/tls.c` | есть | X5a |
| J5 | `genhost(len, шаблон)` — случайное имя той же длины | в `ext/tls.c` / `xhostfake` | есть | X5a |

## K. Оркестрация и автоматика (`zapret-auto.lua`)

| ID | zapret2 | geneva_c 2.0 | Статус | Раздел |
|---|---|---|---|---|
| K1 | `circular`: стратегии с тегом `strategy=N`, ротация по хосту при `fails` (3) за `time` (60), `final` останавливает ротацию; `key`, `hostkey` | `--ext-arm`, `--ext-tune` (селектор `rr` с параметрами `circular`) | с отличием: руки — стратегии geneva; таблица ключей ограничена 65 536 | X11a |
| K2 | `standard_hostkey`: имя хоста, `nld=N` (обрезать до N-го уровня), `reqhost`, иначе IP | ключ тюнера `nld=N`, `reqhost`, иначе адрес | есть | X11a |
| K3 | `standard_failure_detector`: ретрансмиссии (`retrans`, `maxseq`), RST в `inseq`, DPI-редирект, UDP `udp_out/udp_in`, `reset` (RST ретранслятору), `no_rst`, `no_http_redirect` | детекторы `--ext-auto` (классы X9a–X9c: в том числе заморозка, замедление, RST с чужим TTL) | с отличием: RST после данных сервера — неудача только с чужим TTL | X9a, X9b |
| K4 | `standard_success_detector`: исходящий seq > `maxseq`, входящий > `inseq`, UDP `in > udp_in` | критерии успеха класса, с поправкой на заморозку | есть | X9a, X11d |
| K5 | пользовательские детекторы по имени функции | не переносится (решение 11.1); детекторы параметризуются | не переносится | — |
| K6 | `condition` (`iff, neg, instances`), `per_instance_condition` (`cond, cond_neg`), `stopif`, `repeater` (`repeats, instances, iff, neg, stop, clear`) | комбинаторы `xwhen`, `xstop`, `xrepeat` (5.1) | есть | X5c |
| K7 | условия `cond_true/false`, `cond_random` (`percent`), `cond_payload_str` (`pattern`), `cond_tcp_has_ts`, `cond_lua` | условия `rnd:P`, `has:строка`, `tcpts`, триггерные выражения; без `cond_lua` (решение 11.1) | с отличием: нет `cond_lua` (11.1) | X5c |
| K8 | вложенные оркестраторы, `execution_plan` | вложенные комбинаторы в дереве | есть | X5c |
| K9 | состояние хостов `autostate` в памяти процесса | состояние тюнера и лечения в памяти и в `--ext-state FILE` | с отличием: априори без `sdb`; состояние переживает перезапуск | X11b, X11c |

## L. Двусторонняя обфускация (`zapret-obfs.lua`)

| ID | zapret2 | geneva_c 2.0 | Статус | Раздел |
|---|---|---|---|---|
| L1 | `wgobfs` (`secret, padmin, padmax`): AES-GCM с ключом HKDF шифрует рукопожатия WireGuard и меняет их размер | `xwgobfs{…}` | есть | X13a |
| L2 | `ippxor` (`ippxor, dataxor, rebuild`): XOR номера протокола и payload | `xippxor{…}` | есть | X13a |
| L3 | `udp2icmp` (`ctype, ccode, stype, scode, dataxor, server, cgnat, id_lifetime`): UDP внутри ICMP echo того же размера | `xudp2icmp{…}` | с отличием: сторона — параметр `server` | X13a |
| L4 | `synhide` (`ghost, ghost6, synack, magic=x2\|urp\|opt\|tsecr, x2, kind, opt, xorseq`): SYN идёт как ACK с меткой и восстанавливается на сервере | `xsynhide{…}` | с отличием: восстановленный SYN не идёт в conntrack geneva | X13a |

## M. Служебное

| ID | zapret2 | geneva_c 2.0 | Статус | Раздел |
|---|---|---|---|---|
| M1 | `pcap` (`file, keep`) — запись пакетов функцией | `xpcap{file}` в любой точке дерева | с отличием: пишет пакет в его состоянии в этой точке дерева | X5b |
| M2 | таймеры Lua (`timer_set/del/info/enum`), `--intercept=0` (только Lua и таймеры) | не переносится: отложенная отправка (`xsend{delay}`) есть | не переносится | — |
| M3 | Lua C API: dissect/reconstruct, rawsend, csum, crypto, gzip, resolve_pos, get_source_ip, get_ifaddrs, time | не переносится как API (решение 11.1); возможности — x-действия | не переносится | — |
| M4 | `zapret-tests.lua` — самопроверка C API | юнит-тесты модулей, e2e на стенде, сверка с nfqws2 1.0.6 | есть | — |

## N. Безопасность и эксплуатация

| ID | zapret2 | geneva_c 2.0 | Статус | Раздел |
|---|---|---|---|---|
| N1 | `--user`, `--uid=uid[:gid,…]` (сброс root), сброс capabilities | `--user`, `--uid`: остаются только `CAP_NET_ADMIN`, `CAP_NET_RAW` (syscall, без libcap) | с отличием: права сбрасываются, когда пакеты пошли | X7a |
| N2 | seccomp-фильтр (`sec_harden`, таблица архитектур включая mips, arm, ppc, riscv64, loongarch) | seccomp (Linux), `--ext-seccomp=0` выключает | есть | X7a |
| N3 | Windows: low-integrity песочница, удаление привилегий токена | песочница Windows, `--ext-sandbox 0` выключает | с отличием: выключается `--ext-sandbox 0`; метка Low на устройстве всегда | X13d |
| N4 | `--daemon`, `--pidfile`, `--chdir`, systemd `sd_notify` | `--pidfile`, `READY=1` в `$NOTIFY_SOCKET`, `--daemon`; без `--chdir` | с отличием: нет `--chdir` | X7a |
| N5 | `--debug=0\|1\|syslog\|android\|@file` | `--log-target syslog`, `--log-file`; без logcat и `--debug=@file` | с отличием: нет logcat и `--debug=@file` | X7a |
| N6 | `--fuzz=N` — встроенный фаззер обработки пакетов | `geneva selftest --ext --fuzz N`, цели в `tests/fuzz/` (в том числе `nflog`, `ctnl`) | есть | X7c |
| N7 | `--writable[=dir]` (каталог для скриптов) | не нужен: скриптов нет, пути задаются явно | не переносится | — |
| N8 | `--lua-gc` | не нужен: нет Lua, память фиксированная | не переносится | — |

## O. Правила firewall (`common/nft.sh`, `common/ipt.sh`, `config.default`)

| ID | zapret2 | geneva_c 2.0 | Статус | Раздел |
|---|---|---|---|---|
| O1 | postnat (приоритет 101) и prenat (−101) | `--prenat`, по умолчанию после NAT | есть (до 2.0) | — |
| O2 | `predefrag` (−401): notrack своих пакетов, IP-фрагментов, `datanoack` (пакетов без SYN/RST/ACK) | `--ext-notrack all\|frag\|none`, `--ext-ttl-icmp` | с отличием: ct mark на всех пакетах очереди; отбрасывание в `mangle PREROUTING` | X7b |
| O3 | connbytes отдельно по направлениям: `TCP_PKT_OUT=20`, `TCP_PKT_IN=10`, `UDP_PKT_OUT=5`, `UDP_PKT_IN=3` | `--ext-first tcp-out=N,tcp-in=M,udp-out=…` | есть | X7b |
| O4 | `FILTER_TTL_EXPIRED_ICMP`: ct mark на потоках с фейками и отбрасывание входящих ICMP time-exceeded по нему (иначе фейк с малым TTL вызывает ошибку сокета у клиента) | то же; правила снимаются при выходе | есть | X7b |
| O5 | `FLOWOFFLOAD=donttouch\|none\|software\|hardware`: исключение потоков из flowtable, пока они нужны очереди | `--ext-flowoffload software\|hardware` (nft): свой flowtable, потоки не выгружаются, пока нужны очереди | с отличием: только nft | X7b |
| O6 | метки `DESYNC_MARK=0x40000000`, `DESYNC_MARK_POSTNAT=0x20000000` | метка не меняется; предупреждение о пересечении при старте (решение 11.5) | есть | X7b |
| O7 | LAN/WAN-интерфейсы (`IFACE_LAN/WAN/WAN6`, `OPENWRT_LAN/WAN4/WAN6`) | `--ext-wan`, `--ext-lan` (до 8 интерфейсов) | с отличием: один список на IPv4 и IPv6 | X7b |
| O8 | хуки до и после правил (`INIT_FW_*_HOOK`), `DISABLE_IPV4/6` | `--fw-hook-pre/post FILE` (аргументы `up\|down BACKEND QUEUE`) | с отличием: аргументы вместо переменных окружения | X7b |

## P. `blockcheck2` и инструменты

| ID | zapret2 | geneva_c 2.0 | Статус | Раздел |
|---|---|---|---|---|
| P1 | проверка без обхода (curl, полный ответ), прекращение при кодах curl 1, 2, 3, 4, 6, 27 | baseline, коды результата проб | есть (до 2.0) | — |
| P2 | проверка подмены DNS через DoH | `geneva blockcheck`: DNS по UDP и TCP, сравнение с публичными резолверами, DoH через curl | с отличием: адреса сравниваются целиком; подмена ловится и по TCP | X12b |
| P3 | тесты блокировки по IP (заблокированный домен на чужом IP и наоборот) и порта (netcat) | класс `untreatable` (`--ext-auto`), `geneva blockcheck` с тестами по IP | есть | X9a, X12b |
| P4 | сетка стратегий `blockcheck2.d/standard`: http-моды; multisplit/multidisorder по `method+2, midsld` (HTTP) и `2, 1, sniext+1, sniext+4, host+1, midsld, 1,midsld, 1,midsld,1220, 1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1` (TLS); всё то же с `wssize:wsize=1:scale=6`; `tcpseg` с `repeats` 1/20/100/260; `oob urp=b,0,2,midsld`; seqovl с `padencap`; `syndata`; `fake` с TTL 1–12, autottl delta 1–5 (3–20), fooling `tcp_md5`, `badsum`, `tcp_seq=-3000`, `tcp_seq=1000000`, `tcp_ack=-66000:tcp_ts_up`, `tcp_ts=-1000`, `tcp_flags_unset=ACK`, `tcp_flags_set=SYN` (+ IPv6 расширения); «ttl=1 у пустого ACK после SYN,ACK»; «дубль SYN с MD5»; faked/hostfake; комбинации с фейком только если без него не вышло; QUIC: `fake` repeats 1–20, IPv6 расширения, `ipfrag_pos_udp` 8–64 | `geneva blockcheck --ext`: вся сетка `blockcheck2.d/standard`, строки переводятся в стратегии geneva; строки с Lua (`luaexec`) — неудача | с отличием: строки с Lua не переводятся (11.1) | X12b |
| P5 | уровни `quick/standard/force/veryquick`, `REPEATS`, `PARALLEL`, IPv4/IPv6, HTTP / TLS 1.2 / TLS 1.3 / HTTP3 | `--level`, `--repeats`, `--test http3` (curl `--http3-only`) | есть | X12b |
| P6 | отчёт: стратегии по доменам, пересечение по всем доменам, покрытие (сколько доменов закрывает стратегия) | отчёт SUMMARY, COMMON, COVERAGE; `--json` | есть | X12b |
| P7 | `mdig` (многопоточный резолвер списков), `ip2net` (свёртка IP в подсети), скрипты загрузки списков (antifilter, antizapret, reestr, refilter, ipban) | `geneva resolve`, `geneva ip2net`; загрузчики списков — в zapret-gui (решение 11.6) | с отличием: загрузчики списков — в zapret-gui (11.6) | X12a |
| P8 | установщики и init-скрипты: openrc, openwrt, pfsense, runit, s6, systemd, sysv | `packaging/`: OpenRC, runit, s6, SysV, pfSense | есть | README |
