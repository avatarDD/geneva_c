# Changelog

Протокол событий и управления — `proto 1` во всех версиях 1.x: новые поля,
события и команды только добавляются.

## Не выпущено

Расширения `--ext` по `docs/EXT_ROADMAP.md` (паритет с zapret2). Без
`--ext` поведение всех команд прежнее.

- X0: ключ `--ext` у `run`, `check`, `apply`, `eval`, `evolve`, `fw`;
  опции `--ext-*` без `--ext` — ошибка 2. `--help` описывает расширения
  в отдельном разделе «Extensions (with --ext):» в конце; прежняя часть
  справки не изменилась (сборка `EXT=0` раздел не выводит). Сборка `make EXT=0` без
  `src/ext/` (тогда `--ext` — ошибка 2). Фича `ext` в `geneva version
  --json`. Golden-снимки вывода команд (`tests/golden/run.sh`) в CI для
  обеих сборок, бюджет размера `tools/ext_size.sh`.
- X1: контекст воркера в движке (`eng_worker`: счётчики, отложенные
  пакеты, таблица `--first`, состояние расширений) и единственная точка
  расширения `engine_opts.ext` (`NULL` без `--ext`). Поведение прежнее:
  один воркер, те же события и счётчики. Юнит-тесты ядра движка без
  захвата, ThreadSanitizer в CI.
- X2: лабораторные цензоры 12–20 (`geneva censor --ext`, `docs/CENSOR.md`):
  заморозка, полисер, RST по SNI, сборка ClientHello из двух сегментов,
  SNI в QUIC Initial, блокировка по IP, HTTP-редирект, «строгий» цензор
  (TTL, сумма, PAWS), только первые фрагменты. Свои AES-128/256-GCM,
  SHA-256, HMAC, HKDF; расшифровка QUIC Initial (v1, v2, драфты 29–32),
  SNI из ClientHello; проверены на векторах NIST/RFC и пакетах zapret2
  (`tests/data/zapret2/`, MIT). Сборка `make EXT_CRYPTO=0`. e2e
  `tests/e2e/censors_x.sh` и CI-стенд с официальным nfqws2 v1.0.6.
  `--help` описывает расширения в разделе «Extensions (with --ext):».
- X3: conntrack по образцу zapret2 (`src/ext/ctrack.c`): роли клиент и
  сервер, счётчики `n d b s p` обеих сторон, ретрансмиссии, MSS и окно,
  TTL ответа, связанные ICMP, таймауты `--ext-ctrack-timeouts`, предел
  `--ext-ctrack-max` с вытеснением, `--ext-ctrack-disable`. Диапазоны
  zapret2 и триггеры `FLOW:` (`n d b s p`, `rn…rp`, `state`, `retrans`) и
  `META:` (`ifin`, `ifout`, `mark`, из NFQUEUE). Дерево, чей диапазон
  позади, отсекается на потоке; когда отсечены все, поток идёт мимо
  стратегии. `apply --ext --ext-posdebug` печатает строки `posdebug`
  zapret2; CI сверяет их с официальным nfqws2 на одном захвате. Фича
  `ext_ctrack`. Подробно — `docs/EXT.md`.
- X4: распознавание L7 как в nfqws2 (`src/ext/l7.c`): 16 протоколов, 31
  тип payload, имя хоста из HTTP, TLS и QUIC, MTProto по первому пакету.
  Сборка ClientHello из нескольких сегментов TCP и нескольких QUIC
  Initial: пакеты удерживаются (вердикт ждёт, счётчик `held` в `stats`) и
  проходят стратегию со всем ClientHello; отменённая сборка отпускает их
  через стратегию, а не мимо неё, как nfqws2. Триггеры `L7:proto`,
  `L7:payload`, `L7:host`; опции `--ext-payload-disable`,
  `--ext-reasm-disable`, `--ext-reasm-max`. Маркеры позиций zapret2 (`host`,
  `midsld`, `sniext`…) для действий X5. Паритет закреплён выводом самого
  кода zapret2 по всем `files/fake/*.bin` и снятым ClientHello Chromium и
  curl (`tests/data/l7_expected.txt`), дифференциальный фаззинг
  `tests/fuzz/l7_diff.sh`. QUIC Initial расшифровывается во всех версиях,
  что знает zapret2 (v1, v2, черновики с 11, mvfst, Q050, T050, T051).
  Фича `ext_l7`. Подробно — `docs/EXT.md`.
- X5a: x-действия по функциям zapret2 (`lua/zapret-antidpi.lua`):
  `xfake`, `xsplit`, `xdisorder` (и `legacy`), `xtcpseg`, `xhostfake`,
  `xfakedsplit`, `xfakeddisorder`, `xsend`, `xmod` — синтаксис
  `имя{ключ=значение;...}` с одним поддеревом. Общие аргументы zapret2:
  TTL и autottl, seq/ack/ts, MD5, флаги TCP, заголовки расширения IPv6,
  `badsum`, `repeats`, `fwmark`, `ifout`, режимы IP ID, `ipfrag2`, фильтр
  `payload`; сегментация по MSS потока; на собранном ClientHello — целое
  сообщение на первом куске. `tls_mod` (`rnd`, `rndsni`, `sni=`, `dupsid`,
  `padencap`) и `genhost`. Встроенные блобы `fake_default_tls`,
  `fake_default_http`, `fake_default_quic`, `fake_quic_initial` собирает
  сама geneva; `--ext-blob` для своих; фейки BGP, ISAKMP, RDP, Bitcoin из
  zapret2 — в `files/fake/` (MIT). Отправка: метка `fwmark`, интерфейс
  `--ext-bind-fix4/6`, `SO_PRIORITY 6`, `IP_FREEBIND`; сделанные пакеты и
  вердикт уходят в порядке zapret2. Фича `ext_xact`. Подробно —
  `docs/EXT.md`.
- X5b: остальные функции zapret2 как x-действия: `xsynacksplit`,
  `xsynack`, `xwsize`, `xwssize` (с `forced_cutoff`), `xsyndata`, `xrst`,
  `xhttp{domcase;hostcase;methodeol;unixeol}`, `xudplen`, `xdhtdn`,
  `xtlsclone` (`tls_client_hello_clone`: полный разбор и сборка
  ClientHello, правка списка SNI), `xtag` (`detect_payload_str`: своя
  метка payload), `xlog` (`pass`/`pktdebug`/`posdebug`, событие `ext_pkt`),
  `xpcap{file;keep}` (`pcap` в любой точке дерева). Состояние пакета как
  таблица `desync` zapret2: блоб, сделанный `xtlsclone`, и метка `xtag`
  видны следующим действиям и деревьям этого пакета. Отсечка экземпляра
  на потоке (`instance_cutoff`) для `xwsize`, `xwssize`, `xsynack`,
  `xsynacksplit`, `xsyndata`. В `payload=` — любые имена (как в Lua).
- X5c: комбинаторы — оркестраторы zapret2 как x-действия с поддеревьями:
  `xwhen{iff;neg}(тогда,иначе)` (`condition`, `per_instance_condition`),
  `xstop{iff;neg}` (`stopif`), `xrepeat{repeats;iff;neg;stop;clear}(тело,остаток)`
  (`repeater`), `xcutoff{dir}` (`instance_cutoff`: отсечка дерева или леса на
  потоке). Условия zapret2 `cond_true`, `cond_false`, `cond_random`
  (`percent`), `cond_payload_str` (`pattern`), `cond_tcp_has_ts` и любые
  триггерные выражения (`FLOW:n:<5`, `L7:payload:http_req`, `TCP:flags:PA`).
  e2e: x-действия обходят цензоры 14, 15, 18, 19, 20; одинаковые с nfqws2
  v1.0.6 пакеты на проводе для 13 функций и оркестраторов.
- X6a: профили zapret2 в одном процессе (`run`, `apply`, `fw`): `--new[=имя]`,
  `--name`, `--skip`, `--template[=имя]`, `--import`; фильтры
  `--filter-l3`, `--filter-tcp`, `--filter-udp` (`~`, `*`, `0`),
  `--filter-icmp`, `--filter-ipp`, `--filter-l7`, `--filter-mark`; поиск
  первого профиля как `dp_match`, повторный поиск, когда известен протокол
  L7 потока, связанный ICMP — с профилем потока. Файл профилей
  `--ext-profile` (секции `[profile]` и `[template]`). Без `-p` порты для
  правил — из фильтров профилей; ICMP и протоколы `--filter-ipp`
  перехватываются (iptables, nft, WinDivert). Опции с необязательным
  значением (`--new=имя`). Фича `ext_profile`. e2e: два профиля дают те же
  пакеты, что профили nfqws2 v1.0.6.
- X6b: списки профилей zapret2: `--hostlist`, `--hostlist-domains`,
  `--hostlist-exclude`, `--hostlist-exclude-domains` (имя с поддоменами,
  `^имя` — без поддоменов, `!имя` — исключение), `--ipset`, `--ipset-ip`,
  `--ipset-exclude`, `--ipset-exclude-ip` (подсети IPv4/IPv6, двоичный
  поиск); те же ключи в `--ext-profile`, `--import` их копирует. Файлы в
  gzip (свой inflate по puff). Проверка в порядке `dp_match`,
  повторный поиск профиля потока, когда известно имя хоста. Файлы
  перечитываются при изменении (проверка раз в секунду), по SIGHUP и по
  новой команде управления `reload_lists` (ответ `files`). Фича
  `ext_lists`. e2e: профили со списками дают те же пакеты, что nfqws2
  v1.0.6; смена профиля по списку из gzip и его перечитывание по SIGHUP.
- X6c: автосписок zapret2 `--hostlist-auto` с параметрами
  `--hostlist-auto-fail-threshold`, `-fail-time`, `-retrans-threshold`,
  `-retrans-maxseq`, `-retrans-reset`, `-incoming-maxseq`, `-udp-out`,
  `-udp-in` и журналом `--hostlist-auto-debug`: неудачи по повторам
  запроса, RST и редиректу сервера, по счётчикам UDP; хост дописывается в
  файл, клиенту уходит RST (NFQUEUE). Кэш адресов (`ipcache`): имена из
  DNS-ответов и потоков (`--ext-ipcache-hostname`), TTL первого ответа
  сервера для autottl, `--ext-ipcache-lifetime`. Поток, профиль которого
  может появиться только по имени хоста, держит ClientHello из нескольких
  пакетов до имени. Фича `ext_autolist`. e2e: автосписок против цензора,
  сбрасывающего и выбрасывающего пакеты. Удержанный для сборки пакет на
  NFQUEUE сразу выбрасывается и потом отправляется заново, как в nfqws2:
  иначе TCP small queues задерживали следующий сегмент клиента.
- X7a: работа службой (только с `--ext`). Опции из файла `geneva CMD
  @FILE` (или `$FILE`; слова как в shell, `$NAME`, `#`-комментарии, без
  запуска команд), `--comment`. У `run`: `--dry-run` (проверить опции,
  стратегии и списки и выйти), `--daemon` (ждёт запуска и возвращает его
  код), `--pidfile`, `--user`/`--uid` (сброс root с `CAP_NET_ADMIN` и
  `CAP_NET_RAW`), seccomp по списку zapret2 (`--ext-seccomp=0` —
  выключить), `READY=1`/`STOPPING=1` для systemd, `--log-target syslog`.
  Правила firewall снимает root-помощник — и после SIGKILL движка.
  Команды управления `ext_flows` (потоки conntrack) и `ext_keys`
  (счётчики неудач автосписка). Предупреждение, когда `--mark` совпадает
  с меткой zapret2. Фича `ext_service`.
- X7b: правила firewall как у zapret2 (только с `--ext`, у `run` и `fw`):
  `--ext-first` по протоколам и направлениям, `--ext-wan` (список
  интерфейсов), `--ext-notrack frag` (только фрагменты и TCP без
  SYN/RST/ACK, predefrag), `--ext-ttl-icmp` (отбрасывание ICMP
  time-exceeded потоков из очереди), `--ext-flowoffload` с `--ext-lan`
  (свой flowtable nft, потоки из очереди не выгружаются), хуки
  `--fw-hook-pre/post`. Фильтр WinDivert winws2: `--wf-tcp/udp/icmp/ipp-in/out`,
  `--wf-iface`, `--wf-l3`, `--wf-tcp-empty`, `--wf-raw`, `--wf-raw-part`,
  `--wf-raw-filter`, `--wf-filter-lan`, `--wf-filter-loopback`,
  `--wf-priority`, `--wf-save` (на любой платформе). На Windows `--ext-wan`
  — список индексов интерфейсов. Фича `ext_fw`.
- X7c: фаззинг. Цели для каждого разборщика (пакеты, pcap, стратегии с
  x-действиями, JSON, L7, TLS, QUIC, gzip, списки, профили, значения
  опций), `geneva selftest --ext --fuzz N` (воспроизводимые входы по
  `--seed`, падения и зависания с номером входа, `--crash-dir`,
  `--seeds-out`), сборка для libFuzzer и AFL++ (`tests/fuzz/run.sh`), CI
  по 60 с на цель. Фича `ext_selftest`. Найдено и исправлено: число JSON
  вне диапазона `int64` (`json_get_int` и запись чисел — неопределённое
  поведение), ICMP без данных в распознавании L7, утечка пустого блоба `0x`.
- X8: seqtrack и x-действия, удлиняющие первое сообщение клиента:
  `xoob` (байт OOB, функция `oob` zapret2) и `xtlsrec` (первая запись TLS
  разрезана на две). Нумерация сдвигается на SYN. До подтверждения
  сообщения движок правит пакеты клиента без данных, переводит ack и края
  SACK сервера и при потере повторяет изменённое сообщение. `xdrip`: первые
  байты по одному сегменту с паузой. e2e: загрузка 100 МБ со сверкой
  SHA-256 и потерями (`tests/e2e/seqtrack.sh`).
- X9a: `run --ext --ext-auto observe` — наблюдение и детектор блокировок
  без изменения трафика. Первые пакеты каждого потока (любые порты) и ICMP
  unreachable копируются через NFLOG (`--ext-nflog-group`,
  `--ext-observe-first`; цепочки nft `obs_out`/`obs_in`, iptables
  `GENEVA_N_OBO`/`_OBI`). Классы `RETRANS`, `RST_IN`, `REDIRECT`,
  `UDP_NOANSWER` (детекторы zapret2 с его порогами), `RST_INJECT`,
  `BLACKHOLE_SYN`, `ICMP_PROHIBIT`; ключи порт, сеть, адрес и имя с тестом
  Вальда. События `ext_flow`, `ext_impaired`, `ext_class`, команда
  `ext_status`, поле `detect` в `ext_keys`, фича `ext_auto`. e2e против
  цензоров 14–18 и без цензора (`tests/e2e/censors_x.sh auto`).
- X9b: `--ext-auto observe` раз в секунду читает счётчики потоков из
  conntrack (ctnetlink) и находит заморозку (`FREEZE_N`: сервер замолчал на
  8–64 КБ, класс ключа — три заморозки одного размера), полку полисера
  (`THROTTLE`: ровная скорость ниже четверти ёмкости канала) и подмену DNS
  (`DNS_POISON`: адрес-заглушка или два ответа на запрос с разным TTL).
  Заблокированный такими классами ключ засчитывает успех строже. Событие
  `ext_link` о сбое своего канала, новые поля `ext_status`, цель фаззинга
  `ctnl`. e2e против цензоров 12, 13 и `dns`.
- X9c: `--ext-auto observe` на Windows: SNIFF-хэндл WinDivert с приоритетом
  выше движка видит каждый пакет ПК, детектор сам считает байты сервера
  (все классы X9a и X9b), поток начинают только исходящие пакеты ПК.
  `THROTTLE` не ставится, если в то же время такая же полка у потока к
  другой сети (это свой канал). Поле `source` (`nflog` или `windivert`) в
  `ext_status`. e2e без цензора `tests/e2e/auto_synth.sh` (long-poll,
  WebSocket, загрузки по 50 МБ; 30 минут — ни одного класса), Windows
  smoke в CI.
- X10a: многоочередной движок `run --ext --ext-workers N|auto` (Linux):
  у каждого воркера поток, очередь NFQUEUE (`--queue`..`--queue+N-1`),
  raw-сокет и копия стратегии; правила раскладывают потоки по хэшу адресов
  (iptables `--queue-balance A:B`, nft `queue num A-B`). Поля `workers` и
  `worker_pkts` в `stats`, `workers` в `status`. По умолчанию 1 воркер
  (отличие от плана). e2e `tests/e2e/workers.sh` (`BENCH=1` — замер 1 и 4
  воркеров).

## v1.2.0

- `eval`/`evolve --probe external --workers N`: запросы `eval_request`
  нескольких воркеров идут одновременно (у каждого свой блок `lports`),
  контроллер отвечает по `id` в любом порядке. Раньше внешняя проба
  требовала `--workers 1`. Фича `external_workers` в `geneva version
  --json`. Контроллер с одним воркером работает без изменений.

## v1.1.1

- `fw`: iptables/nft работают и тогда, когда geneva запущена с
  игнорируемым SIGCHLD (так делает менеджер служб Keenetic): раньше каждый
  вызов считался «cannot run», и `geneva run` падал на первом правиле.
  Сообщение об ошибке теперь называет причину.

## v1.1.0

Внешний фильтр: стратегия применяется только к трафику заблокированных
ресурсов, несколько экземпляров работают одновременно (режим «Авто»
Zapret2_AutoTuner и zapret-gui). Все изменения аддитивные: прежние
аргументы, события, поля и коды выхода не менялись.

- Windows: `--filter EXPR` и `--filter-file PATH` у `run`, `eval`,
  `evolve`. У `run` выражение WinDivert заменяет фильтр из
  `-p/--proto/--dir/-4/-6`, у `eval`/`evolve` сужает перехват слотов. Всегда
  добавляется `and not loopback`. Выражение проверяется
  `WinDivertHelperCompileFilter`: ошибка — код 2, событие `error` с
  `where: "filter"` и `pos`. `geneva fw print` печатает итоговое выражение.
- Windows: команды управляющего сокета `set_filter` и `reload_filter` —
  смена фильтра на лету без потери пакетов и без обрыва соединений; событие
  `filter` (`source`: `start`, `set_filter`, `reload_filter`); поле
  `status.filter` (на Linux `null`). Строка запроса `set_filter` — до 1 МБ.
- Windows: `--first N` работает: движок сам считает пакеты по потокам
  (таблица до 65536 потоков, LRU). Новые счётчики `stats.passed_first` и
  `stats.flow_evictions`.
- Windows: `--priority N` (−30000…30000) — приоритет хэндла WinDivert;
  несколько экземпляров с непересекающимися фильтрами.
- Linux: `eval`/`evolve --firewall none`; `geneva fw print --local-ports
  BASE --workers N -q Q [--probe KIND]` печатает правила для слотов.
- `geneva version --json`: в `features` добавлены `filter`, `set_filter`,
  `first`, `firewall_none_eval`.
- Документация: раздел «Внешний фильтр: обход только заблокированного» в
  `docs/INTEGRATION.md` (nft-наборы для Linux, выражения WinDivert для
  Windows).

## v1.0.0

Первый релиз: язык стратегий Geneva, исполнитель (NFQUEUE, WinDivert),
подборщик и оценщик, server-side, библиотека, лабораторные цензоры.
