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
