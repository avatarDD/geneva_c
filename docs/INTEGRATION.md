# Встраивание geneva в zapret-gui и Zapret2_AutoTuner

geneva — один статический бинарник без зависимостей. Встраивающая
программа запускает его как дочерний процесс или службу и общается с ним
через аргументы, коды возврата, события JSON Lines и управляющий сокет.
Контракт этих интерфейсов — `docs/PROTOCOL.md` (версия `proto` 1); здесь —
как их собрать в рабочую интеграцию.

Стратегии Geneva — свой язык (`docs/STRATEGY.md`), а не аргументы
nfqws2. Они не переводятся в `--lua-desync` и исполняются только движком
geneva (`geneva run`). В интерфейсе это отдельный движок рядом с nfqws2, а
не формат экспорта zapret2.

## Что даёт geneva

| Задача | Команда | Права |
|---|---|---|
| применить стратегию к трафику | `geneva run -f FILE -p PORTS -c unix:SOCK -e FILE` | root / администратор |
| проверить, заблокирован ли ресурс | `geneva eval --host H` (baseline) | нет |
| оценить список стратегий | `geneva eval -f FILE` | root |
| подобрать стратегию | `geneva evolve --host H --checkpoint F --db F` | root |
| готовые стратегии Geneva | `geneva library --json` | нет |
| база найденных стратегий | `geneva db --db F top --json` | нет |
| разобрать и проверить стратегию | `geneva check --json STRATEGY` | нет |
| пробы из цензурируемой сети для server-side | `geneva agent` (`docs/SERVER_SIDE.md`) | нет |

Версию и возможности сборки даёт `geneva version --json`: `version`,
`proto`, `os`, `arch`, `features` (`nfqueue`, `windivert`, `ipv6`, ...).
Проверяйте `proto` при старте: при несовпадении интеграция должна
отказаться работать с бинарником, а не гадать.

## Общие правила

- **Очереди и метки.** По умолчанию `geneva run` берёт NFQUEUE 310,
  оценщик — 311, лабораторный цензор — 400. zapret-gui держит nfqws2 на
  300–303. Метка своих пакетов geneva — `0x20000000` (`--mark`), та же,
  что исключает zapret-gui из правил nfqws2; так пакеты, отправленные
  одним движком, не попадают во второй. Один и тот же порт не стоит
  отдавать двум движкам сразу: каждый пакет пройдёт через оба.
- **Остановка.** SIGTERM (или команда `stop`) снимает правила firewall.
  SIGKILL их оставляет; тогда поможет `geneva fw down` с теми же
  `-p`/`-q`/`--firewall`, что у `run`. Перед запуском интеграция может
  сделать то же для очистки после сбоя.
- **Ничего без подтверждения.** geneva сама не меняет конфигурацию роутера
  и не устанавливает стратегий. Применять найденную стратегию — решение
  пользователя в интерфейсе. Телеметрии нет: события идут только в
  указанный файл, stdout или сокет.
- **Пути на роутере.** Checkpoint и база пишутся атомарно (tmp + rename).
  На роутере кладите их в `/opt` (Entware) или на USB, а не во flash.

## zapret-gui (Python/Bottle на роутере)

Предлагаемая схема — менеджер-синглтон `core/geneva_manager.py` и тонкий
`api/geneva.py`, как у остальных движков:

1. **Установка.** Бинарник нужной архитектуры из релиза geneva_c (zig,
   статический musl) кладётся в `/opt/bin/geneva` (Entware) или
   `/usr/bin/geneva` (OpenWrt) вместе со скриптом службы из `packaging/`:
   `S51geneva` + `geneva.conf` или procd-скрипт + `/etc/config/geneva`.
   Архитектуру выбирать по `uname -m` и проверять запуском
   `geneva version --json`.
2. **Служба.** Настройки пишутся в `geneva.conf` (Entware) или UCI
   (OpenWrt), стратегия — в файл стратегии (одна строка). Запуск, стоп и
   статус — через скрипт службы. Смена стратегии без разрыва соединений:
   записать файл и вызвать `reload` (SIGHUP) либо отправить
   `set_strategy` в сокет.
3. **Состояние.** Управляющий сокет `unix:/opt/var/run/geneva.sock`:
   `status` для карточки движка, `stats` для счётчиков (срабатывания
   каждого дерева — `out_trees`/`in_trees`), `subscribe` для живого потока
   событий в SSE. Готовность — событие `ready`; ошибки — `error` с полем
   `where`. Клиент на Python: одна строка JSON на запрос, ответ —
   строка с тем же `id`, события отличаются отсутствием `ok`.
4. **Keenetic.** ndm пересобирает firewall и удаляет чужие правила;
   хук `packaging/entware/010-geneva.sh` в `/opt/etc/ndm/netfilter.d/`
   перезапускает geneva после пересборки таблицы mangle.
5. **Подбор на роутере.** `geneva evolve --events FILE` в фоне с
   `--checkpoint` и `--db` в `/opt`. Прогресс — события `generation`,
   найденное — `result` и `geneva db top --json`. Остановка — SIGTERM;
   продолжение — `--resume`. На слабом роутере берите `--workers 1–2` и
   небольшую популяцию. Стратегии библиотеки (`geneva library --json`)
   можно показать как готовые варианты: `-s` для `geneva eval` или
   `--load-from` для засева.
6. **Проба своими средствами.** Если у zapret-gui уже есть проверка
   ресурса (testers/), её можно подключить через `--probe external`:
   geneva пишет `eval_request` с `lports`, менеджер делает соединение с
   локальных портов из этого диапазона и отвечает в stdin
   `{"id":N,"ok":true}`. С фичей `external_workers` (1.2) несколько
   воркеров спрашивают одновременно; на роутере хватает 1–2.

## Zapret2_AutoTuner (C#/.NET на ПК)

В AutoTuner geneva — внешний инструмент в бандле (как winws2/nfqws2), а
запускает его привилегированный ZapretAutoTuner.Agent:

1. **Бандл.** Windows: `geneva.exe` с `WinDivert.dll` и `WinDivert64.sys`
   из официального релиза WinDivert (их кладёт релиз geneva_c), Linux —
   статический `geneva`. Хэши — из `SHA256SUMS` релиза.
2. **Диагностика.** `geneva eval --host H --probe http|tls --events -`
   без стратегии (без прав) показывает, заблокирован ли ресурс и как:
   `outcome` `reset`, `injected`, `timeout`, `connect_timeout`.
   Подбор только при заблокированном baseline — то же правило, что у
   AutoTuner (у `evolve` код возврата 7, если ресурс доступен).
3. **Подбор с проверкой в браузере.** `geneva evolve --probe external
   --events - --workers N`: на каждое `eval_request` Agent открывает
   страницу браузером (Playwright) с локальных портов `lports` — так
   стратегия применяется только к этим соединениям — и отвечает в stdin
   `{"id":N,"ok":true}` или `{"id":N,"fitness":F,"detail":"..."}`. Успех —
   полная загрузка, как в критериях AutoTuner, а не рукопожатие. Несколько
   воркеров (с 1.2, фича `external_workers`) спрашивают одновременно, и
   ответы идут по `id` в любом порядке; без фичи — `--workers 1`.
4. **Монитор.** Найденная стратегия работает в `geneva run -c tcp:PORT
   --control-token T` (на Windows unix-сокетов нет): события `stats`
   показывают, срабатывает ли стратегия, команда `stop` снимает
   перехват.
5. **Режим «Авто».** Главный режим AutoTuner: Agent пассивно смотрит на
   трафик ПК, проверяет подозрительный сервис без обхода (baseline) и
   сначала пробует готовые стратегии — те, что уже работают для других
   сервисов, стартовый набор и импортированные, — а потом запускает
   `evolve` с «Потоками подбора» (1–8, без `external_workers` — 1).
   Найденная стратегия работает в своём `geneva run` только на трафике
   сервиса (раздел «Внешний фильтр» ниже).
6. **Экспорт на роутер.** Стратегия geneva переносится на роутер как
   строка: в файл стратегии службы geneva (`packaging/`) или в
   zapret-gui. Применять её на роутере — только с подтверждения
   пользователя. В конфиг zapret2/nfqws2 она не экспортируется.

## Внешний фильтр: обход только заблокированного

Режим «Авто» AutoTuner (затем zapret-gui) пассивно смотрит на трафик,
находит заблокированные ресурсы и подбирает каждому стратегию geneva.
Стратегия должна применяться **только** к их трафику. Разным ресурсам
нужны разные стратегии, поэтому работает несколько `geneva run`, по одному
на стратегию, каждый со своим набором адресов, портов и протоколов,
который меняется на лету. Включать эти пути — по `features` из
`geneva version --json` (`filter`, `set_filter`, `first`,
`firewall_none_eval`), а не по версии.

### Linux: свои правила NFQUEUE

`geneva run --firewall none -q Q`, а правила ставит интегратор. Пример для
одной стратегии на очереди 320: наборы `адрес . протокол . порт`,
пропуск пакетов, которые отправил сам движок (метка `0x20000000`), —
первой строкой каждой цепочки:

```
table inet autotuner_320 {
	set dst4 { type ipv4_addr . inet_proto . inet_service; flags interval; }
	set dst6 { type ipv6_addr . inet_proto . inet_service; flags interval; }
	chain out {
		type filter hook postrouting priority 101; policy accept;
		meta mark & 0x20000000 == 0x20000000 return
		ip daddr . meta l4proto . th dport @dst4 ct original packets 1-12 queue num 320 bypass
		ip6 daddr . meta l4proto . th dport @dst6 ct original packets 1-12 queue num 320 bypass
	}
	chain in {
		type filter hook prerouting priority -99; policy accept;
		meta mark & 0x20000000 == 0x20000000 return
		ip saddr . meta l4proto . th sport @dst4 ct reply packets 1-6 queue num 320 bypass
		ip6 saddr . meta l4proto . th sport @dst6 ct reply packets 1-6 queue num 320 bypass
	}
}
```

```
nft add element inet autotuner_320 dst4 '{ 1.2.3.4 . tcp . 443, 5.6.7.8 . udp . 51820 }'
sudo geneva run -f strategy.txt -p 443 --proto tcp,udp -q 320 --firewall none -c unix:/run/at-320.sock
```

- Хуки postrouting 101 (после SNAT) и prerouting −99 (после conntrack):
  направление даёт хук, и пакеты считает conntrack (`ct original packets
  1-12` / `ct reply packets 1-6` — аналог `--first`).
- `queue num Q bypass`: пока geneva не слушает очередь, трафик идёт мимо.
- Набор пополняется на лету (`nft add element`), перезапуск geneva не
  нужен. Правила интегратор снимает сам при выходе.
- Для `eval`/`evolve` с `--firewall none` нужные правила печатает
  `geneva fw print --local-ports BASE --workers N -q Q` (`docs/EVAL.md`).

**Внимание, роутер:** не ставьте `geneva run -p 1-65535` в хук FORWARD. Там
направление пакета движок определяет по портам (`-p`), и с диапазоном на
все порты любой ответ сервера тоже окажется «исходящим». Используйте
postrouting/prerouting, как выше.

### Windows: `--filter` и `set_filter`

Каждый экземпляр получает выражение WinDivert на свой набор, например для
адреса `A` на TCP 443 и для DHT на UDP 6881:

```
(outbound and ((ip.DstAddr == A and tcp.DstPort == 443) or (udp and udp.SrcPort == 6881)))
 or (inbound and ((ip.SrcAddr == A and tcp.SrcPort == 443) or (udp and udp.DstPort == 6881)))
```

```
geneva.exe run -f strategy.txt -p 443 --proto tcp,udp --first 12 ^
  --filter-file C:\ProgramData\autotuner\s1.filter -c tcp:47201 --control-token T
geneva.exe ctl -c tcp:47201 -t T set_filter "filter=<новое выражение>"
geneva.exe ctl -c tcp:47201 -t T reload_filter
```

- Фильтр на сотни адресов — через `--filter-file` (до 64 КБ) и
  `reload_filter`, или `set_filter` (строка запроса до 1 МБ).
- Смена фильтра не рвёт открытые соединения; некомпилируемое выражение
  получает `ok:false` и `pos`, прежний фильтр остаётся. Каждая смена — событие
  `filter`.
- Выражения экземпляров должны быть непересекающимися (одинаковый
  `--priority`): WinDivert на одном уровне приоритета отдаёт пакет только
  одному хэндлу (`docs/ENGINE.md`, «Несколько экземпляров»).
- `--first N` на Windows считает движок (`stats.passed_first`).

## Server-side

Если у пользователя есть свой сервер (VPS) с сервисом, стратегию можно
искать на сервере: `geneva agent` работает на роутере или ПК в
цензурируемой сети, а `geneva evolve --agent` — на сервере.
Подробности — `docs/SERVER_SIDE.md`.

## Форматы

| Что | Формат |
|---|---|
| стратегия | одна строка, `docs/STRATEGY.md`; каноническую форму даёт `geneva check` |
| вывод `eval` | `фитнес<TAB>стратегия` построчно; код 0 — хоть одна прошла |
| вывод `evolve` | лучшие: `фитнес<TAB>прогонов<TAB>стратегия` |
| библиотека | `geneva library --json`: `[{strategy, rate, country, test, server_side, description, censors?}]`; `-q` — только стратегии |
| база | JSONL, `docs/EVOLVE.md`; `geneva db export --format txt` — список стратегий |
| события | JSON Lines, `docs/PROTOCOL.md` |
| коды возврата | `docs/PROTOCOL.md` |
| обмен стратегиями между AutoTuner и zapret-gui | JSON `{"format":"zapret-gui/geneva-strategies","version":1,"exported_at","items":[{strategy, transport, services, fitness?}]}` или текст — одна стратегия на строку; без адресов. Эталон — `core/geneva_share.py` zapret-gui; импорт проверяется `geneva check` и только пробуется на трафике, ничего не включает сам |
