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
   `{"id":N,"ok":true}`.

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
   --events - --workers 1`: на каждое `eval_request` Agent открывает
   страницу браузером (Playwright) с локальных портов `lports` — так
   стратегия применяется только к этим соединениям — и отвечает в stdin
   `{"id":N,"ok":true}` или `{"id":N,"fitness":F,"detail":"..."}`. Успех —
   полная загрузка, как в критериях AutoTuner, а не рукопожатие.
4. **Монитор.** Найденная стратегия работает в `geneva run -c tcp:PORT
   --control-token T` (на Windows unix-сокетов нет): события `stats`
   показывают, срабатывает ли стратегия, команда `stop` снимает
   перехват.
5. **Экспорт на роутер.** Стратегия geneva переносится на роутер как
   строка: в файл стратегии службы geneva (`packaging/`) или в
   zapret-gui. Применять её на роутере — только с подтверждения
   пользователя. В конфиг zapret2/nfqws2 она не экспортируется.

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
