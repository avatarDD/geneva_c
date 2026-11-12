# Протокол управления и телеметрии (proto 1)

Этот документ — контракт для интеграции geneva в zapret-gui, Zapret2_AutoTuner
и скрипты. Версия протокола — поле `proto` в событии `start` и в ответе
`version`. Несовместимые изменения увеличивают её; новые поля и события
могут добавляться без смены версии, поэтому клиенты должны пропускать
незнакомые поля и события.

## Поток событий (JSON Lines)

Источники:
- `geneva run|evolve|eval --events -|stderr|FILE`: одна строка — один JSON-объект;
- подписка через управляющий сокет (`subscribe`), тот же формат.

У каждого события есть `ts` (мс с начала эпохи, UTC) и `ev` (тип).

| `ev` | Когда | Поля |
|---|---|---|
| `start` | запуск движка | `proto`, `version`, `mode` (`run`), `pid`, `backend` (`nfqueue`, `windivert`), `queue`, `ports`, `server_side` |
| `start` | запуск цензора (`geneva censor`, `docs/CENSOR.md`) | `proto`, `version`, `mode` (`censor`), `pid`, `censor`, `queue`, `ports` |
| `censorship` | (censor) цензор сработал | `censor`, `action` (`drop`, `rst`, `dns`), `src`, `dst`, `proto`, `sport`, `dport`, `injected` |
| `reset` | (censor) SIGHUP сбросил состояние цензора | — |
| `start` | запуск агента server-side (`geneva agent`) | `proto`, `version`, `mode` (`agent`), `pid` |
| `connected`, `disconnected` | (agent `--connect`) соединение с оценщиком | `addr` |
| `start` | запуск подборщика | `proto`, `version`, `mode` (`evolve`), `pid`, `population`, `generations`, `target`, `resume` |
| `generation` | (evolve) поколение оценено | `gen`, `unique`, `evaluated`, `avg_fitness`, `best_fitness`, `best` |
| `baseline` | (evolve) проба без стратегии | `blocked`, `fitness`, `outcome`, `detail` |
| `eval` | (evolve, eval) стратегия оценена | `strategy`, `fitness`, `runs`, `outcome` (`ok`, `reset`, `injected`, `connect_timeout`, `timeout`, `broken`, `failed`), `detail` |
| `eval_request` | (`--probe external`) контроллер должен сделать прогон и ответить в stdin (`docs/EVAL.md`) | `id`, `strategy`, `run`, `lports` |
| `result` | (evolve) поиск закончен | `stopped`, `best` — `[{"strategy", "avg_fitness", "runs"}]` |
| `strategy` | стратегия установлена (при старте, `set_strategy`, `reload`, SIGHUP) | `strategy` (каноническая строка) |
| `filter` | (Windows) фильтр WinDivert установлен: при старте и после каждой успешной смены | `filter` (итоговое выражение, с `and not loopback`), `source` (`start`, `set_filter`, `reload_filter`) |
| `ready` | правила firewall стоят (или открыт WinDivert), пакеты идут через движок | `backend`, `firewall` (`nft`, `iptables`, `windivert`, `none`) |
| `ready` | (agent) агент ждёт оценщика или начал к нему подключаться | `addr` |
| `state` | `ext_flows` | `limit` (необязателен, 1000) | (`--ext`) потоки conntrack (`docs/EXT.md`, X7a): `flows` — массив объектов `proto`, `client`, `cport`, `server`, `sport`, `state` (TCP: `syn`, `est`, `fin`), `age_ms`, `idle_ms`, `profile_n`, `profile`, `l7`, `host`, `incoming_ttl`, `autolist`, `out` и `in` (`n`, `d`, `b`; TCP: `s`, `win`, `mss`); `total`, `truncated`, `ctrack` |
| `ext_keys` | — | (`--ext`) счётчики неудач автосписка: `autolist` — массив `{profile_n, profile, file, fails: [{host, count, expire_s}]}`; с `--ext-auto` ещё `detect` — ключи детектора (как `impaired` у `ext_status`); с `--ext-arm` ещё `tuner` — массив `{key, arm, fails}` (до 1000) |
| `ext_status` | — | (`--ext`) `auto` (`observe` или `off`); с `--ext-auto`: `source` (`nflog` на Linux, `windivert` на Windows), `nflog_group` (только Linux), `observing`, `packets`, `lost` (сколько раз ядро теряло копии), `flows`, `flows_ok`, `flows_failed`, `keys`, `counters` (байты потоков считаются: ctnetlink работает или, на Windows, их считает сам детектор), `watched` (потоков под счётчиками), `capacity` (ёмкость канала C, байт/с, 0 — неизвестна), `link_degraded`, `impaired` — массив `{key, level (port, net, ip, host), impaired, class, flows, fails, classes: {КЛАСС: число}}` ; `policy` — `{gen, keys, retired}` (поколение политики ключей, ключей в ней, заменённых снапшотов не освобождено) и `surgical` (хирургический путь включён); с `--ext-arm` — `tuner`: `{keys, rotations, state}` (ключей, смен рук, файл `--ext-state`) (`docs/EXT.md`, X9a, X9b, X9c, X10b, X11a) |
| `pause` / `resume` | `state` (`paused`, `running`) |
| `stats` | каждые `--stats-interval` с (по умолчанию 10 с, если есть `--events` или `--control`), по SIGUSR1 и при выходе | см. ниже |
| `ext_flow` | (`--ext-auto`) поток с неудачей | `proto`, `client`, `cport`, `server`, `sport`, `host` (если известно), `class` (`RETRANS`, `RST_IN`, `RST_INJECT`, `REDIRECT`, `UDP_NOANSWER`, `BLACKHOLE_SYN`, `ICMP_PROHIBIT`, `FREEZE_N`, `THROTTLE`, `DNS_POISON`), `why`; успех, который потом оказался заморозкой, замедлением или подменой DNS, тоже даёт `ext_flow` |
| `ext_impaired` | (`--ext-auto`) ключ стал заблокированным или снова здоровым | `key`, `level` (`port`, `net`, `ip`, `host`), `impaired`, `class` (у заблокированного), `flows`, `fails` |
| `ext_class` | (`--ext-auto`) у заблокированного ключа сменился класс | `key`, `level`, `class`, `flows`, `fails` |
| `ext_link` | (`--ext-auto`) неудачи у 30 % и больше адресов за 30 с (хотя бы у 5): скорее сбой своего канала (`degraded: true`), или это прошло (`false`) | `degraded`, `bad`, `active` |
| `ext_arm` | (`--ext-arm`) ключ тюнера перешёл на другую руку | `key` (`ТАБЛИЦА/КЛЮЧ`), `arm` (с 1), `arms`, `final` (рука `final`: дальше не меняется) |
| `ext_pkt` | (`--ext`) пакет прошёл x-действие `xlog` (`docs/EXT.md`, X5b) | `dir` (`out`, `in`), `tree`, `l7payload`, `len`; по параметрам — `msg`, `pkt`, `pos`, `hex`; у куска собранного сообщения `piece`, `pieces` |
| `log` | сообщение лога (в `--log-format json` и для подписчиков) | `level`, `mod`, `msg` |
| `error` | ошибка | `where` (`strategy`, `nfqueue`, `rawsend`, `firewall`, `windivert`, `control`, `reload`, `filter`), `message`; у `filter` для некомпилируемого выражения ещё `pos` |
| `dropped` | только подписчику: он читал слишком медленно и потерял события | `count` |
| `exit` | завершение | `code` (код возврата), `reason` (`signal`, `control`, `duration`, `error`; у evolve — `done`, `signal`, `not_blocked`, `error`) |

Поля `stats` (и ответа на команду `stats`):

| Поле | Смысл |
|---|---|
| `uptime_ms` | время работы |
| `paused` | движок на паузе |
| `pkts_out`, `pkts_in` | пакеты, пришедшие из очереди, по направлениям |
| `triggered` | пакеты, на которых сработало хотя бы одно дерево |
| `accepted` | вердикты «пропустить» |
| `modified` | пакеты, ушедшие вердиктом с изменёнными байтами |
| `dropped` | пакеты, отброшенные стратегией |
| `injected` | дополнительные пакеты, отправленные движком (raw-сокет или WinDivert) |
| `delayed` | пакеты, отложенные `sleep` |
| `pending` | отложенные пакеты, ещё не отправленные |
| `send_errors`, `verdict_errors`, `parse_errors` | ошибки |
| `overruns` | переполнения очереди сокета (ядро теряло пакеты для движка) |
| `passed_first` | (`--first` на Windows) пакеты сверх первых N своего потока, пропущенные без стратегии |
| `flow_evictions` | (`--first` на Windows) живые потоки, вытесненные из заполненной таблицы (65536) |
| `held` | (`--ext`) пакеты, задержанные до конца сборки ClientHello; потом они отправляются заново через стратегию |
| `healthy` | (`--ext` на Linux с `--ext-healthy-mark`) соединения, которые движок отпустил мимо очереди (хирургический путь, `docs/EXT.md`, X10b) |
| `workers`, `worker_pkts` | (`--ext-workers` больше 1) число воркеров и пакеты каждого из них (`pkts_out + pkts_in`, по порядку очередей): как правила разложили потоки |
| `out_trees`, `in_trees` | `[{"tree": "...", "fired": N}]` — срабатывания каждого дерева (с `--ext-workers` — сумма по копиям стратегии всех воркеров) |

## Управляющий сокет

`geneva run --control ADDR [--control-token TOKEN]`, где ADDR:
- `unix:/var/run/geneva.sock` (Linux, роутеры). Файл создаётся с правами
  0600 и удаляется при выходе. Если файл остался от убитого процесса, он
  заменяется; если сокет живой, запуск завершается ошибкой;
- `tcp:PORT` — 127.0.0.1:PORT;
- `tcp:HOST:PORT`, `tcp:[::1]:PORT`. Адрес не из loopback требует токен.

Токен также берётся из переменной `GENEVA_CONTROL_TOKEN`. Одновременно
обслуживается до 16 клиентов.

Обмен построчный: клиент шлёт JSON-объект и `\n`, сервер отвечает одной
строкой с тем же `id` (число или строка, необязателен):

```
-> {"id":1,"cmd":"status"}
<- {"id":1,"ok":true,"mode":"run","state":"running",...}
-> {"id":2,"cmd":"set_strategy","strategy":"[TCP:flags:PA]-drop-| \\/"}
<- {"id":2,"ok":false,"error":"..."}
```

Строка запроса — не длиннее 64 КБ, у `set_filter` — до 1 МБ (фильтр на
много адресов). Более длинная строка получает `ok:false` («request line too
long»), и соединение закрывается. Подписчику события приходят в то же
соединение; у событий нет `ok`, у ответов есть, так их и различают.

### Команды

| Команда | Параметры | Ответ / действие |
|---|---|---|
| `auth` | `token` | нужен первым, если задан токен (до него доступны только `auth` и `ping`). Неверный токен закрывает соединение |
| `ping` | — | `ts` |
| `version` | — | `version`, `proto` |
| `subscribe` / `unsubscribe` | — | включить / выключить поток событий в это соединение |
| `status` | — | `mode`, `state`, `version`, `pid`, `uptime_ms`, `backend`, `queue`, `ports`, `server_side`, `firewall`, `filter` (текущее выражение WinDivert; на Linux `null`), `filter_file`, `log_level`, `strategy`, `strategy_file`; с `--ext-workers` больше 1 ещё `workers` (очереди — `queue` .. `queue + workers - 1`) |
| `stats` | — | поля `stats` |
| `reset_stats` | — | обнулить счётчики и состояние стратегии (gas триггеров) |
| `set_strategy` | `strategy` | заменить стратегию; ответ — каноническая `strategy`. Ошибка разбора оставляет прежнюю |
| `reload` | — | перечитать `--strategy-file` |
| `set_filter` | `filter` | (Windows) заменить фильтр WinDivert на лету (`docs/ENGINE.md`); ответ — итоговый `filter`. Некомпилируемое выражение: `ok:false`, `error`, `pos`, прежний фильтр остаётся. На Linux `ok:false`, `error: "windows only"` |
| `reload_filter` | — | (Windows) перечитать `--filter-file` и установить, как `set_filter`; без `--filter-file` — `ok:false`. На Linux `ok:false`, `error: "windows only"` |
| `reload_lists` | — | (`--ext`) перечитать файлы `--hostlist*`, `--ipset*` всех профилей (`docs/EXT.md`); ответ — `files`, сколько перечитано. Без `--ext` — `unknown command`. SIGHUP делает то же |
| `pause` / `resume` | — | на паузе пакеты проходят без изменений, правила остаются |
| `log_level` | `level` (необязателен) | установить / узнать уровень: `error`, `warn`, `info`, `debug`, `trace` |
| `stop` | — | корректный выход со снятием правил (`exit` с `reason: control`) |

У `geneva evolve` и `geneva eval` управляющего сокета нет: ими управляют
сигналы (SIGINT/SIGTERM — остановка с сохранением checkpoint), а
прогресс идёт событиями. Агент server-side (`geneva agent`) говорит по
тому же протоколу и добавляет команды `hello` и `probe`
(`docs/SERVER_SIDE.md`).

### geneva ctl

```
geneva ctl -c unix:/var/run/geneva.sock status
geneva ctl set_strategy strategy='[TCP:flags:PA]-fragment{tcp:8:True}-| \/'
geneva ctl log_level level=debug
geneva ctl subscribe --until exit          # поток событий до выхода движка
geneva ctl --json '{"cmd":"pause"}'
```

Адрес по умолчанию — `$GENEVA_CONTROL` или `unix:/var/run/geneva.sock`,
токен — `-t` или `$GENEVA_CONTROL_TOKEN`. Печатается ответ сервера,
код возврата 1 при `ok:false`, 6 при ошибке соединения.

### Возможности сборки

`geneva version --json` даёт массив `features`. Новые пути интеграторы
включают по этим флагам, а не по номеру версии:

| Флаг | Где | Смысл |
|---|---|---|
| `nfqueue` / `windivert` | Linux / Windows | бэкенд движка |
| `ipv6`, `pcap`, `control` | везде | IPv6, `--pcap`, управляющий сокет |
| `filter` | Windows | `--filter`, `--filter-file`, `--priority` |
| `set_filter` | Windows | команды `set_filter`, `reload_filter`, событие `filter` |
| `first` | Linux, Windows | `--first N` работает (Windows: счёт в движке, с 1.1) |
| `firewall_none_eval` | Linux | `eval`/`evolve --firewall none` |
| `external_workers` | везде | `--probe external` с `--workers N`: запросы воркеров идут одновременно, ответы по `id` в любом порядке (с 1.2) |

## Сигналы (POSIX)

| Сигнал | Действие |
|---|---|
| SIGHUP | перечитать `--strategy-file`; у `geneva censor` — сбросить состояние цензора |
| SIGUSR1 | событие `stats` |
| SIGINT, SIGTERM | выход со снятием правил firewall |

## Коды возврата

| Код | Смысл |
|---|---|
| 0 | успех |
| 1 | ошибка выполнения; у `geneva ctl` — ответ `ok:false` |
| 2 | неверные аргументы |
| 3 | стратегия не разбирается |
| 4 | нет прав или модулей ядра (NFQUEUE, raw-сокеты) |
| 5 | правила firewall не применились |
| 6 | ошибка ввода-вывода (файл, сокет) |
| 7 | (evolve) цель доступна без стратегии |
