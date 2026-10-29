# Протокол управления и телеметрии (proto 1)

Этот документ — контракт для интеграции geneva в zapret-gui, Zapret2_AutoTuner
и скрипты. Версия протокола — поле `proto` в событии `start` и в ответе
`version`. Несовместимые изменения увеличивают её; новые поля и события
могут добавляться без смены версии, поэтому клиенты должны пропускать
незнакомые поля и события.

## Поток событий (JSON Lines)

Источники:
- `geneva run|evolve --events -|stderr|FILE`: одна строка — один JSON-объект;
- подписка через управляющий сокет (`subscribe`), тот же формат.

У каждого события есть `ts` (мс с начала эпохи, UTC) и `ev` (тип).

| `ev` | Когда | Поля |
|---|---|---|
| `start` | запуск движка | `proto`, `version`, `mode` (`run`), `pid`, `backend` (`nfqueue`, `windivert`), `queue`, `ports`, `server_side` |
| `start` | запуск подборщика | `proto`, `version`, `mode` (`evolve`), `pid`, `population`, `generations`, `target`, `resume` |
| `generation` | (evolve) поколение оценено | `gen`, `unique`, `evaluated`, `avg_fitness`, `best_fitness`, `best` |
| `result` | (evolve) поиск закончен | `stopped`, `best` — `[{"strategy", "avg_fitness", "runs"}]` |
| `strategy` | стратегия установлена (при старте, `set_strategy`, `reload`, SIGHUP) | `strategy` (каноническая строка) |
| `ready` | правила firewall стоят (или открыт WinDivert), пакеты идут через движок | `backend`, `firewall` (`nft`, `iptables`, `windivert`, `none`) |
| `state` | `pause` / `resume` | `state` (`paused`, `running`) |
| `stats` | каждые `--stats-interval` с (по умолчанию 10 с, если есть `--events` или `--control`), по SIGUSR1 и при выходе | см. ниже |
| `log` | сообщение лога (в `--log-format json` и для подписчиков) | `level`, `mod`, `msg` |
| `error` | ошибка | `where` (`strategy`, `nfqueue`, `rawsend`, `firewall`, `windivert`, `control`, `reload`), `message` |
| `dropped` | только подписчику: он читал слишком медленно и потерял события | `count` |
| `exit` | завершение | `code` (код возврата), `reason` (`signal`, `control`, `duration`, `error`; у evolve — `done`, `signal`, `error`) |

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
| `out_trees`, `in_trees` | `[{"tree": "...", "fired": N}]` — срабатывания каждого дерева |

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

Строка запроса — не длиннее 64 КБ. Подписчику события приходят в то же
соединение; у событий нет `ok`, у ответов есть, так их и различают.

### Команды

| Команда | Параметры | Ответ / действие |
|---|---|---|
| `auth` | `token` | нужен первым, если задан токен (до него доступны только `auth` и `ping`). Неверный токен закрывает соединение |
| `ping` | — | `ts` |
| `version` | — | `version`, `proto` |
| `subscribe` / `unsubscribe` | — | включить / выключить поток событий в это соединение |
| `status` | — | `mode`, `state`, `version`, `pid`, `uptime_ms`, `backend`, `queue`, `ports`, `server_side`, `firewall`, `log_level`, `strategy`, `strategy_file` |
| `stats` | — | поля `stats` |
| `reset_stats` | — | обнулить счётчики и состояние стратегии (gas триггеров) |
| `set_strategy` | `strategy` | заменить стратегию; ответ — каноническая `strategy`. Ошибка разбора оставляет прежнюю |
| `reload` | — | перечитать `--strategy-file` |
| `pause` / `resume` | — | на паузе пакеты проходят без изменений, правила остаются |
| `log_level` | `level` (необязателен) | установить / узнать уровень: `error`, `warn`, `info`, `debug`, `trace` |
| `stop` | — | корректный выход со снятием правил (`exit` с `reason: control`) |

Подборщик (этапы 6–7) добавит `hall`, `best`, `fitness` и события
`generation`, `individual`, `best`, `eval_request`.

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

## Сигналы (POSIX)

| Сигнал | Действие |
|---|---|
| SIGHUP | перечитать `--strategy-file` |
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
