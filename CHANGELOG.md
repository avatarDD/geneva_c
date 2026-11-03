# Changelog

Протокол событий и управления — `proto 1` во всех версиях 1.x: новые поля,
события и команды только добавляются.

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
