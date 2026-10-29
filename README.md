# geneva_c

Порт [Geneva](https://github.com/Kkevsterrr/geneva) (Genetic Evasion) на C:
исполнитель стратегий обхода DPI и генетический подборщик стратегий в одном
статическом бинарнике для роутеров (OpenWrt, Keenetic/Entware) и ПК
(Linux, Windows).

План работ — `docs/PLAN.md`.

Сейчас готово (этапы 0–6): модель пакетов с семантикой полей Geneva, язык
стратегий, офлайн-применение к pcap, исполнитель на Linux (NFQUEUE) и на
Windows (WinDivert) с управлением через сокет, генетический алгоритм с
сохранением и продолжением поиска и база стратегий (оценка против
настоящего цензора — этап 7):

```
make && make test
build/geneva check '[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:corrupt},),)-| \/'
build/geneva apply -s '[TCP:flags:PA]-fragment{tcp:8:False}-|' -i in.pcap -o out.pcap -p 80
sudo build/geneva run -s '[TCP:flags:PA]-fragment{tcp:8:False}-| \/' -p 80,443 -c unix:/var/run/geneva.sock
sudo build/geneva ctl stats
geneva.exe run -s '[TCP:flags:S]-duplicate-| \/' -p 80,443 -c tcp:47123   # Windows, администратор
build/geneva evolve --mock-eval drop --checkpoint search.ckpt --db db.jsonl --target test
build/geneva db --db db.jsonl top -n 5
```

Исполнитель и правила firewall — `docs/ENGINE.md`, события и управляющий
сокет — `docs/PROTOCOL.md`, подборщик и база — `docs/EVOLVE.md`.

Язык стратегий и отличия от Geneva — `docs/STRATEGY.md`.
