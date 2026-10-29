# geneva_c

Порт [Geneva](https://github.com/Kkevsterrr/geneva) (Genetic Evasion) на C:
исполнитель стратегий обхода DPI и генетический подборщик стратегий в одном
статическом бинарнике для роутеров (OpenWrt, Keenetic/Entware) и ПК
(Linux, Windows).

План работ — `docs/PLAN.md`.

Сейчас готово (этапы 0–3): модель пакетов с семантикой полей Geneva, язык
стратегий, офлайн-применение к pcap и исполнитель на Linux (NFQUEUE):

```
make && make test
build/geneva check '[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:corrupt},),)-| \/'
build/geneva apply -s '[TCP:flags:PA]-fragment{tcp:8:False}-|' -i in.pcap -o out.pcap -p 80
sudo build/geneva run -s '[TCP:flags:PA]-fragment{tcp:8:False}-| \/' -p 80,443
```

Исполнитель, правила firewall и события — `docs/ENGINE.md`.

Язык стратегий и отличия от Geneva — `docs/STRATEGY.md`.
