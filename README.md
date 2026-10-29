# geneva_c

Порт [Geneva](https://github.com/Kkevsterrr/geneva) (Genetic Evasion) на C:
исполнитель стратегий обхода DPI и генетический подборщик стратегий в одном
статическом бинарнике для роутеров (OpenWrt, Keenetic/Entware) и ПК
(Linux, Windows).

План работ — `docs/PLAN.md`.

Сейчас готово (этапы 0–2): модель пакетов с семантикой полей Geneva, язык
стратегий и офлайн-применение к pcap:

```
make && make test
build/geneva check '[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:corrupt},),)-| \/'
build/geneva apply -s '[TCP:flags:PA]-fragment{tcp:8:False}-|' -i in.pcap -o out.pcap -p 80
```

Язык стратегий и отличия от Geneva — `docs/STRATEGY.md`.
