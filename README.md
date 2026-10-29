# geneva_c

[English](README.en.md)

Порт [Geneva](https://github.com/Kkevsterrr/geneva) (Genetic Evasion) на C.
Исполнитель стратегий обхода DPI и генетический подборщик стратегий
собраны в один статический бинарник без зависимостей. Он работает на
роутерах (OpenWrt, Keenetic/Entware, любой Linux с NFQUEUE) и на ПК (Linux,
Windows через WinDivert).

> [!IMPORTANT]
> Данный материал подготовлен в научно-технических целях.
> Использование предоставленных материалов в целях отличных от ознакомления может являться нарушением действующего законодательства.
> Автор не несет ответственности за неправомерное использование данного материала.

> [!WARNING]
> **Вы пользуетесь этой инструкцией на свой страх и риск!**
> 
> Автор не несёт ответственности за порчу оборудования и программного обеспечения, проблемы с доступом и потенцией.
> Подразумевается, что вы понимаете, что вы делаете.

---

## Возможности

- **Язык стратегий Geneva**: триггеры, действия `duplicate`, `fragment`,
  `tamper`, `drop`, `sleep`, деревья для исходящих и входящих пакетов.
  Поля и их семантика повторяют Geneva (scapy), отличия описаны.
- **Исполнитель** (`geneva run`): NFQUEUE на Linux, WinDivert на Windows.
  Правила firewall (nft или iptables) ставятся сами и снимаются при выходе.
  Есть управляющий сокет, события JSON Lines и замена стратегии на лету.
- **Подборщик** (`geneva evolve`): генетический алгоритм Geneva с
  сохранением и продолжением поиска, базой найденных стратегий и
  параллельной оценкой.
- **Оценщик** (`geneva eval`): пробы `http`, `tls`, `dns`, `tcp`, внешняя
  команда или внешний контроллер. Фитнес и штрафы как в Geneva. Успехом
  считается полный ответ, а не рукопожатие.
- **Server-side** (`geneva agent`): стратегии на своём сервере, пробы из
  цензурируемой сети.
- **Библиотека** (`geneva library`): стратегии из `library.py` Geneva с
  долями успеха против цензоров Китая, Индии и Казахстана.
- **Лабораторные цензоры** (`geneva censor`): цензоры Geneva 1–11 и
  DNS-цензор для проверки стратегий на стенде.
- **Офлайн** (`geneva apply`, `geneva check`): стратегия над pcap, проверка
  и каноническая форма стратегий.

## Как пользоваться: пример

Допустим, сайт `blocked.example` не открывается, и нужно подобрать для него
стратегию на Linux-ПК или роутере. Всё, что меняет трафик, запускается
от root.

**1. Убедиться, что сайт заблокирован.** Проба без стратегии (права не
нужны):

```
$ geneva eval --host blocked.example --probe tls
-360	(no strategy)
```

Положительный фитнес (`400`) значит, что сайт открывается и подбирать
нечего. Отрицательный показывает, как именно сайт не открылся:
`reset` — сброс, `injected` — подмена ответа, `timeout` — тишина.
Подробности пишутся в лог.

**2. Попробовать готовые стратегии Geneva:**

```
$ geneva library -q --test http | sudo geneva eval --host blocked.example --probe tls -f -
-360	\/
398	[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:corrupt},),)-
...
```

Каждая строка — фитнес и стратегия. Подходят стратегии с фитнесом больше
нуля.

**3. Если ничего не подошло — подобрать.** Поиск можно прервать (Ctrl+C) и
продолжить с `--resume`; найденное копится в базе:

```
$ sudo geneva evolve --host blocked.example --probe tls --population 50 --generations 20 \
      --checkpoint /opt/geneva/search.ckpt --db /opt/geneva/db.jsonl
398	2	[TCP:flags:PA]-fragment{tcp:8:True}-| \/
$ geneva db --db /opt/geneva/db.jsonl top -n 3
```

**4. Включить стратегию для всего трафика на порты 80 и 443:**

```
$ sudo geneva run -s '[TCP:flags:PA]-fragment{tcp:8:True}-| \/' -p 80,443 -c unix:/var/run/geneva.sock
$ sudo geneva ctl stats          # в другом терминале: срабатывания стратегии
```

Ctrl+C останавливает движок и снимает правила firewall.

**5. Сделать постоянным.** Запишите стратегию в файл и включите службу
(см. «Установка» ниже):

```
echo '[TCP:flags:PA]-fragment{tcp:8:True}-| \/' > /opt/etc/geneva/strategy.txt   # Entware
sed -i 's/^ENABLED=no/ENABLED=yes/' /opt/etc/geneva/geneva.conf
/opt/etc/init.d/S51geneva start
```

Стратегии в примерах — для иллюстрации; что сработает у вас, зависит от
DPI вашей сети.

## Быстрый старт

```
make && make test
build/geneva check '[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:corrupt},),)-| \/'
build/geneva library --country china --test http
build/geneva eval --host blocked.example                  # заблокирован ли ресурс (без прав)
sudo build/geneva eval --host blocked.example -s '[TCP:flags:PA]-fragment{tcp:-1:True}-| \/'
build/geneva library -q --country china | sudo build/geneva eval --host blocked.example -f -
sudo build/geneva evolve --host blocked.example --workers 8 --checkpoint search.ckpt --db db.jsonl
build/geneva db --db db.jsonl top -n 5
sudo build/geneva run -s '[TCP:flags:PA]-fragment{tcp:8:False}-| \/' -p 80,443 -c unix:/var/run/geneva.sock
sudo build/geneva ctl stats
geneva.exe run -s '[TCP:flags:S]-duplicate-| \/' -p 80,443 -c tcp:47123   # Windows, администратор
```

## Установка

Готовые бинарники для всех архитектур публикуются в релизах:
`geneva-ВЕРСИЯ-linux-АРХИТЕКТУРА.tar.gz` (статический бинарник, документация
и `packaging/`; архитектуры x86_64, x86, aarch64, armv7, armv6, armv5,
mips, mipsel, mips64, riscv64, ppc; mips и mipsel — soft-float, как на
большинстве роутеров) и `geneva-ВЕРСИЯ-windows-АРХИТЕКТУРА.zip` (x86_64 и
x86 с WinDivert из официального релиза; arm64 без него, так как у
WinDivert нет драйвера для ARM64). Суммы — в `SHA256SUMS`. Для сборки
из исходников нужен только компилятор C (gcc, clang, `zig cc` или mingw):

```
make                                       # для этой машины
make STATIC=1 SMALL=1                      # статический и маленький, для роутера
make CC="zig cc -target mipsel-linux-musleabi" STATIC=1 SMALL=1
make CC=x86_64-w64-mingw32-gcc            # Windows
```

На Linux нужны ядро с NFQUEUE (`nfnetlink_queue`, `xt_NFQUEUE` или
`nft_queue`) и `nft` или `iptables`. На Windows рядом с `geneva.exe`
должны лежать `WinDivert.dll` и `WinDivert64.sys` из
[официального релиза](https://github.com/basil00/WinDivert/releases).

Скрипты служб лежат в `packaging/`:

| Система | Файлы | Куда |
|---|---|---|
| OpenWrt (procd) | `openwrt/geneva.init`, `openwrt/geneva.config` | `/etc/init.d/geneva`, `/etc/config/geneva`; бинарник в `/usr/bin/geneva` |
| Entware (Keenetic и др.) | `entware/S51geneva`, `entware/geneva.conf`, `entware/010-geneva.sh` | `/opt/etc/init.d/`, `/opt/etc/geneva/`, `/opt/etc/ndm/netfilter.d/` (Keenetic); бинарник в `/opt/bin/geneva` |
| Linux (systemd) | `systemd/geneva.service`, `systemd/geneva-agent.service`, `systemd/geneva.conf` | `/etc/systemd/system/`, `/etc/geneva/`; бинарник в `/usr/local/bin/geneva` |

Стратегия хранится в файле (одна строка, по умолчанию
`/etc/geneva/strategy.txt` или `/opt/etc/geneva/strategy.txt`). Служба
включается в конфиге (`enabled`/`ENABLED`). `reload` перечитывает
стратегию без разрыва соединений, `stop` снимает правила firewall.

## Документация

| Тема | Файл |
|---|---|
| язык стратегий и отличия от Geneva | `docs/STRATEGY.md` |
| исполнитель, правила firewall, Windows | `docs/ENGINE.md` |
| события, управляющий сокет, коды возврата | `docs/PROTOCOL.md` |
| пробы, фитнес, оценщик | `docs/EVAL.md` |
| подборщик, checkpoint, база | `docs/EVOLVE.md` |
| server-side и `geneva agent` | `docs/SERVER_SIDE.md` |
| лабораторные цензоры и стенд | `docs/CENSOR.md` |
| встраивание в zapret-gui и Zapret2_AutoTuner | `docs/INTEGRATION.md` |
| план работ | `docs/PLAN.md` |

Справочник для ИИ-агентов, которые работают с этим репозиторием или
встраивают geneva, — `.claude/skills/geneva/SKILL.md`.

## Тесты

```
make test                                  # unit-тесты
sudo tests/e2e/run.sh build/geneva         # движок в network namespace
sudo tests/e2e/censors.sh build/geneva     # цензоры, подбор, server-side
sudo tests/e2e/initscripts.sh build/geneva # скрипты служб
```

## Лицензия

BSD 3-Clause, как у Geneva. Geneva: Copyright (c) 2020, University of
Maryland College Park. Библиотека стратегий (`src/library_data.h`)
сгенерирована из `library.py` Geneva скриптом `tools/gen_library.py`.
