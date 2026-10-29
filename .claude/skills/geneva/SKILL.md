---
name: geneva
description: Reference for geneva_c, the C port of Geneva — repository map, build and test commands, the strategy language, every CLI command with its exit codes, the events and control protocol, server-side evaluation with geneva agent, and how zapret-gui and Zapret2_AutoTuner embed it. Read before changing geneva_c or writing code that runs geneva.
---

# geneva_c

One static C11 binary, `geneva <command>`, with no dependencies beyond libc
(pthreads, sockets; Windows: ws2_32, iphlpapi, WinDivert at run time). It
runs Geneva strategies on live traffic and searches for new ones. Targets:
routers (OpenWrt, Keenetic/Entware; mips, mipsel, arm, aarch64, ...), Linux
and Windows PCs. User-facing docs are in Russian (`docs/`); README has an
English twin.

## Repository map

| Path | What |
|---|---|
| `src/pkt*.c` | packet model; Geneva's fields with scapy semantics (`dataofs < 5` means a 20-byte header, flags compared as strings) |
| `src/strategy.c` | parser, printer, action trees (`tamper`, `duplicate`, `fragment`, `drop`, `sleep`, `trace`) |
| `src/engine.c`, `eng_nfq.c`, `eng_windivert.c`, `nfq.c`, `rawsend.c`, `fw.c` | live engine: NFQUEUE / WinDivert, firewall rules (nft or iptables), control socket |
| `src/evolve.c`, `mutate.c` | Geneva's genetic algorithm; checkpoints |
| `src/evaluator.c`, `probe.c` | fitness, probes (http, tls, dns, tcp, exec, external), engine slots per worker |
| `src/agent.c`, `cmd_agent.c` | server-side evaluation: remote probes over the control protocol |
| `src/censor.c`, `cmd_censor.c` | Geneva's lab censors 1–11 + DNS censor on a router namespace |
| `src/library.c`, `library_data.h` | Geneva's `library.py` strategies; regenerate with `tools/gen_library.py` |
| `src/sdb.c` | strategy database (JSONL) |
| `src/ctl.c`, `json.c`, `log.c` | line-JSON control socket, JSON reader/writer, logging and events |
| `src/cmd_*.c`, `main.c` | commands |
| `tests/*.c` | unit tests (`make test`), no framework |
| `tests/e2e/*.sh` | root-only tests in network namespaces |
| `packaging/` | procd (OpenWrt), S-script (Entware) + ndm hook, systemd |
| `tools/` | corpus extraction and differential test against Python Geneva, library generator |

## Rules

- C11, `-Wall -Wextra -Wshadow`, builds clean with gcc, clang, mingw and
  `zig cc` for every router target; CI uses `-Werror`. Keep the binary
  small: no new libraries.
- POSIX and Windows paths go through `plat.h`. Linux-only code sits under
  `#ifdef __linux__` with a Windows stub (unused variables break
  `-Werror`).
- Geneva's semantics are the reference. A deviation is a bug unless it is
  listed under "differences" in the matching doc. Never execute upstream
  Python Geneva in agent sessions; read it, or parse it with
  `ast.literal_eval` as the tools do.
- Third-party binaries (WinDivert) come only from the official release.
- Nothing is applied to a router or zapret-gui without the user's
  confirmation. No telemetry: events go only where `--events` points.
- Firewall rules are removed on every exit path except SIGKILL.
- Every change comes with unit tests; behaviour on real traffic with an
  e2e case.

## Build and test

```
make                         # build/geneva
make test                    # unit tests (about 6500 checks)
make STATIC=1 SMALL=1        # router build
make CC="zig cc -target mipsel-linux-musleabi" STATIC=1 SMALL=1
make CC=x86_64-w64-mingw32-gcc
sudo tests/e2e/run.sh build/geneva          # engine
sudo tests/e2e/evolve.sh build/geneva       # search against a keyword censor
sudo tests/e2e/censors.sh build/geneva [1 2 ... dns evolve server]
sudo tests/e2e/initscripts.sh build/geneva
```

For ASan use gcc (`CC=gcc CFLAGS="-O1 -g -fsanitize=address,undefined" O=build-asan`).

## Strategy language (docs/STRATEGY.md)

```
strategy := out-forest "\/" in-forest
tree     := "[" PROTO:field:value[:gas] "]-" action "-|"
action   := name["{" params "}"]["(" left "," right ")"]
```

- `[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:corrupt},),)-| \/`
- Values: integers or strings; a trailing `*` is a substring match.
- In the inbound forest only `tamper` and `drop`.
- A tree with an empty action (`\/ [TCP:flags:R]-|`) drops the packet,
  as in Geneva.
- `geneva check -f FILE` validates and prints the canonical form (exit 3
  on errors).

## Commands

| Command | Purpose | Root |
|---|---|---|
| `run -s S -p PORTS [-c ADDR] [-e FILE]` | engine on live traffic | yes |
| `eval [-s S]... [-f FILE\|-]` | fitness per strategy; without strategies the baseline | for strategies |
| `evolve --host H ...` | genetic search; `--checkpoint`/`--resume`, `--db` | yes |
| `agent --listen ADDR \| --connect ADDR --token T` | probes for server-side evaluation | no |
| `library [--country C] [--test T] [--censor N] [-q] [--json]` | Geneva's strategies | no |
| `db --db F list\|top\|show\|export\|import\|prune\|compact` | strategy database | no |
| `censor -c N` | lab censor on a Linux router; SIGHUP resets | yes |
| `check`, `apply` | validate, apply to a pcap | no |
| `fw print\|up\|down` | the rules `run` uses | yes |
| `ctl CMD [k=v]` | control socket client | — |
| `version --json` | version, `proto`, os, arch, features | no |

Defaults: `run` NFQUEUE 310, the evaluator 311, the censor 400 (zapret-gui
keeps nfqws2 on 300–303); the mark of injected packets is `0x20000000`;
the evaluator's local ports start at 30000, 64 per worker.

Exit codes: 0 ok, 1 failure (eval/evolve: nothing passed), 2 usage, 3 bad
strategy, 4 no privileges or kernel support, 5 firewall, 6 I/O, 7 evolve:
target not blocked.

## Events and control (docs/PROTOCOL.md, proto 1)

- `--events -|stderr|FILE`: JSON Lines, every object has `ts` and `ev`.
  Main events: `start` (`mode`: run, evolve, censor, agent), `ready`,
  `strategy`, `stats`, `eval`, `generation`, `baseline`, `result`,
  `eval_request`, `error`, `exit`. Skip unknown events and fields.
- Control socket (`run -c unix:/path|tcp:PORT|tcp:HOST:PORT`): one JSON
  object per line, answers carry the request `id` and `ok`; events have no
  `ok`. Commands: `auth`, `ping`, `version`, `subscribe`, `status`,
  `stats`, `reset_stats`, `set_strategy`, `reload`, `pause`, `resume`,
  `log_level`, `stop`. A non-loopback address needs a token.
- External probe (`--probe external --events - --workers 1`): geneva emits
  `eval_request {id, strategy, run, lports}`; the controller connects from
  a local port in `lports` and writes `{"id":N,"ok":true}` or
  `{"id":N,"fitness":F}` to stdin.

## Server-side (docs/SERVER_SIDE.md)

`eval`/`evolve --agent tcp:HOST:PORT` (or `--agent-listen ADDR` for an
agent behind NAT that dials in with `--connect`) on the server: the
strategy applies to the service port (`--port`), one worker; the agent
inside the censored network runs `http`, `tls`, `dns`, `tcp` probes on
request (`auth`, `hello`, `probe` over the control protocol) and refuses
`exec`/`external`. Token via `--token` / `--agent-token` or
`GENEVA_AGENT_TOKEN`.

## Embedding (docs/INTEGRATION.md)

- zapret-gui (Python on the router): install the binary and the service
  script from `packaging/`, keep the strategy in a file, `reload` (SIGHUP)
  or `set_strategy` to change it, read `status`/`stats`/`subscribe` from
  `unix:/opt/var/run/geneva.sock`.
- Zapret2_AutoTuner (C# on a PC): the privileged Agent runs
  `geneva evolve --probe external` and answers `eval_request` with
  browser checks; `geneva run -c tcp:PORT --control-token T` for
  monitoring. Geneva strategies are not nfqws2 strategies and are never
  exported into zapret2 configs.

## Pitfalls

- `censor` models keep Geneva's quirks on purpose (single TCB, refcounts in
  8b, no checksum check except 10/11); tests pin them.
- `censor_new_run` bypasses packets of flows seen before a reset; UDP is
  excluded.
- An `nft` chain must not be named after an nft keyword (`fwd` broke).
- `curl` in e2e probes needs `-f`, or HTTP errors count as success.
- On Windows there are no unix sockets: use `tcp:PORT` with a token for
  non-loopback.
