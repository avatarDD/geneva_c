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
| `src/engine.c`, `eng_nfq.c`, `eng_windivert.c`, `nfq.c`, `rawsend.c`, `fw.c` | live engine: NFQUEUE / WinDivert, firewall rules (nft or iptables), WinDivert filters (`--filter`, `set_filter` handle switch), control socket |
| `src/flowtab.c` | `--first N` on Windows: flow table (5-tuple by direction, FIN/RST/idle expiry, LRU at 65536) |
| `src/evolve.c`, `mutate.c` | Geneva's genetic algorithm; checkpoints |
| `src/evaluator.c`, `probe.c` | fitness, probes (http, tls, dns, tcp, exec, external), engine slots per worker |
| `src/agent.c`, `cmd_agent.c` | server-side evaluation: remote probes over the control protocol |
| `src/censor.c`, `cmd_censor.c` | Geneva's lab censors 1–11 + DNS censor on a router namespace |
| `src/library.c`, `library_data.h` | Geneva's `library.py` strategies; regenerate with `tools/gen_library.py` |
| `src/sdb.c` | strategy database (JSONL) |
| `src/ctl.c`, `json.c`, `log.c` | line-JSON control socket, JSON reader/writer, logging and events |
| `src/cmd_*.c`, `main.c` | commands |
| `src/ext_opt.c`, `src/ext/` | the `--ext` extensions (zapret2 parity, `docs/EXT_ROADMAP.md`, done so far: `docs/EXT.md`); `src/ext/` is left out by `make EXT=0`. Options that need `--ext` get `EXT_HELP("...")` as help: `--help` lists them last under "Extensions (with --ext):". `crypto*` (AES-GCM, SHA-256, HKDF), `quic`/`tls` (Initial decryption, ClientHello SNI), `censor_x` (lab censors 12-20), `ctrack` (zapret2 conntrack), `range` (zapret2 position ranges), `xtrig` (`FLOW:`/`META:`/`L7:` triggers via `strategy_set_xtrig`, per-flow tree cutoff), `l7` (zapret2 protocol/payload probes, SNI/Host, QUIC CRYPTO defrag), `markers` (zapret2 position markers), `xl7` (per-flow L7, ClientHello reassembly over TCP segments and QUIC Initials: held packets keep their verdict pending, `engine_hold`/`engine_replay`), `xact.c`/`xact_tcp.c`/`xact_http.c`/`xact_misc.c` (x-actions `xfake{...}` etc. via `strategy_set_xact`: zapret2's desync functions, common args, fooling, ipfrag2, MSS segmentation; a result with `gpkt.xgen` makes the engine send everything in list order through `send_x`, `xdrop` marks a VERDICT_DROP that still goes down the tree; per-packet state shared by all trees of one `strategy_apply_x` call (zapret2's `desync` table: `xtlsclone` blobs, `xtag` label) hangs off `strat_xenv.dyn` and is freed by `strat_xact.done`; `xa_cutoff` is zapret2's instance cutoff per flow; `xact_comb.c` has the combinators `xwhen`/`xstop`/`xrepeat`/`xcutoff`: conditions given as triggers are parsed once into `xact.priv` and run through `trigger_match` (never cuts a tree), `xrepeat` swaps `env->out` for a temporary list and threads the last non-`xgen` result on, `xcutoff` sets the per-flow cut bits via `xtrig_cut`, checked by `strat_xtrig.cut` before each tree's trigger), `tls_clone.c` (port of `tls_dissect`/`tls_reconstruct` + SNI mods for `xtlsclone`), `blob` (built-in fakes made by our code, `--ext-blob`), `ext.c` (`ext_activate`, engine hooks, `xoff_*` for `apply --ext`). L7 parity with zapret2 is pinned by `tests/data/l7_expected.txt` (zapret2's own code over `tests/data/*`); regenerate it and fuzz with `tests/fuzz/l7_diff.sh ZAPRET2_DIR SECONDS` (see `tests/fuzz/`) |
| `tests/*.c` | unit tests (`make test`), no framework |
| `tests/golden/` | snapshots of every command's output without `--ext` (and with it for strategies without x-actions); the "Extensions (with --ext):" help section is cut there and pinned in `expected-ext.txt` (tag `extonly`) |
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
make test                    # unit tests (about 7600 checks)
make STATIC=1 SMALL=1        # router build
make CC="zig cc -target mipsel-linux-musleabi" STATIC=1 SMALL=1
make CC=x86_64-w64-mingw32-gcc
make EXT=0                   # without src/ext/ (--ext is then exit 2)
make EXT_CRYPTO=0            # src/ext/ without crypto_*.c: no QUIC decryption, no censor 16
tests/golden/run.sh build/geneva            # output snapshots; --update after a deliberate change
tools/ext_size.sh 98304 CC=musl-gcc         # router size budget of src/ext/ (CI: ci.yml)
sudo tests/e2e/run.sh build/geneva          # engine
sudo tests/e2e/evolve.sh build/geneva       # search against a keyword censor
sudo tests/e2e/censors.sh build/geneva [1 2 ... dns evolve server]
sudo [NFQWS2_DIR=zapret2-release] tests/e2e/censors_x.sh build/geneva [12 ... 20 xact x14..x20 nfqws2 diff posdebug]
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
| `run -s S -p PORTS [-c ADDR] [-e FILE]` | engine on live traffic; Windows: `--filter EXPR`/`--filter-file F`, `--priority N`, `--first N` | yes |
| `eval [-s S]... [-f FILE\|-]` | fitness per strategy; without strategies the baseline | for strategies |
| `evolve --host H ...` | genetic search; `--checkpoint`/`--resume`, `--db` | yes |
| `agent --listen ADDR \| --connect ADDR --token T` | probes for server-side evaluation | no |
| `library [--country C] [--test T] [--censor N] [-q] [--json]` | Geneva's strategies | no |
| `db --db F list\|top\|show\|export\|import\|prune\|compact` | strategy database | no |
| `censor -c N` | lab censor on a Linux router; SIGHUP resets | yes |
| `check`, `apply` | validate, apply to a pcap | no |
| `fw print\|up\|down` | the rules `run` uses; `--local-ports/--workers/--probe`: the evaluator's (for `--firewall none`); Windows: the filter | yes |
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
  `log_level`, `stop`, and (Windows) `set_filter {filter}`, `reload_filter`.
  A non-loopback address needs a token. Request lines up to 64 KB, 1 MB for
  `set_filter`.
- Since 1.1: event `filter {filter, source}`, `status.filter` (null on
  Linux), `stats.passed_first`, `stats.flow_evictions`, `error.pos` for a
  filter that does not compile (exit 2 at start). `version --json`
  `features`: `filter`, `set_filter` (Windows), `first`,
  `firewall_none_eval` (Linux); since 1.2 `external_workers`.
  Integrators switch on features, not versions.
- External probe (`--probe external --events - [--workers N]`): geneva
  emits `eval_request {id, strategy, run, lports}`; the controller connects
  from a local port in `lports` and writes `{"id":N,"ok":true}` or
  `{"id":N,"fitness":F}` to stdin. Since 1.2 (feature `external_workers`)
  N workers ask at once, each with its own `lports`, and the controller
  answers by id in any order (`external_run` in `evaluator.c` keeps the
  answers for the other workers).

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
- `--filter` replaces the built WinDivert filter for `run` (`(EXPR) and not
  loopback`) but narrows the slots for `eval`/`evolve` (`(slots) and
  (EXPR)`): `fw_config.filter_narrow`. `-p`/`--proto` stay required.
- WinDivert diverts a packet once per priority level: instances with the
  same `--priority` need disjoint filters. `set_filter` relies on it (old
  and new handle share the level).
- `set_filter` runs locked inside `ctl_dispatch`; waiting for a previous
  switch releases `e->lock` so the receiver can drain the old handle.
- No `nft_queue` in some containers: e2e with `FIREWALLS=iptables`.
- The lab HTTPS server in `censors_x.sh` does the TLS handshake in the
  request thread (`do_handshake_on_connect=False`): a ClientHello a censor
  dropped used to block `accept()` for every later client.
- Differential e2e (`censors_x.sh diff`): compare shapes of client packets
  (seq from SYN, length, flags, TTL, payload hash) — not hashes of TLS
  (curl randomizes it) or of IP fragments (they carry the TCP header).
