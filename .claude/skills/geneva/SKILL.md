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
| `src/ext_opt.c`, `src/ext/` | the `--ext` extensions (zapret2 parity, `docs/EXT_ROADMAP.md`, done so far: `docs/EXT.md`); `src/ext/` is left out by `make EXT=0`. Options that need `--ext` get `EXT_HELP("...")` as help: `--help` lists them last under "Extensions (with --ext):". `crypto*` (AES-GCM, SHA-256, HKDF), `quic`/`tls` (Initial decryption, ClientHello SNI), `censor_x` (lab censors 12-20), `ctrack` (zapret2 conntrack), `range` (zapret2 position ranges), `xtrig` (`FLOW:`/`META:`/`L7:` triggers via `strategy_set_xtrig`, per-flow tree cutoff), `l7` (zapret2 protocol/payload probes, SNI/Host, QUIC CRYPTO defrag), `markers` (zapret2 position markers), `xl7` (per-flow L7, ClientHello reassembly over TCP segments and QUIC Initials: held packets keep their verdict pending, `engine_hold`/`engine_replay`), `xact.c`/`xact_tcp.c`/`xact_http.c`/`xact_misc.c` (x-actions `xfake{...}` etc. via `strategy_set_xact`: zapret2's desync functions, common args, fooling, ipfrag2, MSS segmentation; a result with `gpkt.xgen` makes the engine send everything in list order through `send_x`, `xdrop` marks a VERDICT_DROP that still goes down the tree; per-packet state shared by all trees of one `strategy_apply_x` call (zapret2's `desync` table: `xtlsclone` blobs, `xtag` label) hangs off `strat_xenv.dyn` and is freed by `strat_xact.done`; `xa_cutoff` is zapret2's instance cutoff per flow; `xact_comb.c` has the combinators `xwhen`/`xstop`/`xrepeat`/`xcutoff`: conditions given as triggers are parsed once into `xact.priv` and run through `trigger_match` (never cuts a tree), `xrepeat` swaps `env->out` for a temporary list and threads the last non-`xgen` result on, `xcutoff` sets the per-flow cut bits via `xtrig_cut`, checked by `strat_xtrig.cut` before each tree's trigger), `tls_clone.c` (port of `tls_dissect`/`tls_reconstruct` + SNI mods for `xtlsclone`), `blob` (built-in fakes made by our code, `--ext-blob`), `profile.c` (zapret2's desync profiles: `--new`/`--template`/`--import`, `--filter-*`, `--ext-profile` INI; options before the first `--new` are profile 1 running the command's own `-s`/`-f`, which `ext_cmd_args()` isolates; the engine hook gets `strategy **st` and swaps in the packet's profile strategy (NULL: passes); a flow caches its profile in `ct_flow.xprof*` and searches again once its L7 is known; `xprof_capture` gives the fw ports/ICMP/IP protocols; X6b lists: `lists.c` is the registry of list files shared by path with mtime/size reload (`xlists_reload`, at most once a second from the packet hook, forced by SIGHUP and the `reload_lists` command through `ext_hooks.control`), `hostlist.c` an open-addressing name set with zapret2's suffix walk and `^`/`!` flags, `ipset.c` sorted merged v4/v6 intervals, `inflate.c` puff-style DEFLATE with gzip/zlib wrappers; `xprof_match` checks them in `dp_match` order and `pick()` searches again once the flow's host is known (`ct_flow.xprof_host`); X6c: `ct_flow.chost` is zapret2's `ctrack->hostname` (normalized, from the L7 once: `chost_disc`, or from `ipcache.c` before the first search), `flow_check()` is the hostlist check of `dp_rediscovery` (`xcheck` 2: the flow keeps its profile, no strategy), `autolist.c` has the fail counters per profile, the TCP/UDP detectors run from `xw_packet`/`xoff_packet` (`flow_autolist`: TCP before the second search, UDP after) and the RST through `engine_inject` (not on WinDivert); `ipcache.c` caches host names (DNS answers, flows) and the first reply's TTL per server and interface; X7a: `cfgfile.c` expands `geneva CMD @FILE` in `main()` (shell-like split, needs `--ext`), `svc.c` runs `run --ext` as a service through `engine_opts.on_ready`: `--daemon` (parent waits on a pipe), `--pidfile`, `--user/--uid` (keeps CAP_NET_ADMIN/CAP_NET_RAW), seccomp (zapret2's `sec_harden` list, on by default), a root helper forked before that takes the rules down via `fw_set_down_hook` (also on SIGKILL), `sd_notify`, syslog through `log_set_hook`; X7b: `fwx.c` reads `--ext-first`, `--ext-wan/--ext-lan`, `--ext-notrack`, `--ext-ttl-icmp`, `--ext-flowoffload`, `--fw-hook-pre/post` into the `--ext` part of `fw_config` (all zero without `--ext`; `src/fw.c` renders it for nft and iptables, `fw_first()` gives the per-protocol/direction `--first` to the rules and to the engine's own counter) and builds winws2's `--wf-*` WinDivert filter (`wf_make_filter` of `nfqws.c`) into `fw.filter` with `filter_whole`); X7c: `fuzz.c` holds the fuzz targets (one function per reader of untrusted input, its built-in seeds and own checks via `XFUZZ_CHECK`, which aborts), `selftest.c` the `geneva selftest --ext --fuzz N` command (dispatched in `main()` outside the command table, which is Geneva's; each target in a forked child, inputs reproducible from `--seed`); a new reader gets a target there and a line in `tests/fuzz/run.sh`'s sample list; X8: `seqtrack.c` keeps `ct_flow.xseq` for a flow whose first client message grew (`xoob`, `xtlsrec` in `xact_seq.c` shift the SYN by d and send the changed message); `xseq_packet` runs first in `xw_packet`/`xoff_packet` (before profiles and L7): client packets without data get seq-d, a retransmission of the message is sent again whole via `engine_inject` (apply: the replay fn) and dropped (`XOFF_DROP`), server ack/SACK are mapped back; a changed packet gets its own verdict when the strategy would not run; `xdrip` there too; e2e `tests/e2e/seqtrack.sh`; X9a: `auto.c` is `--ext-auto observe` (one observer per process, opened in worker 0's `worker_open` before the rules; its NFLOG socket is polled by the engine loop through `ext_hooks.pollfds/ready`), `nflog.c` reads NFLOG over raw netlink (`nflog_parse` portable for tests), `detect.c` is the detector (own conntrack, flow classes in `ct_flow.xstate`, keys port/net/ip/host with a clamped Wald SPRT, sink callbacks become `ext_flow`/`ext_impaired`/`ext_class`); `fw_config.obs*` adds the NFLOG chains (iptables chains only listed when `obs`, so legacy golden output is unchanged); e2e `tests/e2e/censors_x.sh auto`; X9b: `ctnl.c` asks the kernel conntrack for one flow's counters (ctnetlink GET, `ctnl_parse` portable for tests), `auto.c` polls it from `ext_hooks.ready` (called after every poll of the engine loop, events or not) about once a second through `xdet_tick`/`xdet_counters`; the detector keeps a volume watch per TCP flow in `ct_flow.xa` of its own conntrack (FREEZE_N, THROTTLE against the capacity C, strict success via `skipmask`), DNS_POISON from answers on port 53, LINK_DEGRADED through `sink.link` → event `ext_link`; e2e `censors_x.sh auto12 auto13 autodns`; X9c: on Windows `auto.c` opens `wdsniff.c` instead of NFLOG (a WinDivert SNIFF|RECV_ONLY handle at the engine's priority + 1, a receiver thread into a 2048-packet ring, a loopback UDP wake socket polled through `ext_hooks.pollfds`), the detector gets `xdet_packet_dir` (only outbound non-SYN,ACK packets start flows) and `xdet_config.self_count` (counts server IP bytes and FIN/RST itself, `xdet_tick` feeds `counters_of` without ctnetlink); THROTTLE skips a plateau shared with a live flow to another /24 or /48 (`parallel_plateau`); e2e `tests/e2e/auto_synth.sh` (no censor, `DURATION`), Windows smoke `--ext-auto` section; X10a: `--ext-workers N|auto` (`xsvc_workers` in `svc.c`, Linux only) sets `engine_opts.workers` and `fw_config.nqueues` (rules: `--queue-balance A:B` / `queue num A-B`); `engine_run` is then `threaded`: one thread per worker (`worker_main` polls the backend's `worker_fd`, reads with `worker_ready`, runs its own timers, all under `w->lock`), each with its own NFQUEUE/rawsend in `eng_nfq.c` and a `strategy_clone` in `w->st`; the main loop takes every worker lock (`engine_lock_workers`, id order, after `e->lock`) for control commands, SIGHUP and stats, and forwards worker events through `evq_push`/`evq_flush`; in `ext.c` the hook runs under the `g_xlock` rwlock when there are profiles (write with an autolist), list reloads move to `xw_ready`, per-worker profile strategy copies are `xworker.pst` (`wprof_st`), `ipcache.c` locks once `xipc_threads()`; tests: `test_threads` in `tests/test_engine.c` (fake threaded backend via `engine_opts.backend`), e2e `tests/e2e/workers.sh` (`BENCH=1`); X10b: the surgical path: `flow_healthy` in `ext.c` decides a flow is done (tree cutoff both ways, profile settled, no autolist/seqtrack, no key impaired in the policy) and calls `engine_healthy` → backend `healthy` (only `eng_nfq.c`: the verdict becomes `NFQ_REPEAT` with mark `| fw.healthy_mark`; `src/fw.c` renders the CONNMARK/`ct mark` rules at the top of the queue chains, obs chains skip the second pass), `--ext-healthy-mark` in `fwx.c`; `policy.c` holds the key states as immutable snapshots freed by QSBR (writer: the main thread via `auto.c`'s `on_key`, readers: `xpol_enter`/`xpol_leave` in the packet hook); tests `tests/test_surgical.c`, e2e `tests/e2e/surgical.sh`; X11a: `tuner.c` is the tuner (`--ext-arm`/`--ext-tune rr`, zapret2's `circular` with `standard_*_detector` and `standard_hostkey`): arms parsed per profile (`xprofile.tune`, `prof_st`/`wprof_st` pick the arm of the flow's key on every packet, per-worker clones in `xworker.arms`), the key records `TABLE/KEY` process-global under a mutex, per-connection state in `ct_flow.xt_*`; `flow_tune` runs the step in `xw_packet` and `xoff_packet` before the second profile search; `--ext-state` JSONL saved from `xw_ready` (`xtune_tick`, every 10 s at most) and at worker 0's close (`xtune_save`); event `ext_arm`; X11b: `ts` (Thompson sampling: per key and arm discounted Beta counts `rec.A/B`, the connection's draw in `ct_flow.xt_arm`/`xt_khash`, `ts_best` Monte Carlo settles the key: `ext_tuned`) and `propose` (a change becomes `rec.prop` + event `ext_proposal`; `xtune_control` handles ctl `ext_proposals`/`ext_approve`/`ext_reject` with `proposal`, since `id` is the request's own); tests `tests/test_tuner.c`, e2e `tests/e2e/censors_x.sh tune` (`tunets`, `tunepropose`); X11c: `treat.c` is `--ext-auto propose|apply` (`xtreat_start` from `xauto_parse`): a built-in portfolio of arms by detector class, records per IP/HOST key under a mutex fed by `auto.c`'s `on_key` (`xtreat_key`; an owned key stays IMPAIRED in the policy) and `on_flow` (`xtreat_outcome`, matched by the client tuple in a 4096-slot table), the worker draws in `flow_treat` (`ext.c`, after the second profile search; per-worker clones in `xworker.tarms`, connection state in `ct_flow.xr_arm`/`xr_khash`), CUSUM in TREAT, UNTREATABLE rechecks from `xtreat_tick`; proposals share the tuner's id sequence (`xtune_new_id`) and its ctl commands (`xtune_control` falls back to `xtreat_decide`/`xtreat_proposals`); tests `tests/test_treat.c`, e2e `censors_x.sh treat`; X11d: a FREEZE_N/THROTTLE key's success is `xdet_flow_ev.provisional` until the detector's strict success (once per flow, `strict_told`), which `xtreat_outcome` waits for; `treatga.c` is `--ext-ga`: when every arm failed the key goes to `S_SEARCH`, `xtreat_tick`'s `ga_step` runs `/proc/self/exe evolve` as a child (one at a time; queue +64, seed file of the library's client TCP strategies, stdout read by a thread, SIGTERM on stop) and a found strategy becomes the key's arm 8 (`XTR_GA_ARM`, text by `xtreat_ga_text`, parsed once per worker into `xworker.gac`); `--ext-treat-arms` masks the portfolio; e2e `censors_x.sh treatga`; X12a: `tools.c` has `geneva resolve --ext` (zapret2's mdig) and `geneva ip2net --ext` (zapret2's ip2net), dispatched in `main()` beside `selftest`; `tests/e2e/tools.sh` diffs them against the zapret2 release binaries (`NFQWS2_DIR`, no root); X12b: `blockcheck.c` is blockcheck2's grid (each `blockcheck2.d/standard` script a C function with the shell's loops, breaks, `ok` variables and `need_*` state in `bc_run`; `T()` is `pktws_curl_test_update`, the probing a `bc_test_fn` callback), `blockcheck_cmd.c` the `geneva blockcheck --ext` command (one evaluator per domain/IP version/test, `attempts()` is `curl_test` with REPEATS), `z2xlate.c` turns an nfqws2 line into a strategy (`--lua-desync` instances nested as x-actions, `--payload`/`--out-range` groups as `xwhen`); `probe_cfg.strict_http` is `curl_test_http`'s 400/redirect check; `tests/e2e/blockcheck_grid.sh` runs the release's own scripts with a stub and diffs the line order against `--print-grid --grid-ok`; X13b: `eng_divert.c` is the BSD backend (divert(4): FreeBSD `PF_DIVERT`/`IPPROTO_DIVERT` one socket for both families, OpenBSD one per family; the recvfrom address is the per-packet context, zero = outbound, interface address = inbound, FreeBSD's ifname after sin_addr feeds `meta` ifin; verdicts and injections are `sendto` with that address; `engine_first` like WinDivert), `fw_bsd.c` the ipfw/pf rules (`fw_ipfw_rules`, `fw_pf_rules`, `fw_bsd_check` refuses Linux-only settings; ipfw rules share the lowest free number from 50 with the comment `geneva PORT`, deleted by number only when all rules there are ours; pf anchor `geneva/PORT`, needs `anchor "geneva/*"` in pf.conf), `fw_int.h` shares `fw_run_argv`/`fw_find_bin` with fw.c; cross-build with `zig cc -target x86_64-freebsd` (zig 0.15+), CI job `bsd` boots the official FreeBSD image (`tests/e2e/freebsd_vm.sh`, NoCloud ISO, nuageinit runs the unit tests and `tests/e2e/bsd_divert.sh`: vnet jail + epair + inetd echo); X13a: `xact_obfs.c` has the zapret-obfs actions (`xwgobfs`, `xippxor`, `xudp2icmp`, `xsynhide`); a protocol change builds the bytes and `reparse()`s them into the same `gpkt` (keeping `xgen`/`xmark`/...), checksums of the new protocol computed there; `xudp2icmp{cgnat}` keeps the server's identifier map in a global mutex-guarded table (`idmap`, initialised by `prepare` at parse time); e2e `tests/e2e/obfs.sh` runs them geneva↔geneva and geneva↔nfqws2; X12c: `bcnet.c` has `check_dns_` (`bc_check_dns` over a `bc_lookup_fn`, so tests give fixed answers; the real one is the system resolver or a `PROBE_DNS` with `dns_out`), DoH through curl (`bc_doh_query`, RFC 8484 GET via `probe_spawn`), the resolver cache (`bc_resolver`, mdig_cache) and netcat's port test (`PROBE_TCP` with `connect_only`); `blockcheck_cmd.c` runs them in blockcheck2's order (DNS check first, port test before http and before the first TLS test, `ip_block` after a failed baseline), results in `bc_run.dns`/`chk` for `--json`; X13c: `wlan.c` reads the SSID of each Wi-Fi interface over nl80211 (generic netlink, no libmnl; GET_INTERFACE then GET_SCAN for the associated BSS on Linux 5.19+; message builders/parsers portable for tests), refreshed at most once a second by `set_ssid` in `ext.c` before the first profile search (interface `reverse ? ifin : ifout`), `--filter-ssid`/`-neg` checked in `xprof_match` like zapret2's `dp_match`; `winnet.c` is winws2's `--ssid-filter`/`--nlm-filter`/`--nlm-list` (wlanapi and NLM COM loaded from System32, a monitor thread once a second, `xwinnet_ok()` false makes `xw_packet` pass every packet untouched); Android is `plat_is_android()`/`plat_tmpdir()`, e2e `tests/e2e/wlan.sh` (mac80211_hwsim + hostapd) and `tests/e2e/android_env.sh` (chroot shaped like Android); `ext.c` (`ext_activate`, engine hooks, `xoff_*` for `apply --ext`). L7 parity with zapret2 is pinned by `tests/data/l7_expected.txt` (zapret2's own code over `tests/data/*`); regenerate it and fuzz with `tests/fuzz/l7_diff.sh ZAPRET2_DIR SECONDS` (see `tests/fuzz/`) |
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
make test                    # unit tests (about 37000 checks)
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
build/geneva selftest --ext --fuzz 20000  # fuzz targets in the binary
tests/fuzz/run.sh 60 [TARGET...]            # libFuzzer (FUZZER=afl: AFL++), ASan+UBSan, build-fuzz/
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
| `fw print\|up\|down` | the rules `run` uses; `--local-ports/--workers/--probe`: the evaluator's (for `--firewall none`); Windows: the filter; `--ext --wf-*`: the WinDivert filter on any platform | yes |
| `ctl CMD [k=v]` | control socket client | — |
| `version --json` | version, `proto`, os, arch, features | no |
| `selftest --ext [--fuzz N]` | the fuzz targets over their seeds and N random inputs each (`--seed`, `--target`, `--crash-dir`, `--seeds-out`); exit 1 on a crash or hang | no |
| `resolve --ext` | names on stdin to addresses with threads, as zapret2's mdig (`--family 4\|6\|46`, `--threads`, `--log-resolved/--log-failed`, `--dns-make-query`, `--dns-parse-query`) | no |
| `ip2net --ext` | addresses on stdin grouped into subnets, as zapret2's ip2net (`-4/-6`, `--prefix-length`, `--v4-threshold`, `--v6-threshold`) | no |
| `blockcheck --ext` | zapret2's blockcheck2 with the whole `blockcheck2.d/standard` grid translated into geneva strategies (`--test http,tls12,tls13,http3`, `--level`, `--repeats`, `--ipv`, `--scripts`, `--ip`, `--json`; report SUMMARY/COMMON/COVERAGE; exit 0 when something works); before the grid the DNS check (`--skip-dnscheck`, `--dns-servers`, `--dns-domains`), DoH when DNS is spoofed (`--secure-dns`, `--doh`, `--doh-servers`, needs curl), port and IP block tests (`--skip-ipblock`, `--unblocked-domain`); `--print-grid [--grid-ok FILE]` lists the grid without probes | yes (not `--print-grid`) |

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
  `log_level`, `stop`, (Windows) `set_filter {filter}`, `reload_filter`,
  and (`--ext`, feature `ext_lists`) `reload_lists` (answer `files`),
  (`--ext`, feature `ext_service`) `ext_flows [limit]` and `ext_keys`,
  (`--ext-auto`, feature `ext_auto`) `ext_status`; events `ext_flow`,
  `ext_impaired`, `ext_class`.
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
