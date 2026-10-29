# geneva_c — rules for agents

C port of Geneva (Genetic Evasion): the strategy engine and the genetic
search in one static binary for routers and PCs. Plan: `docs/PLAN.md`.

Read `.claude/skills/geneva/SKILL.md` before changing code: repository
map, build and tests, strategy language, commands, protocol, integration.

Hard rules:
1. C11 and libc only; the build stays clean with gcc, clang, mingw and zig
   for every router target (`-Werror` in CI).
2. Geneva's behaviour is the reference; every deviation is documented.
3. Third-party binaries only from official upstream releases.
4. Nothing is applied on a router or in zapret-gui without the user's
   confirmation. No telemetry.
5. Firewall rules are always removed on exit.
6. Changes come with unit tests, live behaviour with e2e tests.
7. User documentation is in Russian; README also in English.
