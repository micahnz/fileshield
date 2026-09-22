# Fileshield — Implementation Plan

## Language & Philosophy

- **C99**, no external dependencies beyond libc + Linux kernel headers
- **DRY / KISS**: no unnecessary abstraction, single-purpose functions, flat module structure

## Project Layout

```
Fileshield/
├── AGENTS.md                    # this file (project guide)
├── README.md                    # user-facing documentation
├── Makefile
├── fileshield.conf              # default config shipped with install
├── fileshield.service           # systemd unit
├── src/
│   ├── main.c                   # daemonize, signals, startup/reload orchestration
│   ├── fanotify.c / fanotify.h  # init, marks, event loop, decision pipeline
│   ├── inode.c / inode.h        # protected-inode hash set (hard-link detection)
│   ├── config.c / config.h      # parse fileshield.conf
│   ├── cache.c / cache.h        # target-scoped, PID-keyed allow cache with TTL
│   ├── session.c / session.h    # in-memory session-scoped allow/deny decisions
│   ├── notify.c / notify.h      # kdialog-only menu popups (stdout tokens)
│   ├── persist.c / persist.h    # runtime allow/deny JSON state files
│   ├── pin.c / pin.h            # [allowlist] SHA-512 pins (TOFU, 256-entry table, change state)
│   ├── reload.c / reload.h      # SIGHUP reload: mark install, state/pin loading, reject/rollback
│   ├── ruleid.c / ruleid.h      # stored rule IDs: canonical identity + nonce, prefix lookup, pin IDs
│   ├── prune.c / prune.h        # pure duplicate grouping over persisted rule lists (newest kept)
│   ├── control.c / control.h    # root-only control socket server: mutation and session dispatch
│   ├── control_client.c / control_client.h # control wire protocol + CLI client helper
│   ├── cli_ui.c / cli_ui.h      # pure CLI rendering (tables, describe, JSON) + confirmation gate
│   ├── cli.c                    # fileshield-cli: list/describe/remove/clear/prune/session/reload
│   ├── sha512.c / sha512.h      # digests: helper fork for files, in-process strings/buffers
│   └── utils.c / utils.h        # /proc helpers, path matching, logging, home expansion
└── tests/
    ├── test_cache.c             # unit tests for cache module
    ├── test_config.c            # unit tests for config parser
    ├── test_session.c           # session decisions (stored IDs, snapshot sweep, remove by ID)
    ├── test_persist.c           # JSON state files (rule_id round-trip, legacy migration)
    ├── test_pin.c               # allowlist hash pins (file API, remove/clear, eviction)
    ├── test_reload.c            # reload decision path (parse failure, rollback, shutdown)
    ├── test_sha512.c            # known-answer + differential digest tests
    ├── test_inode.c             # protected-inode set (exact keys, overflow)
    ├── test_fanotify.c          # mark mask, deferred queue, state loading, IDs, mutations
    ├── test_ruleid.c            # rule ID canonicalization, nonces, prefix lookup
    ├── test_prune.c             # duplicate grouping and removal compaction
    ├── test_cli.c               # fileshield-cli: fallback gate, exit codes, confirmation, daemon contact
    ├── test_cli_ui.c            # table/describe/JSON rendering, truncation, confirmation
    ├── test_control.c           # control protocol codec, request parsing, dispatch, socket lifecycle
    ├── test_utils.c             # unit tests for utility functions
    └── bench_hotpath.c          # `make bench` microbenchmarks (not part of `make test`)
```

## Module Responsibilities

Headers are the source of truth for signatures; this table is the map.

| Module         | Owns                                                                                                                                                                                                                                                                                                                                                          |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `main.c`       | daemonize, signal flags, startup orchestration                                                                                                                                                                                                                                |
| `reload.c/h`   | mark installation, persisted-state loading (including legacy rule-ID migration) and pin-table loading, `reload_protection()` with fail-closed reject/rollback (unit-tested with `fan_fd = -1`) |
| `ruleid.c/h`   | stored rule IDs: 16-hex prefix of SHA-512 over the canonical NUL-separated identity (binary, binary SHA-512, target, cmdline SHA-512, chain, `created_at`) with a collision nonce, uniqueness against the list, pin IDs derived from the pattern, `>= 8`-char prefix lookup with ambiguity detection |
| `prune.c/h`    | pure, offline duplicate grouping over `PersistEntry` arrays (binary + target + raw cmdline + call chain; newest kept), removal-index validation and in-place compaction — never hashes a binary or opens a path |
| `control.c/h`  | root-only `/run/fileshield/control.sock` (0600, `SO_PEERCRED` same-uid check, non-blocking, bounded reads per connection; parent directory 0700 created on demand), request parsing and dispatch into the rule/pin/session mutation APIs, `RELOAD` flag, session snapshot serialization |
| `control_client.c/h` | control wire protocol shared by daemon and CLI: JSON field codec, response parser, `control_client_call()`; libc + `persist.h` only, so `fileshield-cli` links without daemon state |
| `cli_ui.c/h`   | pure CLI rendering: sanitization, tail truncation, rule/pin/session tables, kubectl-style describe, JSON output, totals footer, confirmation policy/parse |
| `cli.c`        | `fileshield-cli` main: global flags (`-y`, `-n`, `--wide`, `--json`), command dispatch, state-file reads, socket calls with the stopped-daemon direct-file fallback for rules/pins, exit codes 0/1/2 |
| `fanotify.c/h` | fanotify init, inode marks and init-namespace mount marks via `/proc/1/root` (glob entries mark their static base), startup scope guard, protected-path verdict (glob + `!` exclusion match, deny wins), per-event decision pipeline, runtime allow/deny lists (`DynEntry.rule_id` + real per-entry `created_at`, legacy-ID migration at load, remove/clear/prune mutation APIs that update memory and disk together and restore on write failure), config `[unsafe_allowlist]` and hash-pinned `[allowlist]` verdicts, lazy ancestor-chain hashing, negative hash-failure cache, deferred-event queue, failed-response retry queue (event fds stay open until answered or force-denied before group close), dialog pump (full-pipeline defer-mode evaluation: rule/cache decisions land mid-dialog, only genuine asks defer) |
| `inode.c/h`    | open-addressing `(dev, ino)` set for hard-link detection (fixed capacity; overflow logs and degrades)                                                                                                                                                                                                                                                         |
| `config.c/h`   | INI parse (`[protected_paths]`, `[allowlist]`, `[unsafe_allowlist]`, `[denylist]`, `[settings]`; unknown sections refused), `~` expansion, canonicalization, glob pattern compile (static base + suffix, shared by protected paths and rule sides), `!` exclusions, TTL clamps                                                                                                          |
| `cache.c/h`    | PID+target allow cache with TTL and PID-reuse check (`/proc/<pid>/stat` start time)                                                                                                                                                                                                                                                                           |
| `session.c/h`  | POSIX-session-scoped allow/deny entries, leader-lifetime validity                                                                                                                                                                                                                                                                                             |
| `notify.c/h`   | per-prompt session detection, user drop, environment whitelist, kdialog stages (including the hash-change prompt), fail-closed outcomes, fire-and-forget notify-send rule-hit notifications (dedup window + global flood cap)                                                                                                                                 |
| `persist.c/h`  | atomic JSON save (0600, `O_EXCL` temp + rename; fsync failures fail the write), tolerant line parser with structural completeness check, fail-secure load                                                                                                                                                                                                        |
| `pin.c/h`      | `[allowlist]` binary SHA-512 pins: strict fail-closed JSON load (missing = TOFU), 256-entry table with oldest-eviction, atomic store, change detection                                                                                                                                                                                                        |
| `sha512.c/h`   | `sha512_file` (forked `sha512sum`, `sha512_last_failure()` reason accessor), `sha512_proc_exe`, in-process `sha512_string`/`sha512_buf`                                                                                                                                                                                                                       |
| `utils.c/h`    | `/proc` readers (`proc_exe_path`, `get_ppid`, `read_comm`, `read_cmdline`, `proc_stat_session`), `path_under`/`path_under_len`, protected-path glob matcher (`glob_base_len`, `glob_match_path`), home expansion, logging, `close_fds_from`                                                                                                                   |

### Event pipeline (decision order)

1. `event_resolve` — fd sanity, resolve target path, cache the protected-prefix verdict.
2. `event_fastpath` — mount-mark noise (unknown inode, unprotected path).
3. `event_load_binary` — `/proc/<pid>/exe`; config denylist (with a best-effort
   notify-send tripwire when `notify_denylist` is on); hard-link classification.
4. `event_dedup` — duplicate-event reuse (directory + mount marks fire twice for one
   open), keyed on pid + `/proc/<pid>/stat` start time + resolved binary + dev/ino +
   resolved path: a recycled PID or an exec never inherits a decision.
5. `event_gather_identity` — comm/ppid/cmdline, binary SHA-512 (with its failure reason),
   session id; gathered while the requester is kernel-suspended so `/proc` is still valid.
   The call chain is captured lazily: the runtime matchers request it only after an entry
   passes its path/digest keys, and the prompt boundary builds it (force-refreshing negative
   hash-failure windows) before any dialog. A failed hash is negatively cached for 60 s by
   file identity, with a `(pid, start)` fallback when `/proc/<pid>/exe` cannot be stat()ed,
   so an unhashable binary is retried once per window, not once per event.
6. `event_runtime_denied` — session deny, runtime deny (full-cmdline fingerprint compared,
   computed lazily only when a runtime list can match).
7. `event_runtime_allowed` — skipped entirely for hard-link events; otherwise file cache →
   session allow → runtime allow → `[unsafe_allowlist]` → hash-pinned `[allowlist]`
   (first use pins silently, a changed hash prompts). Config-rule hits raise a
   notify-send notification when their `[settings]` toggle is on (unsafe and denylist
   default on, pinned allowlist off), bounded by `notify_dedup_ttl` and a global cap.
   Unsafe grants log at `WARNING` and notify on the first hit per process; repeat hits log at
   `INFO` marked `(repeat)` and skip the notification, and another process is a new instance
   (per-process gate keyed by `(pid, start)`); other grants stay `INFO`.
8. `event_ask_user` — dialog rate limit, kdialog stages, decision recording.

### `notify.h` decision codes

```c
#define NOTIFY_ALLOW_ONCE 0     /* cached allow, file-scoped, user_ttl */
#define NOTIFY_DENY 1           /* deny this attempt only              */
#define NOTIFY_ALLOW_ALWAYS 2   /* persistent runtime allowlist entry  */
#define NOTIFY_DENY_ALWAYS 3    /* persistent runtime denylist entry   */
#define NOTIFY_ALLOW_SESSION 4  /* allow until the shell session ends  */
#define NOTIFY_DENY_SESSION 5   /* deny until the shell session ends   */
```

The access prompt is a single `kdialog --menu` whose rows offer all six
scopes (once/session/always + the three denies), "Allow once" first; its
body carries the access details and the real match keys.  The decision is
the chosen row's **tag read from the dialog's stdout with a zero exit
code** -- the only grant channel that exists.  Cancel, window close, the
timeout, exec failures and kdialog's runtime errors (including the exit-1
class it shares with the old No button) produce no stdout and therefore
**deny**, so no error path can persist a rule: this replaces the
two-stage button flow and withdraws its accepted exit-1 trade-off.  The
hash-change prompt is the same two-row `kdialog --menu` shape (Update &
Allow first, Deny preselected): only its `update` tag on stdout with a
zero exit code approves; every other outcome denies and keeps the old
pin.  The menu
requires KF6 kdialog argv shape (`--menu TEXT tag item [tag item] ...`);
an older kdialog misparses it and denies (fail closed).  Each scope
(the six rows and the body bullets) pairs its name inline with a concise
description: session = this binary and file until the session ends;
always = saved permanently for this command and file.  The Deny Once row
is preselected via `--default`: confirming with no deliberate selection
denies this attempt -- an accidental Enter can never grant.

The dialog child forwards a whitelist of the user's session appearance
variables (desktop identity, Qt theme/scale, locale, cursor) read from
`/proc/<pid>/environ` so kdialog follows the desktop theme. Display,
session-bus, `LD_*`, `PATH` and `QT_PLUGIN_PATH`/`QT_QPA_PLATFORM*` variables
are deliberately never forwarded: the prompt must stay on the display
Fileshield detected, and no code-loading or platform override may come from
the requesting process.  `QT_QPA_PLATFORMTHEME` is the one deliberate
exception: it selects an installed theme plugin by key (Qt resolves it
without `QT_PLUGIN_PATH`), not a platform or a code path.

### `main.c` — daemon lifecycle

```c
// Usage: fileshield [--foreground] [--config /path/to/fileshield.conf] [--debug]
// Signal handling: SIGTERM/INT -> shutdown, SIGHUP -> reload config
```

## Decision Scopes

| Decision           | Match key                                                                                                                     | Lifetime                                                       | Stored in               |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | ----------------------- |
| Allow Once         | PID + binary + target file                                                                                                    | `user_ttl` (shipped config: 300s; 0 = not cached)              | memory                  |
| Allow/Deny Session | SID + leader start + binary (SHA-512 when hashable; a missing digest is stored deliberately for unhashable binaries) + target | `session_ttl` (0 = shell lifetime)                             | memory                  |
| Allow/Deny Always  | binary SHA-512 + call chain + target file + command line (stored verbatim, matched by SHA-512 over the full raw line, ≤64 KB) | until removed                                                  | JSON state files        |
| Allowlist pin      | matched `[allowlist]` rule binary pattern + binary SHA-512                                                                    | until an approved hash change or eviction at the 256-entry cap | `allowlist-hashes.json` |

Lookup order (a denial always wins): config denylist → session deny → permanent
deny → file cache → session allow → permanent allow → `[unsafe_allowlist]` →
hash-pinned `[allowlist]` → dialog rate limit → prompt. A hard-link event
(protected inode reached through a path outside every protected prefix) skips
the grant stages entirely and always prompts. Persisted entries without a
`target_path` or a recorded command line, and entries whose fingerprint
predates full-line hashing, do not match (fail closed, re-prompt).

Persisted allow/deny entries and live session entries carry a stored 16-hex
`rule_id` (ruleid.h), and `created_at` is the real creation time, stamped once
at creation and preserved across every save; legacy state files get IDs assigned
at load and are rewritten immediately (grants are kept, never dropped).
`fileshield-cli` addresses entries by ID through the control socket. Prune —
shared by the CLI and the daemon — groups the persisted lists by binary + target
+ raw command line + call chain, keeps the newest member and removes the rest;
it never hashes a binary and never opens a path.

## Build & Test

- `make` — compile the `fileshield` daemon and the `fileshield-cli` management binary
- `make test` — compile and run all test suites
- `make bench` — build and run `tests/bench_hotpath.c` (hot-path microbenchmarks)
- `make install` — install the daemon to `/usr/local/sbin` and `fileshield-cli` to `/usr/local/bin`, the systemd unit and `fileshield.conf` (only when the target config is absent); `make install-config` or `REPLACE_CONFIG=1` overwrites the config with the shipped defaults
- `make clean` — remove artifacts
- `make lint` — cppcheck static analysis
- `make debug` — ASan/UBSan build for the daemon
- CFLAGS: `-std=c99 -Wall -Wextra -Wpedantic -Werror -O2` plus hardening
  (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, PIE, RELRO/NOW)

## Testing Strategy

- **`test_cache`**: target-scoped insert/lookup/expire, wildcard vs file-scoped, PID reuse, TTL clamp
- **`test_config`**: parse valid/invalid .conf, rule globs on both sides, `[unsafe_allowlist]`, ~ expansion, user_ttl/session_ttl, clamping, edge cases
- **`test_session`**: SID resolution, allow/deny matching, hash verification, TTL, dead leaders, stored rule IDs, snapshot sweep, remove by ID, per-list clear
- **`test_persist`**: save/load roundtrip, escaping, malformed input, truncation warnings, `rule_id` round-trip, legacy entries without an ID, invalid-ID rejection
- **`test_pin`**: strict load/save roundtrip, missing vs damaged file, escaping, 256-entry eviction (oldest `updated_at`, tie-breaks), write-failure behavior, file API, remove by ID/ambiguity/clear
- **`test_sha512`**: FIPS 180-4 known-answer vectors, differential tests vs `sha512sum`, NUL-safe buffer hashing
- **`test_inode`**: exact-key lookup, device separation, duplicates, clear, overflow degradation
- **`test_reload`**: parse failure keeps the old config, a rejected reload keeps the old config published (unprivileged runs with `fan_fd = -1` cannot install marks, so the mark-set restoration itself is covered by the root canary), a failed rollback requests shutdown
- **`test_fanotify`**: mark mask, deferred queue fail-closed flush, daemon queue-overflow flush, incomplete state entries dropped, command-line scoping, full-cmdline fingerprints, rule glob matching, unsafe-first ordering, pin verdicts, first-seen TOFU, damaged-pin fall-through, `created_at` preservation, legacy ID migration, remove/clear/prune mutations with write-failure restore, kernel queue saturation (root)
- **`test_ruleid`**: canonical identity determinism, field boundaries, chain depth, collision nonces, pin IDs, prefix matching and lookups
- **`test_prune`**: group detection (interleaved, key-field separation, hash fields not part of the key), malformed-entry exclusion, chain-depth boundary, capacity errors, apply validation and compaction
- **`test_cli`**: fallback gate (only ENOENT/ECONNREFUSED reach the file path; EACCES never does), exit-code contract 0/1/2, non-tty confirmation without `-y`, clear/prune contacting a reachable daemon even when the state file shows zero entries (errno-injection + temp-socket seams; never touches `/run` or `/var/lib`)
- **`test_cli_ui`**: sanitize/tail truncation, ARG/CHAIN cells, rule/pin/session tables, totals footer, describe, JSON output, confirmation policy
- **`test_control`**: field codec, request/response parsing, PING/RELOAD, bad and slow clients, rule/session/pin dispatch, setup/teardown (parent-directory creation, rebound-socket identity), accept handling, client call
- **`test_utils`**: `proc_exe_path`, `/proc` readers, home expansion, `path_under`
- **`bench_hotpath`**: cache, path matching, SHA-512, runtime matchers, inode set, fast-path verdict, path resolution (`make bench`; kept only when a change wins)
- Tests are self-contained C files linked against the module `.o` files
- Each test returns 0 on pass, non-zero on failure. `make test` runs them all and reports aggregate.

## Mark scope safety (read before touching fanotify marks or the unit)

On 2026-09-16 a build that switched mount marks to `FAN_MARK_FILESYSTEM`
froze a machine outright.  `/` and `/home` shared one btrfs filesystem, so
the superblock-scoped mark covered every open on the system; the daemon's
own state-file opens then blocked on permission events only it could
answer (it is single-threaded) and no process could proceed.  Treat mark
scope as a safety-critical surface:

- Never install a build that changes mark scope or the service's mount
  namespace without a root smoke test on a disposable, snapshot-backed
  machine, and a way to stop the daemon that does not depend on the GUI.
- The daemon must never open a file it marks.  Load persisted state and
  pins before installing marks; do not read the config while marks are
  live; answer self/child events in every wait loop (main, pump, hash).
- `FAN_MARK_FILESYSTEM` covers every mount and subvolume of a filesystem.
  Safe only when that filesystem is dedicated to protected data — never
  the root/home filesystem.
- `FAN_MARK_MOUNT` is scoped to one mount instance.  A mark placed in the
  service's private mount namespace never sees user opens; attach marks to
  the init-namespace mounts instead (the daemon does this through
  `/proc/1/root`, proven by Phase 0 exp1/exp2/exp2p), or use a
  superblock-scoped mark (`FAN_MARK_FILESYSTEM`) on a dedicated
  filesystem — never on the root/home filesystem.
- Before enabling a new build, record the previous known-good binary hash
  and confirm the daemon can be stopped from a TTY or serial console.

## Limitations (see README for detail)

- Root-only (CAP_SYS_ADMIN for `fanotify_init`); root processes can bypass fanotify
- `kdialog` required for popups; missing/failing kdialog denies access (fail closed)
- Kernel 5.0+ for FAN_OPEN_PERM on directories; no NFS/CIFS coverage; `mmap` and bind-mount aliases are outside the threat model
- Hard links: inodes present at startup are tracked, and an open through an unprotected path always prompts. Files created after startup, deeper than 8 directory levels, or past the inode-table cap are not inode-tracked (`FAN_REPORT_FID` is a planned follow-up)
- Protected-path globs: `*` (one segment) and `**` (zero or more segments) only, at most one `**` segment per pattern (the matcher carries one backtrack slot; a second one would under-match silently and is rejected at load); `?`, `[`, `]` and `\` are literal. A glob entry marks its wildcard-free base directory (the mount mark covers the rest of its mount), a malformed pattern is rejected at load time (fail closed), and a pattern whose wildcard-free base is `/` (any wildcard in the first path segment) refuses the whole config at load — it would mount-mark the root filesystem
- Mount marks are attached to the init-namespace mounts through `/proc/1/root` (CAP_SYS_PTRACE); mount bookkeeping uses `statx(STATX_MNT_ID)` (Linux 5.8+), falling back to device-level dedupe with a warning when unavailable, and the startup scope guard refuses a config whose own state/config files its marks would intercept
- Protected-path exclusions (`!pattern`): deny-wins and order-independent — an excluded path is never protected, never marked, and never inode-tracked; matching is path-based
- TOCTOU on binary identity between `/proc/<pid>/exe` and the hash check (inherent to fanotify permission systems)
- Dialog rate limiting: 20 prompts per binary within 60 s, then a 30 s deny cooldown; additionally 40 prompts across all binaries within 60 s (a path-rotating flood lands in fresh per-binary entries, so a global budget bounds it), same 30 s cooldown
- Config reload is not atomic: marks are cleared before the new set is installed, so there is a short unmediated window during an administrator-triggered reload (delta reload is a possible follow-up; it needs the root smoke test because it changes mark bookkeeping)
- GUI prompts are session-scoped, not process-scoped: a same-uid process can in principle forge GUI input (X11 synthetic events, planted Wayland socket), so GUI consent is not a defense against a fully compromised session
- The shipped `~/...`-based protected list expands once per real user, so it exceeds `MAX_PATHS` at 12 real users (trim it on shared hosts)
- Permanent _Always_ entries pin the exact command line, so invocations whose arguments change re-prompt
- Session grants work without a binary digest: when hashing fails (AppImages under `/tmp/.mount_*`, self-updating tools) an "Allow Session" is stored with an empty digest and matches any binary at the same path and target until the session leader exits. This is deliberate — it is the intended scope for unhashable binaries; do not "fix" it into a fail-closed degradation (a past review did and broke the use case)
- Allowlist hash pins are keyed by the rule's canonical binary pattern: a glob rule shares one pin across every binary that matches it, so switching between them prompts (`[unsafe_allowlist]` is the escape). Binaries under a protected path are never hashed, a missing digest or a damaged `allowlist-hashes.json` (including a file with two rows sharing one pattern) falls back to the prompt (fail closed); the prompt names the failure reason and points at `[unsafe_allowlist]` for a permanent grant, failed hashes are retried at most once per 60 s, and ancestor hashing is skipped while no runtime _Always_ entries exist; the table is capped at 256 entries (oldest evicted)
- Denylist rules are never hash-checked, and pin updates go through the change dialog (or a root edit of `/var/lib/fileshield/allowlist-hashes.json` and a reload); `fileshield-cli` can list, remove and clear pins, but adding or updating one is dialog-only
- Control socket: `fileshield-cli` mutations travel over the root-only `/run/fileshield/control.sock` (0600, `SO_PEERCRED` peer-uid check, non-blocking, bounded reads per connection; the directory is systemd's `RuntimeDirectory=fileshield`, created 0700, or created on demand by a foreground run); reads parse the state files directly; the direct-file fallback applies only when no listener answers (`ENOENT`/`ECONNREFUSED`), never on `EACCES`; session commands require the running daemon because session rules live only in memory
- Rule IDs: 16 lowercase hex stored per entry (first 8 shown by default, 16 with `--wide`, full in `describe`); lookups accept an unambiguous `>= 8`-char prefix; the daemon assigns IDs to legacy entries at load and rewrites the state file immediately (grants preserved); pins store no ID and derive it from the pattern
- Prune keeps the newest entry of each duplicate group (binary + target + raw command line + call chain, by insertion order, not `created_at`) and never hashes a binary, so it does not verify which rule matches what is on disk
- No CLI `add`: the dialog remains the only grant channel; `fileshield-cli` can only list, describe, remove, clear, prune, manage session rules and trigger a reload
- Rule-hit notifications are best-effort (need a detected desktop session and `notify-send`), attacker-triggerable, deduplicated for `notify_dedup_ttl` and capped at `notify_max` per 60 s window; user dialog decisions never notify and no notification ever affects a decision
- Config caps are hard: more than `MAX_PATHS` protected entries (1024; each `~/...` line expands once per real user) or more than `MAX_RULES` (128) in a section makes `config_load()` fail — startup exits, a reload keeps the previous config. `mark_table_add()` failure removes the just-installed kernel mark and fails the installation (no untracked marks across reloads); inode-set and mount-table overflows stay non-fatal but log at `ERR`
