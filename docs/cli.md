# Command-Line Management (`fileshield-cli`)

`fileshield-cli` is a root-only management CLI built alongside the daemon. It lists and describes persisted _Always_ rules and `[allowlist]` hash pins, removes, clears and prunes them, inspects and clears live session rules, and asks the daemon to reload.

## Commands

```text
fileshield-cli list [rules|allow|deny|pins]     # no argument: all three tables
fileshield-cli describe allow|deny|pin [ID]     # every field/digest; all when no ID
fileshield-cli remove allow|deny|pin <ID>...    # asks [y/N] unless -y
fileshield-cli clear allow|deny|pins            # asks [y/N] unless -y
fileshield-cli prune [allow|deny] [-n]          # lists groups, asks [y/N] unless -y
fileshield-cli session list [allow|deny]        # live rules from daemon memory
fileshield-cli session describe [allow|deny] [ID]
fileshield-cli session remove [allow|deny] <ID>...
fileshield-cli session clear [allow|deny]
fileshield-cli reload                           # ask the daemon to reload now
```

## Flags

| Flag              | Effect                                                                    |
| ----------------- | ------------------------------------------------------------------------- |
| `-y`, `--yes`     | assume yes for every confirmation (needed on a non-terminal)              |
| `-n`, `--dry-run` | `prune` only: list the groups, change nothing                             |
| `--wide`          | no binary/ARG/TARGET truncation, and 16-character IDs                     |
| `--json`          | machine-readable output for `list`/`describe` (rules, pins and sessions)  |
| `-h`, `--help`    | usage help; `-v`, `--version` prints the CLI version                      |

Exit status: `0` success, `1` failure or declined confirmation, `2` usage error.

## Example Output

`list rules` merges allow and deny entries, oldest `created_at` first; `list` with no argument adds the pins (oldest `updated_at` first), and a totals footer closes the output. Binary, ARG and TARGET are tail-truncated on a narrow terminal — the end of a path is the informative part — and `--wide` prints them in full.

```text
ID        Rule   Binary       ARG                    TARGET            CHAIN
dd8bf55d  ALLOW  ...bin       args without bin name  .../secret        code-oss > electron > zsh

ID        Binary                   Last Updated
c54d92cd  /nix/store/.../binary    2026-09-12 13:52:33

1 allow, 0 deny, 1 pin
```

## Reads, Mutations and the Control Socket

- `list` and `describe` read the root-only state files directly, so they work while the daemon is stopped.
- Every mutation (`remove`, `clear`, `prune`, all `session` commands) goes through the daemon's root-only control socket at `/run/fileshield/control.sock` (mode 0600, peer uid checked), so the daemon's in-memory lists and the state files change together — no reload needed.
- When no daemon answers (socket missing or connection refused), rules/pins mutations fall back to editing the state file directly and warn that the daemon must be started to enforce the change. Any other error (e.g. `EACCES`) is never a fallback.
- Session rules exist only in daemon memory, so session commands require the running daemon and have no file fallback.

## Session Rules

`session list` prints ID, Rule, SID, Binary, Target and Expires, soonest expiry first with session-lifetime entries (`until session ends`) last; `session describe` prints one record per block and accepts an optional ID. Session entries are not persisted and vanish on daemon restart.

## Prune

A rebuilt or updated binary stops matching its old _Always_ entry (the stored SHA-512 changed), so the next prompt records a new entry and leaves the old one as a stale duplicate.

`prune` groups entries that share the same **binary path, target file, raw command line and call chain** (digests are deliberately not part of the key), keeps the newest entry of each group and removes the rest. It never hashes a binary and never opens a path.

The call chain is compared level by level by comm name, so the same helper run from a different terminal (e.g. `... > zsh` vs `... > warp`) is a separate rule and never merged.

Every matched group is listed before the confirmation prompt with its shared key and then each member — ID, `keep`/`remove`, creation time — so the grouping can be audited. The report and prompt come from the state files; a running daemon may still hold ghost duplicates an empty file never showed, so when a listener answers `prune` always sends its request (with no prompt when the file showed nothing) and the daemon's removed count is what gets printed. When no daemon answers and nothing matches, it prints `there are no results to prune` and exits without prompting. `-n`/`--dry-run` lists and exits without touching anything; `-y` skips the prompt.

## Confirmation

`remove`, `clear`, `prune`, `session remove` and `session clear` print what they will do and ask `[y/N]`; only `y`/`Y` (or `-y`/`--yes`) proceeds. If stdin is not a terminal and `-y` was not given, the CLI refuses with a nonzero exit instead of reading EOF or a pipe as consent.
