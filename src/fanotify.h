#ifndef FILESHIELD_FANOTIFY_H
#define FILESHIELD_FANOTIFY_H

#include <sys/fanotify.h>
#include "config.h"
#include "persist.h"

int fanotify_setup(void);

/*
 * Add a mark for a protected path.
 * Returns 0 when the path was marked directly, 1 when the path does not
 * exist yet (skipped; a mount mark for its filesystem is ensured so a
 * later-created path is still intercepted), or -1 on a real error.
 */
int fanotify_add_mark(int fd, const char *path);

/*
 * Add the mark for one configured [protected_paths] entry.  Exact
 * entries mark the path directly (same contract as fanotify_add_mark);
 * glob entries mark their canonical wildcard-free base and enforce the
 * pattern at match time.  Return values match fanotify_add_mark().
 */
int fanotify_add_protected(int fd, const ProtectedPath *pp);

/*
 * Main event loop.  Blocks in poll() on {group fd, wake pipe, control
 * listener} until an event arrives, a signal handler writes to the wake
 * pipe (read end; pass -1 when there is none), a CLI client connects on
 * the control listener (control_setup()'s non-blocking fd; pass -1 when
 * there is none), or g_running/g_need_reload/g_fatal are set.  The group
 * fd must be non-blocking (FAN_NONBLOCK at init): the wake pipe closes
 * the window in which a signal arriving just before a blocking read()
 * would suspend shutdown/reload on an idle filesystem, which would let a
 * supervisor SIGKILL auto-allow outstanding permission events on
 * close(fan_fd).
 *
 * A readable control fd is served through control_handle(), which makes
 * a bounded number of non-blocking accepts and never waits on a client.
 * A control fd that reports POLLERR/POLLHUP/POLLNVAL is logged and
 * dropped from the poll set (the loop's local copy is cleared to -1)
 * instead of stopping the daemon: a CLI transport failure must not take
 * protection down, and main.c owns the fd's lifetime.
 */
void fanotify_loop(int fd, int wake_fd, int control_fd);

/* Non-zero when at least one file/directory or filesystem/mount mark is active. */
int fanotify_any_mark_active(void);

/*
 * Scope guard: refuse a configuration whose own state directory or config
 * file could be intercepted by the marks it would install (the
 * self-deadlock class).  Runs against the currently published g_config;
 * returns 0 to proceed, -1 to refuse.
 */
int fanotify_scope_guard(const char *config_path);

/* Print the marks a config would install, without touching the kernel. */
void fanotify_dry_run(const Config *cfg);

/*
 * Event mask used for file and directory marks.  Directory-entry events
 * (FAN_CREATE, FAN_DELETE, FAN_MOVED_FROM, FAN_MOVED_TO, FAN_ATTRIB,
 * FAN_DELETE_SELF) require a group initialized with FAN_REPORT_FID and
 * make fanotify_mark() fail with EINVAL on this fd-based group, so they
 * must never be added here.  Exposed for the unprivileged regression test.
 */
unsigned int fanotify_mark_mask(void);

/*
 * Clear mount marks and inode table before a config reload.
 */
void fanotify_clear_marks(int fd);

/*
 * Drain pending FAN_OPEN_PERM events without blocking.
 * Auto-allows events from the dialog process group (dialog child and its
 * children, e.g. kdialog behind timeout(1)) and events from direct daemon
 * children.  Every other permission event runs the FULL decision pipeline
 * in defer mode: deny stages, caches and rule grants decide immediately,
 * so an allowlisted or denylisted read never queues behind the open
 * decision.  Only events that genuinely require the user are copied to a
 * deferred queue (their event fd stays open) and are replayed by the main
 * loop once the dialog finishes.  Closing such an event fd instead would
 * leave the caller's open() blocked forever and leak a kernel permission
 * event.  A nested pump (re-entered from inside a defer-mode decision,
 * e.g. by a hashing helper wait) falls back to the cheap fast-path allow
 * and defers the rest instead of recursing into the pipeline.
 * Bounded per call: after a small number of read(2) batches, or at the
 * first record boundary once g_running, g_need_reload or g_fatal is set,
 * it returns to the caller's poll loop with the rest of the stream left
 * in the group fd (readable, so the next poll/entry continues).  Every
 * record already read is responded to or claimed (batch_abandon) before
 * the return; no record is ever leaked or silently abandoned.
 * Called by notify.c while waiting for the dialog child to finish.
 * Returns the number of events responded to immediately.
 */
int fanotify_pump(int fan_fd, pid_t dialog_child_pid);

/*
 * Queue a read-but-undecided permission event for replay by the main
 * loop; the kernel event fd must stay open.  Returns 0 when queued,
 * -1 when the pending queue is full — the caller must then respond
 * fail-closed (FAN_DENY) and close the event fd.
 */
int fanotify_defer_event(const struct fanotify_event_metadata *ev);

/*
 * Deny every deferred permission event.  Called when the kernel reports
 * FAN_Q_OVERFLOW (saturation) and on config reload and shutdown; fail
 * closed.  A response whose write fails is queued for retry with its
 * event fd kept open (see fanotify_respond): the retry loop or the
 * shutdown drain answers it later, and only events that could not be
 * written are left open; everything else is denied and closed here.
 */
void fanotify_flush_pending(int fan_fd);

/*
 * Deny and close every FAN_OPEN_PERM event still queued in the kernel.
 * Must run before close(fan_fd) on shutdown: the kernel responds
 * FAN_ALLOW to outstanding permission events when the group fd is
 * closed, so the queue has to be drained and denied first (fail closed).
 * Responses still held by the retry queue are delivered (or forced to
 * DENY) before the kernel drain.
 */
void fanotify_drain_and_deny(int fan_fd);

/*
 * Dynamic allowlist / denylist persistence: load root-only state files
 * into the in-memory lists (called on daemon startup and reload).
 *
 * Each admitted entry keeps its stored rule_id (16 lowercase hex chars)
 * and created_at.  A legacy entry with no ID gets one generated from its
 * identity, unique within the same list (allow and deny are independent
 * ID namespaces); a malformed stored ID never reaches this layer because
 * persist_load() drops that entry whole (fail closed).  When at least
 * one ID was regenerated the migrated list is written back to that
 * side's state file immediately (through the path set by
 * fanotify_set_state_files()), so the file gains the IDs at the first
 * load.  Grants are kept, never dropped; an entry is only dropped when
 * no ID can be generated for it (fail closed, logged).  A failed
 * migration write keeps the in-memory IDs (logs, no rollback).
 */

/* Load persisted entries into the dynamic allowlist. Called on daemon startup. */
void fanotify_load_dyn_allowlist(const PersistEntry *entries, int count);

/* Load persisted entries into the dynamic denylist. Called on daemon startup. */
void fanotify_load_dyn_denylist(const PersistEntry *entries, int count);

/*
 * Redirect the state files the runtime lists are written to (adds,
 * migrations and mutations).  NULL or "" restores the production default
 * for that side (PERSIST_STATE_FILE / PERSIST_DENY_STATE_FILE); an
 * over-long path is rejected and leaves the previous value in place.
 * Test seam: lets unprivileged suites use a temp directory instead of
 * /var/lib/fileshield.
 */
void fanotify_set_state_files(const char *allow_path, const char *deny_path);

/*
 * Mutation APIs for the in-memory runtime lists.  Each updates memory and
 * the side's state file atomically, restores the pre-mutation list when
 * the write fails, and logs the change at LOG_INFO (audit trail).  deny
 * selects the list: 0 = allowlist, non-zero = denylist.  The other list
 * is never touched.
 */

/*
 * Remove the entry addressed by id: >= RULEID_MIN_PREFIX (8) and at most
 * RULEID_HEX_LEN (16) lowercase hex chars, an unambiguous prefix of one
 * stored ID or that ID itself.  Entries with an empty ID do not
 * participate.  Returns:
 *    1  removed; memory and the state file no longer hold the entry
 *    0  no stored ID matches (nothing changed)
 *   -2  the prefix matches more than one stored ID (nothing removed)
 *   -1  invalid id, a live entry with an unusable stored ID, or a state
 *       file write failure (the pre-removal list is restored)
 */
int fanotify_remove_dyn_entry(int deny, const char *id);

/*
 * Clear one runtime list (both memory and state file).  Returns the
 * number of entries removed, or -1 on a state file write failure (the
 * pre-clear list is restored).
 */
int fanotify_clear_dyn_list(int deny);

/*
 * Remove duplicate rules from one runtime list: entries sharing binary +
 * target path + raw command line + call chain keep the newest (last
 * added) and the older ones are removed (prune.h grouping; digests and
 * created_at are not part of the key).  *removed_out may be NULL and
 * otherwise receives the number of entries removed.  Returns 0 on
 * success (including when there are no duplicates), or -1 on failure
 * (the pre-prune list is restored).
 */
int fanotify_prune_dyn_list(int deny, int *removed_out);

/*
 * Test seams: evaluate the loaded runtime lists against a synthetic
 * request with a zero-depth call chain.  Used by test_fanotify to
 * regression-test target and command-line scoping without a kernel
 * permission event.  cmdline_fp is the full-cmdline fingerprint exactly
 * as an event would compute it ("" = unverifiable, which never matches);
 * tests and the benchmark build it with sha512_string().
 *
 * The allow seam is boolean (1 match, 0 no match).  The deny seam is
 * tri-state: 1 conclusive match, 0 no match, -1 inconclusive (the
 * entry's path keys fit, it stores a binary SHA-512, and bin_sha512 is
 * empty) -- the pipeline then skips grants and prompts.
 */
int fanotify_test_dyn_allow_match(const char *binary, const char *bin_sha512,
                                  const char *target, const char *cmdline_fp);
int fanotify_test_dyn_deny_match(const char *binary, const char *bin_sha512,
                                 const char *target, const char *cmdline_fp);

/*
 * Test seams: evaluate the loaded config rule sections against a
 * synthetic request.  Unprivileged, no kernel permission event needed.
 * All three use the same matchers as the pipeline, including glob
 * binaries/targets.
 *
 * fanotify_test_config_allow_match() returns the matched [allowlist]
 * rule's canonical binary pattern (the hash-pin key), or NULL when no
 * rule matches.  When grant_target is non-NULL it receives the rule's
 * target_path, or NULL for a global rule (wildcard cache entry).
 *
 * fanotify_test_unsafe_allow_match() does the same for
 * [unsafe_allowlist], which never participates in hash pinning.
 *
 * fanotify_test_config_deny_match() returns the [denylist] verdict:
 * non-zero when a rule matches (deny wins), 0 otherwise.
 */
const char *fanotify_test_config_allow_match(const char *binary,
                                             const char *target,
                                             const char **grant_target);
const char *fanotify_test_unsafe_allow_match(const char *binary,
                                             const char *target);
int fanotify_test_config_deny_match(const char *binary, const char *target);

/*
 * Test seams: the [allowlist] hash-pin verdict without a kernel event.
 * fanotify_test_allowlist_verdict() runs the same decision the pipeline
 * uses for the first rule matching (binary, target):
 *   0 ALLOW            stored pin matches; a first-use rule is also
 *                      reported as ALLOW because the pipeline stores the
 *                      digest and grants (the store itself is covered by
 *                      fanotify_test_pin_first_seen())
 *   1 CHANGED          stored digest differs; the previous digest is
 *                      copied into old_out
 *   2 NO_SILENT_GRANT  pin table damaged or bin_sha512 empty/missing
 *   3 NO_MATCH         no [allowlist] rule matches
 * Side-effect free: it never stores a pin and never prompts.
 *
 * fanotify_test_pin_first_seen() performs the pipeline's first-seen
 * store: when (binary, target) matches an [allowlist] rule that has no
 * pin yet it calls pin_store() on the rule's canonical binary pattern,
 * which writes the state file immediately and atomically.  Returns 0 on
 * success; -1 when no rule matches, the rule already has a pin, or the
 * store fails.
 */
int fanotify_test_allowlist_verdict(const char *binary,
                                    const char *bin_sha512,
                                    const char *target,
                                    char old_out[129]);
int fanotify_test_pin_first_seen(const char *binary,
                                 const char *bin_sha512,
                                 const char *target);

/*
 * Test seam: fingerprint a live process's full raw command line the same
 * way the event pipeline does (NUL-separated bytes, bounded).  Returns 0
 * on success and fills hex_out, -1 when the cmdline is unreadable/empty.
 */
int fanotify_test_cmdline_fingerprint(pid_t pid, char hex_out[129]);

/*
 * Test seam: the fast path's "mount-mark noise" verdict for a synthetic
 * (dev, ino, path) — the same condition event_fastpath uses to allow an
 * event instantly.  Used by bench_hotpath to measure the per-event
 * classification cost at realistic table sizes.
 */
int fanotify_test_fastpath_allows(dev_t dev, ino_t ino, const char *path);

/*
 * Test seam: resolve an open fd to its path exactly like the event
 * pipeline does (including the " (deleted)" marker stripping).  Lets
 * test_fanotify pin the unlinked-file behavior without a kernel
 * permission event.
 */
int fanotify_test_resolve_path(int fd, char *out, size_t outsz);

/*
 * Test seam: the unsafe-hit per-process gate.  Returns 1 the first time
 * (pid, start time) is seen and records it, 0 on every later call for the
 * same process.  Used by test_fanotify without a kernel permission event.
 */
int fanotify_test_unsafe_first_hit(pid_t pid);

/*
 * Test seams: init-namespace mount-mark plumbing.  fanotify_test_mark_path()
 * builds "/proc/1/root" + path (0 on success, -1 when it does not fit);
 * fanotify_test_mount_id() returns the init-namespace mount ID of the mount
 * containing path, or 0 when statx(STATX_MNT_ID) is unavailable.
 */
int fanotify_test_mark_path(const char *path, char *out, size_t outsz);
unsigned long long fanotify_test_mount_id(const char *path);

/*
 * Test seam: force mount_id_of() to report "unavailable", simulating a
 * kernel without statx(STATX_MNT_ID), so the scope guard's device-level
 * fallback can be regression-tested on any kernel.
 */
void fanotify_test_force_mount_id_unavailable(int on);

/*
 * Test seam: batch_abandon() — claim the records left behind when an
 * event walk exits early.  ev/remaining describe a synthetic batch (the
 * walk's current record, already handled by the caller); group_fd may be
 * ANY writable fd: a pipe stand-in receives the fanotify_response writes
 * so a test can assert each stranded permission event was denied.  The
 * seam closes every claimable event fd it passes.  Returns the number of
 * permission events denied.
 */
int fanotify_test_batch_abandon(int group_fd,
                                const struct fanotify_event_metadata *ev,
                                ssize_t remaining);

/*
 * Test seam: event_next()'s tri-state batch advance.  Returns the next
 * record or NULL; *malformed is set to 1 only when a zero/oversized
 * (otherwise invalid) event_len makes the rest of the batch unlocatable,
 * and left 0 for a clean end of the batch (the silent, normal path).
 */
const struct fanotify_event_metadata *
fanotify_test_event_next(const struct fanotify_event_metadata *ev,
                         ssize_t *remaining, int *malformed);

/*
 * Test seam: event_resolve()'s FAN_NOFD branch (M6).  Runs the real
 * stage-1 check on a synthetic context whose event fd is FAN_NOFD and
 * returns its verdict (1 = handled).  group_fd — a pipe write end stands
 * in for the group — must receive NO fanotify_response bytes: no event
 * fd exists to answer, the kernel already auto-DENIED the event, and a
 * write with fd=-1 would earn EINVAL -> g_fatal -> a phantom retry.
 */
int fanotify_test_resolve_nofd(int group_fd);

/*
 * Test seams: the failed-response retry queue.  fanotify_test_respond()
 * runs the real fanotify_respond() against any writable fd (a pipe
 * stand-in receives the fanotify_response writes) and returns 0 when the
 * response was delivered -- the caller may close the event fd -- or -1
 * when the caller MUST keep it open (queued in the growing retry queue,
 * or parked in the bounded stranded list).  The count seams expose the
 * current queue/stranded depth; the force seam makes the next queue
 * admission fail (as if its allocation failed) so the stranded fallback
 * is reachable without real memory pressure.  Draining through
 * fanotify_drain_and_deny() on a fresh pipe delivers one exact
 * fanotify_response (stranded fds as FAN_DENY) and closes every event fd.
 */
int fanotify_test_respond(int group_fd,
                          const struct fanotify_event_metadata *ev,
                          unsigned int response);
int fanotify_test_unanswered_count(void);
int fanotify_test_stranded_count(void);
void fanotify_test_force_unanswered_alloc_fail(int on);

/*
 * Test seam: the dialog pid the current pump stack publishes for the
 * hash-helper wait hook (g_active_dialog_pid).  0 when no dialog pump is
 * on the stack; nonzero only DURING a fanotify_pump() call made with a
 * dialog pid (it must be restored to 0 on return, at every exit path).
 */
pid_t fanotify_test_active_dialog_pid(void);

/*
 * Test seams: the recent-decision dedup cache.  The key is
 * (pid, process start time, resolved binary, dev, ino, resolved path); a
 * newer decision replaces an older one for the same key, and a reload
 * clears the cache.  The start time and binary bind a decision to one
 * process image, so a recycled PID or an exec cannot inherit it.
 */
void fanotify_test_recent_insert(pid_t pid, unsigned long long start,
                                 const char *binary, dev_t dev, ino_t ino,
                                 const char *target, int decision);
int fanotify_test_recent_lookup(pid_t pid, unsigned long long start,
                                const char *binary, dev_t dev, ino_t ino,
                                const char *target);
void fanotify_test_recent_clear(void);

/*
 * Test seam: run the real verdict stages (denials before grants) over a
 * synthetic request.  Returns 1 when a deny stage decided, 2 when a grant
 * stage decided, 0 when the event would reach the dialog.  sid > 0 marks
 * the synthetic context as a member of that session; cmdline_fp may be
 * NULL; hardlink mirrors the pipeline's hard-link classification (which
 * strips every grant); defer mirrors the pump's defer_on_ask mode (a
 * changed hash pin defers instead of opening a second dialog).  An
 * inconclusive deny (a deny entry whose stored digest cannot be checked
 * against an empty bin_sha512) also returns 0: grants are gated, so the
 * event prompts instead of being granted by a hash-free stage.
 */
int fanotify_test_verdict_stage(const char *binary, const char *bin_sha512,
                                const char *target, const char *cmdline_fp,
                                pid_t sid, int hardlink, int defer);

/*
 * Test seam: run the real allow-decision recorder over a synthetic dialog
 * decision and return the fanotify response (FAN_ALLOW).  sid > 0 marks
 * the context as a member of that session with the given leader start
 * time; bin_sha512 may be NULL or "" to mirror an unavailable digest.
 * The event pid is the caller's, so a degraded grant is cached under it.
 */
unsigned int fanotify_test_record_allow_decision(const char *binary,
                                                 const char *bin_sha512,
                                                 const char *target,
                                                 pid_t sid,
                                                 unsigned long long sid_start,
                                                 int decision);

/* Test seam: the per-binary dialog rate limiter. */
int fanotify_test_dialog_rate_limited(const char *binary);

/*
 * Test seam: clear the dialog rate-limit state (per-binary entries and
 * the global prompt budget) so limit tests are order-independent.
 */
void fanotify_test_reset_dialog_rate(void);

/*
 * Test seam: record a mark-table entry like a real installation (no
 * kernel call), so unprivileged reload tests can start from a state
 * where marks are active and exercise the "rollback left no active
 * marks" shutdown branch.  Returns 0 on success, -1 when the table is
 * full; fanotify_clear_marks() removes it again.
 */
int fanotify_test_seed_mark(const char *path);

/*
 * Test seam: run fanotify_pump() with g_pump_in_pipeline forced set —
 * exactly the state hash_wait_pump creates while a hash helper waits
 * inside a defer-mode pipeline decision.  Pins the nested-pump branch
 * (cheap fast-path allow for an unprotected target / defer the rest;
 * never a recursive process_open_perm) without a live hash wait.  The
 * flag is saved and restored around the call like the production
 * set/clear pair.  Returns the pump's responded-event count.
 */
int fanotify_test_pump_nested(int fan_fd, pid_t dialog_pid);

#endif
