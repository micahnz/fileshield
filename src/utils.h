#ifndef FILESHIELD_UTILS_H
#define FILESHIELD_UTILS_H

#include <signal.h>
#include <sys/types.h>

/*
 * Daemon lifecycle flags, defined in main.c: g_running is cleared by
 * SIGTERM/SIGINT, g_need_reload set by SIGHUP, g_fatal set when the
 * fanotify group became unusable or a rollback failed.  One shared
 * declaration so a type change in main.c cannot silently desynchronize
 * the readers (reload.c, notify.c, fanotify.c).
 */
extern volatile sig_atomic_t g_running;
extern volatile sig_atomic_t g_need_reload;
extern volatile sig_atomic_t g_fatal;

extern int g_foreground;

/*
 * Sanity bound for every decision TTL (1 year): keeps `now + ttl`
 * arithmetic safe on any time_t width and stops a typo from silently
 * granting access for decades.  config.c clamps at parse time with a
 * warning; cache.c and session.c clamp again defensively.
 */
#define FS_MAX_TTL_SECONDS (365 * 24 * 60 * 60)

/*
 * mono_seconds: CLOCK_MONOTONIC seconds since boot, as time_t.  The
 * deadline clock for every in-memory decision TTL (cache.c, session.c
 * and the hash-failure windows): immune to wall-clock steps (NTP
 * corrections, manual date, VM/snapshot restore), which would otherwise
 * extend cached grants or mass-expire into prompt storms.  Stored state
 * (pins, persisted entries) keeps wall-clock time so it survives
 * restarts.  Falls back to time(NULL) if clock_gettime fails (it does
 * not on Linux).
 */
time_t mono_seconds(void);

char *proc_exe_path(pid_t pid);
void log_msg(int priority, const char *fmt, ...);

/*
 * Replace control characters (including newlines) with '?' in place.
 * log_msg() applies it to every rendered line as a choke point against
 * log-injection through attacker-controlled paths/comm/cmdline; unit
 * tests verify the scrub directly.
 */
void log_scrub(char *s);

/*
 * Generic /proc readers shared by the event pipeline and the dialog
 * code.  All three return -1 (or 0 for get_ppid) when the process is
 * gone or unreadable; callers treat that as "identity unavailable".
 */

/* Parent pid of 'pid' from /proc/<pid>/status, or 0 when unreadable. */
pid_t get_ppid(pid_t pid);

/*
 * Copy /proc/<pid>/comm (the process name, at most 15 chars plus NUL)
 * into out, stripping the trailing newline.  Returns 0 on success.
 */
int read_comm(pid_t pid, char *out, size_t size);

/*
 * Read /proc/<pid>/cmdline and collapse the NUL argument separators into
 * spaces: the bounded, human-readable display form used in dialogs.
 * Matching uses a fingerprint of the raw bytes instead (fanotify.c).
 * Returns the number of bytes written (excluding the NUL), or -1.
 */
int read_cmdline(pid_t pid, char *out, size_t size);

/*
 * log_set_debug: enable or disable LOG_DEBUG emission.  Disabled by
 * default so the per-event firehose ([event]/[dedup]/[pump]) stays out
 * of the journal; troubleshooting turns it on with [settings] debug or
 * --debug.  The gate sits at log_msg() entry so a disabled LOG_DEBUG
 * call costs one branch, not a vsyslog format+send.
 */
void log_set_debug(int enabled);

/* Current debug gate state (test/introspection only). */
int log_debug_enabled(void);

/*
 * proc_stat_session: read /proc/<pid>/stat once and extract the POSIX
 * session id (field 6) and the process start time (field 22, clock ticks
 * since boot).  Either out pointer may be NULL.  Returns 0 on success,
 * -1 when the process is gone or the stat line cannot be parsed; out
 * values stay untouched on failure.  Shared by cache.c (PID-reuse
 * detection) and session.c (session identity) — one parser instead of
 * two divergent ones.
 */
int proc_stat_session(pid_t pid, unsigned long long *sid_out,
                      unsigned long long *start_out);

/*
 * Test seam: parse a synthetic /proc/<pid>/stat line exactly like
 * proc_stat_session does (n = bytes before the terminator).  Exercises
 * the comm-with-')'-and-spaces path and the field offsets without a
 * live process.
 */
int utils_test_parse_proc_stat(const char *line, size_t n,
                               unsigned long long *sid_out,
                               unsigned long long *start_out);

/*
 * close_fds_from: close every file descriptor >= 'first' in the calling
 * process.  Used by fork()ed children before exec() so no daemon file
 * descriptors (fanotify group fd, event fds, pipes) leak into helpers.
 * Uses close_range(2) when available and falls back to a bounded loop.
 * Fallback cap: when SYS_close_range is unavailable AND
 * sysconf(_SC_OPEN_MAX) > 65536, only fds below 65536 are closed — the
 * loop is deliberately bounded so a huge RLIMIT_NOFILE cannot turn this
 * into a long scan.  Production helper children inherit low fds, so this
 * cap is the leak fence; the high-RLIMIT edge (fds >= 65536 surviving)
 * is accepted and documented here rather than fixed by an unbounded
 * scan.
 */
void close_fds_from(int first);

/*
 * path_under: return 1 if 'path' is equal to or inside 'dir'.
 * Boundary primitive behind every rule match: is_path_under_protected()
 * and rule_matches() in fanotify.c both build on it.
 */
int path_under(const char *path, const char *dir);

/*
 * path_under_len: path_under() with the directory length supplied by the
 * caller.  Glob entries cache their wildcard-free base length, so the
 * hot-path prefilter avoids a strlen per event.
 */
int path_under_len(const char *path, const char *dir, size_t dirlen);

/*
 * glob_base_len: length of the wildcard-free prefix of a glob pattern —
 * the part before the first segment containing '*'.  That prefix is the
 * directory a glob entry can be marked on directly and the cheap
 * prefilter before glob_match_path().  Returns the pattern length when
 * the pattern contains no '*', and 0 when the first segment is a
 * wildcard (no usable base).
 */
int glob_base_len(const char *pattern);

/*
 * glob_match_path: full-path match of a glob pattern against a path
 * (both canonical).  '*' matches zero or more characters within one
 * segment and never crosses '/'; a segment that is exactly "**" matches
 * zero or more segments.  '?', '[' and ']' are literal.  No allocation,
 * no recursion, single-backtrack greedy matcher.  Returns 1 on match.
 */
int glob_match_path(const char *pattern, const char *path);

/*
 * expand_home_all_users: expand a ~/... path template for every user in
 * /etc/passwd and return a NULL-terminated array of malloc'd strings.
 * For paths that do not start with ~/ the array contains a single copy.
 * Returns NULL on allocation failure or when the passwd enumeration
 * fails mid-way (a partial expansion would silently leave some users'
 * paths unprotected while the config still loads).  The caller must call
 * free_string_array().
 */
char **expand_home_all_users(const char *path);
void free_string_array(char **arr);

#endif
