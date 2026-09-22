#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <dirent.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <signal.h>
#include <syslog.h>

#include "fanotify.h"
#include "inode.h"
#include "utils.h"
#include "config.h"
#include "cache.h"
#include "session.h"
#include "notify.h"
#include "sha512.h"
#include "persist.h"
#include "pin.h"
#include "ruleid.h"
#include "prune.h"
#include "control.h"

#define BUF_SIZE 4096

/* Fallback for a config with no [settings] user_ttl (the shipped config
 * sets 300; config.c applies the same default at parse time). */
#define DEFAULT_USER_TTL_S 300

/*
 * fanotify.c — the event decision pipeline and mark bookkeeping.
 *
 * Sections in file order (the banners below mark each one):
 *   proc helpers            - /proc reads used to identify the requester
 *   protected-path matching - prefix/glob/exclusion verdicts
 *   config rule matching    - [allowlist]/[unsafe_allowlist]/[denylist]
 *   hash caches             - binary SHA-512 and failure windows
 *   mark table              - every kernel mark, tracked for removal
 *   scope guard             - refuses configs the marks would intercept
 *   per-event context       - EventCtx and identity gathering
 *   decision pipeline       - event_resolve ... event_ask_user
 *   response handling       - fanotify_respond + the retry queue
 *   deferred queue + pump   - events held while a dialog is open
 *   main event loop         - fanotify_loop
 *   public API + test seams
 *
 * Event -> response lifecycle:
 *   1. fanotify_loop()/fanotify_pump() read FAN_OPEN_PERM events and run
 *      process_open_perm(), which walks the stages in fanotify.h order.
 *   2. A decided event is answered through respond_event(): the response
 *      is written and - on success - the event fd is closed.
 *   3. If the write fails, the response is queued (g_unanswered, which
 *      grows on demand) and the event fd is kept open: closing it would
 *      strand the caller's open() until group close, where the kernel
 *      auto-ALLOWS it.  When the queue cannot grow (allocation failure)
 *      the event fd is parked in the bounded stranded list, which
 *      fanotify_drain_and_deny() force-denies at shutdown.  The main
 *      loop and the pump retry the queue.
 *   4. Events that need the user are deferred with their fds open and
 *      replayed by the main loop after the dialog (fanotify_process_pending).
 */

/* Defined later in this file; declared early for the call-chain hasher. */
static int is_path_under_protected(const char *path);

/* Defined with the protected-path matchers; the inode walk uses it. */
static const ProtectedPath *exclusion_match(const char *path);

/* Defined later; the decision stages respond through this.  Return
 * contract (see fanotify_respond): 0 = delivered or already answered, so
 * the caller may close the event fd; -1 = NOT delivered, the response is
 * queued or stranded and the caller MUST keep the fd open.  There is no
 * third outcome: a decided response is never abandoned. */
static int fanotify_respond(int fd, const struct fanotify_event_metadata *ev,
                            unsigned int response);

/* Defined with fanotify_respond; the pump and the main loop retry queued
 * responses. */
static void unanswered_retry(int fan_fd);

/* Defined with fanotify_respond; claims the records left behind when an
 * event walk exits early (see batch_abandon). */
static int batch_abandon(int fan_fd,
                         const struct fanotify_event_metadata *ev,
                         ssize_t remaining);

/* ------------------------------------------------------------------ */
/*  proc helpers                                                       */
/* ------------------------------------------------------------------ */
/* get_ppid(), read_comm() and the display-form read_cmdline() live in
 * utils.c (unit-tested there); the command-line fingerprint stays here
 * because it is part of the event-matching contract. */

/*
 * Resolve the path of a fanotify event fd into out (outsz bytes).
 * ev->fd is an open fd in the DAEMON's fd table (not the target process's),
 * so we read /proc/self/fd/<fd_num>.
 * Returns 0 on success, -1 when the link cannot be read or its result
 * does not fit the buffer (a truncated result is unverifiable, so a
 * partial path is never treated as a match).  The caller
 * supplies the buffer: this runs once per event, so no malloc per event
 * (bench_hotpath: 1.960 us with a heap buffer vs 1.915 us with the
 * caller's, and one allocation-failure path fewer).  The kernel appends
 * " (deleted)" for unlinked-but-open files; that marker is stripped so
 * matching always sees the real path.
 */
static int resolve_fd_path(int fd_num, char *out, size_t outsz)
{
    char link[64];
    ssize_t len;

    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd_num);
    len = readlink(link, out, outsz - 1);
    /* A result that exactly fills the buffer is either a path that did
     * not fit or one that exactly did; unverifiable either way, so fail
     * closed exactly like proc_exe_path(). */
    if (len < 0 || (size_t)len >= outsz - 1)
        return -1;
    out[len] = '\0';

    static const char deleted[] = " (deleted)";
    size_t dlen = sizeof(deleted) - 1;
    if ((size_t)len >= dlen && strcmp(out + len - dlen, deleted) == 0)
        out[len - dlen] = '\0';
    return 0;
}

/*
 * Upper bound for the raw command line consumed by the fingerprint.  The
 * display form is capped at 512 bytes, but the fingerprint must cover the
 * full invocation: hashing only a prefix let one approved command cover a
 * different command that shared that prefix (e.g. a padded argument
 * followed by a different URL).  64 KB is far beyond any practical
 * invocation while keeping the read and hash bounded.
 */
#define CMDLINE_FP_MAX (64 * 1024)

/*
 * Fingerprint the FULL raw command line of pid (bounded by
 * CMDLINE_FP_MAX).  The NUL-separated bytes are hashed as-is, so two
 * invocations that differ anywhere inside the bound get different
 * fingerprints.  A command line that does not fit the bound has no
 * fingerprint at all (two over-long commands sharing the first 64 KB
 * must not share a key), so callers fail closed.  Returns 0 on success,
 * -1 when the cmdline is unreadable, empty, or over-long.
 */
static int read_cmdline_fingerprint(pid_t pid, char hex_out[129])
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    char *buf = malloc(CMDLINE_FP_MAX);
    if (!buf)
    {
        close(fd);
        return -1;
    }

    size_t total = 0;
    while (total < CMDLINE_FP_MAX)
    {
        ssize_t n = read(fd, buf + total, CMDLINE_FP_MAX - total);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            total = 0;
            break;
        }
        if (n == 0)
            break;
        total += (size_t)n;
    }

    int overflow = 0;
    if (total == CMDLINE_FP_MAX)
    {
        /* One byte past the bound tells whether the command line was
         * truncated at CMDLINE_FP_MAX. */
        char extra;
        ssize_t n;
        do
        {
            n = read(fd, &extra, 1);
        } while (n < 0 && errno == EINTR);
        if (n > 0)
            overflow = 1;
    }
    close(fd);

    if (overflow)
    {
        log_msg(LOG_WARNING,
                "cmdline fingerprint: pid %d command line exceeds %d bytes; "
                "no fingerprint (fail closed)",
                (int)pid, CMDLINE_FP_MAX);
        free(buf);
        return -1;
    }

    int rc = (total > 0) ? sha512_buf(buf, total, hex_out) : -1;
    free(buf);
    return rc;
}

/*
 * Config rule matching.  Each side is exact or glob, prepared by
 * config_load(): exact sides keep their historical semantics (binary by
 * strcmp; target by path_under(), i.e. equal or under) and glob sides
 * use the same cheap path_under_len() prefilter on their cached
 * wildcard-free base that protected-path globs use, then the full
 * glob_match_path() verdict.  An empty target_path makes the rule
 * global: it matches every protected path.
 */
static int rule_matches(const RuleEntry *e, const char *binary,
                        const char *target)
{
    if (e->binary_is_glob)
    {
        if (!path_under_len(binary, e->binary, (size_t)e->binary_base_len))
            return 0;
        if (!glob_match_path(e->binary, binary))
            return 0;
    }
    else if (strcmp(e->binary, binary) != 0)
    {
        return 0;
    }

    if (e->target_path[0] == '\0')
        return 1;
    if (e->target_is_glob)
    {
        if (!path_under_len(target, e->target_path,
                            (size_t)e->target_base_len))
            return 0;
        return glob_match_path(e->target_path, target);
    }
    return path_under(target, e->target_path);
}

/*
 * Config [allowlist]: an explicit admin opt-in.  Returns the matched
 * rule (NULL = no match) so the caller can derive the hash-pin key from
 * rule->binary and the file-cache grant target from rule->target_path
 * (NULL for a global rule = wildcard cache entry).
 */
static const RuleEntry *allowlist_match(const char *binary,
                                        const char *target)
{
    if (!g_config)
        return NULL;
    for (int i = 0; i < g_config->allowlist_count; i++)
    {
        const RuleEntry *e = &g_config->allowlist[i];
        if (rule_matches(e, binary, target))
            return e;
    }
    return NULL;
}

/*
 * Config [unsafe_allowlist]: same matching as [allowlist] but these
 * rules skip hash pinning entirely.  The event pipeline evaluates this
 * section before [allowlist] and grants a hit silently.
 */
static const RuleEntry *unsafe_allowlist_match(const char *binary,
                                               const char *target)
{
    if (!g_config)
        return NULL;
    for (int i = 0; i < g_config->unsafe_allowlist_count; i++)
    {
        const RuleEntry *e = &g_config->unsafe_allowlist[i];
        if (rule_matches(e, binary, target))
            return e;
    }
    return NULL;
}

/* Config [denylist]: static admin-denied binary/target pairs (globs
 * included through rule_matches()), checked before every grant so a
 * denial always wins.  Deny rules are never hash-pinned. */
static const RuleEntry *denylist_match(const char *binary, const char *target)
{
    if (!g_config)
        return NULL;
    for (int i = 0; i < g_config->denylist_count; i++)
    {
        if (rule_matches(&g_config->denylist[i], binary, target))
            return &g_config->denylist[i];
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Executable hash cache                                             */
/* ------------------------------------------------------------------ */
/*
 * Hashing forks sha512sum and runs on the event-loop critical path while
 * the requesting process is suspended, so repeat lookups of the same
 * binary reuse the cached digest.  Keyed by (dev, ino, size, mtime,
 * ctime); any metadata change invalidates the entry.  ctime matters for
 * the pin verdict: mtime is settable by the file's owner (utimensat), so
 * a user-writable binary could otherwise be swapped in place and keep a
 * stale cached digest that still matches the allowlist pin.
 *
 * Failures are remembered for a short window too: a binary that cannot
 * be hashed (helper timeout on a FUSE mount, unreadable path) would
 * otherwise fork, stall for the full SHA-512 timeout and log again on
 * every single event.  The negative entry still reports "unavailable" to
 * the pipeline, so every fail-closed decision is unchanged.
 */
#define HASH_CACHE_MAX 64
/* Negative windows are measured on the monotonic clock (mono_seconds):
 * a wall-clock step must not extend a fail-closed retry, and the fields
 * are memory-only, so no persisted timestamp changes meaning. */
#define HASH_FAIL_RETRY_S 60

typedef struct
{
    dev_t dev;
    ino_t ino;
    off_t size;
    time_t mtime_sec;
    long mtime_nsec;
    time_t ct_sec;
    long ct_nsec;
    char hex[129];
    int failed;         /* 1 = last attempt failed; retry after the window */
    time_t retry_after; /* valid when failed                                */
    char failure[80];   /* reason, kept so a cached miss can explain itself */
} HashCacheEntry;

static HashCacheEntry g_hash_cache[HASH_CACHE_MAX];
static int g_hash_cache_count = 0;
static int g_hash_cache_next = 0;

/*
 * Reason for the most recent binary-hash failure, including failures
 * answered from the negative cache (where sha512_last_failure() would be
 * stale or describe a different file).  Read it right after a -1 return.
 */
static char g_hash_failure_reason[80];

/*
 * Fallback failure cache for processes whose /proc/<pid>/exe cannot be
 * stat()ed (the exe target is unreachable from this mount namespace, or
 * the process is mid-exec).  The main cache has no metadata to key on in
 * that case, so remember the failure against (pid, process start time)
 * instead: hashing such a path fails immediately, and retrying it on
 * every event is pure cost and log noise.  The start time makes PID
 * reuse a miss.  force_retry bypasses the window (recording wants a
 * fresh attempt at the pre-dialog snapshot).
 */
#define HASH_PID_FAIL_MAX 32

typedef struct
{
    pid_t pid;           /* 0 = empty slot                                  */
    unsigned long long start; /* /proc/<pid>/stat field 22                    */
    time_t retry_after;
    char failure[80];
} HashPidFailEntry;

static HashPidFailEntry g_hash_pid_fails[HASH_PID_FAIL_MAX];
static int g_hash_pid_fail_count = 0;
static int g_hash_pid_fail_next = 0;

static void hash_pid_fail_store(pid_t pid, unsigned long long start,
                                time_t now, const char *reason)
{
    int slot = -1;

    for (int i = 0; i < g_hash_pid_fail_count; i++)
    {
        if (g_hash_pid_fails[i].pid == pid &&
            g_hash_pid_fails[i].start == start)
        {
            slot = i;
            break;
        }
    }

    if (slot < 0)
    {
        if (g_hash_pid_fail_count < HASH_PID_FAIL_MAX)
            slot = g_hash_pid_fail_count++;
        else
        {
            slot = g_hash_pid_fail_next;
            g_hash_pid_fail_next = (g_hash_pid_fail_next + 1) % HASH_PID_FAIL_MAX;
        }
    }

    g_hash_pid_fails[slot].pid = pid;
    g_hash_pid_fails[slot].start = start;
    g_hash_pid_fails[slot].retry_after = now + HASH_FAIL_RETRY_S;
    snprintf(g_hash_pid_fails[slot].failure,
             sizeof(g_hash_pid_fails[slot].failure), "%s", reason);
}

static void hash_pid_fail_forget(pid_t pid, unsigned long long start)
{
    for (int i = 0; i < g_hash_pid_fail_count; i++)
    {
        if (g_hash_pid_fails[i].pid == pid &&
            g_hash_pid_fails[i].start == start)
        {
            g_hash_pid_fails[i].pid = 0;
            return;
        }
    }
}

/*
 * Binary SHA-512 for one process, served from the two caches described
 * above:
 *   - /proc/<pid>/exe stat()able: the (dev, ino, size, mtime, ctime)
 *     identity cache, with a failed lookup served from its slot until
 *     retry_after.
 *   - exe unreachable (mid-exec, or not visible in this mount
 *     namespace): the (pid, start) failure cache, so an immediately
 *     failing hash is attempted once per window, not once per event.
 * force_retry ignores both negative windows (the prompt boundary wants
 * a fresh attempt for the pre-dialog snapshot).  Returns 0 and fills
 * hex_out on success; -1 with g_hash_failure_reason set otherwise.
 */
static int cached_sha512_proc_exe(pid_t pid, char hex_out[129], int force_retry)
{
    char proc_path[64];
    struct stat st;
    char hex[129];
    int r;
    int reuse = -1;

    int n = snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", (int)pid);
    if (n < 0 || (size_t)n >= sizeof(proc_path))
        return -1;

    if (stat(proc_path, &st) != 0)
    {
        /* No metadata to key the main cache on: use (pid, start).
         * The start time is mandatory for the key -- without it PID
         * reuse could inherit the failure -- so a missing start means
         * no lookup and no store (the hash is retried every event). */
        unsigned long long start = 0;
        int have_start = proc_stat_session(pid, NULL, &start) == 0;

        if (have_start)
        {
            for (int i = 0; i < g_hash_pid_fail_count; i++)
            {
                const HashPidFailEntry *e = &g_hash_pid_fails[i];
                if (e->pid == pid && e->start == start)
                {
                    if (!force_retry && mono_seconds() < e->retry_after)
                    {
                        snprintf(g_hash_failure_reason,
                                 sizeof(g_hash_failure_reason), "%s",
                                 e->failure);
                        log_msg(LOG_DEBUG,
                                "[hash-cache] recent failure for pid=%d; "
                                "not retrying yet",
                                (int)pid);
                        return -1;
                    }
                    break;
                }
            }
        }

        r = sha512_proc_exe(pid, hex_out);
        if (r == 0)
        {
            g_hash_failure_reason[0] = '\0';
            if (have_start)
                hash_pid_fail_forget(pid, start);
            return 0;
        }

        snprintf(g_hash_failure_reason, sizeof(g_hash_failure_reason), "%s",
                 sha512_last_failure()[0] ? sha512_last_failure()
                                          : "hashing failed");
        if (have_start)
            hash_pid_fail_store(pid, start, mono_seconds(),
                                g_hash_failure_reason);
        return -1;
    }

    /* exe stat()able: the metadata-keyed identity cache.  A live digest
     * answers without forking; a failure inside its window answers -1
     * for the same cost. */
    time_t now = mono_seconds();

    for (int i = 0; i < g_hash_cache_count; i++)
    {
        const HashCacheEntry *e = &g_hash_cache[i];
        if (e->dev == st.st_dev && e->ino == st.st_ino &&
            e->size == st.st_size &&
            e->mtime_sec == st.st_mtim.tv_sec &&
            e->mtime_nsec == st.st_mtim.tv_nsec &&
            e->ct_sec == st.st_ctim.tv_sec &&
            e->ct_nsec == st.st_ctim.tv_nsec)
        {
            if (!e->failed)
            {
                memcpy(hex_out, e->hex, sizeof(e->hex));
                return 0;
            }
            if (!force_retry && now < e->retry_after)
            {
                snprintf(g_hash_failure_reason, sizeof(g_hash_failure_reason),
                         "%s", e->failure);
                log_msg(LOG_DEBUG,
                        "[hash-cache] recent failure for pid=%d; "
                        "not retrying yet",
                        (int)pid);
                return -1;
            }
            reuse = i; /* window expired or forced: retry into this slot */
            break;
        }
    }

    r = sha512_proc_exe(pid, hex);

    /* A matching failed slot is reused: the retry updates its identity
     * in place, and a success there cannot be shadowed by a stale
     * negative entry for the same metadata. */
    int slot;
    if (reuse >= 0)
        slot = reuse;
    else if (g_hash_cache_count < HASH_CACHE_MAX)
        slot = g_hash_cache_count++;
    else
    {
        /* Full: evict round-robin; evicting a live digest only costs a
         * future re-hash, so no correctness depends on the choice. */
        slot = g_hash_cache_next;
        g_hash_cache_next = (g_hash_cache_next + 1) % HASH_CACHE_MAX;
    }

    HashCacheEntry *e = &g_hash_cache[slot];
    e->dev = st.st_dev;
    e->ino = st.st_ino;
    e->size = st.st_size;
    e->mtime_sec = st.st_mtim.tv_sec;
    e->mtime_nsec = st.st_mtim.tv_nsec;
    e->ct_sec = st.st_ctim.tv_sec;
    e->ct_nsec = st.st_ctim.tv_nsec;

    if (r < 0)
    {
        e->failed = 1;
        e->retry_after = now + HASH_FAIL_RETRY_S;
        e->hex[0] = '\0';
        snprintf(e->failure, sizeof(e->failure), "%s",
                 sha512_last_failure()[0] ? sha512_last_failure()
                                          : "hashing failed");
        snprintf(g_hash_failure_reason, sizeof(g_hash_failure_reason), "%s",
                 e->failure);
        return -1;
    }

    e->failed = 0;
    e->retry_after = 0;
    e->failure[0] = '\0';
    g_hash_failure_reason[0] = '\0';
    memcpy(e->hex, hex, sizeof(hex));
    memcpy(hex_out, hex, sizeof(hex));
    return 0;
}

/* ------------------------------------------------------------------ */
/*  process call-chain (parent → grandparent → great-grandparent)     */
/* ------------------------------------------------------------------ */

typedef struct
{
    char comm[PERSIST_CHAIN_MAX][256];
    char sha512[PERSIST_CHAIN_MAX][129]; /* lowercase hex SHA-512 of each ancestor exe */
    int depth;                           /* how many ancestors were captured            */
} ProcChain;

/*
 * force_retry bypasses negative hash-failure entries for every ancestor:
 * used when a decision is about to be recorded, so the persisted chain
 * gets a fresh attempt rather than a cached "unhashable" verdict.
 */
static void build_proc_chain(pid_t start_pid, ProcChain *c, int force_retry)
{
    memset(c, 0, sizeof(*c));
    pid_t cur = start_pid;
    for (int i = 0; i < PERSIST_CHAIN_MAX; i++)
    {
        pid_t p = get_ppid(cur);
        if (p <= 1)
            break;
        read_comm(p, c->comm[i], sizeof(c->comm[i]));
        char *exe = proc_exe_path(p);
        if (exe)
        {
            /* Hash via /proc/<pid>/exe so containerised binaries
             * (Podman/Docker) are reachable even if their path doesn't
             * exist on the host.  Never open a protected path to hash it:
             * the daemon would intercept its own helper. */
            if (!is_path_under_protected(exe))
                cached_sha512_proc_exe(p, c->sha512[i],
                                       force_retry); /* best-effort */
            free(exe);
        }
        c->depth = i + 1;
        cur = p;
    }
}

/* ------------------------------------------------------------------ */
/*  runtime dynamic allowlist / denylist ("Always" decisions)         */
/* ------------------------------------------------------------------ */

#define DYN_MAX 256

typedef struct
{
    char rule_id[RULEID_HEX_LEN + 1];        /* stable stored ID (ruleid.h)     */
    char binary[PATH_MAX];
    char binary_sha512[129];
    char target_path[PATH_MAX];              /* exact file this entry applies to */
    char cmdline[PERSIST_CMDLINE_MAX];       /* raw command line (audit/display) */
    char cmdline_sha512[129];                /* command-line matching key        */
    char chain_comm[PERSIST_CHAIN_MAX][256];
    char chain_sha512[PERSIST_CHAIN_MAX][129];
    int chain_depth;
    time_t created_at;                       /* stamped once at creation         */
} DynEntry;

static DynEntry g_dyn_allow[DYN_MAX];
static int g_dyn_allow_count = 0;

static DynEntry g_dyn_deny[DYN_MAX];
static int g_dyn_deny_count = 0;

/*
 * State files the runtime lists are written to.  The defaults are the
 * shipped paths; fanotify_set_state_files() redirects them so the
 * unprivileged suites never touch /var/lib/fileshield.  They are read at
 * write time, so one redirect covers adds, migrations and mutations.
 */
static char g_dyn_state_file[PATH_MAX] = PERSIST_STATE_FILE;
static char g_dyn_deny_state_file[PATH_MAX] = PERSIST_DENY_STATE_FILE;

/*
 * One-list snapshot for the mutation APIs: a failed state write restores
 * the pre-mutation list exactly (pin.c keeps g_snapshot for the same
 * guarantee).  The daemon is single-threaded, so one shared buffer is
 * enough.
 */
static DynEntry g_dyn_snapshot[DYN_MAX];

/* ------------------------------------------------------------------ */
/*  Dialog rate limiting                                              */
/* ------------------------------------------------------------------ */
/*
 * A process can exec itself repeatedly (new PID each time) so that the
 * per-PID cache never helps, flooding the user with dialogs while each
 * open is suspended.  Two bounds, both fail closed (deny) for a cooldown
 * window once exceeded:
 *   - per binary path: DIALOG_RATE_PROMPTS prompts per window;
 *   - globally across all binaries: DIALOG_RATE_GLOBAL_PROMPTS, because
 *     a stream that rotates through distinct paths (`/tmp/.mount_AA/...`,
 *     `/tmp/.mount_AB/...`, ...) keeps landing in fresh per-binary
 *     entries and would otherwise never trip the per-binary bound.
 * When the 16-entry table is full, an idle entry (expired window, no
 * cooldown) is evicted first; only when every entry is live is the
 * oldest window evicted, so a rotation cannot cheaply reset a live
 * entry's quota.
 */
#define DIALOG_RATE_MAX 16
#define DIALOG_RATE_PROMPTS 20
#define DIALOG_RATE_GLOBAL_PROMPTS 40
#define DIALOG_RATE_WINDOW_S 60
#define DIALOG_RATE_COOLDOWN_S 30

typedef struct
{
    char binary[PATH_MAX];
    time_t window_start;
    int prompts;
    time_t blocked_until;
} DialogRateEntry;

static DialogRateEntry g_dialog_rate[DIALOG_RATE_MAX];
static int g_dialog_rate_count = 0;
static int g_dialog_global_prompts = 0;
static time_t g_dialog_global_window = 0;
static time_t g_dialog_global_blocked_until = 0;

/* Returns 1 when the dialog should be skipped (deny) to bound flooding. */
static int dialog_rate_limited(const char *binary)
{
    time_t now = mono_seconds();
    DialogRateEntry *e = NULL;

    /* Global state gates everything first: a flood rotating through
     * fresh binary paths never trips the per-binary budget below. */
    if (now < g_dialog_global_blocked_until)
        return 1;
    /* Start (or roll) the global window when the old one is over; the
     * initial 0 window start also lands here on the first prompt. */
    if (now - g_dialog_global_window > DIALOG_RATE_WINDOW_S)
    {
        g_dialog_global_window = now;
        g_dialog_global_prompts = 0;
    }

    for (int i = 0; i < g_dialog_rate_count; i++)
    {
        if (strcmp(g_dialog_rate[i].binary, binary) == 0)
        {
            e = &g_dialog_rate[i];
            break;
        }
    }

    if (!e)
    {
        /* New binary: take a free slot or evict one. */
        int slot;

        if (g_dialog_rate_count < DIALOG_RATE_MAX)
        {
            slot = g_dialog_rate_count++;
        }
        else
        {
            /* Prefer a fully idle slot (window expired and no active
             * cooldown); otherwise evict the oldest window so a live
             * entry's quota is the last thing reset. */
            int oldest_slot = 0;

            slot = -1;
            for (int i = 0; i < DIALOG_RATE_MAX; i++)
            {
                DialogRateEntry *c = &g_dialog_rate[i];
                if (now >= c->blocked_until &&
                    now - c->window_start > DIALOG_RATE_WINDOW_S)
                {
                    slot = i;
                    break;
                }
                if (c->window_start <
                    g_dialog_rate[oldest_slot].window_start)
                    oldest_slot = i;
            }
            if (slot < 0)
                slot = oldest_slot;
        }
        e = &g_dialog_rate[slot];
        memset(e, 0, sizeof(*e));
        snprintf(e->binary, sizeof(e->binary), "%s", binary);
        e->window_start = now;
    }

    /* An entry found for this binary may already be in cooldown. */
    if (now < e->blocked_until)
        return 1;

    /* Same window roll as the global counter. */
    if (now - e->window_start > DIALOG_RATE_WINDOW_S)
    {
        e->window_start = now;
        e->prompts = 0;
    }

    /* Over this binary's budget: block it.  The prompt is not shown, so
     * it must not consume global budget below either. */
    if (++e->prompts > DIALOG_RATE_PROMPTS)
    {
        e->blocked_until = now + DIALOG_RATE_COOLDOWN_S;
        /* A fresh window starts when the cooldown ends: without this the
         * still-old window immediately re-triggers the block and extends
         * the lockout toward twice the documented cooldown. */
        e->window_start = e->blocked_until;
        e->prompts = 0;
        log_msg(LOG_WARNING,
                "dialog rate limit: %s exceeded %d prompts in %ds; "
                "denying further prompts for %ds",
                binary, DIALOG_RATE_PROMPTS, DIALOG_RATE_WINDOW_S,
                DIALOG_RATE_COOLDOWN_S);
        return 1;
    }

    /* Only prompts the per-binary budget admitted are counted here. */
    if (++g_dialog_global_prompts > DIALOG_RATE_GLOBAL_PROMPTS)
    {
        /* Rotation through many distinct binaries: the per-binary bound
         * cannot trip, so the global budget does.  Same fresh-window
         * handling as above. */
        g_dialog_global_blocked_until = now + DIALOG_RATE_COOLDOWN_S;
        g_dialog_global_window = g_dialog_global_blocked_until;
        g_dialog_global_prompts = 0;
        log_msg(LOG_WARNING,
                "dialog rate limit: more than %d prompts across all "
                "binaries in %ds; denying further prompts for %ds",
                DIALOG_RATE_GLOBAL_PROMPTS, DIALOG_RATE_WINDOW_S,
                DIALOG_RATE_COOLDOWN_S);
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  shared persistence helpers for allowlist / denylist               */
/* ------------------------------------------------------------------ */

/* Copy DynEntry entries into a PersistEntry array.  Returns count. */
static int dyn_to_persist(const DynEntry *entries, int count,
                          PersistEntry *out, int max)
{
    int n = count < max ? count : max;
    memset(out, 0, sizeof(*out) * max);
    for (int i = 0; i < n; i++)
    {
        const DynEntry *src = &entries[i];
        PersistEntry *dst = &out[i];
        memcpy(dst->rule_id, src->rule_id, sizeof(src->rule_id));
        dst->rule_id[sizeof(dst->rule_id) - 1] = '\0';
        memcpy(dst->binary, src->binary, sizeof(src->binary));
        dst->binary[sizeof(dst->binary) - 1] = '\0';
        memcpy(dst->binary_sha512, src->binary_sha512, sizeof(src->binary_sha512));
        dst->binary_sha512[sizeof(dst->binary_sha512) - 1] = '\0';
        memcpy(dst->target_path, src->target_path, sizeof(src->target_path));
        dst->target_path[sizeof(dst->target_path) - 1] = '\0';
        memcpy(dst->cmdline, src->cmdline, sizeof(src->cmdline));
        dst->cmdline[sizeof(dst->cmdline) - 1] = '\0';
        memcpy(dst->cmdline_sha512, src->cmdline_sha512,
               sizeof(src->cmdline_sha512));
        dst->cmdline_sha512[sizeof(dst->cmdline_sha512) - 1] = '\0';
        dst->chain_depth = src->chain_depth;
        for (int j = 0; j < src->chain_depth; j++)
        {
            memcpy(dst->chain_comm[j], src->chain_comm[j], sizeof(src->chain_comm[j]));
            dst->chain_comm[j][sizeof(dst->chain_comm[j]) - 1] = '\0';
            memcpy(dst->chain_sha512[j], src->chain_sha512[j], sizeof(src->chain_sha512[j]));
            dst->chain_sha512[j][sizeof(dst->chain_sha512[j]) - 1] = '\0';
        }
        /* The real creation time travels with the entry: it is not
         * re-stamped by writes (that moved the ID's own input under the
         * entry and broke oldest-first ordering). */
        dst->created_at = src->created_at;
    }
    return n;
}

/* A live entry's rule ID must be exactly RULEID_HEX_LEN (16) lowercase
 * hex chars -- the format ruleid_make() emits and persist_load() admits.
 * Anything else is damaged state and must never be persisted. */
static int dyn_rule_id_valid(const char *id)
{
    if (!id || strlen(id) != RULEID_HEX_LEN)
        return 0;
    for (int i = 0; i < RULEID_HEX_LEN; i++)
    {
        if (!((id[i] >= '0' && id[i] <= '9') ||
              (id[i] >= 'a' && id[i] <= 'f')))
            return 0;
    }
    return 1;
}

/*
 * Validate a caller-supplied lookup ID without consulting a list, so an
 * invalid argument is -1 even when the list is empty and "not found" is
 * 0.  ruleid_prefix_match() validates both arguments (8..16 lowercase
 * hex); against a well-formed constant it returns -1 exactly when 'id'
 * is malformed, so only the sign is used here (same probe as pin.c).
 */
static int dyn_lookup_id_valid(const char *id)
{
    static const char probe[RULEID_HEX_LEN + 1] = "0000000000000000";

    return ruleid_prefix_match(probe, id) >= 0;
}

/*
 * Generate a rule ID for e from its identity, unique against the other
 * live entries of the same list (allow and deny are independent ID
 * namespaces).  count is the number of live entries to consider; e is
 * skipped when it already lies in list[0..count).  Returns 0 on success,
 * -1 when generation fails (e->rule_id is left untouched); callers must
 * then refuse the entry rather than persist an empty ID.
 */
static int dyn_assign_rule_id(const DynEntry *list, int count, DynEntry *e)
{
    const char *existing[DYN_MAX] = {0}; /* n 0 passes an empty list */
    RuleIdentity id;
    int depth = e->chain_depth;
    int n = 0;

    if (depth < 0)
        depth = 0;
    if (depth > PERSIST_CHAIN_MAX)
        depth = PERSIST_CHAIN_MAX;

    for (int i = 0; i < count; i++)
    {
        if (&list[i] == e || list[i].rule_id[0] == '\0')
            continue;
        existing[n++] = list[i].rule_id;
    }

    memset(&id, 0, sizeof(id));
    id.binary = e->binary;
    id.binary_sha512 = e->binary_sha512;
    id.target_path = e->target_path;
    id.cmdline_sha512 = e->cmdline_sha512;
    id.chain_depth = depth;
    for (int i = 0; i < depth; i++)
    {
        id.chain_comm[i] = e->chain_comm[i];
        id.chain_sha512[i] = e->chain_sha512[i];
    }
    id.created_at = (long)e->created_at;

    return ruleid_make_unique(&id, existing, n, e->rule_id);
}

/* Human-readable list name for logs, shared by every mutation. */
static const char *dyn_list_name(int deny)
{
    return deny ? "always-deny" : "always-allow";
}

/* State file the given side currently writes through. */
static const char *dyn_state_path(int deny)
{
    return deny ? g_dyn_deny_state_file : g_dyn_state_file;
}

/*
 * Copy the live list to PersistEntry and write it to the side's state
 * file.  rule_id and created_at are copied verbatim: created_at is real
 * creation time, stamped once by dyn_add(), and every live entry must
 * already have a generated ID.  Returns 0 on success, -1 when the state
 * file could not be written (the caller keeps or restores its in-memory
 * list).
 */
static int persist_dyn_list(int deny, const DynEntry *entries, int count)
{
    const char *name = dyn_list_name(deny);
    PersistEntry *buf = calloc(DYN_MAX, sizeof(PersistEntry));
    int n;

    if (!buf)
    {
        log_msg(LOG_ERR, "out of memory persisting %s", name);
        return -1;
    }

    n = dyn_to_persist(entries, count, buf, DYN_MAX);

    /* Never write an empty ID: persist_load() drops a present-but-empty
     * rule_id, so such a file would silently lose the entry on the next
     * load.  Every creation path assigns an ID; this only catches a
     * future caller that forgets. */
    for (int i = 0; i < n; i++)
    {
        if (!dyn_rule_id_valid(buf[i].rule_id))
        {
            log_msg(LOG_ERR,
                    "refusing to persist %s entry \"%s\": no usable rule ID",
                    name, buf[i].binary);
            free(buf);
            return -1;
        }
    }

    if (persist_save(dyn_state_path(deny), buf, n) < 0)
    {
        log_msg(LOG_WARNING, "persist_save failed; %s entries not persisted",
                name);
        free(buf);
        return -1;
    }
    free(buf);
    return 0;
}

/*
 * Remove the unique indices in removals from a DynEntry list in place,
 * preserving survivor order; the vacated tail is zeroed so a later
 * append cannot resurrect a removed entry.  Indices come from
 * prune_find() (whose flat list is not globally ascending when groups
 * interleave) or from one lookup result, and are never mutated here, so
 * membership is tested per entry instead of assuming an order.  Returns
 * the new count.
 */
static int dyn_compact(DynEntry *list, int count, const int *removals,
                       int removal_count)
{
    int kept = 0;

    for (int i = 0; i < count; i++)
    {
        int drop = 0;

        for (int t = 0; t < removal_count; t++)
        {
            if (removals[t] == i)
            {
                drop = 1;
                break;
            }
        }
        if (drop)
            continue;
        if (kept != i)
            list[kept] = list[i];
        kept++;
    }
    if (kept < count)
        memset(&list[kept], 0, sizeof(DynEntry) * (count - kept));
    return kept;
}

/* Copy one persisted row into a DynEntry; chain entries beyond the
 * (clamped) depth stay zeroed so a stale tail can never match. */
static void dyn_from_persist(const PersistEntry *src, DynEntry *dst)
{
    int depth = src->chain_depth;

    memset(dst, 0, sizeof(*dst));
    snprintf(dst->binary, sizeof(dst->binary), "%s", src->binary);
    snprintf(dst->binary_sha512, sizeof(dst->binary_sha512), "%s",
             src->binary_sha512);
    snprintf(dst->target_path, sizeof(dst->target_path), "%s",
             src->target_path);
    snprintf(dst->cmdline, sizeof(dst->cmdline), "%s", src->cmdline);
    snprintf(dst->cmdline_sha512, sizeof(dst->cmdline_sha512), "%s",
             src->cmdline_sha512);
    snprintf(dst->rule_id, sizeof(dst->rule_id), "%s", src->rule_id);
    dst->created_at = src->created_at;
    if (depth < 0)
        depth = 0;
    if (depth > PERSIST_CHAIN_MAX)
        depth = PERSIST_CHAIN_MAX;
    dst->chain_depth = depth;
    for (int j = 0; j < depth; j++)
    {
        snprintf(dst->chain_comm[j], sizeof(dst->chain_comm[j]), "%s",
                 src->chain_comm[j]);
        snprintf(dst->chain_sha512[j], sizeof(dst->chain_sha512[j]), "%s",
                 src->chain_sha512[j]);
    }
}

/*
 * Admission checks for one converted entry; returns 1 to admit, 0 to
 * drop (logged).  Each requirement guards against a different way an
 * incomplete state file could grant more than its author intended:
 *   - require_binary_sha512: a grant must prove which binary was
 *     approved, or it would act as a wildcard for that path.
 *   - require_target_path: file-scoped matching cannot honour a
 *     wildcard grant from an old or hand-edited state file.
 *   - require_cmdline: an entry that cannot pin the exact invocation
 *     would cover every command of that binary, and one that cannot
 *     show the invocation is not auditable.
 */
static int dyn_admits(const DynEntry *e, const char *name,
                      int require_binary_sha512, int require_target_path,
                      int require_cmdline)
{
    if (require_binary_sha512 && e->binary_sha512[0] == '\0')
    {
        log_msg(LOG_WARNING,
                "dropping %s entry \"%s\": no binary SHA-512 recorded "
                "(fail closed)",
                name, e->binary);
        return 0;
    }
    if (require_target_path && e->target_path[0] == '\0')
    {
        log_msg(LOG_WARNING,
                "dropping %s entry \"%s\": no target path recorded "
                "(fail closed)",
                name, e->binary);
        return 0;
    }
    if (require_cmdline &&
        (e->cmdline[0] == '\0' || e->cmdline_sha512[0] == '\0'))
    {
        log_msg(LOG_WARNING,
                "dropping %s entry \"%s\": incomplete command-line record "
                "(fail closed)",
                name, e->binary);
        return 0;
    }
    return 1;
}

/*
 * Load PersistEntry entries into a DynEntry array: convert, apply this
 * list's admission rules, migrate the rule ID, append.
 *
 * Each admitted entry keeps its stored rule_id and created_at.  A legacy
 * entry without an ID (or with a malformed one) gets an ID generated
 * from its identity, unique against the entries already admitted to this
 * list; the returned count of regenerated IDs lets the caller persist
 * the migration immediately.  An entry whose ID cannot be generated is
 * dropped (fail closed): persist_load() drops present-but-empty IDs, so
 * an unmigrated entry would silently vanish at the next load anyway.
 * Returns the number of regenerated IDs (>= 0).
 */
static int load_dyn_list(DynEntry *list, int *list_count,
                         const PersistEntry *entries, int count,
                         const char *name, int require_binary_sha512,
                         int require_target_path, int require_cmdline)
{
    int migrated = 0;
    int n = 0;

    /* Always replace the in-memory list so a removed state file or a
     * corrupt/unreadable one cannot leave stale grants or denies active
     * in the running daemon. */
    memset(list, 0, sizeof(DynEntry) * DYN_MAX);
    *list_count = 0;

    if (!entries || count <= 0)
    {
        log_msg(LOG_DEBUG, "cleared persisted %s entries", name);
        return 0;
    }
    if (count > DYN_MAX)
        count = DYN_MAX;

    for (int i = 0; i < count; i++)
    {
        DynEntry candidate;

        dyn_from_persist(&entries[i], &candidate);
        if (!dyn_admits(&candidate, name, require_binary_sha512,
                        require_target_path, require_cmdline))
            continue;

        if (candidate.rule_id[0] == '\0' ||
            !dyn_rule_id_valid(candidate.rule_id))
        {
            if (candidate.rule_id[0] != '\0')
                log_msg(LOG_WARNING,
                        "load %s: entry \"%s\" has a malformed rule ID; "
                        "regenerating it",
                        name, candidate.binary);
            if (dyn_assign_rule_id(list, n, &candidate) < 0)
            {
                log_msg(LOG_ERR,
                        "dropping %s entry \"%s\": rule ID could not be "
                        "generated (fail closed)",
                        name, candidate.binary);
                continue;
            }
            migrated++;
        }
        list[n++] = candidate;
    }
    *list_count = n;
    log_msg(LOG_INFO, "loaded %d persisted %s entries", n, name);
    return migrated;
}

/* ------------------------------------------------------------------ */
/*  runtime matching functions                                        */
/* ------------------------------------------------------------------ */

/*
 * Shared matcher for the runtime allow/deny lists.  Entries are scoped to
 * the exact file and the exact invocation that triggered the dialog:
 * approving a plugin's "kubectl config view" must not silently grant a
 * later "kubectl get secrets" from the same shell.
 *
 * Every recorded key must match; an unverifiable key never matches.  The
 * two lists differ in exactly one admission point, require_binary_sha:
 *   - allow (1): an entry without a binary SHA-512 is skipped -- a grant
 *     must prove which binary was approved or it would act as a wildcard.
 *     The return stays boolean: 1 match, 0 no match.
 *   - deny  (0): a legacy entry without a binary SHA-512 still matches; a
 *     stored digest with no usable current hash is INCONCLUSIVE (return
 *     -1), never a match and never a silent fall-through: the caller
 *     skips every grant stage and prompts instead (fail closed).
 * Returns 1 on a conclusive match, 0 on no match, -1 on an inconclusive
 * deny (impossible when require_binary_sha is 1, so the allow side is
 * always 0/1).  The command-line fingerprint is compared, not
 * recomputed: the caller produces it lazily so unrelated events never
 * pay for the hash.
 */
typedef const ProcChain *(*ChainProviderFn)(void *ctx);

/*
 * Command-line fingerprint provider, mirroring the chain provider: the
 * matchers request the digest only after every cheaper key (binary,
 * target, digest, call chain) has matched, so an event that cannot hit
 * a runtime entry never pays for the /proc read or the hash.  Providers
 * memoize per event.
 */
typedef const char *(*CmdlineProviderFn)(void *ctx);

static int dyn_match(const DynEntry *list, int count,
                     const char *binary, const char *bin_sha512,
                     ChainProviderFn chain_fn, void *chain_ctx,
                     const char *target,
                     CmdlineProviderFn cmdline_fn, void *cmdline_ctx,
                     int require_binary_sha)
{
    int inconclusive = 0;

    /* File-scoped matching: an event with no resolved target can never
     * match a persisted entry (admission always requires a target). */
    if (!target || target[0] == '\0')
        return 0;

    for (int i = 0; i < count; i++)
    {
        const DynEntry *e = &list[i];

        /* Cheap keys first: path equality before any hash comparison. */
        if (strcmp(e->binary, binary) != 0)
            continue;
        if (strcmp(e->target_path, target) != 0)
            continue;

        if (e->binary_sha512[0] == '\0')
        {
            if (require_binary_sha)
                continue;
        }
        else
        {
            /* A stored hash with no usable current hash cannot be
             * verified.  Grants skip the entry (no match); a deny marks
             * the outcome INCONCLUSIVE instead, so the pipeline skips
             * every grant stage and prompts (fail closed) rather than
             * granting past a denial it could not check.  Never set for
             * a hash failure alone: only for an entry whose path keys
             * already matched. */
            if (bin_sha512[0] == '\0')
            {
                if (!require_binary_sha)
                    inconclusive = 1;
                continue;
            }
            if (strcmp(e->binary_sha512, bin_sha512) != 0)
                continue;
        }

        /* Ancestor identity is the first key that needs the call chain:
         * build it only now, so an event whose binary/target/digest
         * matches no entry never pays for ancestor hashing.  The
         * provider memoizes, so the chain is built at most once. */
        const ProcChain *chain = chain_fn(chain_ctx);
        /* Depth must match exactly: a different ancestor count means a
         * different invocation context, so the recorded chain must not
         * prefix- or subset-match a deeper or shallower current chain. */
        if (e->chain_depth != chain->depth)
            continue;

        int ok = 1;
        for (int j = 0; j < chain->depth; j++)
        {
            if (strcmp(e->chain_comm[j], chain->comm[j]) != 0)
            {
                ok = 0;
                break;
            }
            /* Ancestor hashes are checked only when the entry recorded
             * one; a stored hash with no current hash fails the match. */
            if (e->chain_sha512[j][0] != '\0')
            {
                if (chain->sha512[j][0] == '\0')
                {
                    ok = 0;
                    break;
                }
                if (strcmp(e->chain_sha512[j], chain->sha512[j]) != 0)
                {
                    ok = 0;
                    break;
                }
            }
        }
        if (!ok)
            continue;

        /* Command line is the last key: fingerprint it only now, so an
         * event whose earlier keys match nothing never pays for the
         * /proc read or the hash (the provider memoizes per event).
         * An entry without a stored fingerprint can never match, and an
         * unavailable current fingerprint is re-prompted (fail closed). */
        if (e->cmdline_sha512[0] == '\0')
            continue;
        const char *cmdline_fp = cmdline_fn(cmdline_ctx);
        if (!cmdline_fp || cmdline_fp[0] == '\0')
            continue;
        if (strcmp(e->cmdline_sha512, cmdline_fp) != 0)
            continue;
        return 1;
    }
    /* A conclusive match always returns inside the loop, so a pending
     * inconclusive observation can only surface when nothing matched. */
    return inconclusive ? -1 : 0;
}

/* "Always Allow" lookup: grants are strict (see dyn_match). */
static int dyn_allow_match(const char *binary, const char *bin_sha512,
                           ChainProviderFn chain_fn, void *chain_ctx,
                           const char *target,
                           CmdlineProviderFn cmdline_fn, void *cmdline_ctx)
{
    return dyn_match(g_dyn_allow, g_dyn_allow_count, binary, bin_sha512,
                     chain_fn, chain_ctx, target, cmdline_fn, cmdline_ctx,
                     1);
}

/*
 * Append one runtime entry, dropping the oldest when the list is full.
 * Shared by the allow and deny sides; each caller keeps its own admission
 * policy (the allow side refuses entries it cannot pin to a binary).
 * created_at is stamped once here and the rule ID is generated against
 * the live entries of the same list.  Returns 0 on success; -1 when no
 * unique ID could be generated -- nothing is appended (an entry without
 * an ID must never be persisted: persist_load() would drop it).
 */
static int dyn_add(DynEntry *list, int *count, const char *binary,
                   const char *bin_sha512, const ProcChain *chain,
                   const char *target, const char *cmdline,
                   const char *cmdline_sha512, const char *name)
{
    DynEntry entry;
    int depth = chain->depth;
    int rc;

    if (depth < 0)
        depth = 0;
    if (depth > PERSIST_CHAIN_MAX)
        depth = PERSIST_CHAIN_MAX;

    memset(&entry, 0, sizeof(entry));
    snprintf(entry.binary, sizeof(entry.binary), "%s", binary);
    snprintf(entry.binary_sha512, sizeof(entry.binary_sha512), "%s",
             bin_sha512);
    if (target)
        snprintf(entry.target_path, sizeof(entry.target_path), "%s", target);
    snprintf(entry.cmdline, sizeof(entry.cmdline), "%s", cmdline);
    snprintf(entry.cmdline_sha512, sizeof(entry.cmdline_sha512), "%s",
             cmdline_sha512);
    entry.chain_depth = depth;
    for (int i = 0; i < depth; i++)
    {
        snprintf(entry.chain_comm[i], sizeof(entry.chain_comm[i]), "%s",
                 chain->comm[i]);
        snprintf(entry.chain_sha512[i], sizeof(entry.chain_sha512[i]), "%s",
                 chain->sha512[i]);
    }
    entry.created_at = time(NULL);

    /* Generate the ID before any eviction: a generation failure must
     * leave the live list (including its oldest entry) untouched. */
    rc = dyn_assign_rule_id(list, *count, &entry);
    if (rc < 0)
        return -1;

    if (*count >= DYN_MAX)
    {
        log_msg(LOG_WARNING, "dynamic %s full (%d); dropping oldest entry",
                name, DYN_MAX);
        memmove(&list[0], &list[1], sizeof(DynEntry) * (DYN_MAX - 1));
        *count = DYN_MAX - 1;
    }

    list[(*count)++] = entry;
    return 0;
}

/* First 16 hex chars of a digest for log lines; the state file has the
 * full hash.  An empty or short digest logs as "????????????????" — the
 * length check keeps a malformed digest from reading past its NUL. */
static void sha_prefix(const char *sha512, char out[17])
{
    memcpy(out, "????????????????", 17);
    if (strlen(sha512) >= 16)
        memcpy(out, sha512, 16);
    out[16] = '\0';
}

static void dyn_allow_add(const char *binary, const char *bin_sha512,
                          const ProcChain *chain, const char *target,
                          const char *cmdline, const char *cmdline_sha512)
{
    /* Fail closed at creation: a permanent grant is only recorded when the
     * binary's SHA-512 was actually computed.  Without it the entry would
     * match any binary at this path forever. */
    if (bin_sha512[0] == '\0')
    {
        log_msg(LOG_WARNING,
                "refusing permanent allow for %s: binary SHA-512 unavailable; "
                "granting one-time access only (re-prompt will occur)",
                binary);
        return;
    }

    /* Likewise the exact invocation must be pinned and recorded; without
     * it the entry would cover every command of that binary, and an entry
     * nobody can identify is not usable for review. */
    if (!cmdline || cmdline[0] == '\0' ||
        !cmdline_sha512 || cmdline_sha512[0] == '\0')
    {
        log_msg(LOG_WARNING,
                "refusing permanent allow for %s: command line could not be "
                "recorded and fingerprinted; granting one-time access only",
                binary);
        return;
    }

    if (dyn_add(g_dyn_allow, &g_dyn_allow_count, binary, bin_sha512, chain,
                target, cmdline, cmdline_sha512, "allowlist") < 0)
    {
        log_msg(LOG_WARNING,
                "refusing permanent allow for %s: rule ID could not be "
                "generated; granting one-time access only",
                binary);
        return;
    }

    char sha_short[17];
    sha_prefix(bin_sha512, sha_short);
    log_msg(LOG_INFO,
            "always-allow added: %s (sha512: %s...) chain-depth=%d -> %s",
            binary, sha_short, chain->depth, target ? target : "(unknown)");

    /* A failed write keeps the in-memory entry (the pre-existing
     * behavior); persist_dyn_list() already logged the failure. */
    (void)persist_dyn_list(0, g_dyn_allow, g_dyn_allow_count);
}

/*
 * "Always Deny" lookup: denials may be broader than grants (legacy
 * entries without a binary hash still apply).  Tri-state like dyn_match:
 * 1 conclusive match, 0 no match, -1 inconclusive (the entry's path keys
 * fit, it stores a digest, and the current hash is unavailable) -- the
 * caller then skips grants and prompts instead of denying on an
 * unverified identity or granting past the denial.
 */
static int dyn_deny_match(const char *binary, const char *bin_sha512,
                          ChainProviderFn chain_fn, void *chain_ctx,
                          const char *target,
                          CmdlineProviderFn cmdline_fn, void *cmdline_ctx)
{
    return dyn_match(g_dyn_deny, g_dyn_deny_count, binary, bin_sha512,
                     chain_fn, chain_ctx, target, cmdline_fn, cmdline_ctx,
                     0);
}

static void dyn_deny_add(const char *binary, const char *bin_sha512,
                         const ProcChain *chain, const char *target,
                         const char *cmdline, const char *cmdline_sha512)
{
    /* Without the exact invocation the entry could never match; refuse
     * to create a misleading permanent denial. */
    if (!cmdline || cmdline[0] == '\0' ||
        !cmdline_sha512 || cmdline_sha512[0] == '\0')
    {
        log_msg(LOG_WARNING,
                "refusing permanent deny for %s: command line could not be "
                "recorded and fingerprinted; denying this attempt only",
                binary);
        return;
    }

    if (dyn_add(g_dyn_deny, &g_dyn_deny_count, binary, bin_sha512, chain,
                target, cmdline, cmdline_sha512, "denylist") < 0)
    {
        log_msg(LOG_WARNING,
                "refusing permanent deny for %s: rule ID could not be "
                "generated; denying this attempt only",
                binary);
        return;
    }

    char sha_short[17];
    sha_prefix(bin_sha512, sha_short);
    log_msg(LOG_INFO,
            "always-deny added: %s (sha512: %s...) chain-depth=%d -> %s",
            binary, sha_short, chain->depth, target ? target : "(unknown)");

    /* A failed write keeps the in-memory entry (the pre-existing
     * behavior); persist_dyn_list() already logged the failure. */
    (void)persist_dyn_list(1, g_dyn_deny, g_dyn_deny_count);
}

/* ------------------------------------------------------------------ */
/*  Protected inode table  (hard-link bypass detection)               */
/* ------------------------------------------------------------------ */
/* The (dev, ino) set itself lives in inode.c (unit-tested and
 * benchmarked there); this file only feeds it and queries it. */

#define MAX_INODE_WALK_DEPTH 8 /* max recursion depth for protected-directory inode enumeration */

/* One FAN_MARK_MOUNT per unique init-namespace mount.  Mount marks must
 * be attached to the mount instances user processes open through, and a
 * mark placed in a private mount namespace never sees them (Phase 0 exp1,
 * MARK-SCOPE-REDESIGN.md).  The daemon therefore marks through pid 1's
 * namespace: "/proc/1/root" + path resolves the real mount even while the
 * daemon itself runs sandboxed (exp2/exp2p proved delivery).  Inode marks
 * need no prefix: inodes are shared across namespaces. */
#define NS_ROOT_PREFIX "/proc/1/root"
#define MAX_MOUNTS 32
typedef struct
{
    dev_t dev;
    unsigned long long mount_id; /* init-ns mount ID; 0 = unknown */
    char path[PATH_MAX];         /* init-ns path, used for mark removal */
} MountEntry;
static MountEntry g_mounts[MAX_MOUNTS];
static int g_mount_count = 0;

/* Build the init-namespace path used for mount-mark operations.  Returns
 * 0 on success, -1 when the result would not fit. */
static int mark_path_for(const char *path, char *out, size_t outsz)
{
    int n = snprintf(out, outsz, NS_ROOT_PREFIX "%s", path);

    if (n < 0 || (size_t)n >= outsz)
    {
        log_msg(LOG_ERR, "mark path too long: %s", path);
        return -1;
    }
    return 0;
}

/* Test seam (fanotify.h): when set, mount_id_of() reports "unavailable"
 * exactly like a kernel without statx(STATX_MNT_ID), so the device-level
 * fallbacks can be exercised on any kernel. */
static int g_test_mount_id_unavailable = 0;

/*
 * Mount ID of the mount containing 'path', resolved through the init
 * namespace.  Used to dedupe marks per mount instance (st_dev is not a
 * mount identity: btrfs subvolumes share one device).  Returns 0 when
 * statx(STATX_MNT_ID) is unavailable; callers fall back to device dedupe.
 */
static unsigned long long mount_id_of(const char *path)
{
    char ns_path[PATH_MAX];
    struct statx stx;

    if (g_test_mount_id_unavailable)
        return 0;
    if (mark_path_for(path, ns_path, sizeof(ns_path)) < 0)
        return 0;
    memset(&stx, 0, sizeof(stx));
    if (statx(AT_FDCWD, ns_path, 0, STATX_MNT_ID, &stx) != 0)
        return 0;
    /* Only trust stx_mnt_id when the kernel says it filled it in; a
     * success-without-data quirk would otherwise poison the mount
     * bookkeeping with garbage keys. */
    if (!(stx.stx_mask & STATX_MNT_ID))
        return 0;
    return stx.stx_mnt_id;
}

/* Test seams (fanotify.h): the path builder and mount-ID lookup used for
 * mount marks.  Unprivileged and side-effect free. */
int fanotify_test_mark_path(const char *path, char *out, size_t outsz)
{
    return mark_path_for(path, out, outsz);
}

unsigned long long fanotify_test_mount_id(const char *path)
{
    return mount_id_of(path);
}

/* Test seam (fanotify.h): force mount_id_of() to report unavailable. */
void fanotify_test_force_mount_id_unavailable(int on)
{
    g_test_mount_id_unavailable = on;
}

/* Recursively walk a directory and add inodes of regular files.
 * Stays on the same device (no cross-mount traversal).
 * Depth is capped at MAX_INODE_WALK_DEPTH to bound worst-case traversal time.
 * A non-NULL pattern records only files matching a glob protected entry;
 * exact entries pass NULL and record every file. */
static void inode_walk_dir(const char *dirpath, dev_t dev, int depth,
                           const char *pattern)
{
    if (depth > MAX_INODE_WALK_DEPTH)
        return;
    DIR *d = opendir(dirpath);
    if (!d)
    {
        log_msg(LOG_WARNING, "inode_walk_dir: cannot open %s: %s", dirpath,
                strerror(errno));
        return;
    }
    const struct dirent *ent;
    while ((ent = readdir(d)) != NULL)
    {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[PATH_MAX];
        if (snprintf(child, sizeof(child), "%s/%s", dirpath, ent->d_name) >= (int)sizeof(child))
            continue;
        struct stat st;
        if (lstat(child, &st) != 0)
            continue;
        if (st.st_dev != dev) /* skip bind mounts / nested filesystems */
            continue;
        if (S_ISREG(st.st_mode))
        {
            if ((pattern == NULL || glob_match_path(pattern, child)) &&
                exclusion_match(child) == NULL)
                inode_set_add(st.st_dev, st.st_ino);
        }
        else if (S_ISDIR(st.st_mode))
        {
            inode_walk_dir(child, dev, depth + 1, pattern);
        }
    }
    closedir(d);
}

/*
 * Shared entry matcher.  Exact entries use equal-or-under prefix
 * semantics; glob entries pass a cheap path_under_len() prefilter on
 * their canonical wildcard-free base before the full matcher, so a
 * non-matching mount-mark event costs one prefix compare.
 */
static int path_matches_entry(const ProtectedPath *pp, const char *path)
{
    if (!pp->is_glob)
        return path_under(path, pp->path);
    if (!path_under_len(path, pp->path, (size_t)pp->base_len))
        return 0;
    return glob_match_path(pp->path, path);
}

/*
 * First exclusion ('!') entry matching `path`, or NULL.  Gated on
 * exclude_count so configs without exclusions keep the exact same hot
 * path as before, and scans only the recorded exclusion indexes so the
 * cost scales with the number of carve-outs, not the protected list.
 */
static const ProtectedPath *exclusion_match(const char *path)
{
    if (!g_config || g_config->exclude_count == 0)
        return NULL;
    for (int i = 0; i < g_config->exclude_count; i++)
    {
        const ProtectedPath *pp = &g_config->protected[g_config->exclude_idx[i]];
        if (pp->is_exclude && path_matches_entry(pp, path))
            return pp;
    }
    return NULL;
}

/*
 * Returns 1 if `path` falls under any currently protected path and no
 * exclusion matches it.  Deny wins and config order does not matter: a
 * path is protected iff a positive matches and no '!' entry does.
 * Used to distinguish events from directory marks vs. mount marks
 * (hard-link).
 */
static int is_path_under_protected(const char *path)
{
    int matched = 0;

    if (!g_config)
        return 0;
    for (int i = 0; i < g_config->protected_count; i++)
    {
        const ProtectedPath *pp = &g_config->protected[i];
        if (!pp->is_exclude && path_matches_entry(pp, path))
        {
            matched = 1;
            break;
        }
    }
    if (!matched)
        return 0;

    const ProtectedPath *ex = exclusion_match(path);
    if (ex)
    {
        log_msg(LOG_DEBUG, "[event] allowed by exclusion !%s: %s",
                ex->path, path);
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/*  scope guard and dry run                                            */
/* ------------------------------------------------------------------ */
/*
 * Fail closed when the daemon's own config or state files could be
 * intercepted by the marks it is about to install:
 *
 *  - Containment: the file lies under a protected path, so an inode mark
 *    (inodes are shared across namespaces) would fire for the daemon's
 *    own open and deadlock it.  Always checked.
 *  - Mount: the file lies on a mount that will be mount-marked.  With the
 *    daemon in a private mount namespace its own opens traverse
 *    namespace-local mounts, which init-namespace marks cannot reach
 *    (Option B), so this is checked only when mounts are shared
 *    (unsandboxed runs and the Option A fallback).
 */
static int in_init_mount_ns(void)
{
    struct stat self_ns;
    struct stat init_ns;

    if (stat("/proc/self/ns/mnt", &self_ns) != 0 ||
        stat("/proc/1/ns/mnt", &init_ns) != 0)
        return 1; /* cannot tell: assume shared, apply the strict guard */
    return self_ns.st_ino == init_ns.st_ino &&
           self_ns.st_dev == init_ns.st_dev;
}

/*
 * Walk up to the nearest existing ancestor of path (the path itself is
 * presumed missing; the caller stats it first).  Returns 1 and fills
 * out — and *st_out when non-NULL — with an existing path; 0 when even
 * "/" does not resolve (out is "/" then).  Shared by the scope guard's
 * mount-ID lookup, the missing-path mount mark and the dry run.
 */
static int nearest_existing_ancestor(const char *path, char *out,
                                     size_t outsz, struct stat *st_out)
{
    struct stat st;

    snprintf(out, outsz, "%s", path);
    char *slash;
    while ((slash = strrchr(out, '/')) != NULL && slash != out)
    {
        *slash = '\0';
        if (stat(out, &st) == 0)
        {
            if (st_out)
                *st_out = st;
            return 1;
        }
    }
    /* The root is the last resort. */
    snprintf(out, outsz, "/");
    if (stat("/", &st) == 0)
    {
        if (st_out)
            *st_out = st;
        return 1;
    }
    return 0;
}

/* Init-namespace mount that would be marked for `path`: the mount of the
 * path itself when it exists, else the nearest existing ancestor (the
 * path a mount mark would actually be attached to).  0 when unknown.
 *
 * stat() must come first: nearest_existing_ancestor() presumes the path
 * is missing and starts by stripping the last component, so walking an
 * existing path would compare its parent's mount instead of the mount
 * that will actually be marked. */
static unsigned long long mark_target_mount_id(const char *path)
{
    char ancestor[PATH_MAX];
    struct stat st;

    if (stat(path, &st) == 0)
        return mount_id_of(path);
    if (!nearest_existing_ancestor(path, ancestor, sizeof(ancestor), &st))
        return 0;
    return mount_id_of(ancestor);
}

/* Scope guard, check 1: the daemon's own config or state directory must
 * not lie under a protected path, or an inode mark (shared across mount
 * namespaces) would intercept the daemon's own open and deadlock it. */
static int scope_guard_containment(const char *config_path)
{
    /* 1. Containment: inode marks reach every namespace. */
    if (config_path && config_path[0] &&
        is_path_under_protected(config_path))
    {
        log_msg(LOG_ERR,
                "scope guard: config %s is inside a protected path; the "
                "daemon would deadlock on its own open",
                config_path);
        return -1;
    }
    if (is_path_under_protected(PERSIST_STATE_DIR))
    {
        log_msg(LOG_ERR,
                "scope guard: state directory %s is inside a protected "
                "path; the daemon would deadlock on its own open",
                PERSIST_STATE_DIR);
        return -1;
    }
    return 0;
}

/*
 * Scope guard, check 2: the config or state file must not lie on a mount
 * that will be mount-marked.  Only possible when mounts are shared (a
 * private mount namespace cannot be reached by init-namespace marks), so
 * the check short-circuits there.  Without statx(STATX_MNT_ID) mount IDs
 * cannot be compared and the device-level fallback refuses a same-device
 * collision, matching the mount-mark bookkeeping's own dedupe fallback.
 */
static int scope_guard_mount_collision(const char *config_path)
{
    /* 2. Mount collision: only possible when mounts are shared. */
    if (!in_init_mount_ns())
    {
        log_msg(LOG_DEBUG,
                "scope guard: private mount namespace; mount marks cannot "
                "reach the daemon's own opens");
        return 0;
    }

    /* Mount IDs the daemon's own paths would be reached through; 0 =
     * unavailable (kernel without statx or a statx failure), in which
     * case the device fallback below takes over. */
    unsigned long long state_id = mark_target_mount_id(PERSIST_STATE_DIR);
    unsigned long long config_id =
        (config_path && config_path[0]) ? mark_target_mount_id(config_path) : 0;

    /*
     * Device-level fallback for kernels without statx(STATX_MNT_ID)
     * (pre-5.8) or a failed statx: mount IDs cannot be compared there,
     * but the mount-mark bookkeeping itself falls back to device-level
     * dedupe, so a state/config file on the same device as a protected
     * path may still be intercepted.  A refusal is the only fail-closed
     * outcome; proceeding unverified is the self-deadlock freeze class.
     */
    dev_t state_dev = 0;
    dev_t config_dev = 0;
    struct stat dst;

    /* Only the sides without a mount ID need a device value: a
     * mount-ID comparison is strictly stronger. */
    if (state_id == 0 && stat(PERSIST_STATE_DIR, &dst) == 0)
        state_dev = dst.st_dev;
    if (config_id == 0 && config_path && config_path[0] &&
        stat(config_path, &dst) == 0)
        config_dev = dst.st_dev;

    if (state_id == 0 && config_id == 0)
        log_msg(LOG_WARNING,
                "scope guard: mount IDs unavailable (statx); using "
                "device-level collision checks");

    for (int i = 0; i < g_config->protected_count; i++)
    {
        const ProtectedPath *pp = &g_config->protected[i];
        char base[PATH_MAX];
        const char *target = pp->path;
        unsigned long long id;

        /* Exclusions install no mark (fanotify_add_protected returns
         * early), so they cannot collide with the daemon's own opens. */
        if (pp->is_exclude)
            continue;
        /* A glob entry's mark is its wildcard-free base, so that is the
         * path a collision must be tested against. */
        if (pp->is_glob)
        {
            if (pp->base_len <= 0 || pp->base_len >= (int)sizeof(base))
                continue;
            memcpy(base, pp->path, (size_t)pp->base_len);
            base[pp->base_len] = '\0';
            target = base;
        }

        id = mark_target_mount_id(target);
        if (id == 0)
        {
            /* Mount IDs unavailable: compare devices.  An existing
             * target's own device is the one its mount mark would
             * intercept; a missing target would be covered by a mount
             * mark on its nearest existing ancestor. */
            char ancestor[PATH_MAX];
            struct stat pst;

            if (state_dev == 0 && config_dev == 0)
                continue; /* nothing to compare against */
            if (stat(target, &pst) != 0 &&
                !nearest_existing_ancestor(target, ancestor,
                                           sizeof(ancestor), &pst))
                continue;
            if (state_dev != 0 && pst.st_dev == state_dev)
            {
                log_msg(LOG_ERR,
                        "scope guard: statx mount IDs unavailable and state "
                        "directory %s shares device %lu with protected path "
                        "%s; the daemon could deadlock on its own open",
                        PERSIST_STATE_DIR, (unsigned long)pst.st_dev, target);
                return -1;
            }
            if (config_dev != 0 && pst.st_dev == config_dev)
            {
                log_msg(LOG_ERR,
                        "scope guard: statx mount IDs unavailable and config "
                        "%s shares device %lu with protected path %s; the "
                        "daemon could deadlock on its own open",
                        config_path, (unsigned long)pst.st_dev, target);
                return -1;
            }
            continue;
        }
        if (state_id != 0 && id == state_id)
        {
            log_msg(LOG_ERR,
                    "scope guard: state directory %s shares mount %llu "
                    "with protected path %s; the daemon would deadlock on "
                    "its own open",
                    PERSIST_STATE_DIR, id, target);
            return -1;
        }
        if (config_id != 0 && id == config_id)
        {
            log_msg(LOG_ERR,
                    "scope guard: config %s shares mount %llu with "
                    "protected path %s; the daemon would deadlock on its "
                    "own open",
                    config_path, id, target);
            return -1;
        }
    }
    return 0;
}

int fanotify_scope_guard(const char *config_path)
{
    if (!g_config)
        return -1;

    if (scope_guard_containment(config_path) < 0)
        return -1;
    return scope_guard_mount_collision(config_path);
}

/* Print the marks a config would install, without touching the kernel. */
void fanotify_dry_run(const Config *cfg)
{
    printf("fileshield dry run: %d entries (%d exclusions)\n",
           cfg->protected_count, cfg->exclude_count);

    for (int i = 0; i < cfg->protected_count; i++)
    {
        const ProtectedPath *pp = &cfg->protected[i];
        char base[PATH_MAX];
        char ns_path[PATH_MAX];
        const char *target = pp->path;
        struct stat st;

        if (pp->is_exclude)
        {
            printf("  exclusion  : %s\n", pp->path);
            continue;
        }
        if (pp->is_glob)
        {
            if (pp->base_len <= 0 || pp->base_len >= (int)sizeof(base))
            {
                printf("  invalid    : %s (glob base too long)\n", pp->path);
                continue;
            }
            memcpy(base, pp->path, (size_t)pp->base_len);
            base[pp->base_len] = '\0';
            target = base;
            printf("  glob base  : %s (pattern %s)\n", base, pp->path);
        }

        if (stat(target, &st) == 0)
        {
            printf("  inode mark : %s\n", target);
            if (mark_path_for(target, ns_path, sizeof(ns_path)) == 0)
            {
                unsigned long long id = mount_id_of(target);

                printf("  mount mark : %s -> %s (mount %llu)%s\n", target,
                       ns_path, id,
                       id == 0 ? " [mount ID unavailable; run as root to "
                                 "verify mount scope]"
                               : "");
            }
        }
        else
        {
            char ancestor[PATH_MAX];

            nearest_existing_ancestor(target, ancestor, sizeof(ancestor),
                                      NULL);
            printf("  mount mark : (missing %s) covered via %s\n", target,
                   ancestor);
        }
    }
}

/* ------------------------------------------------------------------ */
/*  mark bookkeeping                                                  */
/* ------------------------------------------------------------------ */
/*
 * fanotify_mark() removal needs the same event mask that was used to add
 * the mark (file and directory marks differ), so the mask is recorded per
 * path.  The table also tracks directory marks auto-added for directories
 * created inside protected trees, and lets a reload remove every mark the
 * daemon installed.
 */
#define MAX_MARK_TABLE 4096
#define MAX_AUTO_MARKS 1024

typedef struct
{
    char *path; /* strdup'd */
    unsigned int mask;
    int is_auto; /* created by auto_mark_created_path (counted against
                  * MAX_AUTO_MARKS); recomputed by clear_marks */
} MarkEntry;

static MarkEntry g_marks[MAX_MARK_TABLE];
static int g_mark_count = 0;
static int g_auto_mark_count = 0;

static MarkEntry *mark_find(const char *path)
{
    for (int i = 0; i < g_mark_count; i++)
        if (strcmp(g_marks[i].path, path) == 0)
            return &g_marks[i];
    return NULL;
}

/*
 * Track one installed mark so clear_marks() can remove it on reload.
 * Returns 0 when tracked/updated, -1 when it cannot be tracked (table
 * full or OOM).  A -1 is fatal for the installation: an untracked mark
 * would survive config reloads and could never be removed, so the caller
 * removes the kernel mark again and fails the load.
 */
static int mark_table_add(const char *path, unsigned int mask)
{
    MarkEntry *e = mark_find(path);
    if (e)
    {
        /* Re-adding the same path with a DIFFERENT mask would leave the
         * old kernel bits unremovable (clear_marks removes with the
         * recorded mask), so fail loudly instead of overwriting the
         * record.  Every current caller installs fanotify_mark_mask(),
         * making a mismatch a bug rather than a configuration. */
        if (e->mask != mask)
        {
            log_msg(LOG_ERR,
                    "mark table: %s re-added with a different mask "
                    "(0x%x != 0x%x); refusing the mark set",
                    path, mask, e->mask);
            return -1;
        }
        return 0;
    }
    if (g_mark_count >= MAX_MARK_TABLE)
    {
        log_msg(LOG_ERR,
                "mark table full (max %d); cannot track %s; refusing the "
                "mark set", MAX_MARK_TABLE, path);
        return -1;
    }
    char *copy = strdup(path);
    if (!copy)
    {
        log_msg(LOG_ERR, "out of memory tracking mark %s", path);
        return -1;
    }
    g_marks[g_mark_count].path = copy;
    g_marks[g_mark_count].mask = mask;
    g_marks[g_mark_count].is_auto = 0;
    g_mark_count++;
    return 0;
}

/*
 * Event mask used for file and directory marks.
 *
 * Directory-entry events (FAN_CREATE, FAN_DELETE, FAN_MOVED_FROM,
 * FAN_MOVED_TO, FAN_ATTRIB, FAN_DELETE_SELF) are deliberately absent:
 * they require a group initialized with FAN_REPORT_FID, and adding them
 * to this fd-based group makes fanotify_mark() fail with EINVAL
 * (fanotify_mark(2): "The group was initialized without FAN_REPORT_FID
 * but one or more event types specified in the mask require it").
 * Post-start files are therefore matched by canonical path; FID-based
 * create tracking is a planned follow-up.
 *
 * SAFETY-CRITICAL COUPLING with inode_walk_dir(): the mask deliberately
 * does NOT include FAN_ONDIR, so open()s of directory OBJECTS generate no
 * permission events.  The startup/reload walks opendir() directories
 * that already carry live marks — with FAN_ONDIR added, the very first
 * opendir() would enqueue a permission event only this single-threaded
 * daemon could answer, and it would deadlock inside the walk.  Anyone
 * adding FAN_ONDIR must first make the walks event-safe (defer or
 * pre-walk before marking).
 */
unsigned int fanotify_mark_mask(void)
{
    return FAN_OPEN_PERM | FAN_EVENT_ON_CHILD;
}

/* ------------------------------------------------------------------ */
/*  public API                                                         */
/* ------------------------------------------------------------------ */

/*
 * While a hash helper is blocked on a permission event this daemon has
 * not answered yet (the helper opens /proc/<pid>/exe, which can itself
 * be on a marked filesystem), the event loop is stuck inside the hash
 * wait.  sha512.c calls this hook once per silent wait slice so the
 * queue keeps being serviced: direct daemon children (the helper) and
 * mount-mark noise are allowed, protected events are deferred.
 */
static int g_hash_wait_fan_fd = -1;

/*
 * The dialog the current pump stack belongs to (0 = none).  fanotify_pump
 * publishes its dialog_child_pid for the duration of its own call; this
 * hook has no pid of its own, so without the handoff the nested pump runs
 * dialog-blind: the dialog's own protected-path opens (kdialog reads
 * ~/.config trees) would defer behind the very dialog they must not wait
 * for, freezing it until the 30 s timeout denies the decision — a
 * self-inflicted member of the freeze class the mark-scope rules guard.
 */
static pid_t g_active_dialog_pid = 0;

static void hash_wait_pump(void)
{
    if (g_hash_wait_fan_fd >= 0)
        fanotify_pump(g_hash_wait_fan_fd, g_active_dialog_pid);
}

int fanotify_setup(void)
{
    /*
     * FAN_UNLIMITED_QUEUE is required for fail-closed semantics.  With a
     * bounded queue, fsnotify_insert_event() reports "queue overflown",
     * fanotify_handle_event() drops the permission event and returns 0,
     * and the filesystem operation proceeds without a listener decision
     * (see fs/notify/fanotify/fanotify.c).  Only an event-allocation
     * failure denies.  Event volume is kept down by the mount-mark fast
     * path and the bounded pending queue; FAN_Q_OVERFLOW is still handled
     * fail-closed if it ever appears.
     *
     * FAN_NONBLOCK keeps the group fd non-blocking so the main loop can
     * poll() on {group fd, signal-wake pipe}: a signal arriving between
     * the flag check and a blocking read() would otherwise suspend the
     * daemon until the next open on an idle filesystem — and if the
     * supervisor then escalates to SIGKILL, close(fan_fd) auto-ALLOWs
     * every outstanding permission event.  The main loop treats the fd
     * as edge-gated: poll() first, then read().
     */
    int fd = fanotify_init(FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_CONTENT |
                               FAN_UNLIMITED_QUEUE,
                           O_RDONLY | O_LARGEFILE);
    if (fd < 0)
    {
        log_msg(LOG_ERR, "fanotify_init: %s", strerror(errno));
        return -1;
    }
    log_msg(LOG_INFO, "fanotify fd %d created", fd);
    g_hash_wait_fan_fd = fd;
    sha512_set_wait_hook(hash_wait_pump);
    return fd;
}

/* Add a FAN_MARK_MOUNT for the init-namespace mount containing st, if not
 * already tracked.  "path" may be any existing path on that mount; the
 * "/proc/1/root"-prefixed form is what reaches the kernel and what is
 * remembered for mark removal.  Dedupe is per mount instance (mount ID);
 * st_dev alone would merge distinct btrfs subvolume mounts. */
static void add_mount_mark_if_needed(int fd, const struct stat *st,
                                     const char *path)
{
    char ns_path[PATH_MAX];
    unsigned long long mnt_id = mount_id_of(path);

    if (mark_path_for(path, ns_path, sizeof(ns_path)) < 0)
        return;

    for (int i = 0; i < g_mount_count; i++)
    {
        if (mnt_id != 0)
        {
            if (g_mounts[i].mount_id == mnt_id)
                return;
        }
        else if (g_mounts[i].mount_id == 0 && g_mounts[i].dev == st->st_dev)
        {
            return; /* statx unavailable: fall back to device dedupe */
        }
    }

    if (mnt_id == 0)
    {
        /* AGENTS.md promises a warning on the device-level fallback: it
         * merges distinct btrfs subvolume mounts that share a device, so
         * subvolume-level mark bookkeeping degrades. */
        log_msg(LOG_WARNING,
                "statx(STATX_MNT_ID) unavailable; mount marks for dev %lu "
                "are deduped per device, not per mount",
                (unsigned long)st->st_dev);
    }

    if (g_mount_count >= MAX_MOUNTS)
    {
        log_msg(LOG_ERR,
                "mount table full (max %d); hard-link detection is "
                "incomplete for this filesystem",
                MAX_MOUNTS);
        return;
    }

    if (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                      FAN_OPEN_PERM, AT_FDCWD, ns_path) == 0)
    {
        g_mounts[g_mount_count].dev = st->st_dev;
        g_mounts[g_mount_count].mount_id = mnt_id;
        snprintf(g_mounts[g_mount_count].path,
                 sizeof(g_mounts[g_mount_count].path), "%s", ns_path);
        g_mount_count++;
        log_msg(LOG_INFO,
                "fanotify mount mark added for %s (dev %lu, mount %llu) "
                "for hard-link detection",
                path, (unsigned long)st->st_dev, mnt_id);
    }
    else
    {
        log_msg(LOG_ERR,
                "fanotify mount mark failed for %s (init-ns path %s): %s "
                "(hard-link detection disabled for this filesystem)",
                path, ns_path, strerror(errno));
    }
}

/*
 * A configured path that does not exist yet cannot be marked directly.
 * Walk up to the nearest existing ancestor and make sure its filesystem
 * carries a mount mark, so an open of the path after it is created is
 * still intercepted and matched by is_path_under_protected().
 */
static void ensure_mount_mark_for_missing(int fd, const char *path)
{
    char ancestor[PATH_MAX];
    struct stat st;

    if (nearest_existing_ancestor(path, ancestor, sizeof(ancestor), &st))
        add_mount_mark_if_needed(fd, &st, ancestor);
}

/*
 * fanotify_mark(ADD) plus mark-table tracking, removing the kernel mark
 * again when tracking fails: an untracked mark would survive config
 * reloads and could never be removed.  Returns 0 on success, -1 on
 * failure, with the log written.
 */
static int mark_add_tracked(int fd, const char *target, unsigned int mask)
{
    if (fanotify_mark(fd, FAN_MARK_ADD, mask, AT_FDCWD, target) < 0)
    {
        log_msg(LOG_ERR, "fanotify_mark ADD %s: %s", target, strerror(errno));
        return -1;
    }
    if (mark_table_add(target, mask) < 0)
    {
        /* The kernel mark was installed before tracking: remove it so a
         * refused load cannot leave a stale mark behind. */
        fanotify_mark(fd, FAN_MARK_REMOVE, mask, AT_FDCWD, target);
        return -1;
    }
    return 0;
}

/*
 * Record the (dev, ino) of an installed mark for hard-link detection.
 * An exact path records the object itself; a glob base records only
 * files the pattern matches (pattern == NULL records everything).
 * Directories are walked (bounded depth, same device).
 */
static void record_protected_inodes(const char *target, const struct stat *st,
                                    const char *pattern)
{
    if (S_ISREG(st->st_mode))
    {
        if ((pattern == NULL || glob_match_path(pattern, target)) &&
            exclusion_match(target) == NULL)
            inode_set_add(st->st_dev, st->st_ino);
    }
    else if (S_ISDIR(st->st_mode))
    {
        inode_walk_dir(target, st->st_dev, 0, pattern);
    }
}

int fanotify_add_mark(int fd, const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0)
    {
        if (errno == ENOENT)
        {
            /* Not an error: the secret file simply does not exist yet.
             * The mount mark keeps the path monitored once it appears. */
            ensure_mount_mark_for_missing(fd, path);
            log_msg(LOG_WARNING,
                    "protected path does not exist yet, skipping direct mark: %s",
                    path);
            return 1;
        }
        log_msg(LOG_ERR, "stat %s: %s", path, strerror(errno));
        return -1;
    }

    if (mark_add_tracked(fd, path, fanotify_mark_mask()) < 0)
        return -1;
    log_msg(LOG_INFO, "fanotify mark added: %s", path);

    record_protected_inodes(path, &st, NULL);

    add_mount_mark_if_needed(fd, &st, path);
    return 0;
}

/*
 * Add the mark for one configured [protected_paths] entry.
 *
 * Exact entries behave exactly like fanotify_add_mark().  A glob
 * pattern cannot be stat()ed or marked, so its canonical wildcard-free
 * base is marked instead and the pattern is enforced at match time by
 * is_path_under_protected().  A base that does not exist yet follows
 * the same contract as a missing exact path (mount mark up the tree,
 * return 1/skipped).  Hard-link inode tracking for a glob base records
 * only the files the pattern matches.  Exclusion entries mark nothing
 * and return 0.
 */
int fanotify_add_protected(int fd, const ProtectedPath *pp)
{
    if (pp->is_exclude)
        return 0; /* exclusions only subtract protection; nothing to mark */

    if (!pp->is_glob)
        return fanotify_add_mark(fd, pp->path);

    char base[PATH_MAX];
    if (pp->base_len <= 0 || pp->base_len >= (int)sizeof(base))
        return -1;
    memcpy(base, pp->path, (size_t)pp->base_len);
    base[pp->base_len] = '\0';

    struct stat st;
    if (stat(base, &st) != 0)
    {
        if (errno == ENOENT)
        {
            ensure_mount_mark_for_missing(fd, base);
            log_msg(LOG_WARNING,
                    "protected glob base does not exist yet, skipping "
                    "direct mark: %s (pattern %s)",
                    base, pp->path);
            return 1;
        }
        log_msg(LOG_ERR, "stat %s: %s", base, strerror(errno));
        return -1;
    }

    if (mark_add_tracked(fd, base, fanotify_mark_mask()) < 0)
        return -1;
    log_msg(LOG_INFO, "fanotify mark added: %s (glob base of %s)",
            base, pp->path);

    /* The pattern is anchored in the base directory; record only the
     * files it matches. */
    record_protected_inodes(base, &st, pp->path);

    add_mount_mark_if_needed(fd, &st, base);
    return 0;
}

/* Non-zero when at least one file/directory or mount mark is active. */
int fanotify_any_mark_active(void)
{
    return g_mark_count > 0 || g_mount_count > 0;
}

/*
 * Test seam: record a mark-table entry exactly like a real installation
 * (strdup'd, tracked for removal) without touching the kernel, so reload
 * tests can exercise the "rollback left no active marks" shutdown branch
 * with fan_fd = -1.  Returns 0 on success, -1 when the table is full.
 */
int fanotify_test_seed_mark(const char *path)
{
    return mark_table_add(path, fanotify_mark_mask());
}

/*
 * Newly created directories inside a protected tree need their own mark:
 * directory marks are not recursive, and this keeps path matching (and
 * hard-link inode tracking) effective for their contents.  Bounded by
 * MAX_AUTO_MARKS so a runaway create storm cannot exhaust marks.
 */
static void auto_mark_created_path(int fan_fd, const char *path)
{
    if (g_auto_mark_count >= MAX_AUTO_MARKS)
        return;
    if (mark_find(path))
        return;
    if (fanotify_add_mark(fan_fd, path) == 0)
    {
        /* Flag the tracked entry so clear_marks can recompute the
         * budget after a partial removal (a stale count would keep
         * throttling auto-marking forever). */
        MarkEntry *e = mark_find(path);
        if (e)
            e->is_auto = 1;
        g_auto_mark_count++;
        log_msg(LOG_INFO, "auto-marked created object: %s", path);
    }
}

/*
 * Notification events (FAN_CREATE / FAN_MOVED_TO) are not permission
 * events: no response is written, but the event fd must be closed and the
 * created object's inode is recorded so hard links to it stay protected.
 *
 * The current fd-based group cannot produce these events (they require
 * FAN_REPORT_FID and would make fanotify_mark() fail EINVAL); the branch
 * is kept so a future FID-enabled group still gets inode tracking.
 */
static void handle_notification_event(int fan_fd,
                                      const struct fanotify_event_metadata *ev)
{
    if (!(ev->mask & (FAN_CREATE | FAN_MOVED_TO)))
    {
        if (ev->fd != FAN_NOFD)
            close((int)ev->fd);
        return;
    }

    if (ev->fd == FAN_NOFD)
        return;

    struct stat st;
    if (fstat((int)ev->fd, &st) == 0)
    {
        inode_set_add(st.st_dev, st.st_ino);
        if (S_ISDIR(st.st_mode))
        {
            char created[PATH_MAX];
            if (resolve_fd_path((int)ev->fd, created, sizeof(created)) == 0)
                auto_mark_created_path(fan_fd, created);
        }
    }
    close((int)ev->fd);
}

/* ------------------------------------------------------------------ */
/*  Recent-decision deduplication cache                               */
/* ------------------------------------------------------------------ */
/*
 * When both a directory mark and a mount mark are active, the kernel fires
 * two separate FAN_OPEN_PERM events for the same file open (one per mark).
 * The cache records the decision for the most recent RECENT_CACHE_MAX
 * events so the second identical event is resolved instantly without
 * showing a second dialog.
 *
 * Entries expire after RECENT_CACHE_TTL_MS milliseconds.  The key is the
 * full decision identity — (pid, process start time, resolved binary,
 * dev, ino, resolved path) — so a hard link (different path), a recycled
 * PID (different start time) or an exec to another binary can never
 * inherit a decision the previous process image earned.  A config reload
 * clears the cache so a changed rule set is never replayed around.
 */
#define RECENT_CACHE_MAX 32
#define RECENT_CACHE_TTL_MS 2000

typedef struct
{
    pid_t pid;
    unsigned long long start; /* /proc/<pid>/stat start time (field 22) */
    dev_t dev;
    ino_t ino;
    char binary[PATH_MAX]; /* resolved /proc/<pid>/exe                   */
    char target[PATH_MAX]; /* resolved path: hard links share the inode */
    int fan_decision;      /* FAN_ALLOW or FAN_DENY */
    struct timespec ts;
} RecentDecision;

static RecentDecision g_recent[RECENT_CACHE_MAX];
static int g_recent_count = 0;
static unsigned int g_recent_head = 0; /* ring-buffer write head (wraps) */

static void recent_cache_insert(pid_t pid, unsigned long long start,
                                const char *binary, dev_t dev, ino_t ino,
                                const char *target, int decision)
{
    unsigned int slot;

    /* One entry per key: a newer decision must shadow an older one for the
     * same identity instead of living beside it in the ring. */
    for (int i = 0; i < g_recent_count; i++)
    {
        RecentDecision *e = &g_recent[i];
        if (e->pid == pid && e->start == start && e->dev == dev &&
            e->ino == ino && strcmp(e->binary, binary) == 0 &&
            strcmp(e->target, target) == 0)
        {
            e->fan_decision = decision;
            clock_gettime(CLOCK_MONOTONIC, &e->ts);
            return;
        }
    }

    slot = g_recent_head % RECENT_CACHE_MAX;
    g_recent[slot].pid = pid;
    g_recent[slot].start = start;
    g_recent[slot].dev = dev;
    g_recent[slot].ino = ino;
    snprintf(g_recent[slot].binary, sizeof(g_recent[slot].binary), "%s",
             binary);
    snprintf(g_recent[slot].target, sizeof(g_recent[slot].target), "%s",
             target);
    g_recent[slot].fan_decision = decision;
    clock_gettime(CLOCK_MONOTONIC, &g_recent[slot].ts);
    g_recent_head++; /* unsigned: wraps cleanly at 2^32 */
    if (g_recent_count < RECENT_CACHE_MAX)
        g_recent_count++;
}

/* Returns FAN_ALLOW, FAN_DENY, or -1 (not found / expired). */
static int recent_cache_lookup(pid_t pid, unsigned long long start,
                               const char *binary, dev_t dev, ino_t ino,
                               const char *target)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    for (int i = 0; i < g_recent_count; i++)
    {
        RecentDecision *e = &g_recent[i];
        if (e->pid != pid || e->start != start || e->dev != dev ||
            e->ino != ino || strcmp(e->binary, binary) != 0 ||
            strcmp(e->target, target) != 0)
            continue;
        /* Monotonic age in milliseconds: a wall-clock step cannot make
         * a decision expire early or live on. */
        long age_ms = (now.tv_sec - e->ts.tv_sec) * 1000L + (now.tv_nsec - e->ts.tv_nsec) / 1000000L;
        if (age_ms > RECENT_CACHE_TTL_MS)
            continue; /* expired: a newer entry for this key may follow */
        return e->fan_decision;
    }
    return -1;
}

/* Drop every cached decision (config reload: the rule set changed). */
static void recent_cache_clear(void)
{
    g_recent_count = 0;
    g_recent_head = 0;
}

/* Test seams (fanotify.h): the dedup cache, unprivileged and side-effect
 * free beyond the cache itself. */
void fanotify_test_recent_insert(pid_t pid, unsigned long long start,
                                 const char *binary, dev_t dev, ino_t ino,
                                 const char *target, int decision)
{
    recent_cache_insert(pid, start, binary, dev, ino, target, decision);
}

int fanotify_test_recent_lookup(pid_t pid, unsigned long long start,
                                const char *binary, dev_t dev, ino_t ino,
                                const char *target)
{
    return recent_cache_lookup(pid, start, binary, dev, ino, target);
}

void fanotify_test_recent_clear(void)
{
    recent_cache_clear();
}

/* ------------------------------------------------------------------ */
/*  deferred permission events                                        */
/* ------------------------------------------------------------------ */
/*
 * fanotify_pump() runs while a dialog is displayed.  It may read events it
 * cannot decide (protected paths); those are copied here with their event
 * fd left open and replayed by the main loop once the dialog is finished.
 * Closing the event fd without a response would leave the caller's open()
 * blocked forever and leak a kernel permission event.
 */
#define PENDING_MAX 256

typedef struct
{
    struct fanotify_event_metadata meta;
} PendingEvent;

static PendingEvent g_pending[PENDING_MAX];
static int g_pending_count = 0;

/*
 * Queue a read-but-undecided permission event for replay by the main
 * loop.  The kernel event fd must stay open: the kernel keeps the
 * permission event pending until a response is written, so closing it
 * here would block the caller's open() forever and leak the event.
 * Returns 0 when queued, -1 when the pending queue is full — the caller
 * must then respond fail-closed (FAN_DENY) and close the event fd.
 */
int fanotify_defer_event(const struct fanotify_event_metadata *ev)
{
    if (g_pending_count >= PENDING_MAX)
        return -1;
    g_pending[g_pending_count].meta = *ev;
    g_pending_count++;
    return 0;
}

/* Real uid of the requesting process, or (uid_t)-1 when unknown. */
static uid_t proc_uid(pid_t pid)
{
    char path[64], line[256];
    FILE *f;
    unsigned int uid = 0;
    int found = 0;

    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    f = fopen(path, "r");
    if (!f)
        return (uid_t)-1;
    while (fgets(line, sizeof(line), f))
    {
        if (sscanf(line, "Uid:\t%u", &uid) == 1)
        {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found ? (uid_t)uid : (uid_t)-1;
}

/*
 * Returns 1 if pid is the dialog child, a direct child of it (timeout(1)
 * execs kdialog), or in the dialog's process group (the dialog child calls
 * setpgid(0,0) before exec).
 */
static int process_in_dialog_group(pid_t pid, pid_t dialog_pid)
{
    if (dialog_pid <= 0)
        return 0;
    if (pid == dialog_pid)
        return 1;
    if (get_ppid(pid) == dialog_pid)
        return 1;

    char path[64], buf[512];
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    if (!fgets(buf, sizeof(buf), f))
    {
        fclose(f);
        return 0;
    }
    fclose(f);

    const char *p = strrchr(buf, ')');
    if (!p)
        return 0;
    p++;
    /* After the ')' come state (char), ppid (int), pgrp (int); parse
     * past the first two to read the process group. */
    long pgrp = 0;
    if (sscanf(p, " %*c %*d %ld", &pgrp) != 1)
        return 0;
    return (pid_t)pgrp == dialog_pid;
}

/* ------------------------------------------------------------------ */
/*  per-event decision context                                         */
/* ------------------------------------------------------------------ */
/*
 * Everything the decision stages need for one FAN_OPEN_PERM event.
 * Identity fields are gathered once while the requesting process is
 * kernel-suspended (its /proc entry cannot change under us), then
 * threaded through the stages in fixed decision order.
 */
typedef struct
{
    int fan_fd;
    const struct fanotify_event_metadata *ev;
    int fd_num;
    int close_fd; /* 0 only for FAN_NOFD: there is no descriptor to close */

    /* Set when the decision response could not be written and was queued
     * for retry: the event fd must stay open (a closed fd cannot be
     * answered, and the kernel would auto-allow the event on group
     * close), so the out path skips the close. */
    int keep_event_fd;

    char *binary;          /* /proc/<pid>/exe, malloc'd (freed at out) */
    char target[PATH_MAX]; /* /proc/self/fd/<fd> resolved path         */
    dev_t ev_dev;
    ino_t ev_ino;
    int have_ev_stat;      /* 1 = ev_dev/ev_ino valid (fstat succeeded) */

    /* Cached prefix verdict: the target path needs it in the fast path,
     * the hard-link classification and the prompt policy, and the
     * protected set can hold hundreds of entries. */
    int path_protected;

    /* Set when a protected inode is opened through a path outside every
     * protected prefix (hard link / unverifiable path): grants are then
     * skipped and the user is prompted for this exact path. */
    int hardlink_event;

    /* Defer mode (events read while another dialog is open): the whole
     * verdict chain runs, but the ask stage defers instead of showing a
     * second dialog — the caller queues the event with its fd open. */
    int defer_on_ask;

    /* Set by event_runtime_denied() when a deny entry's path keys match
     * but its stored digest cannot be checked against an unavailable
     * current hash (INCONCLUSIVE): event_runtime_allowed() then skips
     * every grant stage, so the event reaches the dialog (fail closed)
     * instead of being granted by a hash-free stage such as the file
     * cache or [unsafe_allowlist]. */
    int deny_inconclusive;

    /* Requester identity, gathered after the pre-hash deny checks. */
    pid_t ppid;
    char comm[256];
    char pcomm[256];
    char cmdline[512];        /* display form (NUL-collapsed, bounded)     */
    char bin_sha512[129];
    char bin_hash_failure[80]; /* reason bin_sha512 is empty (prompt text) */
    int binary_protected;     /* binary under a protected prefix          */
    char cmdline_sha512[129]; /* full raw cmdline, computed lazily          */
    int cmdline_sha_state;    /* 0 = not computed, 1 = computed, -1 = failed */
    ProcChain chain;
    int chain_built;          /* 1 = chain captured (event_build_chain)    */
    pid_t sid;
    unsigned long long sid_start;
    int have_sid;

    /* Process instance identity for the dedup cache: /proc/<pid>/stat
     * start time, captured by event_dedup() while the process is still
     * suspended. */
    unsigned long long pid_start;
    int have_pid_start;
} EventCtx;

/*
 * Desktop tripwire for one config-rule hit ([allowlist], [unsafe_allowlist]
 * or [denylist]).  Purely advisory: it is rate-limited under the
 * configurable notification window, a missing desktop or notify-send drops
 * it, and it never changes the decision.  comm may be NULL (stage 3 has not
 * read it yet), in which case it is read here.
 */
static void config_rule_notify(EventCtx *c, const RuleEntry *e, int kind,
                               const char *comm)
{
    char comm_buf[256];

    if (!g_config || !e)
        return;

    int enabled;
    switch (kind)
    {
    case NOTIFY_HIT_UNSAFE:
        enabled = g_config->notify_unsafe_allow;
        break;
    case NOTIFY_HIT_DENY:
        enabled = g_config->notify_deny;
        break;
    default:
        enabled = g_config->notify_allow;
        break;
    }
    if (!enabled)
        return;

    if (!comm)
    {
        memset(comm_buf, 0, sizeof(comm_buf));
        read_comm(c->ev->pid, comm_buf, sizeof(comm_buf));
        comm = comm_buf;
    }

    NotifyHit hit;
    memset(&hit, 0, sizeof(hit));
    hit.uid = proc_uid(c->ev->pid);
    hit.kind = kind;
    hit.rule = e->binary;
    hit.binary = c->binary;
    hit.pid = c->ev->pid;
    hit.comm = comm;
    hit.target = c->target;
    hit.dedup_seconds = g_config->notify_dedup_seconds;
    hit.max_per_window = g_config->notify_max;
    notify_rule_hit(&hit);
}

/*
 * Unsafe-rule hits surface once per process: the first hit logs at
 * WARNING and notifies, later hits from the same process log at INFO
 * without notifying.  Another process running the same rule is a new
 * instance and surfaces again.  Keyed by (pid, start time) so PID reuse
 * is a new process; the bounded round-robin table may evict a very old
 * entry, which only re-surfaces a hit (extra visibility, never silence).
 */
#define UNSAFE_SEEN_MAX 256

typedef struct
{
    pid_t pid;
    unsigned long long start; /* /proc/<pid>/stat field 22; 0 = unknown */
} UnsafeSeenEntry;

static UnsafeSeenEntry g_unsafe_seen[UNSAFE_SEEN_MAX];
static int g_unsafe_seen_count = 0;
static int g_unsafe_seen_next = 0;

static int unsafe_first_hit(pid_t pid)
{
    unsigned long long start = 0;
    (void)proc_stat_session(pid, NULL, &start); /* failure leaves 0 */

    /* A failed /proc read leaves start 0, so the key is then (pid, 0):
     * it still de-duplicates this process while its stat stays
     * unreadable, and a different instance gets a different start. */
    for (int i = 0; i < g_unsafe_seen_count; i++)
    {
        if (g_unsafe_seen[i].pid == pid && g_unsafe_seen[i].start == start)
            return 0;
    }

    int slot;
    if (g_unsafe_seen_count < UNSAFE_SEEN_MAX)
        slot = g_unsafe_seen_count++;
    else
    {
        slot = g_unsafe_seen_next;
        g_unsafe_seen_next = (g_unsafe_seen_next + 1) % UNSAFE_SEEN_MAX;
    }
    g_unsafe_seen[slot].pid = pid;
    g_unsafe_seen[slot].start = start;
    return 1;
}

/*
 * Capture the requester's ancestor chain on demand.  The chain is only
 * consumed by the runtime "Always" matchers and recorders: matchers ask
 * for it through event_chain_provider() after an entry has passed every
 * cheap key, so an event that matches no entry (or is granted by the
 * config lists) never pays for ancestor hashing.  force_retry makes the
 * prompt boundary re-attempt ancestors that are inside a negative
 * failure window, so a recorded entry still gets the best available
 * chain; it must be called before the dialog so the permanent key
 * reflects the event, not the state after the user decided.
 */
static void event_build_chain(EventCtx *c, int force_retry)
{
    if (c->chain_built && !force_retry)
        return;
    build_proc_chain(c->ev->pid, &c->chain, force_retry);
    c->chain_built = 1;
}

/* Matcher-side chain provider: builds without bypassing failure windows. */
static const ProcChain *event_chain_provider(void *ctx)
{
    EventCtx *c = ctx;
    event_build_chain(c, 0);
    return &c->chain;
}

/*
 * Lazily fingerprint the requester's full command line.  Only the runtime
 * matchers and permanent-decision recording call it, so cache/session
 * hits never pay for the /proc read or the hash.  Returns the digest, or
 * "" when it cannot be computed (callers fail closed).  The requesting
 * process is kernel-suspended for the whole event, so its /proc entry
 * stays valid between this read and the decision.
 */
static const char *event_cmdline_fp(EventCtx *c)
{
    if (c->cmdline_sha_state == 0)
    {
        if (read_cmdline_fingerprint(c->ev->pid, c->cmdline_sha512) < 0)
        {
            c->cmdline_sha512[0] = '\0';
            c->cmdline_sha_state = -1;
        }
        else
            c->cmdline_sha_state = 1;
    }
    return c->cmdline_sha512;
}

/* Provider wrapper: lets dyn_match request the fingerprint lazily (the
 * computation itself memoizes on the event context). */
static const char *event_cmdline_provider(void *ctx)
{
    return event_cmdline_fp((EventCtx *)ctx);
}

/*
 * Deliver one decision through fanotify_respond() and note when the
 * response was queued for retry, so process_open_perm() leaves the event
 * fd open for the retry to answer.
 */
static void respond_event(EventCtx *c, unsigned int response)
{
    if (fanotify_respond(c->fan_fd, c->ev, response) == -1)
        c->keep_event_fd = 1;
}

/*
 * Every deciding stage funnels through here so the dedup-cache insert
 * and the kernel response always happen together, in that order.
 */
static void ctx_respond(EventCtx *c, unsigned int response)
{
    /* Complete identity only: an event whose start time or inode could
     * not be captured is never cached, so a duplicate runs the pipeline
     * again (fail closed) instead of inheriting a decision. */
    if (c->binary && c->have_pid_start && c->have_ev_stat)
        recent_cache_insert(c->ev->pid, c->pid_start, c->binary, c->ev_dev,
                            c->ev_ino, c->target, (int)response);
    respond_event(c, response);
}

/*
 * Stage 1: sanity-check the event fd and resolve the target path from
 * the daemon's fd table.  Returns 1 when the event was decided here
 * (FAN_NOFD — skipped without a response, the kernel already denied it —
 * or an unresolvable path, which denies fail closed).
 */
static int event_resolve(EventCtx *c)
{
    if (c->fd_num == FAN_NOFD)
    {
        /* No event fd exists: the kernel already auto-DENIED this
         * permission event when its fd creation failed (fanotify_read:
         * copy_event_to_user failure -> finish_permission_event(FAN_DENY)),
         * so FAN_OPEN_PERM+FAN_NOFD is unreachable for this fd-based
         * group — pure defense.  Responding with fd=-1 would earn EINVAL,
         * set g_fatal and queue a phantom retry that can never be
         * delivered: log and skip as handled. */
        log_msg(LOG_WARNING,
                "[event] FAN_NOFD for pid=%d; kernel already denied, "
                "skipping respond",
                (int)c->ev->pid);
        return 1;
    }

    if (resolve_fd_path(c->fd_num, c->target, sizeof(c->target)) < 0)
    {
        log_msg(LOG_WARNING,
                "[event] resolve_fd_path failed for pid=%d fd=%d, denying",
                (int)c->ev->pid, c->fd_num);
        respond_event(c, FAN_DENY);
        return 1;
    }
    /* Compute the protected-prefix verdict once; three later stages use it. */
    c->path_protected = is_path_under_protected(c->target);
    log_msg(LOG_DEBUG, "[event] resolved target: pid=%d target=%s",
            (int)c->ev->pid, c->target);
    return 0;
}

/*
 * Shared mount-mark-noise predicate: the inode is untracked and the path is
 * not protected.  event_fastpath() supplies the cached path verdict plus the
 * runtime guards (mount marks installed, fstat succeeded); the test seam and
 * benchmark call this directly.
 */
static int mount_noise_allows(dev_t dev, ino_t ino, int path_protected)
{
    return !inode_set_contains(dev, ino) && !path_protected;
}

/*
 * Stage 2: cheap pre-identity checks.
 *   - Mount-mark fast path: neither the inode nor the path is protected,
 *     so the event is mount-mark noise and is allowed instantly.
 *   - Deduplication: directory + mount marks can fire twice for one
 *     open; the recent-decision cache answers the duplicate instantly.
 */
static int event_fastpath(EventCtx *c)
{
    /* One fstat serves both checks below: mount-mark noise classification
     * and the dedup-cache key. */
    struct stat st;
    int have_st = (fstat(c->fd_num, &st) == 0);

    if (g_mount_count > 0 && have_st &&
        mount_noise_allows(st.st_dev, st.st_ino, c->path_protected))
    {
        log_msg(LOG_DEBUG, "[fast-path] ALLOW pid=%d target=%s (mount-mark noise)",
                (int)c->ev->pid, c->target);
        respond_event(c, FAN_ALLOW);
        return 1;
    }

    if (have_st)
    {
        c->ev_dev = st.st_dev;
        c->ev_ino = st.st_ino;
        c->have_ev_stat = 1;
    }
    return 0;
}

/*
 * Stage 3: requester identity that needs no hashing, plus the config
 * denylist.  Returns 1 when the event was decided (unresolvable binary
 * or a config denylist hit — both deny, fail closed).
 */
static int event_load_binary(EventCtx *c)
{
    c->binary = proc_exe_path(c->ev->pid);
    if (!c->binary)
    {
        respond_event(c, FAN_DENY);
        return 1;
    }

    /* Hard-link bypass attempt: a path outside every protected prefix
     * means the event came from the mount mark rather than a directory
     * mark.  Flag it so the grant stages skip every rule and the user is
     * asked about this exact path; denies below and in the caller still
     * win, so this only removes silently-inherited grants. */
    if (!c->path_protected)
    {
        c->hardlink_event = 1;
        log_msg(LOG_WARNING,
                "hard-link bypass attempt: %s (pid %d) opened "
                "protected inode via unprotected path \"%s\"",
                c->binary, (int)c->ev->pid, c->target);
    }

    /* Config denylist: a static admin denial always wins over every
     * grant.  Checked before hashing so denied binaries never pay for
     * binary/ancestor SHA-512 computation.  Matching is against the
     * resolved open path: a hard-link event (protected inode reached
     * through an unprotected alias) therefore only matches GLOBAL deny
     * rules — a scoped rule like "binary = /protected/path" cannot know
     * which protected path the inode belongs to, so such an attempt
     * falls through to the always-prompt hard-link path instead of
     * EPERM.  Every grant stage is skipped for it (fail closed). */
    const RuleEntry *deny_rule = denylist_match(c->binary, c->target);
    if (deny_rule)
    {
        log_msg(LOG_INFO, "config denylist hit: %s (pid %d) -> %s",
                c->binary, (int)c->ev->pid, c->target);
        /* Stage 4 has not read comm yet; the notify helper reads it. */
        config_rule_notify(c, deny_rule, NOTIFY_HIT_DENY, NULL);
        ctx_respond(c, FAN_DENY);
        return 1;
    }
    return 0;
}

/*
 * Duplicate-event reuse (runs after the binary is resolved, before the
 * identity gathering).  Now that the full decision identity is
 * available: a directory mark and a mount mark
 * can fire twice for one open, and the second event reuses the first
 * decision.  The key carries the process instance (pid + /proc/<pid>/stat
 * start time) and the resolved binary in addition to (dev, ino, path);
 * the file cache rejects PID reuse the same way, and an exec must not
 * inherit a decision the previous image earned.  A missing start time or
 * inode skips the cache so the pipeline runs again (fail closed).
 * Returns 1 when the event was decided here.
 */
static int event_dedup(EventCtx *c)
{
    unsigned long long start = 0;
    int cached;

    if (!c->have_ev_stat)
        return 0;
    if (proc_stat_session(c->ev->pid, NULL, &start) != 0)
        return 0; /* cannot bind the decision to a process instance */
    c->pid_start = start;
    c->have_pid_start = 1;

    cached = recent_cache_lookup(c->ev->pid, c->pid_start, c->binary,
                                 c->ev_dev, c->ev_ino, c->target);
    if (cached == -1)
        return 0;

    log_msg(LOG_DEBUG,
            "[dedup] reusing cached decision=%s for pid=%d binary=%s target=%s",
            cached == (int)FAN_ALLOW ? "ALLOW" : "DENY", (int)c->ev->pid,
            c->binary, c->target);
    respond_event(c, (unsigned int)cached);
    return 1;
}

/*
 * Stage 4: gather everything the session/runtime checks match on.
 * Hashing and chain building happen while the target process is
 * kernel-suspended so its /proc entry is still valid.  Hashing a path
 * that is itself protected would make the daemon intercept its own
 * helper, so it is skipped and the path+chain decision stands alone.
 */
static void event_gather_identity(EventCtx *c)
{
    pid_t pid = c->ev->pid;

    read_comm(pid, c->comm, sizeof(c->comm));
    c->ppid = get_ppid(pid);
    if (c->ppid > 0)
        read_comm(c->ppid, c->pcomm, sizeof(c->pcomm));
    read_cmdline(pid, c->cmdline, sizeof(c->cmdline));

    /*
     * Requester digest, best effort.  The failure reason is captured now
     * (the sha512 accessor is overwritten by later hashing) so a prompt
     * can explain why "Allow Always" cannot persist.  A binary under a
     * protected path is deliberately never hashed: opening it with the
     * daemon's own helper would be self-interception.
     */
    c->binary_protected = is_path_under_protected(c->binary);
    if (!c->binary_protected)
    {
        if (cached_sha512_proc_exe(pid, c->bin_sha512, 0) < 0)
        {
            snprintf(c->bin_hash_failure, sizeof(c->bin_hash_failure), "%s",
                     g_hash_failure_reason[0] ? g_hash_failure_reason
                                              : "hashing failed");
            log_msg(LOG_DEBUG, "SHA-512 unavailable for %s (pid %d): %s",
                    c->binary, (int)pid, c->bin_hash_failure);
        }
    }
    else
    {
        snprintf(c->bin_hash_failure, sizeof(c->bin_hash_failure),
                 "the binary is under a protected path");
    }

    /* The ancestor chain is captured lazily: by the dynamic matchers only
     * once an entry passes its cheap keys, and at the prompt boundary
     * before any dialog, so silent grants never hash ancestors at all. */

    /* Session identity, best effort.  Without it session-scoped decisions
     * cannot be matched or recorded (they degrade to one-time decisions). */
    c->have_sid = session_id_of(pid, &c->sid, &c->sid_start) == 0;
    if (!c->have_sid)
        log_msg(LOG_WARNING,
                "cannot determine session for pid=%d; session decisions "
                "unavailable for %s",
                (int)pid, c->binary);
}

/*
 * Stage 5: denials that require the binary/call-chain hashes, in order:
 * session denylist (runtime "Deny Session"), then dynamic denylist
 * (runtime "Deny Always").  Returns 1 when the event was denied.
 */
/* Test seam (fanotify.h): the per-binary dialog rate limiter. */
int fanotify_test_dialog_rate_limited(const char *binary)
{
    return dialog_rate_limited(binary);
}

/* Test seam (fanotify.h): clear the per-binary and global rate state so
 * limit tests are deterministic regardless of test order. */
void fanotify_test_reset_dialog_rate(void)
{
    memset(g_dialog_rate, 0, sizeof(g_dialog_rate));
    g_dialog_rate_count = 0;
    g_dialog_global_prompts = 0;
    g_dialog_global_window = 0;
    g_dialog_global_blocked_until = 0;
}

static int event_runtime_denied(EventCtx *c)
{
    if (c->have_sid)
    {
        int m = session_deny_match(c->sid, c->binary, c->bin_sha512,
                                   c->target);

        if (m == 1)
        {
            log_msg(LOG_INFO, "session denylist hit: %s (pid %d, sid %d) -> %s",
                    c->binary, (int)c->ev->pid, (int)c->sid, c->target);
            ctx_respond(c, FAN_DENY);
            return 1;
        }
        if (m < 0)
            c->deny_inconclusive = 1;
    }

    if (g_dyn_deny_count > 0)
    {
        int m = dyn_deny_match(c->binary, c->bin_sha512, event_chain_provider,
                               c, c->target, event_cmdline_provider, c);

        if (m == 1)
        {
            log_msg(LOG_INFO, "dynamic denylist hit: %s (pid %d) -> %s",
                    c->binary, (int)c->ev->pid, c->target);
            ctx_respond(c, FAN_DENY);
            return 1;
        }
        if (m < 0)
            c->deny_inconclusive = 1;
    }

    /* Inconclusive: no deny decided, but one may fit and cannot be
     * verified.  Flag the context so the grant stages are skipped and
     * the event reaches the dialog (fail closed); a conclusive deny
     * would already have returned above. */
    if (c->deny_inconclusive)
        log_msg(LOG_INFO,
                "deny entry matches %s (pid %d) but its stored digest is "
                "unverifiable (SHA-512 unavailable); prompting instead of "
                "falling through to grants",
                c->binary, (int)c->ev->pid);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  [allowlist] hash-pin verdict and change prompt                    */
/* ------------------------------------------------------------------ */
/*
 * config_allow_pin_verdict() result codes.  FIRST_USE is distinct from
 * MATCH because the store belongs to the caller: the verdict helper only
 * compares, so it stays side-effect free.
 */
#define ALLOWLIST_PIN_MATCH 0     /* stored pin matches: grant now         */
#define ALLOWLIST_PIN_CHANGED 1   /* stored digest differs: ask the user   */
#define ALLOWLIST_PIN_NO_GRANT 2  /* damaged table / no digest: prompt     */
#define ALLOWLIST_PIN_FIRST_USE 3 /* no pin yet: caller stores then grants */

/*
 * Hash-pin verdict for one matching [allowlist] rule, side-effect free.
 * An empty or missing bin_sha512 (fork/exec/timeout failure, or a binary
 * under a protected path so the pipeline skipped hashing) never grants
 * silently, and a damaged pin table is never trusted: both fall through
 * to the normal dialog with no re-TOFU, so damage cannot silently reset
 * every pin.  old_out receives the stored digest only for
 * ALLOWLIST_PIN_CHANGED; it is cleared on every other return path.
 */
static int config_allow_pin_verdict(const RuleEntry *e,
                                    const char *bin_sha512,
                                    char old_out[129])
{
    if (old_out)
        old_out[0] = '\0';

    if (!e || !bin_sha512 || bin_sha512[0] == '\0')
        return ALLOWLIST_PIN_NO_GRANT;

    switch (pin_check(e->binary, bin_sha512, old_out))
    {
    case PIN_CHECK_MATCH:
        return ALLOWLIST_PIN_MATCH;
    case PIN_CHECK_FIRST_USE:
        return ALLOWLIST_PIN_FIRST_USE;
    case PIN_CHECK_CHANGED:
        return ALLOWLIST_PIN_CHANGED;
    default:
        return ALLOWLIST_PIN_NO_GRANT; /* PIN_CHECK_DAMAGED */
    }
}

/*
 * First-seen store for one matching rule: pin_store() writes the state
 * file immediately and atomically.  A failed store is a warning, not a
 * denial (the access is still granted and the next daemon start
 * re-TOFUs), so an unwritable state directory cannot block legitimate
 * first use.  Returns pin_store()'s result (0 or -1).
 */
static int config_allow_pin_first_seen(const RuleEntry *e,
                                       const char *bin_sha512)
{
    if (pin_store(e->binary, bin_sha512) < 0)
    {
        log_msg(LOG_WARNING,
                "allowlist rule %s: first-seen hash could not be stored; "
                "allowing this access (the next start re-TOFUs)",
                e->binary);
        return -1;
    }
    log_msg(LOG_INFO, "config allowlist first seen, hash pinned: rule %s",
            e->binary);
    return 0;
}

/*
 * Shared grant for a matching [allowlist] rule: exactly the historical
 * config-allowlist branch -- a cache entry scoped to the rule's target
 * (NULL for a global rule = wildcard) with the configured user_ttl.
 */
static void config_allow_grant(EventCtx *c, const RuleEntry *e)
{
    /*
     * A glob target pattern can never equal a concrete lookup path, so
     * cache the concrete file that just matched; exact targets keep the
     * historical rule-scoped entry (NULL for a global rule = wildcard).
     */
    const char *grant;
    int user_ttl = g_config ? g_config->user_ttl_seconds : DEFAULT_USER_TTL_S;

    if (e->target_is_glob)
        grant = c->target;
    else
        grant = e->target_path[0] ? e->target_path : NULL;

    cache_insert(c->ev->pid, c->binary, grant, user_ttl);
    ctx_respond(c, FAN_ALLOW);
}

/*
 * A matching [allowlist] rule's binary no longer matches the pinned
 * digest: ask the user whether the new binary may replace it.  The
 * existing dialog rate limiter gates the prompt first, so a tampered
 * binary cannot flood the user with change prompts.  The limiter is
 * keyed on the rule's binary pattern (the pin key), not on the concrete
 * path, so glob rules whose mount paths churn cannot reset the quota.
 * Yes = update the pin and grant; No, Cancel, window close, timeout and kdialog failure
 * deny this attempt only and keep the old pin, so the next access
 * re-prompts subject to the rate limiter.  The full old and new digests
 * go to the journal; the dialog shows their 16-hex prefixes only.
 * Returns 1 (the event was decided), the caller's convention.
 */
static int config_allow_hash_change(EventCtx *c, const RuleEntry *e,
                                    const char *old_sha512)
{
    if (dialog_rate_limited(e->binary))
    {
        log_msg(LOG_WARNING,
                "denying hash-change prompt for rule %s (%s): "
                "dialog rate limited",
                e->binary, c->binary);
        ctx_respond(c, FAN_DENY);
        return 1;
    }

    log_msg(LOG_WARNING,
            "allowlist rule %s: binary hash changed for %s "
            "(old %s, new %s); asking the user",
            e->binary, c->binary, old_sha512, c->bin_sha512);

    NotifyHashChange req;
    memset(&req, 0, sizeof(req));
    req.rule_pattern = e->binary;
    req.exe = c->binary;
    req.old_hash = old_sha512;
    req.new_hash = c->bin_sha512;
    req.path = c->target;
    req.cmdline = c->cmdline;
    req.pid = c->ev->pid;
    req.user_uid = proc_uid(c->ev->pid);

    int decision = notify_ask_hash_change(&req);
    log_msg(LOG_INFO, "[dialog] hash-change prompt for rule %s (%s): %s",
            e->binary, c->binary, notify_decision_name(decision));

    if (decision == NOTIFY_ALLOW_ALWAYS)
    {
        if (pin_store(e->binary, c->bin_sha512) < 0)
            log_msg(LOG_WARNING,
                    "allowlist rule %s: hash update approved but the new "
                    "pin could not be stored; granting this access (the new "
                    "digest is active in memory until restart, the on-disk "
                    "pin is unchanged)",
                    e->binary);
        else
            log_msg(LOG_INFO,
                    "allowlist rule %s: hash update approved, new digest "
                    "pinned",
                    e->binary);
        config_allow_grant(c, e);
        return 1;
    }

    log_msg(LOG_WARNING,
            "hash change denied for allowlist rule %s (%s); old pin kept",
            e->binary, c->binary);
    ctx_respond(c, FAN_DENY);
    return 1;
}

/*
 * Grant stages, evaluated in order by event_runtime_allowed().  Each
 * returns 1 when it decided the event (the response has been written, or
 * the hash-change prompt decided it) and 0 to fall through to the next
 * stage.  Denials never reach these: event_runtime_denied() runs first,
 * and hard-link events skip every grant stage.
 */

/* File cache: "Allow Once" decisions and config-allowlist refreshes. */
static int try_file_cache(EventCtx *c)
{
    if (cache_lookup(c->ev->pid, c->binary, c->target) <= 0)
        return 0;
    ctx_respond(c, FAN_ALLOW);
    return 1;
}

/* Session-scoped allow entries: same shell session, binary and file. */
static int try_session_allow(EventCtx *c)
{
    if (!c->have_sid ||
        !session_allow_match(c->sid, c->binary, c->bin_sha512, c->target))
        return 0;
    log_msg(LOG_INFO, "session allowlist hit: %s (pid %d, sid %d) -> %s",
            c->binary, (int)c->ev->pid, (int)c->sid, c->target);
    ctx_respond(c, FAN_ALLOW);
    return 1;
}

/* Runtime "Always" entries: persisted allowlist, command-line keyed. */
static int try_runtime_allow(EventCtx *c)
{
    if (g_dyn_allow_count <= 0 ||
        !dyn_allow_match(c->binary, c->bin_sha512, event_chain_provider, c,
                         c->target, event_cmdline_provider, c))
        return 0;

    int user_ttl = g_config ? g_config->user_ttl_seconds : DEFAULT_USER_TTL_S;
    cache_insert(c->ev->pid, c->binary, c->target, user_ttl);
    log_msg(LOG_INFO, "dynamic allowlist hit: %s (pid %d) -> %s",
            c->binary, (int)c->ev->pid, c->target);
    ctx_respond(c, FAN_ALLOW);
    return 1;
}

/*
 * Config [unsafe_allowlist]: an explicit admin opt-in that skips hash
 * checking and pinning entirely.  Evaluated before the hash-pinned
 * [allowlist]; a hit grants silently with the rule's target scope and
 * never touches the pin state.
 */
static int try_unsafe_allowlist(EventCtx *c)
{
    const RuleEntry *unsafe = unsafe_allowlist_match(c->binary, c->target);
    if (!unsafe)
        return 0;

    int first = unsafe_first_hit(c->ev->pid);

    /* The first hit from a process stands out: WARNING severity and the
     * matched rule, because the rule skips hash pinning and an
     * impersonated binary is exactly what this surfaces.  Repeats from
     * the same process stay in the journal at INFO so the access audit
     * trail remains complete. */
    log_msg(first ? LOG_WARNING : LOG_INFO,
            "unsafe allowlist hit%s: %s (pid %d) -> %s (rule: %s)",
            first ? "" : " (repeat)", c->binary, (int)c->ev->pid,
            c->target, unsafe->binary);
    if (first)
        config_rule_notify(c, unsafe, NOTIFY_HIT_UNSAFE, c->comm);
    config_allow_grant(c, unsafe);
    return 1;
}

/*
 * Config [allowlist], hash-pinned: a pin match grants; a first event
 * stores the digest immediately and grants; a changed digest asks the
 * user (returning 0 in defer mode so the pump queues it); a damaged
 * table or an unavailable digest falls through to the normal dialog
 * (fail closed, no silent re-TOFU).
 */
static int try_pinned_allowlist(EventCtx *c)
{
    const RuleEntry *rule = allowlist_match(c->binary, c->target);
    if (!rule)
        return 0;

    char old_sha512[129];
    int verdict = config_allow_pin_verdict(rule, c->bin_sha512, old_sha512);

    if (verdict == ALLOWLIST_PIN_FIRST_USE)
    {
        config_allow_pin_first_seen(rule, c->bin_sha512);
        config_rule_notify(c, rule, NOTIFY_HIT_ALLOW, c->comm);
        config_allow_grant(c, rule);
        return 1;
    }
    if (verdict == ALLOWLIST_PIN_MATCH)
    {
        log_msg(LOG_INFO,
                "config allowlist hit (pin match): %s (pid %d) -> %s",
                c->binary, (int)c->ev->pid, c->target);
        config_rule_notify(c, rule, NOTIFY_HIT_ALLOW, c->comm);
        config_allow_grant(c, rule);
        return 1;
    }
    if (verdict == ALLOWLIST_PIN_CHANGED)
    {
        /* Defer mode (the dialog pump): the hash-change prompt is a
         * second modal dialog, so queue the event instead of stacking it
         * on the open one.  The main loop replays the event and prompts
         * once the current dialog is done. */
        if (c->defer_on_ask)
            return 0;
        return config_allow_hash_change(c, rule, old_sha512);
    }

    /* ALLOWLIST_PIN_NO_GRANT: damaged table or unavailable hash; never
     * grant silently and never store a fresh pin. */
    if (c->bin_sha512[0] == '\0')
        log_msg(LOG_WARNING,
                "allowlist rule %s: binary SHA-512 unavailable for %s; "
                "asking the user (no silent grant)",
                rule->binary, c->binary);
    else
        log_msg(LOG_ERR,
                "allowlist rule %s: pin table damaged; asking the user "
                "(no silent grant, no re-TOFU)",
                rule->binary);
    return 0;
}

/*
 * Stage 6: grants, in order: file cache ("Allow Once" and fast paths),
 * session allowlist, dynamic allowlist ("Allow Always"), unsafe config
 * allowlist ([unsafe_allowlist], no pinning), hash-pinned config
 * allowlist.  The config sections are last: a denial always wins, and
 * the deny checks above needed the hashes gathered in stage 4.
 * Returns 1 when the event was allowed.
 */
static int event_runtime_allowed(EventCtx *c)
{
    /* An inconclusive deny (path keys fit, stored digest unverifiable)
     * gates every grant stage: no hash-free grant -- file cache, session
     * allow, runtime allow, [unsafe_allowlist] -- may decide while a
     * denial that may well fit is waiting to be verified.  The caller
     * reaches the dialog (fail closed). */
    if (c->deny_inconclusive)
        return 0;

    /*
     * A hard-link/unprotected-path event must not be resolved by a rule
     * scoped to a different path (or by a wildcard grant): force the
     * prompt so the user decides for this exact path.  Denials were
     * already evaluated by the caller, so this strips grants only.
     */
    if (c->hardlink_event)
        return 0;

    /* Order is part of the security contract (AGENTS.md); each helper
     * is a single grant stage and returns 1 only when it decided. */
    if (try_file_cache(c))
        return 1;
    if (try_session_allow(c))
        return 1;
    if (try_runtime_allow(c))
        return 1;
    if (try_unsafe_allowlist(c))
        return 1;
    if (try_pinned_allowlist(c))
        return 1;
    return 0;
}

/*
 * Record an allow decision the user made in the dialog.  Returns the
 * fanotify response (always FAN_ALLOW; session decisions degrade to a
 * one-time cache grant when the session is unknown or the binary digest
 * is unavailable).
 */
static unsigned int record_allow_decision(EventCtx *c, int decision)
{
    int user_ttl = g_config ? g_config->user_ttl_seconds : DEFAULT_USER_TTL_S;
    int session_ttl = g_config ? g_config->session_ttl_seconds : 0;

    if (decision == NOTIFY_ALLOW_ONCE)
    {
        cache_insert(c->ev->pid, c->binary, c->target, user_ttl);
    }
    else if (decision == NOTIFY_ALLOW_SESSION)
    {
        /* DELIBERATE: a session grant is recorded even when the binary
         * digest is unavailable (c->bin_sha512[0] == '\0').  AppImages
         * under /tmp/.mount_* and other self-updating tools cannot be
         * hashed, and "Allow Session" is exactly the scope for them;
         * degrading this to Allow Once earns one cached open and then
         * re-prompts, which breaks the primary use case.  The matcher
         * (session.c) treats an empty stored digest as a match, bounded
         * by the session leader, the binary path and the target.  Do NOT
         * turn this back into a fail-closed degradation: see the
         * session.h contract and the AGENTS.md limitations note. */
        if (c->have_sid)
        {
            session_allow_add(c->sid, c->sid_start, c->binary, c->bin_sha512,
                              c->target, session_ttl);
        }
        else
        {
            log_msg(LOG_WARNING,
                    "session unavailable; degrading Allow Session to "
                    "Allow Once for %s",
                    c->binary);
            cache_insert(c->ev->pid, c->binary, c->target, user_ttl);
        }
    }
    else /* NOTIFY_ALLOW_ALWAYS */
    {
        const char *cmdline_fp = event_cmdline_fp(c);

        /* dyn_allow_add() refuses an entry without a binary digest (it
         * could never be matched) and logs "one-time access", so degrade
         * to the cached one-time grant here instead of handing the user
         * a grant the next open ignores.  The same fallback covers an
         * unfingerprintable command line, whose persistent entry would
         * otherwise cover every invocation of the binary. */
        if (cmdline_fp[0] == '\0' || c->bin_sha512[0] == '\0')
        {
            log_msg(LOG_WARNING,
                    "cannot persist Allow Always for %s (%s); "
                    "degrading to Allow Once",
                    c->binary,
                    c->bin_sha512[0] == '\0'
                        ? "binary SHA-512 unavailable"
                        : "command line could not be fingerprinted");
            cache_insert(c->ev->pid, c->binary, c->target, user_ttl);
        }
        else
        {
            /* Defensive: the prompt path built it already, but a future
             * recorder must never persist an empty chain by accident. */
            event_build_chain(c, 0);
            dyn_allow_add(c->binary, c->bin_sha512, &c->chain, c->target,
                          c->cmdline, cmdline_fp);
        }
    }
    return FAN_ALLOW;
}

/*
 * Record a deny decision from the dialog.  Deny Session degrades to a
 * one-time deny when the session is unknown; Deny Always degrades to a
 * one-time deny when the command line cannot be fingerprinted.
 */
static unsigned int record_deny_decision(EventCtx *c, int decision)
{
    if (decision == NOTIFY_DENY_SESSION)
    {
        int session_ttl = g_config ? g_config->session_ttl_seconds : 0;

        if (c->have_sid)
        {
            /* A missing digest is stored here too (see the allow path).
             * The empty-digest match is conservative on this side: it
             * denies any binary at the same path for the session. */
            session_deny_add(c->sid, c->sid_start, c->binary, c->bin_sha512,
                             c->target, session_ttl);
        }
        else
        {
            log_msg(LOG_WARNING,
                    "session unavailable; denying %s for this attempt only",
                    c->binary);
        }
    }
    else /* NOTIFY_DENY_ALWAYS */
    {
        const char *cmdline_fp = event_cmdline_fp(c);
        if (cmdline_fp[0] != '\0')
        {
            /* Defensive: see record_allow_decision(). */
            event_build_chain(c, 0);
            dyn_deny_add(c->binary, c->bin_sha512, &c->chain, c->target,
                         c->cmdline, cmdline_fp);
        }
        else
        {
            log_msg(LOG_WARNING,
                    "cannot fingerprint the command line for %s; "
                    "denying this attempt only",
                    c->binary);
        }
    }
    return FAN_DENY;
}

/*
 * Stage 7: no rule matched — rate-limit the dialog flood risk, then ask
 * the user and record their decision.
 * Returns 1 when the event must defer instead of asking (defer mode: the
 * caller queues it with its fd open), 0 when the event was decided.
 */
static int event_ask_user(EventCtx *c)
{
    if (c->defer_on_ask)
        return 1; /* never a second dialog while another decision is open */

    if (dialog_rate_limited(c->binary))
    {
        ctx_respond(c, FAN_DENY);
        return 0;
    }

    /* Snapshot the chain before the dialog: an Always/Deny Always decision
     * records the chain as it was when the event arrived, not the state
     * after the user decided.  force_retry gives recording a fresh attempt
     * at ancestors stuck inside a negative failure window. */
    event_build_chain(c, 1);

    /* The digest-unavailable warning belongs here, where a prompt actually
     * needs it: silent grants (cache, rules, unsafe list) never log it. */
    if (c->bin_sha512[0] == '\0')
        log_msg(LOG_WARNING,
                "SHA-512 unavailable for %s (pid %d): %s; prompting "
                "(no persistent \"Allow Always\")",
                c->binary, (int)c->ev->pid, c->bin_hash_failure);

    log_msg(LOG_INFO, "[dialog] asking user: pid=%d binary=%s target=%s comm=%s",
            (int)c->ev->pid, c->binary, c->target, c->comm);

    NotifyRequest req;
    memset(&req, 0, sizeof(req));
    req.comm = c->comm;
    req.pid = c->ev->pid;
    req.ppid = c->ppid;
    req.comm_parent = c->pcomm;
    req.exe = c->binary;
    req.cmdline = c->cmdline;
    req.path = c->target;
    req.user_uid = proc_uid(c->ev->pid);
    req.user_ttl = g_config ? g_config->user_ttl_seconds : DEFAULT_USER_TTL_S;
    req.session_ttl = g_config ? g_config->session_ttl_seconds : 0;
    req.hash_unavailable = (c->bin_sha512[0] == '\0');
    req.hash_failure = c->bin_hash_failure;

    int decision = notify_ask(&req);
    log_msg(LOG_INFO, "[dialog] user chose %s for %s (pid %d) -> %s",
            notify_decision_name(decision), c->binary, (int)c->ev->pid,
            c->target);

    unsigned int response = FAN_DENY;
    if (decision == NOTIFY_ALLOW_ONCE || decision == NOTIFY_ALLOW_SESSION ||
        decision == NOTIFY_ALLOW_ALWAYS)
        response = record_allow_decision(c, decision);
    else if (decision == NOTIFY_DENY_SESSION || decision == NOTIFY_DENY_ALWAYS)
        response = record_deny_decision(c, decision);

    ctx_respond(c, response);
    return 0;
}

/*
 * Full decision path for a FAN_OPEN_PERM event.  Takes ownership of ev->fd:
 * every path responds and closes the event fd (except FAN_NOFD) — or, in
 * defer mode, defers the event to the caller when the pipeline reaches the
 * ask stage (the fd stays open and is queued, never closed).
 *
 * Returns 1 when the event was decided here (responded and closed), 0 when
 * it was deferred in defer mode (fd still open; the caller queues it or
 * denies fail-closed).
 *
 * The stages below are pure structure: each one was a block inside this
 * function, and every respond/close/cache side effect happens in the
 * same order.  The decision order is (a denial always wins over a grant):
 *   config deny -> session deny -> permanent deny -> file cache
 *   -> session allow -> permanent allow -> unsafe config allow
 *   -> pinned config allow -> rate limit -> dialog
 * The config allowlist sections sit after the runtime grants because
 * every deny must be evaluated first, which requires the hashes from
 * stage 4.  Inside the pinned section a damaged table or an unavailable
 * digest falls through to the dialog (fail closed).
 */
/*
 * Run the deny stages before the grant stages over one event.  Shared by
 * process_open_perm() and the order test seam so the ordering (every
 * denial wins over every grant) cannot drift.
 * Returns 1 when a deny stage decided, 2 when a grant stage decided, 0
 * when the event still needs the dialog.
 */
static int run_verdict_stages(EventCtx *c)
{
    if (event_runtime_denied(c))
        return 1;
    if (event_runtime_allowed(c))
        return 2;
    return 0;
}

static int process_open_perm(int fan_fd, const struct fanotify_event_metadata *ev,
                             int defer_on_ask)
{
    EventCtx c;
    memset(&c, 0, sizeof(c));
    c.fan_fd = fan_fd;
    c.ev = ev;
    c.fd_num = (int)ev->fd;
    c.close_fd = (c.fd_num != FAN_NOFD);
    c.defer_on_ask = defer_on_ask;

    log_msg(LOG_DEBUG, "[event] FAN_OPEN_PERM pid=%d fd=%d",
            (int)ev->pid, c.fd_num);

    if (event_resolve(&c))
        goto out;
    if (event_fastpath(&c))
        goto out;
    if (event_load_binary(&c))
        goto out;
    if (event_dedup(&c))
        goto out;
    event_gather_identity(&c);
    if (run_verdict_stages(&c))
        goto out;
    if (event_ask_user(&c))
    {
        free(c.binary);
        return 0; /* defer mode: fd stays open; the caller queues it */
    }

out:
    if (c.close_fd && !c.keep_event_fd)
        close(c.fd_num);
    free(c.binary);
    return 1;
}

/*
 * Test seam (fanotify.h): run the real verdict stages over a synthetic
 * request.  Returns 1 when a deny stage decided, 2 when a grant stage
 * decided, 0 when the event would reach the dialog (or defer, when
 * 'defer' is set).  sid > 0 makes the synthetic context look like a
 * member of that session (for recorded session decisions); cmdline_fp
 * may be NULL.  hardlink mirrors the pipeline's hard-link
 * classification; defer mirrors the pump's defer_on_ask mode.
 */
int fanotify_test_verdict_stage(const char *binary, const char *bin_sha512,
                                const char *target, const char *cmdline_fp,
                                pid_t sid, int hardlink, int defer)
{
    struct fanotify_event_metadata ev;
    EventCtx c;
    int pipefd[2];
    int verdict;

    if (pipe(pipefd) < 0)
        return 0;

    memset(&ev, 0, sizeof(ev));
    ev.event_len = sizeof(ev);
    ev.vers = FANOTIFY_METADATA_VERSION;
    ev.mask = FAN_OPEN_PERM;
    ev.fd = FAN_NOFD;
    ev.pid = (int)getpid();

    memset(&c, 0, sizeof(c));
    c.fan_fd = pipefd[1];
    c.ev = &ev;
    c.fd_num = FAN_NOFD;
    c.binary = (char *)binary; /* owned by the caller; not freed here */
    snprintf(c.target, sizeof(c.target), "%s", target ? target : "");
    snprintf(c.bin_sha512, sizeof(c.bin_sha512), "%s",
             bin_sha512 ? bin_sha512 : "");
    if (cmdline_fp)
    {
        snprintf(c.cmdline_sha512, sizeof(c.cmdline_sha512), "%s", cmdline_fp);
        c.cmdline_sha_state = 1;
    }
    else
        c.cmdline_sha_state = -1;
    if (sid > 0)
    {
        c.sid = sid;
        c.have_sid = 1;
    }
    c.hardlink_event = hardlink;
    c.defer_on_ask = defer;

    verdict = run_verdict_stages(&c);

    close(pipefd[0]);
    close(pipefd[1]);
    return verdict;
}

/*
 * Test seam (fanotify.h): run the real allow-decision recorder over a
 * synthetic dialog decision and return the fanotify response (FAN_ALLOW).
 * sid > 0 marks the context as a member of that session with the given
 * leader start time; bin_sha512 may be NULL or "" to mirror an
 * unavailable digest.  The event pid is the caller's, so a degraded grant
 * is cached under it.
 */
unsigned int fanotify_test_record_allow_decision(const char *binary,
                                                 const char *bin_sha512,
                                                 const char *target,
                                                 pid_t sid,
                                                 unsigned long long sid_start,
                                                 int decision)
{
    struct fanotify_event_metadata ev;
    EventCtx c;

    memset(&ev, 0, sizeof(ev));
    ev.event_len = sizeof(ev);
    ev.vers = FANOTIFY_METADATA_VERSION;
    ev.mask = FAN_OPEN_PERM;
    ev.fd = FAN_NOFD;
    ev.pid = (int)getpid();

    memset(&c, 0, sizeof(c));
    c.ev = &ev;
    c.binary = (char *)binary; /* owned by the caller; not freed here */
    snprintf(c.target, sizeof(c.target), "%s", target ? target : "");
    snprintf(c.bin_sha512, sizeof(c.bin_sha512), "%s",
             bin_sha512 ? bin_sha512 : "");
    if (sid > 0)
    {
        c.sid = sid;
        c.sid_start = sid_start;
        c.have_sid = 1;
    }

    return record_allow_decision(&c, decision);
}

/*
 * Advance to the next event in one read(2) batch.  Encapsulates the
 * offset arithmetic and the malformed-length guard: an event_len outside
 * the walk contract ([header, remaining]) makes every record behind this
 * position unlocatable, so the walk ends instead of looping or stepping
 * outside the buffer.  Tri-state: returns the next record on advance;
 * NULL with *malformed == 0 for a clean end (the caller's while
 * (FAN_EVENT_OK(...)) also fails and exits, silently); NULL with
 * *malformed == 1 when a record length is invalid — the current record
 * was already handled by the caller, only the tail is lost, and the
 * caller logs loudly rather than guessing positions (the stance
 * batch_abandon documents).  A record returned here always satisfies
 * FAN_EVENT_OK.
 */
static const struct fanotify_event_metadata *
event_next(const struct fanotify_event_metadata *ev, ssize_t *remaining,
           int *malformed)
{
    const struct fanotify_event_metadata *next;

    *malformed = 0;
    if (!FAN_EVENT_OK(ev, (size_t)*remaining))
    {
        *malformed = 1;
        return NULL;
    }
    *remaining -= (ssize_t)ev->event_len;
    /* Less than one header left: no full record (and therefore no
     * duplicated event fd) can hide in the tail, so the walk ends. */
    if (*remaining < (ssize_t)sizeof(struct fanotify_event_metadata))
        return NULL;
    next = (const struct fanotify_event_metadata *)((const char *)ev +
                                                    ev->event_len);
    if (!FAN_EVENT_OK(next, (size_t)*remaining))
    {
        *malformed = 1;
        return NULL;
    }
    return next;
}

/*
 * Shared loud reaction to event_next()'s malformed flag: a record whose
 * length is invalid makes the rest of the batch unlocatable, so the tail
 * is dropped rather than guessed at.  The current record was already
 * handled; only the remainder is lost.  A clean end stays silent.
 */
static void log_batch_tail_lost(ssize_t remaining)
{
    log_msg(LOG_ERR,
            "fanotify batch: malformed record length; the remainder of the "
            "batch (%zd bytes) is unlocatable and was dropped",
            remaining);
}

/* ------------------------------------------------------------------ */
/*  fanotify_pump: drain pending events while dialog child is running */
/* ------------------------------------------------------------------ */
/*
 * Called by notify.c in a poll loop while waiting for the dialog child.
 * Reads all currently available FAN_OPEN_PERM events non-blocking and
 * responds to them:
 *   - Events FROM dialog_child_pid: FAN_ALLOW (dialog needs to open files).
 *   - Direct daemon children (hashing helpers): FAN_ALLOW.
 *   - Everything else runs the FULL decision pipeline in defer mode: deny
 *     stages, caches and rule grants decide immediately, so an allowlisted
 *     or denylisted read never queues behind the open decision.  Only
 *     events that genuinely need the user are deferred to the replay
 *     queue with their event fd left open (a full queue denies
 *     fail-closed) — decided once the dialog finishes by
 *     fanotify_process_pending in the main loop.  Non-permission events
 *     are handled in place; the caller must not close fan_fd.
 *
 * Returns number of events responded to.
 */
/*
 * Decide one permission event read while a dialog is open.
 * Returns 1 when the event was responded to (the caller counts it) and 0
 * when it was deferred to the main loop with its event fd left open.
 * Fail closed: a full pending queue denies rather than hanging the caller.
 * A response queued for retry also returns 1: the retry/stranded queue
 * now owns the event fd, and the caller must not close it.
 */

/* Re-entrancy guard: set while a defer-mode pipeline decision is running
 * inside the pump.  The decision path itself pumps (hashing helper waits),
 * and a nested pump must not recurse into the pipeline — it falls back to
 * the cheap fast-path allow and defers the rest. */
static int g_pump_in_pipeline = 0;

/*
 * Per-call work bound for fanotify_pump().  The pump runs from notify.c's
 * dialog wait loops and from sha512.c's hash-helper wait hook; draining a
 * sustained event stream in one call would starve the caller's dialog
 * deadline and signal handling.  Stop after this many read(2) batches
 * (each at most BUF_SIZE bytes) and return to the caller; every record
 * already read is processed or claimed before the return, and the group
 * fd stays readable so the next poll/entry continues.
 */
#define PUMP_MAX_BATCHES 16

static int pump_decide_permission(int fan_fd,
                                  const struct fanotify_event_metadata *ev,
                                  pid_t dialog_child_pid)
{
    int fd_num = (int)ev->fd;
    int allow = 0;

    if (dialog_child_pid > 0 &&
        process_in_dialog_group(ev->pid, dialog_child_pid))
    {
        log_msg(LOG_DEBUG, "[pump] ALLOW fd=%d pid=%d (dialog group)",
                fd_num, (int)ev->pid);
        allow = 1;
    }
    else if (get_ppid(ev->pid) == getpid())
    {
        /* Direct child of the daemon (sha512sum hashing for the event
         * being handled) must never stall. */
        log_msg(LOG_DEBUG, "[pump] ALLOW fd=%d pid=%d (daemon child)",
                fd_num, (int)ev->pid);
        allow = 1;
    }
    else if (g_pump_in_pipeline)
    {
        /* Nested pump (a defer-mode decision is hashing or pumping right
         * now): do not recurse into the pipeline.  Fall back to the cheap
         * fast-path allow and defer the rest. */
        struct stat st;
        if (fstat(fd_num, &st) == 0 &&
            !inode_set_contains(st.st_dev, st.st_ino))
        {
            char tgt[PATH_MAX];
            if (resolve_fd_path(fd_num, tgt, sizeof(tgt)) == 0 &&
                !is_path_under_protected(tgt))
            {
                log_msg(LOG_DEBUG,
                        "[pump] ALLOW fd=%d pid=%d path=%s (non-protected, "
                        "nested)",
                        fd_num, (int)ev->pid, tgt);
                allow = 1;
            }
        }
        if (!allow)
            log_msg(LOG_DEBUG, "[pump] QUEUE fd=%d pid=%d (nested pump)",
                    fd_num, (int)ev->pid);
    }
    else
    {
        /* Full pipeline in defer mode: everything decidable without a
         * dialog decides right now — fast path, config denylist (with its
         * tripwire), session/runtime denies, file cache, session and
         * runtime grants, [unsafe_allowlist], pinned [allowlist].  Only
         * events that genuinely need the user reach the ask stage and are
         * deferred instead. */
        int decided;
        g_pump_in_pipeline = 1;
        decided = process_open_perm(fan_fd, ev, 1);
        g_pump_in_pipeline = 0;
        if (decided)
            return 1;
        log_msg(LOG_DEBUG, "[pump] QUEUE fd=%d pid=%d (needs the user)",
                fd_num, (int)ev->pid);
    }

    if (allow)
    {
        if (fanotify_respond(fan_fd, ev, FAN_ALLOW) == -1)
            return 1; /* queued for retry; the event fd stays open */
        close(fd_num);
        return 1;
    }
    /* Not allowed and not decided by the pipeline: defer, or deny
     * fail-closed when the queue is full. */
    if (fanotify_defer_event(ev) == 0)
        return 0; /* deferred; event fd stays open for the main loop */

    log_msg(LOG_WARNING, "[pump] pending queue full; denying fd=%d pid=%d",
            fd_num, (int)ev->pid);
    if (fanotify_respond(fan_fd, ev, FAN_DENY) == -1)
        return 1; /* queued for retry; the event fd stays open */
    close(fd_num);
    return 1;
}

int fanotify_pump(int fan_fd, pid_t dialog_child_pid)
{
    char buf[BUF_SIZE]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));

    int responded = 0;
    int batches = 0;

    /* Publish the dialog for the duration of this call so the hash-helper
     * wait hook (hash_wait_pump) stays dialog-aware; save/restore keeps a
     * nested pump on the enclosing dialog and clears the pid the moment
     * no dialog pump is on the stack (see g_active_dialog_pid). */
    pid_t saved_dialog = g_active_dialog_pid;
    if (dialog_child_pid > 0)
        g_active_dialog_pid = dialog_child_pid;

    /* Deliver any responses the queue is holding; a failed response must
     * not wait for the main loop while a dialog blocks it. */
    unanswered_retry(fan_fd);

    while (1)
    {
        /* Per-call budget: a sustained stream must not hold the
         * single-threaded daemon (or SIGTERM/SIGHUP) inside one pump.
         * Stop between read(2) batches — after the current buffer was
         * fully processed or claimed — and return to the caller's poll
         * loop; the group fd stays readable, so the next poll/entry
         * continues where this one stopped. */
        if (batches >= PUMP_MAX_BATCHES)
            break;

        /* The group fd is permanently non-blocking (FAN_NONBLOCK at init):
         * a read here can never stall the dialog child, and notify.c
         * re-enters the pump whenever poll(2) reports the fd readable. */
        ssize_t n = read(fan_fd, buf, sizeof(buf));
        if (n <= 0)
            break;
        batches++;

        const struct fanotify_event_metadata *ev =
            (const struct fanotify_event_metadata *)buf;
        ssize_t remaining = n;
        int malformed = 0;

        while (FAN_EVENT_OK(ev, (size_t)remaining))
        {
            if (ev->vers != FANOTIFY_METADATA_VERSION)
            {
                /* A metadata-version mismatch means the event stream
                 * cannot be interpreted at all (fanotify(7)): abandon
                 * the group and let the supervisor restart cleanly.
                 * Deny before closing: the fd field sits at a fixed
                 * offset that has never moved, so a DENY is fail-closed
                 * even if the rest of this record is misread — a
                 * misrouted DENY denies some other pending event (the
                 * correct direction), while closing without any response
                 * only hangs this caller until close(fan_fd) auto-ALLOWS
                 * the open.  The records behind this one are claimed by
                 * batch_abandon() at the loop exit. */
                if (ev->fd != FAN_NOFD)
                {
                    if (fanotify_respond(fan_fd, ev, FAN_DENY) != -1)
                        close((int)ev->fd);
                }
                log_msg(LOG_ERR,
                        "fanotify metadata version mismatch; stopping");
                g_fatal = 1;
                break;
            }
            else if ((ev->mask & FAN_OPEN_PERM) && ev->fd != FAN_NOFD)
            {
                responded += pump_decide_permission(fan_fd, ev,
                                                    dialog_child_pid);
            }
            else if (ev->mask & FAN_OPEN_PERM)
            {
                /* FAN_NOFD (kernel fd-creation failure): unreachable for
                 * this fd-based group — the kernel already auto-DENIED
                 * the permission event (fanotify_read: copy_event_to_user
                 * failure -> finish_permission_event(FAN_DENY)), so this
                 * branch is pure defense.  There is no event fd to answer
                 * with: a write with fd=-1 would earn EINVAL, set g_fatal
                 * and queue a phantom retry.  Log and skip as handled. */
                log_msg(LOG_WARNING,
                        "[pump] FAN_NOFD for pid=%d; kernel already denied, "
                        "skipping respond",
                        (int)ev->pid);
            }
            else if (ev->mask & (FAN_CREATE | FAN_MOVED_TO))
            {
                handle_notification_event(fan_fd, ev);
            }
            else if (ev->mask & FAN_Q_OVERFLOW)
            {
                /* Saturation while a dialog is open: fail closed by denying
                 * every deferred permission event immediately rather than
                 * holding them against state whose events were lost. */
                log_msg(LOG_WARNING,
                        "[pump] fanotify queue overflow; denying %d deferred "
                        "permission events (fail closed)",
                        g_pending_count);
                fanotify_flush_pending(fan_fd);
            }
            else if (ev->fd != FAN_NOFD)
            {
                close((int)ev->fd);
            }

            /* Lifecycle boundary: shutdown, reload and fatal conditions
             * stop the walk at the record boundary.  read(2) duplicated
             * an fd for every later record, so they are claimed by
             * batch_abandon() below; nothing is left open or unanswered. */
            if (g_fatal || !g_running || g_need_reload)
                break;
            ev = event_next(ev, &remaining, &malformed);
            if (!ev)
                break;
        }
        if (malformed)
            log_batch_tail_lost(remaining);
        if (g_fatal || !g_running || g_need_reload)
        {
            /* Claim the records this walk exited in front of before
             * returning: their fds are already duplicated into this
             * process and their permission events would otherwise
             * auto-ALLOW at close(fan_fd).  ev is NULL only when the
             * batch was already walked to its end, so there is nothing
             * left to claim. */
            if (ev)
                batch_abandon(fan_fd, ev, remaining);
            break;
        }
    }

    /* Single exit: nothing returns after publishing, so this restore
     * covers every way out of the loop (budget, EAGAIN, lifecycle). */
    g_active_dialog_pid = saved_dialog;
    return responded;
}

void fanotify_clear_marks(int fd)
{
    /* Remove every mark this daemon installed (tracked in g_marks),
     * including auto-added directory marks, then the mount marks, and
     * clear the in-memory tables.  Called before a config reload so the
     * tables are rebuilt cleanly by the subsequent fanotify_add_mark()
     * calls.  Any deferred permission event is denied first (fail closed).
     *
     * A mark whose removal fails stays tracked and is retried on the next
     * clear: forgetting it would leave an untracked kernel mark intercepting
     * opens under a later config.  A negative fd (unprivileged tests) means
     * no group exists and nothing was ever installed in the kernel, so the
     * table is cleared outright. */
    fanotify_flush_pending(fd);

    int kept = 0;
    for (int i = 0; i < g_mark_count; i++)
    {
        int rc = (fd >= 0)
                     ? fanotify_mark(fd, FAN_MARK_REMOVE, g_marks[i].mask,
                                     AT_FDCWD, g_marks[i].path)
                     : 0;
        if (rc < 0 && errno == ENOENT)
            rc = 0; /* no kernel mark to remove: already gone */
        if (rc < 0)
        {
            log_msg(LOG_WARNING,
                    "fanotify mark remove failed for %s: %s; keeping it "
                    "tracked for the next clear",
                    g_marks[i].path, strerror(errno));
            if (kept != i)
            {
                /* The strdup'd path moves with the entry; clear the
                 * source slot so the dead tail does not alias it. */
                g_marks[kept] = g_marks[i];
                g_marks[i].path = NULL;
            }
            kept++;
        }
        else
        {
            free(g_marks[i].path);
            g_marks[i].path = NULL;
        }
    }
    g_mark_count = kept;

    /* Recompute the auto-mark budget from the SURVIVING entries: a
     * partial removal failure (kept > 0) previously left the old count,
     * which never decays and throttles auto-marking forever even though
     * most auto marks are gone. */
    g_auto_mark_count = 0;
    for (int i = 0; i < kept; i++)
        if (g_marks[i].is_auto)
            g_auto_mark_count++;

    int kept_mounts = 0;
    for (int i = 0; i < g_mount_count; i++)
    {
        int rc = (fd >= 0)
                     ? fanotify_mark(fd, FAN_MARK_REMOVE | FAN_MARK_MOUNT,
                                     FAN_OPEN_PERM, AT_FDCWD,
                                     g_mounts[i].path)
                     : 0;
        if (rc < 0 && errno == ENOENT)
            rc = 0; /* no kernel mount mark to remove */
        if (rc < 0)
        {
            log_msg(LOG_WARNING,
                    "fanotify mount mark remove failed for %s (dev %lu): %s; "
                    "keeping it tracked for the next clear",
                    g_mounts[i].path, (unsigned long)g_mounts[i].dev,
                    strerror(errno));
            if (kept_mounts != i)
                g_mounts[kept_mounts] = g_mounts[i];
            kept_mounts++;
        }
    }
    g_mount_count = kept_mounts;
    inode_set_clear();
    recent_cache_clear(); /* a reload may change every verdict */
    log_msg(LOG_INFO, "marks and inode table cleared");
}

/*
 * Responses whose kernel write failed are queued with their event fd
 * still open: closing the fd does not answer a permission event, and
 * close(fan_fd) would auto-ALLOW it.  The queue starts at UNANSWERED_MAX
 * entries and doubles on demand; if it cannot grow (allocation failure),
 * the event fd is parked in the bounded stranded list instead, so a
 * decided response is never abandoned.  The main loop and the pump retry
 * the queue; fanotify_drain_and_deny() forces a final DENY for the queue
 * and the stranded list before close(fan_fd) on shutdown.
 */
#define UNANSWERED_MAX 64          /* initial queue capacity            */
#define UNANSWERED_STRANDED_MAX 32 /* allocation-failure fallback bound */

typedef struct
{
    int fd;                            /* kernel event fd, kept open   */
    struct fanotify_event_metadata ev; /* its metadata (ev.fd == fd)   */
    unsigned int response;             /* decision still to deliver    */
} UnansweredEvent;

static UnansweredEvent *g_unanswered = NULL;
static int g_unanswered_count = 0;
static int g_unanswered_cap = 0;

/*
 * Bounded fallback for a response whose queue slot could not even be
 * allocated: only the event fd is kept (the shutdown drain force-DENYs
 * it), so the fail-closed direction survives a double allocation
 * failure.  Full list: fanotify_respond() keeps the fd open and logs.
 */
static int g_stranded[UNANSWERED_STRANDED_MAX];
static int g_stranded_count = 0;

/* Test seam (fanotify_test_force_unanswered_alloc_fail): makes the next
 * retry-queue admission fail, as if its allocation failed, so the
 * stranded fallback is reachable without inducing real memory pressure. */
static int g_test_unanswered_alloc_fail = 0;

/* Raw response write: 0 delivered, 1 already answered, -1 failed. */
static int write_response(int fan_fd, int event_fd, unsigned int response)
{
    struct fanotify_response resp;

    resp.fd = event_fd;
    resp.response = response;
    ssize_t total = 0;
    while (total < (ssize_t)sizeof(resp))
    {
        ssize_t w = write(fan_fd, (char *)&resp + total,
                          sizeof(resp) - (size_t)total);
        if (w < 0)
        {
            if (errno == EINTR)
                continue;
            /* "response for this fd has already been written". */
            if (errno == ENOENT)
                return 1;
            return -1;
        }
        if (w == 0)
            return -1;
        total += w;
    }
    return 0;
}

/* Drop one queue slot, closing its (still open) event fd. */
static void unanswered_drop(int idx)
{
    close(g_unanswered[idx].fd);
    memmove(&g_unanswered[idx], &g_unanswered[idx + 1],
            sizeof(UnansweredEvent) *
                (size_t)(g_unanswered_count - idx - 1));
    g_unanswered_count--;
}

/* Queue one failed response; the caller keeps the event fd open.
 * Doubles the queue from UNANSWERED_MAX when full.  Returns 0 when
 * queued, -1 when the queue could not grow (the caller falls back to the
 * stranded list). */
static int unanswered_add(int event_fd,
                          const struct fanotify_event_metadata *ev,
                          unsigned int response)
{
    UnansweredEvent *u;

    if (g_test_unanswered_alloc_fail)
        return -1; /* test seam: simulate the allocation failing */
    if (g_unanswered_count >= g_unanswered_cap)
    {
        int new_cap;
        UnansweredEvent *grown;

        if (g_unanswered_cap == 0)
            new_cap = UNANSWERED_MAX;
        else
        {
            /* Refuse a capacity that cannot be represented or whose
             * allocation size would overflow; the caller strands the
             * event fd instead of risking a wrapped allocation. */
            if (g_unanswered_cap > INT_MAX / 2 ||
                (size_t)g_unanswered_cap * 2 >
                    ((size_t)-1) / sizeof(UnansweredEvent))
                return -1;
            new_cap = g_unanswered_cap * 2;
        }
        grown = realloc(g_unanswered, (size_t)new_cap * sizeof(*grown));
        if (!grown)
            return -1;
        g_unanswered = grown;
        g_unanswered_cap = new_cap;
    }
    u = &g_unanswered[g_unanswered_count++];
    u->fd = event_fd;
    u->ev = *ev;
    u->response = response;
    return 0;
}

/* Park an event fd whose response could not be queued.  Returns 0 when
 * parked, -1 when the bounded list is full. */
static int stranded_add(int event_fd)
{
    if (g_stranded_count >= UNANSWERED_STRANDED_MAX)
        return -1;
    g_stranded[g_stranded_count++] = event_fd;
    return 0;
}

/* Shutdown: force-DENY and close every stranded event fd.  Runs before
 * close(fan_fd), after which the kernel would auto-ALLOW them. */
static void stranded_flush(int fan_fd)
{
    int denied = 0;

    for (int i = 0; i < g_stranded_count; i++)
    {
        int fd = g_stranded[i];
        int rc = write_response(fan_fd, fd, FAN_DENY);

        if (rc < 0)
            log_msg(LOG_ERR,
                    "fanotify stranded response could not be delivered for "
                    "fd %d; the kernel will allow it when the group closes",
                    fd);
        else
            denied++;
        close(fd);
    }
    if (denied > 0)
        log_msg(LOG_WARNING,
                "denied %d stranded permission event(s) before shutdown",
                denied);
    g_stranded_count = 0;
}

/*
 * Deliver queued responses.  Entries whose write still fails stay queued
 * for the next attempt; a delivered or already-answered event has its
 * event fd closed and its slot dropped.
 */
static void unanswered_retry(int fan_fd)
{
    for (int i = 0; i < g_unanswered_count;)
    {
        UnansweredEvent *u = &g_unanswered[i];
        int rc = write_response(fan_fd, u->fd, u->response);

        if (rc < 0)
        {
            i++;
            continue;
        }
        log_msg(LOG_INFO, "fanotify response retry: fd %d %s", u->fd,
                rc == 1 ? "was already answered" : "answered");
        unanswered_drop(i);
    }
}

/*
 * Shutdown: deliver everything still queued, forcing DENY when the
 * original response cannot be written.  Runs before close(fan_fd),
 * after which the kernel would auto-ALLOW every outstanding event.
 */
static void unanswered_flush(int fan_fd)
{
    while (g_unanswered_count > 0)
    {
        UnansweredEvent *u = &g_unanswered[0];
        int rc = write_response(fan_fd, u->fd, u->response);

        if (rc < 0)
        {
            log_msg(LOG_WARNING,
                    "fanotify response retry failed for fd %d; forcing DENY",
                    u->fd);
            rc = write_response(fan_fd, u->fd, FAN_DENY);
        }
        if (rc < 0)
            log_msg(LOG_ERR,
                    "fanotify response could not be delivered for fd %d; "
                    "the kernel will allow it when the group closes",
                    u->fd);
        unanswered_drop(0);
    }
}

/*
 * Respond to one event through the group fd.
 * Returns 0 when the response was delivered (or already delivered), so
 * the caller may close the event fd; -1 whenever it was NOT delivered,
 * so the caller MUST keep the event fd open.  On -1 the response is
 * queued in the growing retry queue, or -- when that cannot be allocated
 * -- parked in the bounded stranded list; the retry loop or the shutdown
 * drain answers it before close(fan_fd).  There is no third outcome: a
 * decided response is never abandoned.
 */
static int fanotify_respond(int fan_fd, const struct fanotify_event_metadata *ev,
                            unsigned int response)
{
    int rc = write_response(fan_fd, (int)ev->fd, response);

    if (rc == 0)
        return 0;
    if (rc == 1)
    {
        /* The kernel reports "response for this fd has already been
         * written" when a decision was already delivered (e.g. a
         * duplicate deferred event); not fatal. */
        log_msg(LOG_WARNING, "fanotify write response: already answered");
        return 0;
    }

    int err = errno;
    if (err != EAGAIN)
        g_fatal = 1; /* the group cannot deliver decisions; restart */

    if (unanswered_add((int)ev->fd, ev, response) == 0)
    {
        log_msg(LOG_WARNING,
                "fanotify write response: %s; response queued for retry",
                strerror(err));
        return -1;
    }

    if (stranded_add((int)ev->fd) == 0)
    {
        log_msg(LOG_WARNING,
                "fanotify write response: %s and the retry queue could not "
                "grow; fd %d held open for a shutdown FAN_DENY",
                strerror(err), (int)ev->fd);
        return -1;
    }

    log_msg(LOG_ERR,
            "fanotify write response: %s and both the retry queue and the "
            "stranded list are full; keeping event fd %d open (never "
            "silently dropped)",
            strerror(err), (int)ev->fd);
    g_fatal = 1;
    return -1;
}

/*
 * Claim the records left behind when an event walk exits early (fatal
 * response failure or metadata-version mismatch).  read(2) duplicated an
 * event fd for EVERY record in the batch, so every later record is now
 * open in this process with its permission event unanswered: an fd
 * nobody answers hangs its caller's open() until close(fan_fd) makes the
 * kernel AUTO-ALLOW it — the fail-open hole this closes — and an fd
 * nobody closes leaks descriptors.  Walk behind the caller's current
 * record, deny every permission event through fanotify_respond()'s
 * ownership contract (a queued retry keeps the fd open; the retry path
 * and the shutdown flush answer it), and close every other claimed fd.
 * A record whose length is malformed makes the rest of the batch
 * unlocatable; log that loudly rather than guessing positions.  Returns
 * the number of permission events denied.
 */
static int batch_abandon(int fan_fd,
                         const struct fanotify_event_metadata *ev,
                         ssize_t remaining)
{
    int malformed = 0;
    const struct fanotify_event_metadata *next =
        event_next(ev, &remaining, &malformed);
    int denied = 0;

    while (next)
    {
        if (!FAN_EVENT_OK(next, (size_t)remaining))
        {
            log_msg(LOG_ERR,
                    "abandoned fanotify batch: malformed record length %llu; "
                    "the rest of the batch (%zd bytes) cannot be claimed",
                    (unsigned long long)next->event_len, remaining);
            break;
        }
        if (next->vers == FANOTIFY_METADATA_VERSION &&
            (next->mask & FAN_OPEN_PERM) && next->fd != FAN_NOFD)
        {
            log_msg(LOG_DEBUG, "[abandon] DENY fd=%d pid=%d (walk abandoned)",
                    (int)next->fd, (int)next->pid);
            if (fanotify_respond(fan_fd, next, FAN_DENY) == -1)
                log_msg(LOG_INFO, "[abandon] DENY queued for retry fd=%d",
                        (int)next->fd); /* the retry queue owns the fd */
            else
                close((int)next->fd);
            denied++;
        }
        else if (next->fd != FAN_NOFD)
        {
            close((int)next->fd);
        }
        next = event_next(next, &remaining, &malformed);
    }

    if (malformed)
        log_msg(LOG_ERR,
                "abandoned fanotify batch: malformed record length; "
                "the rest of the batch (%zd bytes) cannot be claimed",
                remaining);

    if (denied > 0)
        log_msg(LOG_WARNING,
                "abandoned fanotify batch: denied %d unclaimed permission "
                "event(s) (fail closed)", denied);
    return denied;
}

/* Decide all permission events that fanotify_pump() had to defer. */
static int fanotify_process_pending(int fan_fd)
{
    int processed = 0;

    while (g_pending_count > 0)
    {
        PendingEvent ev = g_pending[0];
        memmove(&g_pending[0], &g_pending[1],
                sizeof(PendingEvent) * (size_t)(g_pending_count - 1));
        g_pending_count--;
        process_open_perm(fan_fd, &ev.meta, 0);
        processed++;
    }
    return processed;
}

/* Deny every deferred event (reload/shutdown/overflow, fail closed).  A
 * response that cannot be written is queued for retry and its event fd
 * stays open; the retry/flush paths answer it later. */
void fanotify_flush_pending(int fan_fd)
{
    int kept = 0;

    for (int i = 0; i < g_pending_count; i++)
    {
        if (fanotify_respond(fan_fd, &g_pending[i].meta, FAN_DENY) == -1)
            kept++; /* queued for retry; the event fd stays open */
        else
            close((int)g_pending[i].meta.fd);
    }
    if (g_pending_count > 0)
        log_msg(LOG_WARNING,
                "denied %d pending permission events (%d queued for retry)",
                g_pending_count - kept, kept);
    g_pending_count = 0;
}

/*
 * Deny and close every FAN_OPEN_PERM event still queued in the kernel.
 *
 * Closing the fanotify fd makes the kernel allow outstanding permission
 * events (fanotify(7): "Upon close(2), outstanding permission events
 * will be set to allowed"), so shutdown must drain the queue first and
 * respond FAN_DENY to everything.  Zero-timeout poll then read: the
 * daemon is single-threaded, so a readable poll guarantees read() will
 * not block.  Unrequested notification events just have their fd closed.
 */
void fanotify_drain_and_deny(int fan_fd)
{
    char buf[BUF_SIZE]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));
    int denied = 0;

    /* First deliver anything the retry queue is still holding, forcing
     * DENY when the original response cannot be written, then force-DENY
     * every stranded fd: after close(fan_fd) the kernel would allow all
     * of them. */
    unanswered_flush(fan_fd);
    stranded_flush(fan_fd);

    /* Then the kernel queue itself: from here each response is the last
     * chance before close(fan_fd) auto-ALLOWs whatever is left. */
    while (1)
    {
        struct pollfd pfd;
        pfd.fd = fan_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr;
        while ((pr = poll(&pfd, 1, 0)) < 0 && errno == EINTR)
            ; /* shutdown is signal-driven: retry, never abandon */
        if (pr <= 0 || !(pfd.revents & POLLIN))
            break;

        ssize_t n = read(fan_fd, buf, sizeof(buf));
        if (n < 0)
        {
            if (errno == EINTR)
                continue; /* interrupted drain leaves events unanswered */
            /* Readable race (event consumed elsewhere) ends the drain;
             * anything else is logged so the early exit is visible. */
            if (errno != EAGAIN)
                log_msg(LOG_WARNING, "fanotify drain read: %s",
                        strerror(errno));
            break;
        }
        if (n == 0)
            break;

        const struct fanotify_event_metadata *ev =
            (const struct fanotify_event_metadata *)buf;
        ssize_t remaining = n;
        int malformed = 0;

        while (FAN_EVENT_OK(ev, (size_t)remaining))
        {
            if (ev->vers == FANOTIFY_METADATA_VERSION &&
                (ev->mask & FAN_OPEN_PERM) && ev->fd != FAN_NOFD)
            {
                log_msg(LOG_DEBUG, "[drain] DENY fd=%d pid=%d (shutdown)",
                        (int)ev->fd, (int)ev->pid);
                if (write_response(fan_fd, (int)ev->fd, FAN_DENY) < 0)
                    log_msg(LOG_ERR,
                            "fanotify drain: response failed for fd %d; the "
                            "kernel will allow it when the group closes",
                            (int)ev->fd);
                close((int)ev->fd);
                denied++;
            }
            else if (ev->fd != FAN_NOFD)
            {
                close((int)ev->fd);
            }

            ev = event_next(ev, &remaining, &malformed);
            if (!ev)
                break;
        }
        if (malformed)
            log_batch_tail_lost(remaining);
    }

    if (denied > 0)
        log_msg(LOG_WARNING,
                "denied %d queued permission event(s) before shutdown",
                denied);
}

/*
 * Retry cadence while responses sit in the retry queue: poll() cannot
 * report "ready to write" for fanotify responses, so the loop wakes on
 * this timer -- short enough to deliver a queued response promptly,
 * long enough not to spin an idle daemon.
 */
#define UNANSWERED_RETRY_POLL_MS 250

/*
 * Main event loop.  Blocks in poll() on {group fd, wake pipe, control
 * listener}; wake_fd is the read end of a non-blocking pipe that the
 * signal handlers write a byte to (pass -1 when there is no wake pipe)
 * and control_fd is control_setup()'s non-blocking listening socket
 * (pass -1 when there is none).  The wake pipe makes signal delivery
 * observable even when a signal arrives between the outer flag check and
 * poll(): otherwise an idle marked filesystem could suspend
 * shutdown/reload until the next open, and a supervisor SIGKILL would
 * let the kernel auto-ALLOW every outstanding permission event on
 * close(fan_fd).  The group fd is permanently non-blocking (FAN_NONBLOCK
 * at init), so a read only happens after poll() reports readable; EAGAIN
 * is a spurious wake, not an error.
 *
 * A readable control fd is served through control_handle() -- a bounded,
 * non-blocking batch per wake, so a client can never block the loop.  A
 * control fd that reports POLLERR/POLLHUP/POLLNVAL is logged and dropped
 * from the poll set (the local copy is set to -1) instead of failing the
 * daemon: protection must outlive a CLI transport failure, and main.c
 * owns the fd's lifetime and teardown.
 *
 * Per-iteration order:
 *   1. retry queued responses, replay deferred events;
 *   2. poll, drain the wake pipe, serve one bounded control batch;
 *   3. on group-fd POLLIN walk one read(2) batch, dispatching each
 *      record by kind: metadata version, FAN_OPEN_PERM, create/moved-to
 *      notification, FAN_Q_OVERFLOW, other;
 *   4. exit on g_fatal/g_running/g_need_reload -- a g_fatal exit
 *      abandons (denies and closes) the records behind the fatal one;
 *   5. expire the file cache after a clean batch (100 events or 10 s).
 */
void fanotify_loop(int fd, int wake_fd, int control_fd)
{
    char buf[BUF_SIZE]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));
    const struct fanotify_event_metadata *ev;
    int event_cnt = 0;
    time_t last_expire = time(NULL);

    while (g_running && !g_need_reload)
    {
        /* Retry responses whose kernel write failed earlier. */
        if (g_unanswered_count > 0)
            unanswered_retry(fd);

        /* Replay events deferred while a dialog was open. */
        if (g_pending_count > 0)
        {
            fanotify_process_pending(fd);
            if (!g_running || g_need_reload || g_fatal)
                break;
        }

        /* {group fd, wake pipe, control listener}: up to three slot
         * entries, each optional except the group fd.  Named indices
         * keep the wake drain and the control drop working whatever the
         * optional set looks like this iteration. */
        struct pollfd pfds[3];
        nfds_t nfds = 0;
        int wake_idx = -1;
        int control_idx = -1;
        pfds[nfds].fd = fd;
        pfds[nfds].events = POLLIN;
        pfds[nfds].revents = 0;
        nfds++;
        if (wake_fd >= 0)
        {
            wake_idx = (int)nfds;
            pfds[nfds].fd = wake_fd;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            nfds++;
        }
        if (control_fd >= 0)
        {
            control_idx = (int)nfds;
            pfds[nfds].fd = control_fd;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            nfds++;
        }

        /* A queued response needs periodic retries even on an otherwise
         * idle filesystem; the fanotify poll() does not report POLLOUT. */
        int poll_timeout = (g_unanswered_count > 0) ? UNANSWERED_RETRY_POLL_MS : -1;
        int pr = poll(pfds, nfds, poll_timeout);
        if (pr < 0 && errno == EINTR)
        {
            /* Return to the loop top so g_running/g_need_reload are
             * re-checked for real.  Retrying poll inline instead would
             * swallow the wake before the flags can be seen: in the
             * documented no-wake-pipe degradation (main.c) this EINTR is
             * the ONLY observable signal delivery, so a swallowed one
             * leaves an idle daemon ignoring SIGTERM/SIGHUP until the
             * supervisor escalates to SIGKILL — and close(fan_fd) after
             * SIGKILL makes the kernel auto-ALLOW every outstanding
             * permission event. */
            continue;
        }
        if (pr <= 0)
            continue; /* retry tick (pr == 0) or transient poll error */

        /* Drain the wake pipe so a backlog of signal bytes cannot spin. */
        if (wake_idx >= 0 &&
            (pfds[wake_idx].revents & (POLLIN | POLLHUP | POLLERR)))
        {
            char wake[64];
            while (read(wake_fd, wake, sizeof(wake)) > 0)
                ;
        }

        /*
         * Serve at most one bounded batch of control clients per wake.
         * control_handle() is non-blocking by contract (bounded accepts,
         * bounded non-blocking reads per connection), so no retry or
         * wait belongs here and a client can never hold the loop.  A
         * broken listener
         * is dropped from this loop's poll set (the local copy is set to
         * -1) rather than closing it or failing the daemon: a CLI
         * transport failure must not stop protection, and main.c owns
         * the fd's lifetime.
         */
        if (control_idx >= 0)
        {
            if (pfds[control_idx].revents & (POLLERR | POLLHUP | POLLNVAL))
            {
                log_msg(LOG_WARNING,
                        "control socket poll error (revents=0x%x); no longer "
                        "polling it",
                        (unsigned)pfds[control_idx].revents);
                control_fd = -1;
            }
            else if (pfds[control_idx].revents & POLLIN)
            {
                control_handle(control_fd);
            }
        }

        if (pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL))
        {
            /* A broken group fd otherwise spins this loop at 100% CPU. */
            log_msg(LOG_ERR,
                    "fanotify group fd poll error (revents=0x%x); restarting",
                    (unsigned)pfds[0].revents);
            g_fatal = 1;
            break;
        }
        if (!(pfds[0].revents & POLLIN))
            continue; /* woke for the signal or the control client only */

        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN)
                continue; /* spurious wake on the non-blocking group fd */
            if (errno == EOVERFLOW)
            {
                /* Saturation reported as a read error instead of an event:
                 * same fail-closed path — deny deferred events, keep going. */
                log_msg(LOG_WARNING,
                        "fanotify read: EOVERFLOW (queue overflow); denying "
                        "%d deferred permission events (fail closed)",
                        g_pending_count);
                fanotify_flush_pending(fd);
                continue;
            }
            log_msg(LOG_ERR, "fanotify read: %s", strerror(errno));
            g_fatal = 1;
            break;
        }

        ev = (const struct fanotify_event_metadata *)buf;
        {
            ssize_t remaining = n;
            int malformed = 0;

            while (FAN_EVENT_OK(ev, (size_t)remaining))
            {
                if (ev->vers != FANOTIFY_METADATA_VERSION)
                {
                    /* A metadata-version mismatch means the event stream
                     * cannot be interpreted at all (fanotify(7)):
                     * abandon the group and let the supervisor restart
                     * cleanly instead of parsing an unreadable stream.
                     * Deny before closing (the fd offset never moved;
                     * close-without-response only postpones the decision
                     * to the kernel's auto-ALLOW at group close).  The
                     * records behind this one are claimed at the
                     * g_fatal exit below. */
                    if (ev->fd != FAN_NOFD)
                    {
                        if (fanotify_respond(fd, ev, FAN_DENY) != -1)
                            close((int)ev->fd);
                    }
                    log_msg(LOG_ERR,
                            "fanotify metadata version mismatch; stopping");
                    g_fatal = 1;
                }
                else if (ev->mask & FAN_OPEN_PERM)
                {
                    process_open_perm(fd, ev, 0);
                }
                else if (ev->mask & (FAN_CREATE | FAN_MOVED_TO))
                {
                    handle_notification_event(fd, ev);
                }
                else if (ev->mask & FAN_Q_OVERFLOW)
                {
                    /* Saturation: events were dropped.  Fail closed by
                     * denying every permission event we had deferred —
                     * their opens are still suspended and must not wait
                     * on decisions made against lost state. */
                    log_msg(LOG_WARNING,
                            "fanotify queue overflow; events were lost — "
                            "denying %d deferred permission events (fail closed)",
                            g_pending_count);
                    fanotify_flush_pending(fd);
                }
                else if (ev->fd != FAN_NOFD)
                {
                    close((int)ev->fd);
                }

                if (g_fatal)
                {
                    /* Claim the records this walk exited in front of:
                     * their fds are already duplicated into this process
                     * and their permission events would otherwise
                     * auto-ALLOW at close(fan_fd) during shutdown.
                     * Only g_fatal exits the walk early: a pending
                     * shutdown/reload lets this batch finish in place
                     * (the group fd can still deliver decisions), while
                     * a fatal group failure cannot answer the rest. */
                    batch_abandon(fd, ev, remaining);
                    break;
                }
                ev = event_next(ev, &remaining, &malformed);
                if (!ev)
                    break;
            }
            if (malformed)
                log_batch_tail_lost(remaining);
        }

        if (!g_running || g_need_reload || g_fatal)
            break;

        /* periodic cache expiry — every 100 events or 10 seconds */
        event_cnt++;
        {
            time_t now = time(NULL);
            if (event_cnt >= 100 || difftime(now, last_expire) >= 10.0)
            {
                cache_expire();
                event_cnt = 0;
                last_expire = now;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Public API: dynamic allowlist / denylist persistence              */
/* ------------------------------------------------------------------ */

void fanotify_set_state_files(const char *allow_path, const char *deny_path)
{
    if (!allow_path || allow_path[0] == '\0')
    {
        memcpy(g_dyn_state_file, PERSIST_STATE_FILE,
               sizeof(PERSIST_STATE_FILE));
    }
    else if (strlen(allow_path) >= sizeof(g_dyn_state_file))
    {
        log_msg(LOG_ERR, "fanotify_set_state_files: allow path too long");
    }
    else
    {
        memcpy(g_dyn_state_file, allow_path, strlen(allow_path) + 1);
    }

    if (!deny_path || deny_path[0] == '\0')
    {
        memcpy(g_dyn_deny_state_file, PERSIST_DENY_STATE_FILE,
               sizeof(PERSIST_DENY_STATE_FILE));
    }
    else if (strlen(deny_path) >= sizeof(g_dyn_deny_state_file))
    {
        log_msg(LOG_ERR, "fanotify_set_state_files: deny path too long");
    }
    else
    {
        memcpy(g_dyn_deny_state_file, deny_path, strlen(deny_path) + 1);
    }
}

void fanotify_load_dyn_allowlist(const PersistEntry *entries, int count)
{
    int migrated = load_dyn_list(g_dyn_allow, &g_dyn_allow_count, entries,
                                 count, "always-allow", 1, 1, 1);

    /* Persist the migration immediately so the IDs survive a restart
     * (the next load would regenerate exactly the same IDs).  A failed
     * write keeps the in-memory IDs; the entry itself stays usable. */
    if (migrated > 0)
    {
        log_msg(LOG_INFO, "migrated %d always-allow rule ID(s)", migrated);
        if (persist_dyn_list(0, g_dyn_allow, g_dyn_allow_count) < 0)
            log_msg(LOG_WARNING,
                    "migrated always-allow rule IDs were kept in memory but "
                    "not persisted");
    }
}

void fanotify_load_dyn_denylist(const PersistEntry *entries, int count)
{
    int migrated = load_dyn_list(g_dyn_deny, &g_dyn_deny_count, entries,
                                 count, "always-deny", 0, 1, 1);

    if (migrated > 0)
    {
        log_msg(LOG_INFO, "migrated %d always-deny rule ID(s)", migrated);
        if (persist_dyn_list(1, g_dyn_deny, g_dyn_deny_count) < 0)
            log_msg(LOG_WARNING,
                    "migrated always-deny rule IDs were kept in memory but "
                    "not persisted");
    }
}

int fanotify_remove_dyn_entry(int deny, const char *id)
{
    DynEntry *list = deny ? g_dyn_deny : g_dyn_allow;
    int *count = deny ? &g_dyn_deny_count : &g_dyn_allow_count;
    const char *name = dyn_list_name(deny);
    const char *id_ptrs[DYN_MAX] = {0}; /* n 0 passes an empty list */
    int idx_map[DYN_MAX];
    int ambiguous = 0;
    int n = 0;
    int match;
    int idx;
    int snap_count;

    if (!dyn_lookup_id_valid(id))
    {
        log_msg(LOG_WARNING, "remove %s: invalid rule ID argument", name);
        return -1;
    }

    /* Resolve through the CLI's matcher: an unambiguous 8..16-character
     * lower-case hex prefix (full ID allowed).  Entries with an empty ID
     * do not participate; a malformed non-empty ID means the live list
     * cannot be trusted, so the removal fails closed.
     *
     * ruleid_find() runs over the compact id_ptrs[]; idx_map[] maps the
     * index it returns back to the live list. */
    for (int i = 0; i < *count; i++)
    {
        if (list[i].rule_id[0] == '\0')
            continue;
        if (!dyn_rule_id_valid(list[i].rule_id))
        {
            log_msg(LOG_ERR,
                    "remove %s: entry \"%s\" has no usable rule ID; refusing",
                    name, list[i].binary);
            return -1;
        }
        id_ptrs[n] = list[i].rule_id;
        idx_map[n] = i;
        n++;
    }

    match = ruleid_find(id_ptrs, n, id, &ambiguous);
    if (match < 0)
    {
        if (ambiguous)
        {
            log_msg(LOG_WARNING,
                    "remove %s: ID %s matches more than one rule; "
                    "nothing removed",
                    name, id);
            return -2;
        }
        return 0; /* well-formed prefix, but no stored ID matches it */
    }
    idx = idx_map[match];

    /* Snapshot before mutating so a failed state write restores the
     * pre-removal list exactly (pin.c's guarantee). */
    memcpy(g_dyn_snapshot, list, sizeof(g_dyn_snapshot));
    snap_count = *count;

    *count = dyn_compact(list, *count, &idx, 1);

    if (persist_dyn_list(deny, list, *count) < 0)
    {
        memcpy(list, g_dyn_snapshot, sizeof(g_dyn_snapshot));
        *count = snap_count;
        return -1;
    }

    /* The live list no longer holds the removed entry: log its fields
     * from the pre-removal snapshot. */
    log_msg(LOG_INFO, "removed %s rule %s (%s)", name,
            g_dyn_snapshot[idx].rule_id, g_dyn_snapshot[idx].binary);
    return 1;
}

int fanotify_clear_dyn_list(int deny)
{
    DynEntry *list = deny ? g_dyn_deny : g_dyn_allow;
    int *count = deny ? &g_dyn_deny_count : &g_dyn_allow_count;
    const char *name = dyn_list_name(deny);
    int snap_count = *count;

    memcpy(g_dyn_snapshot, list, sizeof(g_dyn_snapshot));
    memset(list, 0, sizeof(DynEntry) * DYN_MAX);
    *count = 0;

    if (persist_dyn_list(deny, list, 0) < 0)
    {
        memcpy(list, g_dyn_snapshot, sizeof(g_dyn_snapshot));
        *count = snap_count;
        return -1;
    }

    log_msg(LOG_INFO, "cleared %d %s rule(s)", snap_count, name);
    return snap_count;
}

int fanotify_prune_dyn_list(int deny, int *removed_out)
{
    DynEntry *list = deny ? g_dyn_deny : g_dyn_allow;
    int *count = deny ? &g_dyn_deny_count : &g_dyn_allow_count;
    const char *name = dyn_list_name(deny);
    PersistEntry *rows = NULL;
    PruneGroup *groups = NULL;
    int *removals = NULL;
    int removal_count = 0;
    int group_count = 0;
    int n = 0;
    int snap_count = 0;
    int rc = -1;

    if (removed_out)
        *removed_out = 0; /* never leave a stale count on the failure exits */

    /* Only groups of >= 2 members are reported, so the group table
     * needs at most n/2 + 1 slots; removals can cover every entry. */
    rows = calloc(DYN_MAX, sizeof(PersistEntry));
    groups = calloc(DYN_MAX / 2 + 1, sizeof(PruneGroup));
    removals = calloc(DYN_MAX, sizeof(int));
    if (!rows || !groups || !removals)
    {
        log_msg(LOG_ERR, "out of memory pruning %s", name);
        goto out;
    }

    /* prune_find() reports indices into the PersistEntry rows, which
     * mirror the live array 1:1 (dyn_to_persist copies in order), so the
     * same ascending removal list compacts the DynEntry list directly. */
    n = dyn_to_persist(list, *count, rows, DYN_MAX);
    group_count = prune_find(rows, n, groups, DYN_MAX / 2 + 1, removals,
                             DYN_MAX, &removal_count);
    if (group_count < 0)
    {
        log_msg(LOG_ERR, "prune %s: duplicate grouping failed", name);
        goto out;
    }
    if (removal_count == 0)
    {
        rc = 0;
        goto out;
    }

    memcpy(g_dyn_snapshot, list, sizeof(g_dyn_snapshot));
    snap_count = *count;
    *count = dyn_compact(list, *count, removals, removal_count);
    int removed_now = snap_count - *count;

    if (persist_dyn_list(deny, list, *count) < 0)
    {
        memcpy(list, g_dyn_snapshot, sizeof(g_dyn_snapshot));
        *count = snap_count;
        goto out;
    }

    /* removals[] indexes the pre-prune snapshot: the live list is
     * already compacted behind it. */
    for (int i = 0; i < removal_count; i++)
        log_msg(LOG_INFO, "pruned %s rule %s (%s)", name,
                g_dyn_snapshot[removals[i]].rule_id,
                g_dyn_snapshot[removals[i]].binary);
    log_msg(LOG_INFO, "prune %s: removed %d duplicate rule(s), %d kept",
            name, removed_now, *count);
    if (removed_out)
        *removed_out = removed_now;
    rc = 0;

out:
    free(rows);
    free(groups);
    free(removals);
    return rc;
}

/* ------------------------------------------------------------------ */
/*  Test seams (see fanotify.h)                                       */
/* ------------------------------------------------------------------ */

/* Test-seam chain provider: the synthetic zero-depth chain is the ctx. */
static const ProcChain *test_chain_provider(void *ctx)
{
    return (const ProcChain *)ctx;
}

/* Fixed-fingerprint provider for the matcher seams: the synthetic test
 * request carries its precomputed fingerprint as the context. */
static const char *test_fp_provider(void *ctx)
{
    return (const char *)ctx;
}

int fanotify_test_dyn_allow_match(const char *binary, const char *bin_sha512,
                                  const char *target, const char *cmdline_fp)
{
    ProcChain chain;
    memset(&chain, 0, sizeof(chain));
    return dyn_allow_match(binary, bin_sha512, test_chain_provider, &chain,
                           target, test_fp_provider, (void *)cmdline_fp);
}

int fanotify_test_dyn_deny_match(const char *binary, const char *bin_sha512,
                                 const char *target, const char *cmdline_fp)
{
    ProcChain chain;
    memset(&chain, 0, sizeof(chain));
    return dyn_deny_match(binary, bin_sha512, test_chain_provider, &chain,
                          target, test_fp_provider, (void *)cmdline_fp);
}

int fanotify_test_cmdline_fingerprint(pid_t pid, char hex_out[129])
{
    return read_cmdline_fingerprint(pid, hex_out);
}

int fanotify_test_fastpath_allows(dev_t dev, ino_t ino, const char *path)
{
    return mount_noise_allows(dev, ino, is_path_under_protected(path));
}

int fanotify_test_resolve_path(int fd, char *out, size_t outsz)
{
    return resolve_fd_path(fd, out, outsz);
}

int fanotify_test_unsafe_first_hit(pid_t pid)
{
    return unsafe_first_hit(pid);
}

/*
 * Test seam (fanotify.h): run batch_abandon() on a synthetic batch the
 * caller assembled.  Passing a pipe write-end as group_fd makes every
 * fanotify_respond() write succeed (returns 0, no retry queue, no g_fatal
 * side effect), so the seam denies and closes each claimed event fd in
 * isolation.  Returns the number of permission events denied.
 */
int fanotify_test_batch_abandon(int group_fd,
                                const struct fanotify_event_metadata *ev,
                                ssize_t remaining)
{
    return batch_abandon(group_fd, ev, remaining);
}

/*
 * Test seam (fanotify.h): event_next()'s tri-state.  Returns the next
 * batch record or NULL; *malformed is 1 only when an invalid event_len
 * makes the rest of the batch unlocatable, 0 for a clean end.
 */
const struct fanotify_event_metadata *
fanotify_test_event_next(const struct fanotify_event_metadata *ev,
                         ssize_t *remaining, int *malformed)
{
    return event_next(ev, remaining, malformed);
}

/*
 * Test seam (fanotify.h): event_resolve()'s FAN_NOFD branch.  Runs the
 * real stage-1 check on a synthetic context whose event fd is FAN_NOFD
 * and returns its verdict (1 = handled).  group_fd (a pipe write end
 * stands in for the group) must receive NO fanotify_response bytes:
 * there is no event fd to answer, the kernel already denied the event,
 * and a write with fd=-1 would earn EINVAL -> g_fatal -> a phantom retry.
 */
int fanotify_test_resolve_nofd(int group_fd)
{
    struct fanotify_event_metadata ev;
    EventCtx c;

    memset(&ev, 0, sizeof(ev));
    ev.event_len = sizeof(ev);
    ev.vers = FANOTIFY_METADATA_VERSION;
    ev.metadata_len = sizeof(ev);
    ev.mask = FAN_OPEN_PERM;
    ev.fd = FAN_NOFD;
    ev.pid = (int)getpid();

    memset(&c, 0, sizeof(c));
    c.fan_fd = group_fd;
    c.ev = &ev;
    c.fd_num = FAN_NOFD;
    return event_resolve(&c);
}

/*
 * Test seams (fanotify.h): the failed-response retry queue.
 * fanotify_test_respond() runs the real fanotify_respond() so the
 * queue-growth, stranded-fallback and return contract can be driven with
 * a pipe stand-in for the group fd (a full non-blocking pipe makes every
 * write fail with EAGAIN, deterministically and without root).  The
 * count seams expose the queue/stranded depth; the force seam makes the
 * next queue admission fail, as if its allocation failed, so the bounded
 * stranded fallback is reachable without real memory pressure.
 */
int fanotify_test_respond(int group_fd,
                          const struct fanotify_event_metadata *ev,
                          unsigned int response)
{
    return fanotify_respond(group_fd, ev, response);
}

int fanotify_test_unanswered_count(void)
{
    return g_unanswered_count;
}

int fanotify_test_stranded_count(void)
{
    return g_stranded_count;
}

void fanotify_test_force_unanswered_alloc_fail(int on)
{
    g_test_unanswered_alloc_fail = on;
}

/* Test seam (fanotify.h): the pump stack's published dialog pid. */
pid_t fanotify_test_active_dialog_pid(void)
{
    return g_active_dialog_pid;
}

/*
 * Config-section test seams: same matchers the decision pipeline uses,
 * callable without a kernel permission event.  The allow seam returns
 * the matched rule's canonical binary pattern (the hash-pin key) or
 * NULL, and stores the rule's target_path into *grant_target (NULL for
 * a global rule) when that pointer is non-NULL.  The unsafe seam is
 * [unsafe_allowlist] only, and the deny seam returns the [denylist]
 * verdict (non-zero = denied).
 */
const char *fanotify_test_config_allow_match(const char *binary,
                                             const char *target,
                                             const char **grant_target)
{
    const RuleEntry *rule = allowlist_match(binary, target);

    if (grant_target)
    {
        *grant_target = NULL;
        if (rule && rule->target_path[0])
            *grant_target = rule->target_path;
    }
    return rule ? rule->binary : NULL;
}

const char *fanotify_test_unsafe_allow_match(const char *binary,
                                             const char *target)
{
    const RuleEntry *rule = unsafe_allowlist_match(binary, target);

    return rule ? rule->binary : NULL;
}

int fanotify_test_config_deny_match(const char *binary, const char *target)
{
    return denylist_match(binary, target) != NULL;
}

/*
 * Hash-pin verdict seam: run config_allow_pin_verdict() for the first
 * [allowlist] rule matching (binary, target).  Return codes:
 *   0 ALLOW            stored pin matches; a first-use rule is also
 *                      reported as ALLOW (the pipeline stores the digest
 *                      and grants -- the store is covered by
 *                      fanotify_test_pin_first_seen())
 *   1 CHANGED          stored digest differs; old digest copied to old_out
 *   2 NO_SILENT_GRANT  pin table damaged or bin_sha512 empty/missing
 *   3 NO_MATCH         no [allowlist] rule matches
 * Side-effect free: it never stores a pin and never prompts.
 */
int fanotify_test_allowlist_verdict(const char *binary,
                                    const char *bin_sha512,
                                    const char *target,
                                    char old_out[129])
{
    const RuleEntry *rule = allowlist_match(binary, target);
    int verdict;

    if (!rule)
    {
        if (old_out)
            old_out[0] = '\0';
        return 3; /* NO_MATCH */
    }

    verdict = config_allow_pin_verdict(rule, bin_sha512, old_out);
    return verdict == ALLOWLIST_PIN_FIRST_USE ? 0 : verdict;
}

/*
 * First-seen store seam: the pipeline's first-use branch exactly --
 * precondition "no pin for the matched rule", action "immediate atomic
 * pin_store() of bin_sha512 under the rule's canonical binary pattern".
 * Returns 0 on success; -1 when no rule matches, the rule already has a
 * pin (the pipeline would take the changed path instead), or the store
 * fails.
 */
int fanotify_test_pin_first_seen(const char *binary, const char *bin_sha512,
                                 const char *target)
{
    const RuleEntry *rule = allowlist_match(binary, target);

    if (!rule)
    {
        log_msg(LOG_WARNING,
                "pin_first_seen: no allowlist rule matches %s -> %s",
                binary, target);
        return -1;
    }
    if (pin_check(rule->binary, bin_sha512, NULL) != PIN_CHECK_FIRST_USE)
    {
        log_msg(LOG_WARNING,
                "pin_first_seen: rule %s is not in first-use state",
                rule->binary);
        return -1;
    }
    return config_allow_pin_first_seen(rule, bin_sha512);
}

/*
 * Test seam (fanotify.h): fanotify_pump() with g_pump_in_pipeline forced
 * to the state hash_wait_pump creates while a hash helper waits inside a
 * defer-mode decision.  Saves and restores the flag exactly like the
 * guard's set/clear pair around process_open_perm, so the nested branch
 * (cheap fast-path allow / defer — never a recursive pipeline run) is
 * reachable from a test without a live hash wait.  Returns the pump's
 * responded-event count.
 */
int fanotify_test_pump_nested(int fan_fd, pid_t dialog_pid)
{
    int saved = g_pump_in_pipeline;
    int responded;

    g_pump_in_pipeline = 1;
    responded = fanotify_pump(fan_fd, dialog_pid);
    g_pump_in_pipeline = saved;
    return responded;
}
