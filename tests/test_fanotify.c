/*
 * test_fanotify: mark mask, bounded event queue + fail-closed saturation
 * handling.
 *
 * Part 0 (runs unprivileged): the mark mask must be free of FID-requiring
 * directory-entry events.  Regression guard for EINVAL on every directory
 * mark when FAN_CREATE/FAN_MOVED_TO were added to this fd-based group.
 *
 * Part 1 (runs unprivileged): the deferred-event boundary.  A pipe stands
 * in for the fanotify group fd — fanotify_respond() only writes a
 * struct fanotify_response to it, so the flush contract (one FAN_DENY
 * response per deferred event, deferred fds closed) is verifiable
 * without a real fanotify group.
 *
 * Part 2 (needs CAP_SYS_ADMIN; skips otherwise): a real kernel fanotify
 * group created WITHOUT FAN_UNLIMITED_QUEUE must report FAN_Q_OVERFLOW
 * once the bounded queue saturates.  This uses notification events only:
 * permission-event saturation cannot be exercised without deliberately
 * blocking a listener, and note that a *bounded* permission queue is
 * fail-open (the kernel drops the event and allows the access), which is
 * why the daemon itself uses FAN_UNLIMITED_QUEUE.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <sys/fanotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/fanotify.h"
#include "../src/config.h"
#include "../src/cache.h"
#include "../src/inode.h"
#include "../src/notify.h"
#include "../src/pin.h"
#include "../src/session.h"
#include "../src/sha512.h"
#include "../src/utils.h"

/* Globals referenced by fanotify.c (normally defined in main.c). */
volatile sig_atomic_t g_running = 1;
volatile sig_atomic_t g_need_reload = 0;
volatile sig_atomic_t g_fatal = 0;

static int failures = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", (msg)); \
        failures++; \
    } \
} while(0)

/*
 * Convenience wrappers for the matcher seams: fingerprint the command
 * line the way an event would, then run the matcher.  The seams take a
 * precomputed fingerprint so the benchmark can measure matcher cost
 * without the hash.
 */
static int test_match_allow(const char *binary, const char *sha,
                            const char *target, const char *cmdline)
{
    char fp[129];
    if (!cmdline || sha512_string(cmdline, fp) != 0)
        return 0;
    return fanotify_test_dyn_allow_match(binary, sha, target, fp);
}

static int test_match_deny(const char *binary, const char *sha,
                           const char *target, const char *cmdline)
{
    char fp[129];
    if (!cmdline || sha512_string(cmdline, fp) != 0)
        return 0;
    return fanotify_test_dyn_deny_match(binary, sha, target, fp);
}

/*
 * Part 0: the mark mask must not contain FID-requiring directory-entry
 * events.  Adding FAN_CREATE/FAN_MOVED_TO to a group initialized without
 * FAN_REPORT_FID makes fanotify_mark() fail with EINVAL, which breaks
 * every directory mark (fanotify_mark(2), ERRORS).
 */
static void test_mark_mask_rejects_fid_events(void) {
    const unsigned int mask = fanotify_mark_mask();
    const unsigned int fid_only =
        FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO |
        FAN_ATTRIB | FAN_DELETE_SELF;

    ASSERT((mask & FAN_OPEN_PERM) != 0, "mark mask includes FAN_OPEN_PERM");
    ASSERT((mask & FAN_EVENT_ON_CHILD) != 0,
           "mark mask includes FAN_EVENT_ON_CHILD");
    ASSERT((mask & fid_only) == 0,
           "mark mask contains no FID-requiring dirent events");
}

/*
 * Part 0b: a configured path that does not exist is skipped (returns 1)
 * rather than treated as a fatal mark failure, and skipping registers no
 * mark state.  The default config lists many secrets paths that may not
 * exist on a given machine; those must not crash the daemon.
 */
static void test_missing_path_is_skipped(void) {
    ASSERT(fanotify_any_mark_active() == 0, "no mark state before skip test");
    int rc = fanotify_add_mark(-1, "/nonexistent/fileshield/missing-secret");
    ASSERT(rc == 1, "missing configured path is skipped (rc 1)");
    ASSERT(fanotify_any_mark_active() == 0, "skipped path adds no mark state");

    /* An existing path with an unusable group fd is a real failure. */
    rc = fanotify_add_mark(-1, "/");
    ASSERT(rc == -1, "existing path mark failure is fatal (rc -1)");
    ASSERT(fanotify_any_mark_active() == 0, "failed mark adds no state");
}

/*
 * Part 0c: glob entries protect through the fast-path verdict.
 * fanotify_test_fastpath_allows() is the same classification the mount
 * fast path uses: 0 means "protected, needs a decision", 1 means
 * "mount-mark noise, allow instantly".
 */
static void test_glob_protected_verdict(void) {
    static Config cfg;
    const char *base = "/home/u/.cloudflared";

    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.protected[0].path, sizeof(cfg.protected[0].path),
             "%s", "/home/u/.cloudflared/*.json");
    cfg.protected[0].is_glob = 1;
    cfg.protected[0].base_len = (int)strlen(base);
    snprintf(cfg.protected[1].path, sizeof(cfg.protected[1].path),
             "%s", "/home/u/.cloudflared/**/*.json");
    cfg.protected[1].is_glob = 1;
    cfg.protected[1].base_len = (int)strlen(base);
    snprintf(cfg.protected[2].path, sizeof(cfg.protected[2].path),
             "%s", "/home/u/.ssh");
    cfg.protected[2].is_glob = 0;
    cfg.protected[2].base_len = (int)strlen(cfg.protected[2].path);
    cfg.protected_count = 3;

    Config *saved = g_config;
    g_config = &cfg;
    inode_set_clear();

    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.cloudflared/abc.json") == 0,
           "glob matches a direct child");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.cloudflared/a/b/c.json") == 0,
           "globstar matches nested files");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.cloudflared/cert.pem") == 1,
           "non-matching file under the base is mount-mark noise");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.cloudflared/sub/abc.txt") == 1,
           "non-matching nested file is mount-mark noise");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.cloudflaredX/abc.json") == 1,
           "glob base boundary is respected");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/other/abc.json") == 1,
           "path outside the base is not protected");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/id_rsa") == 0,
           "exact entry still protects its subtree");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.sshd/x") == 1,
           "exact entry boundary unchanged");

    g_config = saved;
    inode_set_clear();
}

/*
 * Part 0d: a glob entry whose base does not exist is skipped like a
 * missing exact path (rc 1, no mark state), keeping startup's skipped
 * accounting and the mount-mark fallback intact.
 */
static void test_glob_missing_base_is_skipped(void) {
    ProtectedPath pp;
    memset(&pp, 0, sizeof(pp));
    snprintf(pp.path, sizeof(pp.path),
             "/nonexistent/fileshield/globbase_%d/*.json", (int)getpid());
    pp.is_glob = 1;
    pp.base_len = (int)(strlen(pp.path) - strlen("/*.json"));

    int rc = fanotify_add_protected(-1, &pp);
    ASSERT(rc == 1, "missing glob base is skipped (rc 1)");
    ASSERT(fanotify_any_mark_active() == 0, "missing glob base adds no mark state");

    ProtectedPath exact;
    memset(&exact, 0, sizeof(exact));
    snprintf(exact.path, sizeof(exact.path),
             "/nonexistent/fileshield/missing-exact_%d", (int)getpid());
    exact.base_len = (int)strlen(exact.path);

    rc = fanotify_add_protected(-1, &exact);
    ASSERT(rc == 1, "missing exact entry is skipped (rc 1)");
    ASSERT(fanotify_any_mark_active() == 0, "missing exact entry adds no state");
}

/*
 * Part 0e: the kernel reports unlinked-but-open fds as
 * "/path (deleted)"; resolve_fd_path() strips the marker so a deleted
 * protected file still resolves to (and matches) its real path.
 */
static void test_deleted_suffix_stripped(void) {
    char dir[] = "/tmp/fileshield_del_XXXXXX";
    char path[PATH_MAX];
    char link[64];
    char raw[PATH_MAX];
    char resolved[PATH_MAX];

    if (!mkdtemp(dir)) {
        fprintf(stderr, "FAIL: mkdtemp for deleted-suffix test: %s\n",
                strerror(errno));
        failures++;
        return;
    }

    snprintf(path, sizeof(path), "%s/secret", dir);
    int fd = open(path, O_CREAT | O_RDWR, 0600);
    ASSERT(fd >= 0, "create file for deleted-suffix test");
    if (fd < 0) {
        rmdir(dir);
        return;
    }
    ASSERT(unlink(path) == 0, "unlink the open file");

    /* The kernel must report the marker, or the strip is untested. */
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, raw, sizeof(raw) - 1);
    ASSERT(n > 0, "readlink the deleted fd");
    if (n > 0) {
        raw[n] = '\0';
        ASSERT(strlen(raw) >= sizeof(" (deleted)") - 1 &&
               strcmp(raw + strlen(raw) - (sizeof(" (deleted)") - 1),
                      " (deleted)") == 0,
               "kernel reports the deleted marker");
    }

    ASSERT(fanotify_test_resolve_path(fd, resolved, sizeof(resolved)) == 0,
           "resolve the deleted fd path");
    ASSERT(strstr(resolved, " (deleted)") == NULL, "deleted marker stripped");
    ASSERT(strstr(resolved, "secret") != NULL, "real path preserved");

    close(fd);
    rmdir(dir);
}

/*
 * Part 0e2: resolve_fd_path() rejects a truncated readlink() result.  The
 * kernel fills the buffer without a NUL terminator and readlink(2)
 * returns the number of bytes it would have written; a return of outsz-1
 * is either a path that did not fit or one that exactly filled the
 * buffer.  Both are unverifiable, so the resolver must fail — a partial
 * path must never be treated as a match — exactly like proc_exe_path().
 */
static void test_resolve_path_truncation_rejected(void) {
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT(fd >= 0, "open /dev/null for resolve-truncation test");
    if (fd < 0)
        return;

    /* "/dev/null" is 9 bytes: an 11-byte buffer accepts it with one spare
     * byte; a 10-byte buffer receives exactly outsz-1 bytes and is
     * rejected as unverifiable. */
    char roomy[11];
    char exact[10];
    char tiny[4];

    ASSERT(fanotify_test_resolve_path(fd, roomy, sizeof(roomy)) == 0,
           "a path that fits with room to spare resolves");
    ASSERT(strcmp(roomy, "/dev/null") == 0, "the resolved path is exact");

    ASSERT(fanotify_test_resolve_path(fd, exact, sizeof(exact)) == -1,
           "a readlink result exactly filling the buffer is rejected");
    ASSERT(fanotify_test_resolve_path(fd, tiny, sizeof(tiny)) == -1,
           "a clearly truncated readlink result is rejected");

    close(fd);
}

/*
 * Part 0f: '!' exclusions are deny-wins and order-independent.  The
 * exclusion is listed before the positive to prove that config order
 * does not matter.
 */
static void test_exclusions_deny_wins(void) {
    static Config cfg;
    const char *base = "/home/u/.ssh";

    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.protected[0].path, sizeof(cfg.protected[0].path),
             "%s", "/home/u/.ssh/*.pub");
    cfg.protected[0].is_glob = 1;
    cfg.protected[0].is_exclude = 1;
    cfg.protected[0].base_len = (int)strlen(base);
    snprintf(cfg.protected[1].path, sizeof(cfg.protected[1].path),
             "%s", base);
    cfg.protected[1].is_glob = 0;
    cfg.protected[1].base_len = (int)strlen(base);
    cfg.protected_count = 2;
    cfg.exclude_count = 1;
    cfg.exclude_idx[0] = 0; /* the exclusion's protected[] index */

    Config *saved = g_config;
    g_config = &cfg;
    inode_set_clear();

    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/id_ed25519") == 0,
           "private key stays protected");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/id_ed25519.pub") == 1,
           "excluded public key is allowed as mount-mark noise");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/sub/id_ed25519.pub") == 0,
           "single '*' exclusion does not cross segments");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/id_ed25519.pub.bak") == 0,
           "exclusion requires the full file-name match");

    /* A '**' exclusion reaches nested files and zero segments. */
    snprintf(cfg.protected[0].path, sizeof(cfg.protected[0].path),
             "%s", "/home/u/.ssh/**/*.pub");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/id_ed25519.pub") == 1,
           "globstar exclusion matches zero segments");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/sub/id_ed25519.pub") == 1,
           "globstar exclusion matches nested files");

    /*
     * Non-zero exclusion index: the exclusion sits after the positives in
     * protected[], so a matcher that assumes exclude_idx == 0 (the old
     * accidentally-passing setup) would miss it and wrongly treat the
     * excluded files as protected.
     */
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.protected[0].path, sizeof(cfg.protected[0].path), "%s",
             "/home/u/.ssh");
    cfg.protected[0].base_len = (int)strlen(cfg.protected[0].path);
    snprintf(cfg.protected[1].path, sizeof(cfg.protected[1].path), "%s",
             "/home/u/.ssh/sub/*.pub");
    cfg.protected[1].is_glob = 1;
    cfg.protected[1].is_exclude = 1;
    cfg.protected[1].base_len = (int)strlen("/home/u/.ssh/sub");
    snprintf(cfg.protected[2].path, sizeof(cfg.protected[2].path), "%s",
             "/home/u/.ssh/sub");
    cfg.protected[2].base_len = (int)strlen(cfg.protected[2].path);
    cfg.protected_count = 3;
    cfg.exclude_count = 1;
    cfg.exclude_idx[0] = 1;

    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/sub/key.pub") == 1,
           "exclusion recorded at a non-zero index is honored");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/sub/key") == 0,
           "the positive entry at index 2 still protects");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/top.pub") == 0,
           "a non-matching exclusion leaves other paths protected");

    g_config = saved;
    inode_set_clear();
}

/*
 * Part 0g: an exclusion entry is never marked: fanotify_add_protected()
 * returns 0 without touching the mark table or the inode set.
 */
static void test_exclusion_is_not_marked(void) {
    ProtectedPath pp;
    memset(&pp, 0, sizeof(pp));
    snprintf(pp.path, sizeof(pp.path), "%s", "/home/u/.ssh/*.pub");
    pp.is_glob = 1;
    pp.is_exclude = 1;
    pp.base_len = (int)strlen("/home/u/.ssh");

    int rc = fanotify_add_protected(-1, &pp);
    ASSERT(rc == 0, "exclusion adds no mark (rc 0)");
    ASSERT(fanotify_any_mark_active() == 0, "exclusion adds no mark state");
}

/*
 * Part 0h: config rule matching.  [allowlist], [unsafe_allowlist] and
 * [denylist] accept globs on either side through the same engine as
 * [protected_paths] (covered above).  Three seams expose the matcher
 * without a kernel event:
 *   - fanotify_test_config_allow_match(binary, target, &grant) returns
 *     the matched LHS pattern (the hash-pin key) or NULL and reports
 *     the grant scope (NULL for a global rule);
 *   - fanotify_test_unsafe_allow_match() matches [unsafe_allowlist] only;
 *   - fanotify_test_config_deny_match() returns the [denylist] verdict.
 * Covers all four binary/target combinations, the exact-side regression
 * guarantees (strcmp binary, equal-or-under target), glob boundaries and
 * section independence.
 */

/* Build one rule side the way config_load() does: exact copy with
 * base_len = strlen(); glob with the wildcard-free base length.  The
 * patterns used here are already canonical, so no resolution is needed. */
static void set_rule_side(char *dst, size_t dstsz, int *is_glob,
                          int *base_len, const char *pattern)
{
    snprintf(dst, dstsz, "%s", pattern);
    *is_glob = strchr(dst, '*') != NULL;
    *base_len = *is_glob ? glob_base_len(dst) : (int)strlen(dst);
}

/* Fill one rule; a NULL/empty target leaves a global (bare-line) rule. */
static void set_rule(RuleEntry *e, const char *binary, const char *target)
{
    memset(e, 0, sizeof(*e));
    set_rule_side(e->binary, sizeof(e->binary), &e->binary_is_glob,
                  &e->binary_base_len, binary);
    if (target && target[0] != '\0')
        set_rule_side(e->target_path, sizeof(e->target_path),
                      &e->target_is_glob, &e->target_base_len, target);
}

static void test_config_rule_matching(void) {
    static Config cfg;
    const char *grant;
    const char *m;

    memset(&cfg, 0, sizeof(cfg));

    /*
     * [allowlist]
     *   0 exact binary + exact target  (historical regression case)
     *   1 glob binary  + exact target  (AppImage-style mount pattern)
     *   2 exact binary + glob target
     *   3 glob binary  + glob target
     *   4 exact binary + global
     *   5 glob binary  + global
     */
    set_rule(&cfg.allowlist[0], "/usr/bin/opencode", "/home/u/.local");
    set_rule(&cfg.allowlist[1], "/tmp/.mount_*/openchamber",
             "/home/u/.local/share/opencode");
    set_rule(&cfg.allowlist[2], "/usr/bin/glob-target-tool",
             "/home/u/.local/**");
    set_rule(&cfg.allowlist[3], "/tmp/.mount_*/widget", "/srv/data/**");
    set_rule(&cfg.allowlist[4], "/usr/bin/global-tool", NULL);
    set_rule(&cfg.allowlist[5], "/opt/global_*/tool", NULL);
    cfg.allowlist_count = 6;

    /* [unsafe_allowlist]: separate section, never hash-pinned. */
    set_rule(&cfg.unsafe_allowlist[0], "/opt/unsafe-tool", "/etc/unsafe");
    set_rule(&cfg.unsafe_allowlist[1], "/opt/cache_*/plugin", NULL);
    cfg.unsafe_allowlist_count = 2;

    /* [denylist]: globs on both sides, no hashing involved. */
    set_rule(&cfg.denylist[0], "/usr/bin/curl", NULL);
    set_rule(&cfg.denylist[1], "/tmp/.mount_*/evil", "/etc/**");
    cfg.denylist_count = 2;

    Config *saved = g_config;
    g_config = &cfg;

    /* exact + exact: strcmp binary, equal-or-under target (regression) */
    grant = NULL;
    m = fanotify_test_config_allow_match("/usr/bin/opencode",
                                         "/home/u/.local/share/x", &grant);
    ASSERT(m != NULL && strcmp(m, "/usr/bin/opencode") == 0,
           "exact+exact returns the configured binary pattern");
    ASSERT(grant != NULL && strcmp(grant, "/home/u/.local") == 0,
           "exact target is returned as the grant target");
    ASSERT(fanotify_test_config_allow_match("/usr/bin/opencode",
                                            "/home/u/.local", &grant) != NULL,
           "exact target matches the target directory itself");
    ASSERT(fanotify_test_config_allow_match("/usr/bin/opencode-helper",
                                            "/home/u/.local/share/x",
                                            &grant) == NULL,
           "exact binary is strcmp-strict (no prefix match)");
    ASSERT(fanotify_test_config_allow_match("/usr/bin/opencode",
                                            "/home/u/.localX/y",
                                            &grant) == NULL,
           "exact target rejects a sibling prefix");
    ASSERT(fanotify_test_config_allow_match("/usr/bin/opencode",
                                            "/home/u/other", &grant) == NULL,
           "exact target rejects an unrelated path");

    /* glob binary + exact target */
    grant = NULL;
    m = fanotify_test_config_allow_match(
            "/tmp/.mount_Ab3xY/openchamber",
            "/home/u/.local/share/opencode/config.json", &grant);
    ASSERT(m != NULL && strcmp(m, "/tmp/.mount_*/openchamber") == 0,
           "glob binary returns the configured pattern (pin key)");
    ASSERT(grant != NULL &&
           strcmp(grant, "/home/u/.local/share/opencode") == 0,
           "glob-binary rule keeps its exact grant target");
    ASSERT(fanotify_test_config_allow_match(
               "/tmp/.mount_Ab3xY/openchamber2",
               "/home/u/.local/share/opencode/cfg", &grant) == NULL,
           "glob binary rejects a different basename");
    ASSERT(fanotify_test_config_allow_match(
               "/var/.mount_Ab3xY/openchamber",
               "/home/u/.local/share/opencode/cfg", &grant) == NULL,
           "glob binary base prefilter rejects paths outside its base");

    /* exact binary + glob target */
    grant = NULL;
    m = fanotify_test_config_allow_match("/usr/bin/glob-target-tool",
                                         "/home/u/.local/share/x", &grant);
    ASSERT(m != NULL && strcmp(m, "/usr/bin/glob-target-tool") == 0,
           "exact binary + glob target matches the subtree");
    ASSERT(grant != NULL && strcmp(grant, "/home/u/.local/**") == 0,
           "glob target is returned verbatim as the grant target");
    ASSERT(fanotify_test_config_allow_match("/usr/bin/glob-target-tool",
                                            "/home/u/.local", &grant) != NULL,
           "globstar target matches zero segments");
    ASSERT(fanotify_test_config_allow_match("/usr/bin/glob-target-tool",
                                            "/home/u/.localX/y",
                                            &grant) == NULL,
           "glob target base boundary is respected");
    ASSERT(fanotify_test_config_allow_match("/usr/bin/glob-target-tool",
                                            "/home/u/other/x",
                                            &grant) == NULL,
           "glob target rejects an unrelated path");

    /* glob binary + glob target */
    m = fanotify_test_config_allow_match("/tmp/.mount_q1/widget",
                                         "/srv/data/a/b.json", &grant);
    ASSERT(m != NULL && strcmp(m, "/tmp/.mount_*/widget") == 0,
           "glob+glob rule matches on both sides");
    ASSERT(fanotify_test_config_allow_match("/tmp/.mount_q1/sub/widget",
                                            "/srv/data/a/b.json",
                                            &grant) == NULL,
           "single-star binary glob does not cross segments");
    ASSERT(fanotify_test_config_allow_match("/tmp/.mount_q1/widget",
                                            "/srv/dataX/a", &grant) == NULL,
           "glob+glob target boundary is respected");

    /* global rules report a NULL grant target (wildcard cache entry) */
    grant = "sentinel";
    m = fanotify_test_config_allow_match("/usr/bin/global-tool", "/etc/x",
                                         &grant);
    ASSERT(m != NULL && strcmp(m, "/usr/bin/global-tool") == 0,
           "global exact rule matches any target");
    ASSERT(grant == NULL, "global rule reports a NULL grant target");
    grant = "sentinel";
    m = fanotify_test_config_allow_match("/opt/global_42/tool", "/home/u/x",
                                         &grant);
    ASSERT(m != NULL && strcmp(m, "/opt/global_*/tool") == 0,
           "global glob rule matches and returns its pattern");
    ASSERT(grant == NULL, "global glob rule reports a NULL grant target");

    /* [unsafe_allowlist] is a separate section from [allowlist] */
    m = fanotify_test_unsafe_allow_match("/opt/unsafe-tool", "/etc/unsafe/x");
    ASSERT(m != NULL && strcmp(m, "/opt/unsafe-tool") == 0,
           "unsafe seam matches its own section");
    ASSERT(fanotify_test_config_allow_match("/opt/unsafe-tool",
                                            "/etc/unsafe/x",
                                            &grant) == NULL,
           "unsafe rule is invisible to the allow seam");
    ASSERT(fanotify_test_unsafe_allow_match(
               "/usr/bin/opencode", "/home/u/.local/share/x") == NULL,
           "allowlist rule is invisible to the unsafe seam");
    m = fanotify_test_unsafe_allow_match("/opt/cache_42/plugin", "/etc/x");
    ASSERT(m != NULL && strcmp(m, "/opt/cache_*/plugin") == 0,
           "unsafe seam is glob-capable and global");
    ASSERT(fanotify_test_unsafe_allow_match("/opt/cache_42/plugin2",
                                            "/etc/x") == NULL,
           "unsafe glob binary is segment-bounded");

    /* [denylist] through the deny seam; no hashing needed */
    ASSERT(fanotify_test_config_deny_match("/usr/bin/curl",
                                           "/etc/passwd") == 1,
           "deny seam matches an exact global binary");
    ASSERT(fanotify_test_config_deny_match("/usr/bin/curl2",
                                           "/etc/passwd") == 0,
           "deny seam keeps strcmp-strict exact binaries");
    ASSERT(fanotify_test_config_deny_match("/tmp/.mount_ZZ/evil",
                                           "/etc/passwd") == 1,
           "deny seam matches glob binary + glob target");
    ASSERT(fanotify_test_config_deny_match("/tmp/.mount_ZZ/good",
                                           "/etc/passwd") == 0,
           "deny glob binary rejects a different basename");
    ASSERT(fanotify_test_config_deny_match("/tmp/.mount_ZZ/evil",
                                           "/home/u/x") == 0,
           "deny glob target rejects outside its subtree");
    ASSERT(fanotify_test_config_allow_match("/usr/bin/curl", "/etc/passwd",
                                            &grant) == NULL,
           "deny rule is invisible to the allow seam");
    ASSERT(fanotify_test_config_deny_match("/opt/unsafe-tool",
                                           "/etc/unsafe/x") == 0,
           "allow sections never appear in the deny seam");

    g_config = saved;
}

/*
 * Part 0i: [allowlist] hash pinning.  The pin module is controlled with
 * a per-run temp state file; the seams below run the pipeline's verdict
 * and first-seen store without a kernel permission event.
 */

#define PIN_SHA_A \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define PIN_SHA_B \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define PIN_SHA_C \
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" \
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

static char g_pin_dir[256];
static char g_pin_file[PATH_MAX + 64];
static int g_pin_fixture_ready = 0;

static int pin_fixture_init(void)
{
    if (g_pin_fixture_ready)
        return 0;

    snprintf(g_pin_dir, sizeof(g_pin_dir),
             "/tmp/fileshield_fanotify_pin_XXXXXX");
    if (!mkdtemp(g_pin_dir))
        return -1;
    snprintf(g_pin_file, sizeof(g_pin_file), "%s/allowlist-hashes.json",
             g_pin_dir);
    g_pin_fixture_ready = 1;
    return 0;
}

/* Start from a missing state file (clean first use). */
static int pin_fixture_reset(void)
{
    if (pin_fixture_init() < 0)
        return -1;
    unlink(g_pin_file);
    pin_set_state_file(g_pin_file);
    return pin_load(g_pin_file);
}

/* Install raw file content (used for the damaged-file case). */
static int pin_fixture_write_raw(const char *text)
{
    FILE *fp;

    if (pin_fixture_init() < 0)
        return -1;
    fp = fopen(g_pin_file, "w");
    if (!fp)
        return -1;
    fputs(text, fp);
    fclose(fp);
    pin_set_state_file(g_pin_file);
    return pin_load(g_pin_file);
}

static long read_pin_file(char *out, size_t sz)
{
    FILE *fp = fopen(g_pin_file, "r");
    size_t n;

    if (!fp)
        return -1;
    n = fread(out, 1, sz - 1, fp);
    fclose(fp);
    out[n] = '\0';
    return (long)n;
}

static void pin_fixture_cleanup(void)
{
    if (!g_pin_fixture_ready)
        return;
    unlink(g_pin_file);
    rmdir(g_pin_dir);
    pin_set_state_file(NULL);
    g_pin_fixture_ready = 0;
}

/* First event for a rule: store immediately, then the digest matches. */
static void test_pin_first_seen_tofu(void)
{
    static Config cfg;
    Config *saved = g_config;
    char old[129];
    struct stat st;

    memset(&cfg, 0, sizeof(cfg));
    set_rule(&cfg.allowlist[0], "/usr/bin/pinned-tool", "/home/u/secret");
    cfg.allowlist_count = 1;
    g_config = &cfg;

    ASSERT(pin_fixture_reset() == 0, "missing pin file is a clean first use");
    ASSERT(pin_damaged() == 0, "missing pin file is not damaged");

    ASSERT(fanotify_test_pin_first_seen("/usr/bin/pinned-tool", PIN_SHA_A,
                                        "/home/u/secret") == 0,
           "first-seen store succeeds");

    ASSERT(stat(g_pin_file, &st) == 0 && st.st_size > 0,
           "pin file exists on disk immediately");
    ASSERT(pin_load(g_pin_file) == 0, "freshly written pin file reloads");
    ASSERT(pin_check("/usr/bin/pinned-tool", PIN_SHA_A, old) ==
               PIN_CHECK_MATCH,
           "pin_check matches the stored digest");
    ASSERT(old[0] == '\0', "pin match leaves old_out empty");

    /* With a pin present the pipeline takes the changed path instead. */
    ASSERT(fanotify_test_pin_first_seen("/usr/bin/pinned-tool", PIN_SHA_B,
                                        "/home/u/secret") == -1,
           "first-seen seam refuses once a pin exists");
    ASSERT(pin_check("/usr/bin/pinned-tool", PIN_SHA_A, old) ==
               PIN_CHECK_MATCH,
           "refused store left the existing pin untouched");

    ASSERT(fanotify_test_pin_first_seen("/usr/bin/other", PIN_SHA_A,
                                        "/home/u/secret") == -1,
           "first-seen seam requires a matching allowlist rule");

    g_config = saved;
}

/* Rule verdicts: no match, first use, match, changed, unavailable. */
static void test_allowlist_pin_verdict_codes(void)
{
    static Config cfg;
    Config *saved = g_config;
    char old[129];

    memset(&cfg, 0, sizeof(cfg));
    set_rule(&cfg.allowlist[0], "/usr/bin/pinned-tool", "/home/u/secret");
    cfg.allowlist_count = 1;
    g_config = &cfg;

    old[0] = 'x';
    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/other", PIN_SHA_A,
                                           "/home/u/secret", old) == 3,
           "unmatched binary reports NO_MATCH");
    ASSERT(old[0] == '\0', "NO_MATCH clears old_out");

    /*
     * First use: the pipeline stores the digest and grants, so the seam
     * reports ALLOW; the verdict call itself must not write a pin.
     */
    ASSERT(pin_fixture_reset() == 0, "clean first-use state");
    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/pinned-tool", PIN_SHA_A,
                                           "/home/u/secret", old) == 0,
           "first-use rule reports ALLOW");
    ASSERT(pin_check("/usr/bin/pinned-tool", PIN_SHA_A, old) ==
               PIN_CHECK_FIRST_USE,
           "verdict is side-effect free (pin still absent)");

    ASSERT(fanotify_test_pin_first_seen("/usr/bin/pinned-tool", PIN_SHA_A,
                                        "/home/u/secret") == 0,
           "store the pin for the match/change cases");
    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/pinned-tool", PIN_SHA_A,
                                           "/home/u/secret", old) == 0,
           "matching pin reports ALLOW");
    ASSERT(old[0] == '\0', "pin match leaves old_out empty");

    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/pinned-tool", PIN_SHA_B,
                                           "/home/u/secret", old) == 1,
           "changed digest reports CHANGED");
    ASSERT(strcmp(old, PIN_SHA_A) == 0,
           "CHANGED returns the previously pinned digest");
    ASSERT(pin_check("/usr/bin/pinned-tool", PIN_SHA_A, old) ==
               PIN_CHECK_MATCH,
           "the CHANGED verdict did not touch the pin");

    /* An accepted update (what the dialog path does on Yes) replaces the
     * pin, and the next verdict is ALLOW again. */
    ASSERT(pin_store("/usr/bin/pinned-tool", PIN_SHA_B) == 0,
           "accepted update stores the new digest");
    ASSERT(pin_check("/usr/bin/pinned-tool", PIN_SHA_B, old) ==
               PIN_CHECK_MATCH,
           "pin_check matches the new digest after the update");
    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/pinned-tool", PIN_SHA_B,
                                           "/home/u/secret", old) == 0,
           "new digest reports ALLOW after the update");

    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/pinned-tool", "",
                                           "/home/u/secret", old) == 2,
           "empty digest reports NO_SILENT_GRANT");
    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/pinned-tool", NULL,
                                           "/home/u/secret", old) == 2,
           "missing digest reports NO_SILENT_GRANT");

    g_config = saved;
}

/* A damaged pin file fails closed and is never rewritten. */
static void test_pin_damaged_falls_through(void)
{
    static Config cfg;
    Config *saved = g_config;
    char old[129];
    char before[64];
    char after[64];

    memset(&cfg, 0, sizeof(cfg));
    set_rule(&cfg.allowlist[0], "/usr/bin/pinned-tool", "/home/u/secret");
    cfg.allowlist_count = 1;
    g_config = &cfg;

    ASSERT(pin_fixture_write_raw("this is not json\n") == -1,
           "garbage pin file loads as damaged (fail closed)");
    ASSERT(pin_damaged() == 1, "damaged flag is set");

    ASSERT(read_pin_file(before, sizeof(before)) > 0,
           "read the damaged file before the verdict calls");
    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/pinned-tool", PIN_SHA_A,
                                           "/home/u/secret", old) == 2,
           "damaged table reports NO_SILENT_GRANT");
    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/pinned-tool", "",
                                           "/home/u/secret", old) == 2,
           "empty digest reports NO_SILENT_GRANT while damaged");
    ASSERT(read_pin_file(after, sizeof(after)) > 0, "re-read the file");
    ASSERT(strcmp(before, after) == 0,
           "no pin write happened while the table was damaged");

    ASSERT(pin_fixture_reset() == 0 && pin_damaged() == 0,
           "a missing file reloads clean (admin recovery)");

    g_config = saved;
}

/* The unsafe section wins over the pinned one and skips pin machinery. */
static void test_unsafe_allowlist_skips_pins(void)
{
    static Config cfg;
    Config *saved = g_config;
    const char *pattern = "/tmp/.mount_*/opencode";
    const char *grant = NULL;
    const char *binary = "/tmp/.mount_abc/opencode";
    const char *target = "/home/u/.local/share/x";
    char old[129];

    memset(&cfg, 0, sizeof(cfg));
    /*
     * The same binary pattern is deliberately present in both sections.
     * This pins the matcher invariant that the unsafe path is independent
     * of the safe section and never reads or writes a pin; the pipeline's
     * unsafe-first order is exercised by
     * test_unsafe_allowlist_wins_over_pinned.
     */
    set_rule(&cfg.unsafe_allowlist[0], pattern, "/home/u/.local");
    cfg.unsafe_allowlist_count = 1;
    set_rule(&cfg.allowlist[0], pattern, "/home/u/.local");
    cfg.allowlist_count = 1;
    g_config = &cfg;

    ASSERT(pin_fixture_reset() == 0, "clean pin state for the order test");

    ASSERT(fanotify_test_unsafe_allow_match(binary, target) != NULL,
           "unsafe seam matches the rule shared by both sections");
    ASSERT(fanotify_test_config_allow_match(binary, target, &grant) != NULL,
           "the pinned seam would also match (unsafe wins by order)");

    /* Nothing in the unsafe path reads or writes a pin, so the matching
     * key is still unpinned while the safe seam only compares. */
    ASSERT(pin_check(pattern, PIN_SHA_A, old) == PIN_CHECK_FIRST_USE,
           "no pin was written for the unsafe hit");

    g_config = saved;
}

/* The hash-change prompt must fail closed on a NULL request. */
static void test_hash_change_null_request_denies(void)
{
    ASSERT(notify_ask_hash_change(NULL) == NOTIFY_DENY,
           "NULL hash-change request denies (fail closed)");
}

/*
 * Notification flood control: identical (kind, binary, target) hits are
 * suppressed for the dedup window, distinct keys pass, a zero window
 * notifies every hit, and the global cap bounds a burst of distinct keys.
 */
static void test_notify_rate_windows(void)
{
    notify_test_reset_rate();

    ASSERT(notify_test_hit_rate(NOTIFY_HIT_DENY, "/b", "/t", 60, 20) == 1,
           "first notification passes");
    ASSERT(notify_test_hit_rate(NOTIFY_HIT_DENY, "/b", "/t", 60, 20) == 0,
           "identical hit inside the window is suppressed");
    ASSERT(notify_test_hit_rate(NOTIFY_HIT_DENY, "/b", "/t2", 60, 20) == 1,
           "a different target passes");
    ASSERT(notify_test_hit_rate(NOTIFY_HIT_ALLOW, "/b", "/t", 60, 20) == 1,
           "a different kind passes");
    ASSERT(notify_test_hit_rate(NOTIFY_HIT_DENY, "/b", "/t", 0, 20) == 1,
           "dedup window 0 notifies every hit");

    /* Unsafe hits are gated once per process by the caller, so the
     * per-key window must not suppress a second process using the rule. */
    ASSERT(notify_test_hit_rate(NOTIFY_HIT_UNSAFE, "/b", "/t", 60, 20) == 1,
           "unsafe bypasses the per-key window (first hit)");
    ASSERT(notify_test_hit_rate(NOTIFY_HIT_UNSAFE, "/b", "/t", 60, 20) == 1,
           "unsafe bypasses the per-key window (repeat)");

    /* Configurable global cap: 10 distinct keys, cap 5 -> 5 delivered. */
    notify_test_reset_rate();
    int allowed = 0;
    for (int i = 0; i < 10; i++)
    {
        char bin[32];
        snprintf(bin, sizeof(bin), "/bin/notify-%d", i);
        allowed += notify_test_hit_rate(NOTIFY_HIT_DENY, bin, "/t", 0, 5);
    }
    ASSERT(allowed == 5, "notify_max caps the window at 5");
    notify_test_reset_rate();
}

/*
 * Unsafe hits surface once per process: the first hit qualifies for the
 * warning + notification, repeats are suppressed, and another process is
 * a new instance.  The gate key is (pid, /proc/<pid>/stat start time):
 * the same pid number after the process is gone must surface again, so a
 * pid-only gate fails the last two assertions.
 */
static void test_unsafe_hit_once_per_process(void)
{
    pid_t self = getpid();

    ASSERT(fanotify_test_unsafe_first_hit(self) == 1,
           "first unsafe hit for a process is surfaced");
    ASSERT(fanotify_test_unsafe_first_hit(self) == 0,
           "repeat unsafe hit for the same process is suppressed");
    ASSERT(fanotify_test_unsafe_first_hit(getppid()) == 1,
           "another process is surfaced independently");

    /*
     * (pid, start) coverage: a live child gets its own key; once it is
     * reaped, the same pid number has no readable start time (and a
     * recycled pid would carry a new one), so the gate must treat it as
     * a new instance instead of inheriting the dead process's decision.
     */
    pid_t child = fork();
    ASSERT(child >= 0, "fork the unsafe-gate child");
    if (child == 0)
    {
        for (;;)
            pause();
        _exit(0);
    }
    if (child > 0)
    {
        ASSERT(fanotify_test_unsafe_first_hit(child) == 1,
               "the child's first hit is surfaced");
        ASSERT(fanotify_test_unsafe_first_hit(child) == 0,
               "the child's repeat hit is suppressed");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        ASSERT(fanotify_test_unsafe_first_hit(child) == 1,
               "same pid with a different/unknown start is a new instance");
        ASSERT(fanotify_test_unsafe_first_hit(child) == 0,
               "the new (pid, start) key is remembered");
    }
}

/*
 * Both matchers accept the same access.  The pipeline's deny-before-grant
 * order is enforced in event_load_binary()/process_open_perm() and is
 * exercised by the root canary; this seam test pins only that the deny
 * and allow matchers agree on the tuple.
 */
static void test_glob_deny_and_allow_matchers(void)
{
    static Config cfg;
    Config *saved = g_config;
    const char *grant = NULL;
    const char *binary = "/tmp/.mount_abc/opencode";
    const char *target = "/home/u/.local/share/opencode/x";

    memset(&cfg, 0, sizeof(cfg));
    set_rule(&cfg.allowlist[0], "/tmp/.mount_*/opencode", "/home/u/.local");
    cfg.allowlist_count = 1;
    set_rule(&cfg.denylist[0], "/tmp/.mount_*/open*", "/home/u/.local/**");
    cfg.denylist_count = 1;
    g_config = &cfg;

    ASSERT(fanotify_test_config_deny_match(binary, target) == 1,
           "glob deny rule matches the access");
    ASSERT(fanotify_test_config_allow_match(binary, target, &grant) != NULL,
           "glob allow rule also matches the same access");
    /* In production the deny match runs before every grant stage, so the
     * deny wins; that ordering is not observable through these two
     * independent matcher seams. */

    g_config = saved;
}

/*
 * Part 1b: persisted allow/deny entries are file- and command-scoped.
 * An entry without a target_path, without the raw command line, or
 * without its digest (legacy or hand-edited state file) must never act
 * as a wildcard grant or a blanket denial.  Asserted observably: only a
 * fully-scoped entry can match, and only with its exact keys.
 */
static void test_incomplete_entries_grant_nothing(void) {
    const char *sha =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    char cmd_fingerprint[129];

    ASSERT(sha512_string("kubectl config view --minify", cmd_fingerprint) == 0,
           "digest of the stored command line");

    PersistEntry entries[4];
    memset(entries, 0, sizeof(entries));

    /* Valid file- and command-scoped allow entry. */
    snprintf(entries[0].binary, sizeof(entries[0].binary), "/usr/bin/kubectl");
    snprintf(entries[0].binary_sha512, sizeof(entries[0].binary_sha512), "%s", sha);
    snprintf(entries[0].target_path, sizeof(entries[0].target_path),
             "/home/u/.kube/config");
    snprintf(entries[0].cmdline, sizeof(entries[0].cmdline),
             "kubectl config view --minify");
    snprintf(entries[0].cmdline_sha512, sizeof(entries[0].cmdline_sha512),
             "%s", cmd_fingerprint);

    /* Legacy wildcard entry: no target recorded. */
    snprintf(entries[1].binary, sizeof(entries[1].binary), "/usr/bin/ssh");
    snprintf(entries[1].binary_sha512, sizeof(entries[1].binary_sha512), "%s", sha);
    snprintf(entries[1].cmdline, sizeof(entries[1].cmdline), "ssh-add -l");
    snprintf(entries[1].cmdline_sha512, sizeof(entries[1].cmdline_sha512),
             "%s", sha);

    /* Digest only: the command line cannot be shown. */
    snprintf(entries[2].binary, sizeof(entries[2].binary), "/usr/bin/aws");
    snprintf(entries[2].binary_sha512, sizeof(entries[2].binary_sha512), "%s", sha);
    snprintf(entries[2].target_path, sizeof(entries[2].target_path),
             "/home/u/.aws/credentials");
    snprintf(entries[2].cmdline_sha512, sizeof(entries[2].cmdline_sha512),
             "%s", sha);

    /* Raw command only: cannot be matched. */
    snprintf(entries[3].binary, sizeof(entries[3].binary), "/usr/bin/gh");
    snprintf(entries[3].binary_sha512, sizeof(entries[3].binary_sha512), "%s", sha);
    snprintf(entries[3].target_path, sizeof(entries[3].target_path),
             "/home/u/.config/gh/hosts.yml");
    snprintf(entries[3].cmdline, sizeof(entries[3].cmdline), "gh auth status");

    fanotify_load_dyn_allowlist(entries, 4);

    /* The complete entry loads with every matching key preserved. */
    ASSERT(test_match_allow("/usr/bin/kubectl", sha,
           "/home/u/.kube/config", "kubectl config view --minify") == 1,
           "the complete allow entry matches its exact tuple");

    /* The incomplete records can never act as wildcard grants. */
    ASSERT(test_match_allow("/usr/bin/ssh", sha,
           "/home/u/.ssh/id_rsa", "ssh-add -l") == 0,
           "target-less allow entry grants nothing");
    ASSERT(test_match_allow("/usr/bin/aws", sha,
           "/home/u/.aws/credentials", "aws sts get-caller-identity") == 0,
           "digest-only allow entry grants nothing");
    ASSERT(test_match_allow("/usr/bin/gh", sha,
           "/home/u/.config/gh/hosts.yml", "gh auth status") == 0,
           "cmdline-only allow entry grants nothing");

    /* The surviving entry stays pinned to each of its keys. */
    ASSERT(test_match_allow("/usr/bin/kubectl", "deadbeef",
           "/home/u/.kube/config", "kubectl config view --minify") == 0,
           "unverifiable binary hash does not match");
    ASSERT(test_match_allow("/usr/bin/kubectl", sha,
           "/home/u/.kube/other", "kubectl config view --minify") == 0,
           "different target does not match");
    ASSERT(test_match_allow("/usr/bin/kubectl", sha,
           "/home/u/.kube/config", "kubectl get secrets") == 0,
           "different command does not match");

    /* Denies do not require a binary SHA-512, but incomplete records
     * deny nothing at all. */
    PersistEntry dentries[2];
    memset(dentries, 0, sizeof(dentries));
    snprintf(dentries[0].binary, sizeof(dentries[0].binary), "/usr/bin/curl");

    snprintf(dentries[1].binary, sizeof(dentries[1].binary), "/usr/bin/wget");
    snprintf(dentries[1].target_path, sizeof(dentries[1].target_path),
             "/home/u/.netrc");

    fanotify_load_dyn_denylist(dentries, 2);
    ASSERT(test_match_deny("/usr/bin/curl", "", "/etc/passwd",
           "curl") == 0,
           "bare deny record denies nothing");
    ASSERT(test_match_deny("/usr/bin/wget", "", "/home/u/.netrc",
           "wget") == 0,
           "deny record without a command fingerprint denies nothing");

    /* Reload an empty list so later tests see the daemon's clean state. */
    fanotify_load_dyn_allowlist(NULL, 0);
    fanotify_load_dyn_denylist(NULL, 0);
}

/*
 * Part 1c: permanent entries are scoped to the exact command line.  A
 * grant recorded for "kubectl get pods" must not cover "kubectl get
 * secrets" for the same binary, hash, file and call chain.
 */
static void test_cmdline_scoping(void) {
    const char *sha =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    char cmd_pods[129];
    char cmd_secrets[129];

    ASSERT(sha512_string("kubectl get pods", cmd_pods) == 0,
           "digest of approved command");
    ASSERT(sha512_string("kubectl get secrets", cmd_secrets) == 0,
           "digest of other command");
    ASSERT(strcmp(cmd_pods, cmd_secrets) != 0, "command digests differ");

    PersistEntry e[1];
    memset(e, 0, sizeof(e));
    snprintf(e[0].binary, sizeof(e[0].binary), "/usr/bin/kubectl");
    snprintf(e[0].binary_sha512, sizeof(e[0].binary_sha512), "%s", sha);
    snprintf(e[0].target_path, sizeof(e[0].target_path),
             "/home/u/.kube/config");
    snprintf(e[0].cmdline, sizeof(e[0].cmdline), "kubectl get pods");
    snprintf(e[0].cmdline_sha512, sizeof(e[0].cmdline_sha512), "%s",
             cmd_pods);

    fanotify_load_dyn_allowlist(e, 1);
    ASSERT(test_match_allow("/usr/bin/kubectl", sha,
           "/home/u/.kube/config", "kubectl get pods") == 1,
           "exact command matches the allow entry");
    ASSERT(test_match_allow("/usr/bin/kubectl", sha,
           "/home/u/.kube/config", "kubectl get secrets") == 0,
           "different command does not match the allow entry");
    ASSERT(test_match_allow("/usr/bin/kubectl", sha,
           "/home/u/.ssh/id_rsa", "kubectl get pods") == 0,
           "different target does not match the allow entry");
    ASSERT(test_match_allow("/usr/bin/kubectl", "deadbeef",
           "/home/u/.kube/config", "kubectl get pods") == 0,
           "unverifiable binary hash does not match");
    fanotify_load_dyn_allowlist(NULL, 0);

    /* The deny side mirrors the same scoping. */
    fanotify_load_dyn_denylist(e, 1);
    ASSERT(test_match_deny("/usr/bin/kubectl", sha,
           "/home/u/.kube/config", "kubectl get pods") == 1,
           "exact command matches the deny entry");
    ASSERT(test_match_deny("/usr/bin/kubectl", sha,
           "/home/u/.kube/config", "kubectl get secrets") == 0,
           "different command does not match the deny entry");
    fanotify_load_dyn_denylist(NULL, 0);
}

/*
 * Part 1c2: stored rule IDs and real created_at on the runtime lists.
 *
 * The state files are redirected into a per-run temp directory
 * (fanotify_set_state_files) before any test runs, so migration writes
 * and mutation persistence never touch /var/lib/fileshield from an
 * unprivileged suite -- including the existing fixtures above that load
 * persisted entries without rule_id.
 */
static char g_dyn_dir[256];
static char g_dyn_allow_file[PATH_MAX + 64];
static char g_dyn_deny_file[PATH_MAX + 64];
static int g_dyn_fixture_ready = 0;

static int dyn_fixture_init(void)
{
    if (g_dyn_fixture_ready)
        return 0;

    snprintf(g_dyn_dir, sizeof(g_dyn_dir),
             "/tmp/fileshield_fanotify_dyn_XXXXXX");
    if (!mkdtemp(g_dyn_dir))
        return -1;
    snprintf(g_dyn_allow_file, sizeof(g_dyn_allow_file),
             "%s/runtime-allowlist.json", g_dyn_dir);
    snprintf(g_dyn_deny_file, sizeof(g_dyn_deny_file),
             "%s/runtime-denylist.json", g_dyn_dir);
    fanotify_set_state_files(g_dyn_allow_file, g_dyn_deny_file);
    g_dyn_fixture_ready = 1;
    return 0;
}

/* Empty in-memory lists and no state files on disk. */
static void dyn_fixture_reset(void)
{
    if (dyn_fixture_init() < 0)
        return;
    unlink(g_dyn_allow_file);
    unlink(g_dyn_deny_file);
    fanotify_load_dyn_allowlist(NULL, 0);
    fanotify_load_dyn_denylist(NULL, 0);
}

static void dyn_fixture_cleanup(void)
{
    if (!g_dyn_fixture_ready)
        return;
    unlink(g_dyn_allow_file);
    unlink(g_dyn_deny_file);
    rmdir(g_dyn_dir);
    fanotify_set_state_files(NULL, NULL);
    g_dyn_fixture_ready = 0;
}

/*
 * Fill one PersistEntry the way a real state file would carry it.  id may
 * be NULL (legacy entry); the command-line digest is derived from the raw
 * command line so the matcher seams can match the tuple.
 */
static void dyn_entry_fill(PersistEntry *e, const char *binary, const char *sha,
                           const char *target, const char *cmdline,
                           const char *id, time_t created_at)
{
    char fp[129];

    memset(e, 0, sizeof(*e));
    snprintf(e->binary, sizeof(e->binary), "%s", binary);
    snprintf(e->binary_sha512, sizeof(e->binary_sha512), "%s", sha);
    snprintf(e->target_path, sizeof(e->target_path), "%s", target);
    snprintf(e->cmdline, sizeof(e->cmdline), "%s", cmdline);
    if (sha512_string(cmdline, fp) == 0)
        snprintf(e->cmdline_sha512, sizeof(e->cmdline_sha512), "%s", fp);
    if (id)
        snprintf(e->rule_id, sizeof(e->rule_id), "%s", id);
    e->created_at = created_at;
}

/* Give a fixture entry a recorded three-level call chain. */
static void dyn_entry_set_chain(PersistEntry *e, const char *c0,
                                const char *c1, const char *c2)
{
    e->chain_depth = 3;
    snprintf(e->chain_comm[0], sizeof(e->chain_comm[0]), "%s", c0);
    snprintf(e->chain_comm[1], sizeof(e->chain_comm[1]), "%s", c1);
    snprintf(e->chain_comm[2], sizeof(e->chain_comm[2]), "%s", c2);
    snprintf(e->chain_sha512[0], sizeof(e->chain_sha512[0]), "%s", PIN_SHA_C);
    snprintf(e->chain_sha512[1], sizeof(e->chain_sha512[1]), "%s", PIN_SHA_C);
    snprintf(e->chain_sha512[2], sizeof(e->chain_sha512[2]), "%s", PIN_SHA_C);
}

static int is_hex16(const char *s)
{
    size_t i;

    if (!s || strlen(s) != 16)
        return 0;
    for (i = 0; i < 16; i++)
    {
        if (!((s[i] >= '0' && s[i] <= '9') ||
              (s[i] >= 'a' && s[i] <= 'f')))
            return 0;
    }
    return 1;
}

/*
 * A persisted mutation must carry each survivor's real created_at and
 * rule_id; the old re-stamping made created_at the write time and would
 * move the ID's own input under the entry.
 */
static void test_dyn_created_at_preserved(void)
{
    PersistEntry e[3];
    PersistEntry out[PERSIST_MAX_ENTRIES];
    int n;

    dyn_fixture_reset();

    dyn_entry_fill(&e[0], "/usr/bin/keep-one", PIN_SHA_A, "/home/u/one",
                   "keep-one --read", "1111111111111111",
                   (time_t)1700000000);
    dyn_entry_fill(&e[1], "/usr/bin/drop-two", PIN_SHA_A, "/home/u/two",
                   "drop-two --read", "2222222222222222",
                   (time_t)1700001000);
    dyn_entry_fill(&e[2], "/usr/bin/keep-three", PIN_SHA_A, "/home/u/three",
                   "keep-three --read", "3333333333333333",
                   (time_t)1700002000);
    fanotify_load_dyn_allowlist(e, 3);

    ASSERT(fanotify_remove_dyn_entry(0, "22222222") == 1,
           "remove the middle entry to force a persisted write");

    n = persist_load(g_dyn_allow_file, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 2, "two survivors persisted");
    ASSERT(strcmp(out[0].rule_id, "1111111111111111") == 0 &&
               out[0].created_at == (time_t)1700000000,
           "first survivor kept its rule_id and created_at");
    ASSERT(strcmp(out[1].rule_id, "3333333333333333") == 0 &&
               out[1].created_at == (time_t)1700002000,
           "second survivor kept its rule_id and created_at");
}

/* Legacy entries get IDs at load and the migration is persisted at once. */
static void test_dyn_legacy_id_migration(void)
{
    PersistEntry e[1];
    PersistEntry out[PERSIST_MAX_ENTRIES];
    char migrated_id[17];
    int n;

    dyn_fixture_reset();

    dyn_entry_fill(&e[0], "/usr/bin/legacy-tool", PIN_SHA_A,
                   "/home/u/legacy", "legacy-tool --read", NULL,
                   (time_t)1700005555);
    fanotify_load_dyn_allowlist(e, 1);

    ASSERT(test_match_allow("/usr/bin/legacy-tool", PIN_SHA_A,
                            "/home/u/legacy", "legacy-tool --read") == 1,
           "migrated allow entry still matches its keys");

    n = persist_load(g_dyn_allow_file, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "migration persisted the allow state immediately");
    ASSERT(is_hex16(out[0].rule_id), "migrated ID is 16 lowercase hex");
    ASSERT(out[0].created_at == (time_t)1700005555,
           "migration preserved the loaded created_at");
    memcpy(migrated_id, out[0].rule_id, sizeof(migrated_id));

    ASSERT(fanotify_remove_dyn_entry(0, migrated_id) == 1,
           "the migrated ID addresses the live entry");

    dyn_entry_fill(&e[0], "/usr/bin/legacy-deny", PIN_SHA_A,
                   "/home/u/legacy", "legacy-deny --read", NULL,
                   (time_t)1700006666);
    fanotify_load_dyn_denylist(e, 1);

    ASSERT(test_match_deny("/usr/bin/legacy-deny", PIN_SHA_A,
                           "/home/u/legacy", "legacy-deny --read") == 1,
           "migrated deny entry still matches its keys");
    n = persist_load(g_dyn_deny_file, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "migration persisted the deny state immediately");
    ASSERT(is_hex16(out[0].rule_id), "migrated deny ID is 16 lowercase hex");
    ASSERT(out[0].created_at == (time_t)1700006666,
           "deny migration preserved the loaded created_at");
}

/* Remove-by-ID: prefixes, ambiguity, invalid input, file rewrite. */
static void test_dyn_remove_by_id(void)
{
    PersistEntry e[3];
    PersistEntry deny[1];
    PersistEntry out[PERSIST_MAX_ENTRIES];
    char deny_id[17];
    int n;

    dyn_fixture_reset();

    /* Two stored IDs deliberately share the 8-char prefix "deadbeef";
     * load_dyn_list() trusts an already well-formed stored ID. */
    dyn_entry_fill(&e[0], "/usr/bin/rm-one", PIN_SHA_A, "/home/u/one",
                   "rm-one --read", "deadbeefdeadbe01", (time_t)1700010000);
    dyn_entry_fill(&e[1], "/usr/bin/rm-two", PIN_SHA_A, "/home/u/two",
                   "rm-two --read", "deadbeefdeadbe02", (time_t)1700010001);
    dyn_entry_fill(&e[2], "/usr/bin/rm-three", PIN_SHA_A, "/home/u/three",
                   "rm-three --read", "0123456789abcdef", (time_t)1700010002);
    fanotify_load_dyn_allowlist(e, 3);

    /* Legacy (no stored ID): the load migrates and writes the deny file,
     * so the untouched-file assertion below has a real file to check. */
    dyn_entry_fill(&deny[0], "/usr/bin/deny-keep", PIN_SHA_A,
                   "/home/u/deny", "deny-keep --read", NULL,
                   (time_t)1700010003);
    fanotify_load_dyn_denylist(deny, 1);
    n = persist_load(g_dyn_deny_file, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1 && is_hex16(out[0].rule_id),
           "deny migration persisted a real deny state file");
    memcpy(deny_id, out[0].rule_id, sizeof(deny_id));

    ASSERT(fanotify_remove_dyn_entry(0, "deadbeef") == -2,
           "ambiguous 8-char prefix refuses with -2");
    ASSERT(test_match_allow("/usr/bin/rm-one", PIN_SHA_A, "/home/u/one",
                            "rm-one --read") == 1 &&
               test_match_allow("/usr/bin/rm-two", PIN_SHA_A, "/home/u/two",
                                "rm-two --read") == 1,
           "ambiguous removal left both entries in memory");

    ASSERT(fanotify_remove_dyn_entry(0, "01234567") == 1,
           "unique 8-char prefix removes");
    ASSERT(test_match_allow("/usr/bin/rm-three", PIN_SHA_A,
                            "/home/u/three", "rm-three --read") == 0,
           "removed entry no longer matches");
    n = persist_load(g_dyn_allow_file, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 2, "state file rewritten without the removed entry");
    ASSERT(strcmp(out[0].rule_id, "deadbeefdeadbe01") == 0 &&
               strcmp(out[1].rule_id, "deadbeefdeadbe02") == 0,
           "file keeps the two surviving IDs in order");

    ASSERT(fanotify_remove_dyn_entry(0, "deadbeefdeadbe01") == 1,
           "full 16-char ID removes");
    ASSERT(fanotify_remove_dyn_entry(0, "deadbeefdeadbe01") == 0,
           "already removed ID reports 0");

    ASSERT(fanotify_remove_dyn_entry(0, "deadbee") == -1,
           "7-char prefix is invalid");
    ASSERT(fanotify_remove_dyn_entry(0, "deadbeeg") == -1,
           "non-hex prefix is invalid");
    ASSERT(fanotify_remove_dyn_entry(0, "") == -1, "empty prefix is invalid");
    ASSERT(fanotify_remove_dyn_entry(0, NULL) == -1, "NULL prefix is invalid");

    ASSERT(test_match_deny("/usr/bin/deny-keep", PIN_SHA_A, "/home/u/deny",
                           "deny-keep --read") == 1,
           "remove never touches the other list");
    n = persist_load(g_dyn_deny_file, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1 && strcmp(out[0].rule_id, deny_id) == 0,
           "deny state file untouched by remove");
}

/* Clear: memory and file emptied, the other list untouched. */
static void test_dyn_clear(void)
{
    PersistEntry e[2];
    PersistEntry out[PERSIST_MAX_ENTRIES];
    char deny_id[17];
    int n;

    dyn_fixture_reset();

    dyn_entry_fill(&e[0], "/usr/bin/clear-one", PIN_SHA_A, "/home/u/one",
                   "clear-one --read", "aaaaaaaaaaaaaaaa",
                   (time_t)1700020000);
    dyn_entry_fill(&e[1], "/usr/bin/clear-two", PIN_SHA_B, "/home/u/two",
                   "clear-two --read", "bbbbbbbbbbbbbbbb",
                   (time_t)1700020001);
    fanotify_load_dyn_allowlist(e, 2);

    /* Legacy deny entry: migrated and persisted at load, so the
     * untouched-list check below reads a real file. */
    dyn_entry_fill(&e[0], "/usr/bin/clear-deny", PIN_SHA_A, "/home/u/deny",
                   "clear-deny --read", NULL, (time_t)1700020002);
    fanotify_load_dyn_denylist(e, 1);
    n = persist_load(g_dyn_deny_file, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1 && is_hex16(out[0].rule_id),
           "deny migration persisted a real deny state file");
    memcpy(deny_id, out[0].rule_id, sizeof(deny_id));

    ASSERT(fanotify_clear_dyn_list(0) == 2, "clear reports the removed count");
    ASSERT(test_match_allow("/usr/bin/clear-one", PIN_SHA_A, "/home/u/one",
                            "clear-one --read") == 0,
           "cleared allow entry no longer matches");
    n = persist_load(g_dyn_allow_file, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 0, "cleared allow state file holds no entries");

    ASSERT(test_match_deny("/usr/bin/clear-deny", PIN_SHA_A, "/home/u/deny",
                           "clear-deny --read") == 1,
           "clear never touches the other list");
    n = persist_load(g_dyn_deny_file, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1 && strcmp(out[0].rule_id, deny_id) == 0,
           "deny state file still holds its entry");

    ASSERT(fanotify_clear_dyn_list(0) == 0, "clear on an empty list returns 0");
}

/* Prune: one key, two digest generations -> the newest survives. */
static void test_dyn_prune(void)
{
    PersistEntry e[3];
    PersistEntry out[PERSIST_MAX_ENTRIES];
    char deny_id[17];
    int removed = -1;
    int n;

    dyn_fixture_reset();

    /* Same binary/target/cmdline/chain key, different binary_sha512 and
     * created_at: the binary changed on disk and the older grant is
     * stale.  e[1] is the newest member (highest index). */
    dyn_entry_fill(&e[0], "/usr/bin/prune-tool", PIN_SHA_A, "/home/u/prune",
                   "prune-tool --read", "1111111111111111",
                   (time_t)1700030000);
    dyn_entry_fill(&e[1], "/usr/bin/prune-tool", PIN_SHA_B, "/home/u/prune",
                   "prune-tool --read", "2222222222222222",
                   (time_t)1700030001);
    dyn_entry_fill(&e[2], "/usr/bin/other-tool", PIN_SHA_A, "/home/u/other",
                   "other-tool --read", "3333333333333333",
                   (time_t)1700030002);
    fanotify_load_dyn_allowlist(e, 3);

    /* Legacy deny entry: migrated and persisted at load, so the
     * untouched-list check below reads a real file. */
    dyn_entry_fill(&e[0], "/usr/bin/prune-deny", PIN_SHA_A, "/home/u/deny",
                   "prune-deny --read", NULL, (time_t)1700030003);
    fanotify_load_dyn_denylist(e, 1);
    n = persist_load(g_dyn_deny_file, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1 && is_hex16(out[0].rule_id),
           "deny migration persisted a real deny state file");
    memcpy(deny_id, out[0].rule_id, sizeof(deny_id));

    ASSERT(fanotify_prune_dyn_list(0, &removed) == 0 && removed == 1,
           "prune removes the older duplicate");

    ASSERT(test_match_allow("/usr/bin/prune-tool", PIN_SHA_A, "/home/u/prune",
                            "prune-tool --read") == 0,
           "older duplicate no longer matches");
    ASSERT(test_match_allow("/usr/bin/prune-tool", PIN_SHA_B, "/home/u/prune",
                            "prune-tool --read") == 1,
           "newest duplicate still matches");
    ASSERT(test_match_allow("/usr/bin/other-tool", PIN_SHA_A,
                            "/home/u/other", "other-tool --read") == 1,
           "unrelated entry survives");

    n = persist_load(g_dyn_allow_file, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 2, "prune rewrote the allow state file");
    ASSERT(strcmp(out[0].rule_id, "2222222222222222") == 0 &&
               strcmp(out[1].rule_id, "3333333333333333") == 0,
           "kept the newest duplicate and the unrelated entry");

    removed = -1;
    ASSERT(fanotify_prune_dyn_list(0, &removed) == 0 && removed == 0,
           "a second prune finds no duplicates");

    ASSERT(test_match_deny("/usr/bin/prune-deny", PIN_SHA_A, "/home/u/deny",
                           "prune-deny --read") == 1,
           "prune never touches the other list");
    n = persist_load(g_dyn_deny_file, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1 && strcmp(out[0].rule_id, deny_id) == 0,
           "deny state file untouched by prune");

    /* NULL removed_out is accepted (the count is only logged). */
    ASSERT(fanotify_prune_dyn_list(1, NULL) == 0,
           "prune accepts a NULL removed_out");
}

/*
 * Interleaved groups: prune_find emits per-group removal slices, so the
 * flat list is not globally ascending (A,B,A,A,B -> [0,2,1]).  The
 * daemon compaction must treat it as a set or it silently keeps a
 * duplicate while reporting it removed.
 */
static void test_dyn_prune_interleaved(void)
{
    PersistEntry e[5];
    PersistEntry out[PERSIST_MAX_ENTRIES];
    int removed = -1;
    int n;

    dyn_fixture_reset();

    /* Key A at 0,2,3 (keep 3); key B at 1,4 (keep 4). */
    dyn_entry_fill(&e[0], "/usr/bin/ia", PIN_SHA_A, "/home/u/ia",
                   "ia --read", "aaaaaaaaaaaaaaa1", (time_t)1700040000);
    dyn_entry_fill(&e[1], "/usr/bin/ib", PIN_SHA_A, "/home/u/ib",
                   "ib --read", "bbbbbbbbbbbbbbb1", (time_t)1700040001);
    dyn_entry_fill(&e[2], "/usr/bin/ia", PIN_SHA_B, "/home/u/ia",
                   "ia --read", "aaaaaaaaaaaaaaa2", (time_t)1700040002);
    dyn_entry_fill(&e[3], "/usr/bin/ia", PIN_SHA_C, "/home/u/ia",
                   "ia --read", "aaaaaaaaaaaaaaa3", (time_t)1700040003);
    dyn_entry_fill(&e[4], "/usr/bin/ib", PIN_SHA_B, "/home/u/ib",
                   "ib --read", "bbbbbbbbbbbbbbb2", (time_t)1700040004);
    fanotify_load_dyn_allowlist(e, 5);

    ASSERT(fanotify_prune_dyn_list(0, &removed) == 0 && removed == 3,
           "interleaved prune removes three entries");

    ASSERT(test_match_allow("/usr/bin/ia", PIN_SHA_C, "/home/u/ia",
                            "ia --read") == 1,
           "the newest A survives");
    ASSERT(test_match_allow("/usr/bin/ib", PIN_SHA_B, "/home/u/ib",
                            "ib --read") == 1,
           "the newest B survives");
    ASSERT(test_match_allow("/usr/bin/ia", PIN_SHA_B, "/home/u/ia",
                            "ia --read") == 0,
           "the middle A is gone");
    ASSERT(test_match_allow("/usr/bin/ib", PIN_SHA_A, "/home/u/ib",
                            "ib --read") == 0,
           "the older B is gone");

    n = persist_load(g_dyn_allow_file, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 2 && strcmp(out[0].rule_id, "aaaaaaaaaaaaaaa3") == 0 &&
               strcmp(out[1].rule_id, "bbbbbbbbbbbbbbb2") == 0,
           "the kept pair was persisted in order");
}

/*
 * The call chain is part of the prune key: the same helper run from two
 * terminals (same binary, target and args, different terminal comms at
 * the end of the chain) is two rules, not a duplicate.  Only the
 * same-chain pair is pruned and the other terminal's grant survives.
 */
static void test_dyn_prune_chain_separation(void)
{
    PersistEntry e[3];
    PersistEntry out[PERSIST_MAX_ENTRIES];
    int removed = -1;
    int n;

    dyn_fixture_reset();

    dyn_entry_fill(&e[0], "/usr/bin/gcloud-helper", PIN_SHA_A,
                   "/home/u/gcloud/credentials.db",
                   "gcloud-helper --format=json", "aaaaaaaaaaaaaaa1",
                   (time_t)1700060000);
    dyn_entry_set_chain(&e[0], "gke-gcloud-auth", "kubectl", "zsh");

    dyn_entry_fill(&e[1], "/usr/bin/gcloud-helper", PIN_SHA_B,
                   "/home/u/gcloud/credentials.db",
                   "gcloud-helper --format=json", "bbbbbbbbbbbbbbb1",
                   (time_t)1700060001);
    dyn_entry_set_chain(&e[1], "gke-gcloud-auth", "kubectl", "warp");

    dyn_entry_fill(&e[2], "/usr/bin/gcloud-helper", PIN_SHA_C,
                   "/home/u/gcloud/credentials.db",
                   "gcloud-helper --format=json", "ccccccccccccccc1",
                   (time_t)1700060002);
    dyn_entry_set_chain(&e[2], "gke-gcloud-auth", "kubectl", "zsh");

    fanotify_load_dyn_allowlist(e, 3);

    ASSERT(fanotify_prune_dyn_list(0, &removed) == 0 && removed == 1,
           "only the same-chain duplicate is pruned");

    n = persist_load(g_dyn_allow_file, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 2, "the warp grant and the newest zsh grant survive");
    ASSERT(strcmp(out[0].rule_id, "bbbbbbbbbbbbbbb1") == 0 &&
               strcmp(out[1].rule_id, "ccccccccccccccc1") == 0,
           "survivors are the warp and the newest zsh entries");

    removed = -1;
    ASSERT(fanotify_prune_dyn_list(0, &removed) == 0 && removed == 0,
           "a second prune finds no cross-chain duplicates");
}

/*
 * A failed state write must leave the in-memory list exactly as it was:
 * remove, clear and prune all restore their pre-mutation snapshot and
 * report the failure.
 */
static void test_dyn_write_failure_restores(void)
{
    PersistEntry e[2];
    int removed = -1;

    dyn_fixture_reset();

    dyn_entry_fill(&e[0], "/usr/bin/wf-one", PIN_SHA_A, "/home/u/one",
                   "wf-one --read", "1111111111111111", (time_t)1700040000);
    fanotify_load_dyn_allowlist(e, 1);

    persist_test_fail_fsync_after(0);
    ASSERT(fanotify_remove_dyn_entry(0, "11111111") == -1,
           "failed remove reports the write failure");
    persist_test_fail_fsync_after(-1);
    ASSERT(test_match_allow("/usr/bin/wf-one", PIN_SHA_A, "/home/u/one",
                            "wf-one --read") == 1,
           "failed remove restored the in-memory entry");

    dyn_entry_fill(&e[0], "/usr/bin/wf-two", PIN_SHA_A, "/home/u/two",
                   "wf-two --read", "2222222222222222", (time_t)1700040001);
    fanotify_load_dyn_allowlist(e, 1);

    persist_test_fail_fsync_after(0);
    ASSERT(fanotify_clear_dyn_list(0) == -1, "failed clear reports -1");
    persist_test_fail_fsync_after(-1);
    ASSERT(test_match_allow("/usr/bin/wf-two", PIN_SHA_A, "/home/u/two",
                            "wf-two --read") == 1,
           "failed clear restored the in-memory list");

    dyn_entry_fill(&e[0], "/usr/bin/wf-dup", PIN_SHA_A, "/home/u/dup",
                   "wf-dup --read", "3333333333333333", (time_t)1700040002);
    dyn_entry_fill(&e[1], "/usr/bin/wf-dup", PIN_SHA_B, "/home/u/dup",
                   "wf-dup --read", "4444444444444444", (time_t)1700040003);
    fanotify_load_dyn_allowlist(e, 2);

    persist_test_fail_fsync_after(0);
    ASSERT(fanotify_prune_dyn_list(0, &removed) == -1 && removed == 0,
           "failed prune reports -1 and removed 0");
    persist_test_fail_fsync_after(-1);
    ASSERT(test_match_allow("/usr/bin/wf-dup", PIN_SHA_A, "/home/u/dup",
                            "wf-dup --read") == 1 &&
               test_match_allow("/usr/bin/wf-dup", PIN_SHA_B, "/home/u/dup",
                                "wf-dup --read") == 1,
           "failed prune restored both entries");
}

/*
 * Part 1d: the command-line fingerprint covers the FULL raw command line,
 * not just the 512-byte display form.  Two invocations that share a long
 * prefix but differ at the end must fingerprint differently (the old
 * truncated hash let one approved command cover the other), and the
 * digest must equal SHA-512 over the raw /proc bytes.
 */

/* Spawn a long-running child whose argv carries one unique marker. */
static pid_t spawn_marked_child(const char *marker)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0)
    {
        /* Own process group so the whole child tree can be killed. */
        setpgid(0, 0);
        /* sh keeps the marker in its argv (as $0) while sleep holds it
         * alive.  The trailing ";" stops sh from exec-replacing itself
         * with sleep (which would drop the marker from argv). */
        execl("/bin/sh", "sh", "-c", "sleep 30; :", marker, (char *)NULL);
        _exit(127);
    }
    return pid;
}

static int read_raw_cmdline(pid_t pid, char *buf, size_t sz)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, sz - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    return (int)n;
}

/*
 * Wait until the child's cmdline really contains the marker: right after
 * fork() the child still shows the parent's cmdline, which would make two
 * children look identical.
 */
static int wait_for_marker(pid_t pid, const char *marker)
{
    char raw[8192];
    for (int i = 0; i < 200; i++)
    {
        int n = read_raw_cmdline(pid, raw, sizeof(raw));
        if (n > 0 &&
            memmem(raw, (size_t)n, marker, strlen(marker)) != NULL)
            return 0;
        usleep(5000);
    }
    return -1;
}

static void test_cmdline_fingerprint_full(void) {
    char prefix[600];
    memset(prefix, 'p', sizeof(prefix) - 1);
    prefix[sizeof(prefix) - 1] = '\0';

    char arg_a[1024], arg_b[1024];
    snprintf(arg_a, sizeof(arg_a), "%sAAAA", prefix);
    snprintf(arg_b, sizeof(arg_b), "%sBBBB", prefix);

    pid_t pid_a = spawn_marked_child(arg_a);
    pid_t pid_b = spawn_marked_child(arg_b);
    ASSERT(pid_a > 0 && pid_b > 0, "spawn marked children");
    if (pid_a <= 0 || pid_b <= 0)
        return;

    int ready_a = wait_for_marker(pid_a, arg_a);
    int ready_b = wait_for_marker(pid_b, arg_b);
    ASSERT(ready_a == 0 && ready_b == 0, "children exec with their markers");

    if (ready_a == 0 && ready_b == 0)
    {
        char fp_a[129] = "", fp_b[129] = "";
        ASSERT(fanotify_test_cmdline_fingerprint(pid_a, fp_a) == 0,
               "fingerprint child A");
        ASSERT(fanotify_test_cmdline_fingerprint(pid_b, fp_b) == 0,
               "fingerprint child B");
        ASSERT(strcmp(fp_a, fp_b) != 0,
               "commands sharing a 600-byte prefix fingerprint differently");

        char raw[8192];
        int n = read_raw_cmdline(pid_a, raw, sizeof(raw));
        char expected[129];
        ASSERT(n > 0 && sha512_buf(raw, (size_t)n, expected) == 0,
               "independent digest of the raw cmdline");
        ASSERT(n > 0 && strcmp(fp_a, expected) == 0,
               "fingerprint equals SHA-512 of the raw /proc bytes");
    }

    kill(-pid_a, SIGKILL); /* negative: kill the child's process group */
    kill(-pid_b, SIGKILL);
    waitpid(pid_a, NULL, 0);
    waitpid(pid_b, NULL, 0);
}

/*
 * The kdialog --menu decision seam: a grant exists only as an explicit
 * tag the user selected.  Every other string — including empty, NULL,
 * near-misses and tokens an error path or forged stream might produce —
 * must deny.  The dialog runtime (run_kdialog_menu) is a thin reader:
 * anything but exit-0 yields no token to this mapper.
 */
static void test_menu_choice_mapping(void) {
    ASSERT(notify_test_menu_choice("once") == NOTIFY_ALLOW_ONCE,
           "once tag allows once");
    ASSERT(notify_test_menu_choice("session") == NOTIFY_ALLOW_SESSION,
           "session tag allows for the session");
    ASSERT(notify_test_menu_choice("always") == NOTIFY_ALLOW_ALWAYS,
           "always tag allows permanently");
    ASSERT(notify_test_menu_choice("deny") == NOTIFY_DENY,
           "deny tag denies");
    ASSERT(notify_test_menu_choice("deny-session") == NOTIFY_DENY_SESSION,
           "deny-session tag denies for the session");
    ASSERT(notify_test_menu_choice("deny-always") == NOTIFY_DENY_ALWAYS,
           "deny-always tag denies permanently");

    /* Fail-closed for anything that is not an exact known tag. */
    ASSERT(notify_test_menu_choice("") == NOTIFY_DENY, "empty token denies");
    ASSERT(notify_test_menu_choice(NULL) == NOTIFY_DENY, "NULL token denies");
    ASSERT(notify_test_menu_choice("Once") == NOTIFY_DENY,
           "wrong case is not a known tag: denies");
    ASSERT(notify_test_menu_choice("always ") == NOTIFY_DENY,
           "trailing space is not a known tag: denies");
    ASSERT(notify_test_menu_choice("nope") == NOTIFY_DENY,
           "unknown token denies");
}

/*
 * Exec-capable fixture directory for the kdialog stand-ins.
 *
 * The dialog tests must fork/exec a helper script, but /tmp is commonly
 * mounted noexec (the CI environment does exactly that).  The fixture
 * creates a per-run directory next to the test binary (TMPDIR and /tmp
 * are fallbacks) and proves it can execute a file with a shebang probe:
 * when no candidate directory is exec-capable, the dialog tests print
 * SKIP and return instead of failing.  Every dump path lives in this
 * directory and is passed to the script through the environment, so no
 * fixed global path is ever used and parallel runs cannot collide.
 */
#define DLG_DIR_MAX (PATH_MAX + 64)
#define DLG_PATH_MAX (PATH_MAX + 160)

static char g_dlg_dir[DLG_DIR_MAX];
static int g_dlg_ready = 0;

/* Run a tiny shebang script in 'dir' to prove it can exec. */
static int dlg_probe_is_exec(const char *dir)
{
    char probe[DLG_PATH_MAX];
    FILE *f;
    pid_t pid;
    int status = 0;

    snprintf(probe, sizeof(probe), "%s/probe.sh", dir);
    f = fopen(probe, "w");
    if (!f)
        return -1;
    fputs("#!/bin/sh\nexit 0\n", f);
    if (ferror(f) || fclose(f) != 0)
    {
        unlink(probe);
        return -1;
    }
    if (chmod(probe, 0700) != 0)
    {
        unlink(probe);
        return -1;
    }

    pid = fork();
    if (pid == 0)
    {
        execl(probe, probe, (char *)NULL);
        _exit(127);
    }
    if (pid < 0 || waitpid(pid, &status, 0) != pid)
    {
        unlink(probe);
        return -1;
    }
    unlink(probe);
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

static int dlg_fixture_init(void)
{
    const char *candidates[4];
    const char *tmpdir;
    char exe[PATH_MAX];
    char exe_dir[PATH_MAX];
    ssize_t n;
    int nc = 0;
    int i;

    if (g_dlg_ready)
        return 0;

    exe_dir[0] = '\0';
    n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0)
    {
        char *slash;

        exe[n] = '\0';
        slash = strrchr(exe, '/');
        if (slash && slash != exe)
        {
            *slash = '\0';
            snprintf(exe_dir, sizeof(exe_dir), "%s", exe);
            candidates[nc++] = exe_dir;
        }
    }
    tmpdir = getenv("TMPDIR");
    if (tmpdir && tmpdir[0] != '\0')
        candidates[nc++] = tmpdir;
    candidates[nc++] = "/tmp";
    candidates[nc] = NULL;

    for (i = 0; candidates[i] != NULL; i++)
    {
        snprintf(g_dlg_dir, sizeof(g_dlg_dir), "%s/.fileshield_dlg_XXXXXX",
                 candidates[i]);
        if (!mkdtemp(g_dlg_dir))
            continue;
        if (dlg_probe_is_exec(g_dlg_dir) == 0)
        {
            g_dlg_ready = 1;
            return 0;
        }
        rmdir(g_dlg_dir);
        g_dlg_dir[0] = '\0';
    }
    return -1;
}

static void dlg_fixture_cleanup(void)
{
    static const char *const names[] = {
        "menu.sh", "hashchange.sh", "menu-body.txt", "menu-labels.txt",
        "menu-default.txt", "hashchange-body.txt", "hashchange-default.txt"};
    char path[DLG_PATH_MAX];
    size_t i;

    if (!g_dlg_ready)
        return;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
    {
        snprintf(path, sizeof(path), "%s/%s", g_dlg_dir, names[i]);
        unlink(path);
    }
    rmdir(g_dlg_dir);
    g_dlg_ready = 0;
}

/* Create one fixture script inside the exec-capable directory. */
static int dlg_write_script(const char *name, const char *body)
{
    char path[DLG_PATH_MAX];
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s", g_dlg_dir, name);
    f = fopen(path, "w");
    if (!f)
        return -1;
    fputs(body, f);
    if (ferror(f) || fclose(f) != 0)
        return -1;
    return chmod(path, 0700);
}

/* Read one dump file from the fixture directory into out. */
static long dlg_read_dump(const char *name, char *out, size_t outsz)
{
    char path[DLG_PATH_MAX];
    FILE *f;
    size_t n;

    snprintf(path, sizeof(path), "%s/%s", g_dlg_dir, name);
    f = fopen(path, "r");
    if (!f)
    {
        out[0] = '\0';
        return -1;
    }
    n = fread(out, 1, outsz - 1, f);
    fclose(f);
    out[n] = '\0';
    return (long)n;
}

/*
 * Menu end-to-end: drive the real notify_ask -> run_kdialog_menu fork
 * with a scripted kdialog stand-in (notify_test_set_kdialog_path), so
 * the child's argv shape, the stdout pipe drain and the token->decision
 * mapping are proven together — without needing a desktop click.
 * The script asserts the KF6 --menu shape (kdialog --title Fileshield
 * --menu BODY + 6 tag/label pairs = 16 args after argv[0]) and then
 * behaves per FAKE_KDIALOG_MODE.  Dump paths arrive via the environment
 * (per-run, next to the test binary) instead of fixed /tmp names, so the
 * test works where /tmp is noexec and parallel runs stay independent.
 */
static void test_menu_end_to_end(void) {
    log_msg(LOG_DEBUG, "warm up syslog before menu child fork");

    /* Root without a detected desktop session makes notify_ask() fail
     * closed before any dialog; that is a genuine environment skip. */
    if (getuid() == 0) {
        printf("SKIP: dialog tests run unprivileged (root prompts need a "
               "detected desktop session)\n");
        return;
    }
    if (dlg_fixture_init() < 0) {
        printf("SKIP: no exec-capable temp directory for the fake-kdialog "
               "script (all candidates are noexec or read-only)\n");
        return;
    }

    char script[DLG_PATH_MAX];
    char body_dump[DLG_PATH_MAX];
    char labels_dump[DLG_PATH_MAX];
    char default_dump[DLG_PATH_MAX];
    snprintf(script, sizeof(script), "%s/menu.sh", g_dlg_dir);
    snprintf(body_dump, sizeof(body_dump), "%s/menu-body.txt", g_dlg_dir);
    snprintf(labels_dump, sizeof(labels_dump), "%s/menu-labels.txt",
             g_dlg_dir);
    snprintf(default_dump, sizeof(default_dump), "%s/menu-default.txt",
             g_dlg_dir);

    /* timeout execs the script with argv[0] = script path, so:
     * $1=--title $2=Fileshield $3=--menu $4=BODY $5=first TAG $6=first
     * label ... $16=last label, then $17=--default $18=deny label
     * => 18 positional args.  Asserting the TAG sits at $5 is what pins
     * the real kdialog contract: the earlier bug (an extra argv element
     * shifting the pairs) still matched a naive count check but broke
     * the tag/item alignment.  The --default pair must name the Deny
     * Once row so a confirm with no selection denies instead of
     * granting. */
    ASSERT(dlg_write_script(
               "menu.sh",
               "#!/bin/sh\n"
               "[ \"$#\" -eq 18 ] || exit 0\n"
               "[ \"$1\" = \"--title\" ] || exit 0\n"
               "[ \"$3\" = \"--menu\" ] || exit 0\n"
               "[ \"$5\" = \"once\" ] || exit 0\n"
               "[ \"${17}\" = \"--default\" ] || exit 0\n"
               "case \"$FAKE_KDIALOG_MODE\" in\n"
               "  pick) echo once; exit 0 ;;\n"
               "  garbage) echo \"Not A Tag\"; exit 0 ;;\n"
               "  empty-ok) exit 0 ;;\n"
               "  dump) printf '%s' \"$4\" > \"$FAKE_KDIALOG_BODY_DUMP\"; "
               "printf '%s|%s|%s|%s|%s|%s' \"$6\" \"$8\" \"${10}\" \"${12}\" "
               "\"${14}\" \"${16}\" > \"$FAKE_KDIALOG_LABELS_DUMP\"; "
               "printf '%s|%s' \"${17}\" \"${18}\" "
               "> \"$FAKE_KDIALOG_DEFAULT_DUMP\"; "
               "echo once; exit 0 ;;\n"
               "esac\n"
               "exit 1\n") == 0,
           "write fake kdialog menu script");

    /* The script's dumps are read by the parent after the child exits;
     * the over-long buffer bounds are compile-time only (VAR names are
     * short), so the snprintf result is not checked. */
    (void)setenv("FAKE_KDIALOG_BODY_DUMP", body_dump, 1);
    (void)setenv("FAKE_KDIALOG_LABELS_DUMP", labels_dump, 1);
    (void)setenv("FAKE_KDIALOG_DEFAULT_DUMP", default_dump, 1);

    NotifyRequest req;
    memset(&req, 0, sizeof(req));
    req.comm = "fake";
    req.pid = getpid();
    req.ppid = getppid();
    req.comm_parent = "sh";
    req.exe = "/bin/fake";
    req.cmdline = "fake --arg";
    req.path = "/tmp/fake-secret";
    req.user_uid = getuid();
    req.user_ttl = 60;
    req.session_ttl = 0;
    req.hash_unavailable = 0;
    req.hash_failure = NULL;

    notify_test_set_kdialog_path(script);

    /* Explicit selection: exit 0 + the tag on stdout -> grant. */
    ASSERT(setenv("FAKE_KDIALOG_MODE", "pick", 1) == 0, "set pick mode");
    ASSERT(notify_ask(&req) == NOTIFY_ALLOW_ONCE,
           "menu pick: tag on stdout grants once");

    /* A label (not a tag) on stdout is not a grant channel: deny. */
    ASSERT(setenv("FAKE_KDIALOG_MODE", "garbage", 1) == 0, "set garbage mode");
    ASSERT(notify_ask(&req) == NOTIFY_DENY,
           "menu: non-tag stdout fails the exact match and denies");

    /* Exit 0 but no token at all: deny (only exit-0 is not enough). */
    ASSERT(setenv("FAKE_KDIALOG_MODE", "empty-ok", 1) == 0, "set empty-ok mode");
    ASSERT(notify_ask(&req) == NOTIFY_DENY,
           "menu: zero exit without a token still denies");

    /* Cancel semantics: nonzero exit -> no selection -> deny. */
    ASSERT(unsetenv("FAKE_KDIALOG_MODE") == 0, "clear mode");
    ASSERT(notify_ask(&req) == NOTIFY_DENY,
           "menu: cancel (exit 1, no stdout) denies");

    /*
     * Dump mode: pin the design contract of the text a real kdialog
     * would render, plus the row labels — verified as text, no GUI.
     * The per-run dumps are removed by dlg_fixture_cleanup().
     */
    ASSERT(setenv("FAKE_KDIALOG_MODE", "dump", 1) == 0, "set dump mode");
    ASSERT(notify_ask(&req) == NOTIFY_ALLOW_ONCE, "dump run still grants");

    char dump[4096];
    long dlen = dlg_read_dump("menu-body.txt", dump, sizeof(dump));
    ASSERT(dlen > 0, "rendered body dump written");
    ASSERT(strstr(dump, "<div align=\"left\">") != NULL,
           "body pinned left-aligned against kdialog's center label");
    ASSERT(strstr(dump, "font-size") == NULL,
           "no font-size overrides: one uniform text size");
    ASSERT(strstr(dump, "What each row means") == NULL,
           "row-meaning heading removed");
    ASSERT(strstr(dump, "<b>Binary:</b>") != NULL &&
               strstr(dump, "<b>Command:</b>") != NULL &&
               strstr(dump, "<b>Path:</b>") != NULL,
           "binary/command/path keys present");
    ASSERT(strstr(dump, "<b>Command:</b> <tt>fake --arg</tt><br>"
                        "<b>Path:</b> <tt>/tmp/fake-secret</tt>") != NULL,
           "Path follows Command immediately (no blank line)");
    {
        const char *pbin = strstr(dump, "<b>Binary:</b>");
        const char *pcmd = strstr(dump, "<b>Command:</b>");
        const char *ppth = strstr(dump, "<b>Path:</b>");
        ASSERT(pbin != NULL && pcmd != NULL && ppth != NULL &&
                   pbin < pcmd && pcmd < ppth,
               "field order: Binary, Command, Path");
    }
    ASSERT(strstr(dump, "<b>Allow Once</b> \xe2\x80\x94 "
                        "this file and process") != NULL,
           "Allow Once: description inline after the name");
    ASSERT(strstr(dump, "<b>Allow Session</b> \xe2\x80\x94 "
                        "this binary and file") != NULL,
           "Allow Session: description inline after the name");
    ASSERT(strstr(dump, "<b>Allow Always</b> \xe2\x80\x94 saved "
                        "permanently for this command and file") != NULL,
           "Allow Always description is the concise inline line");
    ASSERT(strstr(dump, "&nbsp;") == NULL,
           "no indentation entities: descriptions sit inline");
    ASSERT(strstr(dump, "call chain") == NULL,
           "old wordy Allow Always description is gone");

    char labels[512];
    long llen = dlg_read_dump("menu-labels.txt", labels, sizeof(labels));
    ASSERT(llen > 0, "labels dump written");
    ASSERT(strcmp(labels,
                  "Allow Once - this file and process, cached 60 seconds|"
                  "Allow Session - this binary and file until the session ends|"
                  "Allow Always - saved permanently for this command and file|"
                  "Deny Once - block this access only|"
                  "Deny Session - block this binary and file until the session ends|"
                  "Deny Always - block permanently for this command and file")
               == 0,
           "rows carry the concise inline descriptions, hyphen separated");

    /* A confirm with no deliberate selection must deny, not grant: the
     * --default row is the deny row. */
    char defdump[128];
    long fllen = dlg_read_dump("menu-default.txt", defdump, sizeof(defdump));
    ASSERT(fllen > 0, "default dump written");
    ASSERT(strcmp(defdump,
                  "--default|Deny Once - block this access only") == 0,
           "no-selection confirm defaults to Deny Once (deny, never allow)");

    notify_test_set_kdialog_path(NULL);
}

/*
 * Hash-change menu end-to-end: the scripted kdialog stand-in asserts the
 * exact two-row --menu argv (--menu BODY update "Update & Allow" deny
 * Deny --default Deny) and dumps the body, so the test proves every
 * interpolated value is HTML-escaped and that only the "update" stdout
 * tag grants.  Pre-fix (the yesnocancel form) the argv did not match and
 * the deny default did not gate Enter; the original B1 bug also let raw
 * <, > and & through, which the escape asserts below catch.
 */
static void test_hash_change_prompt_escapes(void) {
    log_msg(LOG_DEBUG, "warm up syslog before hash-change child fork");

    if (getuid() == 0) {
        printf("SKIP: dialog tests run unprivileged (root prompts need a "
               "detected desktop session)\n");
        return;
    }
    if (dlg_fixture_init() < 0) {
        printf("SKIP: no exec-capable temp directory for the fake-kdialog "
               "script (all candidates are noexec or read-only)\n");
        return;
    }

    char script[DLG_PATH_MAX];
    char body_dump[DLG_PATH_MAX];
    char default_dump[DLG_PATH_MAX];
    snprintf(script, sizeof(script), "%s/hashchange.sh", g_dlg_dir);
    snprintf(body_dump, sizeof(body_dump), "%s/hashchange-body.txt",
             g_dlg_dir);
    snprintf(default_dump, sizeof(default_dump), "%s/hashchange-default.txt",
             g_dlg_dir);

    /*
     * timeout execs the script, so $1..$10 are the kdialog arguments:
     * --title Fileshield --menu BODY update "Update & Allow" deny Deny
     * --default Deny.  Any mismatch writes a diagnostic to the body dump
     * and exits; a missing dump then fails the assertions below (that is
     * how a yesnocancel-shaped argv fails this test).
     */
    ASSERT(dlg_write_script(
               "hashchange.sh",
               "#!/bin/sh\n"
               "body=\"$FAKE_KDIALOG_HASH_BODY_DUMP\"\n"
               "[ \"$#\" -eq 10 ] || { printf 'argv-count:%s' \"$#\" > "
               "\"$body\"; exit 1; }\n"
               "[ \"$1\" = \"--title\" ] && [ \"$2\" = \"Fileshield\" ] || "
               "{ printf 'argv-title' > \"$body\"; exit 1; }\n"
               "[ \"$3\" = \"--menu\" ] || { printf 'argv-mode' > "
               "\"$body\"; exit 1; }\n"
               "[ \"$5\" = \"update\" ] && [ \"$6\" = \"Update & Allow\" ] "
               "|| { printf 'argv-allow-row' > \"$body\"; exit 1; }\n"
               "[ \"$7\" = \"deny\" ] && [ \"$8\" = \"Deny\" ] || { "
               "printf 'argv-deny-row' > \"$body\"; exit 1; }\n"
               "[ \"$9\" = \"--default\" ] && [ \"${10}\" = \"Deny\" ] || { "
               "printf 'argv-default' > \"$body\"; exit 1; }\n"
               "printf '%s|%s' \"$9\" \"${10}\" > "
               "\"$FAKE_KDIALOG_HASH_DEFAULT_DUMP\"\n"
               "printf '%s' \"$4\" > \"$body\"\n"
               "case \"$FAKE_KDIALOG_HASH_MODE\" in "
               "approve) printf 'update'; exit 0 ;; "
               "deny) printf 'deny'; exit 0 ;; "
               "empty) exit 0 ;; esac\n"
               "exit 1\n") == 0,
           "write fake kdialog hash-change script");

    (void)setenv("FAKE_KDIALOG_HASH_BODY_DUMP", body_dump, 1);
    (void)setenv("FAKE_KDIALOG_HASH_DEFAULT_DUMP", default_dump, 1);

    /* Every field carries markup an attacker could use to forge the
     * body; all of them must arrive as entities. */
    NotifyHashChange req;
    memset(&req, 0, sizeof(req));
    req.rule_pattern = "/opt/<tool>&co";
    req.exe = "/usr/bin/<exe>&runner";
    req.old_hash = PIN_SHA_A;
    req.new_hash = PIN_SHA_B;
    req.path = "/home/u/<secret>&file";
    req.cmdline = "run --x <y> & z";
    req.pid = getpid();
    req.user_uid = getuid();

    notify_test_set_kdialog_path(script);

    ASSERT(setenv("FAKE_KDIALOG_HASH_MODE", "deny", 1) == 0, "deny mode");
    ASSERT(notify_ask_hash_change(&req) == NOTIFY_DENY,
           "an emitted deny tag denies (old pin kept)");

    char dump[8192];
    ASSERT(dlg_read_dump("hashchange-body.txt", dump, sizeof(dump)) > 0,
           "hash-change body dump written (argv shape matched)");
    ASSERT(strstr(dump, "/opt/&lt;tool&gt;&amp;co") != NULL,
           "rule pattern is HTML-escaped in the body");
    ASSERT(strstr(dump, "/usr/bin/&lt;exe&gt;&amp;runner") != NULL,
           "binary path is HTML-escaped in the body");
    ASSERT(strstr(dump, "/home/u/&lt;secret&gt;&amp;file") != NULL,
           "target path is HTML-escaped in the body");
    ASSERT(strstr(dump, "run --x &lt;y&gt; &amp; z") != NULL,
           "command line is HTML-escaped in the body");
    ASSERT(strstr(dump, "/opt/<tool>") == NULL &&
               strstr(dump, "<exe>") == NULL &&
               strstr(dump, "<secret>") == NULL &&
               strstr(dump, "<y>") == NULL,
           "no raw interpolated markup anywhere in the body");

    char defdump[64];
    ASSERT(dlg_read_dump("hashchange-default.txt", defdump,
                         sizeof(defdump)) > 0,
           "hash-change default dump written");
    ASSERT(strcmp(defdump, "--default|Deny") == 0,
           "--default preselects the deny row (Enter emits the deny tag)");

    /* Approve mode: the script echoes the allow tag and exits 0. */
    ASSERT(setenv("FAKE_KDIALOG_HASH_MODE", "approve", 1) == 0,
           "approve mode");
    ASSERT(notify_ask_hash_change(&req) == NOTIFY_ALLOW_ALWAYS,
           "explicit update tag grants the update");

    /* Exit 0 with no tag at all must deny (no positive channel). */
    ASSERT(setenv("FAKE_KDIALOG_HASH_MODE", "empty", 1) == 0,
           "empty-output mode");
    ASSERT(notify_ask_hash_change(&req) == NOTIFY_DENY,
           "empty stdout denies (no usable token)");

    notify_test_set_kdialog_path(NULL);
}

/*
 * The styled description renders as rich text, so escaping is the
 * injection defense: file names and comm are attacker-controlled and
 * may legally contain < > &, which must arrive as entities, while UTF-8
 * (bullets, em-dash) passes verbatim.  A buffer that cannot hold the
 * escaped result must yield NO output at all (the caller falls back to
 * the plain body rather than emit half a document).
 */
static void test_html_escape(void) {
    char out[512];

    ASSERT(notify_test_html_escape("a & b < c > d\ne", out, sizeof(out)) == 0,
           "escape succeeds");
    ASSERT(strcmp(out, "a &amp; b &lt; c &gt; d<br>e") == 0,
           "amp/lt/gt escaped, newline became <br>");

    /* Injection attempt through a crafted file name: must render text. */
    ASSERT(notify_test_html_escape("/x/<img src=y onerror=pwn()> <b>ALLOW</b>",
                                   out, sizeof(out)) == 0,
           "hostile name escapes");
    ASSERT(strstr(out, "<img") == NULL, "no live <img> tag emitted");
    ASSERT(strstr(out, "<b>") == NULL, "no forged bold tag emitted");
    ASSERT(strstr(out, "&lt;img") != NULL, "angle brackets neutralized");

    /* UTF-8 (em-dash, bullet) survives byte-for-byte. */
    ASSERT(notify_test_html_escape("\xe2\x80\x94 \xe2\x80\xa2 ok", out,
                                   sizeof(out)) == 0,
           "utf-8 body escapes cleanly");
    ASSERT(strstr(out, "\xe2\x80\x94 \xe2\x80\xa2 ok") != NULL,
           "utf-8 passes verbatim");

    /* Truncation: nothing is emitted, contract says plain fallback. */
    char tiny[8];
    ASSERT(notify_test_html_escape("far too long to fit", tiny,
                                   sizeof(tiny)) == -1,
           "undersized buffer reports truncation");
    ASSERT(tiny[0] == '\0', "truncated output is emptied, not half-written");
}

/*
 * Part 1: fill the deferred queue to capacity, verify a full queue
 * refuses further events, then verify the fail-closed flush denies and
 * closes every deferred event.
 */
static void test_defer_flush_contract(void) {
    /*
     * Pre-warm glibc's lazily-opened /dev/log socket: flush_pending()
     * calls log_msg() after closing the deferred fds, and on first use
     * syslog would otherwise claim the lowest freed fd number — which
     * would make the EBADF close-check below misread that fd as open.
     */
    log_msg(LOG_DEBUG, "warm up syslog socket");

    int resp_pipe[2];
    ASSERT(pipe(resp_pipe) == 0, "create response pipe");

    enum { MAX_PROBE = 4096 }; /* well above the internal PENDING_MAX */
    static int event_fds[MAX_PROBE];
    int filled = 0;

    for (int i = 0; i < MAX_PROBE; i++) {
        int efd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        ASSERT(efd >= 0, "open event fd");
        if (efd < 0)
            break;

        struct fanotify_event_metadata ev;
        memset(&ev, 0, sizeof(ev));
        ev.event_len = sizeof(ev);
        ev.vers = FANOTIFY_METADATA_VERSION;
        ev.mask = FAN_OPEN_PERM;
        ev.fd = efd;
        ev.pid = (int)getpid();

        if (fanotify_defer_event(&ev) == 0) {
            event_fds[filled++] = efd;
        } else {
            /* Queue full: caller contract is to fail closed. */
            close(efd);
            break;
        }
    }

    ASSERT(filled > 0, "deferred queue accepted events");

    struct fanotify_event_metadata probe;
    memset(&probe, 0, sizeof(probe));
    probe.event_len = sizeof(probe);
    probe.vers = FANOTIFY_METADATA_VERSION;
    probe.mask = FAN_OPEN_PERM;
    probe.fd = -1; /* FAN_NOFD */
    probe.pid = (int)getpid();
    ASSERT(fanotify_defer_event(&probe) == -1,
            "defer into a full queue fails closed");

    /* Fail-closed flush: deny + close every deferred event. */
    fanotify_flush_pending(resp_pipe[1]);

    /* Observable empty-queue check without a count helper: after the
     * flush, a fresh event must be accepted again, and the follow-up
     * fail-closed flush denies it exactly like the first batch. */
    int re_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT(re_fd >= 0, "open re-defer event fd");
    struct fanotify_event_metadata re_ev;
    memset(&re_ev, 0, sizeof(re_ev));
    re_ev.event_len = sizeof(re_ev);
    re_ev.vers = FANOTIFY_METADATA_VERSION;
    re_ev.mask = FAN_OPEN_PERM;
    re_ev.fd = re_fd;
    re_ev.pid = (int)getpid();
    ASSERT(fanotify_defer_event(&re_ev) == 0,
            "queue accepts events again after flush");
    fanotify_flush_pending(resp_pipe[1]);
    /* Close the write end so the read below returns EOF instead of
     * blocking forever when a response is missing: a hanging make test is
     * worse than a failing one. */
    close(resp_pipe[1]);
    resp_pipe[1] = -1;

    /* Exactly one fanotify_response per deferred event must arrive. */
    size_t want = (size_t)(filled + 1) * sizeof(struct fanotify_response);
    char *buf = malloc(want);
    ASSERT(buf != NULL, "alloc response buffer");
    size_t got = 0;
    while (got < want) {
        ssize_t n = read(resp_pipe[0], buf + got, want - got);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        got += (size_t)n;
    }
    ASSERT(got == want, "one deny response per deferred event");

    for (int i = 0; i < filled; i++) {
        const struct fanotify_response *r =
            (const struct fanotify_response *)(buf +
                (size_t)i * sizeof(*r));
        ASSERT(r->response == FAN_DENY, "flush response is FAN_DENY");
        ASSERT(r->fd == event_fds[i],
               "flush response targets the deferred fd");
        ASSERT(fcntl(event_fds[i], F_GETFD) == -1 && errno == EBADF,
               "deferred fd was closed by flush");
    }

    /* The re-deferred event is the last response and is also closed. */
    const struct fanotify_response *last =
        (const struct fanotify_response *)(buf + (size_t)filled * sizeof(*last));
    ASSERT(last->response == FAN_DENY, "flush response is FAN_DENY");
    ASSERT(last->fd == re_fd, "flush response targets the re-deferred fd");
    ASSERT(fcntl(re_fd, F_GETFD) == -1 && errno == EBADF,
           "re-deferred fd was closed by flush");

    free(buf);
    close(resp_pipe[0]);
    if (resp_pipe[1] >= 0)
        close(resp_pipe[1]);
}

/*
 * Part 1c: a response the kernel refuses must be queued with its event fd
 * kept open and delivered later — closing the fd would leave the caller's
 * open() blocked until group close, where the kernel auto-allows it.
 * A full non-blocking pipe reproduces the transient EAGAIN failure
 * deterministically.
 */
static void test_respond_failure_retry(void) {
    /* Warm up syslog before fd juggling (same reason as Part 1). */
    log_msg(LOG_DEBUG, "warm up syslog socket");

    int group[2];
    ASSERT(pipe(group) == 0, "create response pipe");
    int fl = fcntl(group[1], F_GETFL, 0);
    ASSERT(fl >= 0 && fcntl(group[1], F_SETFL, fl | O_NONBLOCK) == 0,
           "make the response pipe write end non-blocking");
    int flr = fcntl(group[0], F_GETFL, 0);
    ASSERT(flr >= 0 && fcntl(group[0], F_SETFL, flr | O_NONBLOCK) == 0,
           "make the response pipe read end non-blocking");

    char filler[4096];
    memset(filler, 0, sizeof(filler));
    char drain_buf[4096];

    /* --- 1: queued response is delivered by the retry path --------- */
    while (write(group[1], filler, sizeof(filler)) > 0)
        ;
    ASSERT(errno == EAGAIN, "response pipe is full");

    int efd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT(efd >= 0, "open event fd");
    struct fanotify_event_metadata ev;
    memset(&ev, 0, sizeof(ev));
    ev.event_len = sizeof(ev);
    ev.vers = FANOTIFY_METADATA_VERSION;
    ev.mask = FAN_OPEN_PERM;
    ev.fd = efd;
    ev.pid = (int)getpid();
    ASSERT(fanotify_defer_event(&ev) == 0, "defer the event");

    fanotify_flush_pending(group[1]);
    ASSERT(fcntl(efd, F_GETFD) != -1,
           "event fd stays open while the response is queued");

    /* Free the pipe, then force the shutdown drain: the queued DENY must
     * be delivered and the event fd closed. */
    while (read(group[0], drain_buf, sizeof(drain_buf)) > 0)
        ;
    fanotify_drain_and_deny(group[1]);

    struct fanotify_response resp;
    ssize_t got = read(group[0], &resp, sizeof(resp));
    ASSERT(got == (ssize_t)sizeof(resp), "queued response was delivered");
    ASSERT(resp.fd == efd && resp.response == FAN_DENY,
           "delivered response is the queued DENY");
    ASSERT(fcntl(efd, F_GETFD) == -1 && errno == EBADF,
           "event fd closed after the retry delivered the response");

    /* --- 2: if the write still fails at shutdown, the event must be
     * released (fd closed, queue emptied) rather than leaked ---------- */
    while (write(group[1], filler, sizeof(filler)) > 0)
        ;
    int efd2 = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT(efd2 >= 0, "open second event fd");
    memset(&ev, 0, sizeof(ev));
    ev.event_len = sizeof(ev);
    ev.vers = FANOTIFY_METADATA_VERSION;
    ev.mask = FAN_OPEN_PERM;
    ev.fd = efd2;
    ev.pid = (int)getpid();
    ASSERT(fanotify_defer_event(&ev) == 0, "defer the second event");

    fanotify_flush_pending(group[1]);
    ASSERT(fcntl(efd2, F_GETFD) != -1, "second event fd stays open");
    fanotify_drain_and_deny(group[1]); /* stored and forced DENY both fail */
    ASSERT(fcntl(efd2, F_GETFD) == -1 && errno == EBADF,
           "shutdown releases the event fd even when nothing can be written");

    /* --- 3: delivery works again on a healthy pipe (queue is empty) -- */
    while (read(group[0], drain_buf, sizeof(drain_buf)) > 0)
        ;
    int efd3 = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT(efd3 >= 0, "open third event fd");
    memset(&ev, 0, sizeof(ev));
    ev.event_len = sizeof(ev);
    ev.vers = FANOTIFY_METADATA_VERSION;
    ev.mask = FAN_OPEN_PERM;
    ev.fd = efd3;
    ev.pid = (int)getpid();
    ASSERT(fanotify_defer_event(&ev) == 0, "defer the third event");

    fanotify_flush_pending(group[1]);
    got = read(group[0], &resp, sizeof(resp));
    ASSERT(got == (ssize_t)sizeof(resp) && resp.fd == efd3 &&
               resp.response == FAN_DENY,
           "a healthy pipe delivers directly again");
    ASSERT(fcntl(efd3, F_GETFD) == -1, "third event fd closed");

    close(group[0]);
    close(group[1]);
}

/*
 * Part 1d: the retry queue must never abandon a decision when it reaches
 * the old fixed capacity (UNANSWERED_MAX = 64); it doubles instead.  A
 * full non-blocking pipe makes every write fail with EAGAIN, so the
 * queue is the only storage; after draining the pipe, drain_and_deny()
 * must deliver one exact fanotify_response (FAN_DENY, target fd) per
 * retained decision and close every event fd.  On the pre-fix code call
 * 65 returned -2 and the decision was dropped.
 */
static void test_unanswered_queue_grows(void) {
    log_msg(LOG_DEBUG, "warm up syslog socket");

    int group[2];
    ASSERT(pipe(group) == 0, "create grow-response pipe");
    int fl = fcntl(group[1], F_GETFL, 0);
    ASSERT(fl >= 0 && fcntl(group[1], F_SETFL, fl | O_NONBLOCK) == 0,
           "make the grow pipe write end non-blocking");
    fl = fcntl(group[0], F_GETFL, 0);
    ASSERT(fl >= 0 && fcntl(group[0], F_SETFL, fl | O_NONBLOCK) == 0,
           "make the grow pipe read end non-blocking");

    enum { DECISIONS = 100 }; /* well beyond the old fixed capacity of 64 */
    static int event_fds[DECISIONS];

    char filler[4096];
    memset(filler, 0, sizeof(filler));
    while (write(group[1], filler, sizeof(filler)) > 0)
        ;
    ASSERT(errno == EAGAIN, "grow pipe is full");

    for (int i = 0; i < DECISIONS; i++) {
        event_fds[i] = open("/dev/null", O_RDONLY | O_CLOEXEC);
        ASSERT(event_fds[i] >= 0, "open grow event fd");
        if (event_fds[i] < 0)
            break;

        struct fanotify_event_metadata ev;
        memset(&ev, 0, sizeof(ev));
        ev.event_len = sizeof(ev);
        ev.vers = FANOTIFY_METADATA_VERSION;
        ev.mask = FAN_OPEN_PERM;
        ev.fd = event_fds[i];
        ev.pid = (int)getpid();

        ASSERT(fanotify_test_respond(group[1], &ev, FAN_DENY) == -1,
               "failed write returns -1 (caller keeps the event fd)");
        ASSERT(fcntl(event_fds[i], F_GETFD) != -1,
               "grow event fd stays open while its response is queued");
    }
    ASSERT(fanotify_test_unanswered_count() == DECISIONS,
           "queue doubled past its old fixed capacity, retaining every "
           "decision");

    /* Free the pipe, then drain: every retained decision must arrive. */
    char drain_buf[4096];
    while (read(group[0], drain_buf, sizeof(drain_buf)) > 0)
        ;
    fanotify_drain_and_deny(group[1]);

    struct fanotify_response resp;
    for (int i = 0; i < DECISIONS; i++) {
        ssize_t got = read(group[0], &resp, sizeof(resp));
        ASSERT(got == (ssize_t)sizeof(resp) && resp.fd == event_fds[i] &&
                   resp.response == FAN_DENY,
               "retained decision delivered as the queued FAN_DENY");
        ASSERT(fcntl(event_fds[i], F_GETFD) == -1 && errno == EBADF,
               "grow event fd closed once its response was delivered");
    }
    ASSERT(fanotify_test_unanswered_count() == 0,
           "drain emptied the retry queue");

    close(group[0]);
    close(group[1]);
}

/*
 * Part 1e: when the retry queue cannot take a response (allocation
 * failure), the event fd must be parked in the bounded stranded list and
 * force-denied as FAN_DENY by the shutdown drain -- never closed
 * unanswered, which would auto-ALLOW it at group close.  The failure is
 * injected through the seam so the fallback is deterministic.
 */
static void test_unanswered_stranded_fallback(void) {
    log_msg(LOG_DEBUG, "warm up syslog socket");

    int group[2];
    ASSERT(pipe(group) == 0, "create stranded-response pipe");
    int fl = fcntl(group[1], F_GETFL, 0);
    ASSERT(fl >= 0 && fcntl(group[1], F_SETFL, fl | O_NONBLOCK) == 0,
           "make the stranded pipe write end non-blocking");
    fl = fcntl(group[0], F_GETFL, 0);
    ASSERT(fl >= 0 && fcntl(group[0], F_SETFL, fl | O_NONBLOCK) == 0,
           "make the stranded pipe read end non-blocking");

    char filler[4096];
    memset(filler, 0, sizeof(filler));
    while (write(group[1], filler, sizeof(filler)) > 0)
        ;
    ASSERT(errno == EAGAIN, "stranded pipe is full");

    int efd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT(efd >= 0, "open stranded event fd");

    struct fanotify_event_metadata ev;
    memset(&ev, 0, sizeof(ev));
    ev.event_len = sizeof(ev);
    ev.vers = FANOTIFY_METADATA_VERSION;
    ev.mask = FAN_OPEN_PERM;
    ev.fd = efd;
    ev.pid = (int)getpid();

    fanotify_test_force_unanswered_alloc_fail(1);
    ASSERT(fanotify_test_respond(group[1], &ev, FAN_ALLOW) == -1,
           "unqueueable response still returns -1 (keep the event fd)");
    fanotify_test_force_unanswered_alloc_fail(0);

    ASSERT(fanotify_test_unanswered_count() == 0,
           "queue did not grow under the injected allocation failure");
    ASSERT(fanotify_test_stranded_count() == 1,
           "the event fd is parked in the stranded list");
    ASSERT(fcntl(efd, F_GETFD) != -1, "stranded event fd stays open");

    /* Free the pipe, then drain: the stranded fd gets a forced FAN_DENY
     * (the fail-closed direction, whatever the original decision). */
    char drain_buf[4096];
    while (read(group[0], drain_buf, sizeof(drain_buf)) > 0)
        ;
    fanotify_drain_and_deny(group[1]);

    struct fanotify_response resp;
    ssize_t got = read(group[0], &resp, sizeof(resp));
    ASSERT(got == (ssize_t)sizeof(resp) && resp.fd == efd &&
               resp.response == FAN_DENY,
           "stranded event fd force-denied before group close");
    ASSERT(fcntl(efd, F_GETFD) == -1 && errno == EBADF,
           "stranded event fd closed after the forced DENY");
    ASSERT(fanotify_test_stranded_count() == 0,
           "drain emptied the stranded list");

    close(group[0]);
    close(group[1]);
}

/*
 * Part 0c: batch_abandon claims the records stranded when an event walk
 * exits early (fatal response failure or metadata-version mismatch).
 * read(2) duplicates an fd for EVERY record in the batch, so every
 * record behind the walk's current one sits open and unanswered: the
 * kernel AUTO-ALLOWS an unanswered permission event when the group fd
 * closes (the fail-open this closes).  A pipe stands in for the group:
 * every write succeeds, so the seam denies + closes without touching
 * the retry queue or g_fatal.
 */
static void test_batch_abandon_claims_stranded(void) {
    log_msg(LOG_DEBUG, "warm up syslog before fd juggling");

    int group[2];
    ASSERT(pipe(group) == 0, "create abandon-response pipe");

    /* Assemble a synthetic batch; the walk's "current" record (already
     * handled by its caller) leads, and the records behind it are the
     * stranded ones batch_abandon must claim. */
    static char raw[6 * 64]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));
    const size_t HDR = sizeof(struct fanotify_event_metadata);
    int efd_perm1 = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int efd_notif = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int efd_perm2 = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int efd_bad = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT(efd_perm1 >= 0 && efd_notif >= 0 && efd_perm2 >= 0 &&
               efd_bad >= 0,
           "open stranded-record fds");

    struct fanotify_event_metadata *rec =
        (struct fanotify_event_metadata *)raw;
    for (int i = 0; i < 6; i++) {
        memset(&rec[i], 0, HDR);
        rec[i].event_len = HDR;
        rec[i].vers = FANOTIFY_METADATA_VERSION;
        rec[i].metadata_len = HDR;
        rec[i].pid = (int)getpid();
    }
    rec[0].mask = FAN_OPEN_PERM;         /* current record: never claimed */
    rec[0].fd = FAN_NOFD;
    rec[1].mask = FAN_OPEN_PERM;         /* stranded: deny + close        */
    rec[1].fd = efd_perm1;
    rec[2].mask = 0;                     /* stranded notif: close only    */
    rec[2].fd = efd_notif;
    rec[3].mask = FAN_OPEN_PERM;         /* stranded, kernel had no fd    */
    rec[3].fd = FAN_NOFD;
    rec[4].mask = FAN_OPEN_PERM;         /* stranded: deny + close        */
    rec[4].fd = efd_perm2;
    rec[5].event_len = 8;                /* malformed tail: unclaimable   */
    rec[5].fd = efd_bad;

    int denied = fanotify_test_batch_abandon(
        group[1], rec, (ssize_t)(6 * HDR));
    ASSERT(denied == 2, "both stranded permission events denied");
    ASSERT(fcntl(efd_perm1, F_GETFD) == -1 && errno == EBADF,
           "stranded permission fd 1 closed after DENY");
    ASSERT(fcntl(efd_notif, F_GETFD) == -1 && errno == EBADF,
           "stranded notification fd closed");
    ASSERT(fcntl(efd_perm2, F_GETFD) == -1 && errno == EBADF,
           "stranded permission fd 2 closed after DENY");
    ASSERT(fcntl(efd_bad, F_GETFD) != -1,
           "record past a malformed length is not guessed at (fd untouched)");
    ASSERT(g_fatal == 0, "abandon via a healthy pipe stays non-fatal");

    /* The two DENY responses must have reached the group in order. */
    struct fanotify_response r1, r2;
    ssize_t got = read(group[0], &r1, sizeof(r1));
    ASSERT(got == (ssize_t)sizeof(r1) && r1.fd == efd_perm1 &&
               r1.response == FAN_DENY,
           "first response is the stranded permission event's DENY");
    got = read(group[0], &r2, sizeof(r2));
    ASSERT(got == (ssize_t)sizeof(r2) && r2.fd == efd_perm2 &&
               r2.response == FAN_DENY,
           "second response is the second stranded DENY");

    close(efd_bad);
    close(group[0]);
    close(group[1]);

    /* A batch whose last record IS the current one strands nothing;
     * an exhausted walk never touches the group fd, so -1 is safe. */
    memset(&rec[0], 0, HDR);
    rec[0].event_len = HDR;
    rec[0].vers = FANOTIFY_METADATA_VERSION;
    rec[0].fd = FAN_NOFD;
    ASSERT(fanotify_test_batch_abandon(-1, rec, (ssize_t)HDR) == 0,
           "an exhausted batch abandons nothing");
}

/*
 * Part 0c-bis: pump-level dialog-group fast path and the M2 publish
 * contract.  A socketpair stands in for the fanotify group (read and
 * write share one fd, exactly like the real one).  An event whose pid IS
 * the dialog pid must be ALLOWed and claimed without touching the
 * pipeline, and g_active_dialog_pid — the handoff that keeps the
 * hash-helper wait pump dialog-aware — must be 0 again once the pump
 * returns at every exit path.
 */
static void test_pump_dialog_group_allow(void) {
    log_msg(LOG_DEBUG, "warm up syslog before pump socketpair");

    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
           "socketpair as fake fanotify group");
    int fl = fcntl(sv[0], F_GETFL, 0);
    ASSERT(fl >= 0 && fcntl(sv[0], F_SETFL, fl | O_NONBLOCK) == 0,
           "make the fake group non-blocking like FAN_NONBLOCK");

    int efd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT(efd >= 0, "open dialog-group event fd");

    static char batch[64]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));
    struct fanotify_event_metadata *md =
        (struct fanotify_event_metadata *)batch;
    memset(batch, 0, sizeof(batch));
    md->event_len = sizeof(*md);
    md->vers = FANOTIFY_METADATA_VERSION;
    md->metadata_len = sizeof(*md);
    md->mask = FAN_OPEN_PERM;
    md->fd = efd;
    md->pid = (int)getpid();

    ssize_t wrote = write(sv[1], batch, sizeof(*md));
    ASSERT(wrote == (ssize_t)sizeof(*md), "feed one event to the pump");

    int responded = fanotify_pump(sv[0], getpid());
    ASSERT(responded == 1, "dialog-group event was decided in the pump");
    ASSERT(fcntl(efd, F_GETFD) == -1 && errno == EBADF,
           "dialog-group event fd closed after the ALLOW");
    ASSERT(fanotify_test_active_dialog_pid() == 0,
           "published dialog pid restored to 0 once the pump returns");

    struct fanotify_response resp;
    ssize_t got = read(sv[1], &resp, sizeof(resp));
    ASSERT(got == (ssize_t)sizeof(resp) && resp.fd == efd &&
               resp.response == FAN_ALLOW,
           "dialog-group event was answered FAN_ALLOW");

    close(sv[0]);
    close(sv[1]);
}

/*
 * Part 0c-ter: fanotify_pump() is bounded per call.  A sustained event
 * stream must not hold the single-threaded daemon (or its SIGTERM/SIGHUP
 * handling) inside one pump call: after a bounded number of read(2)
 * batches the pump returns to its caller's poll loop, leaving the rest
 * of the stream in the group fd.  A SOCK_SEQPACKET socketpair makes the
 * bound deterministic — one record per read(2) — where a SOCK_STREAM
 * peer could coalesce every write into the first read and hide it.
 * Every event must still be answered exactly once, in order, and have
 * its event fd claimed across the caller's re-entries.
 */
static void test_pump_bounded_and_lossless(void) {
    enum { N_EVENTS = 40 };
    int sv[2] = { -1, -1 };
    int efd[N_EVENTS];
    static char rec[sizeof(struct fanotify_event_metadata)]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));
    struct fanotify_event_metadata *md =
        (struct fanotify_event_metadata *)rec;
    int total = 0;
    int calls = 0;
    int i;

    log_msg(LOG_DEBUG, "warm up syslog before bounded-pump socketpair");

    ASSERT(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0,
           "SEQPACKET socketpair as fake fanotify group");
    if (sv[0] < 0)
        return;

    int fl = fcntl(sv[0], F_GETFL, 0);
    ASSERT(fl >= 0 && fcntl(sv[0], F_SETFL, fl | O_NONBLOCK) == 0,
           "make the fake group non-blocking like FAN_NONBLOCK");
    fl = fcntl(sv[1], F_GETFL, 0);
    ASSERT(fl >= 0 && fcntl(sv[1], F_SETFL, fl | O_NONBLOCK) == 0,
           "non-blocking response side: a missing answer must not hang");

    memset(rec, 0, sizeof(rec));
    md->event_len = sizeof(*md);
    md->metadata_len = sizeof(*md);
    md->vers = FANOTIFY_METADATA_VERSION;
    md->mask = FAN_OPEN_PERM;
    md->pid = (int)getpid();
    for (i = 0; i < N_EVENTS; i++)
        efd[i] = -1;

    for (i = 0; i < N_EVENTS; i++) {
        ssize_t w;
        efd[i] = open("/dev/null", O_RDONLY | O_CLOEXEC);
        ASSERT(efd[i] >= 0, "open event fd");
        if (efd[i] < 0)
            break;
        md->fd = efd[i];
        w = write(sv[1], rec, sizeof(*md));
        ASSERT(w == (ssize_t)sizeof(*md), "feed one event packet");
        if (w != (ssize_t)sizeof(*md))
            break;
    }
    if (i < N_EVENTS) {
        for (int j = 0; j < N_EVENTS; j++)
            if (efd[j] >= 0)
                close(efd[j]);
        close(sv[0]);
        close(sv[1]);
        return; /* the ASSERTs above recorded the failure */
    }

    /* Re-enter the pump exactly as notify.c's poll loop does until the
     * stream is drained. */
    while (total < N_EVENTS && calls < N_EVENTS + 2) {
        int r = fanotify_pump(sv[0], getpid());
        ASSERT(r >= 0, "pump returns a non-negative count");
        ASSERT(fanotify_test_active_dialog_pid() == 0,
               "dialog pid restored after each bounded pump return");
        total += r;
        calls++;
        if (r == 0)
            break;
    }

    ASSERT(calls >= 2,
           "one bounded pump call did not drain the whole stream");
    ASSERT(total == N_EVENTS,
           "every queued event is responded to across re-entries");

    /* Responses arrive in event order, one per event. */
    for (i = 0; i < N_EVENTS; i++) {
        struct fanotify_response resp;
        ssize_t got = read(sv[1], &resp, sizeof(resp));
        ASSERT(got == (ssize_t)sizeof(resp) && resp.fd == efd[i] &&
                   resp.response == FAN_ALLOW,
               "each event answered FAN_ALLOW once, in order");
    }
    for (i = 0; i < N_EVENTS; i++)
        ASSERT(fcntl(efd[i], F_GETFD) == -1 && errno == EBADF,
               "event fd closed after the response");

    close(sv[0]);
    close(sv[1]);
}

/*
 * Part 0c-quater: a lifecycle flag stops the pump at the next record
 * boundary, and the records already read into the current buffer are
 * claimed exactly like the fatal path before returning: read(2)
 * duplicated an fd for every record, so a later record left unhandled
 * would leak its fd and auto-ALLOW at group close.  g_need_reload is
 * used because it is not fatal (the group stays usable), and one
 * SEQPACKET write delivers a whole three-record buffer to a single
 * read(2), so the in-flight records are deterministic.
 */
static void test_pump_flag_claims_inflight_buffer(void) {
    int sv[2] = { -1, -1 };
    int efd[3];
    static char batch[3 * sizeof(struct fanotify_event_metadata)]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));
    struct fanotify_event_metadata *md =
        (struct fanotify_event_metadata *)batch;
    struct fanotify_response resp;

    log_msg(LOG_DEBUG, "warm up syslog before pump-flag socketpair");

    ASSERT(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0,
           "SEQPACKET socketpair as fake fanotify group");
    if (sv[0] < 0)
        return;

    int fl = fcntl(sv[0], F_GETFL, 0);
    ASSERT(fl >= 0 && fcntl(sv[0], F_SETFL, fl | O_NONBLOCK) == 0,
           "make the fake group non-blocking like FAN_NONBLOCK");
    fl = fcntl(sv[1], F_GETFL, 0);
    ASSERT(fl >= 0 && fcntl(sv[1], F_SETFL, fl | O_NONBLOCK) == 0,
           "non-blocking response side: a missing answer must not hang");

    memset(batch, 0, sizeof(batch));
    for (int i = 0; i < 3; i++) {
        efd[i] = open("/dev/null", O_RDONLY | O_CLOEXEC);
        ASSERT(efd[i] >= 0, "open in-flight event fd");
        md[i].event_len = sizeof(*md);
        md[i].metadata_len = sizeof(*md);
        md[i].vers = FANOTIFY_METADATA_VERSION;
        md[i].mask = FAN_OPEN_PERM;
        md[i].pid = (int)getpid();
        md[i].fd = efd[i];
    }

    ASSERT(write(sv[1], batch, sizeof(batch)) == (ssize_t)sizeof(batch),
           "feed one three-record buffer to the pump");

    g_need_reload = 1;
    int responded = fanotify_pump(sv[0], getpid());
    g_need_reload = 0;

    ASSERT(responded == 1,
           "the pump stopped at the first record boundary after the flag");
    ASSERT(fanotify_test_active_dialog_pid() == 0,
           "dialog pid restored on the flag exit path");
    ASSERT(fcntl(efd[0], F_GETFD) == -1 && errno == EBADF,
           "the handled record's event fd was closed");
    ASSERT(fcntl(efd[1], F_GETFD) == -1 && errno == EBADF,
           "the record behind the flag was claimed (denied + closed)");
    ASSERT(fcntl(efd[2], F_GETFD) == -1 && errno == EBADF,
           "the rest of the in-flight buffer was claimed");

    ssize_t got = read(sv[1], &resp, sizeof(resp));
    ASSERT(got == (ssize_t)sizeof(resp) && resp.fd == efd[0] &&
               resp.response == FAN_ALLOW,
           "the handled record was answered FAN_ALLOW");
    got = read(sv[1], &resp, sizeof(resp));
    ASSERT(got == (ssize_t)sizeof(resp) && resp.fd == efd[1] &&
               resp.response == FAN_DENY,
           "the first claimed record was answered FAN_DENY");
    got = read(sv[1], &resp, sizeof(resp));
    ASSERT(got == (ssize_t)sizeof(resp) && resp.fd == efd[2] &&
               resp.response == FAN_DENY,
           "the second claimed record was answered FAN_DENY");

    /* With nothing left in the group, a re-entry returns promptly. */
    ASSERT(fanotify_pump(sv[0], getpid()) == 0,
           "a drained group makes the pump return without reading");

    close(sv[0]);
    close(sv[1]);
}

/*
 * Part 0c-quinquies: queue saturation while a dialog is open must deny
 * every deferred event (the pump's FAN_Q_OVERFLOW handler).  A regression
 * that drops the flush would leave the suspended opens to auto-ALLOW at
 * group close -- the fail-open the handler exists to close.
 */
static void test_pump_overflow_flushes_deferred(void) {
    int sv[2] = { -1, -1 };
    int efd[2] = { -1, -1 };
    static char rec[sizeof(struct fanotify_event_metadata)]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));
    struct fanotify_event_metadata *md =
        (struct fanotify_event_metadata *)rec;

    log_msg(LOG_DEBUG, "warm up syslog before overflow pump socketpair");

    ASSERT(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0,
           "SEQPACKET socketpair as fake fanotify group");
    if (sv[0] < 0)
        return;

    int fl = fcntl(sv[0], F_GETFL, 0);
    ASSERT(fl >= 0 && fcntl(sv[0], F_SETFL, fl | O_NONBLOCK) == 0,
           "make the fake group non-blocking like FAN_NONBLOCK");
    fl = fcntl(sv[1], F_GETFL, 0);
    ASSERT(fl >= 0 && fcntl(sv[1], F_SETFL, fl | O_NONBLOCK) == 0,
           "non-blocking response side: a missing answer must not hang");

    for (int i = 0; i < 2; i++) {
        struct fanotify_event_metadata ev;

        efd[i] = open("/dev/null", O_RDONLY | O_CLOEXEC);
        ASSERT(efd[i] >= 0, "open deferred event fd");
        if (efd[i] < 0)
            break;
        memset(&ev, 0, sizeof(ev));
        ev.event_len = sizeof(ev);
        ev.vers = FANOTIFY_METADATA_VERSION;
        ev.mask = FAN_OPEN_PERM;
        ev.fd = efd[i];
        ev.pid = (int)getpid();
        ASSERT(fanotify_defer_event(&ev) == 0,
               "defer an event before the overflow record");
    }

    memset(rec, 0, sizeof(rec));
    md->event_len = sizeof(*md);
    md->metadata_len = sizeof(*md);
    md->vers = FANOTIFY_METADATA_VERSION;
    md->mask = FAN_Q_OVERFLOW;
    md->fd = FAN_NOFD;
    md->pid = (int)getpid();
    ASSERT(write(sv[1], rec, sizeof(*md)) == (ssize_t)sizeof(*md),
           "feed the FAN_Q_OVERFLOW record");

    int r = fanotify_pump(sv[0], getpid());
    ASSERT(r >= 0, "pump handles the overflow record");
    ASSERT(fanotify_test_active_dialog_pid() == 0,
           "dialog pid restored after the overflow pump");

    struct fanotify_response resp;
    for (int i = 0; i < 2; i++) {
        ssize_t got = read(sv[1], &resp, sizeof(resp));
        ASSERT(got == (ssize_t)sizeof(resp) && resp.fd == efd[i] &&
                   resp.response == FAN_DENY,
               "deferred event denied on queue overflow (fail closed)");
        ASSERT(fcntl(efd[i], F_GETFD) == -1 && errno == EBADF,
               "deferred event fd closed after the overflow denial");
    }

    close(sv[0]);
    close(sv[1]);
}

/*
 * Part 0c2: a mark whose kernel removal fails must stay tracked (and be
 * retried on the next clear) instead of being forgotten, which would
 * leave an untracked kernel mark behind.  A negative fd means no group
 * (unprivileged tests) and clears the table outright.
 */
static void test_clear_marks_retains_failures(void) {
    ASSERT(fanotify_test_seed_mark("/tmp/clear-retain-a") == 0,
           "seed first mark");
    ASSERT(fanotify_test_seed_mark("/tmp/clear-retain-b") == 0,
           "seed second mark");
    ASSERT(fanotify_any_mark_active() == 1, "seeded marks are active");

    /* /dev/null cannot be a fanotify group: every removal fails. */
    int bad_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT(bad_fd >= 0, "open non-fanotify fd");
    fanotify_clear_marks(bad_fd);
    close(bad_fd);
    ASSERT(fanotify_any_mark_active() == 1,
           "failed removals stay tracked for the next clear");

    /* No group: nothing was installed in the kernel, clear outright. */
    fanotify_clear_marks(-1);
    ASSERT(fanotify_any_mark_active() == 0, "table clear releases the marks");
}

/*
 * Part 0j: a command line longer than the 64 KB fingerprint bound must
 * yield no fingerprint (fail closed) instead of a digest of the
 * truncated prefix, which two different over-long invocations could
 * otherwise share.
 */
static void test_cmdline_fingerprint_overflow(void) {
    const size_t big = 70 * 1024;
    char *arg = malloc(big + 1);
    ASSERT(arg != NULL, "alloc long argv");
    if (!arg)
        return;
    memset(arg, 'x', big);
    arg[big] = '\0';

    pid_t pid = fork();
    ASSERT(pid >= 0, "fork long-argv child");
    if (pid < 0) {
        /* Never let a failed fork turn kill(pid) into kill(-1). */
        free(arg);
        return;
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0)
            dup2(devnull, STDIN_FILENO);
        execl("/bin/sh", "sh", "-c", "while :; do sleep 1; done", arg,
              (char *)NULL);
        _exit(127);
    }

    char hex[129];
    int rc = 0;
    for (int i = 0; i < 200 && rc == 0; i++) {
        rc = fanotify_test_cmdline_fingerprint(pid, hex);
        if (rc == 0)
            usleep(10000);
    }

    /* Prove the child really exec'd with the over-long argv: measure its
     * raw command line (a failed exec would otherwise fake the result). */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    size_t total = 0;
    if (fd >= 0) {
        char buf[8192];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0)
            total += (size_t)n;
        close(fd);
    }
    ASSERT(total > (size_t)64 * 1024, "child cmdline really exceeds 64 KB");
    ASSERT(rc < 0, "an over-long cmdline has no fingerprint");

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    free(arg);
}

/*
 * Part 2: real kernel fanotify group, no FAN_UNLIMITED_QUEUE.  Open 20000
 * distinct files under one marked directory without draining; the kernel
 * default queue holds 16384 events, so saturation is guaranteed and the
 * next read must report FAN_Q_OVERFLOW.
 */
static void test_kernel_bounded_queue_overflow(void) {
    int fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF, O_RDONLY);
    if (fd < 0) {
        if (errno == EPERM || errno == ENOSYS || errno == EAGAIN) {
            printf("SKIP: fanotify group unavailable (%s); "
                   "run as root to exercise the kernel saturation test\n",
                   strerror(errno));
            return;
        }
        fprintf(stderr, "FAIL: fanotify_init: %s\n", strerror(errno));
        failures++;
        return;
    }

    char dir[] = "/tmp/fileshield_queue_sat_XXXXXX";
    if (!mkdtemp(dir)) {
        fprintf(stderr, "FAIL: mkdtemp: %s\n", strerror(errno));
        failures++;
        close(fd);
        return;
    }

    enum { SAT_FILES = 20000 }; /* > 16384 kernel default queue limit */

    /* Create files BEFORE marking so only the opens below queue events. */
    char path[PATH_MAX];
    for (int i = 0; i < SAT_FILES; i++) {
        snprintf(path, sizeof(path), "%s/f%05d", dir, i);
        int f = open(path, O_CREAT | O_WRONLY, 0600);
        if (f >= 0)
            close(f);
    }

    if (fanotify_mark(fd, FAN_MARK_ADD, FAN_OPEN | FAN_EVENT_ON_CHILD,
                      AT_FDCWD, dir) < 0) {
        fprintf(stderr, "FAIL: fanotify_mark: %s\n", strerror(errno));
        failures++;
        goto cleanup;
    }

    /* One open per distinct inode: 20000 unique events, no merging. */
    for (int i = 0; i < SAT_FILES; i++) {
        snprintf(path, sizeof(path), "%s/f%05d", dir, i);
        int o = open(path, O_RDONLY);
        if (o >= 0)
            close(o);
    }

    /* Drain everything and look for the overflow report. */
    int overflow_seen = 0;
    long events_drained = 0;
    char buf[65536]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN)
                break;
            if (errno == EOVERFLOW) { /* overflow as a read error */
                overflow_seen = 1;
                break;
            }
            fprintf(stderr, "FAIL: fanotify read: %s\n", strerror(errno));
            failures++;
            break;
        }
        if (n == 0)
            break;

        const struct fanotify_event_metadata *ev =
            (const struct fanotify_event_metadata *)buf;
        ssize_t remaining = n;
        while (FAN_EVENT_OK(ev, (size_t)remaining)) {
            if (ev->mask & FAN_Q_OVERFLOW)
                overflow_seen = 1;
            if (ev->event_len == 0)
                break;
            remaining -= ev->event_len;
            ev = FAN_EVENT_NEXT(ev, remaining);
            events_drained++;
        }
    }

    /*
     * Bound the drain to the kernel queue limit: fs.fanotify
     * max_queued_events (the kernel default is 16384).  The previous
     * `events_drained < SAT_FILES` was satisfied even by an unbounded
     * queue that drained all 20000, hiding the drop this test proves.
     * One extra slot tolerates the FAN_Q_OVERFLOW pseudo-event the kernel
     * may deliver alongside the bounded queue.
     */
    long queue_max = 16384; /* fanotify(7) kernel default */
    FILE *qf = fopen("/proc/sys/fs/fanotify/max_queued_events", "r");
    if (qf)
    {
        long v = 0;
        if (fscanf(qf, "%ld", &v) == 1 && v > 0)
            queue_max = v;
        fclose(qf);
    }
    ASSERT(overflow_seen, "FAN_Q_OVERFLOW reported after saturation");
    ASSERT(events_drained <= queue_max + 1,
           "the bounded queue held at most max_queued_events");
    ASSERT(events_drained < SAT_FILES,
           "bounded queue dropped events instead of growing unbounded");

cleanup:
    for (int i = 0; i < SAT_FILES; i++) {
        snprintf(path, sizeof(path), "%s/f%05d", dir, i);
        unlink(path);
    }
    rmdir(dir);
    close(fd);
}

/*
 * Part 0d: mount marks must be placed through pid 1's mount namespace
 * ("/proc/1/root" + path) so they attach to the mount instances user
 * processes open through, and must be keyed by mount instance.  Inodes are
 * shared across namespaces, so only mount marks need the prefix
 * (MARK-SCOPE-REDESIGN.md; Phase 0 exp1/exp2/exp2p).
 */
static void test_mark_paths(void) {
    char buf[PATH_MAX];
    unsigned long long id_root, id_proc;

    ASSERT(fanotify_test_mark_path("/home/u/.ssh", buf, sizeof(buf)) == 0,
           "mark path builds");
    ASSERT(strcmp(buf, "/proc/1/root/home/u/.ssh") == 0,
           "mark path is prefixed with /proc/1/root");

    ASSERT(fanotify_test_mark_path("/", buf, sizeof(buf)) == 0,
           "root mark path builds");
    ASSERT(strcmp(buf, "/proc/1/root/") == 0, "root mark path is prefixed");

    ASSERT(fanotify_test_mark_path("/home/u/.ssh", buf, 8) == -1,
           "too-small buffer is rejected");

    id_root = fanotify_test_mount_id("/");
    id_proc = fanotify_test_mount_id("/proc");
    if (id_root == 0 || id_proc == 0) {
        printf("SKIP: statx(STATX_MNT_ID) unavailable; mount-ID checks skipped\n");
    } else {
        ASSERT(fanotify_test_mount_id("/") == id_root,
               "mount ID is stable across calls");
        ASSERT(id_root != id_proc, "different mounts have different IDs");
    }
}

/*
 * Part 0e: the scope guard refuses configurations whose own state or config
 * files the installed marks would intercept (self-deadlock class).
 */
static void test_scope_guard(void) {
    static Config cfg;
    Config *saved = g_config;

    /* Containment: the state directory is protected. */
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.protected[0].path, sizeof(cfg.protected[0].path), "%s",
             PERSIST_STATE_DIR);
    cfg.protected_count = 1;
    g_config = &cfg;
    ASSERT(fanotify_scope_guard("/tmp/scope-guard-nonexistent.conf") == -1,
           "scope guard refuses a protected state directory");

    /* Containment: the config file is inside a protected path. */
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.protected[0].path, sizeof(cfg.protected[0].path),
             "/tmp/scope-guard-test");
    cfg.protected_count = 1;
    g_config = &cfg;
    ASSERT(fanotify_scope_guard("/tmp/scope-guard-test/fileshield.conf") == -1,
           "scope guard refuses a config under a protected path");

    /* Benign: the protected path is on a different mount than the state
     * directory and the config. */
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.protected[0].path, sizeof(cfg.protected[0].path), "/dev");
    cfg.protected_count = 1;
    g_config = &cfg;
    ASSERT(fanotify_scope_guard("/tmp/scope-guard-test.conf") == 0,
           "scope guard accepts a benign config");

    /*
     * Device-level fallback (kernels without statx(STATX_MNT_ID)): a
     * protected path sharing the config's device must refuse instead of
     * trusting an unverified mount check; a different-device target
     * stays accepted.
     */
    char fallback_conf[80];
    char fallback_target[80];
    FILE *tf;

    snprintf(fallback_conf, sizeof(fallback_conf), "/tmp/scope-guard-%d.conf",
             (int)getpid());
    snprintf(fallback_target, sizeof(fallback_target),
             "/tmp/scope-guard-%d.target", (int)getpid());
    tf = fopen(fallback_conf, "w");
    ASSERT(tf != NULL, "create fallback config file");
    if (tf)
        fclose(tf);
    tf = fopen(fallback_target, "w");
    ASSERT(tf != NULL, "create fallback target file");
    if (tf)
        fclose(tf);

    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.protected[0].path, sizeof(cfg.protected[0].path), "%s",
             fallback_target);
    cfg.protected_count = 1;
    g_config = &cfg;

    fanotify_test_force_mount_id_unavailable(1);
    ASSERT(fanotify_scope_guard(fallback_conf) == -1,
           "fallback refuses a same-device config collision");
    snprintf(cfg.protected[0].path, sizeof(cfg.protected[0].path), "/dev");
    ASSERT(fanotify_scope_guard(fallback_conf) == 0,
           "fallback accepts a different-device target");
    fanotify_test_force_mount_id_unavailable(0);

    unlink(fallback_conf);
    unlink(fallback_target);

    g_config = saved;
}

/*
 * Part 0f: an existing protected path must resolve to the mount it is
 * actually marked on, not the mount of its parent.  mark_target_mount_id()
 * called nearest_existing_ancestor() unconditionally, so a mount point
 * like /dev compared equal to the root mount: a root-anchored config path
 * (or a state directory on the root mount) was falsely flagged as sharing
 * a mount with the protected path.  Pre-fix this fails wherever
 * statx(STATX_MNT_ID) is available; without it the check SKIPs.
 */
static void test_scope_guard_existing_path_mount(void) {
    static Config cfg;
    Config *saved = g_config;
    unsigned long long id_dev = fanotify_test_mount_id("/dev");
    unsigned long long id_tmp = fanotify_test_mount_id("/tmp");
    unsigned long long id_root = fanotify_test_mount_id("/");
    char config_path[80];

    if (id_dev == 0 || id_tmp == 0) {
        printf("SKIP: statx mount IDs unavailable; existing-path mount resolution check skipped\n");
        return;
    }
    if (id_dev == id_tmp || id_dev == id_root) {
        printf("SKIP: /dev is not a separate mount; existing-path mount resolution check skipped\n");
        return;
    }

    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.protected[0].path, sizeof(cfg.protected[0].path), "/dev");
    cfg.protected_count = 1;
    g_config = &cfg;

    /*
     * A root-anchored path that does not exist resolves to the root mount
     * both before and after the fix (stat fails and the ancestor walk
     * lands on "/"), so a refusal here can only come from /dev resolving
     * to its parent (root) instead of its own mount.  This makes the pin
     * host-independent: it holds wherever /dev is its own mount.
     */
    snprintf(config_path, sizeof(config_path),
             "/fileshield-scope-guard-%d.conf", (int)getpid());
    ASSERT(fanotify_scope_guard(config_path) == 0,
           "existing protected path is compared by its own mount, not its parent's");

    /* The realistic shape: a config path on another mount is accepted. */
    snprintf(config_path, sizeof(config_path),
             "/tmp/scope-guard-conflict-%d.conf", (int)getpid());
    ASSERT(fanotify_scope_guard(config_path) == 0,
           "scope guard accepts an existing path on a separate mount");

    g_config = saved;
}

/*
 * Part 1b: the shutdown drain denies and closes every permission event the
 * kernel still holds.  A socketpair stands in for the group fd: drain()
 * reads event metadata from it and writes fanotify responses back, exactly
 * like the real fd (which is both readable and writable).
 */
static void test_drain_and_deny(void) {
    log_msg(LOG_DEBUG, "warm up syslog socket");

    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == 0,
           "create drain socketpair");

    enum { PERM_EVENTS = 3 };
    int event_fds[PERM_EVENTS + 1] = { -1 };
    struct fanotify_event_metadata evs[PERM_EVENTS + 1];
    size_t total = 0;

    memset(evs, 0, sizeof(evs));
    for (int i = 0; i < PERM_EVENTS + 1; i++) {
        int efd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        ASSERT(efd >= 0, "open drain event fd");
        if (efd < 0)
            break;
        event_fds[i] = efd;

        /* The last event is a notification: closed, never answered. */
        evs[i].event_len = sizeof(evs[i]);
        evs[i].vers = FANOTIFY_METADATA_VERSION;
        evs[i].mask = (i == PERM_EVENTS) ? FAN_CLOSE_WRITE : FAN_OPEN_PERM;
        evs[i].fd = efd;
        evs[i].pid = (int)getpid();
        total += sizeof(evs[i]);
    }

    ASSERT(write(sv[1], evs, total) == (ssize_t)total, "queue drain events");

    fanotify_drain_and_deny(sv[0]);

    /* One FAN_DENY per permission event; none for the notification event. */
    struct fanotify_response resp[PERM_EVENTS] = {0};
    size_t want = sizeof(resp[0]) * PERM_EVENTS;
    size_t got = 0;
    while (got < want) {
        ssize_t n = read(sv[1], (char *)resp + got, want - got);
        if (n <= 0)
            break;
        got += (size_t)n;
    }
    ASSERT(got == want, "one response per drained permission event");
    for (int i = 0; i < PERM_EVENTS; i++) {
        ASSERT(resp[i].response == FAN_DENY, "drain response is FAN_DENY");
        ASSERT(resp[i].fd == event_fds[i],
               "drain response targets the event fd");
    }
    for (int i = 0; i < PERM_EVENTS + 1; i++) {
        if (event_fds[i] >= 0)
            ASSERT(fcntl(event_fds[i], F_GETFD) == -1 && errno == EBADF,
                   "drained event fd was closed");
    }

    /* Empty queue: a second drain must return immediately. */
    fanotify_drain_and_deny(sv[0]);

    close(sv[0]);
    close(sv[1]);
}

/*
 * Part 0f: the recent-decision dedup cache.  The key is the full decision
 * identity (pid, process start time, resolved binary, dev, ino, path):
 * a hard link, a recycled PID or an exec to another binary must not
 * inherit a decision; a newer decision shadows an older one; a reload
 * clears the cache.
 */
static void test_recent_decision_cache(void) {
    const char *bin_a = "/usr/bin/tool-a";
    const char *bin_b = "/usr/bin/tool-b";

    fanotify_test_recent_clear();

    fanotify_test_recent_insert(100, 111, bin_a, (dev_t)1, (ino_t)2,
                                "/home/u/secret", FAN_ALLOW);
    ASSERT(fanotify_test_recent_lookup(100, 111, bin_a, (dev_t)1, (ino_t)2,
                                       "/home/u/secret") == FAN_ALLOW,
           "dedup cache returns the stored decision");
    ASSERT(fanotify_test_recent_lookup(100, 111, bin_a, (dev_t)1, (ino_t)2,
                                       "/home/u/link") == -1,
           "a different path to the same inode does not reuse the decision");
    ASSERT(fanotify_test_recent_lookup(101, 111, bin_a, (dev_t)1, (ino_t)2,
                                       "/home/u/secret") == -1,
           "a different pid does not reuse the decision");
    ASSERT(fanotify_test_recent_lookup(100, 222, bin_a, (dev_t)1, (ino_t)2,
                                       "/home/u/secret") == -1,
           "a recycled pid (new start time) does not reuse the decision");
    ASSERT(fanotify_test_recent_lookup(100, 111, bin_b, (dev_t)1, (ino_t)2,
                                       "/home/u/secret") == -1,
           "an exec to another binary does not reuse the decision");

    /* Newest decision wins for the same key. */
    fanotify_test_recent_insert(100, 111, bin_a, (dev_t)1, (ino_t)2,
                                "/home/u/secret", FAN_DENY);
    ASSERT(fanotify_test_recent_lookup(100, 111, bin_a, (dev_t)1, (ino_t)2,
                                       "/home/u/secret") == FAN_DENY,
           "a newer decision shadows the older one");

    fanotify_test_recent_clear();
    ASSERT(fanotify_test_recent_lookup(100, 111, bin_a, (dev_t)1, (ino_t)2,
                                       "/home/u/secret") == -1,
           "clear drops every cached decision");
}

/*
 * Part 0g: the dialog environment whitelist accepts only cosmetic keys and
 * rejects everything that could load code or redirect the platform.
 */
static void test_dialog_env_whitelist(void) {
    ASSERT(notify_test_env_key_allowed("XDG_CURRENT_DESKTOP") == 1,
           "desktop identity key is forwarded");
    ASSERT(notify_test_env_key_allowed("LANG") == 1, "locale key is forwarded");
    ASSERT(notify_test_env_key_allowed("XCURSOR_THEME") == 1,
           "cursor key is forwarded");

    ASSERT(notify_test_env_key_allowed("LD_PRELOAD") == 0,
           "LD_PRELOAD is never forwarded");
    ASSERT(notify_test_env_key_allowed("LD_LIBRARY_PATH") == 0,
           "LD_LIBRARY_PATH is never forwarded");
    ASSERT(notify_test_env_key_allowed("PATH") == 0,
           "PATH is never forwarded");
    ASSERT(notify_test_env_key_allowed("QT_PLUGIN_PATH") == 0,
           "QT_PLUGIN_PATH is never forwarded");
    ASSERT(notify_test_env_key_allowed("QT_QPA_PLATFORM") == 0,
           "QT_QPA_PLATFORM is never forwarded");
    ASSERT(notify_test_env_key_allowed("DISPLAY") == 0,
           "DISPLAY is never forwarded");
    ASSERT(notify_test_env_key_allowed("WAYLAND_DISPLAY") == 0,
           "WAYLAND_DISPLAY is never forwarded");
    ASSERT(notify_test_env_key_allowed("DBUS_SESSION_BUS_ADDRESS") == 0,
           "session bus is never forwarded");

    /* Exact match only: no prefix or suffix tricks. */
    ASSERT(notify_test_env_key_allowed("XLD_PRELOAD") == 0,
           "prefixed key does not match");
    ASSERT(notify_test_env_key_allowed("LANGX") == 0,
           "suffixed key does not match");

    /* The one documented exception. */
    ASSERT(notify_test_env_key_allowed("QT_QPA_PLATFORMTHEME") == 1,
           "QT_QPA_PLATFORMTHEME is the documented exception");

    /* Prompt-text sanitizing: control characters become '?', a value
     * that fits exactly is untouched, and a cut tail gets "...". */
    char san[8];
    notify_test_sanitize_ellipsized("abc\x01" "def", san, sizeof(san));
    ASSERT(strcmp(san, "abc?def") == 0, "control characters are replaced");
    notify_test_sanitize_ellipsized("1234567", san, sizeof(san));
    ASSERT(strcmp(san, "1234567") == 0,
           "an exactly fitting value is not ellipsized");
    notify_test_sanitize_ellipsized("12345678", san, sizeof(san));
    ASSERT(strcmp(san, "1234...") == 0, "a cut value gets the ellipsis marker");
}

/*
 * merge_proc_environ: whitelist filtering, malformed entries, duplicate
 * keys, embedded '=' and oversized values (truncated at the cap), all
 * without needing a live process's environment.
 */
static void test_merge_proc_environ(void) {
    char val[512];

    static const char blob[] =
        "XDG_CURRENT_DESKTOP=KDE\0"
        "LD_PRELOAD=/evil.so\0"
        "NOEQUALS\0"
        "KDE_FULL_SESSION=true\0"
        "LANG=a=b\0";
    int n = notify_test_merge_env(blob, sizeof(blob) - 1,
                                  "XDG_CURRENT_DESKTOP", val, sizeof(val));
    ASSERT(n == 3, "only whitelisted, well-formed entries are collected");
    ASSERT(strcmp(val, "KDE") == 0, "value copied for the requested key");
    n = notify_test_merge_env(blob, sizeof(blob) - 1, "LD_PRELOAD", val,
                              sizeof(val));
    ASSERT(n == 3 && strcmp(val, "") == 0,
           "non-whitelisted key is not collected");
    n = notify_test_merge_env(blob, sizeof(blob) - 1, "LANG", val,
                              sizeof(val));
    ASSERT(n == 3 && strcmp(val, "a=b") == 0,
           "value may contain '=' (split at the first one)");

    /* Duplicate keys: first occurrence wins. */
    static const char dup[] = "LANG=first\0LANG=second\0";
    n = notify_test_merge_env(dup, sizeof(dup) - 1, "LANG", val, sizeof(val));
    ASSERT(n == 1, "duplicate key collected once");
    ASSERT(strcmp(val, "first") == 0, "first occurrence wins");

    /* Oversized value truncates at DIALOG_ENV_VALUE_MAX-1 (255). */
    char big[600];
    char blob2[1024];
    memset(big, 'v', 512);
    big[512] = '\0';
    int bl = snprintf(blob2, sizeof(blob2), "LANG=%s", big);
    n = notify_test_merge_env(blob2, (size_t)bl, "LANG", val, sizeof(val));
    ASSERT(n == 1, "oversized value is still collected");
    ASSERT(strlen(val) == 255, "value truncated to the env value cap");
}

/*
 * Run the verdict-stage seam in a child: an unsafe grant records the
 * per-process "first hit" gate for whatever pid asks, and the test binary
 * must not spend its own gate (test_unsafe_hit_once_per_process relies on
 * it).  The child inherits the in-memory session table and config.
 */
static int child_verdict(const char *binary, const char *sha,
                         const char *target, pid_t sid, int hardlink,
                         int defer) {
    int status = 0;
    pid_t pid = fork();

    if (pid < 0)
        return -1;
    if (pid == 0)
        _exit(fanotify_test_verdict_stage(binary, sha, target, NULL, sid,
                                          hardlink, defer));
    if (waitpid(pid, &status, 0) != pid)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/*
 * Part 0h: the verdict stages run denials before grants (a recorded
 * session deny must beat an unsafe grant), and hard-link events skip
 * every grant stage.
 */
static void test_verdict_stage_order(void) {
    static Config cfg;
    Config *saved = g_config;
    pid_t sid = 0;
    unsigned long long start = 0;

    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.unsafe_allowlist[0].binary,
             sizeof(cfg.unsafe_allowlist[0].binary), "/bin/tool");
    snprintf(cfg.unsafe_allowlist[0].target_path,
             sizeof(cfg.unsafe_allowlist[0].target_path), "/home/u/secret");
    cfg.unsafe_allowlist_count = 1;
    g_config = &cfg;
    session_clear();

    /* The unsafe rule grants when nothing denies. */
    ASSERT(child_verdict("/bin/tool", "", "/home/u/secret", 0, 0, 0) == 2,
           "unsafe rule grants when nothing denies");

    /* Hard-link events must not inherit any grant. */
    ASSERT(child_verdict("/bin/tool", "", "/home/u/secret", 0, 1, 0) == 0,
           "hard-link event skips every grant stage");

    /* A recorded session deny beats the unsafe grant. */
    ASSERT(session_id_of(getpid(), &sid, &start) == 0,
           "resolve own session");
    session_deny_add(sid, start, "/bin/tool", PIN_SHA_A, "/home/u/secret", 60);
    ASSERT(child_verdict("/bin/tool", PIN_SHA_A, "/home/u/secret", sid, 0,
                         0) == 1,
           "session deny wins over an unsafe grant");

    session_clear();
    g_config = saved;
}

/*
 * Part 0h1: Session-Allow with no binary digest.  The seam runs the real
 * record_allow_decision() over a synthetic context: an unverifiable
 * decision must degrade to the cached Allow Once (exactly like Allow
 * Always) and must never store a digest-less session entry -- such an
 * entry would cover a different binary at the target for the session's
 * lifetime (and the matcher now refuses it).  The synthetic event pid is
 * this process, so the degraded grant is observable through
 * cache_lookup().
 */
/*
 * A Session-Allow chosen for a binary whose digest is unavailable is
 * stored as a session entry with an empty digest and matches later opens.
 * This is deliberate — AppImages and other unhashable tools are the key
 * use case — and a past review degraded it to Allow Once and broke that
 * case, so this test pins the intended behavior.
 */
static void test_session_allow_without_digest_stored(void) {
    static Config cfg;
    Config *saved = g_config;
    pid_t sid = 0;
    unsigned long long start = 0;
    const char *bin = "/bin/session-digest-test";
    const char *target = "/home/u/.ssh/id_rsa";
    SessionRecord recs[4];
    int total = 0;

    memset(&cfg, 0, sizeof(cfg));
    cfg.user_ttl_seconds = 60;
    cfg.session_ttl_seconds = 60;
    g_config = &cfg;
    session_clear();
    cache_clear();

    ASSERT(session_id_of(getpid(), &sid, &start) == 0, "resolve own session");

    /* No digest: the session entry is stored and matches, no cache fallback. */
    ASSERT(fanotify_test_record_allow_decision(bin, "", target, sid, start,
                                               NOTIFY_ALLOW_SESSION)
               == FAN_ALLOW,
           "digest-less Session-Allow allows this attempt");
    ASSERT(cache_lookup(getpid(), bin, target) == 0,
           "no one-time cache fallback for a digest-less Session-Allow");
    ASSERT(session_snapshot(0, recs, 4, &total) == 1 && total == 1,
           "the digest-less session entry is stored");
    ASSERT(session_allow_match(sid, bin, PIN_SHA_A, target) == 1,
           "the digest-less session grant matches a later open");

    /* Control: with a digest the session entry is stored as before. */
    session_clear();
    cache_clear();
    ASSERT(fanotify_test_record_allow_decision(bin, PIN_SHA_A, target, sid,
                                               start, NOTIFY_ALLOW_SESSION)
               == FAN_ALLOW,
           "digest-bearing Session-Allow allows this attempt");
    ASSERT(session_allow_match(sid, bin, PIN_SHA_A, target) == 1,
           "a digest-bearing Session-Allow is stored");
    ASSERT(cache_lookup(getpid(), bin, target) == 0,
           "a stored session entry needs no one-time cache grant");

    session_clear();
    cache_clear();
    g_config = saved;
}

/*
 * Part 0h0: deny-vs-hash-failure inconclusiveness gates every grant
 * stage.  A digest-bearing session deny whose current digest is
 * unavailable must reach the dialog (verdict 0), never be granted (2)
 * by a hash-free stage such as a live file cache.  Pre-fix the deny
 * matcher skipped the unverifiable entry as "no match", so the file
 * cache decided and this test failed with verdict 2.  The controls pin
 * the unchanged edges: no deny -> cache grants, a conclusive digest
 * still denies outright, and a digest-less deny still matches any
 * current digest (AppImage-side conservatism).
 */
static void test_inconclusive_deny_gates_grants(void) {
    static Config cfg;
    Config *saved = g_config;
    pid_t sid = 0;
    unsigned long long start = 0;
    const char *bin = "/bin/tool-inconclusive";
    const char *target = "/home/u/secret";
    PersistEntry de;

    memset(&cfg, 0, sizeof(cfg));
    g_config = &cfg;
    session_clear();
    cache_clear();
    fanotify_load_dyn_denylist(NULL, 0); /* isolate from earlier fixtures */

    ASSERT(session_id_of(getpid(), &sid, &start) == 0, "resolve own session");

    /* A live "Allow Once" cache entry for this exact request. */
    cache_insert(getpid(), bin, target, 60);
    ASSERT(cache_lookup(getpid(), bin, target) > 0, "cache entry is live");

    /* Control: with no deny recorded, the file cache grants (2). */
    ASSERT(fanotify_test_verdict_stage(bin, "", target, NULL, sid, 0, 0) == 2,
           "file cache grants when no deny is recorded");

    /* Digest-bearing session deny + empty current digest: inconclusive,
     * so every grant stage is gated and the event would prompt (0). */
    session_deny_add(sid, start, bin, PIN_SHA_A, target, 60);
    ASSERT(fanotify_test_verdict_stage(bin, "", target, NULL, sid, 0, 0) == 0,
           "inconclusive deny gates the file-cache grant (prompt, not grant)");

    /* Control: with the recorded digest the deny is conclusive (1). */
    ASSERT(fanotify_test_verdict_stage(bin, PIN_SHA_A, target, NULL, sid, 0,
                                       0) == 1,
           "conclusive digest match still denies");

    /* Control: a digest-less deny still matches any current digest. */
    session_clear();
    session_deny_add(sid, start, bin, "", target, 60);
    ASSERT(fanotify_test_verdict_stage(bin, "", target, NULL, sid, 0, 0) == 1,
           "digest-less deny still matches an unverifiable digest");

    /* The dynamic deny list reports the same three-way outcome.  The load
     * admission requires the command line too (require_cmdline=1), so the
     * fixture must carry it or dyn_admits drops the entry fail-closed and
     * the matcher sees an empty list. */
    memset(&de, 0, sizeof(de));
    snprintf(de.binary, sizeof(de.binary), "%s", bin);
    snprintf(de.binary_sha512, sizeof(de.binary_sha512), "%s", PIN_SHA_A);
    snprintf(de.target_path, sizeof(de.target_path), "%s", target);
    snprintf(de.cmdline, sizeof(de.cmdline), "cmd");
    ASSERT(sha512_string("cmd", de.cmdline_sha512) == 0,
           "hash the fixture command line");
    fanotify_load_dyn_denylist(&de, 1);
    ASSERT(fanotify_test_dyn_deny_match(bin, "", target, "cmd") == -1,
           "dyn deny: path + stored digest + empty hash = inconclusive");
    ASSERT(fanotify_test_dyn_deny_match(bin, "", "/home/u/other", "cmd") == 0,
           "dyn deny: hash failure alone (no path match) is not inconclusive");
    fanotify_load_dyn_denylist(NULL, 0);

    session_clear();
    cache_clear();
    g_config = saved;
}

/*
 * Part 0h2: the pump's defer-mode contract.  While another dialog is
 * open, the pump runs the full pipeline and maps its verdict directly:
 *   verdict != 0 (a deny or a grant stage decided) -> respond mid-dialog,
 *   verdict == 0 (the event would reach the ask stage)     -> defer.
 * Hard-link events therefore always defer (their grants are stripped, so
 * they always prompt in the main loop), and an allowlisted read never
 * queues behind the pending decision.  The real pump flag path
 * (process_open_perm with defer_on_ask) needs a kernel group; this pins
 * the mapping the pump must not drift from.
 */
static void test_pump_defer_contract(void) {
    static Config cfg;
    Config *saved = g_config;
    pid_t sid = 0;
    unsigned long long start = 0;

    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.unsafe_allowlist[0].binary,
             sizeof(cfg.unsafe_allowlist[0].binary), "/bin/tool");
    snprintf(cfg.unsafe_allowlist[0].target_path,
             sizeof(cfg.unsafe_allowlist[0].target_path), "/home/u/secret");
    cfg.unsafe_allowlist_count = 1;
    g_config = &cfg;
    session_clear();

    /* Allowlisted read: decided mid-dialog (granted), never queued. */
    ASSERT(child_verdict("/bin/tool", "", "/home/u/secret", 0, 0, 1) == 2,
           "defer mode: an allowlisted read is decided, not deferred");

    /* Hard-link event: always prompts, so always defers mid-dialog. */
    ASSERT(child_verdict("/bin/tool", "", "/home/u/secret", 0, 1, 1) == 0,
           "defer mode: a hard-link event defers to the main loop");

    /* Recorded session deny: decided mid-dialog (deny wins early). */
    ASSERT(session_id_of(getpid(), &sid, &start) == 0,
           "resolve own session");
    session_deny_add(sid, start, "/bin/tool", PIN_SHA_A, "/home/u/secret", 60);
    ASSERT(child_verdict("/bin/tool", PIN_SHA_A, "/home/u/secret", sid, 0,
                         1) == 1,
           "defer mode: a session deny decides instead of queueing");

    session_clear();
    g_config = saved;
}

/*
 * Part 0h3: a changed [allowlist] hash pin defers while a dialog is open
 * instead of stacking a hash-change prompt on it.  The dialog rate
 * limiter is exhausted first so a regression that reaches the prompt
 * path is denied without ever forking a dialog.
 */
static void test_pin_change_defers_in_pump(void) {
    static Config cfg;
    Config *saved = g_config;

    ASSERT(pin_fixture_reset() == 0, "pin fixture reset");
    ASSERT(pin_store("/bin/pintool", PIN_SHA_A) == 0, "seed the rule pin");

    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.allowlist[0].binary, sizeof(cfg.allowlist[0].binary), "%s",
             "/bin/pintool");
    snprintf(cfg.allowlist[0].target_path,
             sizeof(cfg.allowlist[0].target_path), "%s", "/home/u/secret");
    cfg.allowlist_count = 1;
    g_config = &cfg;

    /* Control: in defer mode a matching pin still grants mid-dialog (the
     * rule and its pin are live). */
    ASSERT(child_verdict("/bin/pintool", PIN_SHA_A, "/home/u/secret", 0, 0,
                         1) == 2,
           "defer mode: an unchanged pin still grants");

    /* Exhaust the dialog rate limiter for this binary: any path that
     * reaches the hash-change prompt is now denied without a dialog. */
    for (int i = 0; i < 25; i++)
        (void)fanotify_test_dialog_rate_limited("/bin/pintool");
    ASSERT(fanotify_test_dialog_rate_limited("/bin/pintool") == 1,
           "dialog rate limit is exhausted");

    /* A changed pin in defer mode must queue (0).  Without the defer
     * check it runs config_allow_hash_change(), hits the exhausted rate
     * limiter and reports the decided stage (2). */
    ASSERT(child_verdict("/bin/pintool", PIN_SHA_B, "/home/u/secret", 0, 0,
                         1) == 0,
           "defer mode: a changed pin queues instead of prompting");

    /* Outside defer mode the same event is still decided: the hash-change
     * stage runs, hits the exhausted rate limiter and reports the decided
     * deny (2 = a granted/decided stage, not the dialog). */
    ASSERT(child_verdict("/bin/pintool", PIN_SHA_B, "/home/u/secret", 0, 0,
                         0) == 2,
           "without defer the changed pin is decided, not queued");

    pin_fixture_cleanup();
    g_config = saved;
}

/*
 * Part 0h4: [unsafe_allowlist] is evaluated before the hash-pinned
 * [allowlist] for the same access.  In defer mode a changed pin would
 * queue (0); the unsafe grant must decide first (2).
 */
static void test_unsafe_allowlist_wins_over_pinned(void) {
    static Config cfg;
    Config *saved = g_config;

    ASSERT(pin_fixture_reset() == 0, "pin fixture reset");
    ASSERT(pin_store("/bin/pintool2", PIN_SHA_A) == 0, "seed the pinned rule");

    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.allowlist[0].binary, sizeof(cfg.allowlist[0].binary), "%s",
             "/bin/pintool2");
    snprintf(cfg.allowlist[0].target_path,
             sizeof(cfg.allowlist[0].target_path), "%s", "/home/u/secret");
    cfg.allowlist_count = 1;
    snprintf(cfg.unsafe_allowlist[0].binary,
             sizeof(cfg.unsafe_allowlist[0].binary), "%s", "/bin/pintool2");
    snprintf(cfg.unsafe_allowlist[0].target_path,
             sizeof(cfg.unsafe_allowlist[0].target_path), "%s",
             "/home/u/secret");
    cfg.unsafe_allowlist_count = 1;
    g_config = &cfg;

    ASSERT(child_verdict("/bin/pintool2", PIN_SHA_B, "/home/u/secret", 0, 0,
                         1) == 2,
           "unsafe rule decides before a changed pin would queue");

    pin_fixture_cleanup();
    g_config = saved;
}

/*
 * Part 0i: the dialog rate limiter bounds prompts per binary path and then
 * fails closed (deny) for a cooldown window.
 */
static void test_dialog_rate_limiter(void) {
    fanotify_test_reset_dialog_rate();

    const char *binary = "/tmp/fileshield-rate-test-unique";

    for (int i = 0; i < 20; i++)
    {
        ASSERT(fanotify_test_dialog_rate_limited(binary) == 0,
               "prompts below the bound are allowed");
    }
    ASSERT(fanotify_test_dialog_rate_limited(binary) == 1,
           "prompt above the bound is denied (fail closed)");
    ASSERT(fanotify_test_dialog_rate_limited(binary) == 1,
           "cooldown keeps denying");

    /* Rotation through distinct binaries (each landing in a fresh
     * per-binary entry) must still be bounded: the global prompt budget
     * denies once it is exceeded, so a flood cannot evade the per-binary
     * bound by cycling executable paths. */
    fanotify_test_reset_dialog_rate();
    int denied_at = -1;
    for (int i = 0; i < 60; i++)
    {
        char b[64];
        snprintf(b, sizeof(b), "/tmp/fileshield-rotate-%d", i);
        if (fanotify_test_dialog_rate_limited(b) == 1)
        {
            denied_at = i;
            break;
        }
    }
    ASSERT(denied_at == 40,
           "41st prompt across distinct binaries is denied by the global cap");

    fanotify_test_reset_dialog_rate();
}

int main(void) {
    printf("=== test_fanotify ===\n");

    /* Redirect runtime-list state writes before any test loads a legacy
     * entry: the load-time migration would otherwise target
     * /var/lib/fileshield. */
    if (dyn_fixture_init() < 0) {
        fprintf(stderr, "FAIL: could not create the dyn state fixture\n");
        return 1;
    }

    test_mark_mask_rejects_fid_events();
    test_mark_paths();
    test_scope_guard();
    test_scope_guard_existing_path_mount();
    test_recent_decision_cache();
    test_dialog_env_whitelist();
    test_merge_proc_environ();
    test_menu_choice_mapping();
    test_menu_end_to_end();
    test_hash_change_prompt_escapes();
    test_html_escape();
    test_verdict_stage_order();
    test_session_allow_without_digest_stored();
    test_inconclusive_deny_gates_grants();
    test_pump_defer_contract();
    test_pump_dialog_group_allow();
    test_pump_bounded_and_lossless();
    test_pump_flag_claims_inflight_buffer();
    test_pump_overflow_flushes_deferred();
    test_pin_change_defers_in_pump();
    test_unsafe_allowlist_wins_over_pinned();
    test_dialog_rate_limiter();
    test_missing_path_is_skipped();
    test_glob_protected_verdict();
    test_glob_missing_base_is_skipped();
    test_exclusions_deny_wins();
    test_exclusion_is_not_marked();
    test_config_rule_matching();
    test_pin_first_seen_tofu();
    test_allowlist_pin_verdict_codes();
    test_pin_damaged_falls_through();
    test_unsafe_allowlist_skips_pins();
    test_hash_change_null_request_denies();
    test_notify_rate_windows();
    test_unsafe_hit_once_per_process();
    test_glob_deny_and_allow_matchers();
    test_deleted_suffix_stripped();
    test_resolve_path_truncation_rejected();
    test_incomplete_entries_grant_nothing();
    test_cmdline_scoping();
    test_dyn_created_at_preserved();
    test_dyn_legacy_id_migration();
    test_dyn_remove_by_id();
    test_dyn_clear();
    test_dyn_prune();
    test_dyn_prune_interleaved();
    test_dyn_prune_chain_separation();
    test_dyn_write_failure_restores();
    test_cmdline_fingerprint_full();
    test_defer_flush_contract();
    test_respond_failure_retry();
    test_unanswered_queue_grows();
    test_unanswered_stranded_fallback();
    test_batch_abandon_claims_stranded();
    test_clear_marks_retains_failures();
    test_cmdline_fingerprint_overflow();
    test_drain_and_deny();
    test_kernel_bounded_queue_overflow();
    dlg_fixture_cleanup();
    dyn_fixture_cleanup();
    pin_fixture_cleanup();
    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
