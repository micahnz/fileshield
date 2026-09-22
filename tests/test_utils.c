#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/limits.h>
#include <pwd.h>

#include "../src/utils.h"

static int failures = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        failures++; \
    } \
} while(0)

static void test_path_under(void) {
    ASSERT(path_under("/home/user/.ssh/id_rsa", "/home/user/.ssh") == 1, "file inside dir");
    ASSERT(path_under("/home/user/.ssh", "/home/user/.ssh") == 1, "exact match");
    ASSERT(path_under("/home/user/.ssh/", "/home/user/.ssh") == 1, "trailing slash same");
    ASSERT(path_under("/home/user/.sshd", "/home/user/.ssh") == 0, "prefix but not under");
    ASSERT(path_under("/home/user/.ssh", "/home/user/.aws") == 0, "different dir");
    ASSERT(path_under("/etc/passwd", "/") == 1, "everything under root");
    ASSERT(path_under("/", "/") == 1, "root equals root");
    ASSERT(path_under("", "/") == 0, "empty path not under root");
}

static void test_path_under_len(void) {
    ASSERT(path_under_len("/a/b/c", "/a/b", 4) == 1, "under with explicit length");
    ASSERT(path_under_len("/a/bc", "/a/b", 4) == 0, "boundary with explicit length");
    ASSERT(path_under_len("/a/b", "/a/b", 4) == 1, "equal with explicit length");
    ASSERT(path_under_len("/x/y", "/a/b", 4) == 0, "different prefix");
    ASSERT(path_under_len("/etc/passwd", "", 0) == 0,
           "an empty directory matches nothing");
}

static void assert_glob_base(const char *pattern, const char *want, const char *msg) {
    int got = glob_base_len(pattern);
    size_t want_len = strlen(want);
    if (got != (int)want_len ||
        (want_len > 0 && memcmp(pattern, want, want_len) != 0)) {
        fprintf(stderr, "FAIL: %s: glob_base_len(%s) = %d, want %s\n",
                msg, pattern, got, want);
        failures++;
    }
}

static void test_glob_base_len(void) {
    assert_glob_base("/home/user/.cloudflared/*.json",
                     "/home/user/.cloudflared", "file glob base");
    assert_glob_base("/home/user/.cloudflared/**/*.json",
                     "/home/user/.cloudflared", "globstar base");
    assert_glob_base("/home/user/.config/*/config.json",
                     "/home/user/.config", "mid glob base");
    assert_glob_base("/foo/bar*", "/foo", "partial-segment base");
    assert_glob_base("/*.json", "/", "root-child base");
    assert_glob_base("/", "/", "root base");
    assert_glob_base("/home/user/.ssh/config", "/home/user/.ssh/config",
                     "no-wildcard base is the whole path");
    assert_glob_base("*.json", "", "first-segment wildcard has no base");
}

static void assert_glob(const char *pattern, const char *path, int want,
                        const char *msg) {
    int got = glob_match_path(pattern, path);
    if (got != want) {
        fprintf(stderr, "FAIL: %s: glob_match_path(%s, %s) = %d, want %d\n",
                msg, pattern, path, got, want);
        failures++;
    }
}

static void test_glob_match(void) {
    /* '*' stays inside one segment, matches dotfiles, honors the tail. */
    assert_glob("/a/*.json", "/a/x.json", 1, "star file match");
    assert_glob("/a/*.json", "/a/.x.json", 1, "star matches dotfiles");
    assert_glob("/a/*.json", "/a/x/y.json", 0, "star does not cross slash");
    assert_glob("/a/*.json", "/a/x.json.bak", 0, "star respects literal tail");
    assert_glob("/a/*.json", "/a/", 0, "empty segment does not match file glob");

    /* '**' matches zero or more whole segments. */
    assert_glob("/a/**/*.json", "/a/x.json", 1, "globstar zero segments");
    assert_glob("/a/**/*.json", "/a/b/x.json", 1, "globstar one segment");
    assert_glob("/a/**/*.json", "/a/b/c/x.json", 1, "globstar many segments");
    assert_glob("/a/**/*.json", "/a/b/x.txt", 0, "globstar needs matching tail");
    assert_glob("/a/**", "/a", 1, "trailing globstar matches base itself");
    assert_glob("/a/**", "/a/b/c", 1, "trailing globstar matches subtree");
    assert_glob("/a/**/b", "/a/b", 1, "mid globstar zero segments");
    assert_glob("/a/**/b", "/a/x/y/b", 1, "mid globstar many segments");
    assert_glob("/a/**/b", "/a/x/y/c", 0, "mid globstar literal tail");
    assert_glob("/**/b", "/a/b", 1, "leading globstar");
    assert_glob("/**/b", "/b", 1, "leading globstar zero segments");
    assert_glob("/a/**/**/b", "/a/x/y/b", 1, "repeated globstar");

    /* Multiple distinct globstars: the matcher carries a single
     * backtrack slot, and these direct-call cases pin that raw-matcher
     * behavior.  Config loading REJECTS patterns with more than one
     * "**" segment (rule_pattern_set): a false negative is fail-open
     * for a protected entry (files silently not protected) and a miss
     * for a deny rule, so the approximation is never reachable from a
     * loaded config. */
    assert_glob("/a/**/b/**/c", "/a/b/c", 1, "two globstars zero filler");
    assert_glob("/a/**/b/**/c", "/a/x/b/y/c", 1, "two globstars with filler");
    assert_glob("/a/**/b/**/c", "/a/x/y/b/c", 1, "first globstar eats more");
    assert_glob("/a/**/b/**/c", "/a/b/x/c", 1, "second globstar eats");
    assert_glob("/a/**/b/**/c", "/a/x/y/z/c", 0, "missing middle segment");
    assert_glob("/a/**/b/**/c", "/a/x/c", 0, "missing literal segment");

    /* Star runs collapse; '?' and '[' ']' are literal. */
    assert_glob("/a/ab**cd", "/a/abXYZcd", 1, "star run collapses");
    assert_glob("/a/ab**cd", "/a/ab/cd", 0, "star run stays in segment");
    assert_glob("/a/x?y", "/a/x?y", 1, "'?' is literal");
    assert_glob("/a/x?y", "/a/xay", 0, "'?' does not wildcard");
    assert_glob("/a/[ab]", "/a/[ab]", 1, "'[]' are literal");
    assert_glob("/a/[ab]", "/a/a", 0, "'[]' do not wildcard");

    /* Full-path, case-sensitive semantics. */
    assert_glob("/a/b", "/a/b/c", 0, "no prefix/subtree semantics");
    assert_glob("/a/b", "/a/bc", 0, "segment boundary respected");
    assert_glob("/A/B", "/a/b", 0, "case-sensitive");
    assert_glob("/a/x*", "/a/x", 1, "trailing star matches empty");
    assert_glob("/a/x*", "/a/", 0, "star cannot fill an empty segment alone");
}

static void test_proc_exe(void) {
    char *exe = proc_exe_path(getpid());
    ASSERT(exe != NULL, "proc_exe_path returns non-NULL for own pid");
    if (exe) {
        ASSERT(strstr(exe, "test_utils") != NULL, "exe path contains test name");
        free(exe);
    }

    exe = proc_exe_path(999999);
    ASSERT(exe == NULL, "proc_exe_path returns NULL for invalid pid");
}

/*
 * M5 regression: the kernel marks a running-but-unlinked binary with a
 * trailing " (deleted)" in /proc/<pid>/exe.  That marker must never
 * reach the pipeline's binary identity, or a self-unlinking process
 * escapes every path-keyed rule ([denylist] demotes from a guaranteed
 * deny to a prompt; allowlist pins break into re-prompt storms).
 * A live child covers the whole path: exec a copy, unlink it while
 * running, and require the stripped identity back.
 */
static void test_proc_exe_deleted(void) {
    const char *srcs[] = { "/bin/sleep", "/usr/bin/sleep" };
    const char *src = NULL;
    for (size_t i = 0; i < sizeof(srcs) / sizeof(srcs[0]); i++)
        if (access(srcs[i], X_OK | R_OK) == 0) { src = srcs[i]; break; }
    if (!src) {
        fprintf(stderr, "SKIP: sleep binary unavailable; deleted-exe test skipped\n");
        return;
    }

    char copy[PATH_MAX];
    snprintf(copy, sizeof(copy), "/tmp/fileshield_delexe_%d.bin",
             (int)getpid());
    unlink(copy);

    FILE *in = fopen(src, "rb");
    FILE *out = in ? fopen(copy, "wb") : NULL;
    char chunk[8192];
    size_t n;
    while (in && out && (n = fread(chunk, 1, sizeof(chunk), in)) > 0)
        fwrite(chunk, 1, n, out) ;
    if (in)
        fclose(in);
    int ok = out != NULL;
    if (out)
        ok = fclose(out) == 0;
    if (!ok) {
        fprintf(stderr, "SKIP: cannot copy sleep binary; deleted-exe test skipped\n");
        unlink(copy);
        return;
    }
    chmod(copy, 0755);

    pid_t child = fork();
    ASSERT(child >= 0, "fork deleted-exe child");
    if (child == 0) {
        execl(copy, copy, "30", (char *)NULL);
        _exit(127);
    }
    if (child < 0) { unlink(copy); return; }

    /* Wait for the exec to land: /proc/<child>/exe points at the copy. */
    char link[64], probe[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/%d/exe", (int)child);
    int execed = 0;
    for (int i = 0; i < 200 && !execed; i++) {
        ssize_t r = readlink(link, probe, sizeof(probe) - 1);
        if (r > 0) {
            probe[r] = '\0';
            execed = strcmp(probe, copy) == 0;
        }
        if (!execed)
            usleep(10000);
    }
    if (!execed) {
        fprintf(stderr, "SKIP: child exec not observable; deleted-exe test skipped\n");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        unlink(copy);
        return;
    }

    ASSERT(unlink(copy) == 0, "unlink the running binary");

    /* The kernel must report the marker, or the strip is untested. */
    int marked = 0;
    for (int i = 0; i < 200 && !marked; i++) {
        ssize_t r = readlink(link, probe, sizeof(probe) - 1);
        if (r > 0) {
            probe[r] = '\0';
            marked = strstr(probe, " (deleted)") != NULL;
        }
        if (!marked)
            usleep(10000);
    }
    ASSERT(marked, "kernel reports the deleted marker on /proc/<pid>/exe");

    char *exe = proc_exe_path(child);
    ASSERT(exe != NULL, "proc_exe_path resolves the deleted binary");
    if (exe) {
        ASSERT(strcmp(exe, copy) == 0,
               "deleted marker stripped: identity is the admin-visible path");
        free(exe);
    }

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    unlink(copy);
}

static void test_proc_helpers(void) {
    char comm[64];
    char cmdline[512];
    pid_t self = getpid();

    ASSERT(get_ppid(self) > 0, "own ppid readable");
    ASSERT(read_comm(self, comm, sizeof(comm)) == 0, "own comm readable");
    ASSERT(strlen(comm) > 0, "own comm non-empty");
    ASSERT(read_cmdline(self, cmdline, sizeof(cmdline)) > 0,
           "own cmdline readable");
    ASSERT(strstr(cmdline, "test_utils") != NULL,
           "cmdline contains the test binary name");

    ASSERT(get_ppid(999999) == 0, "invalid pid yields ppid 0");
    ASSERT(read_comm(999999, comm, sizeof(comm)) == -1,
           "invalid pid comm fails");
    ASSERT(read_cmdline(999999, cmdline, sizeof(cmdline)) == -1,
           "invalid pid cmdline fails");
}

static void test_expand_home(void) {
    char **r;

    /* A path that is not a ~/... pattern: one copy, unchanged. */
    r = expand_home_all_users("/etc/ssh/ssh_config");
    ASSERT(r != NULL, "non-home expansion succeeds");
    if (r) {
        ASSERT(r[0] != NULL &&
                   strcmp(r[0], "/etc/ssh/ssh_config") == 0,
               "non-home path returns a single unchanged copy");
        ASSERT(r[1] == NULL, "non-home array is NULL-terminated");
    }
    free_string_array(r);

    /* ~/sub expands once per real user (uid 1000..65533), mirroring the
     * filter expand_home_all_users() applies to /etc/passwd. */
    int expected = 0;
    struct passwd *pw;
    setpwent();
    while ((pw = getpwent()) != NULL) {
        if (pw->pw_uid >= 1000 && pw->pw_uid < 65534 &&
            pw->pw_dir && pw->pw_dir[0] != '\0')
            expected++;
    }
    endpwent();

    r = expand_home_all_users("~/sub");
    ASSERT(r != NULL, "home expansion succeeds");
    if (r) {
        if (expected == 0) {
            ASSERT(strcmp(r[0], "~/sub") == 0 && r[1] == NULL,
                   "no real users: the original pattern is returned");
        } else {
            int n = 0;
            while (r[n] != NULL)
                n++;
            ASSERT(n == expected, "one entry per real user");
            for (int i = 0; i < n; i++) {
                size_t len = strlen(r[i]);
                ASSERT(r[i][0] == '/', "expanded path is absolute");
                ASSERT(len >= 4 && strcmp(r[i] + len - 4, "/sub") == 0,
                       "expanded path keeps the subpath");
            }
        }
    }
    free_string_array(r);

    /* The freer accepts NULL. */
    free_string_array(NULL);
}

/*
 * M6 regression: every rendered log line passes through log_scrub(), so
 * an attacker-controlled file name or comm can never forge journal
 * entries (e.g. "id_rsa\nfileshield[1]: user chose Allow Always ...").
 */
static void test_log_scrub(void) {
    char buf[128];

    snprintf(buf, sizeof(buf), "%s", "plain/path/is_untouched");
    log_scrub(buf);
    ASSERT(strcmp(buf, "plain/path/is_untouched") == 0,
           "printable text survives the scrub");

    snprintf(buf, sizeof(buf), "%s",
             "/home/u/.ssh/id_rsa\nfileshield[1]: ALLOW /etc/shadow");
    log_scrub(buf);
    ASSERT(strchr(buf, '\n') == NULL, "newline forge neutralized");
    ASSERT(strstr(buf, "/home/u/.ssh/id_rsa") != NULL,
           "path content preserved");
    ASSERT(strstr(buf, "ALLOW /etc/shadow") != NULL,
           "forged text survives as inert content");

    /* Every control byte becomes '?', high bytes and DEL untouched-safe. */
    char raw[8];
    memcpy(raw, "a\x01\x1f\x7fz", 6);
    raw[6] = '\0';
    log_scrub(raw);
    ASSERT(strcmp(raw, "a???z") == 0, "control bytes scrubbed");
}

/*
 * proc_stat_session's parser: the comm field may contain ')' and spaces,
 * so fields are addressed from the LAST ')' onward.  Synthetic lines pin
 * the field offsets (a wrong field 22 means stale allow-cache hits), the
 * anomaly rejections, and the live read stays cross-checked against the
 * real /proc entry.
 */
static void test_parse_proc_stat(void) {
    unsigned long long sid = 0, start = 0;

    static const char weird[] =
        "1234 (a)b c) S 1 2 4242 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 "
        "7777777\n";
    ASSERT(utils_test_parse_proc_stat(weird, strlen(weird), &sid, &start) == 0,
           "comm with ) and spaces parses");
    ASSERT(sid == 4242, "field 6 is the session id");
    ASSERT(start == 7777777ULL, "field 22 is the start time");

    /* Trailing digit without newline is complete; a non-digit tail means
     * the line was cut short and must be rejected. */
    static const char no_newline[] =
        "9 (x) S 1 2 7 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 42";
    ASSERT(utils_test_parse_proc_stat(no_newline, strlen(no_newline), &sid,
                                      &start) == 0,
           "digit-terminated line accepted");
    static const char cut_tail[] =
        "9 (x) S 1 2 7 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 42x";
    ASSERT(utils_test_parse_proc_stat(cut_tail, strlen(cut_tail), &sid,
                                      &start) == -1,
           "non-digit line end is rejected as truncated");

    static const char no_close[] =
        "9 x S 1 2 7 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 42\n";
    ASSERT(utils_test_parse_proc_stat(no_close, strlen(no_close), &sid,
                                      &start) == -1,
           "missing comm terminator is rejected");
    static const char short_fields[] = "9 (x) S 1 2 7 4 5\n";
    ASSERT(utils_test_parse_proc_stat(short_fields, strlen(short_fields),
                                      &sid, &start) == -1,
           "short field list is rejected");
    static const char nonnum[] =
        "9 (x) S abc 2 7 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 42\n";
    ASSERT(utils_test_parse_proc_stat(nonnum, strlen(nonnum), &sid, &start)
               == -1,
           "non-numeric field is rejected");

    /* Live cross-check: the function still reads real processes. */
    ASSERT(proc_stat_session(getpid(), &sid, &start) == 0,
           "live stat read succeeds");
    ASSERT(sid == (unsigned long long)getsid(0), "live session id matches");
    ASSERT(start != 0, "live start time present");
}

/*
 * read_cmdline: "argv\0argv\0" renders as space-separated text, with the
 * trailing NUL (and any space it produced) trimmed.
 */
static void test_read_cmdline_multi_argv(void) {
    const char *src = NULL;
    if (access("/bin/sleep", X_OK) == 0)
        src = "/bin/sleep";
    else if (access("/usr/bin/sleep", X_OK) == 0)
        src = "/usr/bin/sleep";
    if (!src) {
        fprintf(stderr, "SKIP: sleep binary unavailable; cmdline test skipped\n");
        return;
    }

    pid_t child = fork();
    ASSERT(child >= 0, "fork cmdline child");
    if (child < 0)
        return;

    if (child == 0) {
        execl(src, "sleep", "60", (char *)NULL);
        _exit(127);
    }

    char buf[256];
    int ok = 0;
    for (int i = 0; i < 200 && !ok; i++) {
        if (read_cmdline(child, buf, sizeof(buf)) > 0 &&
            strcmp(buf, "sleep 60") == 0)
            ok = 1;
        else
            usleep(10000);
    }
    ASSERT(ok, "nul-separated argv renders as 'sleep 60' (no trailing space)");

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
}

/*
 * Item 6 regression: close_fds_from must close every fd >= 'first' in the
 * calling process (the leak fence so no daemon descriptor reaches a forked
 * helper) while fds below 'first' survive.  Run in a forked child so the
 * parent's descriptors are never touched; the observable contract is
 * identical for the close_range(2) fast path and the bounded fallback
 * loop, so one test covers both.  first=3 keeps stdin/out/err open, so the
 * child can safely report via exit status alone.  Child exit codes:
 * 16 = could not open high fds, 32 = pre-check failed, bits 1/2/4 = the
 * individual post-call assertions.
 */
static void test_close_fds_from(void) {
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "SKIP: fork unavailable; close_fds_from test skipped\n");
        return;
    }
    if (child == 0) {
        int hi1 = open("/dev/null", O_RDONLY);
        int hi2 = open("/dev/null", O_RDONLY);
        if (hi1 < 3 || hi2 < 3)
            _exit(16); /* could not obtain fds >= 3 */
        /* Both high fds must be live before the call, or the check is vacuous. */
        if (fcntl(hi1, F_GETFD) == -1 || fcntl(hi2, F_GETFD) == -1)
            _exit(32);

        close_fds_from(3);

        int status = 0;
        /* fds below 'first' survive: stdio stays valid (first=3). */
        if (fcntl(0, F_GETFD) == -1 || fcntl(1, F_GETFD) == -1 ||
            fcntl(2, F_GETFD) == -1)
            status |= 1;
        errno = 0;
        if (!(fcntl(hi1, F_GETFD) == -1 && errno == EBADF))
            status |= 2;
        errno = 0;
        if (!(fcntl(hi2, F_GETFD) == -1 && errno == EBADF))
            status |= 4;
        _exit(status);
    }

    int wstatus = 0;
    ASSERT(waitpid(child, &wstatus, 0) == child, "waitpid close_fds_from child");
    if (!WIFEXITED(wstatus)) {
        ASSERT(0, "close_fds_from child exited normally");
        return;
    }
    int code = WEXITSTATUS(wstatus);
    ASSERT(code != 16, "child opened fds >= 3");
    ASSERT(code != 32, "high fds live before close_fds_from(3)");
    if (code != 16 && code != 32) {
        ASSERT(!(code & 1), "fds below first survive close_fds_from(3)");
        ASSERT(!(code & 2), "first high fd closed by close_fds_from(3)");
        ASSERT(!(code & 4), "second high fd closed by close_fds_from(3)");
    }
}

int main(void) {
    printf("=== test_utils ===\n");
    test_path_under();
    test_path_under_len();
    test_glob_base_len();
    test_glob_match();
    test_proc_exe();
    test_proc_exe_deleted();
    test_proc_helpers();
    test_expand_home();
    test_log_scrub();
    test_parse_proc_stat();
    test_read_cmdline_multi_argv();
    test_close_fds_from();
    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
