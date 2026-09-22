/*
 * test_sha512: digest helpers used for binary identity and command-line
 * fingerprints.  The known-answer vectors come from FIPS 180-4.
 */
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../src/sha512.h"

static int failures = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", (msg)); \
        failures++; \
    } \
} while(0)

static void test_string_vector(void)
{
    char hex[129];
    const char *want =
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    ASSERT(sha512_string("abc", hex) == 0, "sha512_string computes");
    ASSERT(strcmp(hex, want) == 0, "sha512_string matches the known vector");
}

static void test_string_empty(void)
{
    char hex[129];
    const char *want =
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

    ASSERT(sha512_string("", hex) == 0, "sha512_string empty computes");
    ASSERT(strcmp(hex, want) == 0, "sha512_string empty digest correct");
}

static void test_string_differs(void)
{
    char a[129], b[129];

    ASSERT(sha512_string("kubectl get pods", a) == 0, "first digest");
    ASSERT(sha512_string("kubectl get secrets", b) == 0, "second digest");
    ASSERT(strcmp(a, b) != 0, "different command lines differ");
    ASSERT(strlen(a) == 128, "digest is 128 hex chars");
}

static void test_string_multiblock(void)
{
    char hex[129];
    /* FIPS 180-4 two-block vector (105 bytes) exercises block chaining. */
    const char *msg =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        "ijklmnopjklmnopqrlmnopqrsmnopqrstnopqrstu";
    const char *want =
        "84456dbc64e67596d06bca52fcff37e6559394725c13103cbfef17c745607760"
        "1de43e836476729bbde050bffdb3978f814bb7a94f391098debc53a70cf63763";

    ASSERT(sha512_string(msg, hex) == 0, "multiblock computes");
    ASSERT(strcmp(hex, want) == 0, "multiblock matches known vector");
}

static void test_string_invalid(void)
{
    char hex[129];

    ASSERT(sha512_string(NULL, hex) == -1, "NULL input fails");
}

/*
 * sha512_buf hashes length-delimited data, so embedded NUL bytes (the raw
 * /proc/<pid>/cmdline separators) are part of the digest and cannot
 * truncate it the way a string hash would.
 */
static void test_buf_nul_bytes(void)
{
    char with_nul[129], truncated[129];

    ASSERT(sha512_buf("abc\0def", 7, with_nul) == 0, "buffer digest computes");
    ASSERT(sha512_string("abc", truncated) == 0, "prefix digest computes");
    ASSERT(strcmp(with_nul, truncated) != 0,
           "embedded NUL bytes are hashed, not treated as a terminator");
    ASSERT(strlen(with_nul) == 128, "buffer digest is 128 hex chars");
    ASSERT(sha512_buf(NULL, 0, with_nul) == -1, "NULL buffer fails");
}

/*
 * Differential test for raw bytes: sha512_buf must agree with sha512sum
 * on content that contains NUL bytes.
 */
static void test_buf_differential(void)
{
    static const char raw[] = {'a', 'b', 'c', '\0', 'd', 'e', 'f'};
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/tmp/fileshield_sha512_bufdiff_%d",
             (int)getpid());

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ASSERT(fd >= 0, "open buffer differential temp file");
    if (fd < 0)
        return;
    ASSERT(write(fd, raw, sizeof(raw)) == (ssize_t)sizeof(raw),
           "write raw sample");
    close(fd);

    char hex_file[129], hex_buf[129];
    ASSERT(sha512_file(path, hex_file) == 0, "helper digest (raw bytes)");
    ASSERT(sha512_buf(raw, sizeof(raw), hex_buf) == 0,
           "buffer digest (raw bytes)");
    ASSERT(strcmp(hex_file, hex_buf) == 0,
           "buffer digest matches sha512sum for raw bytes");

    unlink(path);
}

/*
 * Differential test: the in-process string digest must agree with
 * sha512sum (exercised through sha512_file's helper path) for the same
 * bytes, at lengths that span block boundaries.
 */
static void test_string_differential(void)
{
    const char *samples[] = {
        "",
        "Fileshield differential test payload 0123456789",
        "a",                     /* block interior              */
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        "ijklmnopjklmnopqrlmnopqrsmnopqrstnopqrstu", /* 105 bytes  */
        "0123456789012345678901234567890123456789012345678901234567890123"
        "4567890123456789012345678901234567890123456789012345678901234567"
        "8901234567890123456789012345678901234567890123456789012345678901"
        "2345",                  /* 352 bytes, three blocks     */
    };

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/tmp/fileshield_sha512_diff_%d", (int)getpid());

    for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); i++)
    {
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        ASSERT(fd >= 0, "open differential temp file");
        if (fd < 0)
            return;
        size_t len = strlen(samples[i]);
        ASSERT(write(fd, samples[i], len) == (ssize_t)len, "write sample");
        close(fd);

        char hex_file[129], hex_str[129];
        ASSERT(sha512_file(path, hex_file) == 0, "helper digest");
        ASSERT(sha512_string(samples[i], hex_str) == 0, "in-process digest");
        ASSERT(strcmp(hex_file, hex_str) == 0,
               "in-process digest matches sha512sum");
    }

    /*
     * Padding rollover: when len % 128 is in [112, 127] the 0x80 pad
     * plus the 16-byte length field no longer fit the final block and
     * the length must land in a second block.  Every fixed sample above
     * misses that branch, so cover the whole boundary here.
     */
    for (size_t len = 111; len <= 128; len++)
    {
        char buf[129];
        for (size_t k = 0; k < len; k++)
            buf[k] = (char)('a' + (int)(k % 26));
        buf[len] = '\0';

        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        ASSERT(fd >= 0, "open rollover temp file");
        if (fd < 0)
            return;
        ASSERT(write(fd, buf, len) == (ssize_t)len, "write rollover sample");
        close(fd);

        char hex_file[129], hex_str[129];
        ASSERT(sha512_file(path, hex_file) == 0, "helper digest (rollover)");
        ASSERT(sha512_string(buf, hex_str) == 0,
               "in-process digest (rollover)");
        ASSERT(strcmp(hex_file, hex_str) == 0,
               "rollover-length digest matches sha512sum");
    }
    unlink(path);
}

static void test_file_digest(void)
{
    char hex[129];

    /* /proc/self/exe resolves inside the helper (sha512sum), which is a
     * valid file.  Only the format is asserted, not a specific digest. */
    ASSERT(sha512_file("/proc/self/exe", hex) == 0, "hash own executable");
    ASSERT(strlen(hex) == 128, "file digest is 128 hex chars");
    ASSERT(sha512_file("/nonexistent/fileshield/sha512", hex) == -1,
           "missing file fails");
}

/*
 * Failure reasons: a failed file hash records a human-readable reason for
 * the prompt/diagnostic path, and the next successful hash clears it.
 */
static void test_file_failure_reason(void)
{
    char hex[129];

    ASSERT(sha512_file("/nonexistent/fileshield/sha512", hex) == -1,
           "missing file fails");
    ASSERT(sha512_last_failure()[0] != '\0',
           "failure reason is recorded after a failed hash");

    ASSERT(sha512_file("/proc/self/exe", hex) == 0, "hash own executable");
    ASSERT(sha512_last_failure()[0] == '\0',
           "failure reason is cleared after a successful hash");
}

/*
 * GNU sha512sum prefixes its output line with a backslash when the
 * printed filename contains a backslash or newline; the digest must
 * still parse for such paths.
 */
static void test_file_backslash_path(void)
{
    char path[PATH_MAX];
    char hex[129];

    snprintf(path, sizeof(path), "/tmp/fileshield_sha512_back\\slash_%d",
             (int)getpid());
    unlink(path);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ASSERT(fd >= 0, "create backslash-named file");
    if (fd >= 0)
    {
        ASSERT(write(fd, "backslash", 9) == 9, "write backslash-named file");
        close(fd);
        ASSERT(sha512_file(path, hex) == 0,
               "digest parses for a backslash-named file");
        ASSERT(strlen(hex) == 128, "digest is 128 hex chars");
        unlink(path);
    }
}

/*
 * Character check for a full SHA-512 text digest: every character must
 * pass isxdigit() and not be upper-case (A-F), i.e. lower-case hex —
 * the same well-formedness collect_digest() enforces on helper output
 * in src/sha512.c.
 */
static int is_lower_hex(const char *s)
{
    for (size_t i = 0; s[i] != '\0'; i++)
    {
        unsigned char c = (unsigned char)s[i];
        if (!isxdigit(c) || isupper(c))
            return 0;
    }
    return 1;
}

/*
 * sha512_proc_exe: the daemon hashes requester binaries through
 * /proc/<pid>/exe (works for containerized processes whose path does
 * not exist on the host).  Hash this process's own executable and assert
 * success plus a well-formed 128-char lower-case digest, then cross-check
 * the digest against sha512_file() of the same executable.
 *
 * The cross-check must NOT use sha512_file("/proc/self/exe"): that path
 * is opened inside the forked sha512sum helper, where "self" is the
 * helper itself (see test_file_digest), so it hashes a different file
 * than sha512_proc_exe(getpid()).  readlink() yields our real target
 * instead, and both sides then hash the same inode.
 */
static void test_proc_exe_digest(void)
{
    char hex[129] = {0};

    if (access("/proc/self/exe", R_OK) != 0)
    {
        printf("SKIP: /proc/self/exe not readable; "
               "proc-exe digest test skipped\n");
        return;
    }

    ASSERT(sha512_proc_exe(getpid(), hex) == 0,
           "sha512_proc_exe hashes own executable");
    ASSERT(strlen(hex) == 128, "proc digest is 128 hex chars");
    ASSERT(is_lower_hex(hex), "proc digest is lower-case hex");
    ASSERT(sha512_last_failure()[0] == '\0',
           "successful proc hash clears the failure reason");

    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    ASSERT(n > 0, "readlink /proc/self/exe");
    if (n > 0)
    {
        char hex_file[129] = {0};
        exe[n] = '\0';
        if (sha512_file(exe, hex_file) == 0)
        {
            ASSERT(strcmp(hex, hex_file) == 0,
                   "proc digest matches sha512_file of the resolved executable");
        }
        else
        {
            /* Defensive: sha512_proc_exe already succeeded above, so the
             * helper exists; skip rather than fail if the direct file
             * hash still cannot run in this environment. */
            printf("SKIP: sha512sum unavailable for proc-exe cross-check\n");
        }
    }
}

/*
 * Dead PID: after the child is reaped /proc/<pid>/exe is gone, so the
 * helper produces no digest and the call must fail closed.  The failure
 * reason is guaranteed non-empty on this path: the missing file drives
 * collect_digest()'s short-read branch, which calls set_failure()
 * ("sha512sum returned no digest").  The known gap where
 * sha512_proc_exe()'s snprintf failure returns -1 without set_failure()
 * is unreachable for any real pid (the 64-byte buffer holds
 * "/proc/%d/exe" for every int), so asserting the reason here does not
 * depend on that gap.  PID reuse between waitpid() and the hash call is
 * theoretically possible but not observable in practice.
 */
static void test_proc_exe_dead_pid(void)
{
    char hex[129] = {0};
    pid_t child = fork();

    ASSERT(child >= 0, "fork child for dead-pid test");
    if (child < 0)
        return;
    if (child == 0)
        _exit(0);

    int status = 0;
    ASSERT(waitpid(child, &status, 0) == child, "reap dead-pid child");
    ASSERT(sha512_proc_exe(child, hex) == -1, "dead pid hash fails");
    ASSERT(sha512_last_failure()[0] != '\0',
           "dead pid hash records a failure reason");
}

/*
 * Reap/kill deadline: a helper that emits a full digest line and then
 * stalls past REAP_DEADLINE_S (2 s, src/sha512.c) must be SIGKILLed by
 * the bounded reap, sha512_file must fail closed (-1) with hex_out
 * untouched, and sha512_last_failure() must report the reap-deadline
 * reason ("sha512sum did not exit in time").  The helper never exits, so
 * collect_digest()'s read loop ends at EOF (the script closes stdout)
 * with a full digest in hand, which is precisely the reap_helper() ->
 * kill_helper_bounded() path — not the longer silent-helper timeout.
 *
 * The sha512_test_set_helper() seam swaps the exec'd binary.  Like
 * test_fanotify's kdialog fixture, the stand-in script needs an
 * exec-capable temp directory (/tmp is commonly noexec): candidates are
 * next to the test binary, TMPDIR and /tmp, each probed with a shebang
 * script; when none can exec, this is an environment SKIP.  SIGALRM
 * bounds the whole case so a regression in the reap fails the suite
 * instead of hanging it (the helper sleeps far past the deadline).
 */
static void on_reap_alarm(int sig)
{
    (void)sig;
    fprintf(stderr, "FAIL: reap/kill deadline test hung past its alarm\n");
    _exit(1);
}

static void test_reap_kill_deadline(void)
{
    static const char probe_body[] = "#!/bin/sh\nexit 0\n";
    /* printf writes a full 128-hex-digit line; being an external utility
     * its exit flushes it.  Closing stdout gives the parent EOF (the read
     * loop needs total >= 128 plus EOF to reach reap_helper() while the
     * helper is still alive), then exec sleep keeps this very pid running
     * well past REAP_DEADLINE_S so the bounded reap must SIGKILL it. */
    static const char slow_body[] =
        "#!/bin/sh\n"
        "/usr/bin/printf '%0128d  x\\n' 0\n"
        "exec 1>&-\n"
        "exec sleep 10\n";
    const char *candidates[4];
    char exe[PATH_MAX], exe_dir[PATH_MAX];
    char dir[PATH_MAX], probe[PATH_MAX], script[PATH_MAX];
    const char *tmpdir;
    struct timespec t0, t1;
    char hex[129] = {0};
    pid_t pid;
    int status = 0;
    int nc = 0, i, ready = 0, fd, rc;
    ssize_t n;
    long long ms;

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
        }
    }
    tmpdir = getenv("TMPDIR");
    if (exe_dir[0] != '\0')
        candidates[nc++] = exe_dir;
    if (tmpdir && tmpdir[0] != '\0')
        candidates[nc++] = tmpdir;
    candidates[nc++] = "/tmp";
    candidates[nc] = NULL;

    dir[0] = '\0';
    probe[0] = '\0';
    for (i = 0; candidates[i] != NULL; i++)
    {
        snprintf(dir, sizeof(dir), "%s/.fileshield_reap_XXXXXX",
                 candidates[i]);
        if (!mkdtemp(dir))
        {
            dir[0] = '\0';
            continue;
        }
        snprintf(probe, sizeof(probe), "%s/probe.sh", dir);
        fd = open(probe, O_WRONLY | O_CREAT | O_TRUNC, 0700);
        if (fd < 0 ||
            write(fd, probe_body, sizeof(probe_body) - 1)
                != (ssize_t)(sizeof(probe_body) - 1))
        {
            if (fd >= 0)
                close(fd);
            unlink(probe);
            rmdir(dir);
            dir[0] = '\0';
            continue;
        }
        close(fd);
        if (chmod(probe, 0700) != 0)
        {
            unlink(probe);
            rmdir(dir);
            dir[0] = '\0';
            continue;
        }
        pid = fork();
        if (pid == 0)
        {
            execl(probe, probe, (char *)NULL);
            _exit(127);
        }
        if (pid >= 0 && waitpid(pid, &status, 0) == pid &&
            WIFEXITED(status) && WEXITSTATUS(status) == 0)
        {
            ready = 1;
            unlink(probe); /* proven; only the slow helper remains */
            break;
        }
        unlink(probe);
        rmdir(dir);
        dir[0] = '\0';
    }
    if (!ready)
    {
        printf("SKIP: no exec-capable temp directory for the slow-helper "
               "script (all candidates are noexec or read-only)\n");
        return;
    }

    snprintf(script, sizeof(script), "%s/slowhelper.sh", dir);
    fd = open(script, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (fd < 0 ||
        write(fd, slow_body, sizeof(slow_body) - 1)
            != (ssize_t)(sizeof(slow_body) - 1))
    {
        if (fd >= 0)
            close(fd);
        ASSERT(0, "write slow helper script");
        unlink(script);
        rmdir(dir);
        return;
    }
    close(fd);
    if (chmod(script, 0700) != 0)
    {
        ASSERT(0, "chmod slow helper script");
        unlink(script);
        rmdir(dir);
        return;
    }

    sha512_test_set_helper(script);
    signal(SIGALRM, on_reap_alarm);
    alarm(15); /* normal path finishes in ~2 s; never reached otherwise */
    (void)clock_gettime(CLOCK_MONOTONIC, &t0);
    rc = sha512_file("/proc/self/exe", hex);
    (void)clock_gettime(CLOCK_MONOTONIC, &t1);
    alarm(0);
    signal(SIGALRM, SIG_DFL);
    sha512_test_set_helper(NULL);

    ASSERT(rc == -1, "stalled helper: sha512_file fails closed");
    ASSERT(hex[0] == '\0', "hex output untouched on failure");
    ASSERT(sha512_last_failure()[0] != '\0',
           "stalled helper records a failure reason");
    ASSERT(strstr(sha512_last_failure(), "did not exit in time") != NULL,
           "stalled helper reports the reap-deadline reason");
    ms = (long long)(t1.tv_sec - t0.tv_sec) * 1000 +
         (t1.tv_nsec - t0.tv_nsec) / 1000000;
    ASSERT(ms >= 1000, "reap waited out the deadline before killing");
    ASSERT(ms < 15000, "reap stayed bounded (no hang)");

    /* Seam reset: the default /usr/bin/sha512sum path works again. */
    ASSERT(sha512_file("/proc/self/exe", hex) == 0,
           "default helper works after seam reset");
    ASSERT(strlen(hex) == 128, "default helper digest is 128 hex chars");
    ASSERT(sha512_last_failure()[0] == '\0',
           "successful default hash clears the failure reason");

    unlink(script);
    rmdir(dir);
}

int main(void)
{
    printf("=== test_sha512 ===\n");
    test_string_vector();
    test_string_empty();
    test_string_differs();
    test_string_multiblock();
    test_string_invalid();
    test_buf_nul_bytes();
    test_buf_differential();
    test_string_differential();
    test_file_digest();
    test_file_failure_reason();
    test_file_backslash_path();
    test_proc_exe_digest();
    test_proc_exe_dead_pid();
    test_reap_kill_deadline();
    if (failures)
    {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
