#include "sha512.h"
#include "utils.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

/* Upper bound on hashing a single executable before the helper is killed. */
#define SHA512_TIMEOUT_S 15

/*
 * Reason for the most recent file/proc hashing failure, captured so the
 * event pipeline can explain an unavailable digest in a prompt.  Only the
 * forked file path writes it: sha512_string()/sha512_buf() leave it alone.
 */
static char g_last_failure[80] = "";

static void set_failure(const char *reason)
{
    snprintf(g_last_failure, sizeof(g_last_failure), "%s", reason);
}

const char *sha512_last_failure(void)
{
    return g_last_failure;
}

/* ------------------------------------------------------------------ */
/*  in-process SHA-512 (FIPS 180-4)                                    */
/* ------------------------------------------------------------------ */
/*
 * Used for in-memory fingerprints (sha512_string).  String hashing used
 * to fork sha512sum as well, and tests/bench_hotpath.c measured 13.7 ms
 * per call: the dynamic allow/deny matchers reach it on every deep
 * match, so a rule-scoped binary paid a fork+exec per protected open
 * while the requesting process stayed suspended.  The in-process digest
 * is validated by the FIPS 180-4 known-answer vectors in test_sha512
 * plus a differential test against sha512sum.
 *
 * File hashing (sha512_file) deliberately stays on the fork: opening a
 * protected path in-process would raise FAN_OPEN_PERM against the
 * daemon itself and deadlock the event loop.
 *
 * The round constants below are the standard K table (fractional parts
 * of the cube roots of the first 80 primes); regenerating them with
 * exact arithmetic reproduces this table digit-for-digit.
 */

typedef struct
{
    unsigned long long h[8];
    unsigned long long total_bits;
    unsigned char buf[128];
    size_t buf_used;
} Sha512State;

static const unsigned long long K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

static unsigned long long sha512_ror(unsigned long long x, unsigned n)
{
    return (x >> n) | (x << (64 - n));
}

static void sha512_compress(Sha512State *s, const unsigned char block[128])
{
    unsigned long long w[80];

    for (int t = 0; t < 16; t++)
    {
        w[t] = ((unsigned long long)block[t * 8 + 0] << 56) |
               ((unsigned long long)block[t * 8 + 1] << 48) |
               ((unsigned long long)block[t * 8 + 2] << 40) |
               ((unsigned long long)block[t * 8 + 3] << 32) |
               ((unsigned long long)block[t * 8 + 4] << 24) |
               ((unsigned long long)block[t * 8 + 5] << 16) |
               ((unsigned long long)block[t * 8 + 6] << 8) |
               ((unsigned long long)block[t * 8 + 7]);
    }
    for (int t = 16; t < 80; t++)
    {
        unsigned long long s0 = sha512_ror(w[t - 15], 1) ^
                                sha512_ror(w[t - 15], 8) ^ (w[t - 15] >> 7);
        unsigned long long s1 = sha512_ror(w[t - 2], 19) ^
                                sha512_ror(w[t - 2], 61) ^ (w[t - 2] >> 6);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }

    unsigned long long a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    unsigned long long e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];

    for (int t = 0; t < 80; t++)
    {
        unsigned long long S1 = sha512_ror(e, 14) ^ sha512_ror(e, 18) ^
                                sha512_ror(e, 41);
        unsigned long long ch = (e & f) ^ (~e & g);
        unsigned long long temp1 = h + S1 + ch + K512[t] + w[t];
        unsigned long long S0 = sha512_ror(a, 28) ^ sha512_ror(a, 34) ^
                                sha512_ror(a, 39);
        unsigned long long maj = (a & b) ^ (a & c) ^ (b & c);
        unsigned long long temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    s->h[0] += a;
    s->h[1] += b;
    s->h[2] += c;
    s->h[3] += d;
    s->h[4] += e;
    s->h[5] += f;
    s->h[6] += g;
    s->h[7] += h;
}

static void sha512_init(Sha512State *s)
{
    static const unsigned long long IV[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

    memcpy(s->h, IV, sizeof(IV));
    s->total_bits = 0;
    s->buf_used = 0;
}

static void sha512_update(Sha512State *s, const unsigned char *data,
                          size_t len)
{
    s->total_bits += (unsigned long long)len * 8;

    while (len > 0)
    {
        size_t take = 128 - s->buf_used;
        if (take > len)
            take = len;
        memcpy(s->buf + s->buf_used, data, take);
        s->buf_used += take;
        data += take;
        len -= take;
        if (s->buf_used == 128)
        {
            sha512_compress(s, s->buf);
            s->buf_used = 0;
        }
    }
}

static void sha512_final(Sha512State *s, unsigned char digest[64])
{
    unsigned long long bits = s->total_bits;

    /* Padding: 0x80, zeros, then the 128-bit big-endian length.  With a
     * single 128-byte spare slot the length always fits. */
    unsigned char pad = 0x80;
    sha512_update(s, &pad, 1);
    unsigned char zero = 0;
    while (s->buf_used != 112)
        sha512_update(s, &zero, 1);

    unsigned char lenbuf[16];
    memset(lenbuf, 0, sizeof(lenbuf));
    for (int i = 0; i < 8; i++)
        lenbuf[8 + i] = (unsigned char)(bits >> (56 - 8 * i));
    sha512_update(s, lenbuf, 16);

    for (int i = 0; i < 8; i++)
    {
        digest[i * 8 + 0] = (unsigned char)(s->h[i] >> 56);
        digest[i * 8 + 1] = (unsigned char)(s->h[i] >> 48);
        digest[i * 8 + 2] = (unsigned char)(s->h[i] >> 40);
        digest[i * 8 + 3] = (unsigned char)(s->h[i] >> 32);
        digest[i * 8 + 4] = (unsigned char)(s->h[i] >> 24);
        digest[i * 8 + 5] = (unsigned char)(s->h[i] >> 16);
        digest[i * 8 + 6] = (unsigned char)(s->h[i] >> 8);
        digest[i * 8 + 7] = (unsigned char)(s->h[i]);
    }
}

/* Child-side: silence helper error output (callers treat non-zero as failure). */
static void silence_stderr(void)
{
    int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (devnull >= 0)
    {
        dup2(devnull, STDERR_FILENO);
        close(devnull);
    }
}

/*
 * Reap the helper with a deadline.  Returns 0 and fills *status_out when
 * the child exited in time, -1 when it had to be killed after stalling.
 * A helper that wrote a digest but never exits is unconfirmable: the
 * caller treats the reap failure as a hashing failure (fail closed), so
 * a stuck child can never hold the event loop hostage while the
 * requesting process stays suspended.
 */
#define REAP_DEADLINE_S 2
#define REAP_KILL_TRIES 50 /* 50 x 10 ms = 500 ms budget after SIGKILL */

/*
 * SIGKILL the helper and reap it without ever blocking the event loop.
 * A helper wedged in an uninterruptible syscall (e.g. sha512sum reading a
 * FUSE-backed /proc/<pid>/exe) stays in D state until that syscall
 * returns, so waitpid() can block indefinitely.  Blocking here would
 * stall the single-threaded daemon and, with it, every open on every
 * mount-marked filesystem while those processes stay kernel-suspended.
 * The caller treats a missing digest as a hashing failure (fail closed);
 * an orphaned zombie is a bounded cost, not a correctness risk.
 */
static void kill_helper_bounded(pid_t pid, const char *label)
{
    if (kill(pid, SIGKILL) < 0 && errno != ESRCH)
        log_msg(LOG_WARNING, "sha512: %s: kill helper pid %d: %s", label,
                (int)pid, strerror(errno));

    for (int i = 0; i < REAP_KILL_TRIES; i++)
    {
        pid_t w = waitpid(pid, NULL, WNOHANG);
        if (w == pid || (w < 0 && errno != EINTR))
            return; /* reaped, or gone/not our child */
        usleep(10000); /* 10 ms tick */
    }

    log_msg(LOG_WARNING,
            "sha512: %s: helper pid %d survived SIGKILL for %d ms; abandoning",
            label, (int)pid, REAP_KILL_TRIES * 10);
}

/* Monotonic milliseconds: wall-clock steps must not extend a deadline. */
static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int reap_helper(pid_t pid, const char *label, int *status_out)
{
    long long deadline = now_ms() + REAP_DEADLINE_S * 1000;

    for (;;)
    {
        int status = 0;
        pid_t w = waitpid(pid, status_out ? status_out : &status, WNOHANG);
        if (w == pid)
            return 0;
        if (w < 0 && errno != EINTR)
        {
            set_failure("sha512sum wait failed");
            return -1;
        }
        if (now_ms() >= deadline)
            break;
        usleep(10000); /* 10 ms tick */
    }

    set_failure("sha512sum did not exit in time");
    log_msg(LOG_WARNING, "sha512: %s: helper did not exit in %ds; killing",
            label, REAP_DEADLINE_S);
    kill_helper_bounded(pid, label);
    return -1;
}

/* Wait-slice length: the poll in collect_digest wakes this often while
 * the helper is silent, so the wait hook can service outstanding events. */
#define HASH_WAIT_SLICE_MS 100

/*
 * Optional callback, invoked once per silent wait slice while a helper
 * is running (see sha512_set_wait_hook()).
 */
static void (*g_wait_hook)(void) = NULL;

void sha512_set_wait_hook(void (*hook)(void))
{
    g_wait_hook = hook;
}

/*
 * Read sha512sum's stdout until EOF (or the buffer is full), enforce the
 * deadline, reap the child and validate the digest.  Output format:
 * "<128-hex-digits>  <filename>\n"; only the first 128 bytes are used.
 *
 * fd is the read end of the helper's stdout pipe and is owned here: every
 * return path closes it, and the caller must not close fd or reap pid.
 * Wait protocol: the child gets SHA512_TIMEOUT_S to produce the digest; a
 * short read or timeout kills it immediately, while a full digest still
 * gets REAP_DEADLINE_S to exit before the same bounded SIGKILL reap
 * (kill_helper_bounded never blocks the event loop).
 */
static int collect_digest(int fd, pid_t pid, const char *label,
                          char hex_out[129])
{
    char buf[200];
    ssize_t total = 0;
    int timed_out = 0;
    long long deadline = now_ms() + SHA512_TIMEOUT_S * 1000;

    memset(buf, 0, sizeof(buf)); /* validation below must never read a
                                  * byte this function did not write */

    while (total < (ssize_t)sizeof(buf) - 1)
    {
        int remaining_ms = (int)(deadline - now_ms());
        if (remaining_ms <= 0)
        {
            timed_out = 1;
            break;
        }

        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        /* Poll in slices: while the helper is silent, run the wait hook
         * so a permission event held against the helper (it opens
         * /proc/<pid>/exe, which may itself be on a marked filesystem)
         * can be answered instead of stalling it to the deadline. */
        if (remaining_ms > HASH_WAIT_SLICE_MS)
            remaining_ms = HASH_WAIT_SLICE_MS;
        int pr = poll(&pfd, 1, remaining_ms);
        if (pr == 0 || (pr < 0 && errno == EINTR))
        {
            if (g_wait_hook)
                g_wait_hook();
            continue;
        }
        if (pr < 0)
            break; /* poll error: fail like a short read (kill, -1) */

        ssize_t n = read(fd, buf + total, sizeof(buf) - 1 - (size_t)total);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        total += n;
    }
    close(fd);

    if (total < 128)
    {
        if (timed_out)
        {
            set_failure("sha512sum timed out");
            log_msg(LOG_ERR, "sha512: %s: timed out", label);
        }
        else
        {
            set_failure("sha512sum returned no digest");
            log_msg(LOG_ERR, "sha512: %s: short read (helper failed)", label);
        }
        kill_helper_bounded(pid, label);
        return -1;
    }

    int status = 0;
    if (reap_helper(pid, label, &status) < 0)
        return -1;
    if (!WIFEXITED(status))
    {
        set_failure("sha512sum was killed");
        log_msg(LOG_ERR, "sha512: %s: helper was killed by a signal", label);
        return -1;
    }
    if (WEXITSTATUS(status) != 0)
    {
        char reason[48];
        snprintf(reason, sizeof(reason), "sha512sum failed (exit %d)",
                 WEXITSTATUS(status));
        set_failure(reason);
        log_msg(LOG_ERR, "sha512: %s: helper exited %d", label,
                WEXITSTATUS(status));
        return -1;
    }

    /* GNU sha512sum prefixes the line with a backslash when the printed
     * filename contains a backslash or newline; accept and skip it.
     * The full digest must sit inside what was actually READ (not just
     * inside the buffer): a read that stopped at exactly 128 bytes with
     * a backslash prefix has no complete digest. */
    size_t digest_off = (buf[0] == '\\') ? 1 : 0;

    if (total < (ssize_t)(digest_off + 128))
    {
        set_failure("sha512sum returned a truncated digest");
        log_msg(LOG_ERR, "sha512: %s: truncated digest output", label);
        return -1;
    }

    /* Validate: the 128 digest characters must all be hex digits. */
    for (int i = 0; i < 128; i++)
    {
        if (!isxdigit((unsigned char)buf[digest_off + i]))
        {
            set_failure("sha512sum returned an invalid digest");
            log_msg(LOG_ERR, "sha512: %s: invalid digest output", label);
            return -1;
        }
    }

    memcpy(hex_out, buf + digest_off, 128);
    hex_out[128] = '\0';
    set_failure("");
    return 0;
}

/*
 * Test seam (sha512.h): override the hash helper binary.  Empty (the
 * default) selects /usr/bin/sha512sum below, so production helper path,
 * argv, timeout and reap behavior are byte-identical when the seam is
 * unset; tests point it at a slow stand-in to exercise the bounded
 * kill/reap path (kill_helper_bounded / REAP_DEADLINE_S).
 */
static char g_test_helper[PATH_MAX] = "";

void sha512_test_set_helper(const char *path)
{
    if (!path || path[0] == '\0')
    {
        g_test_helper[0] = '\0';
        return;
    }
    snprintf(g_test_helper, sizeof(g_test_helper), "%s", path);
}

int sha512_file(const char *path, char hex_out[129])
{
    int pipefd[2];

    set_failure("");
    if (pipe2(pipefd, O_CLOEXEC) < 0)
    {
        set_failure("pipe() failed");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        set_failure("fork() failed");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0)
    {
        close(pipefd[0]);
        /* dup2() clears CLOEXEC on the copy: after exec the helper's
         * stdout is the pipe, while the O_CLOEXEC original is closed here
         * so no descriptor leaks. */
        if (dup2(pipefd[1], STDOUT_FILENO) < 0)
            _exit(127);
        close(pipefd[1]);
        silence_stderr();
        /* Do not leak the daemon's fanotify/event/pipe fds into the helper. */
        close_fds_from(3);
        /*
         * Pass the path as a separate argument — no shell involved, so
         * no command-injection risk regardless of the path content.
         * The test seam swaps only the executable; argv is unchanged,
         * and with the seam unset this is the original exec exactly.
         */
        const char *helper =
            g_test_helper[0] ? g_test_helper : "/usr/bin/sha512sum";
        execl(helper, "sha512sum", "--", path, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);
    return collect_digest(pipefd[0], pid, path, hex_out);
}

/* Encode a raw 64-byte digest as 128 lower-case hex characters. */
static void digest_to_hex(const unsigned char digest[64], char hex_out[129])
{
    static const char HEX[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++)
    {
        hex_out[i * 2 + 0] = HEX[digest[i] >> 4];
        hex_out[i * 2 + 1] = HEX[digest[i] & 0x0f];
    }
    hex_out[128] = '\0';
}

/*
 * In-process digest for in-memory fingerprints: no fork, validated
 * against sha512sum by test_sha512 (see the in-process SHA-512 comment
 * above for why file hashing keeps the helper).
 */
int sha512_buf(const void *data, size_t len, char hex_out[129])
{
    if (!data)
        return -1;

    Sha512State s;
    sha512_init(&s);
    if (len > 0)
        sha512_update(&s, (const unsigned char *)data, len);

    unsigned char digest[64];
    sha512_final(&s, digest);
    digest_to_hex(digest, hex_out);
    return 0;
}

int sha512_string(const char *str, char hex_out[129])
{
    if (!str)
        return -1;
    return sha512_buf(str, strlen(str), hex_out);
}

/*
 * Hash the executable of process 'pid' via /proc/<pid>/exe.
 * This path is always accessible from the host as root, even when the process
 * lives inside a container (Podman/Docker) whose root filesystem is an overlay
 * mount not visible under the path returned by proc_exe_path().
 */
int sha512_proc_exe(pid_t pid, char hex_out[129])
{
    char proc_path[64];
    int n = snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", (int)pid);
    if (n < 0 || (size_t)n >= sizeof(proc_path))
        return -1;
    return sha512_file(proc_path, hex_out);
}
