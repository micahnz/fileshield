/*
 * test_cli: fileshield-cli exit codes, fallback gate, confirmation gate
 * and the Item-2 clear/prune daemon-contact regression.
 *
 * Every invocation runs cli_test_main() (cli.c built with
 * -DFILESHIELD_TEST_CLI) in a forked child: the -y/getopt statics and
 * getopt's optind do not re-arm across calls in one process.  stdin is
 * /dev/null (non-tty) and stdout+stderr are captured on a pipe, so the
 * non-terminal confirmation gate is exercised for real.
 *
 * The suite never opens /run/fileshield or /var/lib/fileshield:
 *   - errno gate cases arm control_client_test_fail_with() (no socket
 *     work at all);
 *   - reachable-daemon cases redirect control_client_test_set_socket_path()
 *     at a temp UNIX socket served by a canned fork() server;
 *   - state-file commands redirect cli_test_set_state_files() into the
 *     suite's mkdtemp() directory.
 *
 * AAA: each case arranges fixtures/seams, acts via one run_cli(), and
 * asserts on the exit status plus the captured output (and, where the
 * verb matters, the request the canned server received).
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/control_client.h"
#include "../src/persist.h"

/* Provided by build/cli_test.o (cli.c -DFILESHIELD_TEST_CLI). */
int cli_test_main(int argc, char *argv[]);
void cli_test_set_state_files(const char *allow, const char *deny);

static int failures = 0;
static char g_tmp[256];
static char g_allow_path[PATH_MAX];
static char g_deny_path[PATH_MAX];
static char g_sock_path[PATH_MAX];

#define ASSERT(cond, msg)                                               \
    do                                                                  \
    {                                                                   \
        if (!(cond))                                                    \
        {                                                               \
            fprintf(stderr, "FAIL: %s\n", msg);                         \
            failures++;                                                 \
        }                                                               \
    } while (0)

/* ------------------------------------------------------------------ */
/* Harness                                                            */
/* ------------------------------------------------------------------ */

/* Point every seam back at production defaults before arranging a case. */
static void reset_seams(void)
{
    control_client_test_fail_with(0);
    control_client_test_set_socket_path(NULL);
    cli_test_set_state_files(NULL, NULL);
}

/* NULL-terminated argv run in a forked child; returns the exit status
 * (or -1 if the child died on a signal) and leaves combined
 * stdout+stderr in out. */
static int run_cli(char *argv[], char *out, size_t outsz)
{
    int p[2];
    pid_t pid;
    size_t used = 0;
    int status = 0;
    int argc = 0;

    while (argv[argc])
        argc++;
    if (outsz == 0)
        return -1;
    out[0] = '\0';
    if (pipe(p) != 0)
        return -1;

    pid = fork();
    if (pid < 0)
    {
        close(p[0]);
        close(p[1]);
        return -1;
    }
    if (pid == 0)
    {
        int devnull;

        close(p[0]);
        if (dup2(p[1], STDOUT_FILENO) < 0 ||
            dup2(p[1], STDERR_FILENO) < 0)
            _exit(99);
        if (p[1] > STDERR_FILENO)
            close(p[1]);
        /* Non-tty stdin: the confirmation gate must refuse without -y. */
        devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0)
        {
            (void)dup2(devnull, STDIN_FILENO);
            if (devnull > STDIN_FILENO)
                close(devnull);
        }
        {
            /* stdout onto a pipe is fully buffered; _exit skips stdio
             * teardown, so flush explicitly or the parent never sees it. */
            int rc = cli_test_main(argc, argv);

            fflush(stdout);
            fflush(stderr);
            _exit(rc & 0xff);
        }
    }

    close(p[1]);
    for (;;)
    {
        ssize_t n = read(p[0], out + used, outsz - 1 - used);

        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        used += (size_t)n;
        if (used >= outsz - 1)
        {
            /* Drain the rest into a scratch buffer so the child never
             * blocks on a full pipe (the captured output is already
             * full). */
            char scratch[256];

            while (read(p[0], scratch, sizeof(scratch)) > 0)
                ;
            break;
        }
    }
    out[used] = '\0';
    close(p[0]);
    if (waitpid(pid, &status, 0) != pid)
        return -1;
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1;
}

/* Remove both redirected state files (missing file == 0 entries). */
static void clear_state(void)
{
    unlink(g_allow_path);
    unlink(g_deny_path);
}

/* One valid allow-list entry so load_entries() reports count > 0. */
static void seed_allow_one(void)
{
    PersistEntry e;

    memset(&e, 0, sizeof(e));
    snprintf(e.rule_id, sizeof(e.rule_id), "%s", "0123456789abcdef");
    snprintf(e.binary, sizeof(e.binary), "%s", "/usr/bin/demo");
    snprintf(e.binary_sha512, sizeof(e.binary_sha512), "%s", "BSHA");
    snprintf(e.target_path, sizeof(e.target_path), "%s", "/home/u/secret");
    snprintf(e.cmdline, sizeof(e.cmdline), "%s", "demo --run");
    snprintf(e.cmdline_sha512, sizeof(e.cmdline_sha512), "%s", "CSHA");
    e.chain_depth = 1;
    snprintf(e.chain_comm[0], sizeof(e.chain_comm[0]), "%s", "bash");
    e.created_at = (time_t)1700000000;
    if (persist_save(g_allow_path, &e, 1) != 0)
        ASSERT(0, "seed one allow entry");
}

static int allow_count(void)
{
    PersistEntry entries[PERSIST_MAX_ENTRIES];

    return persist_load(g_allow_path, entries, PERSIST_MAX_ENTRIES);
}

/* AF_UNIX path helper (same bound as test_control.c). */
static int fill_sun_path(struct sockaddr_un *addr, const char *path)
{
    size_t n = strlen(path);

    if (n >= sizeof(addr->sun_path))
        return -1;
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    memcpy(addr->sun_path, path, n + 1);
    return 0;
}

/*
 * Canned one-shot server: bind 'path', listen, signal readiness, accept
 * one connection, read the request to EOF, record it at req_path (when
 * non-NULL), write 'response', exit.  alarm() bounds a client that never
 * connects so a failed case cannot hang the suite.
 */
static pid_t serve_once(const char *path, const char *response,
                        const char *req_path, int *sync_fd)
{
    int p[2];
    pid_t pid;

    if (pipe(p) != 0)
        return -1;
    pid = fork();
    if (pid < 0)
    {
        close(p[0]);
        close(p[1]);
        return -1;
    }
    if (pid == 0)
    {
        struct sockaddr_un addr;
        char req[CONTROL_REQ_MAX];
        size_t used = 0;
        size_t rn;
        size_t off;
        int lfd;
        int cfd;

        close(p[0]);
        signal(SIGPIPE, SIG_IGN);
        alarm(10);

        lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (lfd < 0)
            _exit(2);
        if (fill_sun_path(&addr, path) < 0)
            _exit(2);
        if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
            _exit(2);
        if (listen(lfd, 1) < 0)
            _exit(2);
        if (write(p[1], "x", 1) != 1)
            _exit(2);
        close(p[1]);

        cfd = accept(lfd, NULL, NULL);
        if (cfd < 0)
            _exit(2);
        while (used < sizeof(req) - 1)
        {
            ssize_t r = read(cfd, req + used, sizeof(req) - 1 - used);

            if (r < 0 && errno == EINTR)
                continue;
            if (r <= 0)
                break;
            used += (size_t)r;
        }
        req[used] = '\0';
        if (used == 0 || req[used - 1] != '\n')
            _exit(3);

        if (req_path)
        {
            int fd = open(req_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

            if (fd < 0)
                _exit(5);
            off = 0;
            while (off < used)
            {
                ssize_t w = write(fd, req + off, used - off);

                if (w < 0 && errno == EINTR)
                    continue;
                if (w <= 0)
                    _exit(5);
                off += (size_t)w;
            }
            close(fd);
        }

        rn = strlen(response);
        off = 0;
        while (off < rn)
        {
            ssize_t w = write(cfd, response + off, rn - off);

            if (w < 0 && errno == EINTR)
                continue;
            if (w <= 0)
                _exit(4);
            off += (size_t)w;
        }
        close(cfd);
        close(lfd);
        alarm(0);
        _exit(0);
    }

    close(p[1]);
    *sync_fd = p[0];
    return pid;
}

/* Reap the canned server.  A successful client exchange means the server
 * is already exiting; a client that never connected is bounded by the
 * server's alarm(10).  When readiness was not consumed here, pass -1. */
static void reap_server(pid_t pid, int sync_fd, int *status_out)
{
    int status = 0;
    char token;

    if (sync_fd >= 0)
    {
        ssize_t rd = read(sync_fd, &token, 1); /* readiness (or EOF on failure) */
        (void)rd;
        close(sync_fd);
    }
    (void)waitpid(pid, &status, 0);
    if (status_out)
        *status_out = status;
}

/* Read a file into buf; returns bytes read or -1. */
static ssize_t read_file(const char *path, char *buf, size_t sz)
{
    int fd = open(path, O_RDONLY);
    size_t used = 0;

    if (fd < 0)
        return -1;
    while (used + 1 < sz)
    {
        ssize_t n = read(fd, buf + used, sz - 1 - used);

        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        if (n == 0)
            break;
        used += (size_t)n;
    }
    close(fd);
    buf[used] = '\0';
    return (ssize_t)used;
}

/* ------------------------------------------------------------------ */
/* Exit codes: 2 usage, 0 success, 1 domain failure                   */
/* ------------------------------------------------------------------ */

static void test_exit_code_2_usage(void)
{
    char out[4096];
    char *no_args[] = {"fileshield-cli", NULL};
    char *unknown[] = {"fileshield-cli", "frobnicate", NULL};
    char *clear_missing[] = {"fileshield-cli", "clear", NULL};
    char *clear_bogus[] = {"fileshield-cli", "clear", "bogus", NULL};
    char *prune_bogus[] = {"fileshield-cli", "prune", "sideways", NULL};

    reset_seams();
    cli_test_set_state_files(g_allow_path, g_deny_path);
    clear_state();

    ASSERT(run_cli(no_args, out, sizeof(out)) == 2,
           "no command is a usage error (exit 2)");
    ASSERT(strstr(out, "Usage:") != NULL, "usage text on missing command");

    ASSERT(run_cli(unknown, out, sizeof(out)) == 2,
           "unknown command is exit 2");
    ASSERT(strstr(out, "unknown command") != NULL, "unknown-command message");

    ASSERT(run_cli(clear_missing, out, sizeof(out)) == 2,
           "clear without a type is exit 2");
    ASSERT(run_cli(clear_bogus, out, sizeof(out)) == 2,
           "clear with a bad type is exit 2");
    ASSERT(run_cli(prune_bogus, out, sizeof(out)) == 2,
           "prune with a bad filter is exit 2");
}

static void test_exit_code_0_help_version(void)
{
    char out[4096];
    char *help[] = {"fileshield-cli", "-h", NULL};
    char *version[] = {"fileshield-cli", "-v", NULL};

    reset_seams();

    ASSERT(run_cli(help, out, sizeof(out)) == 0, "-h exits 0");
    ASSERT(strstr(out, "Usage:") != NULL, "-h prints usage");
    ASSERT(run_cli(version, out, sizeof(out)) == 0, "-v exits 0");
    ASSERT(strstr(out, "fileshield-cli") != NULL, "-v prints the version");
}

/* ------------------------------------------------------------------ */
/* Fallback gate: only ENOENT/ECONNREFUSED reach the file path         */
/* ------------------------------------------------------------------ */

static void test_fallback_enoent(void)
{
    char out[4096];
    char *clear_y[] = {"fileshield-cli", "-y", "clear", "allow", NULL};
    char *prune_y[] = {"fileshield-cli", "-y", "prune", NULL};
    char *session_y[] = {"fileshield-cli", "-y", "session", "clear", NULL};

    reset_seams();
    cli_test_set_state_files(g_allow_path, g_deny_path);

    /* Empty state + ENOENT: the file-side "nothing to clear" outcome. */
    clear_state();
    control_client_test_fail_with(ENOENT);
    ASSERT(run_cli(clear_y, out, sizeof(out)) == 0,
           "ENOENT clear with an empty list exits 0");
    ASSERT(strstr(out, "no allow rules to clear") != NULL,
           "ENOENT clear uses the file path (no-listener message)");
    ASSERT(strstr(out, "cannot reach") == NULL,
           "ENOENT is not reported as a hard socket error");

    /* One entry + ENOENT: the real file-only rewrite runs. */
    clear_state();
    seed_allow_one();
    ASSERT(allow_count() == 1, "fixture has one allow entry");
    control_client_test_fail_with(ENOENT);
    ASSERT(run_cli(clear_y, out, sizeof(out)) == 0,
           "ENOENT clear with entries exits 0");
    ASSERT(strstr(out, "daemon not running") != NULL,
           "ENOENT clear warns and applies directly to the state file");
    ASSERT(strstr(out, "cleared the allow list") != NULL,
           "ENOENT clear reports success via the file path");
    ASSERT(allow_count() == 0, "ENOENT fallback emptied the state file");

    /* Session commands have no file fallback: ENOENT is "not running". */
    control_client_test_fail_with(ENOENT);
    ASSERT(run_cli(session_y, out, sizeof(out)) == 1,
           "session clear with ENOENT exits 1 (no fallback)");
    ASSERT(strstr(out, "daemon is not running") != NULL,
           "session ENOENT is the not-running message");

    /* Prune, empty files + ENOENT: file-side no-results outcome. */
    clear_state();
    control_client_test_fail_with(ENOENT);
    ASSERT(run_cli(prune_y, out, sizeof(out)) == 0,
           "ENOENT prune with nothing to do exits 0");
    ASSERT(strstr(out, "there are no results to prune") != NULL,
           "ENOENT prune uses the file path (no-results message)");
}

static void test_fallback_econnrefused(void)
{
    char out[4096];
    char *clear_y[] = {"fileshield-cli", "-y", "clear", "allow", NULL};
    char *session_y[] = {"fileshield-cli", "-y", "session", "clear", NULL};

    reset_seams();
    cli_test_set_state_files(g_allow_path, g_deny_path);

    clear_state();
    control_client_test_fail_with(ECONNREFUSED);
    ASSERT(run_cli(clear_y, out, sizeof(out)) == 0,
           "ECONNREFUSED clear with an empty list exits 0");
    ASSERT(strstr(out, "no allow rules to clear") != NULL,
           "ECONNREFUSED clear falls back to the file path");

    clear_state();
    seed_allow_one();
    control_client_test_fail_with(ECONNREFUSED);
    ASSERT(run_cli(clear_y, out, sizeof(out)) == 0,
           "ECONNREFUSED clear with entries exits 0");
    ASSERT(strstr(out, "daemon not running") != NULL,
           "ECONNREFUSED clear applies directly to the state file");
    ASSERT(allow_count() == 0, "ECONNREFUSED fallback emptied the state file");

    control_client_test_fail_with(ECONNREFUSED);
    ASSERT(run_cli(session_y, out, sizeof(out)) == 1,
           "session clear with ECONNREFUSED exits 1");
    ASSERT(strstr(out, "daemon is not running") != NULL,
           "session ECONNREFUSED is the not-running message");
}

static void test_gate_eacces_no_fallback(void)
{
    char out[4096];
    char *clear_y[] = {"fileshield-cli", "-y", "clear", "allow", NULL};
    char *session_y[] = {"fileshield-cli", "-y", "session", "clear", NULL};

    reset_seams();
    cli_test_set_state_files(g_allow_path, g_deny_path);

    /* Empty list + EACCES: still a hard error, never "nothing to clear". */
    clear_state();
    control_client_test_fail_with(EACCES);
    ASSERT(run_cli(clear_y, out, sizeof(out)) == 1,
           "EACCES clear exits 1 (no fallback)");
    ASSERT(strstr(out, "cannot reach") != NULL,
           "EACCES clear reports the socket error");
    ASSERT(strstr(out, "Permission denied") != NULL,
           "EACCES clear surfaces EACCES, not the no-listener path");
    ASSERT(strstr(out, "no allow rules to clear") == NULL,
           "EACCES never maps to the file-only no-listener outcome");

    /* One entry + EACCES: the state file must stay untouched. */
    clear_state();
    seed_allow_one();
    control_client_test_fail_with(EACCES);
    ASSERT(run_cli(clear_y, out, sizeof(out)) == 1,
           "EACCES clear with entries exits 1");
    ASSERT(strstr(out, "daemon not running") == NULL,
           "EACCES never takes the no-listener fallback branch");
    ASSERT(allow_count() == 1, "EACCES left the state file unchanged");

    /* Session clear: same gate, no file involvement at all. */
    control_client_test_fail_with(EACCES);
    ASSERT(run_cli(session_y, out, sizeof(out)) == 1,
           "session clear with EACCES exits 1");
    ASSERT(strstr(out, "cannot reach") != NULL,
           "session EACCES is a hard socket error");
    ASSERT(strstr(out, "daemon is not running") == NULL,
           "session EACCES is not relabeled as not-running (that is "
           "ENOENT/ECONNREFUSED only)");
}

/* ------------------------------------------------------------------ */
/* Confirmation gate: non-tty refuses without -y                      */
/* ------------------------------------------------------------------ */

static void test_confirmation_gate(void)
{
    char out[4096];
    char *session_plain[] = {"fileshield-cli", "session", "clear", NULL};
    char *session_y[] = {"fileshield-cli", "-y", "session", "clear", NULL};
    char *clear_plain[] = {"fileshield-cli", "clear", "allow", NULL};
    char *clear_y[] = {"fileshield-cli", "-y", "clear", "allow", NULL};

    reset_seams();
    cli_test_set_state_files(g_allow_path, g_deny_path);

    /* session clear always prompts: stdin is /dev/null here. */
    control_client_test_fail_with(ENOENT);
    ASSERT(run_cli(session_plain, out, sizeof(out)) == 1,
           "session clear without -y on a non-tty exits 1");
    ASSERT(strstr(out, "refusing to prompt on a non-terminal") != NULL,
           "non-tty session clear refuses instead of reading EOF");
    ASSERT(strstr(out, "daemon is not running") == NULL,
           "refusal happens before any control-socket call");

    /* Same command with -y clears the gate and reaches the socket. */
    control_client_test_fail_with(ENOENT);
    ASSERT(run_cli(session_y, out, sizeof(out)) == 1,
           "-y session clear proceeds past the gate (then no daemon)");
    ASSERT(strstr(out, "refusing to prompt") == NULL,
           "-y skips the non-tty refusal");
    ASSERT(strstr(out, "daemon is not running") != NULL,
           "-y session clear reached the control socket");

    /* clear allow only prompts when the file shows entries. */
    clear_state();
    seed_allow_one();
    control_client_test_fail_with(ENOENT);
    ASSERT(run_cli(clear_plain, out, sizeof(out)) == 1,
           "clear allow without -y on a non-tty exits 1");
    ASSERT(strstr(out, "refusing to prompt on a non-terminal") != NULL,
           "non-tty clear refuses the confirmation");
    ASSERT(strstr(out, "aborted") != NULL, "refusal reports aborted");
    ASSERT(allow_count() == 1, "refused clear left the state file alone");

    control_client_test_fail_with(ENOENT);
    ASSERT(run_cli(clear_y, out, sizeof(out)) == 0,
           "-y clear allow proceeds and falls back to the file");
    ASSERT(strstr(out, "refusing to prompt") == NULL,
           "-y skips the clear confirmation gate");
    ASSERT(allow_count() == 0, "confirmed clear applied the file fallback");
}

/* ------------------------------------------------------------------ */
/* Item 2: a reachable listener is always sent RULE_CLEAR / PRUNE      */
/* ------------------------------------------------------------------ */

static void test_item2_clear_sends_rule_clear(void)
{
    char out[4096];
    char req[512];
    char reqfile[PATH_MAX];
    char *clear_y[] = {"fileshield-cli", "-y", "clear", "allow", NULL};
    int syncfd = -1;
    int status = 0;
    pid_t server;
    ssize_t n;

    /* Empty file snapshot: the pre-fix code returned "nothing to clear"
     * without ever touching the socket. */
    reset_seams();
    cli_test_set_state_files(g_allow_path, g_deny_path);
    clear_state();
    unlink(g_sock_path);

    snprintf(reqfile, sizeof(reqfile), "%s/clear.req", g_tmp);
    unlink(reqfile);
    server = serve_once(g_sock_path, "OK\n1\n0\n", reqfile, &syncfd);
    ASSERT(server > 0, "spawn canned server for clear");
    if (server <= 0)
        return;
    {
        char token;

        ASSERT(read(syncfd, &token, 1) == 1, "clear server ready");
        close(syncfd);
        syncfd = -1;
    }

    control_client_test_fail_with(0);
    control_client_test_set_socket_path(g_sock_path);

    ASSERT(run_cli(clear_y, out, sizeof(out)) == 0,
           "clear with a listener and an empty file exits 0");
    ASSERT(strstr(out, "cleared the allow list") != NULL,
           "reachable daemon: clear reports the daemon's result");
    ASSERT(strstr(out, "no allow rules to clear") == NULL,
           "reachable daemon: clear does NOT take the file-only path");

    reap_server(server, -1, &status);
    ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
           "canned clear server finished cleanly");

    n = read_file(reqfile, req, sizeof(req));
    ASSERT(n > 0, "canned server recorded the clear request");
    if (n > 0)
        ASSERT(strncmp(req, "RULE_CLEAR\tallow\n", 17) == 0,
               "clear sent RULE_CLEAR allow to the listener");
    unlink(reqfile);

    unlink(g_sock_path);
    reset_seams();
}

static void test_item2_prune_sends_prune(void)
{
    char out[4096];
    char req[512];
    char reqfile[PATH_MAX];
    char *prune_y[] = {"fileshield-cli", "-y", "prune", NULL};
    int syncfd = -1;
    int status = 0;
    pid_t server;
    ssize_t n;

    reset_seams();
    cli_test_set_state_files(g_allow_path, g_deny_path);
    clear_state();
    unlink(g_sock_path);

    snprintf(reqfile, sizeof(reqfile), "%s/prune.req", g_tmp);
    unlink(reqfile);
    server = serve_once(g_sock_path, "OK\n1\n0\n", reqfile, &syncfd);
    ASSERT(server > 0, "spawn canned server for prune");
    if (server <= 0)
        return;
    {
        char token;

        ASSERT(read(syncfd, &token, 1) == 1, "prune server ready");
        close(syncfd);
        syncfd = -1;
    }

    control_client_test_fail_with(0);
    control_client_test_set_socket_path(g_sock_path);

    ASSERT(run_cli(prune_y, out, sizeof(out)) == 0,
           "prune with a listener and empty files exits 0");
    ASSERT(strstr(out, "pruned 0 duplicate(s)") != NULL,
           "reachable daemon: prune prints the daemon's removed count");
    ASSERT(strstr(out, "there are no results to prune") == NULL,
           "reachable daemon: prune does NOT take the file-only path");

    reap_server(server, -1, &status);
    ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
           "canned prune server finished cleanly");

    n = read_file(reqfile, req, sizeof(req));
    ASSERT(n > 0, "canned server recorded the prune request");
    if (n > 0)
        ASSERT(strncmp(req, "PRUNE\tboth\n", 11) == 0,
               "prune sent PRUNE both to the listener");
    unlink(reqfile);

    unlink(g_sock_path);
    reset_seams();
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

static int setup_tmp(void)
{
    snprintf(g_tmp, sizeof(g_tmp), "/tmp/fileshield_cli_XXXXXX");
    if (!mkdtemp(g_tmp))
    {
        fprintf(stderr, "FAIL: mkdtemp: %s\n", strerror(errno));
        return -1;
    }
    snprintf(g_allow_path, sizeof(g_allow_path), "%s/allow.json", g_tmp);
    snprintf(g_deny_path, sizeof(g_deny_path), "%s/deny.json", g_tmp);
    snprintf(g_sock_path, sizeof(g_sock_path), "%s/ctl.sock", g_tmp);
    return 0;
}

static void cleanup_tmp(void)
{
    char path[PATH_MAX];

    unlink(g_allow_path);
    unlink(g_deny_path);
    unlink(g_sock_path);
    snprintf(path, sizeof(path), "%s/clear.req", g_tmp);
    unlink(path);
    snprintf(path, sizeof(path), "%s/prune.req", g_tmp);
    unlink(path);
    rmdir(g_tmp);
}

int main(void)
{
    printf("=== test_cli ===\n");
    if (setup_tmp() != 0)
        return 1;

    test_exit_code_2_usage();
    test_exit_code_0_help_version();
    test_fallback_enoent();
    test_fallback_econnrefused();
    test_gate_eacces_no_fallback();
    test_confirmation_gate();
    test_item2_clear_sends_rule_clear();
    test_item2_prune_sends_prune();

    reset_seams();
    cleanup_tmp();

    if (failures)
    {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
