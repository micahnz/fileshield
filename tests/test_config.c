#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pwd.h>
#include <sys/stat.h>

#include "../src/config.h"
#include "../src/utils.h"

static int failures = 0;

#define ASSERT(cond, msg)                       \
    do                                          \
    {                                           \
        if (!(cond))                            \
        {                                       \
            fprintf(stderr, "FAIL: %s\n", msg); \
            failures++;                         \
        }                                       \
    } while (0)

static char *write_temp(const char *content)
{
    char tmpl[] = "/tmp/fileshield_test_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0)
        return NULL;
    size_t len = strlen(content);
    size_t written = 0;
    while (written < len)
    {
        ssize_t n = write(fd, content + written, len - written);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            close(fd);
            unlink(tmpl);
            return NULL;
        }
        written += (size_t)n;
    }
    close(fd);
    return strdup(tmpl);
}

static void test_basic_parse(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/etc/ssh/ssh_config\n" /* absolute paths — no per-user expansion */
        "/etc/ssl/certs\n"
        "# comment line\n"
        "\n"
        "[allowlist]\n"
        "/usr/bin/ssh = /etc/ssl/certs\n"
        "/usr/bin/git\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load success");

    ASSERT(cfg.protected_count == 2, "2 protected paths");
    ASSERT(strstr(cfg.protected[0].path, "ssh_config") != NULL, "first path ssh_config");
    ASSERT(strstr(cfg.protected[1].path, "certs") != NULL, "second path certs");

    ASSERT(cfg.allowlist_count == 2, "2 allowlist entries");
    ASSERT(strcmp(cfg.allowlist[0].binary, "/usr/bin/ssh") == 0, "allowlist ssh binary");
    ASSERT(strcmp(cfg.allowlist[0].target_path, "/etc/ssl/certs") == 0,
           "allowlist ssh target");
    ASSERT(strcmp(cfg.allowlist[1].binary, "/usr/bin/git") == 0, "allowlist git binary");
    ASSERT(cfg.allowlist[1].target_path[0] == '\0', "bare entry is a global rule");

    config_reset(&cfg);
    ASSERT(cfg.protected_count == 0, "config_reset zeros count");
    ASSERT(cfg.allowlist_count == 0, "config_reset zeros allowlist count");

    unlink(path);
    free(path);
}

static void test_missing_file(void)
{
    Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT(config_load("/nonexistent/fileshield_test.conf", &cfg) == -1, "missing file fails");

    /* A directory opens read-only but cannot be read: the read error must
     * refuse the config instead of yielding an empty one. */
    ASSERT(config_load("/tmp", &cfg) == -1, "unreadable directory refused");
}

/*
 * An unknown section header must refuse the whole config: silently
 * ignoring it would drop every rule under a typo'd header while the
 * daemon reports success.
 */
static void test_unknown_section(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/tmp/ok\n"
        "[bogus]\n"
        "/tmp/ignored\n"
        "[allowlist]\n"
        "/usr/bin/x = /tmp/ok\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    ASSERT(config_load(path, &cfg) == -1,
           "unknown section refuses the whole config");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

static void test_settings_user_ttl(void)
{
    const char *conf =
        "[settings]\n"
        "user_ttl = 120\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for settings");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load settings success");
    ASSERT(cfg.user_ttl_seconds == 120, "user_ttl parsed correctly");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

static void test_settings_session_ttl(void)
{
    const char *conf =
        "[settings]\n"
        "user_ttl = 120\n"
        "session_ttl = 0\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for session settings");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load session settings success");
    ASSERT(cfg.user_ttl_seconds == 120, "user_ttl parsed alongside session_ttl");
    ASSERT(cfg.session_ttl_seconds == 0, "session_ttl 0 (leader lifetime) parsed");

    config_reset(&cfg);
    ASSERT(cfg.session_ttl_seconds == 0, "config_reset clears session_ttl");

    unlink(path);
    free(path);
}

static void test_settings_session_ttl_value(void)
{
    const char *conf =
        "[settings]\n"
        "session_ttl = 900\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for session_ttl value");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    config_load(path, &cfg);
    ASSERT(cfg.session_ttl_seconds == 900, "session_ttl value parsed");
    /* Absent session_ttl must default to 0, not inherit user_ttl. */
    ASSERT(cfg.user_ttl_seconds == 0, "user_ttl absent defaults to 0");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

static void test_settings_invalid_session_ttl(void)
{
    const char *conf =
        "[settings]\n"
        "session_ttl = -5\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for invalid session_ttl");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    config_load(path, &cfg);
    ASSERT(cfg.session_ttl_seconds == 0, "invalid session_ttl not applied");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

static void test_settings_invalid_user_ttl(void)
{
    const char *conf =
        "[settings]\n"
        "user_ttl = -5\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for invalid settings");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.user_ttl_seconds = 0; /* default — should stay 0 on invalid value */

    config_load(path, &cfg);
    ASSERT(cfg.user_ttl_seconds == 0, "invalid user_ttl not applied");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * Integer settings go through strtol: overflow and trailing junk are
 * rejected instead of saturated or truncated, and user_ttl = 0 is accepted
 * (documented as "disables caching").
 */
static void test_settings_int_parsing(void)
{
    Config cfg;
    char *path;

    /* user_ttl = 0 disables caching and must be accepted. */
    path = write_temp("[settings]\n"
                      "user_ttl = 0\n");
    ASSERT(path != NULL, "write temp config for user_ttl = 0");
    memset(&cfg, 0, sizeof(cfg));
    ASSERT(config_load(path, &cfg) == 0, "config_load user_ttl = 0");
    ASSERT(cfg.user_ttl_seconds == 0, "user_ttl = 0 is accepted");
    config_reset(&cfg);
    unlink(path);
    free(path);

    /* Trailing junk is rejected rather than accepted as 120. */
    path = write_temp("[settings]\n"
                      "user_ttl = 120junk\n"
                      "notify_max = 5x\n");
    ASSERT(path != NULL, "write temp config for trailing junk");
    memset(&cfg, 0, sizeof(cfg));
    ASSERT(config_load(path, &cfg) == 0, "config_load trailing junk");
    ASSERT(cfg.user_ttl_seconds == 0, "user_ttl junk is rejected");
    ASSERT(cfg.notify_max == NOTIFY_MAX_DEFAULT,
           "notify_max junk keeps the default");
    config_reset(&cfg);
    unlink(path);
    free(path);

    /* Overflow is rejected, not saturated and clamped. */
    path = write_temp("[settings]\n"
                      "user_ttl = 99999999999999999999\n"
                      "session_ttl = 30s\n");
    ASSERT(path != NULL, "write temp config for overflow");
    memset(&cfg, 0, sizeof(cfg));
    ASSERT(config_load(path, &cfg) == 0, "config_load overflow");
    ASSERT(cfg.user_ttl_seconds == 0, "user_ttl overflow is rejected");
    ASSERT(cfg.session_ttl_seconds == 0, "session_ttl junk is rejected");
    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * Notification toggles: unsafe_allowlist and denylist on by default,
 * allowlist off; notify_dedup_ttl defaults to 60 s.  Explicit values use
 * the same yes/no/true/false/1/0 spellings as debug; invalid values are
 * rejected and the default is kept.
 */
static void test_settings_notifications(void)
{
    Config cfg;

    /* Defaults with no keys present. */
    char *path = write_temp("[settings]\n");
    ASSERT(path != NULL, "write temp config for notification defaults");

    memset(&cfg, 0, sizeof(cfg));
    ASSERT(config_load(path, &cfg) == 0, "config_load notification defaults");
    ASSERT(cfg.notify_unsafe_allow == 1, "unsafe allowlist notify defaults on");
    ASSERT(cfg.notify_allow == 0, "allowlist notify defaults off");
    ASSERT(cfg.notify_deny == 1, "denylist notify defaults on");
    ASSERT(cfg.notify_dedup_seconds == NOTIFY_DEDUP_DEFAULT_S,
           "notify_dedup_ttl defaults to 60 s");
    ASSERT(cfg.notify_max == NOTIFY_MAX_DEFAULT,
           "notify_max defaults to 20 per window");
    config_reset(&cfg);
    unlink(path);
    free(path);

    /* Explicit values, mixed accepted spellings. */
    path = write_temp("[settings]\n"
                      "notify_unsafe_allowlist = no\n"
                      "notify_allowlist = true\n"
                      "notify_denylist = 0\n"
                      "notify_dedup_ttl = 15\n"
                      "notify_max = 5\n");
    ASSERT(path != NULL, "write temp config for notification values");

    memset(&cfg, 0, sizeof(cfg));
    ASSERT(config_load(path, &cfg) == 0, "config_load notification values");
    ASSERT(cfg.notify_unsafe_allow == 0, "notify_unsafe_allowlist = no");
    ASSERT(cfg.notify_allow == 1, "notify_allowlist = true");
    ASSERT(cfg.notify_deny == 0, "notify_denylist = 0");
    ASSERT(cfg.notify_dedup_seconds == 15, "notify_dedup_ttl = 15");
    ASSERT(cfg.notify_max == 5, "notify_max = 5");
    config_reset(&cfg);
    unlink(path);
    free(path);

    /* Invalid values and out-of-range numbers keep the defaults. */
    path = write_temp("[settings]\n"
                      "notify_unsafe_allowlist = maybe\n"
                      "notify_denylist = nope\n"
                      "notify_dedup_ttl = -5\n"
                      "notify_max = 0\n");
    ASSERT(path != NULL, "write temp config for invalid notifications");

    memset(&cfg, 0, sizeof(cfg));
    ASSERT(config_load(path, &cfg) == 0, "config_load invalid notifications");
    ASSERT(cfg.notify_unsafe_allow == 1, "invalid toggle keeps default on");
    ASSERT(cfg.notify_deny == 1, "invalid toggle keeps default on");
    ASSERT(cfg.notify_dedup_seconds == NOTIFY_DEDUP_DEFAULT_S,
           "invalid notify_dedup_ttl keeps the default");
    ASSERT(cfg.notify_max == NOTIFY_MAX_DEFAULT,
           "invalid notify_max keeps the default");
    config_reset(&cfg);
    unlink(path);
    free(path);

    /* 0 disables the suppression window (notify on every hit). */
    path = write_temp("[settings]\n"
                      "notify_dedup_ttl = 0\n");
    ASSERT(path != NULL, "write temp config for dedup zero");

    memset(&cfg, 0, sizeof(cfg));
    ASSERT(config_load(path, &cfg) == 0, "config_load dedup zero");
    ASSERT(cfg.notify_dedup_seconds == 0, "notify_dedup_ttl = 0 accepted");
    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * Limit overflow is blocking: too many protected paths or too many rules
 * in a section must refuse the whole config (startup fails; a reload
 * keeps the previous config) instead of silently dropping entries.
 */
static void test_limits_are_blocking(void)
{
    Config cfg;
    const size_t path_cap = 64 * 1024;
    char *buf = malloc(path_cap);
    ASSERT(buf != NULL, "allocate protected-path overflow config");
    if (buf)
    {
        size_t off = (size_t)snprintf(buf, path_cap, "[protected_paths]\n");
        for (int i = 0; i < MAX_PATHS + 1 && off < path_cap; i++)
            off += (size_t)snprintf(buf + off, path_cap - off,
                                    "/tmp/fslimit_%d\n", i);

        char *path = write_temp(buf);
        free(buf);
        ASSERT(path != NULL, "write protected-path overflow config");
        memset(&cfg, 0, sizeof(cfg));
        ASSERT(config_load(path, &cfg) == -1,
               "too many protected paths refuses the config");
        ASSERT(cfg.protected_count <= MAX_PATHS,
               "refused config exposes no overflow");
        config_reset(&cfg);
        unlink(path);
        free(path);
    }

    /* Every rule section enforces MAX_RULES, not just [allowlist]. */
    const char *rule_sections[] = {"allowlist", "unsafe_allowlist",
                                   "denylist"};
    const size_t rule_cap = 32 * 1024;
    for (size_t s = 0;
         s < sizeof(rule_sections) / sizeof(rule_sections[0]); s++)
    {
        buf = malloc(rule_cap);
        ASSERT(buf != NULL, "allocate rule overflow config");
        if (!buf)
            continue;

        size_t off = (size_t)snprintf(buf, rule_cap, "[%s]\n",
                                      rule_sections[s]);
        for (int i = 0; i < MAX_RULES + 1 && off < rule_cap; i++)
            off += (size_t)snprintf(buf + off, rule_cap - off,
                                    "/usr/bin/fslimit_%d = /tmp/fslimit_t_%d\n",
                                    i, i);

        char *path = write_temp(buf);
        free(buf);
        ASSERT(path != NULL, "write rule overflow config");
        memset(&cfg, 0, sizeof(cfg));
        ASSERT(config_load(path, &cfg) == -1,
               "too many rules refuses the config");
        config_reset(&cfg);
        unlink(path);
        free(path);
    }

    /* A config exactly at the protected-path cap still loads. */
    buf = malloc(path_cap);
    ASSERT(buf != NULL, "allocate at-cap config");
    if (buf)
    {
        size_t off = (size_t)snprintf(buf, path_cap, "[protected_paths]\n");
        for (int i = 0; i < MAX_PATHS && off < path_cap; i++)
            off += (size_t)snprintf(buf + off, path_cap - off,
                                    "/tmp/fslimit_%d\n", i);

        char *path = write_temp(buf);
        free(buf);
        ASSERT(path != NULL, "write at-cap config");
        memset(&cfg, 0, sizeof(cfg));
        ASSERT(config_load(path, &cfg) == 0, "exactly MAX_PATHS loads");
        ASSERT(cfg.protected_count == MAX_PATHS,
               "at-cap config keeps every entry");
        config_reset(&cfg);
        unlink(path);
        free(path);
    }
}

/*
 * Absurd TTL values must be clamped (to one year) so cache expiry
 * arithmetic cannot overflow on any time_t width.
 */
static void test_ttl_clamping(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/tmp/ttl_clamp_test\n"
        "[settings]\n"
        "user_ttl = 2000000000\n"
        "session_ttl = 2000000000\n"
        "[allowlist]\n"
        "/usr/bin/huge = /tmp/ttl_clamp_test\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for ttl clamp");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load ttl clamp success");
    ASSERT(cfg.allowlist_count == 1, "allowlist parsed for ttl clamp");
    ASSERT(strcmp(cfg.allowlist[0].target_path, "/tmp/ttl_clamp_test") == 0,
           "allowlist target parsed");
    ASSERT(cfg.user_ttl_seconds == 31536000, "user_ttl clamped to one year");
    ASSERT(cfg.session_ttl_seconds == 31536000, "session_ttl clamped to one year");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

static void test_whitespace_lines(void)
{
    const char *conf =
        "   \n"
        "\t\n"
        "[protected_paths]\n"
        "/etc/ssh/ssh_config\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config with whitespace lines");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load with whitespace lines succeeds");
    ASSERT(cfg.protected_count == 1, "whitespace lines ignored");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * Paths must be canonicalized at load time so symlinked protected
 * directories cannot bypass path matching in the daemon.
 */
static void test_path_canonicalization(void)
{
    char real_dir[128];
    char link_dir[128];
    char conf[2048];
    char target[512];

    snprintf(real_dir, sizeof(real_dir), "/tmp/fileshield_canon_real_%d", (int)getpid());
    snprintf(link_dir, sizeof(link_dir), "/tmp/fileshield_canon_link_%d", (int)getpid());

    ASSERT(mkdir(real_dir, 0700) == 0, "create real dir");
    unlink(link_dir);
    ASSERT(symlink(real_dir, link_dir) == 0, "create symlink");

    snprintf(target, sizeof(target), "%s/secret", link_dir);
    snprintf(conf, sizeof(conf),
             "[protected_paths]\n"
             "%s\n"
             "[allowlist]\n"
             "%s/bin = %s\n",
             target, link_dir, target);

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write symlink config");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load with symlink succeeds");
    ASSERT(cfg.protected_count == 1, "symlink config protected count");
    ASSERT(strncmp(cfg.protected[0].path, real_dir, strlen(real_dir)) == 0,
           "protected path canonicalized through symlink");
    ASSERT(strstr(cfg.protected[0].path, "secret") != NULL,
           "canonicalized protected basename preserved");
    ASSERT(cfg.allowlist_count == 1, "symlink config allowlist count");
    ASSERT(strncmp(cfg.allowlist[0].binary, real_dir, strlen(real_dir)) == 0,
           "allowlist path canonicalized through symlink");
    ASSERT(strncmp(cfg.allowlist[0].target_path, real_dir, strlen(real_dir)) == 0,
           "allowlist target canonicalized through symlink");

    config_reset(&cfg);
    unlink(path);
    free(path);
    unlink(link_dir);
    rmdir(real_dir);
}

/*
 * H2 regression: an entry with TWO missing levels under a symlinked
 * parent is the fresh-install case (~/.aws/credentials before ~/.aws
 * exists).  The old one-level realpath fallback stored the raw string
 * when its parent was missing too — under a symlinked home that never
 * matches the canonical /proc/<pid>/fd target paths, silently leaving
 * the file unprotected with no prompt and no log.  canonicalize_path
 * must walk up to the deepest existing ancestor and re-attach the
 * stripped tail, so the stored pattern keeps the canonical (real)
 * prefix for both exact entries and glob static bases.
 */
static void test_canonicalization_missing_levels_under_symlink(void)
{
    char real_dir[128];
    char link_dir[128];
    char conf[4096];

    snprintf(real_dir, sizeof(real_dir), "/tmp/fileshield_canon2_real_%d",
             (int)getpid());
    snprintf(link_dir, sizeof(link_dir), "/tmp/fileshield_canon2_link_%d",
             (int)getpid());

    ASSERT(mkdir(real_dir, 0700) == 0, "create real dir");
    unlink(link_dir);
    ASSERT(symlink(real_dir, link_dir) == 0, "create symlink");

    snprintf(conf, sizeof(conf),
             "[protected_paths]\n"
             "%s/.aws/credentials\n"
             "%s/.mozilla/**/*.ini\n", link_dir, link_dir);

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write two-missing-level config");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load succeeds");
    ASSERT(cfg.protected_count == 2, "both entries loaded");

    /* Exact entry: canonical real prefix survives the missing parent. */
    ASSERT(strncmp(cfg.protected[0].path, real_dir, strlen(real_dir)) == 0,
           "exact entry canonicalized through symlinked missing parent");
    ASSERT(strncmp(cfg.protected[0].path, link_dir, strlen(link_dir)) != 0,
           "raw symlinked prefix must not survive");
    ASSERT(strstr(cfg.protected[0].path, "/.aws/credentials") != NULL,
           "both stripped levels re-attached");
    ASSERT(cfg.protected[0].is_glob == 0 &&
               cfg.protected[0].base_len ==
                   (int)strlen(cfg.protected[0].path),
           "exact entry keeps a full-length base");

    /* Glob entry: the static base canonicalizes the same way. */
    ASSERT(strncmp(cfg.protected[1].path, real_dir, strlen(real_dir)) == 0,
           "glob base canonicalized through symlinked missing parent");
    const char *suf = strstr(cfg.protected[1].path, "/.mozilla/**/*.ini");
    ASSERT(suf != NULL, "glob suffix preserved verbatim after canonical base");
    ASSERT(cfg.protected[1].is_glob == 1 &&
               cfg.protected[1].base_len ==
                   (suf ? (int)(suf - cfg.protected[1].path) +
                              (int)strlen("/.mozilla")
                        : -1),
           "glob base_len covers the canonical base incl. the missing dir");

    config_reset(&cfg);
    unlink(path);
    free(path);
    unlink(link_dir);
    rmdir(real_dir);
}

/*
 * Legacy-format safety: "binary = ttl_seconds" entries must be rejected
 * with a warning, and an '=' with an empty right side is a parse error.
 * Neither may produce a rule.
 */
static void test_rule_rejection(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/tmp/rej\n"
        "[allowlist]\n"
        "/usr/bin/old = 3600\n"
        "/usr/bin/empty =\n"
        "/usr/bin/ok = /tmp/rej\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for rule rejection");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load succeeds with skipped lines");
    ASSERT(cfg.allowlist_count == 1, "only the valid rule survives");
    ASSERT(strcmp(cfg.allowlist[0].binary, "/usr/bin/ok") == 0,
           "surviving rule is the scoped one");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * [denylist] parses the same format as [allowlist]: scoped rules and
 * bare global rules, with multiple targets for the same binary.
 */
static void test_denylist_parse(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/tmp/deny\n"
        "[denylist]\n"
        "/usr/bin/curl = /tmp/deny\n"
        "/usr/bin/curl = /tmp/other\n"
        "/usr/bin/nc\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for denylist");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load denylist success");
    ASSERT(cfg.denylist_count == 3, "3 denylist entries");
    ASSERT(strcmp(cfg.denylist[0].binary, "/usr/bin/curl") == 0,
           "denylist curl binary");
    ASSERT(strcmp(cfg.denylist[0].target_path, "/tmp/deny") == 0,
           "denylist first target");
    ASSERT(strcmp(cfg.denylist[1].target_path, "/tmp/other") == 0,
           "denylist second target for the same binary");
    ASSERT(strcmp(cfg.denylist[2].binary, "/usr/bin/nc") == 0,
           "denylist global binary");
    ASSERT(cfg.denylist[2].target_path[0] == '\0', "bare deny entry is global");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * Trailing slashes on a target are stripped at parse time so matching
 * is uniformly "equal or under".
 */
static void test_target_trailing_slash(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/tmp/slash_test/\n"
        "[allowlist]\n"
        "/usr/bin/tool = /tmp/slash_test/\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for trailing slash");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load trailing slash success");
    ASSERT(cfg.allowlist_count == 1, "trailing slash entry parsed");
    ASSERT(strcmp(cfg.allowlist[0].target_path, "/tmp/slash_test") == 0,
           "trailing slash stripped from target");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * 'Binary = target' where the target does not exist yet keeps its
 * basename (canonicalize_path resolves the parent).
 */
static void test_scoped_missing_target(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/tmp/rule_missing/secret\n"
        "[allowlist]\n"
        "/usr/bin/app = /tmp/rule_missing/secret\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for missing target");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load missing target success");
    ASSERT(cfg.allowlist_count == 1, "missing-target rule parsed");
    ASSERT(strcmp(cfg.allowlist[0].target_path, "/tmp/rule_missing/secret") == 0,
           "missing target keeps parent resolution");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * config_load() must not publish the parsed Config through g_config: the
 * caller decides whether the config is accepted.  main.c frees a config
 * whose reload was rejected, so publishing inside config_load() would
 * leave g_config dangling (use-after-free on the next event).
 */
static void test_config_load_does_not_publish_global(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/tmp/config_publish_test\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for publish test");

    /* static: Config is several MB (fixed PATH_MAX arrays); a second
     * stack copy alongside `cfg` overflows the default 8 MB stack. */
    static Config sentinel;
    Config *saved = g_config;
    g_config = &sentinel;

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load publish test success");
    ASSERT(g_config == &sentinel,
           "config_load must not publish the parsed config through g_config");

    g_config = saved;
    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * Glob entries: the wildcard-free base is canonicalized, the suffix is
 * preserved verbatim, and is_glob/base_len are recorded.  Exact entries
 * keep is_glob == 0 and a base_len equal to the whole path.
 */
static void test_glob_protected_paths(void)
{
    char base[128];
    char conf[1024];
    char pat_star[256];
    char pat_globstar[256];
    char pat_plain[256];

    snprintf(base, sizeof(base), "/tmp/fileshield_globtest_%d", (int)getpid());
    snprintf(pat_star, sizeof(pat_star), "%s/*.json", base);
    snprintf(pat_globstar, sizeof(pat_globstar), "%s/**/*.json", base);
    snprintf(pat_plain, sizeof(pat_plain), "%s/plain", base);
    snprintf(conf, sizeof(conf),
             "[protected_paths]\n"
             "%s\n"
             "%s\n"
             "%s\n",
             pat_star, pat_globstar, pat_plain);

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for glob paths");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load glob success");
    ASSERT(cfg.protected_count == 3, "3 protected entries parsed");

    ASSERT(cfg.protected[0].is_glob == 1, "star entry is a glob");
    ASSERT(strcmp(cfg.protected[0].path, pat_star) == 0,
           "glob pattern preserved after base canonicalization");
    ASSERT(cfg.protected[0].base_len == (int)strlen(base),
           "glob base length is the wildcard-free prefix");

    ASSERT(cfg.protected[1].is_glob == 1, "globstar entry is a glob");
    ASSERT(strcmp(cfg.protected[1].path, pat_globstar) == 0,
           "globstar pattern preserved");
    ASSERT(cfg.protected[1].base_len == (int)strlen(base),
           "globstar base length");

    ASSERT(cfg.protected[2].is_glob == 0, "exact entry stays exact");
    ASSERT(cfg.protected[2].base_len == (int)strlen(cfg.protected[2].path),
           "exact entry base_len is the full path");

    config_reset(&cfg);
    ASSERT(cfg.protected[0].is_glob == 0, "config_reset clears glob flag");

    unlink(path);
    free(path);
}

/*
 * Root-based globs: a wildcard in the first segment gives a static base
 * of "/" (the documented whole-subtree rule target).  Installing such a
 * pattern would mark the root filesystem (the 2026-09-16 freeze class),
 * so config_load() must refuse the WHOLE configuration with a log - not
 * silently skip the entry.  A normal glob still loads with its stored
 * pattern and wildcard-free base intact.
 */
static void test_glob_root_based(void)
{
    char conf[2048];
    char pat_ok_star[320];
    char pat_ok_globstar[320];
    char base[256];
    static const char *const refused[] = {
        "[protected_paths]\n/**\n",
        "[protected_paths]\n/**/secret\n",
        "[protected_paths]\n/*.conf\n",
        "[protected_paths]\n/*\n",
        /* A wildcard anywhere in the first segment makes the static base
         * "/" too, even when the segment has more text than the star. */
        "[protected_paths]\n/tmp_fileshield_globfirst*/x\n",
        "[protected_paths]\n/tmp/fileshield_rootglob_ok\n"
        "[denylist]\n/usr/bin/curl = /**\n",
    };
    size_t i;
    Config cfg; /* one copy: Config is several MB */

    for (i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
    {
        char msg[96];
        char *path;

        snprintf(conf, sizeof(conf), "%s", refused[i]);
        path = write_temp(conf);
        ASSERT(path != NULL, "write temp config for a root-based glob");
        if (!path)
            continue;

        memset(&cfg, 0, sizeof(cfg));
        snprintf(msg, sizeof(msg), "root-based glob case %zu refuses the config",
                 i);
        ASSERT(config_load(path, &cfg) == -1, msg);
        config_reset(&cfg);
        unlink(path);
        free(path);
    }

    /*
     * Control: a wildcard in a later segment keeps a non-"/" static base
     * (the base is everything before that segment), so the config loads
     * with its pattern and base recorded.
     */
    snprintf(base, sizeof(base), "/tmp/fileshield_glob_ok_%d", (int)getpid());
    snprintf(pat_ok_star, sizeof(pat_ok_star), "%s/*.json", base);
    snprintf(pat_ok_globstar, sizeof(pat_ok_globstar), "%s/**/x.json", base);
    snprintf(conf, sizeof(conf),
             "[protected_paths]\n%s\n%s\n"
             "[denylist]\n/usr/bin/curl = %s/**\n",
             pat_ok_star, pat_ok_globstar, base);
    {
        char *path = write_temp(conf);
        ASSERT(path != NULL, "write temp config for non-root globs");
        if (path)
        {
            memset(&cfg, 0, sizeof(cfg));
            ASSERT(config_load(path, &cfg) == 0,
                   "non-root-based glob config loads");
            ASSERT(cfg.protected_count == 2, "both normal globs parsed");
            ASSERT(cfg.protected[0].is_glob == 1,
                   "normal star glob stays a glob");
            ASSERT(strcmp(cfg.protected[0].path, pat_ok_star) == 0,
                   "normal star glob pattern preserved");
            ASSERT(cfg.protected[0].base_len == (int)strlen(base),
                   "normal star glob base length");
            ASSERT(cfg.protected[1].is_glob == 1,
                   "normal globstar stays a glob");
            ASSERT(strcmp(cfg.protected[1].path, pat_ok_globstar) == 0,
                   "normal globstar pattern preserved");
            ASSERT(cfg.protected[1].base_len == (int)strlen(base),
                   "normal globstar base length");
            ASSERT(cfg.denylist_count == 1 && cfg.denylist[0].target_is_glob == 1,
                   "normal rule glob target parsed");
            ASSERT(cfg.denylist[0].target_base_len == (int)strlen(base),
                   "normal rule glob target base length");
            config_reset(&cfg);
            unlink(path);
            free(path);
        }
    }
}

/*
 * Malformed glob patterns are rejected with a warning and must not
 * produce an entry (fail closed: a typo never silently protects
 * nothing while looking active).
 */
static void test_glob_rejection(void)
{
    char conf[1024];
    snprintf(conf, sizeof(conf),
             "[protected_paths]\n"
             "/tmp/fileshield_ok_%d\n"      /* survives */
             "relative/*.json\n"            /* not absolute */
             "*.json\n"                     /* no static base */
             "/tmp/glob_rej_%d/*//x.json\n" /* empty segment in suffix */
             "/tmp/glob_rej_%d/*.json/\n"   /* trailing slash */
             "/tmp/glob_rej_%d/../*.json\n" /* unresolvable '..' base */
             "/tmp/glob_rej_%d/**/a/**/x.json\n", /* two '**' segments */
             (int)getpid(), (int)getpid(), (int)getpid(), (int)getpid(),
             (int)getpid());

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for glob rejection");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load survives rejected glob lines");
    ASSERT(cfg.protected_count == 1,
           "only the valid exact entry survives malformed globs");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * '!' exclusions: parsed into the same protected array with
 * is_exclude set, counted separately, and canonicalized exactly like
 * positives.
 */
static void test_exclusions_parse(void)
{
    char base[128];
    char pat_pub[256];
    char pat_exact[256];
    char conf[1024];

    snprintf(base, sizeof(base), "/tmp/fileshield_excl_%d", (int)getpid());
    snprintf(pat_pub, sizeof(pat_pub), "%s/*.pub", base);
    snprintf(pat_exact, sizeof(pat_exact), "%s/known_hosts", base);
    snprintf(conf, sizeof(conf),
             "[protected_paths]\n"
             "%s\n"
             "!%s\n"
             "!%s\n",
             base, pat_pub, pat_exact);

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for exclusions");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load exclusions success");
    ASSERT(cfg.protected_count == 3, "positive + 2 exclusions parsed");
    ASSERT(cfg.exclude_count == 2, "exclude_count counts only '!' entries");

    ASSERT(cfg.protected[0].is_exclude == 0, "positive entry is not an exclusion");
    ASSERT(strcmp(cfg.protected[0].path, base) == 0, "positive path preserved");

    ASSERT(cfg.protected[1].is_exclude == 1, "glob exclusion flagged");
    ASSERT(cfg.protected[1].is_glob == 1, "glob exclusion keeps is_glob");
    ASSERT(strcmp(cfg.protected[1].path, pat_pub) == 0,
           "exclusion pattern canonicalized");
    ASSERT(cfg.protected[1].base_len == (int)strlen(base),
           "exclusion base length computed");
    ASSERT(cfg.exclude_idx[0] == 1, "first exclusion index recorded");

    ASSERT(cfg.protected[2].is_exclude == 1, "exact exclusion flagged");
    ASSERT(cfg.protected[2].is_glob == 0, "exact exclusion is not a glob");
    ASSERT(strcmp(cfg.protected[2].path, pat_exact) == 0,
           "exact exclusion path preserved");
    ASSERT(cfg.exclude_idx[1] == 2, "second exclusion index recorded");

    config_reset(&cfg);
    ASSERT(cfg.exclude_count == 0, "config_reset clears exclude_count");

    unlink(path);
    free(path);
}

/*
 * Malformed exclusions are rejected with a warning and must not
 * produce an entry (fail closed); a valid positive in the same file
 * still loads.
 */
static void test_exclusion_rejection(void)
{
    char conf[1024];
    snprintf(conf, sizeof(conf),
             "[protected_paths]\n"
             "/tmp/fileshield_exok_%d\n"
             "!\n"                          /* empty exclusion */
             "!relative/*.pub\n"            /* not absolute */
             "!!/tmp/fileshield_exok_%d\n"  /* path starts with '!' */
             "!/tmp/fileshield_exok_%d/**/\n", /* trailing slash in suffix */
             (int)getpid(), (int)getpid(), (int)getpid());

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for exclusion rejection");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load survives rejected exclusions");
    ASSERT(cfg.protected_count == 1, "only the valid positive survives");
    ASSERT(cfg.exclude_count == 0, "no malformed exclusion recorded");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * A relative exact protected entry can never match a canonical
 * /proc/self/fd target, so it is rejected with a log instead of being
 * stored as a silently-unprotecting entry.
 */
static void test_relative_protected_rejected(void)
{
    const char *conf = "[protected_paths]\n"
                       "home/.ssh\n"
                       "/tmp/fileshield_rel_ok\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load survives the rejected relative entry");
    ASSERT(cfg.protected_count == 1, "only the absolute entry survives");
    ASSERT(strcmp(cfg.protected[0].path, "/tmp/fileshield_rel_ok") == 0,
           "the surviving entry is the valid positive");
    ASSERT(cfg.protected[0].is_exclude == 0, "the surviving entry is positive");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * Line handling and hard caps: CRLF endings parse cleanly (the trim
 * strips '\r'), an over-long line in a RULE section refuses the whole
 * config (never silently skipped — see test_overlong_line_refusal for
 * the [settings]/comment cases that still skip), and the MAX_RULES cap
 * is exact -- loading at the cap, refusing at one over (never silently
 * truncating).
 */
static void test_crlf_longline_and_rule_cap(void)
{
    Config cfg;

    /* A [settings] line missing '=' is ignored (loudly, via the log):
     * the typo must not look like it took effect. */
    {
        const char *conf =
            "[protected_paths]\n"
            "/tmp/fileshield_settings_typo\n"
            "[settings]\n"
            "user_ttl 900\n";
        char *path = write_temp(conf);
        ASSERT(path != NULL, "write settings-typo config");
        memset(&cfg, 0, sizeof(cfg));
        ASSERT(config_load(path, &cfg) == 0,
               "settings typo does not fail the config");
        ASSERT(cfg.user_ttl_seconds == 0,
               "settings line without '=' is ignored, not half-applied");
        config_reset(&cfg);
        unlink(path);
        free(path);
    }

    /* CRLF line endings. */
    {
        const char *crlf =
            "[protected_paths]\r\n"
            "/tmp/fileshield_crlf_ok\r\n"
            "[settings]\r\n"
            "user_ttl = 60\r\n";
        char *path = write_temp(crlf);
        ASSERT(path != NULL, "write CRLF config");
        memset(&cfg, 0, sizeof(cfg));
        ASSERT(config_load(path, &cfg) == 0, "CRLF config loads");
        ASSERT(cfg.protected_count == 1, "CRLF protected entry parsed");
        ASSERT(strcmp(cfg.protected[0].path, "/tmp/fileshield_crlf_ok") == 0,
               "CRLF stripped from the entry");
        ASSERT(cfg.user_ttl_seconds == 60, "CRLF settings value parsed");
        config_reset(&cfg);
        unlink(path);
        free(path);
    }

    /* A line longer than the parser buffer (PATH_MAX * 2) in a rule
     * section refuses the whole config: skipping it would silently
     * drop the rule. */
    {
        char *conf = malloc(PATH_MAX * 2 + 512);
        ASSERT(conf != NULL, "alloc long-line config");
        if (!conf)
            return;
        char *p = conf;
        p += sprintf(p, "[protected_paths]\n");
        p += sprintf(p, "/tmp/");
        memset(p, 'a', PATH_MAX * 2);
        p += PATH_MAX * 2;
        *p++ = '\n';
        p += sprintf(p, "/tmp/fileshield_long_ok\n");
        *p = '\0';

        char *path = write_temp(conf);
        ASSERT(path != NULL, "write long-line config");
        memset(&cfg, 0, sizeof(cfg));
        ASSERT(config_load(path, &cfg) == -1,
               "over-long line in a rule section refuses the config");
        config_reset(&cfg);
        unlink(path);
        free(path);
        free(conf);
    }

    /* MAX_RULES is exact: at the cap loads, one over refuses. */
    {
        char conf[8192];
        char *p = conf;
        p += sprintf(p, "[allowlist]\n");
        for (int i = 0; i < MAX_RULES; i++)
            p += sprintf(p, "/usr/bin/cap%03d\n", i);
        *p = '\0';

        char *path = write_temp(conf);
        ASSERT(path != NULL, "write at-cap config");
        memset(&cfg, 0, sizeof(cfg));
        ASSERT(config_load(path, &cfg) == 0, "MAX_RULES rules load");
        ASSERT(cfg.allowlist_count == MAX_RULES,
               "rule count at the cap is exact");
        config_reset(&cfg);
        unlink(path);
        free(path);

        p = conf;
        p += sprintf(p, "[allowlist]\n");
        for (int i = 0; i <= MAX_RULES; i++)
            p += sprintf(p, "/usr/bin/cap%03d\n", i);
        *p = '\0';

        path = write_temp(conf);
        ASSERT(path != NULL, "write over-cap config");
        memset(&cfg, 0, sizeof(cfg));
        ASSERT(config_load(path, &cfg) == -1,
               "one rule past MAX_RULES refuses the config");
        config_reset(&cfg);
        unlink(path);
        free(path);
    }
}

/*
 * M4 regression: an over-long line that no longer fits the PATH_MAX*2
 * parse buffer must refuse the WHOLE config inside a rule section
 * ([protected_paths]/[allowlist]/[unsafe_allowlist]/[denylist]) —
 * skipping it would silently drop the rule, breaking docs/
 * configuration.md's "a typo cannot silently drop rules" promise
 * (fails before the fix).  [settings] lines, comments/blank lines and
 * preamble garbage drop no rules, so they keep the historical
 * skip-with-log behavior.
 */
static void test_overlong_line_refusal(void)
{
    static Config cfg; /* PATH_MAX-wide tables: keep them off the stack */
    /* Largest body: PATH_MAX*2 filler plus a header/entry around it. */
    char *conf = malloc(PATH_MAX * 2 + 512);
    ASSERT(conf != NULL, "alloc over-long line config");
    if (!conf)
        return;

    /* [denylist] non-comment rule: refuse the whole config. */
    {
        char *p = conf;
        p += sprintf(p, "[denylist]\n/usr/bin/");
        memset(p, 'd', PATH_MAX * 2);
        p += PATH_MAX * 2;
        *p++ = '\n';
        *p = '\0';

        char *path = write_temp(conf);
        ASSERT(path != NULL, "write over-long denylist config");
        memset(&cfg, 0, sizeof(cfg));
        ASSERT(config_load(path, &cfg) == -1,
               "over-long denylist rule refuses the config");
        config_reset(&cfg);
        unlink(path);
        free(path);
    }

    /* [settings]: over-long value keeps the historical skip; the rest
     * of the section still loads. */
    {
        char *p = conf;
        p += sprintf(p, "[settings]\nnotify_max ");
        memset(p, 'x', PATH_MAX * 2);
        p += PATH_MAX * 2;
        *p++ = '\n';
        p += sprintf(p, "user_ttl = 42\n");
        *p = '\0';

        char *path = write_temp(conf);
        ASSERT(path != NULL, "write over-long settings config");
        memset(&cfg, 0, sizeof(cfg));
        ASSERT(config_load(path, &cfg) == 0,
               "over-long settings line still loads");
        ASSERT(cfg.user_ttl_seconds == 42,
               "setting after the over-long settings line applies");
        config_reset(&cfg);
        unlink(path);
        free(path);
    }

    /* An over-long COMMENT inside a rule section never refuses: only
     * the available prefix is examined for the '#' decision. */
    {
        char *p = conf;
        p += sprintf(p, "[protected_paths]\n/tmp/fileshield_olc_ok\n#");
        memset(p, 'c', PATH_MAX * 2);
        p += PATH_MAX * 2;
        *p++ = '\n';
        *p = '\0';

        char *path = write_temp(conf);
        ASSERT(path != NULL, "write over-long comment config");
        memset(&cfg, 0, sizeof(cfg));
        ASSERT(config_load(path, &cfg) == 0,
               "over-long comment in a rule section does not refuse");
        ASSERT(cfg.protected_count == 1,
               "entry before the over-long comment survives");
        config_reset(&cfg);
        unlink(path);
        free(path);
    }

    /* Preamble garbage before any header: skip, matching the
     * entry-outside-any-section handling. */
    {
        char *p = conf;
        memset(p, 'g', PATH_MAX * 2);
        p += PATH_MAX * 2;
        *p++ = '\n';
        p += sprintf(p, "[protected_paths]\n/tmp/fileshield_olp_ok\n");
        *p = '\0';

        char *path = write_temp(conf);
        ASSERT(path != NULL, "write over-long preamble config");
        memset(&cfg, 0, sizeof(cfg));
        ASSERT(config_load(path, &cfg) == 0,
               "over-long preamble garbage still loads");
        ASSERT(cfg.protected_count == 1,
               "header after the over-long preamble line is honored");
        config_reset(&cfg);
        unlink(path);
        free(path);
    }

    free(conf);
}

/*
 * M4 regression: '#' is a comment only at line start.  Mid-line it is a
 * legal path byte — accepting "pattern  # note" verbatim silently
 * un-protected the files the entry appeared to guard (and the README
 * once demonstrated that exact style).  Fail the whole config loudly
 * instead; comments move to their own line.  Trailing junk after a
 * section header is rejected for the same reason.
 */
static void test_inline_hash_rejected(void)
{
    struct { const char *conf; const char *what; } reject_cases[] = {
        { "[protected_paths]\n" "/tmp/a # files inside /tmp/a\n",
          "protected entry with trailing comment" },
        { "[protected_paths]\n" "/tmp/a\n"
          "[allowlist]\n" "/usr/bin/x = /tmp/y # scoped\n",
          "allowlist rule with trailing comment" },
        { "[protected_paths]\n" "/tmp/sharp#tag\n",
          "literal '#' in a path (no silent acceptance)" },
        { "[settings] tuning\n" "user_ttl = 300\n",
          "trailing junk after section header" },
    };

    for (size_t i = 0; i < sizeof(reject_cases) / sizeof(reject_cases[0]); i++) {
        char *path = write_temp(reject_cases[i].conf);
        ASSERT(path != NULL, "write temp config");
        static Config cfg; /* PATH_MAX-wide tables: keep them off the stack */
        memset(&cfg, 0, sizeof(cfg));
        int r = config_load(path, &cfg);
        ASSERT(r == -1, reject_cases[i].what);
        config_reset(&cfg);
        unlink(path);
        free(path);
    }

    /* Control: whole-line comments (also indented) remain fine. */
    const char *ok = "[protected_paths]\n"
                     "# leading comment\n"
                     "   # indented comment\n"
                     "/tmp/fileshield_hash_ok\n";
    char *path = write_temp(ok);
    ASSERT(path != NULL, "write comment control config");
    static Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT(config_load(path, &cfg) == 0, "whole-line comments still load");
    ASSERT(cfg.protected_count == 1, "control entry parsed");
    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * Exact rules keep the historical semantics and record is_glob = 0 with
 * base_len == strlen(path); a bare global rule has an empty target with
 * zeroed target metadata.
 */
static void test_rule_exact_metadata(void)
{
    const char *conf =
        "[allowlist]\n"
        "/usr/bin/ssh = /etc/ssl/certs\n"
        "/usr/bin/git\n"
        "[denylist]\n"
        "/usr/bin/curl = /tmp/curl_target\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for exact rule metadata");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load exact rule metadata success");
    ASSERT(cfg.allowlist_count == 2, "exact allowlist rules parsed");

    ASSERT(cfg.allowlist[0].binary_is_glob == 0, "exact binary is not a glob");
    ASSERT(cfg.allowlist[0].binary_base_len ==
               (int)strlen(cfg.allowlist[0].binary),
           "exact binary base_len is the full path");
    ASSERT(cfg.allowlist[0].target_is_glob == 0, "exact target is not a glob");
    ASSERT(cfg.allowlist[0].target_base_len ==
               (int)strlen(cfg.allowlist[0].target_path),
           "exact target base_len is the full path");

    ASSERT(cfg.allowlist[1].target_path[0] == '\0', "bare rule stays global");
    ASSERT(cfg.allowlist[1].target_is_glob == 0, "global rule target is not a glob");
    ASSERT(cfg.allowlist[1].target_base_len == 0, "global rule target base_len 0");

    ASSERT(cfg.denylist_count == 1, "exact denylist rule parsed");
    ASSERT(cfg.denylist[0].binary_is_glob == 0, "denylist binary is not a glob");
    ASSERT(cfg.denylist[0].binary_base_len ==
               (int)strlen(cfg.denylist[0].binary),
           "denylist binary base_len is the full path");
    ASSERT(cfg.denylist[0].target_is_glob == 0, "denylist target is not a glob");
    ASSERT(cfg.denylist[0].target_base_len ==
               (int)strlen(cfg.denylist[0].target_path),
           "denylist target base_len is the full path");

    config_reset(&cfg);
    ASSERT(cfg.allowlist[0].binary_is_glob == 0, "config_reset clears rule glob flag");
    unlink(path);
    free(path);
}

/*
 * Rule globs: either side of an [allowlist]/[unsafe_allowlist]/[denylist]
 * line accepts the same '*'/'**' engine as [protected_paths].  The
 * wildcard-free base is canonicalized, the suffix stays verbatim, and
 * per-side metadata is recorded for the fanotify matcher.
 */
static void test_rule_glob_binary(void)
{
    const char *conf =
        "[allowlist]\n"
        "/tmp/.mount_*/openchamber = /tmp/rule_glob_bin\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for glob binary rule");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load glob binary rule success");
    ASSERT(cfg.allowlist_count == 1, "glob binary rule parsed");
    ASSERT(cfg.allowlist[0].binary_is_glob == 1, "binary side flagged as glob");
    ASSERT(strcmp(cfg.allowlist[0].binary, "/tmp/.mount_*/openchamber") == 0,
           "glob binary pattern preserved verbatim");
    ASSERT(cfg.allowlist[0].binary_base_len == (int)strlen("/tmp"),
           "binary glob base is the wildcard-free prefix");
    ASSERT(cfg.allowlist[0].target_is_glob == 0, "target side stays exact");
    ASSERT(strcmp(cfg.allowlist[0].target_path, "/tmp/rule_glob_bin") == 0,
           "exact target canonicalized");
    ASSERT(cfg.allowlist[0].target_base_len ==
               (int)strlen(cfg.allowlist[0].target_path),
           "exact target base_len is the full path");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

static void test_rule_glob_target(void)
{
    char base[128];
    char pat[256];
    char conf[1024];

    snprintf(base, sizeof(base), "/tmp/fileshield_rtarget_%d", (int)getpid());
    snprintf(pat, sizeof(pat), "%s/**/*.json", base);
    snprintf(conf, sizeof(conf),
             "[allowlist]\n"
             "/usr/bin/opencode = %s\n",
             pat);

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for glob target rule");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load glob target rule success");
    ASSERT(cfg.allowlist_count == 1, "glob target rule parsed");
    ASSERT(cfg.allowlist[0].binary_is_glob == 0, "binary side stays exact");
    ASSERT(strcmp(cfg.allowlist[0].binary, "/usr/bin/opencode") == 0,
           "exact binary canonicalized");
    ASSERT(cfg.allowlist[0].binary_base_len == (int)strlen("/usr/bin/opencode"),
           "exact binary base_len is the full path");
    ASSERT(cfg.allowlist[0].target_is_glob == 1, "target side flagged as glob");
    ASSERT(strcmp(cfg.allowlist[0].target_path, pat) == 0,
           "glob target pattern preserved verbatim");
    ASSERT(cfg.allowlist[0].target_base_len == (int)strlen(base),
           "target glob base is the wildcard-free prefix");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

static void test_rule_glob_both(void)
{
    char base[128];
    char bin_pat[256];
    char tgt_pat[256];
    char conf[1024];

    snprintf(base, sizeof(base), "/tmp/fileshield_rboth_%d", (int)getpid());
    snprintf(bin_pat, sizeof(bin_pat), "%s/*/app", base);
    snprintf(tgt_pat, sizeof(tgt_pat), "%s/**", base);
    snprintf(conf, sizeof(conf),
             "[allowlist]\n"
             "%s = %s\n",
             bin_pat, tgt_pat);

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for both-side glob rule");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load both-side glob rule success");
    ASSERT(cfg.allowlist_count == 1, "both-side glob rule parsed");
    ASSERT(cfg.allowlist[0].binary_is_glob == 1, "binary glob flagged");
    ASSERT(cfg.allowlist[0].target_is_glob == 1, "target glob flagged");
    ASSERT(strcmp(cfg.allowlist[0].binary, bin_pat) == 0,
           "binary glob pattern preserved");
    ASSERT(strcmp(cfg.allowlist[0].target_path, tgt_pat) == 0,
           "target glob pattern preserved");
    ASSERT(cfg.allowlist[0].binary_base_len == (int)strlen(base),
           "binary glob base length");
    ASSERT(cfg.allowlist[0].target_base_len == (int)strlen(base),
           "target glob base length");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * Malformed rule globs are rejected with a log and skipped (fail closed);
 * a valid line after a rejected one still loads.  Both sides are checked.
 */
static void test_rule_glob_rejection(void)
{
    char ok_bin[256];
    char conf[2048];

    snprintf(ok_bin, sizeof(ok_bin), "/tmp/fileshield_rglob_%d/*/bin", (int)getpid());
    snprintf(conf, sizeof(conf),
             "[allowlist]\n"
             "%s = /tmp/fileshield_rglob_target\n"                /* valid */
             "relative/*.json = /tmp/x\n"                         /* not absolute */
             "*.json = /tmp/x\n"                                  /* no static base */
             "/tmp/fileshield_rglob_%d/../*.json = /tmp/x\n"      /* '..' base */
             "/tmp/fileshield_rglob_%d/*//x = /tmp/x\n"           /* empty segment */
             "/tmp/fileshield_rglob_%d/*.json/ = /tmp/x\n"        /* trailing slash */
             "/usr/bin/exact = relative/*.json\n"                 /* target not absolute */
             "/usr/bin/exact2 = *.json\n"                         /* target no base */
             "/usr/bin/exact3 = /tmp/fileshield_rglob_%d/../*.json\n" /* target '..' */
             "/usr/bin/exact4 = /tmp/fileshield_rglob_%d/*//x\n"  /* target empty segment */
             "/tmp/fileshield_rglob_%d/**/a/**/bin = /tmp/x\n"    /* binary: two '**' */
             "/usr/bin/exact5 = /tmp/fileshield_rglob_%d/**/a/**/y\n" /* target: two '**' */
             "/usr/bin/survivor = /tmp/fileshield_rglob_target\n", /* valid */
             ok_bin,
             (int)getpid(), (int)getpid(), (int)getpid(),
             (int)getpid(), (int)getpid(), (int)getpid(),
             (int)getpid());

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for glob rule rejection");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load survives rejected glob rules");
    ASSERT(cfg.allowlist_count == 2, "only the two valid rules survive");
    ASSERT(strcmp(cfg.allowlist[0].binary, ok_bin) == 0,
           "valid glob binary before the rejects still loads");
    ASSERT(cfg.allowlist[0].binary_is_glob == 1, "surviving glob binary flagged");
    ASSERT(cfg.allowlist[0].binary_base_len ==
               (int)strlen(ok_bin) - (int)strlen("/*/bin"),
           "surviving glob binary base length");
    ASSERT(strcmp(cfg.allowlist[1].binary, "/usr/bin/survivor") == 0,
           "valid exact rule after the rejects still loads");
    ASSERT(cfg.allowlist[1].binary_is_glob == 0, "surviving exact binary not a glob");
    ASSERT(strcmp(cfg.allowlist[1].target_path, "/tmp/fileshield_rglob_target") == 0,
           "surviving exact target canonicalized");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * [denylist] gets the same glob handling through the shared add_rule()
 * path (it never pins hashes, but the parser is identical).
 */
static void test_denylist_glob_parse(void)
{
    const char *conf =
        "[denylist]\n"
        "/tmp/.mount_*/curl = /tmp/deny_glob_target\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for denylist glob");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load denylist glob success");
    ASSERT(cfg.denylist_count == 1, "denylist glob rule parsed");
    ASSERT(cfg.denylist[0].binary_is_glob == 1, "denylist binary glob flagged");
    ASSERT(cfg.denylist[0].binary_base_len == (int)strlen("/tmp"),
           "denylist binary glob base");
    ASSERT(cfg.denylist[0].target_is_glob == 0, "denylist target stays exact");
    ASSERT(strcmp(cfg.denylist[0].target_path, "/tmp/deny_glob_target") == 0,
           "denylist glob rule target canonicalized");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * The two reported user cases must parse: a glob binary scoped to a
 * home-directory target, and an exact binary scoped to a parent folder
 * (the trailing slash is stripped by canonicalization).
 *
 * A '~/' side expands once per real user (the same getpwent() filter
 * utils.c applies: uid in [1000, 65534) with a non-empty home), so the
 * expected entry count is derived here instead of hardcoded and each
 * rule is located by its binary rather than a fixed index - on a
 * multi-user host the expansions interleave.
 */
static void test_reported_user_cases(void)
{
    const char *conf =
        "[allowlist]\n"
        "/tmp/.mount_*/openchamber = ~/.local/share/opencode/\n"
        "/usr/bin/opencode = ~/.local/\n";

    int users = 0;
    const struct passwd *pw;
    setpwent();
    while ((pw = getpwent()) != NULL)
    {
        if (pw->pw_uid < 1000 || pw->pw_uid >= 65534)
            continue;
        if (!pw->pw_dir || pw->pw_dir[0] == '\0')
            continue;
        users++;
    }
    endpwent();

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for reported user cases");
    if (!path)
        return;

    if (users > 0 && users * 2 > MAX_RULES)
    {
        printf("SKIP: %d real users exceed the %d-rule cap for this test\n",
               users, MAX_RULES);
        unlink(path);
        free(path);
        return;
    }

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load reported user cases success");

    if (users == 0)
    {
        /* Nothing to expand '~' against: the side stays relative and is
         * rejected, so no rule is admitted (fail closed). */
        ASSERT(cfg.allowlist_count == 0,
               "no real users: '~' rules load as nothing");
    }
    else
    {
        ASSERT(cfg.allowlist_count == users * 2,
               "one entry per real user for each reported rule");

        int glob_rule = 0;
        int exact_rule = 0;
        for (int i = 0; i < cfg.allowlist_count; i++)
        {
            const RuleEntry *e = &cfg.allowlist[i];

            if (strcmp(e->binary, "/tmp/.mount_*/openchamber") == 0)
            {
                glob_rule++;
                ASSERT(e->binary_is_glob == 1,
                       "AppImage mount path is a glob");
                ASSERT(e->binary_base_len == (int)strlen("/tmp"),
                       "AppImage mount glob base");
                ASSERT(e->target_is_glob == 0,
                       "opencode data dir stays exact");
                ASSERT(strstr(e->target_path,
                              "/.local/share/opencode") != NULL,
                       "opencode data dir target canonicalized");
                size_t len = strlen(e->target_path);
                ASSERT(len > 0 && e->target_path[len - 1] != '/',
                       "trailing slash stripped from data dir target");
                ASSERT(e->target_base_len == (int)len,
                       "exact data dir target base_len");
            }
            else
            {
                ASSERT(strcmp(e->binary, "/usr/bin/opencode") == 0,
                       "only the two reported binaries are present");
                exact_rule++;
                ASSERT(e->binary_is_glob == 0,
                       "exact binary is not a glob");
                ASSERT(strstr(e->target_path, "/.local") != NULL,
                       "parent folder target canonicalized");
                size_t len = strlen(e->target_path);
                ASSERT(len > 0 && e->target_path[len - 1] != '/',
                       "trailing slash stripped from parent folder target");
            }
        }
        ASSERT(glob_rule == users,
               "the glob rule expanded once per real user");
        ASSERT(exact_rule == users,
               "the exact rule expanded once per real user");
    }

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * [unsafe_allowlist] parses exactly like [allowlist] into its own
 * section, applies the same glob validation, and leaves the safe
 * allowlist untouched.
 */
static void test_unsafe_allowlist_parse(void)
{
    const char *conf =
        "[unsafe_allowlist]\n"
        "*.json = /tmp/x\n" /* malformed: rejected like [allowlist] */
        "/usr/bin/opencode\n"
        "/tmp/.mount_*/app = /tmp/unsafe_target\n"
        "[allowlist]\n"
        "/usr/bin/ssh = /tmp/safe_target\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for unsafe allowlist");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load unsafe allowlist success");
    ASSERT(cfg.unsafe_allowlist_count == 2, "unsafe allowlist entries parsed");
    ASSERT(cfg.allowlist_count == 1, "safe allowlist unaffected by unsafe section");

    ASSERT(strcmp(cfg.unsafe_allowlist[0].binary, "/usr/bin/opencode") == 0,
           "unsafe rule binary parsed");
    ASSERT(cfg.unsafe_allowlist[0].target_path[0] == '\0',
           "unsafe bare rule is global");
    ASSERT(cfg.unsafe_allowlist[0].binary_is_glob == 0,
           "unsafe exact binary metadata");
    ASSERT(cfg.unsafe_allowlist[1].binary_is_glob == 1, "unsafe glob binary flagged");
    ASSERT(cfg.unsafe_allowlist[1].binary_base_len == (int)strlen("/tmp"),
           "unsafe glob binary base");
    ASSERT(strcmp(cfg.unsafe_allowlist[1].target_path, "/tmp/unsafe_target") == 0,
           "unsafe rule target parsed");

    config_reset(&cfg);
    ASSERT(cfg.unsafe_allowlist_count == 0, "config_reset clears unsafe count");
    ASSERT(cfg.unsafe_allowlist[0].binary_is_glob == 0,
           "config_reset clears unsafe glob metadata");

    unlink(path);
    free(path);
}

/*
 * '~' expansion still applies to both sides when one or both carry a
 * glob suffix, and pairing is unchanged: entry i pairs expanded user i's
 * binary with expanded user i's target.  The expected count is derived
 * from the same real-user enumeration so the test is stable on hosts
 * without any real users (the rule is then skipped as relative).
 */
static void test_rule_expansion_with_globs(void)
{
    const char *conf =
        "[allowlist]\n"
        "~/bin/* = ~/.config/*.conf\n";

    int users = 0;
    const struct passwd *pw;
    setpwent();
    while ((pw = getpwent()) != NULL)
    {
        if (pw->pw_uid < 1000 || pw->pw_uid >= 65534)
            continue;
        if (!pw->pw_dir || pw->pw_dir[0] == '\0')
            continue;
        users++;
    }
    endpwent();

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for glob expansion");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load glob expansion success");
    ASSERT(cfg.allowlist_count == users,
           "one rule per real user when both sides expand");

    for (int i = 0; i < cfg.allowlist_count; i++)
    {
        ASSERT(cfg.allowlist[i].binary_is_glob == 1,
               "expanded binary keeps its glob");
        ASSERT(cfg.allowlist[i].target_is_glob == 1,
               "expanded target keeps its glob");
        ASSERT(strstr(cfg.allowlist[i].binary, "/bin/*") != NULL,
               "expanded binary keeps the verbatim suffix");
        ASSERT(strstr(cfg.allowlist[i].target_path, "/.config/*.conf") != NULL,
               "expanded target keeps the verbatim suffix");
        ASSERT(cfg.allowlist[i].binary_base_len ==
                   (int)strlen(cfg.allowlist[i].binary) - (int)strlen("/*"),
               "expanded binary base length");
        ASSERT(cfg.allowlist[i].target_base_len ==
                   (int)strlen(cfg.allowlist[i].target_path) - (int)strlen("/*.conf"),
               "expanded target base length");
    }

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * The shipped fileshield.conf is the default every install gets.  Keep it
 * consistent with its documented contract: the rule sections are empty
 * (every rule is an explicit opt-in) and the settings match the README.
 */
static void test_shipped_config_contract(void)
{
    const char *path = "fileshield.conf";
    Config cfg;

    if (access(path, R_OK) != 0)
        path = "../fileshield.conf"; /* running from tests/ or obj/ */

    memset(&cfg, 0, sizeof(cfg));
    ASSERT(config_load(path, &cfg) == 0, "shipped fileshield.conf parses");

    ASSERT(cfg.allowlist_count == 0,
           "shipped [allowlist] is empty (documented opt-in default)");
    ASSERT(cfg.unsafe_allowlist_count == 0,
           "shipped [unsafe_allowlist] is empty");
    ASSERT(cfg.denylist_count == 0, "shipped [denylist] is empty");

    ASSERT(cfg.protected_count > 0, "shipped config protects paths");
    ASSERT(cfg.protected_count <= MAX_PATHS, "shipped config within MAX_PATHS");
    ASSERT(cfg.user_ttl_seconds == 300, "shipped user_ttl is 300");
    ASSERT(cfg.session_ttl_seconds == 0, "shipped session_ttl is 0");
    ASSERT(cfg.notify_unsafe_allow == 1,
           "shipped notify_unsafe_allowlist is on");
    ASSERT(cfg.notify_allow == 0, "shipped notify_allowlist is off");
    ASSERT(cfg.notify_deny == 1, "shipped notify_denylist is on");

    config_reset(&cfg);
}

/*
 * A path (or glob) whose unresolved "." or ".." survives canonicalization
 * can never match a canonical /proc/<pid>/fd target: the entry must be
 * rejected at load time instead of silently protecting nothing.
 */
static void test_unresolved_dot_segments(void)
{
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "[protected_paths]\n"
             "/tmp/fileshield_dots_ok_%d\n"
             "/tmp/fileshield_dots_missing_%d/../secret\n"
             "/tmp/fileshield_dots_missing_%d/./secret\n"
             "/tmp/fileshield_dots_missing_%d/./*.json\n"
             "/tmp/fileshield_dots_missing_%d/../*.json\n",
             (int)getpid(), (int)getpid(), (int)getpid(), (int)getpid(),
             (int)getpid());

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for dot segments");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load survives rejected dot-segment entries");
    ASSERT(cfg.protected_count == 1,
           "only the clean entry survives unresolved dot segments");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * An over-long rule binary must be rejected before it is copied into the
 * PATH_MAX-sized buffer: truncation silently turns the line into a
 * different rule (and a clipped glob suffix can broaden its match).
 */
static void test_overlong_rule_binary(void)
{
    char binary[PATH_MAX + 64];
    char conf[PATH_MAX * 2 + 128];
    char *path;
    Config cfg;

    memset(binary, 'b', sizeof(binary) - 1);
    binary[0] = '/';
    binary[sizeof(binary) - 1] = '\0';

    snprintf(conf, sizeof(conf), "[unsafe_allowlist]\n%s = /tmp/x\n", binary);

    path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for over-long binary");

    memset(&cfg, 0, sizeof(cfg));
    ASSERT(config_load(path, &cfg) == 0,
           "config_load survives the skipped over-long rule");
    ASSERT(cfg.unsafe_allowlist_count == 0,
           "over-long rule binary is rejected, not truncated");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * A typo'd [settings] key must be reported, and the config must still
 * load: unlike unknown sections, a bad key cannot drop protection.
 */
static void test_unknown_setting(void)
{
    const char *conf =
        "[settings]\n"
        "user_ttl = 120\n"
        "user_tll = 55\n"; /* typo: must not vanish silently */

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for unknown setting");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    ASSERT(config_load(path, &cfg) == 0,
           "unknown setting is reported but does not refuse the config");
    ASSERT(cfg.user_ttl_seconds == 120, "known settings still apply");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * [settings] debug is staged in the Config, never applied by
 * config_load() itself: the caller (main.c) applies it only after the
 * config is fully accepted, so a parse-valid but later-rejected config
 * cannot toggle the global logging state and a rejected reload keeps the
 * previous value.  The global state must be unchanged by every
 * config_load() call here.
 */
static void test_debug_staging(void)
{
    char conf[8192];
    size_t off = 0;
    off += (size_t)snprintf(conf + off, sizeof(conf) - off,
                            "[settings]\ndebug = yes\n[allowlist]\n");
    for (int i = 0; i < 129 && off < sizeof(conf); i++)
        off += (size_t)snprintf(conf + off, sizeof(conf) - off,
                                "/usr/bin/x%d = /tmp/t\n", i);

    struct
    {
        int global_before;
        const char *body;
        int load_rc;
        int want_set;
        int want_debug;
    } cases[3];
    char *paths[3] = {0};
    int i;

    cases[0].global_before = 0;
    cases[0].body = conf; /* refused: over-cap allowlist */
    cases[0].load_rc = -1;
    cases[0].want_set = -1; /* not inspected: config was refused */
    cases[0].want_debug = -1;

    cases[1].global_before = 0;
    cases[1].body = "[settings]\ndebug = yes\n";
    cases[1].load_rc = 0;
    cases[1].want_set = 1;
    cases[1].want_debug = 1;

    cases[2].global_before = 1;
    cases[2].body = "[settings]\ndebug = no\n";
    cases[2].load_rc = 0;
    cases[2].want_set = 1;
    cases[2].want_debug = 0;

    for (i = 0; i < 3; i++)
    {
        Config cfg;
        char *path;

        log_set_debug(cases[i].global_before);
        path = write_temp(cases[i].body);
        ASSERT(path != NULL, "write debug-staging config");
        if (!path)
            continue;
        paths[i] = path;

        memset(&cfg, 0, sizeof(cfg));
        ASSERT(config_load(path, &cfg) == cases[i].load_rc,
               "debug-staging config load result");
        ASSERT(log_debug_enabled() == cases[i].global_before,
               "config_load never touches the global debug flag");
        if (cases[i].want_set >= 0)
        {
            ASSERT(cfg.debug_set == cases[i].want_set,
                   "debug_set is staged from [settings] debug");
            ASSERT(cfg.debug == cases[i].want_debug,
                   "staged debug value matches [settings] debug");
        }
        config_reset(&cfg);
    }

    for (i = 0; i < 3; i++)
    {
        if (paths[i])
        {
            unlink(paths[i]);
            free(paths[i]);
        }
    }

    log_set_debug(0);
}

int main(void)
{
    printf("=== test_config ===\n");
    test_basic_parse();
    test_missing_file();
    test_unknown_section();
    test_unknown_setting();
    test_debug_staging();
    test_relative_protected_rejected();
    test_crlf_longline_and_rule_cap();
    test_overlong_line_refusal();
    test_inline_hash_rejected();
    test_settings_user_ttl();
    test_settings_session_ttl();
    test_settings_session_ttl_value();
    test_settings_invalid_session_ttl();
    test_settings_invalid_user_ttl();
    test_settings_int_parsing();
    test_shipped_config_contract();
    test_settings_notifications();
    test_limits_are_blocking();
    test_ttl_clamping();
    test_whitespace_lines();
    test_path_canonicalization();
    test_canonicalization_missing_levels_under_symlink();
    test_glob_protected_paths();
    test_glob_root_based();
    test_glob_rejection();
    test_unresolved_dot_segments();
    test_overlong_rule_binary();
    test_exclusions_parse();
    test_exclusion_rejection();
    test_rule_rejection();
    test_rule_exact_metadata();
    test_rule_glob_binary();
    test_rule_glob_target();
    test_rule_glob_both();
    test_rule_glob_rejection();
    test_denylist_glob_parse();
    test_reported_user_cases();
    test_unsafe_allowlist_parse();
    test_rule_expansion_with_globs();
    test_denylist_parse();
    test_target_trailing_slash();
    test_scoped_missing_target();
    test_config_load_does_not_publish_global();
    if (failures)
    {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
