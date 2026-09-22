#include "config.h"
#include "utils.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

Config *g_config = NULL;

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' ||
                       s[len - 1] == '\n' || s[len - 1] == '\r'))
        len--;
    s[len] = '\0';
    return s;
}

/*
 * parse_bool: accept the same spellings as [settings] debug (and the
 * notification toggles).  Returns 1 and sets *out when recognized.
 */
static int parse_bool(const char *val, int *out)
{
    if (strcmp(val, "yes") == 0 || strcmp(val, "true") == 0 ||
        strcmp(val, "1") == 0)
    {
        *out = 1;
        return 1;
    }
    if (strcmp(val, "no") == 0 || strcmp(val, "false") == 0 ||
        strcmp(val, "0") == 0)
    {
        *out = 0;
        return 1;
    }
    return 0;
}

/*
 * Parse a non-negative integer setting.  strtol is used instead of
 * sscanf("%d"): sscanf on overflow is undefined and accepts trailing
 * junk, and a hand-edited config must fail loudly rather than take a
 * garbage value.  Returns 1 on success, 0 when the value is not a
 * usable non-negative integer.
 */
static int parse_int_setting(const char *val, int *out)
{
    char *end;
    long v;

    errno = 0;
    v = strtol(val, &end, 10);
    if (end == val || *end != '\0' || errno == ERANGE || v < 0 || v > INT_MAX)
        return 0;
    *out = (int)v;
    return 1;
}

/*
 * canonicalize_path: resolve symlinks so path comparisons against
 * /proc/self/fd/N paths (which are always canonical) cannot be bypassed
 * by a symlinked home/config directory.  If the path does not exist yet,
 * strip trailing components one at a time until realpath(3) resolves,
 * then re-attach everything stripped since the first cut.  One level was
 * not enough: a fresh install has ~/.aws/credentials missing together
 * with ~/.aws itself, and storing the raw string in that case yields a
 * non-canonical pattern under a symlinked home — one the canonical
 * event paths never match, silently leaving the file unprotected.
 * Reaching the deepest existing ancestor keeps the pattern canonical.
 * Only a path with no leading '/' at all (rejected by every caller) can
 * still fall through to the raw string.  A failing realpath("/") means
 * no ancestor resolves at all; reducing the path cannot make progress
 * past "/", so the function fails instead of retrying "/" forever.
 *
 * Returns 0 on success, -1 when nothing (not even "/") resolves, which
 * callers must treat as a fatal, fail-closed rejection.
 */
static int canonicalize_path(const char *in, char *out, size_t outsz)
{
    char trimmed[PATH_MAX];
    char buf[PATH_MAX];
    size_t len, cut;
    char *resolved = NULL;
    int failed = 0;

    snprintf(trimmed, sizeof(trimmed), "%s", in);
    len = strlen(trimmed);
    while (len > 1 && trimmed[len - 1] == '/')
        trimmed[--len] = '\0';
    snprintf(buf, sizeof(buf), "%s", trimmed);
    cut = len; /* no component stripped yet: the tail is empty */

    for (;;)
    {
        resolved = realpath(buf, NULL);
        if (resolved)
            break;
        char *slash = strrchr(buf, '/');
        if (!slash)
            break; /* relative junk: only the raw string can represent it */
        cut = (size_t)(slash - buf);
        if (slash == buf)
        {
            /* "/x" reduces to "/" and gets one more realpath attempt;
             * "/" itself cannot shrink, so a failing realpath("/") must
             * terminate the loop instead of re-testing the same path. */
            if (buf[1] == '\0')
            {
                failed = 1;
                break;
            }
            buf[1] = '\0';
        }
        else
            *slash = '\0';
    }

    if (resolved)
    {
        const char *tail = trimmed + cut; /* slash position, or len when */
        if (cut < len)                    /* no cut: tail stays empty    */
            tail++;                       /* start after the cut slash   */
        int need;

        if (tail[0] == '\0')
            need = snprintf(out, outsz, "%s", resolved);
        else if (resolved[1] == '\0') /* resolved is exactly "/": */
            need = snprintf(out, outsz, "/%s", tail); /* tail starts after */
        else                           /* the removed '/' so no "//".     */
            need = snprintf(out, outsz, "%s/%s", resolved, tail);
        free(resolved);
        if (need < 0 || (size_t)need >= outsz)
            snprintf(out, outsz, "%s", in); /* never emit half a path */
        return 0;
    }

    if (failed)
        return -1;

    snprintf(out, outsz, "%s", in);
    return 0;
}

/*
 * True when a supposedly canonical path still contains a "." or ".."
 * segment.  canonicalize_path() keeps the raw string only for input
 * with no leading '/' (every caller rejects that separately); for
 * absolute paths it resolves or fails, so this is a defensive check.
 * A /proc/<pid>/fd target is always canonical, so such a pattern can
 * never match.  Rejecting it at load time keeps a typo from silently
 * protecting nothing.
 */
static int has_unresolved_dot_segment(const char *path)
{
    const char *p = path;

    while (*p != '\0')
    {
        const char *end = strchr(p, '/');
        size_t len = end ? (size_t)(end - p) : strlen(p);

        if ((len == 1 && p[0] == '.') ||
            (len == 2 && p[0] == '.' && p[1] == '.'))
            return 1;
        if (!end)
            break;
        p = end + 1;
    }
    return 0;
}

/*
 * rule_pattern_set: canonicalize one path-or-glob pattern into out,
 * recording whether it is a glob and the length of its wildcard-free
 * base.  Shared by [protected_paths] entries and both sides of every
 * rule, so all three accept the same syntax and fail the same way.
 *
 * Exact patterns keep the historical behavior: the whole path is
 * canonicalized.
 *
 * Glob patterns are split at the first wildcard segment.  Only the
 * wildcard-free base is canonicalized (so symlinked homes still match
 * the canonical /proc/self/fd target paths); the suffix is matched
 * verbatim by glob_match_path().  A wildcard in the first segment
 * gives a static base of "/" and is refused: such a glob would make
 * the installer mark the root filesystem (fail closed).
 * A malformed pattern — relative, no static base, '..', an empty
 * segment ("//" or a trailing slash) — is rejected.  Fail closed: a
 * typo'd pattern must never silently match nothing.
 *
 * Returns 0 on success, -1 when the pattern is rejected (the entry is
 * skipped with a log), or -2 when the rejection must refuse the whole
 * config (nothing resolves at /, or a glob that would mark the root
 * filesystem).  On a negative return the contents of out are
 * unspecified: callers copy or count the pattern only on 0.
 */
static int rule_pattern_set(char *out, size_t outsz, int *is_glob,
                            int *base_len, const char *raw)
{
    if (strchr(raw, '*') == NULL)
    {
        /* Exact paths must be absolute: they are matched against
         * canonical /proc/<pid>/fd target paths, so a relative entry can
         * never match — reject it with a log instead of silently
         * protecting nothing while the config "loads fine".  (This is
         * the same requirement the glob branch enforces below.) */
        if (raw[0] != '/')
        {
            log_msg(LOG_ERR,
                    "config_load: protected/rule path must be absolute: %s",
                    raw);
            return -1;
        }
        if (strlen(raw) >= PATH_MAX)
        {
            log_msg(LOG_ERR, "config_load: path too long: %.64s", raw);
            return -1;
        }
        if (canonicalize_path(raw, out, outsz) < 0)
        {
            log_msg(LOG_ERR,
                    "config_load: no ancestor of %s resolves (realpath "
                    "failed at /); refusing the config", raw);
            return -2;
        }
        if (has_unresolved_dot_segment(out))
        {
            log_msg(LOG_ERR,
                    "config_load: unresolvable '.' or '..' in path: %s", raw);
            return -1;
        }
        *is_glob = 0;
        *base_len = (int)strlen(out);
        return 0;
    }

    if (raw[0] != '/')
    {
        log_msg(LOG_ERR, "config_load: glob pattern must be absolute: %s", raw);
        return -1;
    }

    /* The matcher carries one globstar backtrack slot, so a pattern with
     * two "**" segments can silently under-match: for a protected entry
     * that means silently NOT protecting files the pattern appears to
     * cover (fail open), and for a deny rule it means missing paths it
     * appears to block.  Reject the second "**" at load time instead of
     * accepting semantics the matcher cannot honor (nothing in the
     * shipped config uses more than one); split the pattern or use a
     * single "**". */
    {
        int globstars = 0;
        for (const char *p = raw;;)
        {
            const char *end = strchr(p, '/');
            size_t seglen = end ? (size_t)(end - p) : strlen(p);
            if (seglen == 2 && p[0] == '*' && p[1] == '*')
                globstars++;
            if (!end)
                break;
            p = end + 1;
        }
        if (globstars > 1)
        {
            log_msg(LOG_ERR,
                    "config_load: at most one '**' segment per pattern "
                    "(a second would under-match silently): %s",
                    raw);
            return -1;
        }
    }

    int blen = glob_base_len(raw);
    if (blen <= 0)
    {
        log_msg(LOG_ERR, "config_load: glob pattern has no static base: %s", raw);
        return -1;
    }
    if (blen >= PATH_MAX)
    {
        log_msg(LOG_ERR, "config_load: glob base too long: %s", raw);
        return -1;
    }

    char base[PATH_MAX];
    memcpy(base, raw, (size_t)blen);
    base[blen] = '\0';

    const char *suffix = raw + blen;
    /* A static base longer than "/" always ends just before a '/', so the
     * suffix starts with one.  A base of "/" (wildcard in the first
     * segment) leaves that whole first segment as the suffix, which may
     * begin with any pattern character (e.g. "/foo*"). */
    if (blen > 1 && *suffix != '/')
    {
        log_msg(LOG_ERR, "config_load: malformed glob pattern: %s", raw);
        return -1;
    }

    /* Suffix segments must be non-empty and free of "." and "..".  When
     * the suffix does not start with '/', the first suffix character is
     * already a segment. */
    for (const char *p = (*suffix == '/') ? suffix + 1 : suffix;;)
    {
        const char *end = strchr(p, '/');
        size_t seglen = end ? (size_t)(end - p) : strlen(p);
        if (seglen == 0)
        {
            log_msg(LOG_ERR, "config_load: empty segment in glob pattern: %s", raw);
            return -1;
        }
        if ((seglen == 1 && p[0] == '.') ||
            (seglen == 2 && p[0] == '.' && p[1] == '.'))
        {
            log_msg(LOG_ERR,
                    "config_load: '.' or '..' segment not allowed in glob "
                    "pattern: %s",
                    raw);
            return -1;
        }
        if (!end)
            break;
        p = end + 1;
    }

    char base_canon[PATH_MAX];
    if (canonicalize_path(base, base_canon, sizeof(base_canon)) < 0)
    {
        log_msg(LOG_ERR,
                "config_load: no ancestor of the glob base of %s resolves "
                "(realpath failed at /); refusing the config", raw);
        return -2;
    }

    size_t canon_len = strlen(base_canon);
    size_t suffix_len = strlen(suffix);

    /* An unresolvable "." or ".." in the base yields a pattern no
     * canonical target can ever match; reject it rather than match
     * nothing. */
    if (has_unresolved_dot_segment(base_canon))
    {
        log_msg(LOG_ERR,
                "config_load: unresolvable '.' or '..' in glob base: %s", raw);
        return -1;
    }

    /* A wildcard-free base of "/" would make fanotify_add_protected()
     * attach a mark to the root mount: the 2026-09-16 freeze class (the
     * daemon's own state-file opens then block on events only it could
     * answer).  Refuse the whole config instead of installing it;
     * skipping the pattern silently would leave the path it appears to
     * cover unprotected.  Checking the canonicalized base also catches
     * a base that resolves to "/" through a symlink. */
    if (canon_len == 1)
    {
        log_msg(LOG_ERR,
                "config_load: glob pattern based at / would mark the root "
                "filesystem; refusing the config: %s", raw);
        return -2;
    }

    /* Always store base_canon + suffix so that the wildcard-free base is
     * exactly the first base_len characters of the stored pattern (the
     * mark target and the protected-prefix check slice it that way).  A
     * base of "/" is refused above, so the suffix already starts with
     * the '/' that joins it and there is no "//" junction to skip. */
    size_t sfx_len = suffix_len;

    if (canon_len + sfx_len >= outsz)
    {
        log_msg(LOG_ERR, "config_load: glob pattern too long: %s", raw);
        return -1;
    }

    memcpy(out, base_canon, canon_len);
    memcpy(out + canon_len, suffix, sfx_len + 1);

    *is_glob = 1;
    *base_len = (int)canon_len;
    return 0;
}

/*
 * Count entries of a NULL-terminated string array.
 */
static int string_array_len(char **arr)
{
    int n = 0;
    if (arr)
        while (arr[n])
            n++;
    return n;
}

/*
 * Append one prepared rule to a section array.  The entry is already
 * canonicalized and bounds-checked by rule_pattern_set(), so this is a
 * plain copy past the shared per-section cap.  Returns 0 on success and
 * -1 at the cap: the caller must refuse the whole config, because a
 * dropped allow/deny rule would silently change access behavior.
 */
static int rule_append(RuleEntry *rules, int *count, const RuleEntry *e)
{
    if (*count >= MAX_RULES)
    {
        log_msg(LOG_ERR,
                "config_load: too many allow/deny rules (max %d); refusing "
                "the config instead of dropping rules",
                MAX_RULES);
        return -1;
    }
    rules[*count] = *e;
    (*count)++;
    return 0;
}

/*
 * Parse one rule line in place (buf is a mutable copy of line): split at
 * '=', validate the binary side (non-empty, shorter than PATH_MAX) and
 * the target side (non-empty when '=' is present, and not the legacy
 * numeric TTL form).  Returns 1 when the line is usable and fills
 * *binary / *target (target NULL for a bare, global rule), 0 when the
 * line must be skipped with the log already written.
 */
static int parse_rule_line(const char *line, char *buf, const char **binary,
                           const char **target)
{
    const char *tgt_raw = NULL;

    char *eq = strchr(buf, '=');
    if (eq)
    {
        *eq = '\0';
        tgt_raw = trim(eq + 1);
    }
    const char *b = trim(buf);
    if (b[0] == '\0')
    {
        log_msg(LOG_ERR, "config_load: malformed rule line: %s", line);
        return 0;
    }
    /* Reject an over-long binary before it is expanded: a truncated
     * path is a different rule (a clipped glob suffix can broaden the
     * match) and rule_pattern_set()'s PATH_MAX guard could not fire on
     * the clipped copy. */
    if (strlen(b) >= PATH_MAX)
    {
        log_msg(LOG_ERR,
                "config_load: rule binary path too long (max %d): %.64s",
                PATH_MAX - 1, b);
        return 0;
    }

    if (tgt_raw)
    {
        if (*tgt_raw == '\0')
        {
            log_msg(LOG_ERR,
                    "config_load: empty target after '='; use a bare binary "
                    "line for a global rule: %s", line);
            return 0;
        }

        /* Legacy-format guard: entries used to be "binary = ttl_seconds". */
        int numeric = 1;
        for (const char *p = tgt_raw; *p != '\0'; p++)
        {
            if (*p < '0' || *p > '9')
            {
                numeric = 0;
                break;
            }
        }
        if (numeric)
        {
            log_msg(LOG_ERR,
                    "config_load: numeric target \"%s\" looks like a legacy "
                    "TTL; rules are now \"binary = target\" — skipping",
                    tgt_raw);
            return 0;
        }
    }

    *binary = b;
    *target = tgt_raw;
    return 1;
}

/*
 * Expand both sides of one usable rule for every real user and append
 * each resulting entry.  When only one side expands, the fixed side is
 * shared by every entry.  Entries whose expanded paths fail validation
 * are skipped with a log.  Returns 0 on success, -1 on allocation
 * failure, when the section's MAX_RULES cap is reached, or for a
 * fail-closed pattern rejection that must refuse the whole config.
 */
static int expand_and_append_rule(RuleEntry *rules, int *count,
                                  const char *line, const char *bin_raw,
                                  const char *tgt_raw)
{
    char **bins = expand_home_all_users(bin_raw);
    if (!bins)
        return -1;

    char **tgts = NULL;
    if (tgt_raw)
    {
        tgts = expand_home_all_users(tgt_raw);
        if (!tgts)
        {
            free_string_array(bins);
            return -1;
        }
    }

    /* Zip the two expanded lists: a '~' side yields one entry per real
     * user, a fixed side or an absent target exactly one, and the
     * shorter list reuses its last entry so every expansion of the
     * longer side still gets a rule. */
    int nb = string_array_len(bins);
    int nt = tgts ? string_array_len(tgts) : 1;
    int n = nb > nt ? nb : nt;

    for (int i = 0; i < n; i++)
    {
        const char *bpath = bins[i < nb ? i : nb - 1];
        const char *tpath = tgts ? tgts[i < nt ? i : nt - 1] : "";

        if (bpath[0] != '/' || (tpath[0] != '\0' && tpath[0] != '/'))
        {
            log_msg(LOG_ERR, "config_load: rule paths must be absolute: %s",
                    line);
            continue;
        }

        RuleEntry e;
        memset(&e, 0, sizeof(e));
        int rc = rule_pattern_set(e.binary, sizeof(e.binary),
                                  &e.binary_is_glob, &e.binary_base_len,
                                  bpath);
        if (rc == -2)
        {
            free_string_array(bins);
            free_string_array(tgts);
            return -1;
        }
        if (rc < 0)
            continue; /* malformed glob: rejected with a log */
        if (tpath[0] != '\0')
        {
            rc = rule_pattern_set(e.target_path, sizeof(e.target_path),
                                  &e.target_is_glob, &e.target_base_len,
                                  tpath);
            if (rc == -2)
            {
                free_string_array(bins);
                free_string_array(tgts);
                return -1;
            }
            if (rc < 0)
                continue;
        }

        if (rule_append(rules, count, &e) < 0)
        {
            free_string_array(bins);
            if (tgts)
                free_string_array(tgts);
            return -1;
        }
    }

    free_string_array(bins);
    if (tgts)
        free_string_array(tgts);
    return 0;
}

/*
 * add_rule: parse one [allowlist]/[unsafe_allowlist]/[denylist] line and
 * append the resulting rule(s).  Format:
 *
 *   /path/to/bin = /path/to/target   scoped rule (equal-or-under match)
 *   /path/to/bin                     global rule (no '=' separator)
 *
 * Either side may be a glob ('*' / '**', the [protected_paths] engine);
 * both sides are validated/canonicalized by rule_pattern_set() and
 * expand '~' for every real user (see the two helpers above).  Lines
 * that fail validation are skipped with a log; returns 0 on success
 * (skips included), -1 on out-of-memory or when the section's MAX_RULES
 * cap is reached (the caller then refuses the whole config instead of
 * dropping rules).
 */
static int add_rule(RuleEntry *rules, int *count, const char *line)
{
    char left[PATH_MAX * 2];
    const char *bin_raw = NULL;
    const char *tgt_raw = NULL;

    snprintf(left, sizeof(left), "%s", line);
    if (!parse_rule_line(line, left, &bin_raw, &tgt_raw))
        return 0;
    return expand_and_append_rule(rules, count, line, bin_raw, tgt_raw);
}

/*
 * protected_path_set: canonicalize one [protected_paths] entry into pp
 * via the shared rule_pattern_set() validator (rules accept the same
 * pattern syntax, so both share one implementation).  Exact entries
 * keep the historical behavior; malformed globs are rejected.
 *
 * Returns the shared rule_pattern_set() code: 0 on success, -1 when the
 * entry is rejected (skipped with a log), -2 when the whole config must
 * be refused.
 */
static int protected_path_set(ProtectedPath *pp, const char *raw)
{
    memset(pp, 0, sizeof(*pp));
    return rule_pattern_set(pp->path, sizeof(pp->path), &pp->is_glob,
                            &pp->base_len, raw);
}

/*
 * Add one [protected_paths] line (positive, or '!' exclusion) to cfg,
 * expanding '~/...' once per real user.  Returns 0 on success (including
 * entries rejected by validation, which are logged) and -1 when the
 * config must be refused (allocation failure, MAX_PATHS reached, or a
 * fail-closed pattern rejection).
 */
static int add_protected_entry(Config *cfg, char *s)
{
    /*
     * A leading '!' marks an exclusion: it protects nothing itself and
     * removes matching paths from the protection of every positive entry
     * (deny wins; config order is irrelevant).  '!' elsewhere is an
     * ordinary path character.  Both positives and exclusions must be
     * absolute after '~' expansion: a relative path can never match a
     * canonical target, so it is rejected with a log (fail closed)
     * rather than silently protecting nothing.
     */
    const char *raw = s;
    int is_exclude = 0;
    if (raw[0] == '!')
    {
        is_exclude = 1;
        raw = trim(s + 1);
        if (*raw == '\0')
        {
            log_msg(LOG_ERR, "config_load: empty exclusion: %s", s);
            return 0;
        }
    }

    /* Expand ~/... for every user in /etc/passwd so that each user's
     * home directory is protected, not just root's. */
    char **paths = expand_home_all_users(raw);
    if (!paths)
    {
        log_msg(LOG_ERR, "config_load: out of memory");
        return -1;
    }
    for (int pi = 0; paths[pi] != NULL; pi++)
    {
        if (cfg->protected_count >= MAX_PATHS)
        {
            /* Refuse the whole config: truncating the protection list
             * would silently leave the dropped paths unmarked and
             * unwatched.  A '~/...' line expands once per real user, so
             * multi-user machines reach this sooner than the line count
             * suggests. */
            log_msg(LOG_ERR,
                    "config_load: too many protected paths (max %d); "
                    "refusing the config (note: '~/...' expands once "
                    "per real user)", MAX_PATHS);
            free_string_array(paths);
            return -1;
        }
        /* Fill the next slot first; protected_count is the commit point,
         * so a rejected path leaves only an uncounted, zeroed slot. */
        ProtectedPath *pp = &cfg->protected[cfg->protected_count];
        int rc = protected_path_set(pp, paths[pi]);
        if (rc == -2)
        {
            /* Fail-closed rejection (nothing resolves, or a root-based
             * glob): the whole config is refused, never a silent skip. */
            free_string_array(paths);
            return -1;
        }
        if (rc < 0)
            continue; /* malformed or relative: rejected with a log */
        pp->is_exclude = is_exclude;
        if (is_exclude)
        {
            /* Index recorded before the count advances: the event hot
             * path walks exclude_idx[] instead of scanning protected[]
             * for is_exclude. */
            cfg->exclude_idx[cfg->exclude_count] = cfg->protected_count;
            cfg->exclude_count++;
            /* Audit trail: every carve-out is visible in the journal. */
            log_msg(LOG_INFO, "config_load: exclusion: !%s", pp->path);
        }
        cfg->protected_count++;
    }
    free_string_array(paths);
    return 0;
}

/*
 * Append every rule on one line to a section.  Returns 0 on success
 * (including lines add_rule() skips with a log) and -1 when the config
 * must be refused (allocation failure or the section's rule cap).
 */
static int load_rules(RuleEntry *rules, int *count, const char *section_name,
                      const char *line)
{
    if (add_rule(rules, count, line) < 0)
    {
        log_msg(LOG_ERR,
                "config_load: cannot add to [%s] (out of memory, rule cap "
                "reached, or a fail-closed pattern rejection); refusing the "
                "config",
                section_name);
        return -1;
    }
    return 0;
}

/*
 * Apply one [settings] "key = value" pair to cfg.  Unknown keys are
 * logged and ignored; an invalid value keeps the current/default one.
 * Settings can never make a config unusable, so there is no failure
 * return: a typo is visible in the journal instead of failing startup.
 *
 * Only "debug" is staged (debug_set/debug): it drives the global
 * logging gate, which must not change unless the whole config is
 * accepted.  Every other key mutates cfg alone, and cfg stays
 * unpublished until config_load() returns 0, so those are applied
 * immediately during the parse.
 */
static void apply_setting(Config *cfg, const char *key, const char *val)
{
    if (strcmp(key, "user_ttl") == 0)
    {
        /* 0 disables "Allow Once" caching: each open prompts again. */
        int ttl;
        if (parse_int_setting(val, &ttl))
        {
            if (ttl > FS_MAX_TTL_SECONDS)
            {
                log_msg(LOG_WARNING,
                        "config_load: user_ttl %d clamped to %d seconds",
                        ttl, FS_MAX_TTL_SECONDS);
                ttl = FS_MAX_TTL_SECONDS;
            }
            cfg->user_ttl_seconds = ttl;
        }
        else
            log_msg(LOG_ERR, "config_load: invalid user_ttl: %s", val);
    }
    else if (strcmp(key, "session_ttl") == 0)
    {
        /* 0 is a valid value: session decisions then live exactly
         * as long as the session leader (the shell). */
        int ttl;
        if (parse_int_setting(val, &ttl))
        {
            if (ttl > FS_MAX_TTL_SECONDS)
            {
                log_msg(LOG_WARNING,
                        "config_load: session_ttl %d clamped to %d seconds",
                        ttl, FS_MAX_TTL_SECONDS);
                ttl = FS_MAX_TTL_SECONDS;
            }
            cfg->session_ttl_seconds = ttl;
        }
        else
            log_msg(LOG_ERR, "config_load: invalid session_ttl: %s", val);
    }
    else if (strcmp(key, "debug") == 0)
    {
        /* Enables the per-event LOG_DEBUG firehose at runtime.
         * Staged: applied only when the whole config is accepted. */
        int on;
        if (parse_bool(val, &on))
        {
            cfg->debug_set = 1;
            cfg->debug = on;
        }
        else
            log_msg(LOG_ERR,
                    "config_load: invalid debug value (yes|no): %s",
                    val);
    }
    else if (strcmp(key, "notify_unsafe_allowlist") == 0)
    {
        int on;
        if (parse_bool(val, &on))
            cfg->notify_unsafe_allow = on;
        else
            log_msg(LOG_ERR,
                    "config_load: invalid notify_unsafe_allowlist "
                    "(yes|no): %s", val);
    }
    else if (strcmp(key, "notify_allowlist") == 0)
    {
        int on;
        if (parse_bool(val, &on))
            cfg->notify_allow = on;
        else
            log_msg(LOG_ERR,
                    "config_load: invalid notify_allowlist (yes|no): %s",
                    val);
    }
    else if (strcmp(key, "notify_denylist") == 0)
    {
        int on;
        if (parse_bool(val, &on))
            cfg->notify_deny = on;
        else
            log_msg(LOG_ERR,
                    "config_load: invalid notify_denylist (yes|no): %s",
                    val);
    }
    else if (strcmp(key, "notify_dedup_ttl") == 0)
    {
        /* Seconds an identical (list, binary, target) notification is
         * suppressed; 0 notifies on every hit. */
        int ttl;
        if (parse_int_setting(val, &ttl))
        {
            if (ttl > FS_MAX_TTL_SECONDS)
            {
                log_msg(LOG_WARNING,
                        "config_load: notify_dedup_ttl %d clamped to "
                        "%d seconds", ttl, FS_MAX_TTL_SECONDS);
                ttl = FS_MAX_TTL_SECONDS;
            }
            cfg->notify_dedup_seconds = ttl;
        }
        else
            log_msg(LOG_ERR, "config_load: invalid notify_dedup_ttl: %s",
                    val);
    }
    else if (strcmp(key, "notify_max") == 0)
    {
        /* Global cap per 60 s window; the dedup window bounds each
         * key, this bounds a burst of distinct keys. */
        int max;
        if (parse_int_setting(val, &max) && max >= 1)
            cfg->notify_max = max;
        else
            log_msg(LOG_ERR, "config_load: invalid notify_max (>= 1): %s",
                    val);
    }
    else
    {
        /* A typo'd key must be visible: silently ignoring it could
         * leave a protection or notification toggle at its default
         * while the admin believes it is set. */
        log_msg(LOG_WARNING, "config_load: unknown setting: %s", key);
    }
}

/* Sections of fileshield.conf; SECTION_NONE is "before/outside any". */
enum
{
    SECTION_NONE = 0,
    SECTION_PROTECTED,
    SECTION_ALLOWLIST,
    SECTION_SETTINGS,
    SECTION_DENYLIST,
    SECTION_UNSAFE_ALLOWLIST
};

/*
 * config_load: parse 'path' into cfg, which is reset first.  Phases:
 *
 *   1. open the file and, when running as root, refuse a regular file
 *      another user can modify;
 *   2. reset cfg and seed the notification defaults;
 *   3. walk the file section by section; helpers append entries and log
 *      every skip where it happens;
 *   4. verify the stream ended cleanly;
 *   5. return with [settings] debug staged in cfg and g_config
 *      deliberately unpublished (the caller decides whether to accept).
 *
 * Every failure is fail closed.  A -1 leaves *cfg partially filled and
 * must be discarded in favor of the previous config.  Caps (MAX_PATHS,
 * MAX_RULES) and fail-closed pattern rejections refuse the whole config
 * instead of dropping entries, because a dropped protection or rule
 * silently changes access behavior.
 */
int config_load(const char *path, Config *cfg)
{
    if (!path)
        return -1;

    FILE *fp = fopen(path, "r");
    if (!fp)
    {
        log_msg(LOG_ERR, "config_load: cannot open %s", path);
        return -1;
    }

    /* The daemon runs as root: a config another user can modify is a
     * privilege-escalation path (e.g. adding an [unsafe_allowlist]
     * rule), so it is refused rather than merely warned about.  The
     * check covers regular files only: a non-regular source (fifo,
     * device) skips it and reaches the parser. */
    if (geteuid() == 0)
    {
        struct stat st;
        if (fstat(fileno(fp), &st) == 0 && S_ISREG(st.st_mode))
        {
            int unsafe = 0;
            if (st.st_uid != 0)
            {
                log_msg(LOG_ERR, "config_load: %s is not owned by root", path);
                unsafe = 1;
            }
            if (st.st_mode & 022)
            {
                log_msg(LOG_ERR, "config_load: %s is writable by group/other",
                        path);
                unsafe = 1;
            }
            if (unsafe)
            {
                log_msg(LOG_ERR,
                        "config_load: refusing a config another user can "
                        "modify; fix the ownership/permissions and reload");
                fclose(fp);
                return -1;
            }
        }
    }

    char line[PATH_MAX * 2];
    int section = SECTION_NONE;

    /* Phase 2: reset the caller's Config (a retry must not inherit the
     * previous attempt's counts) and seed documented defaults. */
    memset(cfg, 0, sizeof(*cfg));

    /*
     * Notification defaults, documented in the shipped fileshield.conf:
     * the hash-pinned [allowlist] is silent (an expected, admin-opted-in
     * grant); [unsafe_allowlist] and [denylist] notify so an impersonated
     * binary or an unexpected block is visible.
     */
    cfg->notify_unsafe_allow = 1;
    cfg->notify_allow = 0;
    cfg->notify_deny = 1;
    cfg->notify_dedup_seconds = NOTIFY_DEDUP_DEFAULT_S;
    cfg->notify_max = NOTIFY_MAX_DEFAULT;

    /* Phase 3: section walk -- one line at a time, no cross-line state. */
    while (fgets(line, sizeof(line), fp))
    {
        if (!strchr(line, '\n') && !feof(fp))
        {
            /* The line overflowed the PATH_MAX*2 buffer: only its prefix
             * is available, so the comment/blank decision is made on the
             * first non-whitespace byte of that prefix. */
            const char *lp = line;
            while (*lp == ' ' || *lp == '\t')
                lp++;
            if (*lp != '\0' && *lp != '#' &&
                (section == SECTION_PROTECTED ||
                 section == SECTION_ALLOWLIST ||
                 section == SECTION_UNSAFE_ALLOWLIST ||
                 section == SECTION_DENYLIST || *lp == '['))
            {
                /* A non-comment entry in a rule section that no longer
                 * fits the parse buffer must refuse the whole config,
                 * like the MAX_PATHS/MAX_RULES cap cases: skipping it
                 * would silently drop the rule (or an entire section
                 * behind a header we never see), breaking the promise
                 * that a typo cannot silently drop rules.  Comments,
                 * blanks, [settings] lines and preamble garbage drop no
                 * rules, so they keep the historical skip-with-log. */
                log_msg(LOG_ERR,
                        "config_load: over-long rule/section line; "
                        "refusing the config instead of silently dropping "
                        "it");
                fclose(fp);
                return -1;
            }
            log_msg(LOG_ERR, "config_load: line too long, skipping");
            int c;
            while ((c = fgetc(fp)) != '\n' && c != EOF)
                ;
            continue;
        }
        char *s = trim(line);

        if (*s == '\0' || *s == '#')
            continue;

        /* '#' anywhere else is NOT a comment: '#', spaces and tabs are
         * all legal path bytes, so treating "path # note" as a trailing
         * comment would either truncate a real path silently or (as
         * before) swallow the note into the pattern and protect nothing
         * while the config loads "fine".  Reject loudly instead; move
         * the comment to its own line. */
        if (strchr(s, '#'))
        {
            log_msg(LOG_ERR,
                    "config_load: '#' is only a comment at line start; "
                    "rejecting entry (put comments on their own line): %s",
                    s);
            fclose(fp);
            return -1;
        }

        if (s[0] == '[')
        {
            char *close = strchr(s, ']');
            if (!close)
            {
                log_msg(LOG_ERR, "config_load: malformed section header: %s", s);
                fclose(fp);
                return -1;
            }
            *close = '\0';
            /* Anything after the closing bracket is junk the parser
             * would otherwise ignore while honoring the header. */
            if (*trim(close + 1) != '\0')
            {
                log_msg(LOG_ERR,
                        "config_load: trailing text after section header: %s",
                        close + 1);
                fclose(fp);
                return -1;
            }
            if (strcmp(s + 1, "protected_paths") == 0)
                section = SECTION_PROTECTED;
            else if (strcmp(s + 1, "allowlist") == 0)
                section = SECTION_ALLOWLIST;
            else if (strcmp(s + 1, "unsafe_allowlist") == 0)
                section = SECTION_UNSAFE_ALLOWLIST;
            else if (strcmp(s + 1, "settings") == 0)
                section = SECTION_SETTINGS;
            else if (strcmp(s + 1, "denylist") == 0)
                section = SECTION_DENYLIST;
            else
            {
                /* Refuse the whole config: a typo'd section header would
                 * silently drop every rule under it while the daemon
                 * reports success.  Matches the malformed-header case
                 * above (fail loud, fail closed). */
                log_msg(LOG_ERR,
                        "config_load: unknown section '%s'; refusing the "
                        "config (its entries would be silently ignored)",
                        s + 1);
                fclose(fp);
                return -1;
            }
            continue;
        }

        if (section == SECTION_NONE)
        {
            /* Entries outside a known section (or under an unknown one)
             * are dropped; make that visible instead of silent. */
            log_msg(LOG_ERR,
                    "config_load: entry outside any known section is "
                    "ignored: %s", s);
            continue;
        }

        if (section == SECTION_PROTECTED)
        {
            if (add_protected_entry(cfg, s) < 0)
            {
                fclose(fp);
                return -1;
            }
        }
        else if (section == SECTION_ALLOWLIST)
        {
            /* [allowlist] "binary = target" or a bare binary (global). */
            if (load_rules(cfg->allowlist, &cfg->allowlist_count, "allowlist",
                           s) < 0)
            {
                fclose(fp);
                return -1;
            }
        }
        else if (section == SECTION_UNSAFE_ALLOWLIST)
        {
            /* [unsafe_allowlist]: same format as [allowlist], but grants
             * skip the binary hash pinning entirely. */
            if (load_rules(cfg->unsafe_allowlist, &cfg->unsafe_allowlist_count,
                           "unsafe_allowlist", s) < 0)
            {
                fclose(fp);
                return -1;
            }
        }
        else if (section == SECTION_SETTINGS)
        {
            /* [settings] key = value */
            char *eq = strchr(s, '=');
            if (!eq)
            {
                /* Silently dropping this made a typo like "user_ttl 300"
                 * look like it took effect; report it instead (the line
                 * is still skipped, matching the unknown-key warning). */
                log_msg(LOG_ERR,
                        "config_load: malformed settings line (missing "
                        "'='), ignored: %s", s);
                continue;
            }
            *eq = '\0';
            apply_setting(cfg, trim(s), trim(eq + 1));
        }
        else if (section == SECTION_DENYLIST)
        {
            /* [denylist] "binary = target" or a bare binary (global). */
            if (load_rules(cfg->denylist, &cfg->denylist_count, "denylist",
                           s) < 0)
            {
                fclose(fp);
                return -1;
            }
        }
    }

    /* Phase 4: the stream must have ended cleanly, not on an I/O error. */
    if (ferror(fp))
    {
        log_msg(LOG_ERR, "config_load: read error on %s; refusing the config",
                path);
        fclose(fp);
        return -1;
    }

    /* [settings] debug stays staged in cfg (see apply_setting): the
     * caller applies it only after the config is accepted, so a config
     * refused by the scope guard or a failed mark install cannot toggle
     * global logging (config.h). */
    fclose(fp);
    /*
     * Deliberately do NOT publish cfg through g_config here.  The caller
     * decides whether the parsed config is accepted; publishing during
     * the parse is what once left g_config dangling after a rejected
     * reload free()d the new config.  main.c publishes g_config only
     * after the parse succeeds - before the new marks are installed,
     * because the inode walk consults it - and restores the previous
     * config when a reload is rejected.
     */
    return 0;
}

void config_reset(Config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
}
