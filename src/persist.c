#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <syslog.h>

#include "persist.h"
#include "utils.h"

/* Ensure the state directory exists with secure permissions (0700, root-only). */
static int ensure_state_dir(const char *dirpath)
{
    struct stat st;

    /* lstat: never follow a symlink placed at the state directory path. */
    if (lstat(dirpath, &st) == 0)
    {
        if (S_ISLNK(st.st_mode))
        {
            log_msg(LOG_ERR, "%s is a symlink; refusing to use it", dirpath);
            return -1;
        }
        if (!S_ISDIR(st.st_mode))
        {
            log_msg(LOG_ERR, "%s exists but is not a directory", dirpath);
            return -1;
        }
        if (geteuid() == 0 && st.st_uid != 0)
        {
            log_msg(LOG_ERR, "%s is not owned by root; refusing to use it",
                    dirpath);
            return -1;
        }
        if ((st.st_mode & 0777) != 0700)
        {
            if (chmod(dirpath, 0700) < 0)
            {
                log_msg(LOG_ERR, "chmod %s 0700: %s (refusing the write)",
                        dirpath, strerror(errno));
                return -1;
            }
        }
        return 0;
    }

    if (errno != ENOENT)
    {
        log_msg(LOG_ERR, "stat %s: %s", dirpath, strerror(errno));
        return -1;
    }

    if (mkdir(dirpath, 0700) < 0)
    {
        log_msg(LOG_ERR, "mkdir %s: %s", dirpath, strerror(errno));
        return -1;
    }

    return 0;
}

/* Derive the parent directory of filepath and ensure it exists via
 * ensure_state_dir().  A filepath without a directory component is left
 * to the working directory (previous persist_save() behavior). */
static int ensure_parent_dir(const char *filepath)
{
    char dirpath[PATH_MAX];
    char *slash;

    snprintf(dirpath, sizeof(dirpath), "%s", filepath);
    slash = strrchr(dirpath, '/');
    if (slash && slash != dirpath)
    {
        *slash = '\0';
        return ensure_state_dir(dirpath);
    }
    return 0;
}

/*
 * Shared root-run trust bar for state-file loads (persist.h): a state
 * file another user can modify is a privilege-escalation path (a planted
 * allow/deny rule or hash pin), so it is refused rather than warned
 * about -- the same bar as config_load().  The ownership/mode check
 * covers regular files only (fstat of the opened fd, exactly like
 * config_load(); a non-regular source such as a fifo or device skips it
 * and reaches the parser), while a path that is itself a symlink is
 * refused outright: the daemon's own writer never creates one.  Runs
 * only under geteuid()==0 so unprivileged test runs are unaffected.
 */
int persist_file_trusted(FILE *fp, const char *filepath, const char *what)
{
    struct stat st;
    int unsafe = 0;

    if (geteuid() != 0)
        return 0;

    if (lstat(filepath, &st) == 0 && S_ISLNK(st.st_mode))
    {
        log_msg(LOG_ERR, "%s: %s is a symlink; refusing to load it", what,
                filepath);
        unsafe = 1;
    }
    if (fstat(fileno(fp), &st) == 0 && S_ISREG(st.st_mode))
    {
        if (st.st_uid != 0)
        {
            log_msg(LOG_ERR, "%s: %s is not owned by root", what, filepath);
            unsafe = 1;
        }
        if (st.st_mode & 022)
        {
            log_msg(LOG_ERR, "%s: %s is writable by group/other", what,
                    filepath);
            unsafe = 1;
        }
    }
    if (unsafe)
        log_msg(LOG_ERR,
                "%s: refusing a state file another user can modify; fix the "
                "ownership/permissions and reload",
                what);
    return unsafe ? -1 : 0;
}

/*
 * Create '<filepath>.tmp.<pid>' exclusively at 0600 with O_NOFOLLOW, so a
 * planted symlink is never followed and the file is never readable by
 * others.  A stale temp file from a crash (EEXIST) is removed and the
 * open retried once, matching the previous persist_save() behavior.
 * Returns the fd, or -1 with 'tmp_file' left untouched and an error
 * logged under the caller tag 'what'.
 */
static int open_atomic_temp(const char *filepath, const char *what,
                            char *tmp_file, size_t tmp_size)
{
    int fd;
    int need;

    /* A filepath near PATH_MAX would silently truncate the ".tmp.<pid>"
     * suffix, and the EEXIST retry below would then unlink a file whose
     * name this function never verified fits.  Refuse instead of
     * guessing (callers surface the failure; writes fail closed). */
    need = snprintf(tmp_file, tmp_size, "%s.tmp.%d", filepath,
                    (int)getpid());
    if (need < 0 || (size_t)need >= tmp_size)
    {
        log_msg(LOG_ERR, "%s: temp path for %s is too long", what, filepath);
        tmp_file[0] = '\0';
        return -1;
    }

    fd = open(tmp_file, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
              0600);
    if (fd < 0 && errno == EEXIST)
    {
        /* Stale temp file from a previous crash: remove and retry once. */
        unlink(tmp_file);
        fd = open(tmp_file,
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    }
    if (fd < 0)
        log_msg(LOG_ERR, "%s: open %s: %s", what, tmp_file, strerror(errno));
    return fd;
}

/*
 * fsync with a test injection point: after persist_test_fail_fsync_after(n)
 * the (n+1)-th fsync call fails with EIO, so the failure branches are
 * reachable in tests on any filesystem.  Disabled by default.
 */
static int g_test_fail_fsync_after = -1;
static int g_test_fsync_calls = 0;

static int fsync_maybe_failing(int fd)
{
    g_test_fsync_calls++;
    if (g_test_fail_fsync_after >= 0 &&
        g_test_fsync_calls > g_test_fail_fsync_after)
    {
        errno = EIO;
        return -1;
    }
    return fsync(fd);
}

void persist_test_fail_fsync_after(int nth)
{
    g_test_fail_fsync_after = nth;
    g_test_fsync_calls = 0;
}

/*
 * Finish an atomic write: flush, fsync, close and rename the temp file
 * over filepath.  Any failure — including fsync — unlinks the temp file
 * so no partial or non-durable state is published, and returns -1; 'what'
 * tags the log messages.  Only a directory-fsync failure after the
 * rename cannot remove the new file; it is still reported as a failure
 * so the caller does not treat the write as durable.
 */
static int commit_atomic_temp(FILE *fp, const char *tmp_file,
                              const char *filepath, const char *what)
{
    if (fflush(fp) < 0)
    {
        log_msg(LOG_ERR, "%s: flush %s: %s", what, tmp_file, strerror(errno));
        fclose(fp);
        unlink(tmp_file);
        return -1;
    }
    if (fsync_maybe_failing(fileno(fp)) < 0)
    {
        log_msg(LOG_ERR, "%s: fsync %s: %s (not publishing the update)",
                what, tmp_file, strerror(errno));
        fclose(fp);
        unlink(tmp_file);
        return -1;
    }

    /* An error surfacing at close must fail the write before the rename
     * can publish the file. */
    if (fclose(fp) < 0)
    {
        log_msg(LOG_ERR, "%s: close %s: %s", what, tmp_file, strerror(errno));
        unlink(tmp_file);
        return -1;
    }

    if (rename(tmp_file, filepath) < 0)
    {
        log_msg(LOG_ERR, "%s: rename %s -> %s: %s", what, tmp_file, filepath,
                strerror(errno));
        unlink(tmp_file);
        return -1;
    }

    /* Persist the rename itself: without a directory fsync a crash right
     * after this point can leave the old file — or nothing — on disk.
     * For the pin table a vanished file is re-read as a clean empty
     * table, which would silently reset every rule to first-use (TOFU).
     * The rename is already committed, so the new file cannot be
     * removed; report the failure anyway so the caller does not treat
     * the write as durable. */
    char dirbuf[PATH_MAX];
    snprintf(dirbuf, sizeof(dirbuf), "%s", filepath);
    char *slash = strrchr(dirbuf, '/');
    if (slash)
    {
        const char *dirpath = "/"; /* filepath at the root */
        if (slash != dirbuf)
        {
            *slash = '\0';
            dirpath = dirbuf;
        }
        int dirfd = open(dirpath, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dirfd < 0)
        {
            /* Same contract as a failing directory fsync below: the
             * rename is already visible, but the write must not be
             * reported as durable while the directory flush was skipped. */
            log_msg(LOG_ERR,
                    "%s: open dir %s: %s (rename committed but it may "
                    "not survive a crash)",
                    what, dirpath, strerror(errno));
            return -1;
        }
        if (fsync_maybe_failing(dirfd) < 0)
        {
            log_msg(LOG_ERR,
                    "%s: fsync dir %s: %s (rename committed but it may "
                    "not survive a crash)",
                    what, dirpath, strerror(errno));
            close(dirfd);
            return -1;
        }
        close(dirfd);
    }
    return 0;
}

int persist_json_escape(const char *src, char *dst, size_t dst_size)
{
    size_t written = 0;

    if (!src || !dst || dst_size < 1)
        return -1;

    for (; *src; src++)
    {
        unsigned char c = (unsigned char)*src;

        if (written + 2 >= dst_size)
            return -1;

        if (c == '"')
        {
            dst[written++] = '\\';
            dst[written++] = '"';
        }
        else if (c == '\\')
        {
            dst[written++] = '\\';
            dst[written++] = '\\';
        }
        else if (c == '\b')
        {
            dst[written++] = '\\';
            dst[written++] = 'b';
        }
        else if (c == '\f')
        {
            dst[written++] = '\\';
            dst[written++] = 'f';
        }
        else if (c == '\n')
        {
            dst[written++] = '\\';
            dst[written++] = 'n';
        }
        else if (c == '\r')
        {
            dst[written++] = '\\';
            dst[written++] = 'r';
        }
        else if (c == '\t')
        {
            dst[written++] = '\\';
            dst[written++] = 't';
        }
        else if (c < 0x20)
        {
            if (written + 6 >= dst_size)
                return -1;
            int n = snprintf(&dst[written], dst_size - written, "\\u%04x", c);
            if (n < 0 || n >= (int)(dst_size - written))
                return -1;
            written += (size_t)n;
        }
        else
        {
            dst[written++] = c;
        }
    }

    if (written >= dst_size)
        return -1;

    dst[written] = '\0';
    return (int)written;
}

/* Bounded string copy with NUL termination.  A truncated value is a
 * state entry that will never match at decision time (the truncated
 * digest/path keys differ from the real ones) — log it so the silent
 * re-prompting the truncation causes is diagnosable. */
static void copy_field(const char *filepath, char *dst, size_t dstsz,
                       const char *src)
{
    size_t len;

    if (!dst || dstsz == 0)
        return;
    len = strlen(src);
    if (len >= dstsz)
    {
        log_msg(LOG_WARNING,
                "persist_load: %s: value too long for a field (%zu >= %zu); "
                "truncated — the entry will not match",
                filepath, len, dstsz - 1);
        len = dstsz - 1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/*
 * Extract a JSON string key/value pair from a single line of the form
 *   "key": "value",
 * Unescapes the value into out (bounded, always NUL-terminated) and
 * returns 1 when a string pair was found, writing the key into key_out.
 *
 * A plain %[^"] sscanf scan cannot handle escaped quotes, which command
 * lines contain routinely (`sh -c "..."`), so the value is decoded
 * escape-aware instead.  Returns 0 for numeric fields or malformed input.
 *
 * Keys are writer-generated and never contain escapes or ':', so the
 * first quoted token and the first ':' locate the pair; anything after
 * the closing quote (the writer's optional comma) is ignored.  out must
 * hold the decoded value plus its NUL: a value that does not fit
 * returns 0 with out left empty, and the caller falls through to its
 * numeric parser.  Accepted escapes are JSON's \" \\ \/ \b \f \n \r
 * \t and \uXXXX; an unknown escape, a raw control byte, \u0000 (not
 * representable in a C string) or a lone surrogate all return 0.
 */
int persist_json_extract_string(const char *line, char *key_out, size_t keysz,
                                char *out, size_t outsz)
{
    char found_key[256];
    const char *p;
    size_t j = 0;

    if (!out || outsz == 0)
        return 0;
    out[0] = '\0';

    /* Key scan: keys are writer-generated and escape-free, so a plain
     * quoted token suffices; the value is decoded escape-aware below. */
    if (sscanf(line, " \"%255[^\"]\"", found_key) != 1)
        return 0;

    p = strchr(line, ':');
    if (!p)
        return 0;
    p++;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p != '"')
        return 0; /* numeric or non-string value */
    p++;

    while (*p != '\0' && *p != '"')
    {
        unsigned char c = (unsigned char)*p;

        if (c == '\\')
        {
            p++;
            if (*p == '\0')
                return 0; /* malformed trailing escape */
            switch (*p)
            {
            case '"': c = '"'; break;
            case '\\': c = '\\'; break;
            case '/': c = '/'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'u':
            {
                unsigned int code = 0;
                int digits = 0;

                /* Consume up to four hex digits and advance by exactly how
                 * many were present.  sscanf("%4x") accepts a short escape
                 * such as "\u1", but an unconditional four-byte advance
                 * would skip the closing quote and scan past the string. */
                while (digits < 4 && isxdigit((unsigned char)p[1 + digits]))
                {
                    char h = p[1 + digits];
                    unsigned int d = (h >= '0' && h <= '9')
                                         ? (unsigned int)(h - '0')
                                         : (unsigned int)((h | 0x20) - 'a' + 10);
                    code = (code << 4) | d;
                    digits++;
                }
                if (digits == 0 || code == 0)
                    return 0; /* not a \u escape / NUL cannot be stored */
                /* Lone surrogates (D800-DFFF) encode to invalid UTF-8:
                 * reject them like any other malformed escape so a real
                 * JSON consumer never chokes on the state file. */
                if (code >= 0xD800 && code <= 0xDFFF)
                    return 0;
                p += digits; /* p now points at the last hex digit */
                if (code < 0x80)
                {
                    c = (unsigned char)code;
                }
                else
                {
                    /* Encode the code point back to UTF-8. */
                    unsigned char utf8[3];
                    int n;
                    if (code < 0x800)
                    {
                        utf8[0] = (unsigned char)(0xC0 | (code >> 6));
                        utf8[1] = (unsigned char)(0x80 | (code & 0x3F));
                        n = 2;
                    }
                    else
                    {
                        utf8[0] = (unsigned char)(0xE0 | (code >> 12));
                        utf8[1] = (unsigned char)(0x80 | ((code >> 6) & 0x3F));
                        utf8[2] = (unsigned char)(0x80 | (code & 0x3F));
                        n = 3;
                    }
                    if (j + (size_t)n >= outsz)
                        return 0; /* value does not fit */
                    for (int k = 0; k < n; k++)
                        out[j++] = (char)utf8[k];
                    p++;
                    continue;
                }
                break;
            }
            default:
                return 0; /* unknown escape sequence */
            }
        }
        else if (c < 0x20)
        {
            return 0; /* raw control character inside a JSON string */
        }

        if (j + 1 >= outsz)
            return 0; /* value does not fit */
        out[j++] = (char)c;
        p++;
    }
    if (*p != '"')
        return 0; /* unterminated value */

    out[j] = '\0';
    if (key_out && keysz > 0)
        snprintf(key_out, keysz, "%s", found_key);
    return 1;
}

/*
 * Parse one bracketed chain-slot key ("chain_comm[2]" or
 * "chain_sha512[0]") against 'prefix'.  Returns 1 and sets *idx when the
 * key matches exactly with an in-range index, 0 otherwise.
 *
 * strtol, not sscanf("%d"): an overflowing index is undefined behavior
 * with scanf conversions, while ERANGE is a defined rejection here.  The
 * opening bracket, the closing ']' and the end of the key are all
 * required, so trailing junk never parses — the same discipline
 * apply_entry_number() and pin.c's parse_numeric_field() follow.
 */
static int parse_chain_slot(const char *key, const char *prefix, int *idx)
{
    size_t plen = strlen(prefix);
    const char *rest;
    char *end;
    long value;

    if (strncmp(key, prefix, plen) != 0 || key[plen] != '[')
        return 0;

    rest = key + plen + 1;
    errno = 0;
    value = strtol(rest, &end, 10);
    if (end == rest || errno == ERANGE || *end != ']' || end[1] != '\0')
        return 0;
    if (value < 0 || value >= PERSIST_CHAIN_MAX)
        return 0;

    *idx = (int)value;
    return 1;
}

/*
 * Apply one parsed string field to an entry.  Values arrive already
 * unescaped; unknown keys are ignored so hand-edited state files stay
 * loadable.  Returns 0 normally, or -1 when a numeric field
 * (chain_depth / created_at) carries a string value: the caller drops
 * that entry (mirroring a malformed rule_id), because admitting it
 * would silently weaken a persisted rule (a zero depth, or an epoch
 * timestamp).
 */
static int apply_entry_field(const char *filepath, PersistEntry *e,
                             const char *key, const char *value)
{
    int idx;

    if (strcmp(key, "binary") == 0)
        copy_field(filepath, e->binary, sizeof(e->binary), value);
    else if (strcmp(key, "binary_sha512") == 0)
        copy_field(filepath, e->binary_sha512, sizeof(e->binary_sha512), value);
    else if (strcmp(key, "target_path") == 0)
        copy_field(filepath, e->target_path, sizeof(e->target_path), value);
    else if (strcmp(key, "cmdline") == 0)
        copy_field(filepath, e->cmdline, sizeof(e->cmdline), value);
    else if (strcmp(key, "cmdline_sha512") == 0)
        copy_field(filepath, e->cmdline_sha512, sizeof(e->cmdline_sha512),
                   value);
    else if (strcmp(key, "chain_depth") == 0 ||
             strcmp(key, "created_at") == 0)
    {
        log_msg(LOG_WARNING,
                "persist_load: %s: numeric field \"%s\" has a string value; "
                "dropping the entry (a stored rule must never silently "
                "weaken)",
                filepath, key);
        return -1;
    }
    else if (parse_chain_slot(key, "chain_comm", &idx))
        copy_field(filepath, e->chain_comm[idx], sizeof(e->chain_comm[idx]),
                   value);
    else if (parse_chain_slot(key, "chain_sha512", &idx))
        copy_field(filepath, e->chain_sha512[idx],
                   sizeof(e->chain_sha512[idx]), value);
    return 0;
}

/*
 * Apply the numeric fields (chain_depth, created_at) of one line.
 * strtol (not sscanf %d/%ld): an out-of-range value in a hand-edited or
 * corrupt file is undefined behavior with scanf conversions, while
 * ERANGE is a defined rejection here.  The same reason pin.c parses its
 * numeric fields with strtol.
 */
static void apply_entry_number(PersistEntry *e, const char *line)
{
    char key_buf[256];
    const char *rest;
    char *end;
    long value;
    int pos = 0;

    if (sscanf(line, " \"%255[^\"]\": %n", key_buf, &pos) != 1)
        return;
    rest = line + pos;
    errno = 0;
    value = strtol(rest, &end, 10);
    if (end == rest || errno == ERANGE)
        return; /* malformed or out of range: leave the field untouched */

    if (strcmp(key_buf, "chain_depth") == 0)
    {
        /* chain_depth is used as an array bound: reject anything outside
         * [0, PERSIST_CHAIN_MAX] at the parse boundary. */
        if (value >= 0 && value <= PERSIST_CHAIN_MAX)
        {
            e->chain_depth = (int)value;
        }
        else
        {
            log_msg(LOG_WARNING,
                    "persist_load: chain_depth %ld out of range [0,%d], "
                    "clamping",
                    value, PERSIST_CHAIN_MAX);
            e->chain_depth = value < 0 ? 0 : PERSIST_CHAIN_MAX;
        }
    }
    else if (strcmp(key_buf, "created_at") == 0)
    {
        e->created_at = (time_t)value;
    }
}

/*
 * A stored rule ID is exactly 16 lowercase hex digits.  ruleid.c generates
 * the values; this parser is the trust boundary that keeps a hand-edited
 * state file from admitting an ID the CLI could never address.  The field
 * holds one byte more than the canonical value, so a valid ID is copied
 * whole and never reaches copy_field()'s truncation path.
 */
static int valid_rule_id(const char *value)
{
    int i;

    if (!value || strlen(value) != 16)
        return 0;
    for (i = 0; i < 16; i++)
    {
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return 0;
    }
    return 1;
}

/*
 * The value reaches this point through the JSON extractor, which decodes
 * escapes: a \n in a hand-edited value could otherwise forge journal
 * lines.  Log a capped, sanitized copy instead of the raw bytes.
 */
static void log_bad_rule_id(const char *filepath, const char *value)
{
    char safe[33];
    size_t i;

    for (i = 0; i < sizeof(safe) - 1 && value[i] != '\0'; i++)
    {
        unsigned char c = (unsigned char)value[i];
        safe[i] = (c < 0x20 || c == 0x7f) ? '?' : (char)c;
    }
    safe[i] = '\0';
    log_msg(LOG_WARNING,
            "persist_load: %s: invalid rule_id \"%s%s\"; dropping the entry "
            "(want 16 lowercase hex chars)",
            filepath, safe, value[i] != '\0' ? "..." : "");
}

/*
 * Validate and store one parsed "rule_id".  Returns 0 for a present but
 * malformed value: the caller drops the whole entry, mirroring the
 * per-entry admission fanotify's load_dyn_list applies to incomplete
 * entries.
 */
static int apply_rule_id(const char *filepath, PersistEntry *e,
                         const char *value)
{
    if (!valid_rule_id(value))
    {
        log_bad_rule_id(filepath, value);
        return 0;
    }
    memcpy(e->rule_id, value, sizeof(e->rule_id));
    return 1;
}

/*
 * persist_load: read a runtime allow/deny state file.  The reader
 * accepts exactly the shape persist_save() writes, scanned line by line:
 *
 *   {
 *     "entries": [
 *       {
 *         "rule_id": "0123456789abcdef",
 *         "binary": "...", "binary_sha512": "...", "target_path": "...",
 *         "cmdline": "...", "cmdline_sha512": "...",
 *         "chain_depth": 2, "created_at": 123,
 *         "chain_comm[0]": "...", ... "chain_sha512[j]": "..."
 *       },
 *       ...
 *     ]
 *   }
 *
 * Each line holds at most one "key": "value" string pair or one numeric
 * field.  Blank lines, comments (#) and unknown keys are tolerated.
 * Damage is layered by what it can affect:
 *
 *   - file-damaging (returns -1; the caller clears the in-memory
 *     lists): open/read errors (including a root-run ownership,
 *     permission or symlink refusal of the file itself), a line longer
 *     than JSON_LINE_MAX (which the writer can never emit), and
 *     structural incompleteness (no "entries" array, a missing ] or },
 *     an entry cut off mid-way).  A partial or foreign file must never
 *     load as state.
 *   - entry-damaging (dropped at that entry's '}', the file still
 *     loads): a present-but-malformed rule_id, or a string value on a
 *     known numeric field -- admitting either would silently weaken a
 *     stored rule.
 *   - field-damaging (the entry may still load): an over-long value is
 *     truncated by copy_field() with a warning; a non-rule_id value
 *     whose escapes cannot be decoded is left at its default, and the
 *     caller's completeness check later drops an entry that ends up
 *     missing a key.
 *
 * A line without a rule_id is legacy state and loads with an empty ID
 * (the daemon assigns one when migrating).
 */
int persist_load(const char *filepath, PersistEntry *out_entries, int max_entries)
{
    FILE *fp;
    /* One convention with the pin-table parser (JSON_LINE_MAX): a line
     * this reader must handle is one the runtime-list writer can emit
     * for a near-PATH_MAX field with escapes. */
    char line[JSON_LINE_MAX];
    PersistEntry *current = NULL;
    int count = 0;
    int warned_truncated = 0;
    int saw_entries = 0;
    int closed_array = 0;
    int closed_object = 0;
    /* Per-entry rule_id tracking: PersistEntry stays flag-free, so an
     * absent key and a present-but-malformed value are told apart here. */
    int have_rule_id = 0;
    int rule_id_valid = 0;
    /* Set when a known numeric field carries a string value: the entry
     * must not be admitted with a weakened (default) value. */
    int entry_damaged = 0;

    /*
     * Minimal line-oriented scanner: just enough JSON structure to find
     * the "entries" array and one object per entry, then apply fields
     * line by line.  Comments (#) and unknown keys are tolerated so the
     * state files stay hand-editable.
     */
    enum
    {
        S_OUTSIDE,
        S_IN_ENTRIES,
        S_IN_ENTRY
    } state = S_OUTSIDE;

    if (!out_entries || max_entries <= 0)
        return 0;

    memset(out_entries, 0, sizeof(*out_entries) * max_entries);

    fp = fopen(filepath, "r");
    if (!fp)
    {
        if (errno == ENOENT)
            return 0;
        log_msg(LOG_ERR, "persist_load: open %s: %s", filepath,
                strerror(errno));
        return -1;
    }

    /*
     * Root-run trust bar (persist_file_trusted): a state file another
     * user can modify is a privilege-escalation path (a planted
     * allow/deny rule); refusal is fail-secure -- the caller clears the
     * list.  ENOENT above is untouched and still means an empty table.
     */
    if (persist_file_trusted(fp, filepath, "persist_load") < 0)
    {
        fclose(fp);
        return -1; /* fail secure: the caller clears the list */
    }

    /* Scan to EOF even past the entry cap so truncation is detected and
     * reported instead of silently dropping grants. */
    while (fgets(line, sizeof(line), fp))
    {
        if (!strchr(line, '\n') && !feof(fp))
        {
            /* A line longer than any persist_save() can emit: the file
             * was not written by the daemon or is corrupt.  Fail instead
             * of parsing a split line as valid structure. */
            log_msg(LOG_ERR,
                    "persist_load: %s has a line longer than %d bytes; "
                    "ignoring the state file",
                    filepath, JSON_LINE_MAX - 1);
            fclose(fp);
            return -1;
        }
        char *p = line;

        while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
            p++;

        if (!*p || *p == '#')
            continue;

        /* Detect the "entries": [ array opener. */
        if (state == S_OUTSIDE && strstr(p, "\"entries\":") != NULL)
        {
            saw_entries = 1;
            state = S_IN_ENTRIES;
            continue;
        }

        /* Entry start: opening brace inside the entries array. */
        if (state == S_IN_ENTRIES && *p == '{')
        {
            have_rule_id = 0;
            rule_id_valid = 0;
            entry_damaged = 0;
            if (count >= max_entries)
            {
                /* Make truncation at the caller's cap visible: silently
                 * ignoring entries would hide grants from review. */
                if (!warned_truncated)
                {
                    log_msg(LOG_WARNING,
                            "persist_load: %s holds more than %d entries; "
                            "truncating", filepath, max_entries);
                    warned_truncated = 1;
                }
                /* Over the cap: skip the fields but keep tracking the
                 * object's braces so the state machine still advances. */
                current = NULL;
            }
            else
            {
                current = &out_entries[count];
                memset(current, 0, sizeof(*current));
            }
            state = S_IN_ENTRY;
            continue;
        }

        /* Entry end: closing brace.  Sanitise and finalise. */
        if (state == S_IN_ENTRY && *p == '}')
        {
            /* A present-but-malformed rule_id, or a string where a
             * numeric field belongs (both logged at the field), drops
             * this entry only: one damaged line must not fail the rest
             * of the file. */
            if (current && (!have_rule_id || rule_id_valid) && !entry_damaged)
            {
                /* Defense in depth: never index arrays with an out-of-range
                 * depth, even if a previous validation step was bypassed. */
                if (current->chain_depth < 0)
                    current->chain_depth = 0;
                if (current->chain_depth > PERSIST_CHAIN_MAX)
                    current->chain_depth = PERSIST_CHAIN_MAX;
                for (int k = current->chain_depth; k < PERSIST_CHAIN_MAX; k++)
                {
                    current->chain_comm[k][0] = '\0';
                    current->chain_sha512[k][0] = '\0';
                }
                count++;
            }
            current = NULL;
            state = S_IN_ENTRIES;
            continue;
        }

        /* End of entries array or outer closing brace.  A '}' seen
         * while inside the array is tolerated as a missing ']'
         * hand-edit; the completeness check still requires the outer
         * '}'. */
        if ((state == S_IN_ENTRIES && (*p == ']' || *p == '}')) ||
            (state == S_OUTSIDE && *p == '}'))
        {
            if (state == S_IN_ENTRIES)
            {
                closed_array = 1;
                state = S_OUTSIDE;
            }
            else
                closed_object = 1;
            continue;
        }

        /* No field to apply on this line: array/object clutter, a line
         * outside any entry, or a field of an over-cap entry. */
        if (state != S_IN_ENTRY || !current)
            continue;

        /* Parse key-value pairs.  String values are decoded escape-aware
         * (command lines routinely contain quotes); numeric fields fall
         * through to apply_entry_number().  Patterns intentionally omit
         * the trailing comma so they match both "value", and "value".
         * The value buffer uses the shared escape bound: a near-PATH_MAX
         * field of escapable bytes must survive extraction, not be
         * dropped by its own reader. */
        char key_buf[256], val_buf[JSON_ESCAPED_MAX];
        if (persist_json_extract_string(p, key_buf, sizeof(key_buf), val_buf,
                                        sizeof(val_buf)))
        {
            /* rule_id is tracked separately: a present-but-malformed value
             * must drop the whole entry, not be copied like a free-form
             * field. */
            if (strcmp(key_buf, "rule_id") == 0)
            {
                have_rule_id = 1;
                rule_id_valid = apply_rule_id(filepath, current, val_buf);
            }
            else if (apply_entry_field(filepath, current, key_buf, val_buf) < 0)
                entry_damaged = 1;
        }
        else
        {
            /* A rule_id line the extractor could not decode (truncated,
             * malformed escape, oversized value) is still a present key:
             * reject the entry instead of letting it load as legacy state.
             * val_buf is empty on extraction failure, so the warning shows
             * an empty offending value. */
            char failed_key[256];

            if (sscanf(p, " \"%255[^\"]\"", failed_key) == 1 &&
                strcmp(failed_key, "rule_id") == 0)
            {
                have_rule_id = 1;
                rule_id_valid = 0;
                log_bad_rule_id(filepath, val_buf);
            }
            else
                /* Not rule_id: only the known numeric fields can still
                 * apply; an unknown or undecodable line is tolerated. */
                apply_entry_number(current, p);
        }
    }

    if (ferror(fp))
    {
        log_msg(LOG_ERR, "persist_load: read error on %s; ignoring the "
                "state file", filepath);
        fclose(fp);
        return -1; /* fail secure: the caller clears the in-memory list */
    }

    /* Structural completeness: a truncated or foreign file must not be
     * accepted as an empty or partial state.  The caller clears the
     * in-memory list on -1, which fails closed (re-prompt/re-hash) and
     * is visible in the journal. */
    if (!saw_entries || !closed_array || !closed_object || state != S_OUTSIDE)
    {
        log_msg(LOG_ERR,
                "persist_load: %s is truncated or malformed; ignoring the "
                "state file", filepath);
        fclose(fp);
        return -1; /* fail secure: the caller clears the in-memory list */
    }

    fclose(fp);
    log_msg(LOG_INFO, "persist_load: loaded %d entries from %s", count, filepath);
    return count;
}

int persist_write_text(const char *filepath, const char *text)
{
    char tmp_file[PATH_MAX];
    FILE *fp;
    size_t len;
    int fd;

    if (!filepath || !text)
        return -1;

    if (ensure_parent_dir(filepath) < 0)
        return -1;

    fd = open_atomic_temp(filepath, "persist_write_text", tmp_file,
                          sizeof(tmp_file));
    if (fd < 0)
        return -1;

    fp = fdopen(fd, "w");
    if (!fp)
    {
        log_msg(LOG_ERR, "persist_write_text: fdopen %s: %s", tmp_file,
                strerror(errno));
        close(fd);
        unlink(tmp_file);
        return -1;
    }

    len = strlen(text);
    if (fwrite(text, 1, len, fp) != len)
    {
        log_msg(LOG_ERR, "persist_write_text: write %s: %s", tmp_file,
                strerror(errno));
        fclose(fp);
        unlink(tmp_file);
        return -1;
    }

    if (commit_atomic_temp(fp, tmp_file, filepath, "persist_write_text") < 0)
        return -1;

    log_msg(LOG_INFO, "persist_write_text: wrote %zu bytes to %s", len, filepath);
    return 0;
}

/*
 * Escape one field into the scratch buffer, or fail the save.  Writing an
 * empty string on overflow (previous behavior) silently dropped the entry
 * on the next load; failing keeps the previous state file intact and makes
 * the refusal visible in the journal.
 */
#define SAVE_ESCAPED(field, value)                                            \
    do                                                                        \
    {                                                                         \
        if (persist_json_escape((value), escaped, sizeof(escaped)) < 0)       \
        {                                                                     \
            log_msg(LOG_ERR,                                                  \
                    "persist_save: %s does not fit the escape buffer; "       \
                    "not saving", (field));                                   \
            fclose(fp);                                                       \
            unlink(tmp_file);                                                 \
            return -1;                                                        \
        }                                                                     \
    } while (0)

/*
 * persist_save: serialize entries[0..count-1] in exactly the shape
 * persist_load() reads and commit it atomically (temp file, fsync,
 * rename): until the rename the previous file is untouched, so a
 * failure never leaves a half-written state file behind.
 *
 * Returns 0 on success; -1 for out-of-range arguments, a field that
 * does not fit the escape buffer, or any write failure.  Memory is not
 * touched: callers that mirror a live table on disk must roll their
 * in-memory changes back on -1 (fanotify.c and pin.c do).
 */
int persist_save(const char *filepath, const PersistEntry *entries, int count)
{
    FILE *fp;
    int i, j;
    char tmp_file[PATH_MAX];
    char escaped[JSON_ESCAPED_MAX];
    int fd;

    if (!entries || count < 0 || count > PERSIST_MAX_ENTRIES)
        return -1;

    if (ensure_parent_dir(filepath) < 0)
        return -1;

    fd = open_atomic_temp(filepath, "persist_save", tmp_file, sizeof(tmp_file));
    if (fd < 0)
        return -1;

    fp = fdopen(fd, "w");
    if (!fp)
    {
        log_msg(LOG_ERR, "persist_save: fdopen %s: %s", tmp_file, strerror(errno));
        close(fd);
        unlink(tmp_file);
        return -1;
    }

    fprintf(fp, "{\n");
    fprintf(fp, "  \"entries\": [\n");

    for (i = 0; i < count; i++)
    {
        const PersistEntry *e = &entries[i];

        fprintf(fp, "    {\n");

        /* First field in the object so the ID is visible at a glance. */
        SAVE_ESCAPED("rule_id", e->rule_id);
        fprintf(fp, "      \"rule_id\": \"%s\",\n", escaped);

        SAVE_ESCAPED("binary", e->binary);
        fprintf(fp, "      \"binary\": \"%s\",\n", escaped);

        SAVE_ESCAPED("binary_sha512", e->binary_sha512);
        fprintf(fp, "      \"binary_sha512\": \"%s\",\n", escaped);

        SAVE_ESCAPED("target_path", e->target_path);
        fprintf(fp, "      \"target_path\": \"%s\",\n", escaped);

        SAVE_ESCAPED("cmdline", e->cmdline);
        fprintf(fp, "      \"cmdline\": \"%s\",\n", escaped);

        SAVE_ESCAPED("cmdline_sha512", e->cmdline_sha512);
        fprintf(fp, "      \"cmdline_sha512\": \"%s\",\n", escaped);

        fprintf(fp, "      \"chain_depth\": %d,\n", e->chain_depth);
        fprintf(fp, "      \"created_at\": %ld,\n", (long)e->created_at);

        /* chain_comm always gets a trailing comma: chain_sha512 fields follow. */
        for (j = 0; j < PERSIST_CHAIN_MAX; j++)
        {
            SAVE_ESCAPED("chain_comm", e->chain_comm[j]);
            fprintf(fp, "      \"chain_comm[%d]\": \"%s\",\n", j, escaped);
        }

        /* Last chain_sha512 field has no trailing comma (closes the object). */
        for (j = 0; j < PERSIST_CHAIN_MAX; j++)
        {
            SAVE_ESCAPED("chain_sha512", e->chain_sha512[j]);
            fprintf(fp, "      \"chain_sha512[%d]\": \"%s\"%s\n", j, escaped,
                    j < PERSIST_CHAIN_MAX - 1 ? "," : "");
        }

        fprintf(fp, "    }%s\n", i < count - 1 ? "," : "");
    }

    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    if (commit_atomic_temp(fp, tmp_file, filepath, "persist_save") < 0)
        return -1;

    log_msg(LOG_INFO, "persist_save: saved %d entries to %s", count, filepath);
    return 0;
}
