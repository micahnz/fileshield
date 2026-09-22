/*
 * pin.c - hash pins for [allowlist] rules (see pin.h for the contract).
 *
 * The module keeps a bounded in-memory table and mirrors it to a strict,
 * atomically written JSON file.  Parsing fails closed: one anomaly
 * anywhere in an existing file marks the whole file damaged instead of
 * silently dropping entries, because dropping one would re-TOFU its rule.
 *
 * pin_load_file()/pin_write_file() expose that parser and serializer
 * without daemon state, so fileshield-cli can manage the pin file
 * directly; the daemon's pin_load()/pin_store() are built on them.
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "pin.h"
#include "persist.h"
#include "ruleid.h"
#include "utils.h"

/*
 * A pattern is at most PATH_MAX-1 bytes and persist_json_escape() may
 * encode one byte as six (\uXXXX), so one serialized line can reach
 * 6*PATH_MAX plus the field wrapper.  The parser needs line and value
 * buffers of that size; the writer an escaped scratch buffer.  The
 * bounds are shared with persist.c (persist.h).
 */
#define PIN_LINE_MAX JSON_LINE_MAX
#define PIN_ESCAPED_MAX JSON_ESCAPED_MAX

typedef struct
{
    char pattern[PATH_MAX];
    char sha512[129];
    time_t updated_at;
    unsigned long seq; /* store order: updated_at tie-break */
} PinEntry;

/* One entry under construction plus "was this key seen" flags. */
typedef struct
{
    PinRecord pin;
    int have_pattern;
    int have_sha512;
    int have_updated_at;
} PinDraft;

static PinEntry g_pins[PIN_MAX];
static int g_pin_count;
static int g_pin_damaged;
static unsigned long g_pin_seq;
static char g_state_file[PATH_MAX] = PIN_STATE_FILE;

/*
 * Staging for pin_load() (a damaged file is parsed here and never
 * disturbs g_pins) and, on the write side, the public row copy that the
 * table mutations serialize.  The single-threaded daemon never overlaps
 * the two uses.
 */
static PinRecord g_stage[PIN_MAX];

/*
 * Restore-on-write-failure snapshot for pin_store(), pin_remove_by_id()
 * and pin_clear(): memory is committed only after the write succeeded.
 */
static PinEntry g_snapshot[PIN_MAX];

/* Exactly 128 lowercase hex characters: sha512sum's canonical output
 * form and the form pin_check() compares byte-for-byte, so an uppercase
 * value is rejected instead of deriving the same ID but never
 * matching. */
static int is_valid_sha512(const char *s)
{
    size_t i;

    if (!s || strlen(s) != 128)
        return 0;
    for (i = 0; i < 128; i++)
    {
        if (!((s[i] >= '0' && s[i] <= '9') ||
              (s[i] >= 'a' && s[i] <= 'f')))
            return 0;
    }
    return 1;
}

/* Pin keys are the canonical absolute binary patterns from config.c. */
static int is_valid_pattern(const char *p)
{
    return p && p[0] == '/' && strlen(p) < PATH_MAX;
}

/*
 * Parse one '"key": <long>' numeric pair (strict: only whitespace and an
 * optional trailing comma may follow the number).  Returns 1 with
 * *key_out and *out populated when the line is a well-formed numeric
 * field, 0 otherwise.
 */
static int parse_numeric_field(const char *line, char *key_out,
                               size_t keysz, long *out)
{
    char key[256];
    const char *rest;
    char *end;
    long value;
    size_t klen;
    int pos = 0;

    if (sscanf(line, " \"%255[^\"]\": %n", key, &pos) != 1)
        return 0;

    /* strtol (not scanf %ld): out-of-range values must be rejected, not
     * undefined.  A hand-edited file is exactly the damaged-file case. */
    rest = line + pos;
    errno = 0;
    value = strtol(rest, &end, 10);
    if (end == rest || errno == ERANGE)
        return 0;

    rest = end;
    while (*rest == ' ' || *rest == '\t')
        rest++;
    if (*rest == ',')
        rest++;
    while (*rest == ' ' || *rest == '\t' || *rest == '\r' || *rest == '\n')
        rest++;
    if (*rest != '\0')
        return 0;

    if (key_out && keysz > 0)
    {
        klen = strlen(key);
        if (klen >= keysz)
            klen = keysz - 1;
        memcpy(key_out, key, klen);
        key_out[klen] = '\0';
    }
    *out = value;
    return 1;
}

/*
 * Apply one decoded string field to the entry under construction.
 * Returns 0 to continue, -1 when a known key carries a bad value (the
 * whole file is then marked damaged).
 */
static int apply_string_field(PinDraft *d, const char *key, const char *value)
{
    size_t len;

    if (strcmp(key, "pattern") == 0)
    {
        len = strlen(value);
        if (!is_valid_pattern(value))
            return -1;
        memcpy(d->pin.pattern, value, len + 1);
        d->have_pattern = 1;
        return 0;
    }
    if (strcmp(key, "sha512") == 0)
    {
        if (!is_valid_sha512(value))
            return -1;
        memcpy(d->pin.sha512, value, 129); /* 128 validated chars + NUL */
        d->have_sha512 = 1;
        return 0;
    }
    if (strcmp(key, "updated_at") == 0)
        return -1; /* numeric field with a string value */

    return 0; /* unknown string key: ignore for forward compatibility */
}

/*
 * 1 when 'pattern' already appears in out[0..count-1].  Duplicate
 * patterns derive the same pin ID for two rows, so fileshield-cli could
 * never address them unambiguously; pin_read_entries() treats the file
 * as damaged instead of silently keeping one of the duplicates.
 */
static int has_duplicate_pattern(const PinRecord *out, int count,
                                 const char *pattern)
{
    int i;

    for (i = 0; i < count; i++)
    {
        if (strcmp(out[i].pattern, pattern) == 0)
            return 1;
    }
    return 0;
}

/*
 * Parse an open pin file into out[0..max-1].  The reader accepts exactly
 * the shape pin_serialize_records() writes, scanned line by line:
 *
 *   {
 *     "pins": [
 *       {
 *         "pattern": "...",
 *         "sha512": "...",       each value on its key's line
 *         "updated_at": 123
 *       },
 *       ...
 *     ]
 *   }
 *
 * State machine: S_OUTSIDE -> ("pins": [) S_IN_PINS -> ({) S_IN_ENTRY
 * -> (} with all three fields) S_IN_PINS -> (]) S_OUTSIDE -> (}) S_DONE.
 * An entry reaches 'out' only when it is complete, and the caller zeroes
 * 'out' on failure, so a damaged file never yields a partial table.
 *
 * Staging model: this function writes only into the caller's 'out'
 * array.  pin_load_file() zeroes that array on -1, and pin_load()
 * parses into g_stage and copies into g_pins only after a count came
 * back, so a damaged file can neither publish a partial table nor
 * silently drop one bad row from the live table.
 *
 * Blank lines, comments (#) and unknown keys are tolerated; a second
 * "pins" array, junk after an entry close, an incomplete entry, a
 * duplicate pattern, a missing closer or more entries than max marks
 * the whole file damaged (fail closed).  Returns the entry count, or
 * -1 on any anomaly.
 */
static int pin_read_entries(FILE *fp, const char *path, PinRecord *out,
                            int max)
{
    char line[PIN_LINE_MAX];
    char key[256];
    char value[PIN_LINE_MAX];
    PinDraft draft;
    PinDraft *cur = NULL;
    int count = 0;
    int saw_pins = 0;
    int closed_array = 0;
    int closed_object = 0;
    int ok = 1;
    enum
    {
        S_OUTSIDE,
        S_IN_PINS,
        S_IN_ENTRY,
        S_DONE
    } state = S_OUTSIDE;

    memset(&draft, 0, sizeof(draft));

    while (ok && fgets(line, sizeof(line), fp))
    {
        if (!strchr(line, '\n') && !feof(fp))
        {
            /* A line longer than any writer can emit: the file was not
             * written by the daemon or is corrupt.  Fail instead of
             * parsing a split line as valid structure (the same
             * convention persist_load() enforces). */
            log_msg(LOG_ERR,
                    "pin_load_file: %s has a line longer than %d bytes; "
                    "ignoring the pin file",
                    path, PIN_LINE_MAX - 1);
            ok = 0;
            break;
        }
        char *p = line;
        char *pins_key;

        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
        if (*p == '\0' || *p == '#')
            continue;

        switch (state)
        {
        case S_OUTSIDE:
            pins_key = strstr(p, "\"pins\":");
            if (pins_key != NULL)
            {
                if (saw_pins)
                {
                    /* A second "pins" array is structural damage; the
                     * first array's pins would silently win. */
                    ok = 0;
                    break;
                }
                char *q = pins_key + 7; /* just after the "pins": key */

                saw_pins = 1;
                while (*q == ' ' || *q == '\t')
                    q++;
                if (*q != '[')
                {
                    ok = 0; /* "pins" must open the array */
                    break;
                }
                q++;
                while (*q == ' ' || *q == '\t')
                    q++;
                if (*q == ']')
                {
                    /* "pins": [] on one line; nothing may follow it. */
                    q++;
                    while (*q == ' ' || *q == '\t' || *q == '\r' ||
                           *q == '\n')
                        q++;
                    if (*q != '\0')
                        ok = 0;
                    else
                        closed_array = 1;
                }
                else if (*q == '\0' || *q == '\r' || *q == '\n')
                {
                    /* Array opener alone on its line. */
                    state = S_IN_PINS;
                }
                else
                {
                    /* Content on the opener line cannot be parsed by
                     * this line-oriented reader; accepting it as an
                     * empty array would silently drop pins. */
                    ok = 0;
                }
            }
            else if (*p == '{' || *p == '"')
            {
                /* Outer object opener / unknown top-level key. */
            }
            else if (*p == '}')
            {
                closed_object = 1;
                state = S_DONE;
            }
            else
            {
                ok = 0; /* structural anomaly */
            }
            break;

        case S_IN_PINS:
            if (*p == '[')
            {
                /* Array opener on its own line. */
                char *q = p + 1;
                while (*q == ' ' || *q == '\t')
                    q++;
                if (*q != '\0' && *q != '\r' && *q != '\n')
                    ok = 0; /* content on the opener line is unsupported */
            }
            else if (*p == '{')
            {
                if (count >= max || strchr(p, '}') != NULL)
                {
                    /* More entries than the caller can hold / unsupported
                     * one-liner: damage, never a silent drop. */
                    ok = 0;
                    break;
                }
                memset(&draft, 0, sizeof(draft));
                cur = &draft;
                state = S_IN_ENTRY;
            }
            else if (*p == ']')
            {
                char *q = p + 1;

                while (*q == ' ' || *q == '\t')
                    q++;
                if (*q != '\0' && *q != '\r' && *q != '\n')
                {
                    ok = 0; /* junk after the array close */
                    break;
                }
                closed_array = 1;
                state = S_OUTSIDE;
            }
            else
            {
                ok = 0;
            }
            break;

        case S_IN_ENTRY:
            if (cur == NULL)
            {
                ok = 0;
                break;
            }
            if (*p == '}')
            {
                /* Only whitespace, an optional entry comma and the
                 * newline may follow the close: anything else is junk
                 * this line-oriented reader would silently ignore. */
                const char *q = p + 1;
                while (*q == ' ' || *q == '\t')
                    q++;
                if (*q == ',')
                    q++;
                while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n')
                    q++;
                if (*q != '\0' || !cur->have_pattern || !cur->have_sha512 ||
                    !cur->have_updated_at)
                {
                    ok = 0; /* junk after the close, or incomplete entry:
                             * never dropped or tolerated silently */
                    break;
                }
                if (has_duplicate_pattern(out, count, cur->pin.pattern))
                {
                    /* Two rows with one derived ID can never be managed
                     * unambiguously through the CLI.  Damage the whole
                     * file (prompt/TOFU semantics) rather than silently
                     * keeping one of the duplicates. */
                    log_msg(LOG_ERR,
                            "pin_load_file: %s: duplicate pattern \"%s\"; "
                            "ignoring the pin file (fail closed)",
                            path, cur->pin.pattern);
                    ok = 0;
                    break;
                }
                /* Complete, unique entry: the only point a draft is
                 * allowed to reach 'out'. */
                out[count] = cur->pin;
                count++;
                cur = NULL;
                state = S_IN_PINS;
                break;
            }

            if (persist_json_extract_string(p, key, sizeof(key), value,
                                            sizeof(value)))
            {
                if (apply_string_field(cur, key, value) < 0)
                    ok = 0;
            }
            else
            {
                long num;

                if (!parse_numeric_field(p, key, sizeof(key), &num))
                {
                    ok = 0; /* neither a string field nor a number */
                }
                else if (strcmp(key, "updated_at") == 0)
                {
                    if (num < 0)
                    {
                        ok = 0;
                    }
                    else
                    {
                        cur->pin.updated_at = (time_t)num;
                        cur->have_updated_at = 1;
                    }
                }
                else if (strcmp(key, "pattern") == 0 ||
                         strcmp(key, "sha512") == 0)
                {
                    ok = 0; /* known string key with a numeric value */
                }
                /* else: unknown numeric key, ignored. */
            }
            break;

        case S_DONE:
            ok = 0; /* nothing may follow the outer object */
            break;
        }
    }

    if (ferror(fp))
        ok = 0;

    /* Every closer must have been seen and no entry may still be open:
     * a file cut off at any point fails here instead of loading the
     * prefix that was parsed so far. */
    if (!ok || !saw_pins || !closed_array || !closed_object ||
        state == S_IN_ENTRY)
    {
        log_msg(LOG_ERR,
                "pin_load_file: %s is damaged; no table was loaded "
                "(fail closed)",
                path);
        return -1;
    }
    return count;
}

int pin_load_file(const char *filepath, PinRecord *out, int max,
                  int *damaged_out)
{
    FILE *fp;
    int count;

    if (damaged_out)
        *damaged_out = 0;
    if (!filepath || filepath[0] == '\0' || !out || max < 1)
    {
        if (damaged_out)
            *damaged_out = 1;
        log_msg(LOG_ERR, "pin_load_file: invalid arguments");
        return -1;
    }
    /* A missing file reports an empty table; a parse failure zeroes the
     * table again below, so 'out' is never left partially filled. */
    memset(out, 0, (size_t)max * sizeof(*out));

    fp = fopen(filepath, "r");
    if (!fp)
    {
        if (errno == ENOENT)
        {
            log_msg(LOG_INFO,
                    "pin_load_file: %s not present; starting with no pins",
                    filepath);
            return 0;
        }
        log_msg(LOG_ERR, "pin_load_file: open %s: %s", filepath,
                strerror(errno));
        if (damaged_out)
            *damaged_out = 1;
        return -1;
    }

    /*
     * Same trust bar as config_load() and persist_load()
     * (persist_file_trusted, root-run only): a pin file another user can
     * modify could silently re-pin a binary (the grant channel), so the
     * load is refused -- at least as strict as an fopen failure:
     * damaged_out=1, never an empty/TOFU table.  The ENOENT branch above
     * is untouched and still means TOFU.
     */
    if (persist_file_trusted(fp, filepath, "pin_load_file") < 0)
    {
        fclose(fp);
        if (damaged_out)
            *damaged_out = 1;
        return -1;
    }

    count = pin_read_entries(fp, filepath, out, max);
    fclose(fp);

    if (count < 0)
    {
        memset(out, 0, (size_t)max * sizeof(*out));
        if (damaged_out)
            *damaged_out = 1;
        return -1;
    }
    log_msg(LOG_INFO, "pin_load_file: loaded %d pin(s) from %s", count,
            filepath);
    return count;
}

int pin_damaged(void)
{
    return g_pin_damaged;
}

int pin_load(const char *filepath)
{
    const char *path = (filepath && filepath[0] != '\0') ? filepath
                                                         : g_state_file;
    int count;
    int i;

    /* Stage into g_stage: pin_load_file() zeroes its output on failure,
     * so a damaged file leaves the previously loaded (now untrusted)
     * table in g_pins untouched. */
    count = pin_load_file(path, g_stage, PIN_MAX, NULL);
    if (count < 0)
    {
        g_pin_damaged = 1;
        return -1;
    }

    for (i = 0; i < count; i++)
    {
        memcpy(g_pins[i].pattern, g_stage[i].pattern,
               sizeof(g_pins[i].pattern));
        memcpy(g_pins[i].sha512, g_stage[i].sha512, sizeof(g_pins[i].sha512));
        g_pins[i].updated_at = g_stage[i].updated_at;
        g_pins[i].seq = (unsigned long)i;
    }
    g_pin_count = count;
    g_pin_seq = (unsigned long)count;
    g_pin_damaged = 0;
    /* Clear slots beyond the loaded table: stale pins from an earlier,
     * larger load must never become live (or be serialized) again. */
    for (i = count; i < PIN_MAX; i++)
        memset(&g_pins[i], 0, sizeof(g_pins[i]));
    return 0;
}

int pin_check(const char *pattern, const char *sha512, char old_out[129])
{
    int i;

    if (old_out)
        old_out[0] = '\0';

    if (g_pin_damaged)
        return PIN_CHECK_DAMAGED;
    if (!pattern || !is_valid_pattern(pattern) || !is_valid_sha512(sha512))
        return PIN_CHECK_DAMAGED;

    for (i = 0; i < g_pin_count; i++)
    {
        if (strcmp(g_pins[i].pattern, pattern) != 0)
            continue;
        if (strcmp(g_pins[i].sha512, sha512) == 0)
            return PIN_CHECK_MATCH;
        if (old_out)
            memcpy(old_out, g_pins[i].sha512, 129);
        return PIN_CHECK_CHANGED;
    }
    return PIN_CHECK_FIRST_USE;
}

/* Grow *buf so that 'need' bytes (including the NUL) fit. */
static int sb_reserve(char **buf, size_t *cap, size_t need)
{
    char *grown;
    size_t ncap = *cap;

    if (need <= ncap)
        return 0;
    while (ncap < need)
    {
        if (ncap > SIZE_MAX / 2)
            return -1;
        ncap *= 2;
    }
    grown = realloc(*buf, ncap);
    if (!grown)
        return -1;
    *buf = grown;
    *cap = ncap;
    return 0;
}

static int sb_append_n(char **buf, size_t *cap, size_t *len,
                       const char *s, size_t n)
{
    if (sb_reserve(buf, cap, *len + n + 1) < 0)
        return -1;
    memcpy(*buf + *len, s, n);
    *len += n;
    (*buf)[*len] = '\0';
    return 0;
}

static int sb_append(char **buf, size_t *cap, size_t *len, const char *s)
{
    return sb_append_n(buf, cap, len, s, strlen(s));
}

/*
 * Append one serialized row.  The live table and the pure writer share
 * this so the file a mutation persists and the file the CLI persists are
 * always the same shape.
 */
static int sb_append_pin_row(char **buf, size_t *cap, size_t *len,
                             const char *pattern, const char *sha512,
                             time_t updated_at, int comma)
{
    char escaped[PIN_ESCAPED_MAX];
    char num[32];
    int n;

    if (persist_json_escape(pattern, escaped, sizeof(escaped)) < 0)
        return -1;
    n = snprintf(num, sizeof(num), "%ld", (long)updated_at);
    if (n < 0 || (size_t)n >= sizeof(num))
        return -1;

    if (sb_append(buf, cap, len, "    {\n      \"pattern\": \"") < 0 ||
        sb_append(buf, cap, len, escaped) < 0 ||
        sb_append(buf, cap, len, "\",\n      \"sha512\": \"") < 0 ||
        sb_append(buf, cap, len, sha512) < 0 ||
        sb_append(buf, cap, len, "\",\n      \"updated_at\": ") < 0 ||
        sb_append(buf, cap, len, num) < 0 ||
        sb_append(buf, cap, len, "\n    }") < 0)
        return -1;
    if (comma && sb_append(buf, cap, len, ",") < 0)
        return -1;
    return sb_append(buf, cap, len, "\n");
}

/*
 * Serialize rows[0..count-1] into a freshly allocated JSON text (caller
 * frees).  Returns 0 on success, -1 on allocation failure or when a
 * pattern cannot be represented (defense in depth: load and write both
 * bound patterns to PATH_MAX-1, so this cannot happen for valid state).
 */
static int pin_serialize_records(const PinRecord *rows, int count,
                                 char **out_text)
{
    char *buf;
    size_t cap = 4096;
    size_t len = 0;
    int i;

    if (count < 0 || (count > 0 && !rows) || !out_text)
        return -1;

    buf = malloc(cap);
    if (!buf)
        return -1;
    buf[0] = '\0';

    if (sb_append(&buf, &cap, &len, "{\n  \"pins\": [\n") < 0)
        goto fail;

    for (i = 0; i < count; i++)
    {
        if (sb_append_pin_row(&buf, &cap, &len, rows[i].pattern,
                              rows[i].sha512, rows[i].updated_at,
                              i + 1 < count) < 0)
        {
            log_msg(LOG_ERR, "pin_serialize_records: entry %d does not fit",
                    i);
            goto fail;
        }
    }

    if (sb_append(&buf, &cap, &len, "  ]\n}\n") < 0)
        goto fail;

    *out_text = buf;
    return 0;

fail:
    free(buf);
    return -1;
}

int pin_write_file(const char *filepath, const PinRecord *rows, int count)
{
    char *text = NULL;
    int i;

    /* The format cap is checked before any row is touched: a table over
     * PIN_MAX would make the daemon load the file as damaged. */
    if (count > PIN_MAX)
    {
        log_msg(LOG_WARNING,
                "pin_write_file: count %d exceeds the %d-pin file limit",
                count, PIN_MAX);
        return -1;
    }
    if (!filepath || filepath[0] == '\0' || count < 0 ||
        (count > 0 && !rows))
    {
        log_msg(LOG_WARNING, "pin_write_file: invalid arguments");
        return -1;
    }

    /* Validate at the boundary: pin_write_file must never create a file
     * the strict loader would reject as damaged (absolute pattern below
     * PATH_MAX, 128-hex digest, non-negative timestamp). */
    for (i = 0; i < count; i++)
    {
        if (!is_valid_pattern(rows[i].pattern) ||
            !is_valid_sha512(rows[i].sha512) ||
            (long)rows[i].updated_at < 0)
        {
            log_msg(LOG_ERR,
                    "pin_write_file: row %d is not a valid pin; refusing "
                    "to write %s",
                    i, filepath);
            return -1;
        }
    }

    if (pin_serialize_records(rows, count, &text) < 0)
    {
        log_msg(LOG_WARNING,
                "pin_write_file: could not serialize the pin table");
        return -1;
    }
    if (persist_write_text(filepath, text) < 0)
    {
        free(text);
        log_msg(LOG_WARNING, "pin_write_file: could not write %s", filepath);
        return -1;
    }
    free(text);
    return 0;
}

/*
 * Copy the live table into the public row shape for serialization.  The
 * seq tie-break is daemon-only state and is deliberately not persisted.
 */
static void pin_table_rows(PinRecord *rows)
{
    int i;

    for (i = 0; i < g_pin_count; i++)
    {
        memcpy(rows[i].pattern, g_pins[i].pattern, sizeof(rows[i].pattern));
        memcpy(rows[i].sha512, g_pins[i].sha512, sizeof(rows[i].sha512));
        rows[i].updated_at = g_pins[i].updated_at;
    }
}

int pin_store(const char *pattern, const char *sha512)
{
    int i;
    int idx = -1;

    if (!is_valid_pattern(pattern) || !is_valid_sha512(sha512))
    {
        log_msg(LOG_WARNING, "pin_store: invalid pattern or sha512 argument");
        return -1;
    }

    if (g_pin_damaged)
    {
        log_msg(LOG_ERR, "pin_store: pin table is damaged; refusing to "
                         "overwrite %s (repair the file and reload first)",
                g_state_file);
        return -1;
    }

    /*
     * Stage on a snapshot and commit to memory only after the write
     * succeeded: a serialize or write failure must not leave the live
     * table diverged from disk (the eviction victim would be gone from
     * memory while its pin still exists on disk, silently re-TOFUing a
     * rule until the next successful store or restart).  The snapshot
     * is taken before the append increments g_pin_count: captured
     * after it, a failed write would restore a count one past the last
     * valid entry, leaving a phantom pin that the next successful
     * store would serialize (empty pattern -> damaged file, or a stale
     * pattern from an earlier larger load -> silent re-grant).
     */
    int snap_count = g_pin_count;
    unsigned long snap_seq = g_pin_seq;
    memcpy(g_snapshot, g_pins, sizeof(g_pins));

    /* One row per pattern: an existing pattern is refreshed in place,
     * a new one takes the next slot while the table has room. */
    for (i = 0; i < g_pin_count; i++)
    {
        if (strcmp(g_pins[i].pattern, pattern) == 0)
        {
            idx = i;
            break;
        }
    }

    if (idx < 0 && g_pin_count < PIN_MAX)
        idx = g_pin_count++;
    if (idx < 0)
    {
        /* Table full: evict the smallest updated_at; ties go to the
         * oldest store (a refresh counts as a store). */
        idx = 0;
        for (i = 1; i < g_pin_count; i++)
        {
            if (g_pins[i].updated_at < g_pins[idx].updated_at ||
                (g_pins[i].updated_at == g_pins[idx].updated_at &&
                 g_pins[i].seq < g_pins[idx].seq))
                idx = i;
        }
        log_msg(LOG_INFO, "pin_store: table full; evicting pin %s",
                g_pins[idx].pattern);
    }

    memcpy(g_pins[idx].pattern, pattern, strlen(pattern) + 1);
    memcpy(g_pins[idx].sha512, sha512, 129);
    g_pins[idx].updated_at = time(NULL);
    g_pins[idx].seq = g_pin_seq++;

    pin_table_rows(g_stage);
    if (pin_write_file(g_state_file, g_stage, g_pin_count) < 0)
    {
        log_msg(LOG_WARNING, "pin_store: could not write %s; the pre-store "
                             "table is kept in memory",
                g_state_file);
        goto restore;
    }
    log_msg(LOG_INFO, "pin_store: wrote %d pin(s) to %s", g_pin_count,
            g_state_file);
    return 0;

restore:
    memcpy(g_pins, g_snapshot, sizeof(g_pins));
    g_pin_count = snap_count;
    g_pin_seq = snap_seq;
    return -1;
}

/*
 * Validate a lookup prefix without consulting the table, so an invalid
 * argument is -1 even when the table is empty and "not found" is 0.
 * ruleid_prefix_match() validates both of its arguments: against a
 * well-formed constant it returns -1 exactly when 'id' is malformed, so
 * only the sign of its result is used here.
 */
static int pin_id_valid(const char *id)
{
    static const char probe[RULEID_HEX_LEN + 1] = "0000000000000000";

    return ruleid_prefix_match(probe, id) >= 0;
}

int pin_remove_by_id(const char *id)
{
    char ids[PIN_MAX][RULEID_HEX_LEN + 1];
    const char *id_ptrs[PIN_MAX] = {0}; /* count 0 passes an empty list */
    int ambiguous = 0;
    int snap_count;
    unsigned long snap_seq;
    int idx;
    int i;

    if (!id || !pin_id_valid(id))
    {
        log_msg(LOG_WARNING, "pin_remove_by_id: invalid id argument");
        return -1;
    }
    if (g_pin_damaged)
    {
        log_msg(LOG_ERR, "pin_remove_by_id: pin table is damaged; refusing "
                         "to overwrite %s (repair the file and reload first)",
                g_state_file);
        return -1;
    }

    /* Resolve through the same matcher the CLI uses: an unambiguous
     * 8..16-character lower-case hex prefix, full ID allowed. */
    for (i = 0; i < g_pin_count; i++)
    {
        if (ruleid_pin(g_pins[i].pattern, ids[i]) < 0)
        {
            /* Live patterns are always canonical; failing here means
             * the in-memory table cannot be trusted (fail closed). */
            log_msg(LOG_ERR, "pin_remove_by_id: pin %d has no usable ID", i);
            return -1;
        }
        id_ptrs[i] = ids[i];
    }

    idx = ruleid_find(id_ptrs, g_pin_count, id, &ambiguous);
    if (idx < 0)
    {
        if (ambiguous)
        {
            log_msg(LOG_WARNING, "pin_remove_by_id: id %s matches more "
                                 "than one pin; nothing removed",
                    id);
            return -2;
        }
        return 0; /* well-formed prefix, but no pin matches it */
    }

    /* Stage the removal like pin_store(): memory commits only after the
     * rewritten file lands, and the compaction keeps table order. */
    snap_count = g_pin_count;
    snap_seq = g_pin_seq;
    memcpy(g_snapshot, g_pins, sizeof(g_pins));

    for (i = idx; i + 1 < g_pin_count; i++)
        memcpy(&g_pins[i], &g_pins[i + 1], sizeof(g_pins[i]));
    g_pin_count--;
    /* Clear the vacated slot: a later append must not resurrect it. */
    memset(&g_pins[g_pin_count], 0, sizeof(g_pins[g_pin_count]));

    pin_table_rows(g_stage);
    if (pin_write_file(g_state_file, g_stage, g_pin_count) < 0)
    {
        log_msg(LOG_WARNING, "pin_remove_by_id: could not write %s; the "
                             "pre-removal table is kept in memory",
                g_state_file);
        goto restore;
    }
    log_msg(LOG_INFO, "pin_remove_by_id: removed pin %s (id %s) from %s",
            g_snapshot[idx].pattern, ids[idx], g_state_file);
    return 1;

restore:
    memcpy(g_pins, g_snapshot, sizeof(g_pins));
    g_pin_count = snap_count;
    g_pin_seq = snap_seq;
    return -1;
}

int pin_clear(void)
{
    int snap_count;
    unsigned long snap_seq;

    if (g_pin_damaged)
    {
        log_msg(LOG_ERR, "pin_clear: pin table is damaged; refusing to "
                         "overwrite %s (repair the file and reload first)",
                g_state_file);
        return -1;
    }

    snap_count = g_pin_count;
    snap_seq = g_pin_seq;
    memcpy(g_snapshot, g_pins, sizeof(g_pins));
    /* Zero the whole table, not just the count: stale patterns must
     * never become live (or be serialized) again. */
    memset(g_pins, 0, sizeof(g_pins));
    g_pin_count = 0;
    g_pin_seq = 0;

    if (pin_write_file(g_state_file, NULL, 0) < 0)
    {
        log_msg(LOG_WARNING, "pin_clear: could not write %s; the pre-clear "
                             "table is kept in memory",
                g_state_file);
        memcpy(g_pins, g_snapshot, sizeof(g_pins));
        g_pin_count = snap_count;
        g_pin_seq = snap_seq;
        return -1;
    }
    log_msg(LOG_INFO, "pin_clear: removed %d pin(s) from %s", snap_count,
            g_state_file);
    return 0;
}

void pin_set_state_file(const char *path)
{
    if (!path || path[0] == '\0')
    {
        memcpy(g_state_file, PIN_STATE_FILE, sizeof(PIN_STATE_FILE));
        return;
    }
    if (strlen(path) >= sizeof(g_state_file))
    {
        log_msg(LOG_ERR, "pin_set_state_file: path too long");
        return;
    }
    memcpy(g_state_file, path, strlen(path) + 1);
}
