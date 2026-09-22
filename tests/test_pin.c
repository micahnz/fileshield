#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/pin.h"
#include "../src/persist.h"
#include "../src/ruleid.h"

/* All tests run unprivileged against a per-pid temp directory. */
#define TEST_FILE_BUF (512 * 1024)
#define TPATH (PATH_MAX + 64) /* a state file path built from g_test_dir */
#define TTBUF (PATH_MAX + 96) /* path + ".tmp.<pid>"                    */

#define SHA_A \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define SHA_B \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define SHA_BAD \
    "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" \
    "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"

static char g_test_dir[256];
static char g_file_buf[TEST_FILE_BUF];

#define TEST_FAIL(msg)                      \
    do                                      \
    {                                       \
        fprintf(stderr, "FAIL: %s\n", msg); \
        return 1;                           \
    } while (0)

#define TEST_PASS(msg)                      \
    do                                      \
    {                                       \
        fprintf(stdout, "PASS: %s\n", msg); \
    } while (0)

#define ASSERT(cond, msg)   \
    do                      \
    {                       \
        if (!(cond))        \
            TEST_FAIL(msg); \
    } while (0)

static void make_test_path(char *out, size_t sz, const char *name)
{
    snprintf(out, sz, "%s/%s", g_test_dir, name);
}

static void make_tmp_path(char *out, size_t sz, const char *path)
{
    snprintf(out, sz, "%s.tmp.%d", path, (int)getpid());
}

static int write_raw_file(const char *path, const char *content)
{
    FILE *fp = fopen(path, "w");

    if (!fp)
        return -1;
    fputs(content, fp);
    if (ferror(fp))
    {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    /* 0600: a root-run pin_load() refuses group/other-writable files,
     * so raw fixtures must not depend on the ambient umask. */
    if (chmod(path, 0600) != 0)
        return -1;
    return 0;
}

/* Read a whole state file into g_file_buf (NUL-terminated). */
static long read_file(const char *path)
{
    FILE *fp = fopen(path, "r");
    size_t n;

    if (!fp)
        return -1;
    n = fread(g_file_buf, 1, sizeof(g_file_buf) - 1, fp);
    fclose(fp);
    g_file_buf[n] = '\0';
    return (long)n;
}

/* Point the module at 'path' and start from a missing file (clean). */
static int reset_pins(const char *path)
{
    unlink(path);
    pin_set_state_file(path);
    return pin_load(path);
}

static void build_valid_json(char *out, size_t sz, const char *pattern,
                             const char *sha, long updated_at)
{
    snprintf(out, sz,
             "{\n"
             "  \"pins\": [\n"
             "    {\n"
             "      \"pattern\": \"%s\",\n"
             "      \"sha512\": \"%s\",\n"
             "      \"updated_at\": %ld\n"
             "    }\n"
             "  ]\n"
             "}\n",
             pattern, sha, updated_at);
}

static int expect_damaged(const char *path, const char *content,
                          const char *what)
{
    if (write_raw_file(path, content) != 0)
    {
        fprintf(stderr, "FAIL: %s: cannot write test file\n", what);
        return 1;
    }
    if (pin_load(path) != -1)
    {
        fprintf(stderr, "FAIL: %s: pin_load did not fail\n", what);
        return 1;
    }
    if (pin_damaged() != 1)
    {
        fprintf(stderr, "FAIL: %s: pin_damaged not set\n", what);
        return 1;
    }
    return 0;
}

/* A PIN_MAX-entry table; the killed entry gets updated_at 1 or all
 * entries share one timestamp (tie-break case). */
static int write_full_pin_file(const char *path, int victim, int all_equal)
{
    FILE *fp = fopen(path, "w");
    int i;

    if (!fp)
        return -1;
    fputs("{\n  \"pins\": [\n", fp);
    for (i = 0; i < PIN_MAX; i++)
    {
        long updated = all_equal
                           ? 1000L
                           : ((i == victim) ? 1L : 100000L + i);

        fprintf(fp, "    {\n");
        fprintf(fp, "      \"pattern\": \"/usr/bin/gen-%03d\",\n", i);
        fprintf(fp, "      \"sha512\": \"" SHA_A "\",\n");
        fprintf(fp, "      \"updated_at\": %ld\n", updated);
        fprintf(fp, "    }%s\n", i + 1 < PIN_MAX ? "," : "");
    }
    fputs("  ]\n}\n", fp);
    if (ferror(fp))
    {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    /* 0600: keep root-run loads past the ownership/mode trust bar. */
    return chmod(path, 0600) == 0 ? 0 : -1;
}

static int write_over_cap_file(const char *path, int entries)
{
    FILE *fp = fopen(path, "w");
    int i;

    if (!fp)
        return -1;
    fputs("{\n  \"pins\": [\n", fp);
    for (i = 0; i < entries; i++)
    {
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"pattern\": \"/usr/bin/over-%03d\",\n", i);
        fprintf(fp, "      \"sha512\": \"" SHA_A "\",\n");
        fprintf(fp, "      \"updated_at\": %d\n", 1000 + i);
        fprintf(fp, "    }%s\n", i + 1 < entries ? "," : "");
    }
    fputs("  ]\n}\n", fp);
    if (ferror(fp))
    {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    /* 0600: keep root-run loads past the ownership/mode trust bar. */
    return chmod(path, 0600) == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/*  a pattern with quotes/backslashes survives the JSON escaping      */
/* ------------------------------------------------------------------ */

static int test_pattern_escaping(void)
{
    char path[TPATH];
    char old[129];
    const char *pattern = "/usr/bin/weird\"name\\x";

    make_test_path(path, sizeof(path), "escape.json");
    ASSERT(reset_pins(path) == 0, "reset");
    ASSERT(pin_store(pattern, SHA_A) == 0, "store an escaped pattern");
    ASSERT(read_file(path) > 0, "escaped state file readable");
    ASSERT(strstr(g_file_buf, "weird\\\"name\\\\x") != NULL,
           "state file escapes the quote and backslash");
    ASSERT(pin_load(path) == 0, "reload escaped state");
    ASSERT(pin_check(pattern, SHA_A, old) == PIN_CHECK_MATCH,
           "escaped pattern roundtrips");

    unlink(path);
    TEST_PASS("pattern escaping roundtrip");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  missing file = clean, empty table (normal first use)              */
/* ------------------------------------------------------------------ */

static int test_missing_file(void)
{
    char path[TPATH];
    char old[129];

    make_test_path(path, sizeof(path), "missing.json");
    pin_set_state_file(path);
    unlink(path);

    ASSERT(pin_load(path) == 0, "missing file loads as empty");
    ASSERT(pin_damaged() == 0, "missing file is not damaged");
    ASSERT(pin_check("/usr/bin/git", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "empty table reports first use");
    ASSERT(old[0] == '\0', "old_out cleared on first use");

    TEST_PASS("missing file = clean empty table");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  store -> immediate file -> fresh load -> check roundtrip          */
/* ------------------------------------------------------------------ */

static int test_store_roundtrip(void)
{
    char path[TPATH];
    char tmp[TTBUF];
    char old[129];
    struct stat st;
    const char *pattern = "/tmp/.mount_*/openchamber";

    make_test_path(path, sizeof(path), "roundtrip.json");
    ASSERT(reset_pins(path) == 0, "reset to a missing state file");
    ASSERT(pin_store(pattern, SHA_A) == 0, "pin_store succeeds");

    ASSERT(read_file(path) > 0, "state file readable right after store");
    ASSERT(strstr(g_file_buf, "\"pins\"") != NULL, "state has a pins array");
    ASSERT(strstr(g_file_buf, pattern) != NULL, "state has the pattern");
    ASSERT(strstr(g_file_buf, SHA_A) != NULL, "state has the digest");
    ASSERT(strstr(g_file_buf, "\"updated_at\":") != NULL,
           "state has updated_at");

    ASSERT(stat(path, &st) == 0, "stat the state file");
    ASSERT((st.st_mode & 0777) == 0600, "state file mode is 0600");

    make_tmp_path(tmp, sizeof(tmp), path);
    ASSERT(access(tmp, F_OK) != 0, "no temp file left behind");

    /* A fresh load sees the same pin; NULL uses the pin_set_state_file
     * override. */
    ASSERT(pin_load(NULL) == 0, "fresh pin_load of the state file");
    ASSERT(pin_damaged() == 0, "fresh load is clean");
    ASSERT(pin_check(pattern, SHA_A, old) == PIN_CHECK_MATCH,
           "roundtrip match");
    ASSERT(old[0] == '\0', "old_out cleared on match");

    ASSERT(pin_check(pattern, SHA_B, old) == PIN_CHECK_CHANGED,
           "changed digest reports 2");
    ASSERT(strcmp(old, SHA_A) == 0, "old_out holds the stored digest");
    ASSERT(old[128] == '\0', "old_out is NUL-terminated");

    ASSERT(pin_check("/usr/bin/other", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "unknown pattern is first use");

    unlink(path);
    TEST_PASS("store/roundtrip/check");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  check contract: invalid arguments and side-effect freedom         */
/* ------------------------------------------------------------------ */

static int test_check_contract(void)
{
    char path[TPATH];
    char old[129];
    char big[PATH_MAX + 16];

    make_test_path(path, sizeof(path), "checkargs.json");
    ASSERT(reset_pins(path) == 0, "reset");

    ASSERT(pin_check(NULL, SHA_A, old) == PIN_CHECK_DAMAGED,
           "NULL pattern reports damaged/cannot-check");
    ASSERT(pin_check("/usr/bin/git", NULL, old) == PIN_CHECK_DAMAGED,
           "NULL sha reports damaged/cannot-check");
    ASSERT(pin_check("/usr/bin/git", "abc", old) == PIN_CHECK_DAMAGED,
           "short sha reports damaged/cannot-check");
    ASSERT(pin_check("", SHA_A, old) == PIN_CHECK_DAMAGED,
           "empty pattern reports damaged/cannot-check");
    ASSERT(old[0] == '\0', "old_out cleared for invalid arguments");

    /* Side-effect free: a valid store/check afterwards still works. */
    ASSERT(pin_store("/usr/bin/git", SHA_A) == 0, "store after bad checks");
    ASSERT(pin_check("/usr/bin/git", SHA_A, old) == PIN_CHECK_MATCH,
           "valid check unaffected by the invalid calls");

    ASSERT(pin_store(NULL, SHA_A) == -1, "store NULL pattern refused");
    ASSERT(pin_store("/usr/bin/git", "xyz") == -1, "store short sha refused");
    memset(big, 'a', sizeof(big) - 1);
    big[0] = '/';
    big[sizeof(big) - 1] = '\0';
    ASSERT(pin_store(big, SHA_A) == -1, "store overlong pattern refused");

    unlink(path);
    TEST_PASS("check argument/damage contract");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  damaged file: fail closed, never a silent reset, store refuses    */
/* ------------------------------------------------------------------ */

static int test_damaged_semantics(void)
{
    char path[TPATH];
    char json[PATH_MAX + 512];
    char old[129];
    long stored;
    const char *pattern = "/usr/bin/damaged-pin";

    make_test_path(path, sizeof(path), "damaged_semantics.json");
    ASSERT(reset_pins(path) == 0, "reset");
    ASSERT(pin_store(pattern, SHA_A) == 0, "store a pin to damage later");
    ASSERT(pin_load(path) == 0, "clean load");
    ASSERT(pin_check(pattern, SHA_A, old) == PIN_CHECK_MATCH,
           "pin matches before damage");

    /* Damage the file: the loaded table must not silently reset. */
    ASSERT(write_raw_file(path, "garbage, not json\n") == 0,
           "corrupt the file");
    ASSERT(pin_load(path) == -1, "damaged file returns -1");
    ASSERT(pin_damaged() == 1, "damage flag set");
    ASSERT(pin_check(pattern, SHA_A, old) == PIN_CHECK_DAMAGED,
           "damaged table refuses to check");

    /* pin_store must not overwrite the damaged file. */
    stored = read_file(path);
    ASSERT(stored > 0, "damaged file readable");
    ASSERT(pin_store("/usr/bin/new", SHA_B) == -1,
           "store refuses while damaged");
    ASSERT(read_file(path) == stored &&
           strcmp(g_file_buf, "garbage, not json\n") == 0,
           "damaged file left untouched");

    /* Repairing and reloading clears the damage. */
    build_valid_json(json, sizeof(json), pattern, SHA_A, 42);
    ASSERT(write_raw_file(path, json) == 0, "repair the file");
    ASSERT(pin_load(path) == 0, "repaired file loads");
    ASSERT(pin_damaged() == 0, "damage cleared");
    ASSERT(pin_check(pattern, SHA_A, old) == PIN_CHECK_MATCH,
           "repaired pin matches again");

    unlink(path);
    TEST_PASS("damaged file fail-closed semantics");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  malformed JSON / entries mark the WHOLE file damaged              */
/* ------------------------------------------------------------------ */

struct bad_case
{
    const char *what;
    const char *content;
};

static int test_malformed_files(void)
{
    char path[TPATH];
    char old[129];
    int i;

    static const struct bad_case cases[] = {
        {"garbage text", "not json at all\n"},
        {"wrong top-level array",
         "{\n  \"entries\": [\n  ]\n}\n"},
        {"missing sha512",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"updated_at\": 5\n    }\n  ]\n}\n"},
        {"missing pattern",
         "{\n  \"pins\": [\n    {\n      \"sha512\": \"" SHA_A "\",\n"
         "      \"updated_at\": 5\n    }\n  ]\n}\n"},
        {"missing updated_at",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"sha512\": \"" SHA_A "\"\n    }\n  ]\n}\n"},
        {"relative pattern",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"relative/path\",\n"
         "      \"sha512\": \"" SHA_A "\",\n      \"updated_at\": 5\n"
         "    }\n  ]\n}\n"},
        {"empty pattern",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"\",\n"
         "      \"sha512\": \"" SHA_A "\",\n      \"updated_at\": 5\n"
         "    }\n  ]\n}\n"},
        {"short sha512",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"sha512\": \"abc123\",\n      \"updated_at\": 5\n"
         "    }\n  ]\n}\n"},
        {"non-hex sha512",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"sha512\": \"" SHA_BAD "\",\n      \"updated_at\": 5\n"
         "    }\n  ]\n}\n"},
        {"string updated_at",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"sha512\": \"" SHA_A "\",\n      \"updated_at\": \"5\"\n"
         "    }\n  ]\n}\n"},
        {"negative updated_at",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"sha512\": \"" SHA_A "\",\n      \"updated_at\": -5\n"
         "    }\n  ]\n}\n"},
        {"junk after updated_at",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"sha512\": \"" SHA_A "\",\n      \"updated_at\": 5x\n"
         "    }\n  ]\n}\n"},
        {"numeric pattern",
         "{\n  \"pins\": [\n    {\n      \"pattern\": 5,\n"
         "      \"sha512\": \"" SHA_A "\",\n      \"updated_at\": 5\n"
         "    }\n  ]\n}\n"},
        {"numeric sha512",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"sha512\": 5,\n      \"updated_at\": 5\n"
         "    }\n  ]\n}\n"},
        {"truncated file",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"sha512\": \"" SHA_A "\",\n      \"updated_at\": 5\n"},
        {"compact one-line entry",
         "{\"pins\": [{\"pattern\": \"/x\", \"sha512\": \"" SHA_A "\", "
         "\"updated_at\": 5}]}\n"},
        {"content after the outer object",
         "{\n  \"pins\": [\n  ]\n}\n\"junk\": 1\n"},
        {"one-line array with an entry",
         "{\n  \"pins\": [ {\"pattern\": \"/usr/bin/x\", \"sha512\": \""
         SHA_A "\", \"updated_at\": 5} ]\n}\n"},
        {"content on the array opener line",
         "{\n  \"pins\": [ {\n  ]\n}\n"},
        {"junk after the array close",
         "{\n  \"pins\": [\n  ] junk\n}\n"},
    };

    make_test_path(path, sizeof(path), "malformed.json");
    pin_set_state_file(path);

    for (i = 0; i < (int)(sizeof(cases) / sizeof(cases[0])); i++)
    {
        if (expect_damaged(path, cases[i].content, cases[i].what) != 0)
            return 1;
    }

    /*
     * A line longer than any pin_store() can emit (JSON_LINE_MAX =
     * PATH_MAX * 6 + 256) must refuse the whole file: parsing a split
     * line as valid structure would be a silent-corruption path (same
     * convention as persist_load).
     */
    {
        char big[PATH_MAX * 6 + 512];

        memset(big, 'x', sizeof(big) - 1);
        big[0] = '{';
        big[sizeof(big) - 2] = '}';
        big[sizeof(big) - 1] = '\0'; /* no newline: one over-long line */
        ASSERT(write_raw_file(path, big) == 0, "write over-long-line file");
        ASSERT(pin_load(path) == -1,
               "over-long line marks the file damaged");
        ASSERT(pin_damaged() == 1, "over-long line sets damaged");
    }

    /* The empty one-line array is still a valid, clean empty table. */
    ASSERT(write_raw_file(path, "{\n  \"pins\": []\n}\n") == 0,
           "write empty one-line pins array");
    ASSERT(pin_load(path) == 0, "empty one-line pins array loads");
    ASSERT(pin_damaged() == 0, "empty one-line pins array is not damaged");
    ASSERT(pin_check("/usr/bin/x", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "empty one-line pins array has no pins");

    /* Over-cap and at-cap boundary. */
    ASSERT(write_over_cap_file(path, PIN_MAX + 1) == 0,
           "write over-cap file");
    ASSERT(pin_load(path) == -1, "over-cap file is damaged");
    ASSERT(pin_damaged() == 1, "over-cap sets damaged");

    ASSERT(write_over_cap_file(path, PIN_MAX) == 0, "write at-cap file");
    ASSERT(pin_load(path) == 0, "at-cap file loads");
    ASSERT(pin_damaged() == 0, "at-cap file is clean");
    ASSERT(pin_check("/usr/bin/over-000", SHA_A, old) == PIN_CHECK_MATCH,
           "at-cap first entry loaded");
    ASSERT(pin_check("/usr/bin/over-042", SHA_A, old) == PIN_CHECK_MATCH,
           "at-cap middle entry loaded");

    unlink(path);
    TEST_PASS("malformed files mark the whole file damaged");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  unknown keys and comments are tolerated                           */
/* ------------------------------------------------------------------ */

static int test_unknown_keys_ignored(void)
{
    char path[TPATH];
    char old[129];
    static const char content[] =
        "{\n"
        "  # a comment before the table\n"
        "  \"version\": 2,\n"
        "  \"pins\": [\n"
        "    # a comment inside the array\n"
        "    {\n"
        "      \"pattern\": \"/usr/bin/future\",\n"
        "      \"sha512\": \"" SHA_A "\",\n"
        "      \"updated_at\": 1234,\n"
        "      \"algorithm\": \"sha512\",\n"
        "      \"note_count\": 7\n"
        "    }\n"
        "  ]\n"
        "}\n";

    make_test_path(path, sizeof(path), "unknown.json");
    pin_set_state_file(path);

    ASSERT(write_raw_file(path, content) == 0, "write file with extras");
    ASSERT(pin_load(path) == 0, "unknown keys load cleanly");
    ASSERT(pin_damaged() == 0, "unknown keys do not damage");
    ASSERT(pin_check("/usr/bin/future", SHA_A, old) == PIN_CHECK_MATCH,
           "pin with unknown siblings matches");

    unlink(path);
    TEST_PASS("unknown keys/comments ignored");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  refresh updates the digest and updated_at                         */
/* ------------------------------------------------------------------ */

static int test_updated_at_refresh(void)
{
    char path[TPATH];
    char json[PATH_MAX + 512];
    char old[129];
    char *u;
    long before = 1000;
    long after;
    const char *pattern = "/usr/bin/refresh";

    make_test_path(path, sizeof(path), "refresh.json");
    ASSERT(reset_pins(path) == 0, "reset");
    build_valid_json(json, sizeof(json), pattern, SHA_A, before);
    ASSERT(write_raw_file(path, json) == 0, "write initial pin");
    ASSERT(pin_load(path) == 0, "load initial pin");
    ASSERT(pin_check(pattern, SHA_A, old) == PIN_CHECK_MATCH,
           "initial digest matches");

    ASSERT(pin_store(pattern, SHA_B) == 0, "refresh with the new digest");
    ASSERT(pin_check(pattern, SHA_B, old) == PIN_CHECK_MATCH,
           "new digest matches");
    ASSERT(pin_check(pattern, SHA_A, old) == PIN_CHECK_CHANGED,
           "old digest reports changed");
    ASSERT(strcmp(old, SHA_B) == 0, "old_out holds the refreshed digest");

    ASSERT(read_file(path) > 0, "refreshed file readable");
    u = strstr(g_file_buf, "\"updated_at\":");
    ASSERT(u != NULL, "updated_at present after refresh");
    after = strtol(u + strlen("\"updated_at\":"), NULL, 10);
    ASSERT(after > before, "updated_at refreshed");
    ASSERT(strstr(g_file_buf, SHA_B) != NULL, "file holds the new digest");
    ASSERT(strstr(g_file_buf, SHA_A) == NULL, "file no longer holds the old");

    unlink(path);
    TEST_PASS("updated_at refresh on change");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  cap: PIN_MAX + 1 stores evict the oldest insertion                */
/* ------------------------------------------------------------------ */

static int test_cap_eviction_by_store(void)
{
    char path[TPATH];
    char pat[64];
    char old[129];
    char *p;
    int i;
    int count = 0;

    make_test_path(path, sizeof(path), "evict_store.json");
    ASSERT(reset_pins(path) == 0, "reset");

    for (i = 0; i <= PIN_MAX; i++) /* PIN_MAX + 1 inserts */
    {
        snprintf(pat, sizeof(pat), "/usr/bin/evict-%03d", i);
        ASSERT(pin_store(pat, SHA_A) == 0, "bulk pin_store");
    }

    ASSERT(pin_check("/usr/bin/evict-000", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "oldest inserted entry was evicted");
    snprintf(pat, sizeof(pat), "/usr/bin/evict-%03d", PIN_MAX);
    ASSERT(pin_check(pat, SHA_A, old) == PIN_CHECK_MATCH,
           "newest entry survives");

    ASSERT(read_file(path) > 0, "state file readable");
    for (p = strstr(g_file_buf, "\"pattern\":"); p != NULL;
         p = strstr(p + 1, "\"pattern\":"))
        count++;
    ASSERT(count == PIN_MAX, "file never exceeds PIN_MAX entries");

    unlink(path);
    TEST_PASS("cap eviction on insert");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  eviction uses the smallest updated_at, not file order             */
/* ------------------------------------------------------------------ */

static int test_eviction_smallest_updated_at(void)
{
    char path[TPATH];
    char old[129];

    make_test_path(path, sizeof(path), "evict_smallest.json");
    pin_set_state_file(path);
    unlink(path);

    ASSERT(write_full_pin_file(path, 7, 0) == 0, "write full table");
    ASSERT(pin_load(path) == 0, "load full table");
    ASSERT(pin_check("/usr/bin/gen-007", SHA_A, old) == PIN_CHECK_MATCH,
           "victim present before store");
    ASSERT(pin_store("/usr/bin/gen-new", SHA_A) == 0, "insert beyond the cap");

    ASSERT(pin_check("/usr/bin/gen-007", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "smallest updated_at evicted");
    ASSERT(pin_check("/usr/bin/gen-000", SHA_A, old) == PIN_CHECK_MATCH,
           "other entries survive");
    ASSERT(pin_check("/usr/bin/gen-new", SHA_A, old) == PIN_CHECK_MATCH,
           "new entry stored");

    unlink(path);
    TEST_PASS("eviction keeps the largest updated_at");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  eviction tie-break: oldest store order goes first                 */
/* ------------------------------------------------------------------ */

static int test_eviction_tie_break(void)
{
    char path[TPATH];
    char old[129];

    make_test_path(path, sizeof(path), "evict_tie.json");
    pin_set_state_file(path);
    unlink(path);

    ASSERT(write_full_pin_file(path, -1, 1) == 0, "write tied table");
    ASSERT(pin_load(path) == 0, "load tied table");
    ASSERT(pin_store("/usr/bin/gen-new", SHA_A) == 0, "insert beyond the cap");

    ASSERT(pin_check("/usr/bin/gen-000", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "first stored entry evicted on an updated_at tie");
    ASSERT(pin_check("/usr/bin/gen-255", SHA_A, old) == PIN_CHECK_MATCH,
           "last stored entry survives");
    ASSERT(pin_check("/usr/bin/gen-new", SHA_A, old) == PIN_CHECK_MATCH,
           "new entry stored");

    unlink(path);
    TEST_PASS("eviction tie-break by store order");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  a failed write restores the pre-store table (memory stays          */
/*  consistent with disk)                                             */
/* ------------------------------------------------------------------ */

static int test_write_failure_keeps_memory(void)
{
    char path[TPATH];
    char blocker[TPATH];
    char bad[TTBUF];
    char old[129];

    make_test_path(path, sizeof(path), "writefail.json");
    ASSERT(reset_pins(path) == 0, "reset");

    /* A regular file where the parent directory should be: the atomic
     * write cannot even create its temp file. */
    make_test_path(blocker, sizeof(blocker), "writefail_blocker");
    unlink(blocker);
    ASSERT(write_raw_file(blocker, "not a directory") == 0,
           "create blocker file");
    snprintf(bad, sizeof(bad), "%s/state.json", blocker);
    pin_set_state_file(bad);

    ASSERT(pin_store("/usr/bin/kept", SHA_A) == -1,
           "store fails when the path is un-writable");
    /* The failed store must not mutate the live table: memory stays
     * consistent with disk, so the pattern is first use again (the
     * re-prompt is the fail-closed path, and the next store retries). */
    ASSERT(pin_check("/usr/bin/kept", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "failed store does not keep the entry in memory");
    ASSERT(access(bad, F_OK) != 0, "no state file left after failure");

    /* An open error other than ENOENT is damage, not first use. */
    ASSERT(pin_load(bad) == -1, "unreadable path is damaged, not missing");
    ASSERT(pin_damaged() == 1, "unreadable path sets damaged");

    pin_set_state_file(path);
    unlink(blocker);
    unlink(path);
    TEST_PASS("write failure keeps memory consistent with disk");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  unwritable parent directory (skipped for root, which bypasses it) */
/* ------------------------------------------------------------------ */

static int test_unwritable_dir_non_root(void)
{
    char dir[TPATH];
    char path[TTBUF];
    char old[129];

    if (geteuid() == 0)
    {
        printf("SKIP: unwritable-dir store failure needs an unprivileged "
               "user\n");
        return 0;
    }

    make_test_path(dir, sizeof(dir), "ro_dir");
    rmdir(dir);
    ASSERT(mkdir(dir, 0555) == 0, "create read-only dir");
    snprintf(path, sizeof(path), "%s/sub/state.json", dir);
    pin_set_state_file(path);

    ASSERT(pin_load(path) == 0, "missing nested file loads clean");
    ASSERT(pin_store("/usr/bin/ro", SHA_A) == -1,
           "store inside an unwritable dir fails");
    /* The failed store must not mutate the live table. */
    ASSERT(pin_check("/usr/bin/ro", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "failed store does not keep the entry in memory");

    ASSERT(chmod(dir, 0700) == 0, "restore dir mode");
    rmdir(dir);
    TEST_PASS("unwritable directory store failure");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  a failed append must not leave a phantom slot behind: the next     */
/*  successful store has to persist exactly the valid pins             */
/* ------------------------------------------------------------------ */

static int test_failed_append_then_store(void)
{
    char path[TPATH];
    char blocker[TPATH];
    char bad[TTBUF];
    char old[129];

    make_test_path(path, sizeof(path), "appendfail.json");
    ASSERT(reset_pins(path) == 0, "reset");

    /* Seed exactly one live pin, then delete the state file and reload:
     * the table is empty again, but the seeded slot is still in memory
     * (slots past the count are not visible). */
    ASSERT(pin_store("/usr/bin/known", SHA_A) == 0, "seed a known pin");
    ASSERT(unlink(path) == 0, "delete the state file");
    ASSERT(pin_load(path) == 0, "missing file reloads as an empty table");
    ASSERT(pin_check("/usr/bin/known", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "deleted table grants nothing");

    /* A regular file where the parent directory should be: the atomic
     * write cannot even create its temp file (same trick as the
     * write-failure test). */
    make_test_path(blocker, sizeof(blocker), "appendfail_blocker");
    unlink(blocker);
    ASSERT(write_raw_file(blocker, "not a directory") == 0,
           "create blocker file");
    snprintf(bad, sizeof(bad), "%s/state.json", blocker);
    pin_set_state_file(bad);

    ASSERT(pin_store("/usr/bin/phantom", SHA_A) == -1, "append fails");
    /* The failed append must not make the deleted pin live again: the
     * count may only cover the entries the pre-store table had. */
    ASSERT(pin_check("/usr/bin/known", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "failed append does not resurrect the deleted pin");
    ASSERT(pin_check("/usr/bin/phantom", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "failed append leaves no phantom entry");

    /* With a working path again, the next store must persist a file the
     * strict loader accepts.  A phantom slot (count incremented before
     * the snapshot) would serialize an empty or stale pattern and either
     * poison the whole table as damaged or resurrect a removed pin. */
    pin_set_state_file(path);
    ASSERT(pin_store("/usr/bin/real", SHA_A) == 0, "next store succeeds");
    ASSERT(pin_load(path) == 0, "stored file loads clean (no phantom)");
    ASSERT(pin_check("/usr/bin/real", SHA_A, old) == PIN_CHECK_MATCH,
           "valid entry preserved");
    ASSERT(pin_check("/usr/bin/known", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "deleted pin stays gone after the next store");

    unlink(blocker);
    unlink(path);
    TEST_PASS("failed append leaves no phantom for the next store");
    return 0;
}

/*
 * Structural strictness: junk after an entry close, a duplicate "pins"
 * array, and a non-canonical pin_check() pattern are all damage, not
 * silently tolerated input.
 */
static int test_pin_strict_structure(void)
{
    char path[TPATH];
    char old[129];
    char valid[512];
    int failed = 0;

    make_test_path(path, sizeof(path), "strict.json");

    const char *junk =
        "{\n  \"pins\": [\n    {\n"
        "      \"pattern\": \"/usr/bin/a\",\n"
        "      \"sha512\": \"" SHA_A "\",\n"
        "      \"updated_at\": 1\n"
        "    } trailing\n  ]\n}\n";
    if (expect_damaged(path, junk, "junk after entry close") != 0)
        failed = 1;

    const char *dup =
        "{\n  \"pins\": [\n    {\n"
        "      \"pattern\": \"/usr/bin/a\",\n"
        "      \"sha512\": \"" SHA_A "\",\n"
        "      \"updated_at\": 1\n"
        "    }\n  ]\n  \"pins\": [\n  ]\n}\n";
    if (expect_damaged(path, dup, "duplicate pins array") != 0)
        failed = 1;

    if (failed)
        return 1;

    /* Control: a writer-shaped file still loads after the damage. */
    build_valid_json(valid, sizeof(valid), "/usr/bin/a", SHA_A, 1);
    ASSERT(write_raw_file(path, valid) == 0, "write valid control file");
    ASSERT(pin_load(path) == 0, "valid file still loads");

    /* pin_check() rejects a non-canonical pattern as damaged instead of
     * reporting a clean first use. */
    ASSERT(pin_check("relative/path", SHA_A, old) == PIN_CHECK_DAMAGED,
           "non-canonical pattern is damaged");
    ASSERT(pin_check("", SHA_A, old) == PIN_CHECK_DAMAGED,
           "empty pattern is damaged");

    unlink(path);
    TEST_PASS("pin structure strictness");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  D9: duplicate patterns damage the whole file (fail closed)        */
/* ------------------------------------------------------------------ */

/*
 * Two rows with the same pattern derive one CLI ID and can never be
 * managed unambiguously, so the file is damaged as a whole.  The live
 * table is not silently replaced by either duplicate row: the previously
 * loaded table stays untrusted (pin_damaged), store refuses, and the file
 * is left untouched.  Pre-fix the file loaded with both rows and the
 * table was swapped in.
 */
static int test_duplicate_pattern_damaged(void)
{
    char path[TPATH];
    char json[PATH_MAX + 512];
    char old[129];
    long stored;
    const char *pattern = "/usr/bin/dup-pin";

    make_test_path(path, sizeof(path), "duplicate.json");
    ASSERT(reset_pins(path) == 0, "reset for the duplicate test");
    ASSERT(pin_store(pattern, SHA_A) == 0, "seed the live pin");

    snprintf(json, sizeof(json),
             "{\n  \"pins\": [\n"
             "    {\n"
             "      \"pattern\": \"%s\",\n"
             "      \"sha512\": \"" SHA_A "\",\n"
             "      \"updated_at\": 1000\n"
             "    },\n"
             "    {\n"
             "      \"pattern\": \"%s\",\n"
             "      \"sha512\": \"" SHA_B "\",\n"
             "      \"updated_at\": 2000\n"
             "    }\n"
             "  ]\n}\n",
             pattern, pattern);
    ASSERT(write_raw_file(path, json) == 0, "write duplicate-pattern file");
    stored = read_file(path);
    ASSERT(stored > 0, "duplicate-pattern file readable");

    ASSERT(pin_load(path) == -1, "duplicate patterns damage the whole file");
    ASSERT(pin_damaged() == 1, "duplicate patterns set the damaged flag");

    /* The live table is untrusted, not silently replaced. */
    ASSERT(pin_check(pattern, SHA_A, old) == PIN_CHECK_DAMAGED,
           "the previously loaded table is untrusted after the damaged load");
    ASSERT(pin_store("/usr/bin/new", SHA_A) == -1,
           "store refuses while the duplicate-damaged file is active");
    ASSERT(read_file(path) == stored && strstr(g_file_buf, pattern) != NULL,
           "duplicate-pattern file left untouched");

    /* The pure file API agrees and returns no partial table. */
    {
        PinRecord out[4];
        int damaged = -1;

        ASSERT(pin_load_file(path, out, 4, &damaged) == -1,
               "pin_load_file rejects duplicate patterns");
        ASSERT(damaged == 1, "pin_load_file reports the damage");
        ASSERT(out[0].pattern[0] == '\0', "no partial table is returned");
    }

    unlink(path);
    TEST_PASS("duplicate patterns mark the file damaged");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  D11: only [0-9a-f] digests load; uppercase hex is damage           */
/* ------------------------------------------------------------------ */

/*
 * A digest is exactly 128 lowercase hex characters (sha512sum's canonical
 * form).  Uppercase hex used to load but could never match, because
 * pin_check compares byte-for-byte: it is rejected at every boundary -
 * load, store, check and the pure file API - so the file is damaged
 * instead of being silently useless.  Pre-fix both the load and the
 * write accepted the uppercase value.
 */
static int test_uppercase_digest_rejected(void)
{
    char path[TPATH];
    char json[PATH_MAX + 512];
    char upper[129];
    char old[129];
    PinRecord rows[1];
    PinRecord out[2];
    int damaged = -1;
    size_t i;

    for (i = 0; i < 128; i++)
        upper[i] = (SHA_A[i] >= 'a' && SHA_A[i] <= 'f')
                       ? (char)(SHA_A[i] - 'a' + 'A')
                       : SHA_A[i];
    upper[128] = '\0';

    make_test_path(path, sizeof(path), "uppercase.json");
    unlink(path);

    /* Load: an uppercase digest damages the whole file. */
    snprintf(json, sizeof(json),
             "{\n  \"pins\": [\n    {\n"
             "      \"pattern\": \"/usr/bin/upper\",\n"
             "      \"sha512\": \"%s\",\n"
             "      \"updated_at\": 5\n"
             "    }\n  ]\n}\n",
             upper);
    ASSERT(write_raw_file(path, json) == 0, "write uppercase-digest file");
    pin_set_state_file(path);
    ASSERT(pin_load(path) == -1, "uppercase digest marks the file damaged");
    ASSERT(pin_damaged() == 1, "uppercase digest sets the damaged flag");

    /* Store/check: an uppercase digest is an invalid argument. */
    ASSERT(reset_pins(path) == 0, "reset for the store check");
    ASSERT(pin_store("/usr/bin/upper", upper) == -1,
           "pin_store refuses an uppercase digest");
    ASSERT(pin_check("/usr/bin/upper", upper, old) == PIN_CHECK_DAMAGED,
           "pin_check refuses an uppercase digest argument");

    /* Pure file API: both load and write reject it. */
    ASSERT(write_raw_file(path, json) == 0, "rewrite uppercase-digest file");
    ASSERT(pin_load_file(path, out, 2, &damaged) == -1,
           "pin_load_file rejects an uppercase digest");
    ASSERT(damaged == 1, "pin_load_file reports the uppercase damage");

    memset(rows, 0, sizeof(rows));
    snprintf(rows[0].pattern, sizeof(rows[0].pattern), "%s", "/usr/bin/upper");
    memcpy(rows[0].sha512, upper, sizeof(rows[0].sha512));
    rows[0].updated_at = 5;
    unlink(path);
    ASSERT(pin_write_file(path, rows, 1) == -1,
           "pin_write_file refuses an uppercase digest");
    ASSERT(access(path, F_OK) != 0, "refused write creates no file");

    unlink(path);
    TEST_PASS("uppercase hex digests are rejected");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  pure file API: pin_load_file / pin_write_file                     */
/* ------------------------------------------------------------------ */

static int test_file_api_roundtrip(void)
{
    char path[TPATH];
    char json[PATH_MAX + 512];
    char old[129];
    PinRecord rows[3];
    PinRecord out[4];
    static PinRecord over_rows[PIN_MAX + 1];
    int damaged = -1;
    const char *escaped = "/usr/bin/api\"quoted\\x";

    make_test_path(path, sizeof(path), "api_roundtrip.json");
    unlink(path);

    memset(rows, 0, sizeof(rows));
    snprintf(rows[0].pattern, sizeof(rows[0].pattern), "%s", escaped);
    memcpy(rows[0].sha512, SHA_A, sizeof(rows[0].sha512));
    rows[0].updated_at = 111;
    snprintf(rows[1].pattern, sizeof(rows[1].pattern), "/usr/bin/api-plain");
    memcpy(rows[1].sha512, SHA_B, sizeof(rows[1].sha512));
    rows[1].updated_at = 222;
    snprintf(rows[2].pattern, sizeof(rows[2].pattern), "/usr/bin/api-third");
    memcpy(rows[2].sha512, SHA_A, sizeof(rows[2].sha512));
    rows[2].updated_at = 333;

    ASSERT(pin_write_file(path, rows, 3) == 0, "pin_write_file writes rows");
    ASSERT(read_file(path) > 0, "api state file readable");
    ASSERT(strstr(g_file_buf, "api\\\"quoted\\\\x") != NULL,
           "pin_write_file escapes the pattern");
    ASSERT(strstr(g_file_buf, "\"updated_at\": 333") != NULL,
           "pin_write_file writes updated_at");

    ASSERT(pin_load_file(path, out, 4, &damaged) == 3,
           "pin_load_file returns the row count");
    ASSERT(damaged == 0, "clean file is not damaged");
    ASSERT(strcmp(out[0].pattern, escaped) == 0,
           "escaped pattern roundtrips");
    ASSERT(strcmp(out[0].sha512, SHA_A) == 0, "digest roundtrips");
    ASSERT(out[0].updated_at == 111, "updated_at roundtrips");
    ASSERT(strcmp(out[1].pattern, "/usr/bin/api-plain") == 0,
           "row order kept");
    ASSERT(strcmp(out[1].sha512, SHA_B) == 0, "second digest roundtrips");
    ASSERT(out[2].updated_at == 333, "third timestamp roundtrips");
    ASSERT(out[3].pattern[0] == '\0', "unused out slots stay zeroed");

    /* Missing file: empty table, not damage. */
    unlink(path);
    memset(out, 'x', sizeof(out));
    ASSERT(pin_load_file(path, out, 4, &damaged) == 0,
           "missing file = 0 rows");
    ASSERT(damaged == 0, "missing file is not damaged");
    ASSERT(out[0].pattern[0] == '\0', "missing file yields an empty table");

    /* A file with more rows than max is damage: never silently dropped. */
    ASSERT(pin_write_file(path, rows, 3) == 0, "rewrite three rows");
    ASSERT(pin_load_file(path, out, 2, &damaged) == -1,
           "over-max file is damaged");
    ASSERT(damaged == 1, "over-max sets the damaged flag");
    ASSERT(out[0].pattern[0] == '\0', "failed load zeroes the table");
    ASSERT(pin_load_file(path, out, 3, &damaged) == 3, "at-max file loads");
    ASSERT(damaged == 0, "at-max file is clean");

    /* Argument validation. */
    ASSERT(pin_load_file(NULL, out, 4, &damaged) == -1, "NULL path refused");
    ASSERT(damaged == 1, "NULL path sets damaged");
    ASSERT(pin_load_file("", out, 4, &damaged) == -1, "empty path refused");
    ASSERT(pin_load_file(path, NULL, 4, &damaged) == -1, "NULL out refused");
    ASSERT(pin_load_file(path, out, 0, &damaged) == -1, "max 0 refused");
    ASSERT(pin_load_file(path, out, -3, &damaged) == -1,
           "negative max refused");
    ASSERT(damaged == 1, "bad arguments set damaged");
    ASSERT(pin_load_file(path, out, 4, NULL) == 3,
           "NULL damaged_out is accepted");

    /* Broken files: wrong digest length, junk and truncation are damage. */
    ASSERT(write_raw_file(path,
                          "{\n  \"pins\": [\n    {\n"
                          "      \"pattern\": \"/usr/bin/x\",\n"
                          "      \"sha512\": \"abc\",\n"
                          "      \"updated_at\": 5\n    }\n  ]\n}\n") == 0,
           "write short-digest file");
    ASSERT(pin_load_file(path, out, 4, &damaged) == -1,
           "short digest is damage");
    ASSERT(damaged == 1, "short digest sets damaged");
    ASSERT(out[0].pattern[0] == '\0', "damage leaves an empty table");

    ASSERT(write_raw_file(path, "not json at all\n") == 0, "write junk");
    ASSERT(pin_load_file(path, out, 4, &damaged) == -1, "junk is damage");
    ASSERT(damaged == 1, "junk sets damaged");

    build_valid_json(json, sizeof(json), "/usr/bin/x", SHA_A, 5);
    json[strlen(json) - 2] = '\0'; /* drop the outer close */
    ASSERT(write_raw_file(path, json) == 0, "write truncated file");
    ASSERT(pin_load_file(path, out, 4, &damaged) == -1,
           "truncation is damage");
    ASSERT(damaged == 1, "truncation sets damaged");

    /* The pure API reports damage through its out-parameter only. */
    ASSERT(reset_pins(path) == 0, "reset the daemon table cleanly");
    ASSERT(pin_load_file(path, out, 4, &damaged) == 0,
           "missing file loads clean");
    ASSERT(pin_damaged() == 0, "daemon damage flag untouched by clean load");
    ASSERT(pin_load_file(NULL, out, 4, &damaged) == -1, "invalid args fail");
    ASSERT(pin_damaged() == 0, "daemon damage flag untouched by file API");

    /* Daemon writer and pure writer must stay interchangeable. */
    ASSERT(pin_store("/usr/bin/api-daemon", SHA_A) == 0, "store via daemon");
    ASSERT(pin_load_file(path, out, 4, &damaged) == 1,
           "daemon-written file loads via the file API");
    ASSERT(strcmp(out[0].pattern, "/usr/bin/api-daemon") == 0,
           "daemon-written row roundtrips");
    ASSERT(pin_write_file(path, out, 1) == 0, "rewrite via the file API");
    ASSERT(pin_load(path) == 0, "file-API-written file loads via the daemon");
    ASSERT(pin_check("/usr/bin/api-daemon", SHA_A, old) == PIN_CHECK_MATCH,
           "file-API-written row roundtrips through the daemon");

    /* pin_write_file boundary checks. */
    ASSERT(pin_write_file(NULL, rows, 1) == -1, "write NULL path refused");
    ASSERT(pin_write_file("", rows, 1) == -1, "write empty path refused");
    ASSERT(pin_write_file(path, NULL, 1) == -1, "write NULL rows refused");
    ASSERT(pin_write_file(path, rows, -1) == -1,
           "write negative count refused");
    ASSERT(pin_write_file(path, over_rows, PIN_MAX + 1) == -1,
           "write over PIN_MAX refused");
    ASSERT(pin_write_file(path, NULL, 0) == 0, "write empty table allowed");
    ASSERT(read_file(path) > 0 && strstr(g_file_buf, "\"pins\"") != NULL,
           "empty table file readable");
    ASSERT(strstr(g_file_buf, "\"pattern\"") == NULL,
           "empty table has no rows");

    rows[0].sha512[10] = 'z';
    ASSERT(pin_write_file(path, rows, 1) == -1, "write bad digest refused");
    rows[0].sha512[10] = 'a'; /* restore */
    rows[0].updated_at = (time_t)-1;
    ASSERT(pin_write_file(path, rows, 1) == -1, "write negative time refused");
    rows[0].updated_at = 111;
    snprintf(rows[0].pattern, sizeof(rows[0].pattern), "relative");
    ASSERT(pin_write_file(path, rows, 1) == -1, "write bad pattern refused");
    ASSERT(read_file(path) > 0 && strstr(g_file_buf, "\"pattern\"") == NULL,
           "refused rows leave the file untouched");

    unlink(path);
    TEST_PASS("pure pin file API");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  remove-by-id: unique prefix, full ID, unknown, invalid            */
/* ------------------------------------------------------------------ */

static int test_remove_by_id(void)
{
    char path[TPATH];
    char id_a[RULEID_HEX_LEN + 1];
    char id_b[RULEID_HEX_LEN + 1];
    char id_c[RULEID_HEX_LEN + 1];
    char prefix[RULEID_HEX_LEN + 1];
    char unknown[RULEID_MIN_PREFIX + 1];
    char candidate[16];
    char old[129];
    long stored;
    int plen;
    int i;

    make_test_path(path, sizeof(path), "remove.json");
    ASSERT(reset_pins(path) == 0, "reset");

    ASSERT(pin_store("/usr/bin/rm-a", SHA_A) == 0, "seed pin A");
    ASSERT(pin_store("/usr/bin/rm-b", SHA_B) == 0, "seed pin B");
    ASSERT(pin_store("/usr/bin/rm-c", SHA_A) == 0, "seed pin C");
    ASSERT(ruleid_pin("/usr/bin/rm-a", id_a) == 0, "id A");
    ASSERT(ruleid_pin("/usr/bin/rm-b", id_b) == 0, "id B");
    ASSERT(ruleid_pin("/usr/bin/rm-c", id_c) == 0, "id C");

    /* The shortest prefix of B (>= RULEID_MIN_PREFIX) that matches no
     * other pin removes exactly one pin and rewrites the file. */
    for (plen = RULEID_MIN_PREFIX; plen <= RULEID_HEX_LEN; plen++)
    {
        memcpy(prefix, id_b, (size_t)plen);
        prefix[plen] = '\0';
        if (ruleid_prefix_match(id_a, prefix) != 1 &&
            ruleid_prefix_match(id_c, prefix) != 1)
            break;
    }
    ASSERT(plen <= RULEID_HEX_LEN, "found a unique prefix of B");
    ASSERT(plen >= RULEID_MIN_PREFIX, "prefix meets the minimum length");
    ASSERT(pin_remove_by_id(prefix) == 1, "unique prefix removes B");
    ASSERT(pin_check("/usr/bin/rm-b", SHA_B, old) == PIN_CHECK_FIRST_USE,
           "B removed from memory");
    ASSERT(pin_check("/usr/bin/rm-a", SHA_A, old) == PIN_CHECK_MATCH,
           "A untouched");
    ASSERT(pin_check("/usr/bin/rm-c", SHA_A, old) == PIN_CHECK_MATCH,
           "C untouched");
    ASSERT(pin_load(path) == 0, "reload after removal");
    ASSERT(pin_check("/usr/bin/rm-b", SHA_B, old) == PIN_CHECK_FIRST_USE,
           "B gone from disk");
    ASSERT(pin_check("/usr/bin/rm-a", SHA_A, old) == PIN_CHECK_MATCH,
           "A persisted");

    /* The full 16-char ID works too. */
    ASSERT(pin_remove_by_id(id_c) == 1, "full id removes C");
    ASSERT(pin_check("/usr/bin/rm-c", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "C removed");

    /* A valid prefix that matches nothing is 0, not an error. */
    for (i = 0; i < 64; i++)
    {
        snprintf(candidate, sizeof(candidate), "%08x", (unsigned)i);
        if (ruleid_prefix_match(id_a, candidate) == 0)
            break;
    }
    ASSERT(i < 64, "found an unknown candidate prefix");
    memcpy(unknown, candidate, RULEID_MIN_PREFIX + 1);
    ASSERT(pin_remove_by_id(unknown) == 0, "unknown prefix is not found");
    ASSERT(pin_check("/usr/bin/rm-a", SHA_A, old) == PIN_CHECK_MATCH,
           "unknown prefix removes nothing");

    /* Invalid inputs are -1 and never touch the table. */
    ASSERT(pin_remove_by_id(NULL) == -1, "NULL id refused");
    ASSERT(pin_remove_by_id("") == -1, "empty id refused");
    ASSERT(pin_remove_by_id("1234567") == -1, "7-char id refused");
    ASSERT(pin_remove_by_id("0123456789abcdef0") == -1, "17-char id refused");
    ASSERT(pin_remove_by_id("zzzzzzzz") == -1, "non-hex id refused");
    ASSERT(pin_remove_by_id("0123456G") == -1, "upper-case id refused");
    ASSERT(pin_check("/usr/bin/rm-a", SHA_A, old) == PIN_CHECK_MATCH,
           "invalid ids remove nothing");

    /* A damaged file is never overwritten. */
    ASSERT(write_raw_file(path, "damaged remove state\n") == 0,
           "damage the pin file");
    ASSERT(pin_load(path) == -1, "damaged load");
    stored = read_file(path);
    ASSERT(stored > 0, "damaged file readable");
    ASSERT(pin_remove_by_id(id_a) == -1, "damaged table refuses removal");
    ASSERT(read_file(path) == stored &&
           strcmp(g_file_buf, "damaged remove state\n") == 0,
           "damaged file left untouched");

    /* A missing file is an empty table: valid IDs are "not found". */
    unlink(path);
    ASSERT(pin_load(path) == 0, "missing file reloads clean");
    ASSERT(pin_remove_by_id(unknown) == 0, "empty table reports not found");

    unlink(path);
    TEST_PASS("remove-by-id prefix resolution");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  ambiguous prefix: nothing removed, file untouched                 */
/* ------------------------------------------------------------------ */

/*
 * Ambiguity needs two patterns whose ruleid_pin() IDs share their first
 * 8 hex characters (RULEID_MIN_PREFIX).  SHA-512 has no shortcut for
 * that, so this is a deterministic birthday search: 2^20 buckets and
 * 400k tries yield ~18.6 expected colliding pairs, making an unfound
 * pair's probability below 1e-8.  Only the first pair found is used.
 */
#define COLLIDE_SLOTS (1u << 20)
#define COLLIDE_TRIES 400000
#define COLLIDE_PAT_MAX 64

typedef struct
{
    unsigned int key; /* first 8 hex chars of the pin ID, as a number */
    int idx;          /* bucket owner: pattern index + 1, 0 = empty   */
} CollideSlot;

static CollideSlot g_collide[COLLIDE_SLOTS];

static int build_collide_pattern(unsigned index, char *out, size_t sz)
{
    int n = snprintf(out, sz, "/usr/bin/collide-%u", index);

    return (n < 0 || (size_t)n >= sz) ? -1 : 0;
}

static int collide_prefix(unsigned index, unsigned int *key_out)
{
    char pattern[COLLIDE_PAT_MAX];
    char id[RULEID_HEX_LEN + 1];
    char hex8[9];

    if (build_collide_pattern(index, pattern, sizeof(pattern)) < 0)
        return -1;
    if (ruleid_pin(pattern, id) < 0)
        return -1;
    memcpy(hex8, id, 8);
    hex8[8] = '\0';
    *key_out = (unsigned int)strtoul(hex8, NULL, 16);
    return 0;
}

static int find_colliding_patterns(char *a_out, size_t a_sz, char *b_out,
                                   size_t b_sz)
{
    unsigned int i;

    memset(g_collide, 0, sizeof(g_collide));
    for (i = 0; i < COLLIDE_TRIES; i++)
    {
        unsigned int key;
        unsigned int slot;

        if (collide_prefix(i, &key) < 0)
            return -1;
        slot = key & (COLLIDE_SLOTS - 1);
        for (;;)
        {
            if (g_collide[slot].idx == 0)
            {
                g_collide[slot].key = key;
                g_collide[slot].idx = (int)i + 1;
                break;
            }
            if (g_collide[slot].key == key)
            {
                unsigned int other = (unsigned int)g_collide[slot].idx - 1;

                if (build_collide_pattern(other, a_out, a_sz) < 0 ||
                    build_collide_pattern(i, b_out, b_sz) < 0)
                    return -1;
                return 0;
            }
            slot = (slot + 1) & (COLLIDE_SLOTS - 1);
        }
    }
    return -1;
}

static int test_remove_ambiguous_id(void)
{
    char path[TPATH];
    char pattern_a[COLLIDE_PAT_MAX];
    char pattern_b[COLLIDE_PAT_MAX];
    char id_a[RULEID_HEX_LEN + 1];
    char id_b[RULEID_HEX_LEN + 1];
    char prefix[RULEID_MIN_PREFIX + 1];
    char old[129];
    PinRecord rows[2];
    long stored;

    if (find_colliding_patterns(pattern_a, sizeof(pattern_a), pattern_b,
                                sizeof(pattern_b)) != 0)
    {
        fprintf(stderr, "FAIL: no colliding pattern pair found in %d tries\n",
                COLLIDE_TRIES);
        return 1;
    }

    ASSERT(ruleid_pin(pattern_a, id_a) == 0, "pair id A");
    ASSERT(ruleid_pin(pattern_b, id_b) == 0, "pair id B");
    ASSERT(strncmp(id_a, id_b, RULEID_MIN_PREFIX) == 0,
           "pair shares the minimum prefix");
    memcpy(prefix, id_a, RULEID_MIN_PREFIX);
    prefix[RULEID_MIN_PREFIX] = '\0';

    make_test_path(path, sizeof(path), "ambiguous_remove.json");
    memset(rows, 0, sizeof(rows));
    snprintf(rows[0].pattern, sizeof(rows[0].pattern), "%s", pattern_a);
    memcpy(rows[0].sha512, SHA_A, sizeof(rows[0].sha512));
    rows[0].updated_at = 1000;
    snprintf(rows[1].pattern, sizeof(rows[1].pattern), "%s", pattern_b);
    memcpy(rows[1].sha512, SHA_B, sizeof(rows[1].sha512));
    rows[1].updated_at = 2000;

    ASSERT(pin_write_file(path, rows, 2) == 0, "write the colliding pair");
    pin_set_state_file(path);
    ASSERT(pin_load(path) == 0, "load the colliding pair");
    stored = read_file(path);
    ASSERT(stored > 0, "ambiguous file readable");

    ASSERT(pin_remove_by_id(prefix) == -2, "ambiguous prefix reports -2");
    ASSERT(pin_check(pattern_a, SHA_A, old) == PIN_CHECK_MATCH,
           "ambiguous removal keeps the first pin");
    ASSERT(pin_check(pattern_b, SHA_B, old) == PIN_CHECK_MATCH,
           "ambiguous removal keeps the second pin");
    ASSERT(read_file(path) == stored && strstr(g_file_buf, pattern_a) != NULL &&
           strstr(g_file_buf, pattern_b) != NULL,
           "ambiguous removal leaves the file untouched");

    unlink(path);
    TEST_PASS("ambiguous id removal refused");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  pin_clear: empty memory + file, refuse damage, restore on failure */
/* ------------------------------------------------------------------ */

static int test_pin_clear(void)
{
    char path[TPATH];
    char old[129];
    long stored;

    make_test_path(path, sizeof(path), "clear.json");
    ASSERT(reset_pins(path) == 0, "reset");
    ASSERT(pin_store("/usr/bin/clear-a", SHA_A) == 0, "seed clear A");
    ASSERT(pin_store("/usr/bin/clear-b", SHA_B) == 0, "seed clear B");

    ASSERT(pin_clear() == 0, "pin_clear succeeds");
    ASSERT(pin_check("/usr/bin/clear-a", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "A cleared from memory");
    ASSERT(pin_check("/usr/bin/clear-b", SHA_B, old) == PIN_CHECK_FIRST_USE,
           "B cleared from memory");

    ASSERT(read_file(path) > 0, "cleared file readable");
    ASSERT(strstr(g_file_buf, "\"pins\"") != NULL,
           "cleared file still has the pins array");
    ASSERT(strstr(g_file_buf, "\"pattern\"") == NULL,
           "no pin rows remain in the cleared file");
    ASSERT(pin_load(path) == 0, "cleared file reloads cleanly");
    ASSERT(pin_damaged() == 0, "cleared file is not damaged");
    ASSERT(pin_check("/usr/bin/clear-a", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "cleared file has no pins");

    /* Clearing an empty table is a successful, idempotent write. */
    ASSERT(pin_clear() == 0, "clear on an empty table succeeds");

    /* A damaged file is refused and left untouched. */
    ASSERT(pin_store("/usr/bin/clear-c", SHA_A) == 0, "seed clear C");
    ASSERT(write_raw_file(path, "damaged clear state\n") == 0,
           "damage the pin file");
    ASSERT(pin_load(path) == -1, "damaged load");
    stored = read_file(path);
    ASSERT(stored > 0, "damaged file readable");
    ASSERT(pin_clear() == -1, "clear refuses a damaged table");
    ASSERT(read_file(path) == stored &&
           strcmp(g_file_buf, "damaged clear state\n") == 0,
           "damaged file left untouched by clear");
    ASSERT(pin_damaged() == 1, "clear refusal keeps the damage flag");

    unlink(path);
    TEST_PASS("pin_clear empties memory and file");
    return 0;
}

static int test_mutation_write_failure_restores_table(void)
{
    char path[TPATH];
    char id_a[RULEID_HEX_LEN + 1];
    char old[129];

    make_test_path(path, sizeof(path), "mutationfail.json");
    ASSERT(reset_pins(path) == 0, "reset");
    ASSERT(pin_store("/usr/bin/keep-a", SHA_A) == 0, "seed keep A");
    ASSERT(pin_store("/usr/bin/keep-b", SHA_B) == 0, "seed keep B");
    ASSERT(ruleid_pin("/usr/bin/keep-a", id_a) == 0, "keep A id");

    /* Remove: the file-data fsync fails before the rename, so the
     * pre-removal table stays both in memory and on disk. */
    persist_test_fail_fsync_after(0);
    ASSERT(pin_remove_by_id(id_a) == -1, "remove fails on write error");
    persist_test_fail_fsync_after(-1);
    ASSERT(pin_check("/usr/bin/keep-a", SHA_A, old) == PIN_CHECK_MATCH,
           "failed remove restores the removed pin in memory");
    ASSERT(pin_load(path) == 0, "reload after failed remove");
    ASSERT(pin_check("/usr/bin/keep-a", SHA_A, old) == PIN_CHECK_MATCH,
           "failed remove leaves the pin on disk");
    ASSERT(pin_check("/usr/bin/keep-b", SHA_B, old) == PIN_CHECK_MATCH,
           "other pins intact after failed remove");

    /* Clear: the same restore-on-write-failure guarantee. */
    persist_test_fail_fsync_after(0);
    ASSERT(pin_clear() == -1, "clear fails on write error");
    persist_test_fail_fsync_after(-1);
    ASSERT(pin_check("/usr/bin/keep-a", SHA_A, old) == PIN_CHECK_MATCH,
           "failed clear restores A in memory");
    ASSERT(pin_check("/usr/bin/keep-b", SHA_B, old) == PIN_CHECK_MATCH,
           "failed clear restores B in memory");
    ASSERT(pin_load(path) == 0, "reload after failed clear");
    ASSERT(pin_check("/usr/bin/keep-a", SHA_A, old) == PIN_CHECK_MATCH,
           "failed clear leaves the file intact");
    ASSERT(pin_check("/usr/bin/keep-b", SHA_B, old) == PIN_CHECK_MATCH,
           "both pins still on disk");

    /* With the injection off, the next mutation succeeds. */
    ASSERT(pin_remove_by_id(id_a) == 1, "remove succeeds after failures");

    unlink(path);
    TEST_PASS("failed mutations restore the pre-mutation table");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  root refuses unsafe pin-file loads (M3 trust bar); ENOENT = TOFU   */
/* ------------------------------------------------------------------ */

/*
 * Regression for the config_load() trust bar mirrored into
 * pin_load_file(): as root the loader refuses a pin file that is
 * group/other-writable, not root-owned, or reached via a symlink.  The
 * refusal is at least as strict as an fopen failure -- -1 with
 * damaged_out=1 / pin_damaged()==1 (fail closed to the prompt), never
 * an empty table that would silently re-TOFU every rule.  The guard
 * runs only under geteuid()==0: unprivileged runs load the very same
 * file cleanly, and the root-only cases SKIP when unprivileged.  ENOENT
 * keeps meaning TOFU (0 rows, not damaged) for every euid.
 */
static int test_pin_unsafe_load_root_refused(void)
{
    char path[TPATH];
    char victim[TPATH];
    char json[PATH_MAX + 512];
    char old[129];
    PinRecord out[4];
    int damaged = -1;

    /* ENOENT for every euid, before any root-only case. */
    make_test_path(path, sizeof(path), "unsafe_missing.json");
    unlink(path);
    memset(out, 'x', sizeof(out));
    ASSERT(pin_load_file(path, out, 4, &damaged) == 0,
           "missing pin file still returns 0 rows (ENOENT preserved)");
    ASSERT(damaged == 0, "missing pin file is not damaged");
    ASSERT(out[0].pattern[0] == '\0', "missing pin file yields an empty table");

    build_valid_json(json, sizeof(json), "/usr/bin/unsafe", SHA_A, 5);

    /* Group/other-writable file: refused (damaged) as root, loaded
     * unchanged when unprivileged (the trust bar is root-only). */
    make_test_path(path, sizeof(path), "unsafe_mode.json");
    unlink(path);
    ASSERT(write_raw_file(path, json) == 0, "write pin file");
    ASSERT(chmod(path, 0666) == 0, "chmod 0666 the pin file");
    if (geteuid() == 0)
    {
        ASSERT(pin_load(path) == -1,
               "root refuses a group/other-writable pin file");
        ASSERT(pin_damaged() == 1,
               "refusal marks the table damaged (fail closed, not TOFU)");

        damaged = -1;
        ASSERT(pin_load_file(path, out, 4, &damaged) == -1,
               "pin_load_file refuses the writable file");
        ASSERT(damaged == 1,
               "pin_load_file reports damage, not an empty/TOFU table");
        ASSERT(out[0].pattern[0] == '\0', "refused load returns no rows");
    }
    else
    {
        ASSERT(pin_load(path) == 0,
               "unprivileged load of a 0666 file is unaffected");
        ASSERT(pin_damaged() == 0, "unprivileged load is clean");
        ASSERT(pin_check("/usr/bin/unsafe", SHA_A, old) == PIN_CHECK_MATCH,
               "unprivileged load keeps the pin");
    }
    unlink(path);

    if (geteuid() != 0)
    {
        printf("SKIP: pin symlink/foreign-owner load refusal needs root\n");
        TEST_PASS("pin trust bar (root-only) + ENOENT TOFU preserved");
        return 0;
    }

    /* A symlink at the pin path: refused even though the target is a
     * trustworthy root-owned 0600 file; the victim is untouched. */
    make_test_path(victim, sizeof(victim), "unsafe_symlink_victim");
    make_test_path(path, sizeof(path), "unsafe_symlink.json");
    unlink(path);
    unlink(victim);
    ASSERT(write_raw_file(victim, json) == 0, "write symlink victim");
    ASSERT(symlink(victim, path) == 0, "plant symlink at the pin path");
    ASSERT(pin_load(path) == -1, "root refuses a symlinked pin file");
    ASSERT(pin_damaged() == 1, "symlink refusal sets damaged");
    ASSERT(access(victim, F_OK) == 0, "symlink victim left in place");
    unlink(path);

    /* A foreign-owned pin file: refused (chown needs root). */
    make_test_path(path, sizeof(path), "unsafe_owner.json");
    unlink(path);
    ASSERT(write_raw_file(path, json) == 0, "write pin file");
    ASSERT(chown(path, 1, 1) == 0, "chown the pin file to uid 1");
    ASSERT(pin_load(path) == -1, "root refuses a non-root-owned pin file");
    ASSERT(pin_damaged() == 1, "ownership refusal sets damaged");
    unlink(path);

    /* Control: a root-owned 0600 file still loads and clears damage. */
    make_test_path(path, sizeof(path), "unsafe_control.json");
    unlink(path);
    ASSERT(write_raw_file(path, json) == 0, "write control pin file");
    ASSERT(chmod(path, 0600) == 0, "chmod 0600 the control file");
    ASSERT(pin_load(path) == 0, "root-owned 0600 pin file still loads");
    ASSERT(pin_damaged() == 0, "control load is clean");
    ASSERT(pin_check("/usr/bin/unsafe", SHA_A, old) == PIN_CHECK_MATCH,
           "control pin matches");

    unlink(path);
    unlink(victim);
    TEST_PASS("root refuses unsafe pin-file loads; ENOENT TOFU preserved");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  main                                                              */
/* ------------------------------------------------------------------ */

int main(void)
{
    int failed = 0;

    fprintf(stdout, "=== test_pin ===\n");

    /* Per-run temp directory avoids the need for root access. */
    snprintf(g_test_dir, sizeof(g_test_dir), "/tmp/fileshield_test_pin_%d",
             (int)getpid());
    if (mkdir(g_test_dir, 0700) < 0 && errno != EEXIST)
    {
        fprintf(stderr, "FAIL: could not create temp dir %s: %s\n",
                g_test_dir, strerror(errno));
        return 1;
    }

    failed |= test_missing_file();
    failed |= test_store_roundtrip();
    failed |= test_pattern_escaping();
    failed |= test_check_contract();
    failed |= test_damaged_semantics();
    failed |= test_malformed_files();
    failed |= test_unknown_keys_ignored();
    failed |= test_updated_at_refresh();
    failed |= test_cap_eviction_by_store();
    failed |= test_eviction_smallest_updated_at();
    failed |= test_eviction_tie_break();
    failed |= test_write_failure_keeps_memory();
    failed |= test_unwritable_dir_non_root();
    failed |= test_failed_append_then_store();
    failed |= test_pin_strict_structure();
    failed |= test_duplicate_pattern_damaged();
    failed |= test_uppercase_digest_rejected();
    failed |= test_file_api_roundtrip();
    failed |= test_remove_by_id();
    failed |= test_remove_ambiguous_id();
    failed |= test_pin_clear();
    failed |= test_mutation_write_failure_restores_table();
    failed |= test_pin_unsafe_load_root_refused();

    rmdir(g_test_dir);

    if (failed)
    {
        fprintf(stdout, "FAIL\n");
        return 1;
    }
    fprintf(stdout, "PASS\n");
    return 0;
}
