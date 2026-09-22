#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#include "../src/persist.h"

/* All tests write to a temp directory under /tmp to avoid needing root. */
static char g_test_dir[256];

static void make_test_path(char *out, size_t sz, const char *name)
{
    snprintf(out, sz, "%s/%s", g_test_dir, name);
}

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

/* Pre-counted SHA-512 test values (62 hex chars, within 128-char limit) */
#define SHA_GIT "aaaa1111111111111111111111111111111111111111111111111111111111"
#define SHA_VIM "bbbb2222222222222222222222222222222222222222222222222222222222"
#define SHA_SSH "cccc3333333333333333333333333333333333333333333333333333333333"

/* Valid stored rule IDs (16 lowercase hex chars); distinct values prove
 * the field is carried per entry rather than defaulted at save time. */
#define RULE_ID_A "0123456789abcdef"
#define RULE_ID_B "fedcba9876543210"
#define RULE_ID_C "1111111111111111"
#define RULE_ID_D "2222222222222222"
#define RULE_ID_E "3333333333333333"
#define RULE_ID_F "4444444444444444"

static int test_persist_roundtrip(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "roundtrip.json");
    unlink(path);

    PersistEntry in[2];
    memset(in, 0, sizeof(in));

    /* Entry 0: chain depth 2 */
    snprintf(in[0].binary, sizeof(in[0].binary), "/usr/bin/git");
    snprintf(in[0].binary_sha512, sizeof(in[0].binary_sha512),
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    snprintf(in[0].target_path, sizeof(in[0].target_path), "/home/user/.ssh/id_rsa");
    snprintf(in[0].cmdline, sizeof(in[0].cmdline), "git status --short");
    snprintf(in[0].cmdline_sha512, sizeof(in[0].cmdline_sha512),
             "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
             "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    in[0].chain_depth = 2;
    snprintf(in[0].chain_comm[0], sizeof(in[0].chain_comm[0]), "code");
    snprintf(in[0].chain_sha512[0], sizeof(in[0].chain_sha512[0]),
             "1111111111111111111111111111111111111111111111111111111111111111"
             "1111111111111111111111111111111111111111111111111111111111111111");
    snprintf(in[0].chain_comm[1], sizeof(in[0].chain_comm[1]), "systemd");
    snprintf(in[0].chain_sha512[1], sizeof(in[0].chain_sha512[1]),
             "2222222222222222222222222222222222222222222222222222222222222222"
             "2222222222222222222222222222222222222222222222222222222222222222");
    in[0].created_at = (time_t)1700000000;
    snprintf(in[0].rule_id, sizeof(in[0].rule_id), RULE_ID_A);

    /* Entry 1: chain depth 1 */
    snprintf(in[1].binary, sizeof(in[1].binary), "/usr/bin/ssh");
    snprintf(in[1].binary_sha512, sizeof(in[1].binary_sha512),
             "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
             "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    snprintf(in[1].target_path, sizeof(in[1].target_path), "/etc/ssl/private/key.pem");
    in[1].chain_depth = 1;
    snprintf(in[1].chain_comm[0], sizeof(in[1].chain_comm[0]), "bash");
    snprintf(in[1].chain_sha512[0], sizeof(in[1].chain_sha512[0]),
             "3333333333333333333333333333333333333333333333333333333333333333"
             "3333333333333333333333333333333333333333333333333333333333333333");
    in[1].created_at = (time_t)1700001000;
    snprintf(in[1].rule_id, sizeof(in[1].rule_id), RULE_ID_B);

    ASSERT(persist_save(path, in, 2) == 0, "persist_save returned 0");

    PersistEntry out[PERSIST_MAX_ENTRIES];
    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 2, "persist_load returned 2 entries");

    ASSERT(strcmp(out[0].binary, "/usr/bin/git") == 0, "entry0 binary");
    ASSERT(strcmp(out[0].binary_sha512, in[0].binary_sha512) == 0, "entry0 sha512");
    ASSERT(strcmp(out[0].target_path, "/home/user/.ssh/id_rsa") == 0, "entry0 target_path");
    ASSERT(strcmp(out[0].cmdline, "git status --short") == 0, "entry0 cmdline");
    ASSERT(strcmp(out[0].cmdline_sha512, in[0].cmdline_sha512) == 0,
           "entry0 cmdline_sha512");
    ASSERT(out[0].chain_depth == 2, "entry0 chain_depth");
    ASSERT(strcmp(out[0].chain_comm[0], "code") == 0, "entry0 chain_comm[0]");
    ASSERT(strcmp(out[0].chain_comm[1], "systemd") == 0, "entry0 chain_comm[1]");
    ASSERT(strcmp(out[0].chain_sha512[0], in[0].chain_sha512[0]) == 0,
           "entry0 chain_sha512[0]");
    ASSERT(strcmp(out[0].chain_sha512[1], in[0].chain_sha512[1]) == 0,
           "entry0 chain_sha512[1]");
    ASSERT(out[0].created_at == (time_t)1700000000, "entry0 created_at");
    ASSERT(strcmp(out[0].rule_id, RULE_ID_A) == 0, "entry0 rule_id");

    ASSERT(strcmp(out[1].binary, "/usr/bin/ssh") == 0, "entry1 binary");
    ASSERT(strcmp(out[1].rule_id, RULE_ID_B) == 0, "entry1 rule_id");
    ASSERT(strcmp(out[1].target_path, "/etc/ssl/private/key.pem") == 0, "entry1 target_path");
    ASSERT(out[1].chain_depth == 1, "entry1 chain_depth");
    ASSERT(strcmp(out[1].chain_comm[0], "bash") == 0, "entry1 chain_comm[0]");

    unlink(path);
    TEST_PASS("roundtrip save/load");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: max chain depth (depth == PERSIST_CHAIN_MAX)                */
/*  Exercises the formerly-broken chain_comm/sha512[PERSIST_CHAIN_MAX-1] */
/* ------------------------------------------------------------------ */

static int test_persist_max_chain_depth(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "maxchain.json");
    unlink(path);

    PersistEntry in[1];
    memset(in, 0, sizeof(in));

    snprintf(in[0].binary, sizeof(in[0].binary), "/usr/bin/kubectl");
    snprintf(in[0].rule_id, sizeof(in[0].rule_id), RULE_ID_A);
    snprintf(in[0].target_path, sizeof(in[0].target_path), "/var/run/secrets/tls.crt");
    in[0].chain_depth = PERSIST_CHAIN_MAX;
    for (int j = 0; j < PERSIST_CHAIN_MAX; j++)
    {
        snprintf(in[0].chain_comm[j], sizeof(in[0].chain_comm[j]), "ancestor%d", j);
        memset(in[0].chain_sha512[j], '0' + j, 128);
        in[0].chain_sha512[j][128] = '\0';
    }

    ASSERT(persist_save(path, in, 1) == 0, "persist_save max chain");

    PersistEntry out[PERSIST_MAX_ENTRIES];
    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "persist_load max chain returns 1");
    ASSERT(out[0].chain_depth == PERSIST_CHAIN_MAX, "chain_depth == PERSIST_CHAIN_MAX");
    ASSERT(strcmp(out[0].rule_id, RULE_ID_A) == 0, "max chain rule_id");
    ASSERT(strcmp(out[0].target_path, "/var/run/secrets/tls.crt") == 0, "max chain target_path");

    for (int j = 0; j < PERSIST_CHAIN_MAX; j++)
    {
        char expected_comm[32];
        snprintf(expected_comm, sizeof(expected_comm), "ancestor%d", j);
        char msg[64];
        snprintf(msg, sizeof(msg), "chain_comm[%d] correct", j);
        ASSERT(strcmp(out[0].chain_comm[j], expected_comm) == 0, msg);
        snprintf(msg, sizeof(msg), "chain_sha512[%d] correct", j);
        ASSERT(strcmp(out[0].chain_sha512[j], in[0].chain_sha512[j]) == 0, msg);
    }

    unlink(path);
    TEST_PASS("max chain depth roundtrip");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: load from nonexistent file returns 0                        */
/* ------------------------------------------------------------------ */

static int test_persist_load_nonexistent(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "nonexistent.json");
    unlink(path);

    PersistEntry out[PERSIST_MAX_ENTRIES];
    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 0, "load nonexistent returns 0");

    /* A directory opens read-only but cannot be read: the read error must
     * fail the load so the caller clears the in-memory list. */
    ASSERT(persist_load(g_test_dir, out, PERSIST_MAX_ENTRIES) == -1,
           "directory state path fails the load");

    TEST_PASS("load nonexistent file");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: save zero entries, reload returns 0                         */
/* ------------------------------------------------------------------ */

static int test_persist_save_empty(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "empty.json");
    unlink(path);

    PersistEntry dummy[1];
    memset(dummy, 0, sizeof(dummy));
    ASSERT(persist_save(path, dummy, 0) == 0, "persist_save 0 entries");

    PersistEntry out[PERSIST_MAX_ENTRIES];
    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 0, "persist_load after empty save returns 0");

    unlink(path);
    TEST_PASS("save empty entries");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: chain depth variations (1..PERSIST_CHAIN_MAX)               */
/* ------------------------------------------------------------------ */

static int test_persist_chain_depths(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "chains.json");
    unlink(path);

    PersistEntry in[PERSIST_CHAIN_MAX];
    memset(in, 0, sizeof(in));
    static const char *const ids[PERSIST_CHAIN_MAX] = {
        RULE_ID_A, RULE_ID_B, RULE_ID_C
    };

    for (int i = 0; i < PERSIST_CHAIN_MAX; i++)
    {
        snprintf(in[i].binary, sizeof(in[i].binary), "/usr/bin/chain%d", i);
        snprintf(in[i].rule_id, sizeof(in[i].rule_id), "%s", ids[i]);
        snprintf(in[i].target_path, sizeof(in[i].target_path), "/etc/target%d.conf", i);
        in[i].chain_depth = i + 1;
        for (int j = 0; j <= i; j++)
            snprintf(in[i].chain_comm[j], sizeof(in[i].chain_comm[j]), "proc%d", j);
    }

    ASSERT(persist_save(path, in, PERSIST_CHAIN_MAX) == 0, "persist_save chain depths");

    PersistEntry out[PERSIST_MAX_ENTRIES];
    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == PERSIST_CHAIN_MAX, "persist_load chain depths count");

    for (int i = 0; i < PERSIST_CHAIN_MAX; i++)
    {
        char msg[64];
        snprintf(msg, sizeof(msg), "entry %d chain_depth", i);
        ASSERT(out[i].chain_depth == i + 1, msg);
        snprintf(msg, sizeof(msg), "entry %d rule_id", i);
        ASSERT(strcmp(out[i].rule_id, in[i].rule_id) == 0, msg);
        char expected_target[64];
        snprintf(expected_target, sizeof(expected_target), "/etc/target%d.conf", i);
        snprintf(msg, sizeof(msg), "entry %d target_path", i);
        ASSERT(strcmp(out[i].target_path, expected_target) == 0, msg);
        for (int j = 0; j <= i; j++)
        {
            char expected[32];
            snprintf(expected, sizeof(expected), "proc%d", j);
            snprintf(msg, sizeof(msg), "entry %d chain_comm[%d]", i, j);
            ASSERT(strcmp(out[i].chain_comm[j], expected) == 0, msg);
        }
    }

    unlink(path);
    TEST_PASS("chain depth variations");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: JSON special characters are escaped and restored            */
/*  Values are decoded escape-aware, so quotes and backslashes round-  */
/*  trip even though a naive %[^"] scan would stop at the first quote. */
/* ------------------------------------------------------------------ */

static int test_persist_json_escaping(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "escape.json");
    unlink(path);

    PersistEntry in[1];
    memset(in, 0, sizeof(in));

    /* A backslash in a binary path: unusual but valid on Linux. */
    snprintf(in[0].binary, sizeof(in[0].binary), "/usr/bin/my\\tool");
    /* A command line with escaped quotes and a backslash, as produced
     * by `sh -c "..."` invocations. */
    snprintf(in[0].cmdline, sizeof(in[0].cmdline),
             "sh -c \"echo \\\"hi\\\" > /tmp/x\"");
    snprintf(in[0].rule_id, sizeof(in[0].rule_id), RULE_ID_A);
    in[0].chain_depth = 1;
    snprintf(in[0].chain_comm[0], sizeof(in[0].chain_comm[0]), "normalproc");

    ASSERT(persist_save(path, in, 1) == 0, "persist_save escaped chars");

    PersistEntry out[PERSIST_MAX_ENTRIES];
    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "persist_load escaped chars returns 1");
    ASSERT(strcmp(out[0].binary, "/usr/bin/my\\tool") == 0,
           "binary backslash roundtrip");
    ASSERT(strcmp(out[0].cmdline, "sh -c \"echo \\\"hi\\\" > /tmp/x\"") == 0,
           "cmdline quotes and backslash roundtrip");
    ASSERT(strcmp(out[0].chain_comm[0], "normalproc") == 0,
           "chain_comm normal name roundtrip");
    ASSERT(strcmp(out[0].rule_id, RULE_ID_A) == 0,
           "rule_id roundtrips alongside escaped fields");

    unlink(path);
    TEST_PASS("JSON special character escaping");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: malformed state files (negative / oversized chain_depth)    */
/*  Regression test for OOB write in persist_load().                  */
/* ------------------------------------------------------------------ */

static int write_raw_file(const char *path, const char *content)
{
    FILE *fp = fopen(path, "w");
    if (!fp)
        return -1;
    fputs(content, fp);
    fclose(fp);
    /* 0600: a root-run persist_load() refuses group/other-writable
     * files, so raw fixtures must not depend on the ambient umask. */
    if (chmod(path, 0600) != 0)
        return -1;
    return 0;
}

static int test_persist_malformed_depth(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "malformed_depth.json");
    unlink(path);

    const char *negative =
        "{\n  \"entries\": [\n    {\n"
        "      \"binary\": \"/usr/bin/evil\",\n"
        "      \"chain_depth\": -1000000,\n"
        "      \"created_at\": 1\n"
        "    }\n  ]\n}\n";

    ASSERT(write_raw_file(path, negative) == 0, "write negative depth file");

    PersistEntry *out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc negative depth output");

    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "negative depth entry still loads");
    ASSERT(out[0].chain_depth == 0, "negative depth clamped to 0");
    free(out);

    const char *huge =
        "{\n  \"entries\": [\n    {\n"
        "      \"binary\": \"/usr/bin/evil\",\n"
        "      \"chain_depth\": 999999,\n"
        "      \"created_at\": 1\n"
        "    }\n  ]\n}\n";

    ASSERT(write_raw_file(path, huge) == 0, "write huge depth file");

    out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc huge depth output");

    n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "huge depth entry still loads");
    ASSERT(out[0].chain_depth == PERSIST_CHAIN_MAX, "huge depth clamped");
    free(out);

    /* A string where a numeric field belongs is a damaged entry: it is
     * dropped (never admitted with a silently weakened default), while
     * genuinely numeric out-of-range values keep the documented clamp. */
    const char *garbage_depth =
        "{\n  \"entries\": [\n    {\n"
        "      \"binary\": \"/usr/bin/evil\",\n"
        "      \"chain_depth\": \"not-a-number\",\n"
        "      \"created_at\": 1\n"
        "    }\n  ]\n}\n";

    ASSERT(write_raw_file(path, garbage_depth) == 0,
           "write garbage depth file");

    out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc garbage depth output");

    n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 0, "a string-valued chain_depth drops the entry");
    free(out);

    const char *garbage_time =
        "{\n  \"entries\": [\n    {\n"
        "      \"binary\": \"/usr/bin/evil\",\n"
        "      \"chain_depth\": 1,\n"
        "      \"created_at\": \"yesterday\"\n"
        "    }\n  ]\n}\n";

    ASSERT(write_raw_file(path, garbage_time) == 0,
           "write garbage created_at file");

    out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc garbage created_at output");

    n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 0, "a string-valued created_at drops the entry");
    free(out);

    /* A valid sibling survives a dropped entry: only the damaged entry
     * is removed, the rest of the file still loads. */
    const char *mixed =
        "{\n  \"entries\": [\n"
        "    {\n"
        "      \"binary\": \"/usr/bin/good\",\n"
        "      \"chain_depth\": 1,\n"
        "      \"created_at\": 1\n"
        "    },\n"
        "    {\n"
        "      \"binary\": \"/usr/bin/evil\",\n"
        "      \"chain_depth\": \"not-a-number\",\n"
        "      \"created_at\": 1\n"
        "    }\n"
        "  ]\n}\n";

    ASSERT(write_raw_file(path, mixed) == 0, "write mixed damaged entry");
    out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc mixed output");
    n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "only the valid sibling of a damaged entry is admitted");
    ASSERT(strcmp(out[0].binary, "/usr/bin/good") == 0,
           "the surviving entry is the valid one");
    free(out);

    /* A value beyond long's range must be a defined rejection (strtol
     * ERANGE), not scanf's undefined behavior; both numeric fields are
     * left at their defaults. */
    const char *overflow =
        "{\n  \"entries\": [\n    {\n"
        "      \"binary\": \"/usr/bin/evil\",\n"
        "      \"chain_depth\": 999999999999999999999999,\n"
        "      \"created_at\": 999999999999999999999999\n"
        "    }\n  ]\n}\n";

    ASSERT(write_raw_file(path, overflow) == 0, "write overflow file");

    out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc overflow output");

    n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "overflow entry still loads");
    ASSERT(out[0].chain_depth == 0, "overflow depth ignored");
    ASSERT(out[0].created_at == 0, "overflow created_at ignored");
    free(out);

    unlink(path);
    TEST_PASS("malformed chain_depth handling");
    return 0;
}

/*
 * D4: chain-slot keys are parsed with strtol plus range and trailing-junk
 * checks, so a hand-edited or over-long index can never write outside
 * chain_comm[]/chain_sha512[] (the old sscanf("%d") overflow was
 * undefined behavior).  Out-of-range and trailing-junk keys are ignored;
 * the entry still loads with only its valid slots populated.
 */
static int test_persist_chain_slot_junk(void)
{
    char path[PATH_MAX];
    const char *content =
        "{\n  \"entries\": [\n    {\n"
        "      \"binary\": \"/usr/bin/slot\",\n"
        "      \"chain_depth\": 2,\n"
        "      \"created_at\": 5,\n"
        "      \"chain_comm[0]\": \"sh\",\n"
        "      \"chain_comm[99999999999999999999]\": \"overflow\",\n"
        "      \"chain_comm[-1]\": \"negative\",\n"
        "      \"chain_comm[1]\": \"loader\",\n"
        "      \"chain_comm[1]junk\": \"trailing-junk\",\n"
        "      \"chain_comm[3]\": \"out-of-range\",\n"
        "      \"chain_sha512[99999999999999999999]\": \"bad\",\n"
        "      \"chain_sha512[0]\": \"d0\",\n"
        "      \"chain_sha512[3]\": \"bad2\"\n"
        "    }\n  ]\n}\n";

    make_test_path(path, sizeof(path), "chain_slot_junk.json");
    unlink(path);
    ASSERT(write_raw_file(path, content) == 0, "write chain-slot junk file");

    PersistEntry *out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc chain-slot output");

    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "chain-slot junk entries still load");
    ASSERT(strcmp(out[0].binary, "/usr/bin/slot") == 0, "entry binary kept");
    ASSERT(out[0].chain_depth == 2, "chain depth kept");
    ASSERT(strcmp(out[0].chain_comm[0], "sh") == 0,
           "in-range chain slot loaded");
    ASSERT(strcmp(out[0].chain_comm[1], "loader") == 0,
           "a trailing-junk key does not overwrite the real slot");
    ASSERT(out[0].chain_comm[2][0] == '\0',
           "a slot beyond chain_depth stays empty");
    ASSERT(strcmp(out[0].chain_sha512[0], "d0") == 0,
           "in-range chain digest loaded");
    ASSERT(out[0].chain_sha512[1][0] == '\0' &&
               out[0].chain_sha512[2][0] == '\0',
           "no out-of-range chain digest slot was written");

    free(out);
    unlink(path);
    TEST_PASS("chain-slot index parsing is range-checked");
    return 0;
}

static int test_persist_truncated(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "truncated.json");
    unlink(path);

    /* No closing braces: the structural completeness check must report
     * the file as damaged (the caller then clears the in-memory list)
     * instead of loading a partial state as if it were complete. */
    const char *truncated =
        "{\n  \"entries\": [\n    {\n"
        "      \"binary\": \"/usr/bin/evil\",\n"
        "      \"chain_depth\": 2";

    ASSERT(write_raw_file(path, truncated) == 0, "write truncated file");

    PersistEntry *out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc truncated output");

    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == -1, "truncated file is reported as damaged");

    free(out);
    unlink(path);
    TEST_PASS("truncated state file is rejected");
    return 0;
}

/*
 * A structurally foreign file (no "entries" array at all) must be
 * rejected, while a writer-produced empty file still loads cleanly.
 */
static int test_persist_no_structure(void)
{
    char path[PATH_MAX];
    const char *foreign = "{\n  \"other\": [\n  ]\n}\n";

    make_test_path(path, sizeof(path), "no_structure.json");
    unlink(path);
    ASSERT(write_raw_file(path, foreign) == 0, "write foreign-state file");

    PersistEntry *out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc no-structure output");
    ASSERT(persist_load(path, out, PERSIST_MAX_ENTRIES) == -1,
           "a file without an entries array is damaged");
    free(out);

    PersistEntry dummy[1];
    memset(dummy, 0, sizeof(dummy));
    ASSERT(persist_save(path, dummy, 0) == 0, "save empty state");
    out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc empty-state output");
    ASSERT(persist_load(path, out, PERSIST_MAX_ENTRIES) == 0,
           "writer-produced empty state still loads clean");
    free(out);

    unlink(path);
    TEST_PASS("structurally foreign state is rejected");
    return 0;
}

/*
 * A line longer than the reader's buffer cannot come from persist_save():
 * it must fail the load instead of being split and parsed as structure.
 */
static int test_persist_long_line(void)
{
    char path[PATH_MAX];
    const char *head = "{\n  \"entries\": [\n";
    size_t head_len = strlen(head);
    size_t big = (size_t)JSON_LINE_MAX + 1024;
    char *content;

    make_test_path(path, sizeof(path), "longline.json");
    unlink(path);

    content = malloc(head_len + big + 2);
    ASSERT(content != NULL, "alloc long-line content");
    memcpy(content, head, head_len);
    memset(content + head_len, 'x', big);
    content[head_len + big] = '\n';
    content[head_len + big + 1] = '\0';

    ASSERT(write_raw_file(path, content) == 0, "write long-line file");
    free(content);

    PersistEntry *out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc long-line output");
    ASSERT(persist_load(path, out, PERSIST_MAX_ENTRIES) == -1,
           "a line longer than the reader buffer is damaged");
    free(out);

    unlink(path);
    TEST_PASS("over-long state lines are rejected");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: over-cap truncation                                           */
/*  A state file with more entries than the caller's cap loads exactly  */
/*  cap entries instead of crashing or miscounting.                     */
/* ------------------------------------------------------------------ */

static int test_persist_over_cap(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "overcap.json");
    unlink(path);

    PersistEntry in[4];
    memset(in, 0, sizeof(in));
    static const char *const ids[4] = {
        RULE_ID_C, RULE_ID_D, RULE_ID_E, RULE_ID_F
    };
    for (int i = 0; i < 4; i++)
    {
        snprintf(in[i].binary, sizeof(in[i].binary), "/usr/bin/bin%d", i);
        snprintf(in[i].rule_id, sizeof(in[i].rule_id), "%s", ids[i]);
        snprintf(in[i].binary_sha512, sizeof(in[i].binary_sha512),
                 "sha%d", i);
    }
    ASSERT(persist_save(path, in, 4) == 0, "persist_save 4 entries");

    PersistEntry *out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc over-cap output");

    int n = persist_load(path, out, 2);
    ASSERT(n == 2, "load with cap 2 returns exactly 2 entries");
    ASSERT(strcmp(out[0].binary, "/usr/bin/bin0") == 0, "first entry kept");
    ASSERT(strcmp(out[1].binary, "/usr/bin/bin1") == 0, "second entry kept");
    ASSERT(strcmp(out[0].rule_id, RULE_ID_C) == 0,
           "first entry rule_id kept");
    ASSERT(strcmp(out[1].rule_id, RULE_ID_D) == 0,
           "second entry rule_id kept");

    free(out);
    unlink(path);
    TEST_PASS("over-cap truncation");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: a save fully replaces the previous state file               */
/* ------------------------------------------------------------------ */

static int test_persist_save_replaces(void)
{
    char path[PATH_MAX];
    PersistEntry in[2];
    PersistEntry out[PERSIST_MAX_ENTRIES];
    int n;

    make_test_path(path, sizeof(path), "replace.json");
    unlink(path);

    memset(in, 0, sizeof(in));
    snprintf(in[0].binary, sizeof(in[0].binary), "/usr/bin/keep");
    snprintf(in[0].rule_id, sizeof(in[0].rule_id), RULE_ID_A);
    snprintf(in[1].binary, sizeof(in[1].binary), "/usr/bin/drop");
    snprintf(in[1].rule_id, sizeof(in[1].rule_id), RULE_ID_B);

    ASSERT(persist_save(path, in, 2) == 0, "save two entries");
    ASSERT(persist_save(path, in, 1) == 0, "save one entry over it");

    n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "the second save replaced the file, not appended");
    ASSERT(strcmp(out[0].binary, "/usr/bin/keep") == 0,
           "the kept entry is intact");
    ASSERT(strcmp(out[0].rule_id, RULE_ID_A) == 0, "the kept ID is intact");

    unlink(path);
    TEST_PASS("persist_save replaces the previous state");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: persist_write_text roundtrip + 0600 permissions             */
/* ------------------------------------------------------------------ */

/* Read a whole small file into out (NUL-terminated).  Returns the
 * number of bytes read, or -1 when the file cannot be opened. */
static long read_file_text(const char *path, char *out, size_t outsz)
{
    FILE *fp = fopen(path, "r");
    size_t n;

    if (!fp)
        return -1;
    n = fread(out, 1, outsz - 1, fp);
    fclose(fp);
    out[n] = '\0';
    return (long)n;
}

static int test_persist_write_text_roundtrip(void)
{
    char path[PATH_MAX];
    char tmp[PATH_MAX + 64];
    char buf[256];
    struct stat st;
    const char *text = "{\n  \"pin\": \"abc123\"\n}\n";

    make_test_path(path, sizeof(path), "write_text.json");
    unlink(path);

    ASSERT(persist_write_text(path, text) == 0, "persist_write_text returns 0");
    ASSERT(read_file_text(path, buf, sizeof(buf)) == (long)strlen(text),
           "write_text wrote the exact length");
    ASSERT(strcmp(buf, text) == 0, "write_text wrote the exact bytes");

    ASSERT(stat(path, &st) == 0, "stat written file");
    ASSERT((st.st_mode & 0777) == 0600, "new file mode is 0600");

    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    ASSERT(access(tmp, F_OK) != 0, "no temp file left after success");

    unlink(path);
    TEST_PASS("persist_write_text roundtrip + 0600 mode");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: persist_write_text refuses a truncated temp path            */
/* ------------------------------------------------------------------ */

static int test_persist_write_text_temp_path_guard(void)
{
    char dir[PATH_MAX];
    char path[PATH_MAX];
    size_t dlen;
    size_t n = sizeof(path) - 3; /* strlen(path) == PATH_MAX - 3 */
    struct stat st;

    /*
     * A filepath whose ".tmp.<pid>" suffix cannot fit in the reader's
     * PATH_MAX buffer must fail the write cleanly.  Without the guard the
     * temp name would be silently truncated, and the stale-temp retry
     * could unlink a file at the truncated name.
     *
     * The parent is a test-owned 0700 directory: persist_write_text()
     * refuses a parent whose mode cannot be forced to 0700 (D6), and a
     * shared /tmp parent would fail there before the temp-length guard
     * was ever reached.  The test dir keeps the intended guard in play.
     */
    snprintf(dir, sizeof(dir), "%s/temp_guard_%d", g_test_dir, (int)getpid());
    rmdir(dir);
    ASSERT(mkdir(dir, 0700) == 0, "create the temp-guard parent dir");
    ASSERT(stat(dir, &st) == 0 && (st.st_mode & 0777) == 0700,
           "temp-guard parent is 0700");

    dlen = strlen(dir);
    ASSERT(dlen + 1 < n, "parent dir leaves room for the over-long name");
    memcpy(path, dir, dlen);
    path[dlen] = '/';
    memset(path + dlen + 1, 'a', n - dlen - 1);
    path[n] = '\0';
    ASSERT(strlen(path) == n, "constructed path hits PATH_MAX - 3");

    ASSERT(persist_write_text(path, "x") == -1,
           "over-long temp path fails the write");
    ASSERT(access(path, F_OK) != 0, "no file left behind by the refusal");

    rmdir(dir);
    TEST_PASS("persist_write_text temp-path truncation refused");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: persist_write_text replaces an existing file                */
/* ------------------------------------------------------------------ */

static int test_persist_write_text_overwrite(void)
{
    char path[PATH_MAX];
    char buf[256];
    struct stat st;
    const char *first = "first-version-with-a-longer-body\n";
    const char *second = "second\n";

    make_test_path(path, sizeof(path), "write_text_overwrite.json");
    unlink(path);

    ASSERT(persist_write_text(path, first) == 0, "initial write succeeds");
    ASSERT(persist_write_text(path, second) == 0, "overwrite succeeds");
    ASSERT(read_file_text(path, buf, sizeof(buf)) == (long)strlen(second),
           "overwritten file has the new length");
    ASSERT(strcmp(buf, second) == 0, "overwritten file has the new content");

    ASSERT(stat(path, &st) == 0, "stat overwritten file");
    ASSERT((st.st_mode & 0777) == 0600, "overwritten file stays 0600");

    unlink(path);
    TEST_PASS("persist_write_text overwrite");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: persist_write_text creates a missing parent directory 0700  */
/* ------------------------------------------------------------------ */

static int test_persist_write_text_creates_dir(void)
{
    char dir[PATH_MAX];
    char path[PATH_MAX + 32];
    char buf[64];
    struct stat st;
    const char *text = "nested-state";

    snprintf(dir, sizeof(dir), "%s/write_text_dir", g_test_dir);
    snprintf(path, sizeof(path), "%s/state.json", dir);
    unlink(path);
    rmdir(dir);

    ASSERT(persist_write_text(path, text) == 0, "write into a missing parent dir");
    ASSERT(stat(dir, &st) == 0 && S_ISDIR(st.st_mode), "parent dir created");
    ASSERT((st.st_mode & 0777) == 0700, "parent dir mode is 0700");
    ASSERT(read_file_text(path, buf, sizeof(buf)) == (long)strlen(text) &&
           strcmp(buf, text) == 0, "file inside the new dir matches");

    unlink(path);
    rmdir(dir);
    TEST_PASS("persist_write_text creates missing parent dir");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: persist_write_text failure paths leave no partial state     */
/* ------------------------------------------------------------------ */

static int test_persist_write_text_failure(void)
{
    char blocker[PATH_MAX];
    char path[PATH_MAX + 32];
    char tmp[PATH_MAX + 64];
    struct stat st;

    /* A regular file where a directory is needed: creating the parent
     * must fail before any temp file exists. */
    make_test_path(blocker, sizeof(blocker), "write_text_blocker");
    snprintf(path, sizeof(path), "%s/child.json", blocker);
    unlink(path);
    unlink(blocker);
    ASSERT(write_raw_file(blocker, "not a directory") == 0,
           "create blocker file");

    ASSERT(persist_write_text(path, "data") == -1, "un-creatable parent fails");
    ASSERT(stat(path, &st) != 0, "no target file left after failure");
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    ASSERT(access(tmp, F_OK) != 0, "no temp file after parent failure");
    unlink(blocker);

    /* A directory at the target path lets the temp file be written but
     * makes the final rename fail: the temp must be cleaned up and the
     * directory left untouched. */
    make_test_path(path, sizeof(path), "write_text_target_dir");
    rmdir(path);
    ASSERT(mkdir(path, 0700) == 0, "create directory at target path");

    ASSERT(persist_write_text(path, "data") == -1, "write over directory fails");
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    ASSERT(access(tmp, F_OK) != 0, "temp removed when rename fails");
    ASSERT(stat(path, &st) == 0 && S_ISDIR(st.st_mode), "target dir untouched");

    rmdir(path);
    TEST_PASS("persist_write_text failure paths");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: a planted symlink at the temp path is never followed        */
/* ------------------------------------------------------------------ */

static int test_persist_write_text_symlink_temp(void)
{
    char path[PATH_MAX];
    char victim[PATH_MAX];
    char tmp[PATH_MAX + 64];
    char buf[64];
    struct stat st;

    make_test_path(path, sizeof(path), "write_text_symlink.json");
    make_test_path(victim, sizeof(victim), "write_text_symlink_victim");
    unlink(path);
    unlink(victim);
    ASSERT(write_raw_file(victim, "victim") == 0, "create symlink victim");

    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    unlink(tmp);
    ASSERT(symlink(victim, tmp) == 0, "plant symlink at the temp path");

    ASSERT(persist_write_text(path, "safe") == 0,
           "write replaces the planted symlink with a real temp file");
    ASSERT(read_file_text(victim, buf, sizeof(buf)) == 6 &&
               strcmp(buf, "victim") == 0,
           "symlink target is untouched");
    ASSERT(lstat(tmp, &st) != 0, "no temp file left after the write");
    ASSERT(read_file_text(path, buf, sizeof(buf)) == 4 &&
               strcmp(buf, "safe") == 0,
           "target file holds the written text");

    unlink(path);
    unlink(victim);
    TEST_PASS("write_text never follows a planted temp symlink");
    return 0;
}

/*
 * fsync failures must fail the write.  The injection seam makes the
 * first fsync (file data) and the second (directory after the rename)
 * fail on any filesystem.
 */
static int test_persist_fsync_failure(void)
{
    char path[PATH_MAX];
    char tmp[PATH_MAX + 64];
    char buf[256];
    const char *old_text = "{\"version\":\"old\"}\n";
    const char *new_text = "{\"version\":\"new\"}\n";

    make_test_path(path, sizeof(path), "fsync_fail.json");
    unlink(path);
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());

    ASSERT(persist_write_text(path, old_text) == 0, "initial write");

    /* File-data fsync fails: the temp file is removed and the previous
     * file is untouched. */
    persist_test_fail_fsync_after(0);
    ASSERT(persist_write_text(path, new_text) == -1,
           "file fsync failure fails the write");
    ASSERT(access(tmp, F_OK) != 0, "temp file removed after fsync failure");
    ASSERT(read_file_text(path, buf, sizeof(buf)) == (long)strlen(old_text) &&
               strcmp(buf, old_text) == 0,
           "previous file untouched after fsync failure");

    /* Directory fsync fails after the rename committed: the new file is
     * live, but the write must still be reported as failed so callers do
     * not treat it as durable. */
    persist_test_fail_fsync_after(1);
    ASSERT(persist_write_text(path, new_text) == -1,
           "directory fsync failure fails the write");
    ASSERT(read_file_text(path, buf, sizeof(buf)) == (long)strlen(new_text) &&
               strcmp(buf, new_text) == 0,
           "rename committed when only the directory fsync failed");

    persist_test_fail_fsync_after(-1);
    ASSERT(persist_write_text(path, old_text) == 0,
           "injection disabled again");

    unlink(path);
    TEST_PASS("fsync failures fail the write");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: public JSON escape/extract helpers roundtrip                */
/* ------------------------------------------------------------------ */

static int test_persist_json_helpers(void)
{
    const char *raw = "a\"b\\c\nd"; /* quote, backslash, newline */
    const char *expected_escaped = "a\\\"b\\\\c\\nd";
    char escaped[64];
    char line[128];
    char key[64];
    char out[64];
    char tiny[4];
    int n;

    n = persist_json_escape(raw, escaped, sizeof(escaped));
    ASSERT(n == (int)strlen(expected_escaped), "escape returns written length");
    ASSERT(strcmp(escaped, expected_escaped) == 0, "escape output is exact");

    snprintf(line, sizeof(line), "  \"cmdline\": \"%s\",", escaped);
    ASSERT(persist_json_extract_string(line, key, sizeof(key), out,
                                       sizeof(out)) == 1,
           "extract finds the string pair");
    ASSERT(strcmp(key, "cmdline") == 0, "extract returns the key");
    ASSERT(strcmp(out, raw) == 0, "escape/extract roundtrip");

    /* Control characters decode from \uXXXX back to their byte value. */
    {
        const char *ctrl = "x\x01y";
        char ctrl_escaped[32];
        char ctrl_line[64];

        ASSERT(persist_json_escape(ctrl, ctrl_escaped, sizeof(ctrl_escaped)) > 0,
               "escape control character");
        ASSERT(strcmp(ctrl_escaped, "x\\u0001y") == 0,
               "control char uses \\u form");
        snprintf(ctrl_line, sizeof(ctrl_line), "  \"v\": \"%s\"", ctrl_escaped);
        ASSERT(persist_json_extract_string(ctrl_line, key, sizeof(key), out,
                                           sizeof(out)) == 1,
               "extract control char value");
        ASSERT(strcmp(out, ctrl) == 0, "control char roundtrip");
    }

    /* Short \u escapes must advance only past the digits they consumed;
     * an unconditional four-byte advance would scan past the closing
     * quote into the rest of the buffer. */
    ASSERT(persist_json_extract_string("  \"k\": \"\\u1\"", key, sizeof(key),
                                       out, sizeof(out)) == 1,
           "short \\u escape parses");
    ASSERT(strcmp(out, "\x01") == 0, "short \\u escape decodes");
    ASSERT(strcmp(key, "k") == 0, "short \\u escape returns the key");

    ASSERT(persist_json_extract_string("  \"k\": \"\\u12\",", key, sizeof(key),
                                       out, sizeof(out)) == 1,
           "short \\u before more content parses");
    ASSERT(strcmp(out, "\x12") == 0, "short \\u before more content decodes");

    /* \u0000 cannot be represented in the decoded value; a bare \u has
     * no digits at all.  Both are malformed. */
    ASSERT(persist_json_extract_string("  \"k\": \"\\u0000x\"", key, sizeof(key),
                                       out, sizeof(out)) == 0,
           "\\u0000 is rejected");
    ASSERT(persist_json_extract_string("  \"k\": \"\\u\"", key, sizeof(key),
                                       out, sizeof(out)) == 0,
           "\\u with no digits is rejected");

    /* Error paths: too-small escape buffer and numeric values. */
    ASSERT(persist_json_escape("abcdef", tiny, sizeof(tiny)) == -1,
           "escape fails when the buffer is too small");
    ASSERT(persist_json_extract_string("  \"chain_depth\": 2,", key, sizeof(key),
                                       out, sizeof(out)) == 0,
           "extract rejects numeric values");

    TEST_PASS("persist_json_escape/extract public helpers");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: persist_save serialization is byte-for-byte fixed           */
/* ------------------------------------------------------------------ */

static int test_persist_save_fixed_bytes(void)
{
    char path[PATH_MAX];
    char content[2048];
    PersistEntry in[1];
    static const char expected[] =
        "{\n"
        "  \"entries\": [\n"
        "    {\n"
        "      \"rule_id\": \"0123456789abcdef\",\n"
        "      \"binary\": \"/usr/bin/fixed\",\n"
        "      \"binary_sha512\": \"abc123\",\n"
        "      \"target_path\": \"/etc/fixed.conf\",\n"
        "      \"cmdline\": \"fixed --run\",\n"
        "      \"cmdline_sha512\": \"def456\",\n"
        "      \"chain_depth\": 1,\n"
        "      \"created_at\": 1700002000,\n"
        "      \"chain_comm[0]\": \"bash\",\n"
        "      \"chain_comm[1]\": \"\",\n"
        "      \"chain_comm[2]\": \"\",\n"
        "      \"chain_sha512[0]\": \"111\",\n"
        "      \"chain_sha512[1]\": \"\",\n"
        "      \"chain_sha512[2]\": \"\"\n"
        "    }\n"
        "  ]\n"
        "}\n";

    make_test_path(path, sizeof(path), "fixed_bytes.json");
    unlink(path);

    memset(in, 0, sizeof(in));
    snprintf(in[0].binary, sizeof(in[0].binary), "/usr/bin/fixed");
    snprintf(in[0].rule_id, sizeof(in[0].rule_id), RULE_ID_A);
    snprintf(in[0].binary_sha512, sizeof(in[0].binary_sha512), "abc123");
    snprintf(in[0].target_path, sizeof(in[0].target_path), "/etc/fixed.conf");
    snprintf(in[0].cmdline, sizeof(in[0].cmdline), "fixed --run");
    snprintf(in[0].cmdline_sha512, sizeof(in[0].cmdline_sha512), "def456");
    in[0].chain_depth = 1;
    snprintf(in[0].chain_comm[0], sizeof(in[0].chain_comm[0]), "bash");
    snprintf(in[0].chain_sha512[0], sizeof(in[0].chain_sha512[0]), "111");
    in[0].created_at = (time_t)1700002000;

    ASSERT(persist_save(path, in, 1) == 0, "persist_save fixed entry");
    ASSERT(read_file_text(path, content, sizeof(content)) == (long)strlen(expected),
           "fixed entry serializes to the expected length");
    ASSERT(strcmp(content, expected) == 0,
           "fixed entry serializes byte-for-byte unchanged");

    unlink(path);
    TEST_PASS("persist_save serialization fixed (rule_id included)");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: the worst-case escaped field fits and round-trips            */
/* ------------------------------------------------------------------ */

static int test_persist_escape_overflow_fails(void)
{
    char path[PATH_MAX];
    PersistEntry in[1];
    PersistEntry out[PERSIST_MAX_ENTRIES];

    make_test_path(path, sizeof(path), "escape_overflow.json");
    unlink(path);

    memset(in, 0, sizeof(in));
    snprintf(in[0].rule_id, sizeof(in[0].rule_id), RULE_ID_A);
    /* Worst case: a full-length field of control bytes, each escaping to
     * six characters (\uXXXX).  JSON_ESCAPED_MAX is sized for exactly
     * this, so the save must now succeed and the field must survive a
     * load byte-exact. */
    memset(in[0].target_path, 0x01, sizeof(in[0].target_path) - 1);
    in[0].target_path[sizeof(in[0].target_path) - 1] = '\0';

    ASSERT(persist_save(path, in, 1) == 0,
           "worst-case escaped field fits the shared scratch buffer");

    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "the escaped full-length field round-trips");
    ASSERT(strcmp(out[0].target_path, in[0].target_path) == 0,
           "escaped field round-trips byte-exact");
    ASSERT(strcmp(out[0].rule_id, RULE_ID_A) == 0,
           "rule_id survives the escaped field");

    /* A NULL entry array fails the save without leaving files behind. */
    ASSERT(persist_save(path, NULL, 1) == -1,
           "NULL entry array fails the save");

    TEST_PASS("persist_save handles the worst-case escaped field");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: stored rule_id round-trips byte-identically                  */
/* ------------------------------------------------------------------ */

static int test_persist_rule_id_roundtrip(void)
{
    char path[PATH_MAX];
    PersistEntry in[2];
    PersistEntry out[PERSIST_MAX_ENTRIES];

    make_test_path(path, sizeof(path), "rule_id_roundtrip.json");
    unlink(path);

    memset(in, 0, sizeof(in));
    snprintf(in[0].binary, sizeof(in[0].binary), "/usr/bin/id0");
    snprintf(in[0].rule_id, sizeof(in[0].rule_id), RULE_ID_A);
    snprintf(in[0].target_path, sizeof(in[0].target_path), "/etc/id0.conf");
    in[0].created_at = (time_t)1700003000;

    snprintf(in[1].binary, sizeof(in[1].binary), "/usr/bin/id1");
    snprintf(in[1].rule_id, sizeof(in[1].rule_id), RULE_ID_B);

    ASSERT(persist_save(path, in, 2) == 0, "save entries with rule_ids");

    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 2, "both rule_id entries load");
    ASSERT(strcmp(out[0].rule_id, RULE_ID_A) == 0, "entry0 rule_id preserved");
    ASSERT(strcmp(out[1].rule_id, RULE_ID_B) == 0, "entry1 rule_id preserved");
    ASSERT(strcmp(out[0].binary, "/usr/bin/id0") == 0, "entry0 binary intact");
    ASSERT(strcmp(out[1].binary, "/usr/bin/id1") == 0, "entry1 binary intact");
    ASSERT(out[0].created_at == (time_t)1700003000, "entry0 created_at intact");

    unlink(path);
    TEST_PASS("rule_id roundtrip");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: persist_save writes one "rule_id" line per entry             */
/* ------------------------------------------------------------------ */

static int test_persist_save_writes_rule_id(void)
{
    char path[PATH_MAX];
    char content[4096];
    PersistEntry in[2];

    make_test_path(path, sizeof(path), "rule_id_lines.json");
    unlink(path);

    memset(in, 0, sizeof(in));
    snprintf(in[0].binary, sizeof(in[0].binary), "/usr/bin/idline0");
    snprintf(in[0].rule_id, sizeof(in[0].rule_id), RULE_ID_A);
    snprintf(in[1].binary, sizeof(in[1].binary), "/usr/bin/idline1");
    snprintf(in[1].rule_id, sizeof(in[1].rule_id), RULE_ID_B);

    ASSERT(persist_save(path, in, 2) == 0, "save two entries with IDs");
    ASSERT(read_file_text(path, content, sizeof(content)) > 0,
           "read written state file");

    /* The exact key/value pair must appear once per entry. */
    int occurrences = 0;
    for (const char *p = content; (p = strstr(p, "\"rule_id\"")) != NULL; p++)
        occurrences++;
    ASSERT(occurrences == 2, "one rule_id line per entry");
    ASSERT(strstr(content, "\"rule_id\": \"" RULE_ID_A "\"") != NULL,
           "entry0 rule_id value written");
    ASSERT(strstr(content, "\"rule_id\": \"" RULE_ID_B "\"") != NULL,
           "entry1 rule_id value written");

    unlink(path);
    TEST_PASS("save writes a rule_id line per entry");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: a legacy line without rule_id loads with an empty ID         */
/* ------------------------------------------------------------------ */

static int test_persist_legacy_without_rule_id(void)
{
    char path[PATH_MAX];
    PersistEntry *out;
    const char *legacy =
        "{\n  \"entries\": [\n    {\n"
        "      \"binary\": \"/usr/bin/legacy\",\n"
        "      \"target_path\": \"/etc/legacy.conf\",\n"
        "      \"chain_depth\": 1,\n"
        "      \"created_at\": 5\n"
        "    }\n  ]\n}\n";

    make_test_path(path, sizeof(path), "legacy_no_id.json");
    unlink(path);
    ASSERT(write_raw_file(path, legacy) == 0, "write legacy state file");

    out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc legacy output");

    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "legacy entry is counted");
    ASSERT(out[0].rule_id[0] == '\0', "legacy entry has an empty rule_id");
    ASSERT(strcmp(out[0].binary, "/usr/bin/legacy") == 0, "legacy binary loads");
    ASSERT(strcmp(out[0].target_path, "/etc/legacy.conf") == 0,
           "legacy target_path loads");
    ASSERT(out[0].chain_depth == 1, "legacy chain_depth loads");

    free(out);
    unlink(path);
    TEST_PASS("legacy state without rule_id loads");
    return 0;
}

/*
 * Append one raw JSON entry carrying a rule_id value (use "" for an
 * explicit empty string) to a bounded buffer.  A trailing comma is fine:
 * the line parser ends the object at '}'.  Returns 0 on success.
 */
static int append_raw_rule_entry(char *buf, size_t cap, size_t *off,
                                 const char *rule_id, const char *binary)
{
    int n = snprintf(buf + *off, cap - *off,
                     "    {\n"
                     "      \"rule_id\": \"%s\",\n"
                     "      \"binary\": \"%s\",\n"
                     "      \"chain_depth\": 0,\n"
                     "      \"created_at\": 1\n"
                     "    },\n",
                     rule_id, binary);
    if (n < 0 || (size_t)n >= cap - *off)
        return -1;
    *off += (size_t)n;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: malformed rule_ids drop only their own entry                 */
/* ------------------------------------------------------------------ */

static int test_persist_invalid_rule_id_rejected(void)
{
    char path[PATH_MAX];
    char content[8192];
    char binary[64];
    size_t off;
    int f;
    static const char *bad[] = {
        "0123456789ABCDEF",  /* uppercase      */
        "0123456789abcde",   /* 15 chars       */
        "0123456789abcdef0", /* 17 chars       */
        "0123456789abcdeg",  /* non-hex char   */
        ""                   /* explicit empty */
    };
    PersistEntry *out;

    make_test_path(path, sizeof(path), "bad_ids.json");
    unlink(path);

    f = snprintf(content, sizeof(content), "{\n  \"entries\": [\n");
    ASSERT(f > 0 && (size_t)f < sizeof(content), "bounded header");
    off = (size_t)f;

    ASSERT(append_raw_rule_entry(content, sizeof(content), &off, RULE_ID_A,
                                 "/usr/bin/good0") == 0, "append first good");
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        snprintf(binary, sizeof(binary), "/usr/bin/bad%zu", i);
        ASSERT(append_raw_rule_entry(content, sizeof(content), &off, bad[i],
                                     binary) == 0, "append bad entry");
    }

    /* An undecodable rule_id (unterminated string) is still a present key:
     * extraction fails, but the entry must not slip through as legacy. */
    f = snprintf(content + off, sizeof(content) - off,
                 "    {\n"
                 "      \"rule_id\": \"abc,\n"
                 "      \"binary\": \"/usr/bin/badtrunc\",\n"
                 "      \"created_at\": 1\n"
                 "    },\n");
    ASSERT(f > 0 && (size_t)f < sizeof(content) - off, "append undecodable");
    off += (size_t)f;

    ASSERT(append_raw_rule_entry(content, sizeof(content), &off, RULE_ID_B,
                                 "/usr/bin/good1") == 0, "append second good");

    f = snprintf(content + off, sizeof(content) - off, "  ]\n}\n");
    ASSERT(f > 0 && (size_t)f < sizeof(content) - off, "bounded footer");

    ASSERT(write_raw_file(path, content) == 0, "write mixed state file");

    out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc mixed output");

    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 2, "only the valid siblings are admitted");
    ASSERT(strcmp(out[0].rule_id, RULE_ID_A) == 0, "first valid ID kept");
    ASSERT(strcmp(out[0].binary, "/usr/bin/good0") == 0,
           "first valid binary kept");
    ASSERT(strcmp(out[1].rule_id, RULE_ID_B) == 0, "second valid ID kept");
    ASSERT(strcmp(out[1].binary, "/usr/bin/good1") == 0,
           "second valid binary kept");

    free(out);
    unlink(path);
    TEST_PASS("malformed rule_ids drop only their own entry");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: a file with only invalid rule_ids loads as 0 entries         */
/* ------------------------------------------------------------------ */

static int test_persist_all_rule_ids_invalid(void)
{
    char path[PATH_MAX];
    char content[4096];
    char binary[64];
    size_t off;
    int f;
    static const char *bad[] = { "0123456789ABCDEF", "nope" };
    PersistEntry *out;

    make_test_path(path, sizeof(path), "all_bad_ids.json");
    unlink(path);

    f = snprintf(content, sizeof(content), "{\n  \"entries\": [\n");
    ASSERT(f > 0 && (size_t)f < sizeof(content), "bounded header");
    off = (size_t)f;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        snprintf(binary, sizeof(binary), "/usr/bin/onlybad%zu", i);
        ASSERT(append_raw_rule_entry(content, sizeof(content), &off, bad[i],
                                     binary) == 0, "append invalid entry");
    }
    f = snprintf(content + off, sizeof(content) - off, "  ]\n}\n");
    ASSERT(f > 0 && (size_t)f < sizeof(content) - off, "bounded footer");

    ASSERT(write_raw_file(path, content) == 0, "write all-invalid state file");

    out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc all-invalid output");

    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 0, "only invalid IDs: 0 entries loaded, not -1");

    free(out);
    unlink(path);
    TEST_PASS("all-invalid rule_id file is not a load failure");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: root refuses unsafe state-file loads (M3 trust bar);         */
/*        ENOENT still means an empty table everywhere                 */
/* ------------------------------------------------------------------ */

/*
 * Regression for the config_load() trust bar mirrored into persist_load():
 * as root the loader refuses a state file that is group/other-writable,
 * not root-owned, or reached via a symlink -- each refusal is the same
 * fail-secure -1 as an open error (the caller clears the in-memory list),
 * never a silent empty/partial load.  The ownership guard runs only under
 * geteuid()==0, so unprivileged runs load the very same file cleanly;
 * those root-only cases SKIP when unprivileged.  ENOENT keeps meaning
 * "empty table" for every euid.
 */
static int test_persist_load_unsafe_refused(void)
{
    char path[PATH_MAX];
    char victim[PATH_MAX];
    PersistEntry out[PERSIST_MAX_ENTRIES];
    const char *content =
        "{\n  \"entries\": [\n    {\n"
        "      \"rule_id\": \"0123456789abcdef\",\n"
        "      \"binary\": \"/usr/bin/unsafe\",\n"
        "      \"chain_depth\": 0,\n"
        "      \"created_at\": 1\n"
        "    }\n  ]\n}\n";

    /* ENOENT: a missing file is an empty table (0), not an error --
     * asserted for every euid, before any root-only case. */
    make_test_path(path, sizeof(path), "unsafe_missing.json");
    unlink(path);
    ASSERT(persist_load(path, out, PERSIST_MAX_ENTRIES) == 0,
           "missing file still returns 0 (ENOENT preserved)");

    /* Group/other-writable file: refused as root, loaded unchanged when
     * unprivileged (the trust bar is root-only). */
    make_test_path(path, sizeof(path), "unsafe_mode.json");
    unlink(path);
    ASSERT(write_raw_file(path, content) == 0, "write state file");
    ASSERT(chmod(path, 0666) == 0, "chmod 0666 the state file");
    if (geteuid() == 0)
    {
        ASSERT(persist_load(path, out, PERSIST_MAX_ENTRIES) == -1,
               "root refuses a group/other-writable state file");
    }
    else
    {
        ASSERT(persist_load(path, out, PERSIST_MAX_ENTRIES) == 1,
               "unprivileged load is unaffected by the root-only bar");
        ASSERT(strcmp(out[0].binary, "/usr/bin/unsafe") == 0,
               "unprivileged load parses the file normally");
    }
    unlink(path);

    if (geteuid() != 0)
    {
        printf("SKIP: symlink/foreign-owner state-file refusal needs root\n");
        TEST_PASS("state-file trust bar (root-only) + ENOENT preserved");
        return 0;
    }

    /* A symlink at the state path: refused even though the target is a
     * perfectly trustworthy root-owned 0600 file. */
    make_test_path(victim, sizeof(victim), "unsafe_symlink_victim");
    make_test_path(path, sizeof(path), "unsafe_symlink.json");
    unlink(path);
    unlink(victim);
    ASSERT(write_raw_file(victim, content) == 0, "write symlink victim");
    ASSERT(symlink(victim, path) == 0, "plant symlink at the state path");
    ASSERT(persist_load(path, out, PERSIST_MAX_ENTRIES) == -1,
           "root refuses a symlinked state file");
    ASSERT(access(victim, F_OK) == 0, "symlink victim left in place");
    unlink(path);

    /* A foreign-owned state file: refused (chown needs root, so this
     * case only exists in the root branch). */
    make_test_path(path, sizeof(path), "unsafe_owner.json");
    unlink(path);
    ASSERT(write_raw_file(path, content) == 0, "write state file");
    ASSERT(chown(path, 1, 1) == 0, "chown the state file to uid 1");
    ASSERT(persist_load(path, out, PERSIST_MAX_ENTRIES) == -1,
           "root refuses a non-root-owned state file");
    unlink(path);

    /* Control: a root-owned 0600 file still loads -- the bar is not
     * over-broad. */
    make_test_path(path, sizeof(path), "unsafe_control.json");
    unlink(path);
    ASSERT(write_raw_file(path, content) == 0, "write control state file");
    ASSERT(chmod(path, 0600) == 0, "chmod 0600 the control file");
    ASSERT(persist_load(path, out, PERSIST_MAX_ENTRIES) == 1,
           "root-owned 0600 state file still loads");
    ASSERT(strcmp(out[0].binary, "/usr/bin/unsafe") == 0,
           "control load parses the entry");

    unlink(path);
    unlink(victim);
    TEST_PASS("root refuses unsafe state-file loads; ENOENT preserved");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */

int main(void)
{
    int failed = 0;

    fprintf(stdout, "=== test_persist ===\n");

    /* Per-run temp directory avoids the need for root access. */
    snprintf(g_test_dir, sizeof(g_test_dir), "/tmp/fileshield_test_%d", (int)getpid());
    if (mkdir(g_test_dir, 0700) < 0 && errno != EEXIST)
    {
        fprintf(stderr, "FAIL: could not create temp dir %s: %s\n",
                g_test_dir, strerror(errno));
        return 1;
    }

    failed |= test_persist_load_nonexistent();
    failed |= test_persist_roundtrip();
    failed |= test_persist_max_chain_depth();
    failed |= test_persist_save_empty();
    failed |= test_persist_chain_depths();
    failed |= test_persist_json_escaping();
    failed |= test_persist_malformed_depth();
    failed |= test_persist_chain_slot_junk();
    failed |= test_persist_truncated();
    failed |= test_persist_no_structure();
    failed |= test_persist_long_line();
    failed |= test_persist_fsync_failure();
    failed |= test_persist_over_cap();
    failed |= test_persist_save_replaces();
    failed |= test_persist_write_text_roundtrip();
    failed |= test_persist_write_text_temp_path_guard();
    failed |= test_persist_write_text_overwrite();
    failed |= test_persist_write_text_creates_dir();
    failed |= test_persist_write_text_failure();
    failed |= test_persist_write_text_symlink_temp();
    failed |= test_persist_json_helpers();
    failed |= test_persist_save_fixed_bytes();
    failed |= test_persist_escape_overflow_fails();
    failed |= test_persist_rule_id_roundtrip();
    failed |= test_persist_save_writes_rule_id();
    failed |= test_persist_legacy_without_rule_id();
    failed |= test_persist_invalid_rule_id_rejected();
    failed |= test_persist_all_rule_ids_invalid();
    failed |= test_persist_load_unsafe_refused();

    rmdir(g_test_dir);

    if (failed)
    {
        fprintf(stdout, "FAIL\n");
        return 1;
    }
    fprintf(stdout, "PASS\n");
    return 0;
}
