/*
 * test_session: session-scoped allow/deny entries keyed by POSIX session
 * id + session-leader start time, with optional TTL and binary hash
 * verification.
 *
 * Each test spawns its own session leader child (setsid + pause) so the
 * tests do not depend on the harness being attached to a live terminal.
 */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/session.h"

static int failures = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", (msg)); \
        failures++; \
    } \
} while(0)

static void stop_leader(pid_t pid)
{
    if (pid > 0)
    {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
}

/* Fork a child that becomes a new session leader and sleeps until killed.
 * A pipe synchronizes so the parent only reads its /proc entry after
 * setsid() has taken effect (otherwise the recorded SID could still be the
 * harness's session). */
static pid_t spawn_leader(void)
{
    int sync_pipe[2];
    char token = 'x';

    if (pipe(sync_pipe) != 0)
        return -1;

    pid_t pid = fork();
    if (pid == 0)
    {
        close(sync_pipe[0]);
        if (setsid() < 0)
            _exit(1);
        ssize_t ignored = write(sync_pipe[1], &token, 1);
        (void)ignored;
        close(sync_pipe[1]);
        for (;;)
            pause();
    }

    close(sync_pipe[1]);
    ssize_t n = read(sync_pipe[0], &token, 1);
    close(sync_pipe[0]);
    if (n != 1)
    {
        stop_leader(pid);
        return -1;
    }
    return pid;
}

/* Resolve the fixture session; returns 0 on success. */
static int fixture_session(pid_t leader, pid_t *sid, unsigned long long *start)
{
    if (leader <= 0)
        return -1;
    return session_id_of(leader, sid, start);
}

static int is_hex_id(const char *id)
{
    if (strlen(id) != RULEID_HEX_LEN)
        return 0;
    for (int i = 0; i < RULEID_HEX_LEN; i++)
    {
        char c = id[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

/* Index of the snapshot record whose target matches, or -1.  Keeps the
 * per-entry assertions independent of the table order. */
static int record_for_target(const SessionRecord *recs, int n,
                             const char *target)
{
    for (int i = 0; i < n; i++)
    {
        if (strcmp(recs[i].target, target) == 0)
            return i;
    }
    return -1;
}

static void test_session_id_of(void)
{
    pid_t leader = spawn_leader();
    pid_t sid = 0;
    unsigned long long start = 0;

    ASSERT(leader > 0, "fork session leader");
    ASSERT(fixture_session(leader, &sid, &start) == 0, "session_id_of leader");
    ASSERT(sid == leader, "leader's session id is its own pid");
    ASSERT(start > 0, "leader start time captured");

    pid_t self_sid = getsid(0);
    ASSERT(session_id_of(getpid(), &sid, &start) == 0, "session_id_of self");
    ASSERT(sid == self_sid, "self session id matches getsid(0)");

    ASSERT(session_id_of((pid_t)99999999, &sid, &start) == -1,
           "session_id_of missing pid fails");

    stop_leader(leader);
}

static void test_allow_match(void)
{
    session_clear();

    pid_t leader = spawn_leader();
    pid_t sid = 0;
    unsigned long long start = 0;
    ASSERT(fixture_session(leader, &sid, &start) == 0, "fixture session");
    if (leader <= 0)
        return;

    const char *bin = "/usr/bin/kubectl";
    const char *hash = "aaaaaaaaaaaaaaaa";
    const char *target = "/home/u/.kube/config";

    session_allow_add(sid, start, bin, hash, target, 0);

    ASSERT(session_allow_match(sid, bin, hash, target) == 1,
           "allow match on exact key");
    ASSERT(session_allow_match(sid, bin, hash, "/home/u/.kube/other") == 0,
           "other target does not match");
    ASSERT(session_allow_match(sid, "/usr/bin/other", hash, target) == 0,
           "other binary does not match");
    ASSERT(session_allow_match(sid + 12345, bin, hash, target) == 0,
           "other session does not match");
    ASSERT(session_allow_match(sid, bin, "", target) == 0,
           "missing current hash fails closed");
    ASSERT(session_allow_match(sid, bin, "bbbbbbbbbbbbbbbb", target) == 0,
           "wrong hash does not match");

    stop_leader(leader);
}

/*
 * Fail-closed digest rule: an entry that stores no binary SHA-512 must
 * never match, even when the requester presents a digest.  Pre-fix,
 * hash_matches() returned 1 for an empty stored digest, so one
 * hash-failure grant covered any later binary at the same path for the
 * session's lifetime.  session_allow_add() still stores such an entry
 * (the recorder, not this module, owns that guard), which is exactly what
 * lets this test pin the matcher's behavior.
 */
/*
 * A digest-less session entry is deliberate: unhashable binaries
 * (AppImages under /tmp/.mount_*, self-updating tools) rely on "Allow
 * Session" as their scoped grant.  The entry matches any requester digest
 * for the same binary path and target while the session lives; a recorded
 * digest still must match.  A past review turned the empty stored digest
 * into a fail-closed rejection and broke that use case — this test pins
 * the restored, intended behavior so it is not "fixed" again.
 */
static void test_empty_digest_matches_for_session(void)
{
    pid_t leader;
    pid_t sid = 0;
    unsigned long long start = 0;
    const char *bin = "/usr/bin/evil";
    const char *target = "/home/u/.ssh/id_rsa";
    SessionRecord recs[4];
    int total = 0;

    session_clear();
    leader = spawn_leader();
    ASSERT(fixture_session(leader, &sid, &start) == 0, "fixture session");
    if (leader <= 0)
        return;

    session_allow_add(sid, start, bin, "", target, 0);
    ASSERT(session_snapshot(0, recs, 4, &total) == 1 && total == 1,
           "the digest-less allow entry is stored");
    ASSERT(session_allow_match(sid, bin, "", target) == 1,
           "empty stored digest matches without a requester digest");
    ASSERT(session_allow_match(sid, bin, "cccccccccccccccc", target) == 1,
           "empty stored digest matches any requester digest (session-scoped)");
    ASSERT(session_allow_match(sid, bin, "cccccccccccccccc",
                               "/home/u/other") == 0,
           "the target must still match");

    session_deny_add(sid, start, bin, "", target, 0);
    ASSERT(session_deny_match(sid, bin, "cccccccccccccccc", target) == 1,
           "a digest-less deny entry also matches (conservative)");
    ASSERT(session_deny_match(sid, bin, "", target) == 1,
           "a digest-less deny entry matches even with no requester digest");

    /* Control: a recorded digest must still match exactly. */
    session_clear();
    session_allow_add(sid, start, bin, "dddddddddddddddd", target, 0);
    ASSERT(session_allow_match(sid, bin, "dddddddddddddddd", target) == 1,
           "a recorded digest still matches its requester digest");
    ASSERT(session_allow_match(sid, bin, "eeeeeeeeeeeeeeee", target) == 0,
           "a recorded digest mismatch re-prompts");

    session_clear();
    stop_leader(leader);
}

static void test_ttl_expiry(void)
{
    session_clear();

    pid_t leader = spawn_leader();
    pid_t sid = 0;
    unsigned long long start = 0;
    ASSERT(fixture_session(leader, &sid, &start) == 0, "fixture session");
    if (leader <= 0)
        return;

    const char *bin = "/usr/bin/aws";
    const char *hash = "dddddddddddddddd";
    const char *target = "/home/u/.aws/credentials";

    session_allow_add(sid, start, bin, hash, target, 1);
    ASSERT(session_allow_match(sid, bin, hash, target) == 1,
           "match before TTL expiry");

    sleep(2);
    ASSERT(session_allow_match(sid, bin, hash, target) == 0,
           "match after TTL expiry");

    stop_leader(leader);
}

static void test_dead_leader(void)
{
    session_clear();

    pid_t leader = spawn_leader();
    pid_t sid = 0;
    unsigned long long start = 0;
    ASSERT(fixture_session(leader, &sid, &start) == 0, "fixture session");
    if (leader <= 0)
        return;

    session_allow_add(sid, start, "/usr/bin/gh", "eeeeeeeeeeeeeeee",
                      "/home/u/.config/gh/hosts.yml", 0);
    ASSERT(session_allow_match(sid, "/usr/bin/gh", "eeeeeeeeeeeeeeee",
                               "/home/u/.config/gh/hosts.yml") == 1,
           "match while leader alive");

    stop_leader(leader);

    ASSERT(session_allow_match(sid, "/usr/bin/gh", "eeeeeeeeeeeeeeee",
                               "/home/u/.config/gh/hosts.yml") == 0,
           "dead leader does not match");
}

/*
 * M7 regression: the matchers now drop dead leaders only on the
 * full-key-match path (no per-event /proc storm), so entries whose
 * leaders died OUTSIDE their own session linger as used.  Reclaiming
 * them is the table-full sweep's job: an add at capacity must reuse a
 * dead slot rather than memmove-evict a live entry.
 */
static void test_full_table_reclaims_dead(void)
{
    int cap = session_test_max();
    const char *hash = "aaaaaaaaaaaaaaaa";
    session_clear();

    pid_t dead = spawn_leader();
    pid_t live = spawn_leader();
    pid_t dsid = 0, lsid = 0;
    unsigned long long dstart = 0, lstart = 0;
    ASSERT(fixture_session(dead, &dsid, &dstart) == 0, "doomed session");
    ASSERT(fixture_session(live, &lsid, &lstart) == 0, "live session");
    if (dead <= 0 || live <= 0) {
        stop_leader(dead);
        stop_leader(live);
        return;
    }

    /* Slot 0: an entry whose leader dies before the fill below. */
    session_allow_add(dsid, dstart, "/bin/doomed", hash, "/doomed", 0);
    stop_leader(dead);

    /* Fill the remaining slots with live-session entries. */
    char target[64];
    for (int i = 1; i < cap; i++) {
        snprintf(target, sizeof(target), "/live/%d", i);
        session_allow_add(lsid, lstart, "/bin/live", hash, target, 0);
    }
    ASSERT(session_allow_match(lsid, "/bin/live", hash, "/live/1") == 1,
           "oldest live entry matches before overflow (memmove victim)");

    /* The overflow add: the sweep must reclaim the doomed slot, keeping
     * every live entry in place. */
    session_allow_add(lsid, lstart, "/bin/live", hash, "/live/extra", 0);

    ASSERT(session_allow_match(lsid, "/bin/live", hash, "/live/extra") == 1,
           "overflow entry stored via dead-slot reclaim");
    ASSERT(session_allow_match(lsid, "/bin/live", hash, "/live/1") == 1,
           "oldest live entry survived the overflow add");
    ASSERT(session_allow_match(lsid, "/bin/live", hash, "/live/2") == 1,
           "second live entry survived the overflow add");
    ASSERT(session_allow_match(dsid, "/bin/doomed", hash, "/doomed") == 0,
           "doomed entry matches nothing (its session is dead)");

    session_clear();
    stop_leader(live);
}

static void test_deny(void)
{
    session_clear();

    pid_t leader = spawn_leader();
    pid_t sid = 0;
    unsigned long long start = 0;
    ASSERT(fixture_session(leader, &sid, &start) == 0, "fixture session");
    if (leader <= 0)
        return;

    const char *bin = "/usr/bin/terraform";
    const char *hash = "ffffffffffffffff";
    const char *target = "/home/u/.terraform.d/credentials.tfrc.json";

    session_deny_add(sid, start, bin, hash, target, 0);

    ASSERT(session_deny_match(sid, bin, hash, target) == 1,
           "deny match on exact key");
    ASSERT(session_deny_match(sid, bin, hash, "/home/u/other") == 0,
           "deny does not match another target");
    /* Tri-state deny: path keys fit, the entry pins a digest, and the
     * requester has none -- the deny cannot be verified either way, so
     * the matcher reports INCONCLUSIVE (-1); the pipeline then skips
     * grants and prompts instead of denying outright or falling through
     * to a hash-free grant. */
    ASSERT(session_deny_match(sid, bin, "", target) == -1,
           "hash-protected deny with no current hash is inconclusive");
    ASSERT(session_deny_match(sid, bin, "", "/home/u/other") == 0,
           "hash failure alone (no path match) is never inconclusive");
    ASSERT(session_deny_match(sid, bin, "0000000000000000", target) == 0,
           "deny match with wrong hash");

    stop_leader(leader);
}

/*
 * Observable state checks without count helpers: clear empties the
 * lists (matches fail), adds make them match again, and a live entry
 * survives an expiry sweep because nothing expires it.
 */
static void test_clear_and_entries(void)
{
    session_clear();
    ASSERT(session_allow_match((pid_t)1, "/bin/a", "", "/tmp/a") == 0,
           "no match after clear (allow)");
    ASSERT(session_deny_match((pid_t)1, "/bin/b", "", "/tmp/b") == 0,
           "no match after clear (deny)");

    pid_t leader = spawn_leader();
    pid_t sid = 0;
    unsigned long long start = 0;
    const char *hash = "aaaaaaaaaaaaaaaa";
    ASSERT(fixture_session(leader, &sid, &start) == 0, "fixture session");
    if (leader <= 0)
        return;

    session_allow_add(sid, start, "/bin/a", hash, "/tmp/a", 0);
    session_deny_add(sid, start, "/bin/b", hash, "/tmp/b", 0);
    ASSERT(session_allow_match(sid, "/bin/a", hash, "/tmp/a") == 1,
           "allow entry present after add");
    ASSERT(session_deny_match(sid, "/bin/b", hash, "/tmp/b") == 1,
           "deny entry present after add");

    session_clear();
    ASSERT(session_allow_match(sid, "/bin/a", hash, "/tmp/a") == 0,
           "clear removes allow entries");
    ASSERT(session_deny_match(sid, "/bin/b", hash, "/tmp/b") == 0,
           "clear removes deny entries");

    stop_leader(leader);
}

/*
 * Stored rule IDs: generated at add, stable across a refresh, unique per
 * list.  Two entries can share an allow list and still get distinct IDs
 * even when their canonical identity collides (the session id is not
 * part of the identity), because uniqueness is enforced against the
 * list.
 */
static void test_rule_id_stored(void)
{
    session_clear();

    pid_t leader = spawn_leader();
    pid_t sid = 0;
    unsigned long long start = 0;
    ASSERT(fixture_session(leader, &sid, &start) == 0, "fixture session");
    if (leader <= 0)
        return;

    SessionRecord recs[8];
    memset(recs, 0, sizeof(recs));
    int total = 0;
    int n = session_snapshot(0, recs, 8, &total);
    ASSERT(n == 0 && total == 0, "empty allow list snapshots no records");

    const char *bin = "/usr/bin/git";
    const char *hash = "1111111111111111";
    const char *target = "/home/u/.git-credentials";

    session_allow_add(sid, start, bin, hash, target, 0);
    n = session_snapshot(0, recs, 8, &total);
    ASSERT(n == 1 && total == 1, "allow snapshot sees the new entry");
    ASSERT(is_hex_id(recs[0].rule_id), "stored rule ID is 16 lower-case hex");
    ASSERT(recs[0].sid == sid && recs[0].leader_start == start,
           "snapshot carries the session identity");
    ASSERT(strcmp(recs[0].binary, bin) == 0 &&
           strcmp(recs[0].target, target) == 0,
           "snapshot carries the decision key");
    ASSERT(recs[0].ttl_remaining == -1,
           "a session-lifetime entry reports ttl -1");

    char first_id[RULEID_HEX_LEN + 1];
    memcpy(first_id, recs[0].rule_id, sizeof(first_id));

    /* Repeating the identical grant refreshes one entry; the ID the CLI
     * already holds stays valid. */
    session_allow_add(sid, start, bin, hash, target, 60);
    n = session_snapshot(0, recs, 8, &total);
    ASSERT(n == 1 && total == 1,
           "identical add refreshes instead of duplicating");
    ASSERT(strcmp(recs[0].rule_id, first_id) == 0,
           "rule ID is stable across a refresh");
    ASSERT(recs[0].ttl_remaining > 0, "refresh applies the new TTL");

    /* A different target is a different decision: its own ID. */
    session_allow_add(sid, start, bin, hash, "/home/u/.config/git/credentials", 0);
    n = session_snapshot(0, recs, 8, &total);
    ASSERT(n == 2 && total == 2, "second allow entry");
    ASSERT(strcmp(recs[0].rule_id, recs[1].rule_id) != 0,
           "distinct entries carry distinct IDs");

    /* Same binary/hash/target from another session: the canonical
     * identity is identical (the session id is not hashed), so the second
     * entry must still receive a distinct ID. */
    pid_t second = spawn_leader();
    pid_t ssid = 0;
    unsigned long long sstart = 0;
    ASSERT(fixture_session(second, &ssid, &sstart) == 0,
           "second fixture session");
    if (second > 0)
    {
        session_allow_add(ssid, sstart, bin, hash, target, 0);
        n = session_snapshot(0, recs, 8, &total);
        ASSERT(n == 3 && total == 3, "same key from a second session");
        int same = -1;
        for (int i = 0; i < n; i++)
        {
            if (recs[i].sid == ssid && strcmp(recs[i].target, target) == 0)
                same = i;
        }
        ASSERT(same >= 0, "second-session entry reported");
        ASSERT(same >= 0 && strcmp(recs[same].rule_id, first_id) != 0,
               "identical identity in one list still gets a unique ID");
    }

    /* The deny list is a separate namespace: valid and unique IDs of its
     * own, independent of what the allow list holds. */
    session_deny_add(sid, start, bin, hash, target, 0);
    session_deny_add(sid, start, bin, hash, "/home/u/.config/gh/hosts.yml", 0);
    n = session_snapshot(1, recs, 8, &total);
    ASSERT(n == 2 && total == 2, "two deny entries");
    ASSERT(is_hex_id(recs[0].rule_id) && is_hex_id(recs[1].rule_id),
           "deny IDs are 16 lower-case hex");
    ASSERT(strcmp(recs[0].rule_id, recs[1].rule_id) != 0,
           "deny IDs are unique within their list");
    n = session_snapshot(0, recs, 8, &total);
    ASSERT(n == 3 && total == 3, "deny adds leave the allow list alone");

    /* The second leader is stopped only now: killing it earlier would
     * sweep its allow entry and hide the cross-list isolation check. */
    stop_leader(second);
    session_clear();
    stop_leader(leader);
}

/*
 * Snapshot sweep and TTL reporting.  The dead leader is swept without a
 * sleep; the expired entry uses the suite's existing sleep pattern (a
 * 1-second TTL, then sleep(2)).
 */
static void test_snapshot_sweep(void)
{
    session_clear();

    pid_t live = spawn_leader();
    pid_t doomed = spawn_leader();
    pid_t sid = 0, dsid = 0;
    unsigned long long start = 0, dstart = 0;
    ASSERT(fixture_session(live, &sid, &start) == 0, "live fixture session");
    ASSERT(fixture_session(doomed, &dsid, &dstart) == 0,
           "doomed fixture session");
    if (live <= 0 || doomed <= 0)
    {
        stop_leader(live);
        stop_leader(doomed);
        return;
    }

    session_allow_add(sid, start, "/bin/live", "", "/live", 0);
    session_allow_add(dsid, dstart, "/bin/doomed", "", "/doomed", 0);
    session_allow_add(sid, start, "/bin/ttl", "", "/ttl", 60);
    stop_leader(doomed);

    SessionRecord recs[8];
    memset(recs, 0, sizeof(recs));
    int total = 0;
    int n = session_snapshot(0, recs, 8, &total);
    ASSERT(n == 2 && total == 2, "snapshot sweeps the dead leader");
    ASSERT(record_for_target(recs, n, "/doomed") < 0,
           "dead-leader entry is not reported");

    int live_i = record_for_target(recs, n, "/live");
    int ttl_i = record_for_target(recs, n, "/ttl");
    ASSERT(live_i >= 0 && recs[live_i].ttl_remaining == -1,
           "session-lifetime entry reports -1");
    ASSERT(ttl_i >= 0 && recs[ttl_i].ttl_remaining > 0 &&
           recs[ttl_i].ttl_remaining <= 60,
           "finite TTL reports its remaining seconds");

    /* max truncates the output but total still reports every live entry. */
    n = session_snapshot(0, recs, 1, &total);
    ASSERT(n == 1 && total == 2, "max truncates, total reports the truth");
    ASSERT(is_hex_id(recs[0].rule_id), "truncated record still carries its ID");

    /* Bad arguments: reported as errors, lists untouched. */
    ASSERT(session_snapshot(0, NULL, 1, &total) == -1, "NULL out rejected");
    ASSERT(session_snapshot(0, recs, 0, &total) == -1, "zero max rejected");
    ASSERT(session_snapshot(0, recs, -3, &total) == -1, "negative max rejected");
    ASSERT(session_snapshot(0, recs, 1, NULL) == -1, "NULL total rejected");
    ASSERT(session_snapshot(2, recs, 1, &total) == -1, "deny 2 rejected");
    ASSERT(session_snapshot(-1, recs, 1, &total) == -1, "deny -1 rejected");

    /* An expired entry is swept by the next snapshot. */
    session_allow_add(sid, start, "/bin/expiring", "", "/expiring", 1);
    n = session_snapshot(0, recs, 8, &total);
    ASSERT(n == 3 && total == 3, "TTL entry present before expiry");

    sleep(2);
    n = session_snapshot(0, recs, 8, &total);
    ASSERT(n == 2 && total == 2, "expired entry swept by snapshot");
    ASSERT(record_for_target(recs, n, "/expiring") < 0,
           "expired entry is not reported");

    session_clear();
    stop_leader(live);
}

/*
 * Removal by ID prefix.  Ambiguous removal (-2) is not covered: IDs are
 * SHA-512 prefixes, so two realistic entries sharing 8 hex chars require
 * a 32-bit collision search that a 256-entry table cannot produce through
 * the public API; the suite deliberately does not reach into the module's
 * private state to fake it.
 */
static void test_remove_by_id(void)
{
    session_clear();

    pid_t leader = spawn_leader();
    pid_t sid = 0;
    unsigned long long start = 0;
    const char *hash = "aaaaaaaaaaaaaaaa";
    ASSERT(fixture_session(leader, &sid, &start) == 0, "fixture session");
    if (leader <= 0)
        return;

    session_allow_add(sid, start, "/bin/a", hash, "/tmp/a", 0);
    session_allow_add(sid, start, "/bin/b", hash, "/tmp/b", 0);
    session_deny_add(sid, start, "/bin/c", hash, "/tmp/c", 0);

    SessionRecord recs[4];
    memset(recs, 0, sizeof(recs));
    int total = 0;
    int n = session_snapshot(0, recs, 4, &total);
    ASSERT(n == 2 && total == 2, "allow list starts with two entries");

    int ai = record_for_target(recs, n, "/tmp/a");
    int bi = record_for_target(recs, n, "/tmp/b");
    ASSERT(ai >= 0 && bi >= 0, "both allow entries reported");
    if (ai < 0 || bi < 0)
    {
        session_clear();
        stop_leader(leader);
        return;
    }

    char id_a[RULEID_HEX_LEN + 1];
    char id_b[RULEID_HEX_LEN + 1];
    memcpy(id_a, recs[ai].rule_id, sizeof(id_a));
    memcpy(id_b, recs[bi].rule_id, sizeof(id_b));

    /* Argument validation happens before the table walk. */
    ASSERT(session_remove_by_id(0, NULL) == -1, "NULL ID rejected");
    ASSERT(session_remove_by_id(0, "abcdef0") == -1, "7-char prefix rejected");
    ASSERT(session_remove_by_id(0, "") == -1, "empty prefix rejected");
    ASSERT(session_remove_by_id(0, "ABCDEF01") == -1,
           "upper-case prefix rejected");
    ASSERT(session_remove_by_id(0, "0123456g") == -1, "non-hex prefix rejected");
    ASSERT(session_remove_by_id(2, id_a) == -1, "invalid list selector rejected");

    char prefix_a[9];
    memcpy(prefix_a, id_a, 8);
    prefix_a[8] = '\0';

    /* Build a valid prefix that matches neither entry: its first char
     * differs from id_a's and the full 8 chars must not hit id_b. */
    char unknown[9];
    memcpy(unknown, prefix_a, sizeof(unknown));
    for (char c = '0'; c <= '9'; c++)
    {
        unknown[0] = c;
        if (unknown[0] != id_a[0] && strncmp(unknown, id_b, 8) != 0)
            break;
    }
    ASSERT(unknown[0] != id_a[0] && strncmp(unknown, id_b, 8) != 0,
           "constructed an unknown prefix");
    ASSERT(session_remove_by_id(0, unknown) == 0, "unknown prefix not found");
    ASSERT(session_allow_match(sid, "/bin/a", hash, "/tmp/a") == 1,
           "not-found removal leaves the entry in place");

    ASSERT(session_remove_by_id(0, prefix_a) == 1,
           "unique 8-char prefix removes exactly one");
    ASSERT(session_allow_match(sid, "/bin/a", hash, "/tmp/a") == 0,
           "removed allow entry no longer matches");
    ASSERT(session_allow_match(sid, "/bin/b", hash, "/tmp/b") == 1,
           "the other allow entry survives");
    ASSERT(session_remove_by_id(0, prefix_a) == 0,
           "the same prefix no longer matches after removal");

    ASSERT(session_remove_by_id(0, id_b) == 1, "full 16-char ID removes");
    ASSERT(session_allow_match(sid, "/bin/b", hash, "/tmp/b") == 0,
           "second allow entry removed");

    /* An empty list still rejects malformed prefixes (argument error)... */
    ASSERT(session_remove_by_id(0, "abcdef0") == -1,
           "short prefix rejected on an empty list");
    /* ...and reports a valid prefix as "not found", not an error. */
    ASSERT(session_remove_by_id(0, "abcdef01") == 0,
           "valid prefix on an empty list is not found");

    /* The lists are separate namespaces: a deny ID is not visible in the
     * allow list, and removing it from the deny list leaves the allow
     * list untouched. */
    n = session_snapshot(1, recs, 4, &total);
    ASSERT(n == 1, "deny list holds its entry");
    char id_c[RULEID_HEX_LEN + 1];
    memcpy(id_c, recs[0].rule_id, sizeof(id_c));

    ASSERT(session_remove_by_id(0, id_c) == 0,
           "deny ID does not match in the allow list");
    ASSERT(session_deny_match(sid, "/bin/c", hash, "/tmp/c") == 1,
           "deny entry survives the wrong-list removal");
    ASSERT(session_remove_by_id(1, id_c) == 1, "deny ID removes from deny list");
    ASSERT(session_deny_match(sid, "/bin/c", hash, "/tmp/c") == 0,
           "removed deny entry no longer matches");

    session_clear();
    stop_leader(leader);
}

/* Per-list clear: session_clear_list() touches only the selected list;
 * session_clear() still clears both.  An invalid selector clears
 * nothing (fail closed). */
static void test_clear_list(void)
{
    session_clear();

    pid_t leader = spawn_leader();
    pid_t sid = 0;
    unsigned long long start = 0;
    const char *hash = "aaaaaaaaaaaaaaaa";
    ASSERT(fixture_session(leader, &sid, &start) == 0, "fixture session");
    if (leader <= 0)
        return;

    session_allow_add(sid, start, "/bin/a", hash, "/tmp/a", 0);
    session_deny_add(sid, start, "/bin/b", hash, "/tmp/b", 0);

    session_clear_list(1);
    ASSERT(session_allow_match(sid, "/bin/a", hash, "/tmp/a") == 1,
           "deny-list clear leaves allow entries");
    ASSERT(session_deny_match(sid, "/bin/b", hash, "/tmp/b") == 0,
           "deny-list clear removes deny entries");

    session_deny_add(sid, start, "/bin/b", hash, "/tmp/b", 0);
    session_clear_list(2);
    ASSERT(session_allow_match(sid, "/bin/a", hash, "/tmp/a") == 1,
           "invalid selector clears no allow entries");
    ASSERT(session_deny_match(sid, "/bin/b", hash, "/tmp/b") == 1,
           "invalid selector clears no deny entries");

    session_clear_list(0);
    ASSERT(session_allow_match(sid, "/bin/a", hash, "/tmp/a") == 0,
           "allow-list clear removes allow entries");
    ASSERT(session_deny_match(sid, "/bin/b", hash, "/tmp/b") == 1,
           "allow-list clear leaves deny entries");

    session_allow_add(sid, start, "/bin/a", hash, "/tmp/a", 0);
    session_clear();
    ASSERT(session_allow_match(sid, "/bin/a", hash, "/tmp/a") == 0,
           "session_clear clears allow");
    ASSERT(session_deny_match(sid, "/bin/b", hash, "/tmp/b") == 0,
           "session_clear clears deny");

    stop_leader(leader);
}

int main(void)
{
    printf("=== test_session ===\n");
    test_session_id_of();
    test_allow_match();
    test_empty_digest_matches_for_session();
    test_ttl_expiry();
    test_dead_leader();
    test_full_table_reclaims_dead();
    test_deny();
    test_clear_and_entries();
    test_rule_id_stored();
    test_snapshot_sweep();
    test_remove_by_id();
    test_clear_list();
    if (failures)
    {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
