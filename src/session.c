#include "session.h"
#include "ruleid.h"
#include "utils.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

/*
 * Session-scoped decisions are deliberately runtime-only: they describe
 * what the user approved/denied in a terminal that exists right now, so
 * they are rebuilt from scratch after a daemon restart (fail closed).
 */
#define SESSION_MAX 256

typedef struct
{
    int used;
    /* Stored rule ID: generated at add, preserved across a refresh, and
     * unique within this list.  Empty when generation failed; such an
     * entry is never removable by ID (fail closed). */
    char rule_id[RULEID_HEX_LEN + 1];
    pid_t sid;
    unsigned long long leader_start;
    char binary[PATH_MAX];
    char binary_sha512[129];
    char target[PATH_MAX];
    time_t expiry; /* mono_seconds() deadline; 0 = leader lifetime */
} SessionEntry;

static SessionEntry g_allow[SESSION_MAX];
static SessionEntry g_deny[SESSION_MAX];
static int g_allow_count = 0;
static int g_deny_count = 0;

/*
 * A syntactically valid stored ID used only to validate a lookup prefix
 * through ruleid_prefix_match(): with an empty list there is no stored ID
 * to match against, yet a short or malformed prefix must still be an
 * argument error, never "not found".
 */
static const char g_probe_id[RULEID_HEX_LEN + 1] = "0000000000000000";

/*
 * Resolve the POSIX session id and the session leader's start time for
 * pid.  Thin wrapper over the shared /proc/<pid>/stat parser; returns 0
 * on success, -1 when the process is gone.
 */
static int read_proc_session(pid_t pid, pid_t *sid_out,
                             unsigned long long *start_out)
{
    unsigned long long sid = 0;
    unsigned long long start = 0;

    if (proc_stat_session(pid, &sid, start_out ? &start : NULL) != 0)
        return -1;
    if (sid_out)
        *sid_out = (pid_t)sid;
    if (start_out)
        *start_out = start;
    return 0;
}

int session_id_of(pid_t pid, pid_t *sid_out, unsigned long long *leader_start_out)
{
    pid_t sid;
    unsigned long long leader_start;

    if (read_proc_session(pid, &sid, NULL) != 0)
        return -1;

    /* The leader's start time, not the requester's: a recycled SID must
     * not resurrect a previous session's decisions. */
    if (read_proc_session(sid, NULL, &leader_start) != 0)
        return -1;

    if (sid_out)
        *sid_out = sid;
    if (leader_start_out)
        *leader_start_out = leader_start;
    return 0;
}

static int leader_alive(pid_t sid, unsigned long long start)
{
    unsigned long long current;

    if (read_proc_session(sid, NULL, &current) != 0)
        return 0;
    return current == start;
}

static int entry_expired(const SessionEntry *e, time_t now)
{
    return e->expiry != 0 && e->expiry < now;
}

/*
 * Session matching deliberately accepts a digest-less entry: when the
 * binary cannot be hashed (AppImages under /tmp/.mount_*, self-updating
 * tools) the recorder stores an empty digest, and "Allow Session" is the
 * intended grant for exactly those binaries.  The entry is still bounded
 * by the session leader, the binary path and the target, so the exposure
 * is session-scoped; a missing digest must NOT be turned back into a
 * fail-closed rejection (a past review did and broke the use case).
 * A recorded digest, however, must match: when the requester's digest
 * is unavailable the deny walker reports INCONCLUSIVE (see
 * list_deny_match) and the allow walker treats it as a non-match, so
 * neither side ever matches an unverifiable recorded digest outright.
 */
static int hash_matches(const SessionEntry *e, const char *bin_sha512)
{
    if (e->binary_sha512[0] == '\0')
        return 1; /* deliberate: digest-less session entry (see above) */
    if (!bin_sha512 || bin_sha512[0] == '\0')
        return 0; /* cannot verify the approved binary: fail closed */
    return strcmp(e->binary_sha512, bin_sha512) == 0;
}

/*
 * Common path-level checks shared by all matchers.  Never matches an
 * entry without a target.  Key comparisons come FIRST: the per-event
 * match must not pay a /proc leader check for every live entry (with
 * both lists near capacity that is up to 512 /proc opens per protected
 * open, while the requester is kernel-suspended).  Leader liveness is
 * therefore verified only on the full-key-match path — the only entries
 * this scan acts on — and expiry (a cheap time compare) still drops on
 * sight.  Reclaiming dead leaders' non-matching entries happens in the
 * table-full sweep of session_add_entry: once per user decision, not
 * once per event.
 */
static int entry_covers(SessionEntry *e, time_t now, pid_t sid,
                        const char *binary, const char *target)
{
    if (!e->used)
        return 0;
    if (entry_expired(e, now))
    {
        e->used = 0;
        return 0;
    }
    if (!binary || !target || target[0] == '\0')
        return 0;
    if (e->sid != sid || strcmp(e->binary, binary) != 0 ||
        strcmp(e->target, target) != 0)
        return 0;
    if (!leader_alive(e->sid, e->leader_start))
    {
        e->used = 0; /* this very session asked; its leader is gone */
        return 0;
    }
    return 1;
}

static int list_match(SessionEntry *list, int count, pid_t sid,
                      const char *binary, const char *bin_sha512,
                      const char *target)
{
    time_t now = mono_seconds();

    for (int i = 0; i < count; i++)
    {
        SessionEntry *e = &list[i];
        if (!entry_covers(e, now, sid, binary, target))
            continue;
        if (hash_matches(e, bin_sha512))
            return 1;
    }
    return 0;
}

int session_allow_match(pid_t sid, const char *binary, const char *bin_sha512,
                        const char *target)
{
    return list_match(g_allow, g_allow_count, sid, binary, bin_sha512, target);
}

/*
 * Deny-side walk: the same path keys as list_match, but an unverifiable
 * digest is reported instead of silently dropped.  hash_matches() already
 * gives the two boolean outcomes -- a digest-less entry matches
 * (conservative: it denies any digest at the same session/binary/target)
 * and a verified mismatch does not -- and the one extra outcome is -1,
 * INCONCLUSIVE: the entry pins a digest and the requester has none, so
 * the denial can be neither verified nor refuted.  The caller
 * (event_runtime_denied) then skips every grant stage and prompts:
 * denying outright would punish an unverifiable identity, while falling
 * through to grants could allow straight past a denial that may well
 * fit.  Never returned for a hash failure alone -- only for an entry
 * whose path keys already matched.  A conclusive match wins over a
 * pending inconclusive one at any table position.
 */
static int list_deny_match(SessionEntry *list, int count, pid_t sid,
                           const char *binary, const char *bin_sha512,
                           const char *target)
{
    time_t now = mono_seconds();
    int inconclusive = 0;

    for (int i = 0; i < count; i++)
    {
        SessionEntry *e = &list[i];

        if (!entry_covers(e, now, sid, binary, target))
            continue;
        if (hash_matches(e, bin_sha512))
            return 1; /* conclusive: verified, or a digest-less entry */
        if (e->binary_sha512[0] != '\0' &&
            (!bin_sha512 || bin_sha512[0] == '\0'))
            inconclusive = 1; /* path fits; stored digest unverifiable */
    }
    return inconclusive ? -1 : 0;
}

int session_deny_match(pid_t sid, const char *binary, const char *bin_sha512,
                       const char *target)
{
    return list_deny_match(g_deny, g_deny_count, sid, binary, bin_sha512,
                           target);
}

/*
 * Remove one entry and close the hole.  Table order is preserved: it is
 * the CLI's display order and the overflow eviction order.
 */
static void list_remove_at(SessionEntry *list, int *count, int idx)
{
    if (idx < 0 || idx >= *count)
        return;

    (*count)--;
    if (idx < *count)
        memmove(&list[idx], &list[idx + 1],
                sizeof(SessionEntry) * (size_t)(*count - idx));
    memset(&list[*count], 0, sizeof(SessionEntry));
}

static void list_clear(SessionEntry *list, int *count)
{
    memset(list, 0, sizeof(SessionEntry) * SESSION_MAX);
    *count = 0;
}

/*
 * Drop expired and dead-leader entries and compact the holes.  The
 * snapshot sweeps first: the CLI must not display an entry the matcher
 * would already treat as gone, and the compaction keeps the table dense
 * for later reads.
 */
static void list_sweep(SessionEntry *list, int *count)
{
    time_t now = mono_seconds();
    int w = 0;

    for (int i = 0; i < *count; i++)
    {
        SessionEntry *e = &list[i];

        if (!e->used || entry_expired(e, now) ||
            !leader_alive(e->sid, e->leader_start))
        {
            e->used = 0;
            continue;
        }
        if (w != i)
        {
            list[w] = list[i];
            list[i].used = 0;
        }
        w++;
    }
    *count = w;
}

/*
 * Fill e->rule_id from the entry's identity, unique against the other
 * live entries of the same list (allow and deny are separate ID
 * namespaces).  A session decision has no recorded command line or call
 * chain, so those identity fields are empty/zero; created_at is the
 * generation time in wall-clock seconds.  A failure -- which should not
 * happen -- leaves the ID empty and logs: an entry without an ID is
 * invisible to ID-based management (fail closed) and still matches by
 * key.
 */
static void generate_rule_id(SessionEntry *list, int count, SessionEntry *e)
{
    const char *existing[SESSION_MAX] = {0}; /* n 0 passes an empty list */
    RuleIdentity id;
    int n = 0;

    for (int i = 0; i < count; i++)
    {
        if (&list[i] == e || !list[i].used || list[i].rule_id[0] == '\0')
            continue;
        existing[n++] = list[i].rule_id;
    }

    memset(&id, 0, sizeof(id));
    id.binary = e->binary;
    id.binary_sha512 = e->binary_sha512;
    id.target_path = e->target;
    id.cmdline_sha512 = "";
    id.chain_depth = 0;
    id.created_at = (long)time(NULL);

    if (ruleid_make_unique(&id, existing, n, e->rule_id) < 0)
    {
        e->rule_id[0] = '\0'; /* the generator leaves out untouched on failure */
        log_msg(LOG_WARNING,
                "session rule ID generation failed for %s -> %s; "
                "the entry cannot be managed by ID",
                e->binary, e->target);
    }
}

/*
 * The existing entry covering this exact decision (same session,
 * leader instance, binary and target), or NULL.  Callers refresh it in
 * place instead of appending a duplicate.
 */
static SessionEntry *list_find_refresh(SessionEntry *list, int count,
                                       pid_t sid,
                                       unsigned long long leader_start,
                                       const char *binary, const char *target)
{
    for (int i = 0; i < count; i++)
    {
        SessionEntry *c = &list[i];

        if (c->used && c->sid == sid && c->leader_start == leader_start &&
            strcmp(c->binary, binary) == 0 && strcmp(c->target, target) == 0)
            return c;
    }
    return NULL;
}

/*
 * A slot for a new entry.  Holes come first (lazily-dropped dead entries
 * would otherwise be shifted or evicted past on every insert); when the
 * table is full, expired and dead-leader entries are swept once per user
 * decision before the oldest live entry is evicted (matchers deliberately
 * do not pay a /proc check per event, so those entries linger as used).
 * Returns an index in [0, SESSION_MAX).
 */
static int list_alloc_slot(SessionEntry *list, int *count)
{
    int slot = -1;

    if (*count < SESSION_MAX)
    {
        for (int i = 0; i < *count; i++)
        {
            if (!list[i].used)
            {
                slot = i;
                break;
            }
        }
        if (slot < 0)
            slot = (*count)++;
        return slot;
    }

    time_t now = mono_seconds();

    for (int i = 0; i < SESSION_MAX; i++)
    {
        if (!list[i].used)
        {
            slot = i;
            break;
        }
        if (entry_expired(&list[i], now) ||
            !leader_alive(list[i].sid, list[i].leader_start))
        {
            list[i].used = 0;
            slot = i;
            break;
        }
    }
    if (slot < 0)
    {
        log_msg(LOG_INFO,
                "session table full; dropping the oldest entry "
                "(sid %d, %s -> %s)",
                (int)list[0].sid, list[0].binary, list[0].target);
        memmove(&list[0], &list[1], sizeof(SessionEntry) * (SESSION_MAX - 1));
        slot = SESSION_MAX - 1;
    }
    return slot;
}

static void list_add(SessionEntry *list, int *count, pid_t sid,
                     unsigned long long leader_start, const char *binary,
                     const char *bin_sha512, const char *target, int ttl_seconds)
{
    if (!binary || !target || target[0] == '\0')
        return;

    if (ttl_seconds < 0)
        ttl_seconds = 0;
    if (ttl_seconds > FS_MAX_TTL_SECONDS)
        ttl_seconds = FS_MAX_TTL_SECONDS;

    SessionEntry *e = list_find_refresh(list, *count, sid, leader_start,
                                        binary, target);
    int refresh = e != NULL;
    char kept_id[RULEID_HEX_LEN + 1];

    memset(kept_id, 0, sizeof(kept_id));
    if (refresh)
        memcpy(kept_id, e->rule_id, sizeof(kept_id));
    else
        e = &list[list_alloc_slot(list, count)];

    memset(e, 0, sizeof(*e));
    e->used = 1;
    e->sid = sid;
    e->leader_start = leader_start;
    snprintf(e->binary, sizeof(e->binary), "%s", binary);
    if (bin_sha512)
        snprintf(e->binary_sha512, sizeof(e->binary_sha512), "%s", bin_sha512);
    snprintf(e->target, sizeof(e->target), "%s", target);
    if (ttl_seconds > 0)
        e->expiry = mono_seconds() + ttl_seconds;

    /* A refresh keeps the ID the CLI already holds: the decision key did
     * not change, while re-hashing with a new created_at would mint a new
     * ID on every repeat grant.  An empty ID (generation failed earlier)
     * is the one case that gets a fresh attempt. */
    if (refresh && kept_id[0] != '\0')
        memcpy(e->rule_id, kept_id, sizeof(kept_id));
    else
        generate_rule_id(list, *count, e);
}

void session_allow_add(pid_t sid, unsigned long long leader_start,
                       const char *binary, const char *bin_sha512,
                       const char *target, int ttl_seconds)
{
    list_add(g_allow, &g_allow_count, sid, leader_start, binary, bin_sha512,
             target, ttl_seconds);
}

void session_deny_add(pid_t sid, unsigned long long leader_start,
                      const char *binary, const char *bin_sha512,
                      const char *target, int ttl_seconds)
{
    list_add(g_deny, &g_deny_count, sid, leader_start, binary, bin_sha512,
             target, ttl_seconds);
}

void session_clear(void)
{
    list_clear(g_allow, &g_allow_count);
    list_clear(g_deny, &g_deny_count);
}

void session_clear_list(int deny)
{
    if (deny == 0)
        list_clear(g_allow, &g_allow_count);
    else if (deny == 1)
        list_clear(g_deny, &g_deny_count);
    /* Any other selector clears nothing (fail closed). */
}

int session_snapshot(int deny, SessionRecord *out, int max, int *total_out)
{
    SessionEntry *list;
    int *count;
    int live;
    int n;
    time_t now;

    if (!out || !total_out || max <= 0 || (deny != 0 && deny != 1))
        return -1;

    list = deny ? g_deny : g_allow;
    count = deny ? &g_deny_count : &g_allow_count;
    list_sweep(list, count);

    live = *count;
    n = live < max ? live : max;
    now = mono_seconds();

    for (int i = 0; i < n; i++)
    {
        SessionEntry *e = &list[i];
        SessionRecord *r = &out[i];

        snprintf(r->rule_id, sizeof(r->rule_id), "%s", e->rule_id);
        r->sid = e->sid;
        r->leader_start = e->leader_start;
        snprintf(r->binary, sizeof(r->binary), "%s", e->binary);
        snprintf(r->target, sizeof(r->target), "%s", e->target);
        if (e->expiry == 0)
        {
            r->ttl_remaining = -1; /* lives until the session leader exits */
        }
        else
        {
            long ttl = (long)(e->expiry - now);
            /* The sweep kept entries live at its instant; the clock may
             * have ticked since, so an about-to-expire entry reports at
             * least one second rather than zero/negative. */
            r->ttl_remaining = ttl < 1 ? 1 : ttl;
        }
    }

    *total_out = live;
    return n;
}

int session_remove_by_id(int deny, const char *id)
{
    SessionEntry *list;
    int *count;
    int found = -1;

    if (deny != 0 && deny != 1)
        return -1;
    /* Validate the prefix before walking (or skipping) the table: with an
     * empty list there is no stored ID to match against, yet a short or
     * malformed prefix must still be an argument error, not "not found". */
    if (ruleid_prefix_match(g_probe_id, id) < 0)
        return -1;

    list = deny ? g_deny : g_allow;
    count = deny ? &g_deny_count : &g_allow_count;

    for (int i = 0; i < *count; i++)
    {
        SessionEntry *e = &list[i];
        int matches;

        /* An entry without an ID (generation failed) can never be
         * addressed by ID; a damaged stored ID fails the lookup closed. */
        if (!e->used || e->rule_id[0] == '\0')
            continue;
        matches = ruleid_prefix_match(e->rule_id, id);
        if (matches < 0)
            return -1;
        if (matches == 1)
        {
            if (found >= 0)
                return -2; /* ambiguous: remove nothing */
            found = i;
        }
    }

    if (found < 0)
        return 0;

    log_msg(LOG_INFO, "session %s rule %s (%s -> %s) removed by ID",
            deny ? "deny" : "allow", list[found].rule_id,
            list[found].binary, list[found].target);
    list_remove_at(list, count, found);
    return 1;
}

/* Test seam (session.h): table capacity. */
int session_test_max(void)
{
    return SESSION_MAX;
}
