#ifndef FILESHIELD_SESSION_H
#define FILESHIELD_SESSION_H

#include <limits.h>
#include <sys/types.h>

#include "ruleid.h"

/*
 * In-memory session-scoped allow/deny decisions.
 *
 * A "session" is the POSIX session (setsid(2)) the requesting process
 * belongs to -- for an interactive shell that is the shell itself, so a
 * new terminal window/tab is a new session and closing the shell ends it.
 * Entries are never persisted: a daemon restart clears them (fail closed,
 * the user is re-prompted).
 *
 * Each entry carries a stored rule ID (see ruleid.h) generated from its
 * decision key at add.  IDs are unique per list and stable across a
 * refresh, so the control socket / CLI can list and remove entries by an
 * unambiguous prefix of at least RULEID_MIN_PREFIX (8) characters without
 * exposing table indices.
 */

/*
 * Resolve the POSIX session id for pid and the start time of the session
 * leader (/proc/<sid>/stat field 22).  The start time guards against a
 * recycled SID being mistaken for the original session.  Either out
 * pointer may be NULL.  Returns 0 on success, -1 on failure.
 */
int session_id_of(pid_t pid, pid_t *sid_out, unsigned long long *leader_start_out);

/*
 * Record a session-scoped decision.  ttl_seconds == 0 means the entry is
 * valid for as long as the session leader lives; > 0 caps its lifetime in
 * seconds as well.  The target file is mandatory (an empty target never
 * matches).  The binary SHA-512 is optional BY DESIGN: when the binary
 * cannot be hashed (AppImages under /tmp/.mount_*, self-updating tools)
 * the empty digest is stored and the entry matches any requester digest
 * for the same binary path and target until the session ends.  Do not
 * turn a missing digest into a refusal: "Allow Session" is the intended
 * scope for unhashable binaries (a past review "fixed" this and broke
 * the use case).  Repeating an identical decision refreshes the existing
 * entry and keeps its rule ID.
 */
void session_allow_add(pid_t sid, unsigned long long leader_start,
                       const char *binary, const char *bin_sha512,
                       const char *target, int ttl_seconds);
void session_deny_add(pid_t sid, unsigned long long leader_start,
                      const char *binary, const char *bin_sha512,
                      const char *target, int ttl_seconds);

/*
 * Match a session-scoped entry.  A match also lazily drops entries whose
 * leader exited, whose start time changed, or whose TTL expired.
 *
 * session_allow_match returns 1 on match, 0 otherwise.  An entry without
 * a stored digest matches any requester digest (deliberate for
 * unhashable binaries; see session_allow_add).  A recorded digest must
 * match: a missing or different requester digest does not match, so the
 * event falls through to the pipeline's later grant stages or to the
 * dialog -- this matcher never denies and never prompts by itself.
 *
 * session_deny_match is tri-state:
 *     1  conclusive match -- the path keys fit and the digest is
 *        verified (or the entry stores no digest, which deliberately
 *        matches any requester digest: conservative on this side)
 *     0  no deny entry's path keys fit; a verified digest mismatch is
 *        also a plain non-match (that entry does not apply)
 *    -1  inconclusive -- a deny entry's path keys fit, it stores a
 *        digest, and the requester's digest is empty (hash failure), so
 *        the denial can be neither verified nor refuted.  The caller
 *        must then skip every grant stage and prompt (fail closed):
 *        never returned for a hash failure alone, without a
 *        path-matching deny entry.
 */
int session_allow_match(pid_t sid, const char *binary, const char *bin_sha512,
                        const char *target);
int session_deny_match(pid_t sid, const char *binary, const char *bin_sha512,
                       const char *target);

/* Remove every entry from both lists (tests / shutdown). */
void session_clear(void);

/*
 * Remove every entry from one list only: `deny` selects the deny list
 * when 1 and the allow list when 0.  Any other value clears nothing (fail
 * closed), so a caller bug or typo can never wipe a list it did not
 * select.
 */
void session_clear_list(int deny);

/*
 * Snapshot record: one live entry of one session list, copied out for the
 * control socket / CLI.  ttl_remaining is -1 when the entry lives as long
 * as its session, otherwise the remaining seconds (> 0).
 */
typedef struct
{
    char rule_id[RULEID_HEX_LEN + 1];
    pid_t sid;
    unsigned long long leader_start;
    char binary[PATH_MAX];
    char target[PATH_MAX];
    long ttl_remaining; /* -1 = until session ends, else seconds > 0 */
} SessionRecord;

/*
 * Report the live entries of one session list in table order.
 *
 * `deny` selects the list (0 = allow, 1 = deny).  The selected list is
 * swept first: entries whose TTL expired or whose session leader exited
 * are dropped and the holes compacted, so the snapshot -- and every later
 * match -- only sees live entries.  At most `max` records are written;
 * *total_out receives the number of live entries before truncation, so a
 * caller detects truncation when it exceeds the return value.
 *
 * Returns the number of records written (>= 0), or -1 on bad arguments
 * (out NULL, total_out NULL, max <= 0, deny not 0 or 1) without touching
 * the lists.
 */
int session_snapshot(int deny, SessionRecord *out, int max, int *total_out);

/*
 * Remove one entry from one list by its stored rule ID.  `deny` selects
 * the list (0 = allow, 1 = deny).  The ID may be any unambiguous prefix
 * of at least RULEID_MIN_PREFIX (8) lower-case hex characters, up to the
 * full RULEID_HEX_LEN (16); an entry whose stored ID is empty never
 * matches (it cannot be addressed by ID).
 *
 * Returns 1 when exactly one entry was removed, 0 when none matched, -2
 * when two or more entries match the prefix (ambiguity is a caller
 * error: nothing is removed), and -1 for invalid arguments (id NULL,
 * deny not 0 or 1) or a prefix that is shorter than RULEID_MIN_PREFIX or
 * not lower-case hex.
 */
int session_remove_by_id(int deny, const char *id);

/* Test seam: table capacity (SESSION_MAX). The overflow-reclamation
 * behavior is only observable by filling to the cap. */
int session_test_max(void);

#endif
