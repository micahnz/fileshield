#ifndef FILESHIELD_NOTIFY_H
#define FILESHIELD_NOTIFY_H

#include <sys/types.h>

/* Return values for notify_ask(). */
#define NOTIFY_ALLOW_ONCE 0    /* cache this file for the process (user_ttl)    */
#define NOTIFY_DENY 1          /* block this attempt only                       */
#define NOTIFY_ALLOW_ALWAYS 2  /* persistent runtime allowlist entry            */
#define NOTIFY_DENY_ALWAYS 3   /* persistent runtime denylist entry             */
#define NOTIFY_ALLOW_SESSION 4 /* allow this binary+file until the session ends */
#define NOTIFY_DENY_SESSION 5  /* deny this binary+file until the session ends  */

/*
 * One prompt: everything the dialogs need to describe the access and to
 * label the scope choices accurately.  Strings are borrowed from the
 * caller for the duration of the call; notify_ask() sanitizes and bounds
 * them before they reach kdialog.
 */
typedef struct
{
    const char *comm;        /* requester process name                    */
    pid_t pid;
    pid_t ppid;
    const char *comm_parent; /* parent process name                       */
    const char *exe;         /* binary path; NULL/"" = unknown            */
    const char *cmdline;     /* display command line; "" = unknown        */
    const char *path;        /* target file                               */
    uid_t user_uid;          /* real uid of the requester                 */
    int user_ttl;            /* "Allow once" TTL in seconds (display only) */
    int session_ttl;         /* session cap in seconds; 0 = session life   */
    int hash_unavailable;    /* 1 = binary digest missing: "Allow Always"
                                cannot persist for this binary             */
    const char *hash_failure; /* human-readable reason; may be NULL/""    */
} NotifyRequest;

/*
 * One hash-change prompt: an [allowlist] rule matched but the requester's
 * binary no longer matches the pinned SHA-512.  Strings are borrowed from
 * the caller for the duration of the call; notify_ask_hash_change()
 * sanitizes and bounds them before they reach kdialog.
 *
 * The caller owns dialog rate limiting: this prompt must never be
 * reachable for a binary that dialog_rate_limited() would reject (same
 * contract as notify_ask()).
 */
typedef struct
{
    const char *rule_pattern; /* canonical rule binary pattern (pin key)  */
    const char *exe;          /* concrete binary path                     */
    const char *old_hash;     /* pinned SHA-512 hex digest                */
    const char *new_hash;     /* freshly computed SHA-512 hex digest      */
    const char *path;         /* target file                              */
    const char *cmdline;      /* display command line; "" = unknown       */
    pid_t pid;
    uid_t user_uid;           /* real uid of the requester                */
} NotifyHashChange;

/*
 * Store the fanotify fd so notify_ask() can pump pending events while the
 * dialog child is running (prevents dialog deadlock on mount-marked FSes).
 */
void notify_set_fan_fd(int fd);

int notify_ask(const NotifyRequest *req);

/*
 * Ask the user whether a changed [allowlist] binary hash may replace the
 * pinned value.  A two-row menu: choosing "Update & Allow" ->
 * NOTIFY_ALLOW_ALWAYS (the caller persists the new hash and grants this
 * access); the preselected "Deny", window close, timeout, kdialog
 * failure and a NULL req all return NOTIFY_DENY with the old pin
 * untouched.  The grant rides on the same positive stdout-tag channel as
 * notify_ask().  When running as root, refuses to prompt without a
 * detected non-root desktop session (every other failure path also
 * denies and keeps the old pin).
 */
int notify_ask_hash_change(const NotifyHashChange *req);

/* Human-readable name of a NOTIFY_* decision code ("Allow Once"). */
const char *notify_decision_name(int decision);

/*
 * Desktop notifications for config-rule hits (notify-send).  The daemon
 * runs as root, so delivery reuses the dialog session detection and drops
 * to the requesting user's session; the call is fire-and-forget and never
 * affects the access decision.
 */

/* Notification kinds: title, urgency and icon differ per kind. */
#define NOTIFY_HIT_ALLOW 0  /* hash-pinned [allowlist] hit */
#define NOTIFY_HIT_UNSAFE 1 /* [unsafe_allowlist] hit      */
#define NOTIFY_HIT_DENY 2   /* [denylist] block            */

typedef struct
{
    uid_t uid;         /* requester's real uid (session to notify)    */
    int kind;          /* NOTIFY_HIT_*                                 */
    const char *rule;  /* matched config rule pattern                  */
    const char *binary; /* concrete binary path                        */
    pid_t pid;
    const char *comm;  /* process name; may be NULL/""                 */
    const char *target; /* file the request was for                    */
    int dedup_seconds; /* identical-hit suppression window; 0 = all    */
    int max_per_window; /* global cap per 60 s window; <= 0 = default  */
} NotifyHit;

/*
 * Fire-and-forget notification for one config-rule hit.  Identical
 * (kind, binary, target) hits inside dedup_seconds are suppressed, as is a
 * flood of distinct keys; NOTIFY_HIT_UNSAFE ignores dedup_seconds because
 * its caller gates it once per process instead.  A missing notify-send or
 * an undetectable desktop session logs once / at DEBUG and drops the
 * notification.  Never blocks the event loop and never changes the
 * decision.
 */
void notify_rule_hit(const NotifyHit *hit);

/* Test seams: exercise the rate/dedup window without a desktop session. */
int notify_test_hit_rate(int kind, const char *binary, const char *target,
                         int dedup_seconds, int max_per_window);
void notify_test_reset_rate(void);

/* Test seam: the dialog environment whitelist (see notify.c). */
int notify_test_env_key_allowed(const char *key);

/*
 * Test seam: merge a synthetic NUL-separated environ blob exactly like
 * the dialog code merges /proc/<pid>/environ.  Returns the number of
 * collected entries; when out/outsz are non-NULL, copies the value
 * collected for key ("" when the key was not collected).
 */
int notify_test_merge_env(const char *blob, size_t len, const char *key,
                          char *out, size_t outsz);

/*
 * Test seam: sanitize one dialog-body value exactly like the prompt
 * builder (control characters become '?', an over-long value gets its
 * tail replaced by "...").  Writes at most outsz-1 bytes plus the NUL.
 */
void notify_test_sanitize_ellipsized(const char *in, char *out, size_t outsz);

/*
 * Test seam: map a kdialog --menu selection token (the tag echoed on
 * stdout for an explicit pick) to a NOTIFY_* decision.  Every unknown,
 * empty or NULL token denies (fail closed): a grant exists only as a
 * row the user actually selected, never as a side effect of an error.
 */
int notify_test_menu_choice(const char *token);

/*
 * Test seam: override the kdialog binary spawned by both prompts (NULL
 * restores /usr/bin/kdialog). Lets an integration test drive the full
 * fork/pipe/drain/token flow with a scripted stand-in, proving the
 * --menu argv shape and that only a stdout tag grants; the hash-change
 * menu can likewise be driven to pin its two rows, its --default deny
 * row and its HTML-escaped body.
 */
void notify_test_set_kdialog_path(const char *path);

/*
 * Test seam: the prompt-body HTML escaper used for the styled --menu
 * description (& < > -> entities, newlines -> <br>).  Returns 0 on
 * success; -1 with out[0] == '\0' when outsz cannot hold the result,
 * in which case the caller passes the plain-text body instead.
 */
int notify_test_html_escape(const char *in, char *out, size_t outsz);

/*
 * Test seam: hard-wrap one dialog body to 80 display columns exactly
 * like both prompts do, so a long path or command line cannot widen the
 * popup.  html=1 counts HTML tags as zero columns and entities as one
 * glyph and breaks with <br>; html=0 wraps plain text with newlines.
 * Returns 0 on success; -1 with out[0] == '\0' when outsz cannot hold
 * the result (the caller then shows the unwrapped body).
 */
int notify_test_wrap_text(const char *in, char *out, size_t outsz, int html);

#endif
