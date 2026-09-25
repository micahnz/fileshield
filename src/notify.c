#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>

#include "notify.h"
#include "fanotify.h"
#include "session.h"
#include "utils.h"

/* Monotonic milliseconds: wall-clock steps must not extend a deadline. */
static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*
 * Fanotify fd stored here so the dialog runners can pump pending events
 * while waiting for the dialog child (prevents mount-mark deadlock).
 */
static int g_fan_fd = -1;

/* Total wall-clock budget for a dialog, slightly longer than the inner
 * "timeout 30" the child enforces. */
#define DIALOG_OUTER_TIMEOUT_S 40

/* ------------------------------------------------------------------ */
/*  user session environment forwarding                                */
/* ------------------------------------------------------------------ */
/*
 * The daemon runs as root from systemd with a bare environment, so a
 * kdialog child would miss the user's desktop session variables and Qt
 * falls back to the generic light theme instead of the user's theme
 * (on Plasma, KDE_FULL_SESSION / XDG_CURRENT_DESKTOP drive platform
 * theme selection).  Forward a fixed whitelist of cosmetic variables
 * from the user's own session.
 *
 * Deliberately NOT forwarded:
 *   - DISPLAY / WAYLAND_DISPLAY / XAUTHORITY / DBUS_SESSION_BUS_ADDRESS:
 *     the prompt must stay on the display Fileshield detected, never one
 *     a malicious process points at.
 *   - LD_* / PATH / QT_PLUGIN_PATH / QT_QPA_PLATFORM*: no code loading or
 *     platform override.  QT_QPA_PLATFORMTHEME is the one deliberate
 *     exception: it names an installed theme plugin by key (Qt resolves it
 *     without QT_PLUGIN_PATH), not a platform or a code path.
 * The forwarded values are cosmetic only and length-capped; a malicious
 * value can at worst make the dialog look wrong or fail, which still
 * fails closed.
 */
static const char *const g_dialog_env_keys[] = {
    "XDG_CURRENT_DESKTOP",
    "XDG_SESSION_DESKTOP",
    "XDG_SESSION_TYPE",
    "KDE_FULL_SESSION",
    "KDE_SESSION_VERSION",
    "KDE_APPLICATIONS_AS_SCOPE",
    "QT_QPA_PLATFORMTHEME",
    "QT_STYLE_OVERRIDE",
    "QT_AUTO_SCREEN_SCALE_FACTOR",
    "QT_SCALE_FACTOR",
    "QT_SCREEN_SCALE_FACTORS",
    "QT_FONT_DPI",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_NUMERIC",
    "XCURSOR_THEME",
    "XCURSOR_SIZE",
    "GTK_THEME",
    NULL};

#define DIALOG_ENV_MAX 24
#define DIALOG_ENV_KEY_MAX 32
#define DIALOG_ENV_VALUE_MAX 256
#define DIALOG_ENV_FILE_MAX (128 * 1024)

typedef struct
{
    char key[DIALOG_ENV_KEY_MAX];
    char value[DIALOG_ENV_VALUE_MAX];
} DialogEnvSetting;

static int dialog_env_key_allowed(const char *key)
{
    for (int i = 0; g_dialog_env_keys[i] != NULL; i++)
    {
        if (strcmp(g_dialog_env_keys[i], key) == 0)
            return 1;
    }
    return 0;
}

/* Test seam (notify.h): the dialog environment whitelist. */
int notify_test_env_key_allowed(const char *key)
{
    return dialog_env_key_allowed(key);
}

static int dialog_env_collected(const DialogEnvSetting *out, int count,
                                const char *key)
{
    for (int i = 0; i < count; i++)
    {
        if (strcmp(out[i].key, key) == 0)
            return 1;
    }
    return 0;
}

/* Merge NUL-separated KEY=VALUE entries from a /proc environ buffer. */
static int merge_proc_environ(const char *buf, size_t len,
                              DialogEnvSetting *out, int count, int max)
{
    size_t pos = 0;

    while (pos < len && count < max)
    {
        const char *entry = buf + pos;
        size_t entry_len = strnlen(entry, len - pos);
        const char *eq = memchr(entry, '=', entry_len);

        if (eq != NULL && (size_t)(eq - entry) < DIALOG_ENV_KEY_MAX)
        {
            char key[DIALOG_ENV_KEY_MAX];
            size_t klen = (size_t)(eq - entry);

            memcpy(key, entry, klen);
            key[klen] = '\0';

            if (dialog_env_key_allowed(key) &&
                !dialog_env_collected(out, count, key))
            {
                size_t vlen = entry_len - klen - 1;
                if (vlen >= DIALOG_ENV_VALUE_MAX)
                    vlen = DIALOG_ENV_VALUE_MAX - 1;
                snprintf(out[count].key, sizeof(out[count].key), "%s", key);
                memcpy(out[count].value, eq + 1, vlen);
                out[count].value[vlen] = '\0';
                count++;
            }
        }
        pos += entry_len + 1;
    }
    return count;
}

/*
 * Test seam (notify.h): run merge_proc_environ over a synthetic
 * NUL-separated blob (like /proc/<pid>/environ).  Returns the number of
 * collected entries and, when out/outsz are non-NULL, copies the value
 * collected for key ("" when the key was not collected).
 */
int notify_test_merge_env(const char *blob, size_t len, const char *key,
                          char *out, size_t outsz)
{
    DialogEnvSetting merged[DIALOG_ENV_MAX];
    int count;

    memset(merged, 0, sizeof(merged));
    count = merge_proc_environ(blob, len, merged, 0, DIALOG_ENV_MAX);
    if (out && outsz > 0)
    {
        out[0] = '\0';
        for (int i = 0; i < count; i++)
            if (strcmp(merged[i].key, key) == 0)
                snprintf(out, outsz, "%s", merged[i].value);
    }
    return count;
}

static int read_proc_environ(pid_t pid, char *buf, size_t bufsz)
{
    char path[64];
    int fd;
    ssize_t total = 0;

    snprintf(path, sizeof(path), "/proc/%d/environ", (int)pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    /* Drain what fits: a short read is not EOF on procfs, and SIGHUP
     * (handlers run without SA_RESTART) must not silently drop the
     * user's environment -- the dialog would lose its theme variables. */
    while (total < (ssize_t)bufsz - 1)
    {
        ssize_t n = read(fd, buf + total, bufsz - 1 - (size_t)total);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        total += n;
    }
    close(fd);
    if (total <= 0)
        return -1;
    buf[total] = '\0';
    return (int)total;
}

/*
 * Collect the whitelisted variables for requester.  The session leader
 * (the user's shell) holds the authoritative session environment; the
 * requester fills any gaps.  Returns the number of settings found.
 */
static int collect_dialog_env(pid_t requester, DialogEnvSetting *out, int max)
{
    char *buf = malloc(DIALOG_ENV_FILE_MAX);
    pid_t leader = 0;
    unsigned long long leader_start = 0;
    int count = 0;
    int n;

    if (buf == NULL)
        return 0;

    if (session_id_of(requester, &leader, &leader_start) == 0 && leader > 0)
    {
        unsigned long long now_start = 0;

        /* Read the leader's environment only while it is still the process
         * the SID was resolved to: a recycled leader PID must not feed the
         * dialog from an unrelated process. */
        if (proc_stat_session(leader, NULL, &now_start) == 0 &&
            now_start == leader_start)
        {
            n = read_proc_environ(leader, buf, DIALOG_ENV_FILE_MAX);
            if (n > 0)
                count = merge_proc_environ(buf, (size_t)n, out, count, max);
        }
    }

    if (count < max && requester != leader)
    {
        n = read_proc_environ(requester, buf, DIALOG_ENV_FILE_MAX);
        if (n > 0)
            count = merge_proc_environ(buf, (size_t)n, out, count, max);
    }

    free(buf);
    return count;
}

/* Called in the dialog child after dropping to the desktop user. */
static void apply_dialog_env(const DialogEnvSetting *env, int count)
{
    for (int i = 0; i < count; i++)
        setenv(env[i].key, env[i].value, 1);
}

void notify_set_fan_fd(int fd)
{
    g_fan_fd = fd;
}

/*
 * Desktop session selected for one prompt.  Detection never mutates the
 * daemon's environment: the values are applied inside the dialog child
 * after it drops to the desktop user, so a prompt is always shown on the
 * display detected for that user and cannot leak into later, unrelated
 * requests (or into forked helpers such as sha512sum).
 */
typedef struct
{
    uid_t uid;                 /* desktop user; 0 = none found            */
    char wayland_display[256]; /* "" when unset                           */
    char display[256];         /* X11 DISPLAY from the unit, "" when unset */
    char xdg_runtime_dir[PATH_MAX];
    char dbus_address[PATH_MAX + 32];
} DisplaySession;

/*
 * find_wayland_session: look for an active Wayland session owned by
 * uid_val under /run/user/<uid>.  The runtime directory and the socket
 * are both validated (real directory / socket, owned by the user) so a
 * planted regular file or another user's endpoint cannot capture the
 * prompt.  On success fills *out and returns 1.
 */
static int find_wayland_session(unsigned long uid_val, DisplaySession *out)
{
    char user_dir[PATH_MAX];
    struct stat st;
    DIR *d;
    const struct dirent *ent;
    char sock[256] = "";

    snprintf(user_dir, sizeof(user_dir), "/run/user/%lu", uid_val);

    if (lstat(user_dir, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != (uid_t)uid_val)
        return 0;

    d = opendir(user_dir);
    if (!d)
        return 0;

    while ((ent = readdir(d)) != NULL)
    {
        if (strncmp(ent->d_name, "wayland-", 8) != 0)
            continue;
        if (strstr(ent->d_name, ".lock") != NULL)
            continue;

        char full[PATH_MAX];
        if (snprintf(full, sizeof(full), "%s/%s", user_dir, ent->d_name) >=
            (int)sizeof(full))
            continue;

        struct stat sst;
        if (lstat(full, &sst) != 0)
            continue;
        /* Only a socket owned by the user can serve a Wayland session. */
        if (!S_ISSOCK(sst.st_mode) || sst.st_uid != (uid_t)uid_val)
            continue;

        snprintf(sock, sizeof(sock), "%s", ent->d_name);
        break;
    }
    closedir(d);

    if (sock[0] == '\0')
        return 0;

    memset(out, 0, sizeof(*out));
    out->uid = (uid_t)uid_val;
    snprintf(out->wayland_display, sizeof(out->wayland_display), "%s", sock);
    snprintf(out->xdg_runtime_dir, sizeof(out->xdg_runtime_dir), "%s",
             user_dir);
    snprintf(out->dbus_address, sizeof(out->dbus_address), "unix:path=%s/bus",
             user_dir);
    return 1;
}

/*
 * user_runtime_dir: validate /run/user/<uid> (real directory owned by the
 * user, mirroring find_wayland_session's checks) and fill the session's
 * runtime dir and bus address from it.  Returns 1 on success.
 */
static int user_runtime_dir(unsigned long uid_val, DisplaySession *out)
{
    char user_dir[PATH_MAX];
    struct stat st;

    snprintf(user_dir, sizeof(user_dir), "/run/user/%lu", uid_val);
    if (lstat(user_dir, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != (uid_t)uid_val)
        return 0;

    snprintf(out->xdg_runtime_dir, sizeof(out->xdg_runtime_dir), "%s",
             user_dir);
    snprintf(out->dbus_address, sizeof(out->dbus_address), "unix:path=%s/bus",
             user_dir);
    out->uid = (uid_t)uid_val;
    return 1;
}

/*
 * detect_display_session: determine which desktop session should show the
 * prompt.  Preference order:
 *   1. Environment already provides WAYLAND_DISPLAY/DISPLAY (systemd
 *      override or a manual run); derive the session uid from
 *      XDG_RUNTIME_DIR ownership when it is usable, otherwise from the
 *      requester's uid (a systemd service normally has no
 *      XDG_RUNTIME_DIR, and the shipped unit's X11 guidance sets only
 *      DISPLAY).
 *   2. The requesting process's own uid (preferred_uid): the prompt must
 *      be shown to the user whose process triggered it.
 *   3. As a last resort for unknown requesters, the first active non-root
 *      Wayland session found under /run/user.
 * Returns 1 when a non-root session was found; the dialog child then
 * drops to out->uid.  Returns 0 when no such session exists, in which
 * case notify_ask() refuses to run a GUI as root (fail closed).
 */
static int detect_display_session(uid_t preferred_uid, DisplaySession *out)
{
    memset(out, 0, sizeof(*out));

    /* 1. Explicitly configured display (unit override or manual run):
     * trusted as-is; only the session uid needs resolving. */
    const char *env_wayland = getenv("WAYLAND_DISPLAY");
    const char *env_display = getenv("DISPLAY");

    if (env_wayland || env_display)
    {
        if (env_wayland)
            snprintf(out->wayland_display, sizeof(out->wayland_display), "%s",
                     env_wayland);
        if (env_display)
            snprintf(out->display, sizeof(out->display), "%s", env_display);

        const char *xdg = getenv("XDG_RUNTIME_DIR");
        struct stat st;
        if (xdg && stat(xdg, &st) == 0 && st.st_uid != 0)
        {
            out->uid = st.st_uid;
            snprintf(out->xdg_runtime_dir, sizeof(out->xdg_runtime_dir), "%s",
                     xdg);

            /* An explicitly configured bus address wins; otherwise derive
             * it from the runtime directory, as the auto-detection path
             * does. */
            const char *dbus_env = getenv("DBUS_SESSION_BUS_ADDRESS");
            if (dbus_env && dbus_env[0] != '\0')
                snprintf(out->dbus_address, sizeof(out->dbus_address), "%s",
                         dbus_env);
            else
                snprintf(out->dbus_address, sizeof(out->dbus_address),
                         "unix:path=%s/bus", xdg);
            return 1;
        }

        /* No usable XDG_RUNTIME_DIR: derive the runtime dir from the
         * requester's uid — the prompt belongs to the user whose process
         * triggered it anyway.  uid 0 or unknown requesters must not be
         * pointed at an arbitrary desktop user, so they refuse (fail
         * closed) instead of scanning /run/user. */
        if (preferred_uid != (uid_t)-1 && preferred_uid != 0 &&
            user_runtime_dir((unsigned long)preferred_uid, out))
        {
            log_msg(LOG_WARNING,
                    "XDG_RUNTIME_DIR unset or root-owned; using the "
                    "requester's runtime dir for uid %d",
                    (int)preferred_uid);
            return 1;
        }
        log_msg(LOG_WARNING,
                "env display set but no usable XDG_RUNTIME_DIR and no "
                "promptable requester uid; refusing a GUI prompt");
        return 0;
    }

    /* 2. The requester's own session: the prompt must never be shown to
     * a different user. */
    if (preferred_uid != (uid_t)-1 && preferred_uid != 0)
    {
        if (find_wayland_session((unsigned long)preferred_uid, out))
            return 1;
        log_msg(LOG_WARNING,
                "no active Wayland session for uid %d; not prompting another user",
                (int)preferred_uid);
        return 0;
    }

    /*
     * 3. Last resort for an unknown requester: the first active Wayland
     * session under /run/user.  Auto-detection is Wayland-only because
     * an X11 DISPLAY cannot be resolved to a user (the server socket
     * sits in the shared /tmp/.X11-unix, not under a per-user
     * directory), so an X11 session must arrive through the explicit
     * environment above.
     */
    DIR *top = opendir("/run/user");
    if (!top)
        return 0;

    const struct dirent *uid_ent;
    while ((uid_ent = readdir(top)) != NULL)
    {
        if (uid_ent->d_name[0] == '.')
            continue;

        char *endptr;
        unsigned long uid_val = strtoul(uid_ent->d_name, &endptr, 10);
        if (*endptr != '\0' || uid_val == 0)
            continue;

        if (find_wayland_session(uid_val, out))
        {
            closedir(top);
            return 1;
        }
    }
    closedir(top);
    return 0;
}

/*
 * apply_display_env: called in the dialog child after dropping to the
 * desktop user.  Exports the detected session so kdialog reaches the
 * right compositor.  Deliberately never called in the daemon: a session
 * must not leak across prompts or into unrelated forked helpers.
 */
static void apply_display_env(const DisplaySession *session)
{
    if (session->wayland_display[0] != '\0')
        setenv("WAYLAND_DISPLAY", session->wayland_display, 1);
    if (session->display[0] != '\0')
        setenv("DISPLAY", session->display, 1);
    if (session->xdg_runtime_dir[0] != '\0')
        setenv("XDG_RUNTIME_DIR", session->xdg_runtime_dir, 1);
    if (session->dbus_address[0] != '\0')
        setenv("DBUS_SESSION_BUS_ADDRESS", session->dbus_address, 1);
}

/*
 * drop_to_session_user: called in the dialog child after fork().
 * Switches uid/gid to the desktop user (including supplementary groups)
 * so the dialog can connect to their compositor and D-Bus session.
 */
static void drop_to_session_user(const DisplaySession *session)
{
    if (session->uid == 0 || getuid() != 0)
        return;

    struct passwd *pw = getpwuid(session->uid);
    if (!pw)
        _exit(127);

    /* Drop supplementary groups first, then gid, then uid. */
    if (initgroups(pw->pw_name, pw->pw_gid) < 0)
        _exit(127);
    if (setgid(pw->pw_gid) < 0)
        _exit(127);
    if (setuid(session->uid) < 0)
        _exit(127);

    /* The child must not inherit root's HOME/USER/PATH when the daemon was
     * started outside systemd; PATH is a fixed trusted value so nothing
     * from the requesting process can steer helper lookup. */
    if (pw->pw_dir)
        setenv("HOME", pw->pw_dir, 1);
    setenv("USER", pw->pw_name, 1);
    setenv("LOGNAME", pw->pw_name, 1);
    setenv("PATH",
           "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
}

/*
 * sanitize_text: replace control characters (including newlines) with
 * '?' and bound the length so attacker-controlled file names, comm names
 * and cmdlines cannot spoof extra dialog content.
 */
static void sanitize_text(const char *in, char *out, size_t outsz)
{
    size_t j = 0;

    if (outsz == 0)
        return;
    if (!in)
    {
        out[0] = '\0';
        return;
    }
    for (size_t i = 0; in[i] != '\0' && j + 1 < outsz; i++)
    {
        unsigned char c = (unsigned char)in[i];
        out[j++] = (c < 0x20 || c == 0x7f) ? '?' : (char)c;
    }
    out[j] = '\0';
}

/*
 * sanitize_ellipsized: sanitize src into out (bounded) and, when content
 * was actually cut, mark the cut by replacing the tail with "...".
 * A value that fits exactly is left untouched.
 */
static void sanitize_ellipsized(const char *in, char *out, size_t outsz)
{
    sanitize_text(in, out, outsz);
    if (!in || strlen(in) <= outsz - 1)
        return; /* nothing was cut */
    if (outsz >= 4)
        memcpy(out + outsz - 4, "...", 4);
}

/* Test seam (notify.h): bounded prompt-text sanitizing with the cut
 * marker, shared with the real prompt builder. */
void notify_test_sanitize_ellipsized(const char *in, char *out, size_t outsz)
{
    sanitize_ellipsized(in, out, outsz);
}

/* Kill the dialog process group and reap with a bounded wait. */
static void kill_and_reap(pid_t pid, int *status, int *child_exited)
{
    /* The PID may have been recycled between the last WNOHANG check and
     * this kill: confirm the process still leads this group before
     * signaling it, and fall back to the single pid when it does not. */
    if (getpgid(pid) == pid)
        kill(-pid, SIGKILL);
    else
        kill(pid, SIGKILL);
    for (int i = 0; i < 100 && !*child_exited; i++) /* up to ~10s */
    {
        pid_t wr = waitpid(pid, status, WNOHANG);
        if (wr == pid)
            *child_exited = 1;
        else if (wr < 0 && errno != EINTR)
            break;
        usleep(100000);
    }
    if (!*child_exited)
        log_msg(LOG_ERR,
                "[dialog] pid=%d did not exit after SIGKILL; abandoning it",
                (int)pid);
}

/* Both dialog children exec this kdialog; notify_test_set_kdialog_path()
 * can swap it for a scripted stand-in so the fork/pipe/drain mechanics,
 * the argv shape and the hash-change body can be proven without a
 * desktop click. */
static char g_kdialog_path[PATH_MAX] = "/usr/bin/kdialog";

/*
 * Escape a plain string for safe embedding in the prompt's rich text.
 *
 * The --menu body renders as HTML (KListBoxDialog uses a plain QLabel
 * with Qt::AutoText), which widens the injection surface beyond control
 * characters: sanitize_text() neutralizes those but NOT '&', '<' or '>',
 * all legal in file names and comm.  Without this escape a crafted path
 * like "<img src=y onerror=...>" would execute markup INSIDE a security
 * prompt.  Newlines become <br> (the only multi-line inputs we escape
 * are daemon-built, e.g. the hash-unavailable note; requester fields
 * are already \n-stripped by sanitize_text).  UTF-8 bytes pass verbatim:
 * continuation bytes are >= 0x80 and never collide with the escaped set.
 *
 * Returns 0 on success; on ANY capacity shortfall returns -1 with
 * out[0] == '\0' so callers fall back to the plain-text body rather
 * than emit a half-written markup document.
 */
static int html_escape(const char *in, char *out, size_t outsz)
{
    size_t j = 0;
    size_t i;

    if (outsz == 0)
        return -1;
    out[0] = '\0';

    for (i = 0; in[i] != '\0'; i++)
    {
        const char *rep = NULL;
        size_t rl;

        switch (in[i])
        {
        case '&':
            rep = "&amp;";
            break;
        case '<':
            rep = "&lt;";
            break;
        case '>':
            rep = "&gt;";
            break;
        case '\n':
            rep = "<br>";
            break;
        default:
            break;
        }
        rl = rep ? strlen(rep) : 1;
        if (j + rl >= outsz)
        {
            out[0] = '\0';
            return -1;
        }
        if (rep)
        {
            memcpy(out + j, rep, rl);
            j += rl;
        }
        else
            out[j++] = in[i];
        out[j] = '\0';
    }
    return 0;
}

/* Test seam (notify.h): the prompt-body HTML escaper. */
int notify_test_html_escape(const char *in, char *out, size_t outsz)
{
    return html_escape(in, out, outsz);
}

/* ------------------------------------------------------------------ */
/*  dialog body hard wrapping                                          */
/* ------------------------------------------------------------------ */
/*
 * Hard limit for one rendered dialog line: a long path or command line
 * must not widen the kdialog popup beyond this many display columns.
 */
#define DIALOG_TEXT_WIDTH 80

/*
 * 1 when an HTML tag opens a fresh rendered line (block or break
 * element).  Only the inline elements the prompt builder emits keep the
 * current column; anything unknown counts as a block, which can only
 * wrap a line earlier, never later.
 */
static int html_tag_breaks_line(const char *tag, size_t len)
{
    static const char *const inline_tags[] = {
        "a", "b", "i", "u", "em", "strong", "tt", "code", "span", "font",
        "sub", "sup", "small", "big", NULL};
    char name[16];
    size_t k = 1;
    size_t n = 0;

    if (k < len && tag[k] == '/')
        k++;
    while (k < len && n + 1 < sizeof(name))
    {
        unsigned char c = (unsigned char)tag[k];

        if (c >= 'A' && c <= 'Z')
            c = (unsigned char)(c - 'A' + 'a');
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')))
            break;
        name[n++] = (char)c;
        k++;
    }
    name[n] = '\0';

    for (int i = 0; inline_tags[i] != NULL; i++)
        if (strcmp(name, inline_tags[i]) == 0)
            return 0;
    return 1;
}

/*
 * Length of the HTML entity starting at s, or 0 when s does not start
 * one.  An entity counts as one visible column and must never be split,
 * or the prompt would show its raw source text ("&amp;") to the user.
 */
static size_t html_entity_len(const char *s)
{
    static const char *const names[] = {
        "amp", "lt", "gt", "quot", "apos", "nbsp", NULL};
    size_t k;

    if (s[0] != '&')
        return 0;

    k = 1;
    if (s[k] == '#')
    {
        size_t digits = 0;

        k++;
        while (s[k] >= '0' && s[k] <= '9' && digits < 7)
        {
            k++;
            digits++;
        }
        return (digits > 0 && s[k] == ';') ? k + 1 : 0;
    }

    for (int i = 0; names[i] != NULL; i++)
    {
        size_t l = strlen(names[i]);

        if (strncmp(s + k, names[i], l) == 0 && s[k + l] == ';')
            return k + l + 1;
    }
    return 0;
}

/*
 * wrap_dialog_text: hard-wrap one dialog body to DIALOG_TEXT_WIDTH
 * display columns so long file names and command lines cannot widen the
 * popup.  The plain body break is '\n'; in html mode the break is
 * '<br>', tags count zero columns, and entities and UTF-8 sequences
 * count one column and are never split.  Existing newlines and block
 * tags reset the column.  A line breaks at the last space at or before
 * the limit; a token with no space (a long path) hard-breaks at the
 * limit.
 *
 * Pure and cosmetic: returns 0 on success; on a capacity shortfall
 * returns -1 with out[0] == '\0' so the caller keeps the unwrapped body
 * rather than emit a clipped one.  Wrapping never affects a decision.
 */
static int wrap_dialog_text(const char *in, char *out, size_t outsz, int html)
{
    const char *br = html ? "<br>" : "\n";
    const size_t blen = strlen(br);
    size_t j = 0;                 /* next output byte                    */
    size_t i = 0;                 /* next input byte                     */
    int col = 0;                  /* display columns since the last break */
    size_t space_out = (size_t)-1; /* output index of the line's last space */
    int space_col = 0;            /* columns before that space           */

    if (outsz == 0)
        return -1;
    out[0] = '\0';

    while (in[i] != '\0')
    {
        size_t ulen = 1;
        int width = 1;
        int is_space = 0;
        int new_line = 0;

        if (in[i] == '\n')
            new_line = 1;
        else if (html && in[i] == '<')
        {
            size_t k = i + 1;

            while (in[k] != '\0' && in[k] != '>' && k - i < 256)
                k++;
            if (in[k] == '>')
            {
                ulen = k - i + 1;
                width = 0;
                new_line = html_tag_breaks_line(in + i, ulen);
            }
        }
        else if (html && in[i] == '&')
        {
            size_t e = html_entity_len(in + i);

            if (e > 0)
                ulen = e;
        }
        else if ((unsigned char)in[i] >= 0xC0)
        {
            /* One UTF-8 sequence = one column; copy it whole. */
            while (ulen < 4 && ((unsigned char)in[i + ulen] & 0xC0) == 0x80)
                ulen++;
        }
        else
            is_space = (in[i] == ' ');

        /* Newline or block tag: emit verbatim and restart the line. */
        if (new_line)
        {
            if (j + ulen >= outsz)
                goto overflow;
            memcpy(out + j, in + i, ulen);
            j += ulen;
            out[j] = '\0';
            col = 0;
            space_out = (size_t)-1;
            i += ulen;
            continue;
        }

        /* Inline tag: zero columns, never split. */
        if (width == 0)
        {
            if (j + ulen >= outsz)
                goto overflow;
            memcpy(out + j, in + i, ulen);
            j += ulen;
            out[j] = '\0';
            i += ulen;
            continue;
        }

        /* A space at the start of a line would sit against the wrap edge
         * with nothing before it: drop it. */
        if (is_space && col == 0)
        {
            i += ulen;
            continue;
        }

        /* The line is full and another glyph follows: break at the last
         * space on this line when there is one, otherwise hard-break at
         * the limit (long paths and command tokens have no space). */
        if (col >= DIALOG_TEXT_WIDTH)
        {
            if (space_out != (size_t)-1)
            {
                /* Replace the space with the break and shift the tail. */
                if (j + blen >= outsz)
                    goto overflow;
                memmove(out + space_out + blen, out + space_out + 1,
                        j - (space_out + 1));
                memcpy(out + space_out, br, blen);
                j += blen - 1;
                out[j] = '\0';
                col = col - space_col - 1;
                space_out = (size_t)-1;
            }
            else
            {
                if (j + blen >= outsz)
                    goto overflow;
                memcpy(out + j, br, blen);
                j += blen;
                out[j] = '\0';
                col = 0;
            }
            /* The space that hit the limit was the wrap point: drop it. */
            if (is_space)
            {
                i += ulen;
                continue;
            }
        }

        if (j + ulen >= outsz)
            goto overflow;
        if (is_space)
        {
            space_out = j;
            space_col = col;
        }
        memcpy(out + j, in + i, ulen);
        j += ulen;
        out[j] = '\0';
        col++;
        i += ulen;
    }

    return 0;

overflow:
    out[0] = '\0';
    return -1;
}

/* Test seam (notify.h): the dialog body hard-wrapper. */
int notify_test_wrap_text(const char *in, char *out, size_t outsz, int html)
{
    return wrap_dialog_text(in, out, outsz, html);
}

/*
 * One choice row of a kdialog --menu prompt: the tag is what kdialog
 * echoes to stdout when the user picks the row; the label is the
 * descriptive text the user reads.
 */
typedef struct
{
    const char *tag;
    const char *label;
} DialogMenuItem;

#define DIALOG_MENU_MAX_ITEMS 8
#define DIALOG_TOKEN_MAX 64

/* Test seam (notify.h): override the dialog kdialog binary (NULL = reset). */
void notify_test_set_kdialog_path(const char *path)
{
    if (!path)
        snprintf(g_kdialog_path, sizeof(g_kdialog_path), "/usr/bin/kdialog");
    else
        snprintf(g_kdialog_path, sizeof(g_kdialog_path), "%s", path);
}

/*
 * Map the selected menu tag to a NOTIFY_* decision.  Exact matches only;
 * NULL, empty, unknown and oversized tokens all deny (fail closed), so a
 * token stream produced by anything other than a real selection cannot
 * grant access.
 */
static int menu_token_to_decision(const char *token)
{
    if (!token)
        return NOTIFY_DENY;
    if (strcmp(token, "once") == 0)
        return NOTIFY_ALLOW_ONCE;
    if (strcmp(token, "session") == 0)
        return NOTIFY_ALLOW_SESSION;
    if (strcmp(token, "always") == 0)
        return NOTIFY_ALLOW_ALWAYS;
    if (strcmp(token, "deny") == 0)
        return NOTIFY_DENY;
    if (strcmp(token, "deny-session") == 0)
        return NOTIFY_DENY_SESSION;
    if (strcmp(token, "deny-always") == 0)
        return NOTIFY_DENY_ALWAYS;
    return NOTIFY_DENY;
}

/* Test seam (notify.h): the menu-token decision mapping. */
int notify_test_menu_choice(const char *token)
{
    return menu_token_to_decision(token);
}

/*
 * run_kdialog_menu: show a kdialog --menu picker and return the TAG of
 * the user's selection in token (NUL-terminated; empty when none).
 *
 * Why a menu on stdout instead of --yesnocancel on the exit code: KF6
 * kdialog prints the chosen row's tag and exits 0 ONLY for an explicit
 * selection; cancel, window close, argument errors, runtime failures,
 * timeouts and aborts all leave stdout empty (verified against the KDE
 * source: Widgets::listBox prints result = args[tag] only on Accepted).
 * The decision therefore rides on a positive channel no error path can
 * produce — deny is the literal default, and the old trade-off where
 * kdialog's No (exit 1, shared with runtime errors) could persist an
 * "Allow Always" nobody clicked is withdrawn.
 *
 * Requires the KF6 kdialog argv shape (--menu TEXT tag item [tag item]
 * ..., no numeric geometry args); an older kdialog misparses the pairs
 * and emits no valid token — every failure path denies.
 *
 * default_label (optional) names the row preselected via --default: a
 * confirm without any deliberate selection emits that row's tag.  The
 * caller passes the Deny Once label, so an accidental Enter/confirm can
 * never grant — it denies this attempt.  This also avoids kdialog's own
 * out-of-bounds read (args[currentItem()*2] with currentRow == -1) when
 * OK is pressed with no current row, keeping the failure defined.
 *
 * Returns 1 when the child exited normally with code 0 (a tag should be
 * in token; menu_token_to_decision still vets it), 0 for any other
 * normal exit (cancel/error), -1 for timeout, shutdown or spawn failure.
 */
static int run_kdialog_menu(const DisplaySession *session,
                            const DialogEnvSetting *env, int env_count,
                            const char *text, const char *default_label,
                            const DialogMenuItem *items, int nitems,
                            char *token, size_t tokensz)
{
    int pipefd[2];

    token[0] = '\0';
    if (nitems <= 0 || nitems > DIALOG_MENU_MAX_ITEMS)
        return -1;
    if (pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) < 0)
    {
        log_msg(LOG_ERR, "pipe2 failed for kdialog menu: %m");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        log_msg(LOG_ERR, "fork failed for kdialog menu: %m");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    /*
     * Phase 1 (child): drop to the desktop user, export the detected
     * session environment, and exec timeout/kdialog with stdout on the
     * pipe.  Never returns.
     */
    if (pid == 0)
    {
        /* Same child posture as run_kdialog: own process group, session
         * user, display and theme env, fd sweep.  Redirect stdout to the
         * pipe BEFORE close_fds_from(3) (fd 2 survives the sweep; the
         * pipe ends beyond fd 3 do not need to). */
        setpgid(0, 0);
        drop_to_session_user(session);
        apply_display_env(session);
        apply_dialog_env(env, env_count);
        if (pipefd[1] != STDOUT_FILENO)
            dup2(pipefd[1], STDOUT_FILENO);
        close_fds_from(3);
        signal(SIGPIPE, SIG_DFL);

        /* timeout execs the child with argv[0] = the command string, so
         * there is NO extra argv[0] slot here: everything after the path
         * would land in kdialog as a positional argument, shifting the
         * --menu tag/item pairs by one (a selected row would then echo a
         * wrong token and deny — the exact bug an earlier build shipped
         * with).  The KF6 --menu shape is: --menu TEXT tag item [...]. */
        /* Sizing: timeout + seconds + kdialog + --title + title + --menu
         * + TEXT (7), then 2 per row, the optional --default pair, NULL. */
        char *argv[7 + 2 * DIALOG_MENU_MAX_ITEMS + 2 + 1];
        int n = 0;
        argv[n++] = "/usr/bin/timeout";
        argv[n++] = "30";
        argv[n++] = g_kdialog_path;
        argv[n++] = "--title";
        argv[n++] = "Fileshield";
        argv[n++] = "--menu";
        argv[n++] = (char *)text;
        for (int i = 0; i < nitems; i++)
        {
            argv[n++] = (char *)items[i].tag;
            argv[n++] = (char *)items[i].label;
        }
        if (default_label)
        {
            /* Preselect the deny row: a confirm with no deliberate
             * selection emits its tag (deny once), never a grant. */
            argv[n++] = "--default";
            argv[n++] = (char *)default_label;
        }
        argv[n] = NULL;

        execv(argv[0], argv);
        _exit(127);
    }

    log_msg(LOG_DEBUG, "[dialog] forked kdialog menu child pid=%d", (int)pid);
    close(pipefd[1]);

    /*
     * Phase 2: pump fanotify events while the dialog is open -- a
     * pending permission event on a mount mark would otherwise deadlock
     * the opener -- and reap the child.  Ends on child exit, the
     * deadline, or shutdown (the dialog is then killed, which denies).
     */
    int child_exited = 0;
    int status = 0;
    long long deadline = now_ms() + DIALOG_OUTER_TIMEOUT_S * 1000;

    while (!child_exited && now_ms() < deadline)
    {
        if (!g_running || g_fatal)
        {
            log_msg(LOG_WARNING,
                    "[dialog] shutdown while a menu dialog is open; "
                    "denying it");
            break;
        }

        struct pollfd pfd;
        int nfds = 0;

        if (g_fan_fd >= 0)
        {
            pfd.fd = g_fan_fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            nfds = 1;
        }

        /* With no fanotify fd this is a bounded sleep; the 200 ms tick
         * keeps waitpid polling without busy-looping. */
        int ret = poll(nfds ? &pfd : NULL, (nfds_t)nfds, 200);
        if (ret < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }

        if (nfds && (pfd.revents & POLLIN))
            fanotify_pump(g_fan_fd, pid);

        pid_t wr = waitpid(pid, &status, WNOHANG);
        if (wr == pid)
        {
            child_exited = 1;
        }
        else if (wr < 0 && errno != EINTR)
        {
            log_msg(LOG_ERR, "waitpid failed for menu dialog: %m");
            kill_and_reap(pid, &status, &child_exited);
            close(pipefd[0]);
            return -1;
        }
    }

    if (!child_exited)
    {
        log_msg(LOG_WARNING,
                "[dialog] kdialog menu timeout or shutdown, killing pid=%d",
                (int)pid);
        kill_and_reap(pid, &status, &child_exited);
    }

    log_msg(LOG_DEBUG, "[dialog] kdialog menu exited status=0x%x ec=%d",
            status, WIFEXITED(status) ? WEXITSTATUS(status) : -1);

    /* Phase 3: stdout token drain.
     *
     * The child flushed its stdout before exiting (kdialog prints the tag
     * then leaves, and the write is far below the pipe capacity), so one
     * non-blocking drain after the reap captures the token.  Anything
     * unexpected — no data, oversized, no newline — leaves an empty or
     * unmatched token, which menu_token_to_decision denies. */
    size_t len = 0;
    int overflow = 0;
    for (;;)
    {
        char c;
        ssize_t r = read(pipefd[0], &c, 1);
        if (r != 1)
            break;
        if (c == '\n')
            break;
        if (len + 1 < tokensz)
            token[len++] = c;
        else
            overflow = 1;
    }
    token[overflow ? 0 : len] = '\0';
    close(pipefd[0]);

    if (!child_exited)
        return -1;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return 1;
    return 0;
}

const char *notify_decision_name(int decision)
{
    switch (decision)
    {
    case NOTIFY_ALLOW_ONCE:
        return "Allow Once";
    case NOTIFY_ALLOW_SESSION:
        return "Allow Session";
    case NOTIFY_ALLOW_ALWAYS:
        return "Allow Always";
    case NOTIFY_DENY_SESSION:
        return "Deny Session";
    case NOTIFY_DENY_ALWAYS:
        return "Deny Always";
    case NOTIFY_DENY:
        return "Deny";
    default:
        return "Unknown";
    }
}

/*
 * Sanitized, bounded copies of the requester fields, safe to place in a
 * dialog: control characters cannot forge extra lines.
 */
typedef struct
{
    char comm[64];
    char pcomm[64];
    char cmd[256];
    char exe[512];
    char path[512];
    char note[280]; /* hash-unavailable note; empty when the hash is known */
} PromptText;

/*
 * One menu prompt replaces the old two-stage button flow.  Every outcome
 * is an explicit row choice reported by kdialog on stdout; Cancel, window
 * close, timeouts, exec failures and every runtime error leave no token
 * and deny (see run_kdialog_menu).  The Deny Once row is preselected via
 * --default, so an accidental Enter denies this attempt; every grant
 * takes a deliberate row selection, and a persistent grant takes the
 * "Allow Always" row.
 */
int notify_ask(const NotifyRequest *req)
{
    /* Return values: NOTIFY_ALLOW_ONCE, NOTIFY_DENY,
     *                NOTIFY_ALLOW_SESSION, NOTIFY_DENY_SESSION,
     *                NOTIFY_ALLOW_ALWAYS, NOTIFY_DENY_ALWAYS. */
    if (!req)
        return NOTIFY_DENY;

    PromptText t;
    char msg[3072];
    char once_desc[96];
    char session_desc[96];
    char label_once[128];
    char label_session[128];
    char label_always[128];
    char label_deny[128];
    char label_deny_session[128];
    char label_deny_always[128];

    /* Attacker-controlled strings (file names, comm, cmdline) are
     * sanitized so control characters cannot forge dialog content. */
    sanitize_text(req->comm, t.comm, sizeof(t.comm));
    sanitize_text(req->comm_parent, t.pcomm, sizeof(t.pcomm));
    sanitize_ellipsized(req->exe && req->exe[0] != '\0' ? req->exe : "(unknown)",
                        t.exe, sizeof(t.exe));
    sanitize_ellipsized(req->path, t.path, sizeof(t.path));
    sanitize_ellipsized(req->cmdline && req->cmdline[0] != '\0'
                            ? req->cmdline
                            : "(unknown)",
                        t.cmd, sizeof(t.cmd));

    /* An unavailable digest cannot back a persistent grant: say so before
     * the user picks, and point at the deliberate escape hatch.  The
     * reason string is daemon-generated (sha512.c), never requester text. */
    t.note[0] = '\0';
    if (req->hash_unavailable)
        snprintf(t.note, sizeof(t.note),
                 "\nNote: the binary SHA-512 is unavailable (%s). \n"
                 "This means \"Allow Always\" cannot persist for this binary. "
                 "Add it to [unsafe_allowlist] in fileshield.conf if it needs a permanent grant.",
                 req->hash_failure && req->hash_failure[0] != '\0'
                     ? req->hash_failure
                     : "hashing failed");

    /* Concise per-scope descriptions, shared by the menu rows, the body
     * bullets and the plain fallback so the three can never drift. */
    if (req->user_ttl > 0)
        snprintf(once_desc, sizeof(once_desc),
                 "this file and process, cached %d seconds", req->user_ttl);
    else
        snprintf(once_desc, sizeof(once_desc), "this access only");

    if (req->session_ttl > 0)
        snprintf(session_desc, sizeof(session_desc),
                 "this binary and file, up to %d seconds", req->session_ttl);
    else
        snprintf(session_desc, sizeof(session_desc),
                 "this binary and file until the session ends");

    static const char always_desc[] =
        "saved permanently for this command and file";
    static const char deny_once_desc[] = "block this access only";
    static const char deny_session_desc[] =
        "block this binary and file until the session ends";
    static const char deny_always_desc[] =
        "block permanently for this command and file";

    snprintf(msg, sizeof(msg),
             "Process %s (PID %d, parent: %s (PID %d)) wants to read:\n"
             "Binary:   %s\n"
             "Command:  %s\n"
             "Path:     %s\n\n"
             "\xe2\x80\xa2 Allow Once: %s\n"
             "\xe2\x80\xa2 Allow Session: %s\n"
             "\xe2\x80\xa2 Allow Always: %s\n"
             "\xe2\x80\xa2 The Deny rows block with the same scopes.\n"
             "Cancelling or closing this dialog, or any failure, denies "
             "this attempt only.%s",
             t.comm, (int)req->pid, t.pcomm, (int)req->ppid,
             t.exe, t.cmd, t.path, once_desc, session_desc, always_desc,
             t.note);
    /* Auto-detect the active graphical session if env vars are not set.
     * The daemon itself is never modified: the session is applied by the
     * dialog child, per prompt. */
    DisplaySession session;
    int have_session = detect_display_session(req->user_uid, &session);
    log_msg(LOG_DEBUG,
            "[notify_ask] session: uid=%d wayland=%s display=%s",
            (int)session.uid,
            session.wayland_display[0] ? session.wayland_display : "(none)",
            session.display[0] ? session.display : "(none)");

    /* Never run a security prompt as a root GUI process. */
    if (getuid() == 0 && !have_session)
    {
        log_msg(LOG_ERR,
                "no non-root desktop session found; denying access to %s",
                t.path);
        return NOTIFY_DENY;
    }

    /* Forward the user's theme/font/scale/locale environment so kdialog
     * renders like the rest of their desktop. */
    DialogEnvSetting dialog_env[DIALOG_ENV_MAX];
    int dialog_env_count = collect_dialog_env(req->pid, dialog_env,
                                              DIALOG_ENV_MAX);
    log_msg(LOG_DEBUG, "[dialog] forwarding %d session variables",
            dialog_env_count);

    /* Menu rows repeat each scope's concise description inline (hyphen
     * separated), built from the same fragments as the body bullets so
     * the two can never drift. */
    snprintf(label_once, sizeof(label_once), "Allow Once - %s", once_desc);
    snprintf(label_session, sizeof(label_session), "Allow Session - %s",
             session_desc);
    snprintf(label_always, sizeof(label_always), "Allow Always - %s",
             always_desc);
    snprintf(label_deny, sizeof(label_deny), "Deny Once - %s",
             deny_once_desc);
    snprintf(label_deny_session, sizeof(label_deny_session),
             "Deny Session - %s", deny_session_desc);
    snprintf(label_deny_always, sizeof(label_deny_always),
             "Deny Always - %s", deny_always_desc);

    /* Tags are the wire contract with menu_token_to_decision(): labels
     * are for the user, tags are matched byte-for-byte after the prompt. */
    const DialogMenuItem items[] = {
        { "once",          label_once },
        { "session",       label_session },
        { "always",        label_always },
        { "deny",          label_deny },
        { "deny-session",  label_deny_session },
        { "deny-always",   label_deny_always },
    };

    /*
     * Styled rich-text body: left-aligned paragraphs, bold keys, the
     * protected path in larger monospace, bold scope names.  kdialog
     * renders the --menu label as rich text (Qt::AutoText QLabel), so
     * every interpolated value goes through html_escape first — after
     * sanitize_text removed control characters, < > & are the remaining
     * markup-injection channel and must not survive into the document.
     *
     * Any escape failure or snprintf truncation leaves `body` on the
     * plain msg built above: readable, unstyled, never half-markup.
     */
    /* Worst-case escape growth: 5 bytes per input byte ("&amp;"). */
    char e_comm[64 * 5 + 1];
    char e_pcomm[64 * 5 + 1];
    char e_exe[512 * 5 + 1];
    char e_cmd[256 * 5 + 1];
    char e_path[512 * 5 + 1];
    char e_note[280 * 5 + 1];
    char html[8192];
    const char *body = msg;
    int body_html = 0;

    if (html_escape(t.comm, e_comm, sizeof(e_comm)) == 0 &&
        html_escape(t.pcomm, e_pcomm, sizeof(e_pcomm)) == 0 &&
        html_escape(t.exe, e_exe, sizeof(e_exe)) == 0 &&
        html_escape(t.cmd, e_cmd, sizeof(e_cmd)) == 0 &&
        html_escape(t.path, e_path, sizeof(e_path)) == 0 &&
        html_escape(t.note, e_note, sizeof(e_note)) == 0)
    {
        /* Body bullets reuse the same shared descriptions as the rows. */
        char once_scope[192];
        char session_scope[192];

        snprintf(once_scope, sizeof(once_scope),
                 "\xe2\x80\xa2 <b>Allow Once</b> \xe2\x80\x94 %s<br>",
                 once_desc);
        snprintf(session_scope, sizeof(session_scope),
                 "\xe2\x80\xa2 <b>Allow Session</b> \xe2\x80\x94 %s<br>",
                 session_desc);

        char note_para[1450];

        if (e_note[0] != '\0')
            /* The note is daemon-generated but escaped like everything
             * else; its leading \n\n already became <br><br>. */
            snprintf(note_para, sizeof(note_para), "<p><i>%s</i></p>",
                     e_note);
        else
            note_para[0] = '\0';

        int need = snprintf(
            html, sizeof(html),
            "<div align=\"left\">"
            "<p><b>Process %s</b> (PID %d, parent: %s, PID %d) "
            "wants to read:</p>"
            "<p><b>Binary:</b> <tt>%s</tt><br>"
            "<b>Command:</b> <tt>%s</tt><br>"
            "<b>Path:</b> <tt>%s</tt></p>"
            "%s" /* note paragraph (empty when the hash is known) */
            "<p>%s"  /* once scope */
            "%s"     /* session scope */
            "\xe2\x80\xa2 <b>Allow Always</b> \xe2\x80\x94 %s<br>"
            "\xe2\x80\xa2 <b>Deny</b> rows block with the same scopes</p>"
            "<p><i>Cancelling or closing this dialog, or any failure, "
            "denies this attempt only.</i></p></div>",
            e_comm, (int)req->pid, e_pcomm, (int)req->ppid,
            e_exe, e_cmd, e_path, note_para, once_scope, session_scope,
            always_desc);

        /* Use the styled body only when it rendered completely; a
         * truncation keeps the plain fallback already pointed to. */
        if (need >= 0 && (size_t)need < sizeof(html))
        {
            body = html;
            body_html = 1;
        }
    }

    /* Hard-wrap the body to 80 columns so a long path, binary or command
     * line cannot widen the popup.  A wrap failure keeps the unwrapped
     * body: formatting is cosmetic and never changes the decision. */
    char wrapped[10240];

    if (wrap_dialog_text(body, wrapped, sizeof(wrapped), body_html) == 0)
        body = wrapped;
    else
        log_msg(LOG_WARNING,
                "dialog body could not be wrapped to %d columns; "
                "showing it unwrapped", DIALOG_TEXT_WIDTH);

    /* Run the menu, then re-vet the returned tag: a zero exit alone is
     * not a grant (empty and unknown tokens map to NOTIFY_DENY). */
    char token[DIALOG_TOKEN_MAX];
    int r = run_kdialog_menu(&session, dialog_env, dialog_env_count, body,
                             label_deny,
                             items, (int)(sizeof(items) / sizeof(items[0])),
                             token, sizeof(token));
    if (r != 1)
    {
        log_msg(LOG_WARNING,
                "[dialog] menu returned no selection (r=%d); denying "
                "(fail closed)", r);
        return NOTIFY_DENY;
    }

    int decision = menu_token_to_decision(token);
    log_msg(LOG_INFO, "[dialog] menu choice '%s' -> %s",
            token[0] != '\0' ? token : "(unknown)",
            notify_decision_name(decision));
    return decision;
}

/*
 * Prompt for a changed [allowlist] binary hash.  A two-row --menu
 * (Update & Allow first, Deny preselected): only the "update" tag on
 * kdialog's stdout with a zero exit code approves (the caller persists
 * new_hash and grants the access); Deny, window close, timeout, exec or
 * runtime failures leave no usable tag and deny this attempt with the
 * old pin kept.  The menu's positive stdout channel is what makes an
 * accidental Enter safe: the preselected deny row emits "deny", so
 * kdialog's message-box default-to-Yes behavior is not involved.  The
 * two-stage grant flow is deliberately not involved: the change already
 * names one rule, one binary and one file.
 *
 * Rate limiting is the caller's job (see notify.h): the pipeline must
 * reject dialog_rate_limited() binaries before calling so a tampered
 * binary cannot flood prompts.
 */
int notify_ask_hash_change(const NotifyHashChange *req)
{
    if (!req)
        return NOTIFY_DENY;

    char rule[512];
    char exe[512];
    char cmd[256];
    char path[512];
    char old_hash[64];
    char new_hash[64];

    /* Sanitized, bounded copies: even the rule pattern and the digests
     * are treated as untrusted so control characters cannot forge dialog
     * lines. */
    sanitize_text(req->rule_pattern, rule, sizeof(rule));
    sanitize_ellipsized(req->exe && req->exe[0] != '\0' ? req->exe : "(unknown)",
                        exe, sizeof(exe));
    sanitize_ellipsized(req->path, path, sizeof(path));
    sanitize_ellipsized(req->cmdline && req->cmdline[0] != '\0'
                            ? req->cmdline
                            : "(unknown)",
                        cmd, sizeof(cmd));
    sanitize_text(req->old_hash && req->old_hash[0] != '\0' ? req->old_hash
                                                            : "(unknown)",
                  old_hash, sizeof(old_hash));
    sanitize_text(req->new_hash && req->new_hash[0] != '\0' ? req->new_hash
                                                            : "(unknown)",
                  new_hash, sizeof(new_hash));

    /*
     * kdialog's --menu body renders as rich text (Qt::AutoText QLabel,
     * like notify_ask()'s body), so every interpolated value must arrive as
     * entities: sanitize_text() leaves '<', '>' and '&' alone, which a
     * crafted file name could otherwise use to inject markup into the
     * prompt itself.  Each escape buffer holds the worst case (5 bytes
     * per input byte: "&amp;") plus the NUL, exactly like the --menu
     * body.  body_text stays on the static fallback unless the whole
     * document rendered: a failed escape or a truncating snprintf must
     * never leave partial markup on screen, and the fallback contains
     * no interpolated value at all.
     */
    char e_rule[512 * 5 + 1];
    char e_exe[512 * 5 + 1];
    char e_cmd[256 * 5 + 1];
    char e_path[512 * 5 + 1];
    char e_old_hash[64 * 5 + 1];
    char e_new_hash[64 * 5 + 1];
    char body[16384];
    static const char fallback_body[] =
        "SHA-512 changed for an allowlist rule.\n\n"
        "Update & Allow trusts the new binary and records the new hash.\n"
        "Deny (or closing this dialog) blocks this attempt and keeps the "
        "old hash.";
    const char *body_text = fallback_body;

    if (html_escape(rule, e_rule, sizeof(e_rule)) == 0 &&
        html_escape(exe, e_exe, sizeof(e_exe)) == 0 &&
        html_escape(path, e_path, sizeof(e_path)) == 0 &&
        html_escape(cmd, e_cmd, sizeof(e_cmd)) == 0 &&
        html_escape(old_hash, e_old_hash, sizeof(e_old_hash)) == 0 &&
        html_escape(new_hash, e_new_hash, sizeof(e_new_hash)) == 0)
    {
        /* Full digests are journal-logged by the caller; the prompt
         * shows only the 16-hex prefixes a human can compare at a
         * glance. */
        int need = snprintf(body, sizeof(body),
                 "SHA-512 changed for allowlist rule:\n"
                 "%s\n\n"
                 "Binary:   %s\n"
                 "Target:   %s\n"
                 "Command:  %s\n\n"
                 "Old SHA-512: %.16s\xe2\x80\xa6\n"
                 "New SHA-512: %.16s\xe2\x80\xa6\n\n"
                 "Update & Allow trusts the new binary and records the new "
                 "hash.\n"
                 "Deny (or closing this dialog) blocks this attempt and "
                 "keeps the old hash.",
                 e_rule, e_exe, e_path, e_cmd, e_old_hash, e_new_hash);
        if (need >= 0 && (size_t)need < sizeof(body))
            body_text = body;
    }

    /* Hard-wrap the body to 80 columns exactly like notify_ask(), so a
     * long rule pattern or path cannot widen the popup.  A wrap failure
     * keeps the unwrapped body; formatting never changes the decision. */
    char wrapped[18432];

    if (wrap_dialog_text(body_text, wrapped, sizeof(wrapped),
                         body_text == body) == 0)
        body_text = wrapped;
    else
        log_msg(LOG_WARNING,
                "hash-change dialog body could not be wrapped to %d "
                "columns; showing it unwrapped", DIALOG_TEXT_WIDTH);

    DisplaySession session;
    int have_session = detect_display_session(req->user_uid, &session);
    log_msg(LOG_DEBUG,
            "[notify_hash_change] session: uid=%d wayland=%s display=%s",
            (int)session.uid,
            session.wayland_display[0] ? session.wayland_display : "(none)",
            session.display[0] ? session.display : "(none)");

    /* Never run a security prompt as a root GUI process. */
    if (getuid() == 0 && !have_session)
    {
        log_msg(LOG_ERR,
                "no non-root desktop session found; denying hash update "
                "for %s",
                exe);
        return NOTIFY_DENY;
    }

    /* Cosmetic session variables only, same whitelist as notify_ask(). */
    DialogEnvSetting dialog_env[DIALOG_ENV_MAX];
    int dialog_env_count = collect_dialog_env(req->pid, dialog_env,
                                              DIALOG_ENV_MAX);
    log_msg(LOG_DEBUG, "[dialog] forwarding %d session variables",
            dialog_env_count);

    /* Two-row menu, same positive stdout channel as the access prompt:
     * only the "update" tag grants; the deny row is preselected so an
     * accidental confirm emits "deny".  Every other outcome leaves no
     * usable tag and denies. */
    const DialogMenuItem items[] = {
        { "update", "Update & Allow" },
        { "deny", "Deny" },
    };
    char token[DIALOG_TOKEN_MAX];
    int r = run_kdialog_menu(&session, dialog_env, dialog_env_count, body_text,
                             "Deny", items,
                             (int)(sizeof(items) / sizeof(items[0])), token,
                             sizeof(token));
    /* Update tag only: a normal zero exit is not a grant by itself, and
     * the preselected "deny" row lands in the deny branch below. */
    if (r == 1 && strcmp(token, "update") == 0)
    {
        log_msg(LOG_WARNING,
                "hash change approved for allowlist rule %s (%s); "
                "new hash pinned by caller",
                rule, exe);
        return NOTIFY_ALLOW_ALWAYS;
    }

    log_msg(LOG_WARNING,
            "hash change denied for allowlist rule %s (%s, selection '%s'); "
            "old pin kept",
            rule, exe, token[0] != '\0' ? token : "(none)");
    return NOTIFY_DENY;
}

/* ------------------------------------------------------------------ */
/*  config-rule desktop notifications (notify-send)                    */
/* ------------------------------------------------------------------ */
/*
 * Bounded, spoof-proof tripwire for config-rule hits.  An attacker can
 * trigger these notifications, so flood control is mandatory: identical
 * (kind, binary, target) hits are deduplicated for the configured window,
 * and a global cap bounds a stream of distinct keys.  Both counters are
 * best-effort side channels, never inputs to the access decision.
 */
#define NOTIFY_DEDUP_MAX 128
/* Defensive fallback only: the effective cap comes from [settings] notify_max. */
#define NOTIFY_GLOBAL_MAX NOTIFY_MAX_DEFAULT
#define NOTIFY_GLOBAL_WINDOW_S 60
/*
 * A *successful* notify-send availability probe is cached for this many
 * seconds (one notification window, so a helper removed at runtime is
 * noticed on the first hit after the window).  A failed probe is never
 * cached: it re-runs on every hit so a re-installed helper is picked up
 * immediately.  access() is cheap and the probe never reaches a decision.
 */
#define NOTIFY_SEND_RECHECK_S 60
#define NOTIFY_SEND_PATH "/usr/bin/notify-send"

typedef struct
{
    int kind;
    char binary[PATH_MAX];
    char target[PATH_MAX];
    time_t last;
} NotifyDedupEntry;

static NotifyDedupEntry g_notify_dedup[NOTIFY_DEDUP_MAX];
static int g_notify_dedup_count = 0;
static int g_notify_dedup_next = 0;

static int g_notify_window_count = 0;
static time_t g_notify_window_start = 0;
static int g_notify_window_logged = 0;

static int g_notify_send_ok = 0;       /* last access() probe result       */
static int g_notify_send_logged = 0;   /* miss warning already emitted     */
static time_t g_notify_send_check = 0; /* mono_seconds() of the last probe */

/* 1 = this hit may be delivered (and is counted / remembered). */
static int notify_rate_allow(int kind, const char *binary, const char *target,
                             int dedup_seconds, int max_per_window)
{
    /* The project deadline clock: wall-clock steps must not extend the
     * dedup suppression of a security tripwire or reset the flood
     * budget early (mono_seconds, see utils.h). */
    time_t now = mono_seconds();
    int cap = max_per_window > 0 ? max_per_window : NOTIFY_GLOBAL_MAX;

    if (now - g_notify_window_start >= NOTIFY_GLOBAL_WINDOW_S)
    {
        g_notify_window_start = now;
        g_notify_window_count = 0;
        g_notify_window_logged = 0;
    }

    if (g_notify_window_count >= cap)
    {
        if (!g_notify_window_logged)
        {
            log_msg(LOG_WARNING,
                    "notification flood: more than %d in %ds; suppressing "
                    "further rule notifications for the window",
                    cap, NOTIFY_GLOBAL_WINDOW_S);
            g_notify_window_logged = 1;
        }
        return 0;
    }

    /*
     * Unsafe hits are gated once per process by the caller, so the
     * per-key window must not suppress a *different* process using the
     * same rule; the global cap below still bounds any burst.
     */
    if (kind != NOTIFY_HIT_UNSAFE && dedup_seconds > 0)
    {
        for (int i = 0; i < g_notify_dedup_count; i++)
        {
            NotifyDedupEntry *e = &g_notify_dedup[i];
            if (e->kind == kind && strcmp(e->binary, binary) == 0 &&
                strcmp(e->target, target) == 0)
            {
                if (now - e->last < dedup_seconds)
                    return 0;
                e->last = now;
                g_notify_window_count++;
                return 1;
            }
        }

        int slot;
        if (g_notify_dedup_count < NOTIFY_DEDUP_MAX)
            slot = g_notify_dedup_count++;
        else
        {
            slot = g_notify_dedup_next;
            g_notify_dedup_next = (g_notify_dedup_next + 1) % NOTIFY_DEDUP_MAX;
        }
        NotifyDedupEntry *e = &g_notify_dedup[slot];
        memset(e, 0, sizeof(*e));
        e->kind = kind;
        snprintf(e->binary, sizeof(e->binary), "%s", binary);
        snprintf(e->target, sizeof(e->target), "%s", target);
        e->last = now;
    }

    g_notify_window_count++;
    return 1;
}

/*
 * Availability check for notify-send, cached only briefly.  A missing
 * helper must not spend the dedup or flood budget on notifications that
 * can never be shown; the "not found" warning is emitted once per
 * missing episode.  A success is trusted for NOTIFY_SEND_RECHECK_S, so
 * a helper removed at runtime is detected (and logged once) on the next
 * hit after the window; a failure is re-probed every hit, so a
 * re-installed helper is picked up immediately.  The probe is
 * best-effort only and never influences an access decision.
 */
static int notify_send_available(void)
{
    time_t now = mono_seconds();

    if (g_notify_send_ok && now - g_notify_send_check < NOTIFY_SEND_RECHECK_S)
        return 1;

    g_notify_send_ok = access(NOTIFY_SEND_PATH, X_OK) == 0;
    g_notify_send_check = now;

    if (!g_notify_send_ok)
    {
        if (!g_notify_send_logged)
        {
            g_notify_send_logged = 1;
            log_msg(LOG_WARNING,
                    "notify_rule_hit: %s not found; rule notifications "
                    "disabled (see README)",
                    NOTIFY_SEND_PATH);
        }
    }
    else
        g_notify_send_logged = 0; /* re-arm for a later removal */
    return g_notify_send_ok;
}

/*
 * Build the notification text for one rule hit: sanitized fields plus
 * the title, urgency and icon selected by the hit kind.  notify-send
 * only knows low/normal/critical urgency, so an unsafe hit is normal
 * urgency with the warning icon: it stands out without the persistence
 * of a critical notification.
 */
static void build_hit_notification(const NotifyHit *hit, char *title,
                                   size_t titlesz, char *body, size_t bodysz,
                                   const char **urgency, const char **icon)
{
    char rule[512], bin[512], comm[64], target[512];

    /* Per-field sanitation: newlines inside fields must not forge lines. */
    sanitize_text(hit->rule ? hit->rule : "(unknown)", rule, sizeof(rule));
    sanitize_text(hit->binary ? hit->binary : "(unknown)", bin, sizeof(bin));
    sanitize_text(hit->comm ? hit->comm : "", comm, sizeof(comm));
    sanitize_text(hit->target ? hit->target : "(unknown)", target,
                  sizeof(target));

    if (hit->kind == NOTIFY_HIT_UNSAFE)
    {
        snprintf(title, titlesz, "Fileshield: unsafe allowlist rule used");
        *urgency = "normal";
        *icon = "dialog-warning";
    }
    else if (hit->kind == NOTIFY_HIT_DENY)
    {
        snprintf(title, titlesz, "Fileshield: denylist blocked an access");
        *urgency = "critical";
        *icon = "security-high";
    }
    else
    {
        snprintf(title, titlesz, "Fileshield: allowlist rule used");
        *urgency = "normal";
        *icon = "dialog-information";
    }

    snprintf(body, bodysz,
             "rule:   %s\nbinary: %s (pid %d%s%s)\ntarget: %s",
             rule, bin, (int)hit->pid, comm[0] != '\0' ? ", " : "", comm,
             target);
}

/*
 * Deliver a notification through notify-send from a double-forked
 * grandchild reparented to init: the daemon reaps only the intermediate,
 * with a bounded wait so the event loop never stalls.  The grandchild's
 * exec failure is deliberately unobservable (fire-and-forget); a 127
 * observed here is the intermediate's own fork failure, so the
 * availability flag is dropped to force an immediate re-probe on the
 * next hit.
 */
static void spawn_notify_send(const DisplaySession *session,
                              const char *title, const char *body,
                              const char *urgency, const char *icon)
{
    pid_t pid = fork();
    if (pid < 0)
    {
        log_msg(LOG_WARNING, "notify_rule_hit: fork failed: %m");
        return;
    }

    if (pid == 0)
    {
        pid_t g = fork();
        if (g < 0)
            _exit(127);
        if (g > 0)
            _exit(0);

        setsid();
        drop_to_session_user(session);
        apply_display_env(session);
        close_fds_from(3);
        execl(NOTIFY_SEND_PATH, "notify-send", "-a", "Fileshield",
              "-u", urgency, "-i", icon, title, body, (char *)NULL);
        _exit(127);
    }

    /* Bounded reap: the intermediate exits immediately in practice, but
     * the single-threaded event loop must never block on it. */
    int st = 0;
    int reaped = 0;
    for (int i = 0; i < 100; i++) /* up to ~1 s */
    {
        pid_t w = waitpid(pid, &st, WNOHANG);
        if (w == pid)
        {
            reaped = 1;
            break;
        }
        if (w < 0 && errno != EINTR)
        {
            log_msg(LOG_WARNING, "notify_rule_hit: waitpid: %m");
            return;
        }
        usleep(10000);
    }
    if (!reaped)
    {
        log_msg(LOG_WARNING,
                "notify_rule_hit: intermediate %d did not exit; killing it",
                (int)pid);
        kill(pid, SIGKILL);
        while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
            ;
    }
    /*
     * The intermediate exits 0 as soon as it has forked the helper, so
     * the only 127 observable here is its own fork() failure — a
     * transient condition, NOT "notify-send is gone": the helper's exec
     * failure happens in the reparented grandchild and is deliberately
     * unobservable (fire-and-forget).  A genuinely missing helper is
     * caught by notify_send_available()'s access() probe within its
     * recheck window.  Reset the cached success anyway so the next hit
     * re-probes before spending another fork pair.
     */
    if (WIFEXITED(st) && WEXITSTATUS(st) == 127)
        g_notify_send_ok = 0;
}

/*
 * Fire-and-forget notification for one config-rule hit.  Availability
 * and deliverability are checked before the rate budget (a missing
 * helper or a desktop-less uid must not consume the shared cap);
 * failures are logged and never affect the decision.
 */
void notify_rule_hit(const NotifyHit *hit)
{
    if (!hit || hit->uid == (uid_t)-1 || hit->uid == 0)
        return;

    /* Availability first: a missing notify-send must not spend the
     * dedup or flood budget on notifications that are never shown. */
    if (!notify_send_available())
        return;

    /* Deliverability before budget: a uid with no desktop session must
     * not spend the dedup or flood budget (the global cap is shared by
     * every user) on notifications that are never shown. */
    DisplaySession session;
    if (!detect_display_session(hit->uid, &session))
    {
        log_msg(LOG_DEBUG,
                "notify_rule_hit: no desktop session for uid %d; "
                "notification skipped",
                (int)hit->uid);
        return;
    }

    if (!notify_rate_allow(hit->kind, hit->binary ? hit->binary : "",
                           hit->target ? hit->target : "",
                           hit->dedup_seconds, hit->max_per_window))
        return;

    char title[128];
    char body[2048];
    const char *urgency = "";
    const char *icon = "";
    build_hit_notification(hit, title, sizeof(title), body, sizeof(body),
                           &urgency, &icon);
    spawn_notify_send(&session, title, body, urgency, icon);
}

int notify_test_hit_rate(int kind, const char *binary, const char *target,
                         int dedup_seconds, int max_per_window)
{
    return notify_rate_allow(kind, binary ? binary : "",
                             target ? target : "", dedup_seconds,
                             max_per_window);
}

void notify_test_reset_rate(void)
{
    memset(g_notify_dedup, 0, sizeof(g_notify_dedup));
    g_notify_dedup_count = 0;
    g_notify_dedup_next = 0;
    g_notify_window_count = 0;
    g_notify_window_start = 0;
    g_notify_window_logged = 0;
}
