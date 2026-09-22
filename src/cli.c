/*
 * cli.c - fileshield-cli: manage the daemon's runtime allow/deny rules,
 * [allowlist] hash pins and live session decisions.
 *
 * Read paths are deliberately daemon-free: list/describe parse the
 * root-only JSON state files directly, so they work while the daemon is
 * stopped.  Every mutation (remove/clear/prune, session commands) goes
 * through the control socket so the daemon's in-memory lists and the
 * files change together; the direct-file fallback exists only for a
 * stopped daemon (ENOENT/ECONNREFUSED), where there is no writer to race.
 * Session rules live only in daemon memory, so session commands have no
 * fallback.  See control_client.h for the wire protocol.
 */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cli_ui.h"
#include "control_client.h"
#include "persist.h"
#include "pin.h"
#include "prune.h"
#include "ruleid.h"

#define CLI_VERSION "0.1.0"

/*
 * `session list` can show both 256-entry tables at once.  A payload line
 * is worst-case binary+target each escaped sixfold (a path of raw
 * control bytes), so one generous buffer sized for the full 512-record,
 * all-control-bytes case replaces a growable read.
 */
#define CLI_SESSION_MAX (2 * CONTROL_PAYLOAD_MAX)
#define CLI_RESP_MAX (CLI_SESSION_MAX * (6 * 2 * PATH_MAX + 512))

static int g_yes;  /* -y/--yes: skip confirmations */
static int g_wide; /* --wide: no binary/args/target truncation */
static int g_dry;  /* -n/--dry-run: prune lists only */
static int g_json; /* --json: machine-readable list/describe */

#ifdef FILESHIELD_TEST_CLI
/* Test-only state-file redirect (cli_test_set_state_files): both paths
 * must be set together so rule_path() never mixes a temp allow file with
 * the real deny file.  Production builds strip this block entirely. */
static char g_test_allow_path[PATH_MAX];
static char g_test_deny_path[PATH_MAX];

void cli_test_set_state_files(const char *allow, const char *deny)
{
    g_test_allow_path[0] = '\0';
    g_test_deny_path[0] = '\0';
    if (!allow || allow[0] == '\0' || !deny || deny[0] == '\0')
        return;
    if (strlen(allow) >= sizeof(g_test_allow_path) ||
        strlen(deny) >= sizeof(g_test_deny_path))
        return;
    memcpy(g_test_allow_path, allow, strlen(allow) + 1);
    memcpy(g_test_deny_path, deny, strlen(deny) + 1);
}
#endif /* FILESHIELD_TEST_CLI */

/* Allocated on first socket use so read-only commands never pay for it. */
static char *g_resp_buf;

/* argv[0], so per-command usage hints name the same binary as the help. */
static const char *g_prog = "fileshield-cli";

/* ------------------------------------------------------------------ */
/*  small helpers                                                      */
/* ------------------------------------------------------------------ */

static void print_usage(FILE *f, const char *prog)
{
    fprintf(f,
            "Usage: %s [OPTIONS] <command> [args]\n"
            "\n"
            "Commands:\n"
            "  list [rules|allow|deny|pins]     list entries (default: all)\n"
            "  describe allow|deny|pin [ID]     full description (all when no ID)\n"
            "  remove allow|deny|pin <ID>...    remove entries by ID\n"
            "  clear allow|deny|pins            remove every entry\n"
            "  prune [allow|deny]               remove stale duplicate rules\n"
            "  session list [allow|deny]        show live session rules\n"
            "  session describe [allow|deny] [ID]\n"
            "  session remove [allow|deny] <ID>...\n"
            "  session clear [allow|deny]       clear session rules\n"
            "  reload                           ask the daemon to reload\n"
            "\n"
            "Options:\n"
            "  -y, --yes     assume yes for every confirmation\n"
            "  -n, --dry-run prune: list what would be removed, change nothing\n"
            "      --wide    show full binary/args/target and 16-char IDs\n"
            "      --json    machine-readable output for list/describe\n"
            "  -h, --help    show this help\n"
            "  -v, --version show the version\n"
            "\n"
            "IDs are the first 8+ hex characters of an entry's rule ID.\n",
            prog);
}

/* One concrete command line under an error message, so a usage mistake
 * shows what to type next instead of only what went wrong. */
static void usage_hint(const char *syntax)
{
    fprintf(stderr, "usage: %s %s\n", g_prog, syntax);
}

/*
 * Ambiguous ID prefix (or duplicate full IDs in a hand-edited file): no
 * action is taken anywhere this is called.  An abbreviated prefix gets
 * told to use the full ID; a full-length collision cannot be split this
 * way and says so.
 */
static void print_ambiguous(const char *kind, const char *input)
{
    if (!input)
    {
        fprintf(stderr,
                "error: the ID matches more than one %s; use the full "
                "%d-character ID to differentiate\n",
                kind, RULEID_HEX_LEN);
        return;
    }
    if (strlen(input) >= RULEID_HEX_LEN)
    {
        fprintf(stderr,
                "error: %s matches more than one %s even at full length "
                "(duplicate stored IDs); nothing changed\n",
                input, kind);
        return;
    }
    fprintf(stderr,
            "error: %s matches more than one %s; use the full %d-character "
            "ID to differentiate\n",
            input, kind, RULEID_HEX_LEN);
}

/*
 * Translate a resolve_*() result into the user-facing error.  Returns 0
 * when the ID resolved to exactly one record, -1 otherwise, so callers
 * can `if (report_resolve(kind, input, rc) < 0) ...`.
 */
static int report_resolve(const char *kind, const char *input, int rc)
{
    switch (rc)
    {
    case 1:
        return 0;
    case 0:
        fprintf(stderr, "error: no %s matches %s\n", kind, input);
        break;
    case -2:
        print_ambiguous(kind, input);
        break;
    default:
        fprintf(stderr, "error: invalid %s ID: %s\n", kind, input);
        break;
    }
    return -1;
}

static const char *rule_path(int deny)
{
#ifdef FILESHIELD_TEST_CLI
    /* Test-only redirect so suite cases open a temp file, never
     * /var/lib/fileshield.  NULL/empty on either side clears both. */
    if (g_test_allow_path[0] != '\0' && g_test_deny_path[0] != '\0')
        return deny ? g_test_deny_path : g_test_allow_path;
#endif
    return deny ? PERSIST_DENY_STATE_FILE : PERSIST_STATE_FILE;
}

static const char *rule_label(int deny)
{
    return deny ? "deny" : "allow";
}

static const char *session_label(int deny)
{
    return deny ? "deny" : "allow";
}

/*
 * Parse an "allow"/"deny" argument.  Returns 0 for allow, 1 for deny, -2
 * when the token is not a list name, and -1 for NULL ("not given"; the
 * caller decides the default).  Every caller only tests for < 0.
 */
static int parse_list(const char *arg)
{
    if (!arg)
        return -1;
    if (strcmp(arg, "allow") == 0)
        return 0;
    if (strcmp(arg, "deny") == 0)
        return 1;
    return -2;
}

/* ------------------------------------------------------------------ */
/*  state-file loading                                                 */
/* ------------------------------------------------------------------ */

static int load_entries(int deny, PersistEntry **out, int *count_out)
{
    const char *path = rule_path(deny);
    PersistEntry *entries = calloc(PERSIST_MAX_ENTRIES, sizeof(*entries));

    if (!entries)
    {
        fprintf(stderr, "error: out of memory reading %s\n", path);
        return -1;
    }
    int count = persist_load(path, entries, PERSIST_MAX_ENTRIES);
    if (count < 0)
    {
        fprintf(stderr, "error: %s is damaged or unreadable (fail closed)\n",
                path);
        free(entries);
        return -1;
    }
    *out = entries;
    *count_out = count;
    return 0;
}

static int load_pins(PinRecord **out, int *count_out)
{
    PinRecord *rows = calloc(PIN_MAX, sizeof(*rows));
    int damaged = 0;

    if (!rows)
    {
        fprintf(stderr, "error: out of memory reading %s\n", PIN_STATE_FILE);
        return -1;
    }
    int count = pin_load_file(PIN_STATE_FILE, rows, PIN_MAX, &damaged);
    if (count < 0)
    {
        fprintf(stderr, "error: %s is damaged or unreadable (fail closed)\n",
                PIN_STATE_FILE);
        free(rows);
        return -1;
    }
    *out = rows;
    *count_out = count;
    return 0;
}

/*
 * persist_load() rejects an entry whose stored rule_id is present but
 * empty, so a direct-file fallback write must never emit one.  A file
 * written before the rule-ID upgrade holds empty IDs until the daemon
 * migrates it at load; the CLI cannot invent matching IDs (the daemon's
 * nonce assignment depends on its own list state), so the fallback
 * refuses and tells the user to start the daemon once instead of
 * silently dropping every survivor on the next load.
 */
static int entries_all_have_ids(const PersistEntry *entries, int count)
{
    for (int i = 0; i < count; i++)
    {
        if (entries[i].rule_id[0] == '\0')
            return 0;
    }
    return 1;
}

static void refuse_legacy_write(int deny)
{
    fprintf(stderr,
            "error: %s holds entries without rule IDs; start fileshield "
            "once to migrate them, then retry\n",
            rule_path(deny));
}

/* ------------------------------------------------------------------ */
/*  ID resolution                                                      */
/* ------------------------------------------------------------------ */

/*
 * Prefix-resolve 'input' against entries' stored rule IDs.  Returns 1
 * with *idx_out set, 0 for no match, -2 for an ambiguous prefix, -1 for
 * an invalid prefix.  Empty stored IDs (legacy, not yet migrated by the
 * daemon) never match.
 */
static int resolve_rule(const PersistEntry *entries, int count,
                        const char *input, int *idx_out)
{
    int found = -1;
    int matches = 0;

    /* Probe with a known-valid ID so a short/non-hex prefix is reported
     * as invalid even against an empty list. */
    if (ruleid_prefix_match("0000000000000000", input) < 0)
        return -1;

    for (int i = 0; i < count; i++)
    {
        if (entries[i].rule_id[0] == '\0')
            continue;
        if (ruleid_prefix_match(entries[i].rule_id, input) == 1)
        {
            found = i;
            matches++;
        }
    }
    if (matches == 0)
        return 0;
    if (matches > 1)
        return -2;
    *idx_out = found;
    return 1;
}

/*
 * Prefix-resolve against pattern-derived pin IDs.  full_id (optional)
 * receives the matched entry's ID for later socket requests; callers
 * that only need the index pass NULL.
 */
static int resolve_pin(const PinRecord *rows, int count, const char *input,
                       int *idx_out, char full_id[RULEID_HEX_LEN + 1])
{
    int found = -1;
    int matches = 0;

    /* Probe with a known-valid ID so an invalid prefix is reported even
     * against an empty table (same trick as resolve_rule). */
    if (ruleid_prefix_match("0000000000000000", input) < 0)
        return -1;

    for (int i = 0; i < count; i++)
    {
        char id[RULEID_HEX_LEN + 1];

        if (ruleid_pin(rows[i].pattern, id) < 0)
            continue; /* unhashable pattern: never a candidate */
        if (ruleid_prefix_match(id, input) == 1)
        {
            found = i;
            matches++;
            if (full_id)
                memcpy(full_id, id, sizeof(id));
        }
    }
    if (matches == 0)
        return 0;
    if (matches > 1)
        return -2;
    *idx_out = found;
    return 1;
}

/*
 * Resolve every ID argument before any action is taken, storing the
 * entry index and its full stored ID for the socket request.  Returns 0
 * only when all inputs resolved to exactly one record.
 */
static int resolve_rule_set(const PersistEntry *entries, int count,
                            char *const *inputs, int n, int *indices,
                            char (*full)[RULEID_HEX_LEN + 1])
{
    for (int i = 0; i < n; i++)
    {
        int rc = resolve_rule(entries, count, inputs[i], &indices[i]);

        if (report_resolve("rule", inputs[i], rc) < 0)
            return -1;
        memcpy(full[i], entries[indices[i]].rule_id, RULEID_HEX_LEN + 1);
    }
    return 0;
}

static int resolve_pin_set(const PinRecord *rows, int count,
                           char *const *inputs, int n, int *indices,
                           char (*full)[RULEID_HEX_LEN + 1])
{
    for (int i = 0; i < n; i++)
    {
        int rc = resolve_pin(rows, count, inputs[i], &indices[i], full[i]);

        if (report_resolve("pin", inputs[i], rc) < 0)
            return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  control socket                                                     */
/* ------------------------------------------------------------------ */

/*
 * Send one request.  Returns 0 with *resp populated on OK, 1 when no
 * daemon answered (ENOENT/ECONNREFUSED, the only fallback case), -1 on
 * any other failure (message already printed).
 */
static int ctl_call(const char *request, ControlResponse *resp)
{
    if (!g_resp_buf)
    {
        g_resp_buf = malloc(CLI_RESP_MAX);
        if (!g_resp_buf)
        {
            fprintf(stderr, "error: out of memory\n");
            return -1;
        }
    }

    int rc = control_client_call(CONTROL_SOCKET_PATH, request, g_resp_buf,
                                 CLI_RESP_MAX, resp);
    if (rc < 0)
    {
        if (errno == ENOENT || errno == ECONNREFUSED)
            return 1;
        fprintf(stderr, "error: cannot reach the fileshield daemon at %s: %s\n",
                CONTROL_SOCKET_PATH, strerror(errno));
        return -1;
    }
    if (!resp->ok)
    {
        fprintf(stderr, "error: daemon refused: %s\n",
                resp->message ? resp->message : "(no message)");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  list                                                               */
/* ------------------------------------------------------------------ */

static void build_rule_rows(PersistEntry *allow, int na, PersistEntry *deny,
                            int nd, CliRuleRow *rows, int *n_out)
{
    int n = 0;

    for (int i = 0; i < na; i++)
    {
        rows[n].is_deny = 0;
        rows[n].entry = &allow[i];
        snprintf(rows[n].id, sizeof(rows[n].id), "%s",
                 allow[i].rule_id[0] ? allow[i].rule_id : "(none)");
        n++;
    }
    for (int i = 0; i < nd; i++)
    {
        rows[n].is_deny = 1;
        rows[n].entry = &deny[i];
        snprintf(rows[n].id, sizeof(rows[n].id), "%s",
                 deny[i].rule_id[0] ? deny[i].rule_id : "(none)");
        n++;
    }

    /* Oldest creation first; insertion sort keeps equal timestamps in
     * list order (allow before deny for a tie, stable by construction). */
    for (int i = 1; i < n; i++)
    {
        CliRuleRow key = rows[i];
        int j = i - 1;

        while (j >= 0 &&
               (long long)rows[j].entry->created_at >
                   (long long)key.entry->created_at)
        {
            rows[j + 1] = rows[j];
            j--;
        }
        rows[j + 1] = key;
    }
    *n_out = n;
}

static void build_pin_rows(const PinRecord *pins, int np, CliPinRow *rows,
                           int *n_out)
{
    int n = 0;

    for (int i = 0; i < np; i++)
    {
        char id[RULEID_HEX_LEN + 1];

        if (ruleid_pin(pins[i].pattern, id) < 0)
            snprintf(id, sizeof(id), "%s", "(none)");
        snprintf(rows[n].id, sizeof(rows[n].id), "%s", id);
        rows[n].pattern = pins[i].pattern;
        rows[n].sha512 = pins[i].sha512;
        rows[n].updated_at = pins[i].updated_at;
        n++;
    }
    for (int i = 1; i < n; i++)
    {
        CliPinRow key = rows[i];
        int j = i - 1;

        while (j >= 0 && rows[j].updated_at > key.updated_at)
        {
            rows[j + 1] = rows[j];
            j--;
        }
        rows[j + 1] = key;
    }
    *n_out = n;
}

static int cmd_list(const char *filter)
{
    int want_allow = 1, want_deny = 1, want_pins = 1;
    unsigned sections;

    if (filter)
    {
        if (strcmp(filter, "rules") == 0)
            want_pins = 0;
        else if (strcmp(filter, "allow") == 0)
            want_deny = want_pins = 0;
        else if (strcmp(filter, "deny") == 0)
            want_allow = want_pins = 0;
        else if (strcmp(filter, "pins") == 0)
            want_allow = want_deny = 0;
        else
        {
            fprintf(stderr, "error: unknown list filter: %s "
                            "(expected rules|allow|deny|pins)\n", filter);
            usage_hint("list [rules|allow|deny|pins]");
            return 2;
        }
    }

    /* Load only the requested sections; a damaged or unreadable state
     * file aborts the whole listing (fail closed, never "empty"). */
    PersistEntry *allow = NULL, *deny = NULL;
    PinRecord *pins = NULL;
    int na = 0, nd = 0, np = 0;
    /* Sticky failure flag: a failed load or allocation skips rendering but
     * must still flow through the single cleanup path below. */
    int rc = 0;

    if (want_allow && load_entries(0, &allow, &na) < 0)
        rc = -1;
    if (rc == 0 && want_deny && load_entries(1, &deny, &nd) < 0)
        rc = -1;
    if (rc == 0 && want_pins && load_pins(&pins, &np) < 0)
        rc = -1;
    if (rc < 0)
    {
        free(allow);
        free(deny);
        free(pins);
        return 1;
    }

    sections = (want_allow ? CLI_UI_SECTION_ALLOW : 0u) |
               (want_deny ? CLI_UI_SECTION_DENY : 0u) |
               (want_pins ? CLI_UI_SECTION_PINS : 0u);

    /* Display rows borrow the loaded records; build_*_rows also applies
     * the documented ordering (rules by created_at, pins by updated_at). */
    CliRuleRow *rule_rows = NULL;
    CliPinRow *pin_rows = NULL;
    int n_rules = 0, n_pins = 0;

    if (want_allow || want_deny)
    {
        /* +1 keeps the allocation nonzero when both lists are empty, so
         * an empty table is never mistaken for an allocation failure. */
        rule_rows = calloc((size_t)(na + nd) + 1, sizeof(*rule_rows));
        if (!rule_rows)
        {
            fprintf(stderr, "error: out of memory\n");
            rc = -1;
        }
        else
            build_rule_rows(allow, na, deny, nd, rule_rows, &n_rules);
    }
    if (rc == 0 && want_pins)
    {
        pin_rows = calloc((size_t)np + 1, sizeof(*pin_rows));
        if (!pin_rows)
        {
            fprintf(stderr, "error: out of memory\n");
            rc = -1;
        }
        else
            build_pin_rows(pins, np, pin_rows, &n_pins);
    }

    /* All shaping of stored fields (control bytes -> '?', tail truncation,
     * JSON escaping) happens inside the cli_ui renderers; cli.c only hands
     * over the loaded records. */
    if (rc == 0 && g_json)
    {
        cli_ui_render_list_json(stdout, sections, rule_rows, n_rules,
                                pin_rows, n_pins, NULL, 0, time(NULL));
    }
    else if (rc == 0)
    {
        int rules_shown = want_allow || want_deny;

        /* Human output: rules table, blank line, pins table, totals. */

        if (rules_shown)
            cli_ui_render_rules(stdout, rule_rows, n_rules,
                                cli_ui_terminal_width(stdout), g_wide);
        if (rules_shown && want_pins)
            fputc('\n', stdout); /* visually split the two tables */
        if (want_pins)
            cli_ui_render_pins(stdout, pin_rows, n_pins,
                               cli_ui_terminal_width(stdout), g_wide);
        cli_ui_render_totals(stdout, na, nd, np, sections);
    }

    free(rule_rows);
    free(pin_rows);
    free(allow);
    free(deny);
    free(pins);
    return rc < 0 ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/*  describe                                                           */
/* ------------------------------------------------------------------ */

/* `describe pin [ID]`: one record, or every pin when input is NULL. */
static int describe_pins(const char *input)
{
    PinRecord *pins = NULL;
    int np = 0;

    if (load_pins(&pins, &np) < 0)
        return 1;

    if (!input)
    {
        /* Same oldest-updated-first order as `list pins`. */
        CliPinRow *rows = calloc((size_t)np + 1, sizeof(*rows));
        int nr = 0;

        if (!rows)
        {
            fprintf(stderr, "error: out of memory\n");
            free(pins);
            return 1;
        }
        build_pin_rows(pins, np, rows, &nr);
        if (g_json)
            cli_ui_render_list_json(stdout, CLI_UI_SECTION_PINS, NULL, 0,
                                    rows, nr, NULL, 0, time(NULL));
        else
            for (int i = 0; i < nr; i++)
            {
                if (i > 0)
                    putchar('\n');
                cli_ui_render_pin_describe(stdout, &rows[i]);
            }
        free(rows);
        free(pins);
        return 0;
    }

    int idx = -1;
    if (report_resolve("pin", input, resolve_pin(pins, np, input, &idx,
                                                 NULL)) < 0)
    {
        free(pins);
        return 1;
    }

    CliPinRow row;
    if (ruleid_pin(pins[idx].pattern, row.id) < 0)
        snprintf(row.id, sizeof(row.id), "%s", "(none)");
    row.pattern = pins[idx].pattern;
    row.sha512 = pins[idx].sha512;
    row.updated_at = pins[idx].updated_at;
    if (g_json)
        cli_ui_render_pin_describe_json(stdout, &row);
    else
        cli_ui_render_pin_describe(stdout, &row);
    free(pins);
    return 0;
}

/* `describe allow|deny [ID]`: one rule, or every rule of that list. */
static int describe_rules(int deny, const char *input)
{
    PersistEntry *entries = NULL;
    int count = 0;

    if (load_entries(deny, &entries, &count) < 0)
        return 1;

    if (!input)
    {
        /* Same oldest-created-first order as `list`, one block per rule. */
        CliRuleRow *rows = calloc((size_t)count + 1, sizeof(*rows));
        int nr = 0;

        if (!rows)
        {
            fprintf(stderr, "error: out of memory\n");
            free(entries);
            return 1;
        }
        if (deny)
            build_rule_rows(NULL, 0, entries, count, rows, &nr);
        else
            build_rule_rows(entries, count, NULL, 0, rows, &nr);
        if (g_json)
            cli_ui_render_list_json(stdout,
                                    deny ? CLI_UI_SECTION_DENY
                                         : CLI_UI_SECTION_ALLOW,
                                    rows, nr, NULL, 0, NULL, 0, time(NULL));
        else
            for (int i = 0; i < nr; i++)
            {
                if (i > 0)
                    putchar('\n');
                cli_ui_render_rule_describe(stdout, &rows[i]);
            }
        free(rows);
        free(entries);
        return 0;
    }

    int idx = -1;
    if (report_resolve("rule", input, resolve_rule(entries, count, input,
                                                   &idx)) < 0)
    {
        free(entries);
        return 1;
    }

    CliRuleRow row;
    row.is_deny = deny;
    row.entry = &entries[idx];
    snprintf(row.id, sizeof(row.id), "%s",
             entries[idx].rule_id[0] ? entries[idx].rule_id : "(none)");
    if (g_json)
        cli_ui_render_rule_describe_json(stdout, &row);
    else
        cli_ui_render_rule_describe(stdout, &row);
    free(entries);
    return 0;
}

static int cmd_describe(const char *kind, const char *input)
{
    if (strcmp(kind, "pin") == 0)
        return describe_pins(input);

    int deny = parse_list(kind);
    if (deny < 0)
    {
        fprintf(stderr, "error: unknown describe type: %s "
                        "(expected allow|deny|pin)\n", kind);
        usage_hint("describe allow|deny|pin [ID]");
        return 2;
    }
    return describe_rules(deny, input);
}

/* ------------------------------------------------------------------ */
/*  remove                                                             */
/* ------------------------------------------------------------------ */

/* Drop duplicates from the resolved sets so a repeated argument cannot
 * produce a half-applied request. */
static int dedupe_full_ids(char (*full)[RULEID_HEX_LEN + 1], int *indices,
                           int n)
{
    int w = 0;

    for (int i = 0; i < n; i++)
    {
        int seen = 0;

        for (int j = 0; j < w; j++)
        {
            if (strcmp(full[j], full[i]) == 0)
            {
                seen = 1;
                break;
            }
        }
        if (seen)
            continue;
        if (w != i)
        {
            memcpy(full[w], full[i], RULEID_HEX_LEN + 1);
            indices[w] = indices[i];
        }
        w++;
    }
    return w;
}

static int fallback_remove_rules(int deny,
                                 const char (*full)[RULEID_HEX_LEN + 1], int n)
{
    const char *path = rule_path(deny);
    PersistEntry *entries = NULL;
    int count = 0, w = 0;

    if (load_entries(deny, &entries, &count) < 0)
        return -1;
    for (int i = 0; i < count; i++)
    {
        int drop = 0;

        for (int j = 0; j < n; j++)
        {
            if (entries[i].rule_id[0] != '\0' &&
                strcmp(entries[i].rule_id, full[j]) == 0)
            {
                drop = 1;
                break;
            }
        }
        if (!drop)
        {
            if (w != i)
                entries[w] = entries[i];
            w++;
        }
    }
    if (!entries_all_have_ids(entries, w))
    {
        refuse_legacy_write(deny);
        free(entries);
        return -1;
    }
    int rc = persist_save(path, entries, w);
    free(entries);
    if (rc < 0)
    {
        fprintf(stderr, "error: failed to write %s\n", path);
        return -1;
    }
    fprintf(stderr, "warning: daemon not running; applied directly to %s "
                    "(start fileshield to enforce)\n", path);
    return 0;
}

static int fallback_remove_pins(const char (*full)[RULEID_HEX_LEN + 1], int n)
{
    PinRecord *rows = NULL;
    int count = 0, w = 0;

    if (load_pins(&rows, &count) < 0)
        return -1;
    for (int i = 0; i < count; i++)
    {
        char id[RULEID_HEX_LEN + 1];
        int drop = 0;

        if (ruleid_pin(rows[i].pattern, id) == 0)
        {
            for (int j = 0; j < n; j++)
            {
                if (strcmp(id, full[j]) == 0)
                {
                    drop = 1;
                    break;
                }
            }
        }
        if (!drop)
        {
            if (w != i)
                rows[w] = rows[i];
            w++;
        }
    }
    int rc = pin_write_file(PIN_STATE_FILE, rows, w);
    free(rows);
    if (rc < 0)
    {
        fprintf(stderr, "error: failed to write %s\n", PIN_STATE_FILE);
        return -1;
    }
    fprintf(stderr, "warning: daemon not running; applied directly to %s "
                    "(start fileshield to enforce)\n", PIN_STATE_FILE);
    return 0;
}

/*
 * Append one TAB-separated field to the request under construction.
 * 'used' is its current length; returns the new length, or -1 when the
 * field does not fit.  The caller refuses a request that would be
 * truncated: it is never assembled past the buffer or sent half-formed.
 */
static int request_append(char *request, size_t size, int used,
                          const char *field)
{
    int n;

    if (used < 0 || (size_t)used >= size)
        return -1;
    n = snprintf(request + used, size - (size_t)used, "\t%s", field);
    if (n < 0 || (size_t)n >= size - (size_t)used)
        return -1;
    return used + n;
}

/*
 * Send the remove request in chunks of CONTROL_MAX_IDS IDs.  On return:
 * 0 with *removed_out set when the daemon applied the chunks; 0 with
 * *no_listener set when no daemon answered (the caller then edits the
 * file directly); -1 on a transport failure or a malformed reply.
 */
static int remove_over_socket(const char *verb, const char *list_arg,
                              char (*full)[RULEID_HEX_LEN + 1], int n,
                              int *removed_out, int *no_listener)
{
    char request[CONTROL_REQ_MAX];
    int removed = 0;

    *no_listener = 0;
    for (int start = 0; start < n; start += CONTROL_MAX_IDS)
    {
        ControlResponse resp;
        int chunk = n - start;
        int pos;

        if (chunk > CONTROL_MAX_IDS)
            chunk = CONTROL_MAX_IDS;

        /* "VERB[\tlist]" then one "\t<id>" per chunk member; IDs are 16
         * hex chars, so the 4 KiB request bound cannot be reached.  The
         * checks below still refuse a request that would not fit instead
         * of letting sizeof(request) - pos underflow. */
        pos = snprintf(request, sizeof(request), "%s", verb);
        if (pos < 0 || (size_t)pos >= sizeof(request))
        {
            fprintf(stderr, "error: control request does not fit its buffer\n");
            return -1;
        }
        if (list_arg)
            pos = request_append(request, sizeof(request), pos, list_arg);
        for (int i = 0; i < chunk && pos >= 0; i++)
            pos = request_append(request, sizeof(request), pos,
                                 full[start + i]);
        if (pos < 0)
        {
            fprintf(stderr, "error: control request does not fit its buffer\n");
            return -1;
        }

        int rc = ctl_call(request, &resp);

        if (rc == 1)
        {
            *no_listener = 1;
            break;
        }
        if (rc < 0)
            return -1;

        long got = control_response_scalar(&resp);

        if (got < 0)
        {
            fprintf(stderr, "error: malformed daemon response\n");
            return -1;
        }
        removed += (int)got;
    }
    *removed_out = removed;
    return 0;
}

static int remove_rules(int deny, char *const *inputs, int n)
{
    PersistEntry *entries = NULL;
    int count = 0, rc = 0, removed = 0, no_listener = 0;
    int *indices = calloc((size_t)n + 1, sizeof(*indices));
    char (*full)[RULEID_HEX_LEN + 1] =
        calloc((size_t)n + 1, sizeof(*full));

    if (!indices || !full)
    {
        fprintf(stderr, "error: out of memory\n");
        free(indices);
        free(full);
        return 1;
    }
    if (load_entries(deny, &entries, &count) < 0 ||
        resolve_rule_set(entries, count, inputs, n, indices, full) < 0)
    {
        free(entries);
        free(indices);
        free(full);
        return 1;
    }
    n = dedupe_full_ids(full, indices, n);

    printf("Will remove %d %s rule(s):\n", n, rule_label(deny));

    int width = cli_ui_terminal_width(stdout);

    for (int i = 0; i < n; i++)
        cli_ui_render_confirm_line(stdout, full[i], entries[indices[i]].binary,
                                   entries[indices[i]].target_path, width,
                                   g_wide);

    if (!cli_confirm("Remove these rules?", g_yes))
    {
        printf("aborted; nothing removed\n");
        free(entries);
        free(indices);
        free(full);
        return 1;
    }

    if (remove_over_socket("RULE_REMOVE", rule_label(deny), full, n, &removed,
                           &no_listener) < 0)
        rc = -1;
    else if (no_listener)
    {
        /* No daemon to race: apply the removals to the state file. */
        if (fallback_remove_rules(
                deny, (const char (*)[RULEID_HEX_LEN + 1])full, n) < 0)
            rc = -1;
        else
            removed = n;
    }

    if (rc == 0)
        printf("removed %d rule(s)\n", removed);
    free(entries);
    free(indices);
    free(full);
    return rc == 0 ? 0 : 1;
}

static int remove_pins(char *const *inputs, int n)
{
    PinRecord *rows = NULL;
    int count = 0, rc = 0, removed = 0, no_listener = 0;
    int *indices = calloc((size_t)n + 1, sizeof(*indices));
    char (*full)[RULEID_HEX_LEN + 1] =
        calloc((size_t)n + 1, sizeof(*full));

    if (!indices || !full)
    {
        fprintf(stderr, "error: out of memory\n");
        free(indices);
        free(full);
        return 1;
    }
    if (load_pins(&rows, &count) < 0 ||
        resolve_pin_set(rows, count, inputs, n, indices, full) < 0)
    {
        free(rows);
        free(indices);
        free(full);
        return 1;
    }
    n = dedupe_full_ids(full, indices, n);

    printf("Will remove %d pin(s):\n", n);

    int width = cli_ui_terminal_width(stdout);

    for (int i = 0; i < n; i++)
        cli_ui_render_confirm_line(stdout, full[i], rows[indices[i]].pattern,
                                   NULL, width, g_wide);

    if (!cli_confirm("Remove these pins?", g_yes))
    {
        printf("aborted; nothing removed\n");
        free(rows);
        free(indices);
        free(full);
        return 1;
    }

    if (remove_over_socket("PIN_REMOVE", NULL, full, n, &removed,
                           &no_listener) < 0)
        rc = -1;
    else if (no_listener)
    {
        if (fallback_remove_pins(
                (const char (*)[RULEID_HEX_LEN + 1])full, n) < 0)
            rc = -1;
        else
            removed = n;
    }

    if (rc == 0)
        printf("removed %d pin(s)\n", removed);
    free(rows);
    free(indices);
    free(full);
    return rc == 0 ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/*  clear                                                              */
/* ------------------------------------------------------------------ */

static int clear_rules(int deny)
{
    PersistEntry *entries = NULL;
    int count = 0;

    if (load_entries(deny, &entries, &count) < 0)
        return 1;
    if (count > 0)
    {
        printf("This clears all %d %s rule(s).\n", count, rule_label(deny));
        if (!cli_confirm("Clear the list?", g_yes))
        {
            printf("aborted; nothing cleared\n");
            free(entries);
            return 1;
        }
    }
    /*
     * The file snapshot drives the prompt above, never the socket: a live
     * daemon can hold entries whose persist_save() failed earlier, so a
     * clear is sent whenever a listener answers -- even when the file was
     * empty (then no prompt: there is nothing there to confirm).  The
     * daemon's count is authoritative; the file-only path below runs only
     * when no listener answers (ENOENT/ECONNREFUSED).
     */
    int rc = ctl_call(deny ? "RULE_CLEAR\tdeny" : "RULE_CLEAR\tallow",
                      &(ControlResponse){0});
    if (rc == 1)
    {
        if (count == 0)
        {
            printf("no %s rules to clear\n", rule_label(deny));
            free(entries);
            return 0;
        }
        if (persist_save(rule_path(deny), entries, 0) < 0)
        {
            fprintf(stderr, "error: failed to write %s\n", rule_path(deny));
            free(entries);
            return 1;
        }
        fprintf(stderr, "warning: daemon not running; applied directly to %s "
                        "(start fileshield to enforce)\n", rule_path(deny));
        rc = 0;
    }
    free(entries);
    if (rc < 0)
        return 1;
    printf("cleared the %s list\n", rule_label(deny));
    return 0;
}

static int clear_pins(void)
{
    PinRecord *rows = NULL;
    int count = 0;

    if (load_pins(&rows, &count) < 0)
        return 1;
    if (count == 0)
    {
        printf("no pins to clear\n");
        free(rows);
        return 0;
    }
    printf("This clears all %d pin(s); allowlisted binaries will be hashed "
           "again on first use.\n", count);
    if (!cli_confirm("Clear every pin?", g_yes))
    {
        printf("aborted; nothing cleared\n");
        free(rows);
        return 1;
    }

    int rc = ctl_call("PIN_CLEAR", &(ControlResponse){0});
    if (rc == 1)
    {
        if (pin_write_file(PIN_STATE_FILE, rows, 0) < 0)
        {
            fprintf(stderr, "error: failed to write %s\n", PIN_STATE_FILE);
            free(rows);
            return 1;
        }
        fprintf(stderr, "warning: daemon not running; applied directly to %s "
                        "(start fileshield to enforce)\n", PIN_STATE_FILE);
        rc = 0;
    }
    free(rows);
    if (rc < 0)
        return 1;
    printf("cleared every pin\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  prune                                                              */
/* ------------------------------------------------------------------ */

/* One printable cell: sanitized, tail-truncated unless --wide. */
static void print_cell(const char *s, int width)
{
    char buf[PATH_MAX + PERSIST_CMDLINE_MAX + 64];
    size_t max = g_wide ? sizeof(buf) : (size_t)(width + 1);

    if (max > sizeof(buf))
        max = sizeof(buf);
    if (g_wide)
        cli_ui_sanitize(s, buf, sizeof(buf));
    else
        cli_ui_truncate_tail(s, width, buf, max);
    fputs(buf, stdout);
}

static void format_time(time_t t, char *out, size_t outsz)
{
    struct tm tm;

    /* Mirror cli_ui.c's format_epoch(): a time_t the libc cannot convert
     * (corrupt created_at) must not make strftime() read a struct tm
     * localtime_r() never filled. */
    if (t <= 0 || localtime_r(&t, &tm) == NULL ||
        strftime(out, outsz, "%Y-%m-%d %H:%M:%S", &tm) == 0)
        snprintf(out, outsz, "(unknown)");
}

/*
 * One group member: ID, keep/remove and creation time.  The call chain is
 * part of the grouping key, so a member can only differ there if the key
 * comparison is broken; print it when it does so such a bug can never
 * hide behind the kept entry's chain.
 */
static void print_prune_member(const PersistEntry *e, const char *tag,
                               const char *keep_chain)
{
    char when[32];
    char chain[4 * 256];
    int idlen = g_wide ? RULEID_HEX_LEN : 8;

    format_time(e->created_at, when, sizeof(when));
    printf("    %.*s  %-6s  %s\n", idlen,
           e->rule_id[0] ? e->rule_id : "(none)", tag, when);

    cli_ui_chain_column(e->chain_comm, e->chain_depth, chain, sizeof(chain));
    if (strcmp(chain, keep_chain) != 0)
        printf("      chain: %s\n", chain);
}

static void print_prune_groups(int deny, const PersistEntry *entries,
                               const PruneGroup *groups, int ngroups,
                               const int *removals)
{
    printf("%s: %d duplicate group(s)\n", rule_label(deny), ngroups);
    for (int g = 0; g < ngroups; g++)
    {
        const PersistEntry *keep = &entries[groups[g].keep_index];
        char arg[PERSIST_CMDLINE_MAX];
        char chain[4 * 256];

        cli_ui_arg_column(keep->cmdline, arg, sizeof(arg));
        cli_ui_chain_column(keep->chain_comm, keep->chain_depth, chain,
                            sizeof(chain));
        printf("  ");
        print_cell(keep->binary, 48);
        printf(" ");
        print_cell(arg, 32);
        printf(" -> ");
        print_cell(keep->target_path, 48);
        if (strcmp(chain, "(none)") != 0)
        {
            printf("  (");
            print_cell(chain, 40);
            printf(")");
        }
        printf("  [%d duplicate(s)]\n", groups[g].remove_count);

        print_prune_member(keep, "keep", chain);
        for (int r = groups[g].remove_offset;
             r < groups[g].remove_offset + groups[g].remove_count; r++)
        {
            print_prune_member(&entries[removals[r]], "remove", chain);
        }
    }
}

/* Report the duplicate groups of one list; returns the group count,
 * or -1 on a read/allocation/analysis failure. */
static int prune_list(int deny)
{
    PersistEntry *entries = NULL;
    int count = 0, ngroups = 0, nremovals = 0;
    PruneGroup *groups;
    int *removals;

    if (load_entries(deny, &entries, &count) < 0)
        return -1;
    if (count == 0)
    {
        free(entries);
        return 0;
    }
    groups = calloc((size_t)count + 1, sizeof(*groups));
    removals = calloc((size_t)count + 1, sizeof(*removals));
    if (!groups || !removals)
    {
        fprintf(stderr, "error: out of memory\n");
        free(entries);
        free(groups);
        free(removals);
        return -1;
    }

    ngroups = prune_find(entries, count, groups, count, removals, count,
                         &nremovals);
    if (ngroups < 0)
    {
        fprintf(stderr, "error: could not analyze %s\n", rule_path(deny));
        free(groups);
        free(removals);
        free(entries);
        return -1;
    }
    if (ngroups > 0)
        print_prune_groups(deny, entries, groups, ngroups, removals);

    free(groups);
    free(removals);
    free(entries);
    return ngroups;
}

static int prune_apply_local(int deny)
{
    PersistEntry *entries = NULL;
    int count = 0, ngroups, nremovals = 0, new_count = 0;
    PruneGroup *groups;
    int *removals;
    int rc = 0;

    if (load_entries(deny, &entries, &count) < 0)
        return -1;
    groups = calloc((size_t)count + 1, sizeof(*groups));
    removals = calloc((size_t)count + 1, sizeof(*removals));
    if (!groups || !removals)
    {
        fprintf(stderr, "error: out of memory\n");
        free(entries);
        free(groups);
        free(removals);
        return -1;
    }
    ngroups = prune_find(entries, count, groups, count, removals, count,
                         &nremovals);
    if (ngroups < 0)
    {
        fprintf(stderr, "error: could not analyze %s\n", rule_path(deny));
        rc = -1;
    }
    else if (ngroups > 0)
    {
        if (prune_apply(entries, count, removals, nremovals, &new_count) < 0)
        {
            fprintf(stderr, "error: could not apply the prune to %s\n",
                    rule_path(deny));
            rc = -1;
        }
        else if (!entries_all_have_ids(entries, new_count))
        {
            refuse_legacy_write(deny);
            rc = -1;
        }
        else if (persist_save(rule_path(deny), entries, new_count) < 0)
        {
            fprintf(stderr, "error: failed to write %s\n", rule_path(deny));
            rc = -1;
        }
        else
        {
            fprintf(stderr, "warning: daemon not running; applied directly "
                            "to %s (start fileshield to enforce)\n",
                    rule_path(deny));
            rc = nremovals;
        }
    }
    free(groups);
    free(removals);
    free(entries);
    return rc;
}

static int cmd_prune(const char *which)
{
    int want_allow = 1, want_deny = 1;

    if (which)
    {
        if (strcmp(which, "allow") == 0)
            want_deny = 0;
        else if (strcmp(which, "deny") == 0)
            want_allow = 0;
        else
        {
            fprintf(stderr, "error: unknown prune filter: %s "
                            "(expected allow|deny)\n", which);
            usage_hint("prune [allow|deny] [-n]");
            return 2;
        }
    }

    /* The pre-confirmation report is the dry run: always computed from
     * the files, then discarded unless the user confirms.  A live daemon
     * can hold entries whose state-file write failed earlier, so its
     * prune may remove a group this report never showed; the daemon's
     * removed count (printed below) stays authoritative. */
    int total_groups = 0;

    /* Each prune_list() prints one list's duplicate report and returns its
     * group count; only the sum matters here, as the prompt gate. */
    if (want_allow)
    {
        int g = prune_list(0);

        if (g < 0)
            return 1;
        total_groups += g;
    }
    if (want_deny)
    {
        int g = prune_list(1);

        if (g < 0)
            return 1;
        total_groups += g;
    }
    /* Dry run never touches the socket; with no groups it keeps the
     * documented "no results" message instead of "dry run". */
    if (g_dry)
    {
        if (total_groups == 0)
            printf("there are no results to prune\n");
        else
            printf("dry run: nothing removed\n");
        return 0;
    }
    /*
     * The file snapshot drives the prompt -- and is skipped when it shows
     * nothing to confirm -- but it never gates the socket: a live daemon
     * can hold ghost duplicates an empty file never showed (see the
     * divergence note above), so PRUNE is still sent below whenever a
     * listener answers.  The daemon's removed count is authoritative.
     */
    if (total_groups > 0 && !cli_confirm("Prune these duplicates?", g_yes))
    {
        printf("aborted; nothing removed\n");
        return 1;
    }

    /* One request: the daemon prunes its in-memory lists and rewrites the
     * files together.  "both" mirrors this default scope; the no-listener
     * branch below recomputes the same groups locally. */
    const char *what = want_allow && want_deny ? "both"
                       : want_allow             ? "allow"
                                                : "deny";
    char request[64];
    ControlResponse resp;
    int rc;

    snprintf(request, sizeof(request), "PRUNE\t%s", what);
    rc = ctl_call(request, &resp);
    if (rc == 1)
    {
        /* No listener (ENOENT/ECONNREFUSED): the file-only path.  An
         * empty file snapshot had nothing to prune, and the daemon that
         * might hold ghosts is unreachable now. */
        if (total_groups == 0)
        {
            printf("there are no results to prune\n");
            return 0;
        }
        int total = 0;

        if (want_allow)
        {
            int r = prune_apply_local(0);
            if (r < 0)
                return 1;
            total += r;
        }
        if (want_deny)
        {
            int r = prune_apply_local(1);
            if (r < 0)
                return 1;
            total += r;
        }
        printf("pruned %d duplicate(s)\n", total);
        return 0;
    }
    if (rc < 0)
        return 1;
    long got = control_response_scalar(&resp);
    if (got < 0)
    {
        fprintf(stderr, "error: malformed daemon response\n");
        return 1;
    }
    printf("pruned %ld duplicate(s)\n", got);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  session                                                            */
/* ------------------------------------------------------------------ */

typedef struct
{
    CliSessionRow row;
    char binary[PATH_MAX];
    char target[PATH_MAX];
} SessionStore;

/* Split line on TABs in place; returns the field count (capped). */
static int split_tabs(char *line, char **fields, int max)
{
    int n = 0;

    while (n < max)
    {
        fields[n++] = line;
        char *tab = strchr(line, '\t');
        if (!tab)
            break;
        *tab = '\0';
        line = tab + 1;
    }
    return n;
}

static int parse_long_field(const char *s, long *out)
{
    char *end;
    long v;

    if (!s || *s == '\0')
        return -1;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || *end != '\0')
        return -1;
    *out = v;
    return 0;
}

/*
 * Fetch one list and append parsed records.  Returns 0 on success, -1 on
 * any failure (message printed; no listener prints the daemon-down
 * message because session state has no file fallback).
 */
static int session_fetch(int deny, SessionStore *store, int max, int *count)
{
    char request[64];
    ControlResponse resp;

    snprintf(request, sizeof(request), "SESSION_LIST\t%s",
             session_label(deny));
    int rc = ctl_call(request, &resp);
    if (rc == 1)
    {
        fprintf(stderr, "error: the fileshield daemon is not running; session "
                        "rules live only in daemon memory\n");
        return -1;
    }
    if (rc < 0)
        return -1;

    for (int i = 0; i < resp.count; i++)
    {
        char *fields[6];
        long sid, start, ttl;
        SessionStore *s;

        if (*count >= max)
        {
            fprintf(stderr, "error: too many session records\n");
            return -1;
        }
        if (split_tabs(resp.lines[i], fields, 6) != 6)
        {
            fprintf(stderr, "error: malformed session record\n");
            return -1;
        }
        s = &store[*count];
        memset(s, 0, sizeof(*s));
        if (control_decode_field(fields[0], s->row.id,
                                 sizeof(s->row.id)) < 0 ||
            parse_long_field(fields[1], &sid) < 0 ||
            parse_long_field(fields[2], &start) < 0 ||
            control_decode_field(fields[3], s->binary,
                                 sizeof(s->binary)) < 0 ||
            control_decode_field(fields[4], s->target,
                                 sizeof(s->target)) < 0 ||
            parse_long_field(fields[5], &ttl) < 0)
        {
            fprintf(stderr, "error: malformed session record\n");
            return -1;
        }
        s->row.is_deny = deny;
        s->row.sid = (pid_t)sid;
        s->row.binary = s->binary;
        s->row.target = s->target;
        s->row.ttl_remaining = ttl;
        (*count)++;
    }
    return 0;
}

/* Soonest expiry first; session-lifetime records last. */
static int session_before(const CliSessionRow *a, const CliSessionRow *b)
{
    int a_life = a->ttl_remaining < 0;
    int b_life = b->ttl_remaining < 0;

    if (a_life != b_life)
        return a_life ? 0 : 1;
    if (a_life)
        return 0;
    return a->ttl_remaining < b->ttl_remaining;
}

static void session_sort(SessionStore *store, int count)
{
    for (int i = 1; i < count; i++)
    {
        SessionStore key = store[i];
        int j = i - 1;

        while (j >= 0 && !session_before(&store[j].row, &key.row))
        {
            store[j + 1] = store[j];
            j--;
        }
        store[j + 1] = key;
    }
}

static int session_by_id(const SessionStore *store, int count,
                         const char *input, int *idx_out)
{
    int found = -1;
    int matches = 0;

    if (ruleid_prefix_match("0000000000000000", input) < 0)
        return -1;
    for (int i = 0; i < count; i++)
    {
        if (store[i].row.id[0] == '\0')
            continue;
        if (ruleid_prefix_match(store[i].row.id, input) == 1)
        {
            found = i;
            matches++;
        }
    }
    if (matches == 0)
        return 0;
    if (matches > 1)
        return -2;
    *idx_out = found;
    return 1;
}

/*
 * now + ttl for display, bounded so a corrupt or hostile TTL (it arrives
 * over the control socket) can never overflow time_t: saturation lands
 * outside localtime_r()'s range, which renders "(unknown)" instead.  The
 * unsigned sum is well defined; a failed time(NULL) (-1) is treated as
 * the epoch for the base.
 */
static time_t deadline_after(time_t now, long ttl)
{
    unsigned long long sum;

    if (ttl <= 0)
        return now;
    if (now < 0)
        now = 0;
    sum = (unsigned long long)now + (unsigned long long)ttl;
    if (sum > (unsigned long long)LLONG_MAX)
        return (time_t)LLONG_MAX;
    return (time_t)sum;
}

static void format_expiry(long ttl, char *out, size_t outsz)
{
    char human[32];
    char abs_time[32];
    struct tm tm;
    time_t when;

    if (ttl < 0)
    {
        snprintf(out, outsz, "until session ends");
        return;
    }
    if (ttl >= 3600)
        snprintf(human, sizeof(human), "%ldh %ldm", ttl / 3600,
                 (ttl % 3600) / 60);
    else if (ttl >= 60)
        snprintf(human, sizeof(human), "%ldm %lds", ttl / 60, ttl % 60);
    else
        snprintf(human, sizeof(human), "%lds", ttl);

    /* Mirrors cli_ui.c's format_epoch(): a deadline the libc cannot
     * convert renders "(unknown)" instead of reading an uninitialized
     * struct tm. */
    when = deadline_after(time(NULL), ttl);
    if (localtime_r(&when, &tm) == NULL ||
        strftime(abs_time, sizeof(abs_time), "%Y-%m-%d %H:%M:%S", &tm) == 0)
        snprintf(abs_time, sizeof(abs_time), "(unknown)");
    snprintf(out, outsz, "%s (in %s)", abs_time, human);
}

static void session_describe_one(const CliSessionRow *row, int first)
{
    char expiry[96];
    char binary[PATH_MAX];
    char target[PATH_MAX];

    /* Paths can carry control bytes; the table renderer sanitizes and so
     * must this one, or a rule's target could drive the user's terminal. */
    cli_ui_sanitize(row->binary, binary, sizeof(binary));
    cli_ui_sanitize(row->target, target, sizeof(target));

    if (!first)
        putchar('\n');
    format_expiry(row->ttl_remaining, expiry, sizeof(expiry));
    printf("ID:         %s\n", row->id);
    printf("Type:       %s\n", row->is_deny ? "DENY" : "ALLOW");
    printf("Session:    SID %d\n", (int)row->sid);
    printf("Binary:     %s\n", binary);
    printf("Target:     %s\n", target);
    printf("Expires:    %s\n", expiry);
}

static int session_list_cmd(const char *list, const char *id, int describe)
{
    int want_allow = 1, want_deny = 1;

    if (list)
    {
        int parsed = parse_list(list);

        if (parsed < 0)
        {
            fprintf(stderr, "error: unknown session list: %s "
                            "(expected allow|deny)\n", list);
            return 2;
        }
        want_allow = parsed == 0;
        want_deny = parsed == 1;
    }

    SessionStore *store = calloc(CLI_SESSION_MAX, sizeof(*store));
    int count = 0;

    if (!store)
    {
        fprintf(stderr, "error: out of memory\n");
        return 1;
    }
    if ((want_allow &&
         session_fetch(0, store, CLI_SESSION_MAX, &count) < 0) ||
        (want_deny &&
         session_fetch(1, store, CLI_SESSION_MAX, &count) < 0))
    {
        free(store);
        return 1;
    }
    session_sort(store, count);

    if (describe && id)
    {
        int idx = -1;
        int rc = session_by_id(store, count, id, &idx);

        if (rc == 0)
            fprintf(stderr, "error: no session rule matches %s\n", id);
        else if (rc == -2)
            print_ambiguous("session rule", id);
        else if (rc == -1)
            fprintf(stderr, "error: invalid rule ID: %s\n", id);
        if (rc != 1)
        {
            free(store);
            return 1;
        }
        if (g_json)
            cli_ui_render_list_json(stdout, CLI_UI_SECTION_SESSIONS, NULL, 0,
                                    NULL, 0, &store[idx].row, 1, time(NULL));
        else
            session_describe_one(&store[idx].row, 1);
        free(store);
        return 0;
    }

    if (describe && !g_json)
    {
        /* `session describe` without an ID describes every record. */
        for (int i = 0; i < count; i++)
            session_describe_one(&store[i].row, i == 0);
        if (count == 0)
            printf("no session rules\n");
        free(store);
        return 0;
    }

    /* `session list`, or `session describe --json`: both take the row
     * view (the JSON renderer emits the same records either way). */
    CliSessionRow *rows = calloc((size_t)count + 1, sizeof(*rows));

    if (!rows)
    {
        fprintf(stderr, "error: out of memory\n");
        free(store);
        return 1;
    }
    for (int i = 0; i < count; i++)
        rows[i] = store[i].row;
    if (g_json)
        cli_ui_render_list_json(stdout, CLI_UI_SECTION_SESSIONS, NULL, 0, NULL,
                                0, rows, count, time(NULL));
    else
        cli_ui_render_sessions(stdout, rows, count,
                               cli_ui_terminal_width(stdout), g_wide,
                               time(NULL));
    free(rows);
    free(store);
    return 0;
}

static int session_remove_cmd(const char *list, char **ids, int n)
{
    int want_allow = 1, want_deny = 1;

    if (list)
    {
        int parsed = parse_list(list);

        if (parsed < 0)
        {
            fprintf(stderr, "error: unknown session list: %s\n", list);
            return 2;
        }
        want_allow = parsed == 0;
        want_deny = parsed == 1;
    }

    SessionStore *store = calloc(CLI_SESSION_MAX, sizeof(*store));
    int count = 0, removed = 0;

    if (!store)
    {
        fprintf(stderr, "error: out of memory\n");
        return 1;
    }
    /* Session rules live only in daemon memory, so the snapshot the IDs
     * are resolved against has to come over the socket first; there is no
     * state file to fall back to (unlike rules and pins). */
    if ((want_allow &&
         session_fetch(0, store, CLI_SESSION_MAX, &count) < 0) ||
        (want_deny &&
         session_fetch(1, store, CLI_SESSION_MAX, &count) < 0))
    {
        free(store);
        return 1;
    }

    /* Resolve every ID before asking, then act on the snapshot; a failed
     * resolve aborts before the first request, so a typo cannot remove
     * part of the batch.  As in the rules/pins paths, repeated IDs
     * collapse to one: a duplicate would otherwise be removed twice and
     * the second daemon reply ("no match") would fail an otherwise
     * successful request. */
    int *indices = calloc((size_t)n + 1, sizeof(*indices));
    char (*full)[RULEID_HEX_LEN + 1] =
        calloc((size_t)n + 1, sizeof(*full));

    if (!indices || !full)
    {
        fprintf(stderr, "error: out of memory\n");
        free(store);
        free(indices);
        free(full);
        return 1;
    }
    for (int i = 0; i < n; i++)
    {
        int rc = session_by_id(store, count, ids[i], &indices[i]);

        if (rc == 0)
            fprintf(stderr, "error: no session rule matches %s\n", ids[i]);
        else if (rc == -2)
            print_ambiguous("session rule", ids[i]);
        else if (rc == -1)
            fprintf(stderr, "error: invalid rule ID: %s\n", ids[i]);
        if (rc != 1)
        {
            free(store);
            free(indices);
            free(full);
            return 1;
        }
        memcpy(full[i], store[indices[i]].row.id, RULEID_HEX_LEN + 1);
    }
    n = dedupe_full_ids(full, indices, n);

    printf("Will remove %d session rule(s):\n", n);

    int width = cli_ui_terminal_width(stdout);

    for (int i = 0; i < n; i++)
        cli_ui_render_confirm_line(stdout, full[i],
                                   store[indices[i]].row.binary,
                                   store[indices[i]].row.target, width,
                                   g_wide);

    if (!cli_confirm("Remove these session rules?", g_yes))
    {
        printf("aborted; nothing removed\n");
        free(store);
        free(indices);
        free(full);
        return 1;
    }

    /* One request per ID (the current wire verb removes exactly one
     * record).  The batch was resolved and deduped up front, so the only
     * partial state reachable here is the daemon going away mid-loop; the
     * error branch reports how many IDs already went through. */
    for (int i = 0; i < n; i++)
    {
        char request[128];
        ControlResponse resp;

        snprintf(request, sizeof(request), "SESSION_REMOVE\t%s\t%s",
                 store[indices[i]].row.is_deny ? "deny" : "allow", full[i]);
        int rc = ctl_call(request, &resp);

        if (rc != 0)
        {
            if (rc == 1)
                fprintf(stderr,
                        "error: the fileshield daemon is not running\n");
            /* IDs earlier in the batch are already gone; report the
             * partial count instead of a bare failure. */
            if (removed > 0)
                printf("removed %d session rule(s)\n", removed);
            free(store);
            free(indices);
            free(full);
            return 1;
        }
        removed++;
    }
    printf("removed %d session rule(s)\n", removed);
    free(store);
    free(indices);
    free(full);
    return 0;
}

static int session_clear_cmd(const char *list)
{
    int both = list == NULL;
    int deny = 0;

    if (list)
    {
        int parsed = parse_list(list);

        if (parsed < 0)
        {
            fprintf(stderr, "error: unknown session list: %s\n", list);
            return 2;
        }
        deny = parsed;
    }
    if (!cli_confirm(both ? "Clear every session rule?"
                          : "Clear the session rules for this list?", g_yes))
    {
        printf("aborted; nothing cleared\n");
        return 1;
    }

    char request[64];
    ControlResponse resp;

    snprintf(request, sizeof(request), "SESSION_CLEAR\t%s",
             both ? "both" : session_label(deny));
    int rc = ctl_call(request, &resp);

    if (rc == 1)
    {
        fprintf(stderr, "error: the fileshield daemon is not running\n");
        return 1;
    }
    if (rc < 0)
        return 1;
    printf("cleared the session rules\n");
    return 0;
}

static int session_cmd(char **args, int nargs)
{
    if (nargs < 1)
    {
        fprintf(stderr, "error: session requires a subcommand "
                        "(list|describe|remove|clear)\n");
        usage_hint("session list|describe|remove|clear [allow|deny] [ID]");
        return 2;
    }
    const char *sub = args[0];
    const char *list = NULL;
    int pos = 1;

    /* The optional list argument comes first; anything else is IDs. */
    if (pos < nargs && (strcmp(args[pos], "allow") == 0 ||
                        strcmp(args[pos], "deny") == 0))
        list = args[pos++];

    if (strcmp(sub, "list") == 0)
    {
        if (pos != nargs)
        {
            fprintf(stderr, "error: session list takes at most one list\n");
            usage_hint("session list [allow|deny]");
            return 2;
        }
        return session_list_cmd(list, NULL, 0);
    }
    if (strcmp(sub, "describe") == 0)
    {
        const char *id = NULL;

        if (pos < nargs)
            id = args[pos++];
        if (pos != nargs || (id && !list && nargs > 2))
        {
            fprintf(stderr, "error: session describe takes at most a list "
                            "and an ID\n");
            usage_hint("session describe [allow|deny] [ID]");
            return 2;
        }
        return session_list_cmd(list, id, 1);
    }
    if (strcmp(sub, "remove") == 0)
    {
        if (pos >= nargs)
        {
            fprintf(stderr, "error: session remove needs at least one ID\n");
            usage_hint("session remove [allow|deny] <ID> [<ID>...]");
            return 2;
        }
        return session_remove_cmd(list, &args[pos], nargs - pos);
    }
    if (strcmp(sub, "clear") == 0)
    {
        if (pos != nargs)
        {
            fprintf(stderr, "error: session clear takes at most one list\n");
            usage_hint("session clear [allow|deny]");
            return 2;
        }
        return session_clear_cmd(list);
    }
    fprintf(stderr, "error: unknown session subcommand: %s "
                    "(expected list|describe|remove|clear)\n", sub);
    usage_hint("session list|describe|remove|clear [allow|deny] [ID]");
    return 2;
}

/* ------------------------------------------------------------------ */
/*  reload                                                             */
/* ------------------------------------------------------------------ */

static int cmd_reload(void)
{
    ControlResponse resp;

    int rc = ctl_call("RELOAD", &resp);

    if (rc == 1)
    {
        fprintf(stderr, "error: the fileshield daemon is not running\n");
        return 1;
    }
    if (rc < 0)
        return 1;
    printf("reload requested\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */

/*
 * FILESHIELD_TEST_CLI renames main to cli_test_main for the test build;
 * production omits the flag and keeps main (tests: one call per process).
 */
#ifdef FILESHIELD_TEST_CLI
int cli_test_main(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
    g_prog = argv[0];
    static struct option long_opts[] = {
        {"yes", no_argument, 0, 'y'},
        {"dry-run", no_argument, 0, 'n'},
        {"wide", no_argument, &g_wide, 1},
        {"json", no_argument, &g_json, 1},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {0, 0, 0, 0}};
    int opt;

    /* GNU getopt permutes argv, so global flags may follow the command
     * word (e.g. `prune -n`); when parsing stops, argv[optind..] holds
     * the command and its arguments only. */
    while ((opt = getopt_long(argc, argv, "ynhv", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'y':
            g_yes = 1;
            break;
        case 'n':
            g_dry = 1;
            break;
        case 'h':
            print_usage(stdout, argv[0]);
            return 0;
        case 'v':
            printf("fileshield-cli %s\n", CLI_VERSION);
            return 0;
        case 0:
            break; /* long option stored its flag */
        default:
            print_usage(stderr, argv[0]);
            return 2;
        }
    }

    if (optind >= argc)
    {
        print_usage(stderr, argv[0]);
        return 2;
    }

    const char *cmd = argv[optind++];
    int rest = argc - optind;

    /* Command dispatch, a flat if-chain: each branch validates its own
     * arity first and prints the concrete command line on a usage error
     * (exit 2); data and transport errors are reported by the handlers
     * (exit 1).  Exit codes: 0 success (including "nothing to do"), 1
     * domain failure, 2 usage.  The first match returns; an unknown
     * command falls through to the usage dump below. */
    if (strcmp(cmd, "list") == 0)
    {
        if (rest > 1)
        {
            fprintf(stderr, "error: list takes at most one filter\n");
            usage_hint("list [rules|allow|deny|pins]");
            return 2;
        }
        return cmd_list(rest == 1 ? argv[optind] : NULL);
    }
    if (strcmp(cmd, "describe") == 0)
    {
        if (rest < 1 || rest > 2)
        {
            fprintf(stderr, "error: describe needs a type "
                            "(and at most one ID)\n");
            usage_hint("describe allow|deny|pin [ID]");
            return 2;
        }
        return cmd_describe(argv[optind], rest == 2 ? argv[optind + 1] : NULL);
    }
    if (strcmp(cmd, "remove") == 0)
    {
        if (rest < 2)
        {
            fprintf(stderr, "error: remove needs a type and at least one ID\n");
            usage_hint("remove allow|deny|pin <ID> [<ID>...]");
            return 2;
        }
        if (strcmp(argv[optind], "pin") == 0)
            return remove_pins(&argv[optind + 1], rest - 1);
        int deny = parse_list(argv[optind]);
        if (deny < 0)
        {
            fprintf(stderr, "error: unknown remove type: %s "
                            "(expected allow|deny|pin)\n", argv[optind]);
            usage_hint("remove allow|deny|pin <ID> [<ID>...]");
            return 2;
        }
        return remove_rules(deny, &argv[optind + 1], rest - 1);
    }
    if (strcmp(cmd, "clear") == 0)
    {
        if (rest != 1)
        {
            fprintf(stderr, "error: clear needs exactly one type "
                            "(allow|deny|pins)\n");
            usage_hint("clear allow|deny|pins");
            return 2;
        }
        if (strcmp(argv[optind], "pins") == 0)
            return clear_pins();
        int deny = parse_list(argv[optind]);
        if (deny < 0)
        {
            fprintf(stderr, "error: unknown clear type: %s "
                            "(expected allow|deny|pins)\n", argv[optind]);
            usage_hint("clear allow|deny|pins");
            return 2;
        }
        return clear_rules(deny);
    }
    if (strcmp(cmd, "prune") == 0)
    {
        if (rest > 1)
        {
            fprintf(stderr, "error: prune takes at most one filter\n");
            usage_hint("prune [allow|deny] [-n]");
            return 2;
        }
        return cmd_prune(rest == 1 ? argv[optind] : NULL);
    }
    if (strcmp(cmd, "session") == 0)
        return session_cmd(&argv[optind], rest);
    if (strcmp(cmd, "reload") == 0)
    {
        if (rest != 0)
        {
            fprintf(stderr, "error: reload takes no arguments\n");
            usage_hint("reload");
            return 2;
        }
        return cmd_reload();
    }

    fprintf(stderr, "error: unknown command: %s\n", cmd);
    print_usage(stderr, argv[0]);
    return 2;
}
