#ifndef FILESHIELD_CONTROL_CLIENT_H
#define FILESHIELD_CONTROL_CLIENT_H

#include <stddef.h>

/*
 * control_client: client half of the control socket protocol and the
 * wire-format definitions both halves share.
 *
 * fileshield-cli manages the daemon's runtime state through an AF_UNIX
 * stream socket at CONTROL_SOCKET_PATH (0600, owned by the daemon's
 * effective uid -- root in production; the server also checks
 * SO_PEERCRED).  This module is deliberately self-contained: libc plus
 * persist.h (the shared JSON escaper) only.  It must stay linkable into
 * fileshield-cli WITHOUT the daemon's fanotify/notify/session/pin
 * modules, so it never references daemon state or globals.  The server
 * half (socket lifecycle, request parsing, dispatch) lives in
 * control.h/control.c, which includes this header.
 *
 * Wire format (one connection per request):
 *
 *   request:   VERB[\tARG]...\n
 *              One TAB-separated line.  Free-text arguments would be
 *              JSON-escaped with control_encode_field() (the current
 *              verbs carry only IDs and list names, which are raw);
 *              IDs and list names are never escaped.
 *
 *   response:  OK\n<count>\n          followed by exactly <count>
 *              <payload line>\n ...   payload lines, each '\n'-ended
 *   or         ERR\n<message>\n       with no payload lines
 *
 * The client reads to EOF: after writing the single response the server
 * closes the connection.  <count> is the number of payload lines, never a
 * command result, and control_response_parse() rejects a mismatch.
 *
 * SESSION_LIST is the only verb that enumerates: it sends one payload
 * line per live session entry with the TAB-separated, JSON-escaped
 * fields rule_id, sid, leader_start, binary, target and ttl_remaining.
 * Verbs with a scalar result (RULE_REMOVE, RULE_CLEAR, PRUNE,
 * PIN_REMOVE) report it as their single payload line, so their response
 * is OK\n1\n<number>\n; control_response_scalar() reads it back.
 */

/*
 * Root-owned socket the daemon listens on.  The parent directory is
 * /run/fileshield: systemd creates it 0700 through the unit's
 * RuntimeDirectory=, and a foreground/direct run creates it on demand
 * (also 0700) before binding.
 */
#define CONTROL_SOCKET_PATH "/run/fileshield/control.sock"

/*
 * Maximum request size in bytes, including the terminating newline.
 * The server reads at most CONTROL_REQ_MAX bytes per connection (its
 * buffer is one byte larger for the NUL terminator), so a line of
 * exactly this size including its newline is accepted.  A request that
 * does not fit, or that arrives without a newline, is closed without a
 * response: the CLI writes its single line up front.
 */
#define CONTROL_REQ_MAX 4096

/* Maximum number of IDs in one RULE_REMOVE / PIN_REMOVE request. */
#define CONTROL_MAX_IDS 16

/* Maximum payload lines one response may carry (mirrors session.c's
 * 256-entry table; also the bound of ControlResponse.lines). */
#define CONTROL_PAYLOAD_MAX 256

/*
 * Parsed response.  message/lines point into the response text, which is
 * modified in place ('\n' becomes '\0') and must stay alive while the
 * struct is used.  On success count == the number of valid lines[].
 */
typedef struct
{
    int ok;                 /* 1 = OK, 0 = ERR                          */
    int count;              /* payload lines (OK only)                  */
    const char *message;    /* ERR message (pointer into the text)      */
    char *lines[CONTROL_PAYLOAD_MAX]; /* payload lines into the text    */
} ControlResponse;

/* ------------------------------------------------------------------ */
/* Pure codec functions (no I/O; unit-testable)                       */
/* ------------------------------------------------------------------ */

/*
 * JSON-escape one field into dst (bounded, NUL-terminated), exactly the
 * persist_json_escape() encoding: quotes, backslashes and control bytes.
 * Returns the bytes written (without the NUL) or -1 when src/dst is NULL
 * or the result does not fit.
 */
int control_encode_field(const char *src, char *dst, size_t dst_size);

/*
 * Decode one control_encode_field() field: \" \\ \/ \b \f \n \r \t and
 * \uXXXX (UTF-8 encoded; surrogate pairs are combined, lone surrogates
 * and unknown escapes are rejected).  Raw control bytes inside the
 * value, a NUL code point (\u0000) and a result that does not fit are
 * errors.  Returns the decoded length or -1.
 */
int control_decode_field(const char *src, char *dst, size_t dst_size);

/*
 * Parse a whole response text of 'len' bytes in place.  text must be
 * writable; it needs no NUL terminator (the parser works within len).
 * On success exactly one of the OK or ERR shapes was found and every
 * declared payload line was present (no more, no less).  Returns 0 on
 * success, -1 on any malformed or truncated response.
 */
int control_response_parse(char *text, size_t len, ControlResponse *out);

/*
 * Scalar result of the verbs that report one (RULE_REMOVE, RULE_CLEAR,
 * PRUNE, PIN_REMOVE): the decimal value of the single payload line.
 * Returns -1 when the response is not OK with exactly one numeric line
 * (an ERR, an empty payload or a non-numeric line).
 */
long control_response_scalar(const ControlResponse *resp);

/* ------------------------------------------------------------------ */
/* Client helper for fileshield-cli                                   */
/* ------------------------------------------------------------------ */

/*
 * Send one request and read the whole response.
 *
 * Connects to sock_path (AF_UNIX), writes 'request' plus the terminating
 * newline (pass the line WITHOUT one), half-closes the write side and
 * reads to EOF into resp_buf (always NUL-terminated).  A response that
 * would not fit in resp_size bytes (including the NUL) is a failure, not
 * a truncation.  No retries: the caller decides what an unreachable
 * daemon means.
 *
 * Returns 0 when a complete response was read and parsed into out, -1 on
 * any transport failure, a too-large response or a malformed response.
 * errno is preserved across the internal close so the caller can
 * distinguish ENOENT/ECONNREFUSED (no listener) from EACCES and friends.
 *
 * One request per call; a caller that prefers per-ID requests simply
 * loops, while the multi-ID request forms (RULE_REMOVE / PIN_REMOVE) let
 * it remove several entries with one round trip.
 */
int control_client_call(const char *sock_path, const char *request,
                        char *resp_buf, size_t resp_size,
                        ControlResponse *out);

/*
 * Test seam: arm failure injection so the next control_client_call() --
 * and every later one until disarmed -- returns -1 with errno == err
 * before touching the filesystem or socket.  err == 0 disarms and
 * restores normal behaviour.  Tests use this instead of ever connecting
 * to /run/fileshield/control.sock; production never calls it, so the
 * cost when disarmed is one static-int check.  Takes priority over
 * control_client_test_set_socket_path().
 */
void control_client_test_fail_with(int err);

/*
 * Test seam: redirect every control_client_call() to connect at 'path'
 * instead of the sock_path argument, so a test can point the CLI at a
 * canned server under /tmp and never open CONTROL_SOCKET_PATH.  NULL or
 * "" restores the normal behaviour; an over-long path is ignored and the
 * previous redirect stays in effect.  Production never calls it (one
 * static-byte check when disarmed).
 */
void control_client_test_set_socket_path(const char *path);

#endif /* FILESHIELD_CONTROL_CLIENT_H */
