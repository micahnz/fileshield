#include "control_client.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "persist.h"

/*
 * Client half of the control protocol (see control_client.h).  This
 * translation unit is linked into fileshield-cli and therefore must not
 * reference any daemon module or global: it depends on libc and
 * persist.c (persist_json_escape) only.
 */

/* ------------------------------------------------------------------ */
/* Field codec                                                        */
/* ------------------------------------------------------------------ */

int control_encode_field(const char *src, char *dst, size_t dst_size)
{
    /* One escaping convention for every state file, dialog and socket
     * field; a second implementation would be a place to disagree. */
    return persist_json_escape(src, dst, dst_size);
}

/* Hex digit value, or -1. */
static int hex_digit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Encode one code point as UTF-8; returns the byte count (1..4).
 * 0 < cp <= 0x10FFFF is guaranteed by the caller. */
static int utf8_encode(unsigned int cp, char out[4])
{
    if (cp < 0x80)
    {
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800)
    {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000)
    {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = (char)(0xF0 | (cp >> 18));
    out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

/* Parse exactly four hex digits (the encoder always emits four, so a
 * short escape is malformed input, not a shorter value). */
static int decode_hex4(const char *digits, unsigned int *out)
{
    unsigned int code = 0;

    for (int k = 0; k < 4; k++)
    {
        int d = hex_digit(digits[k]);

        if (d < 0)
            return -1;
        code = (code << 4) | (unsigned int)d;
    }
    *out = code;
    return 0;
}

/*
 * Decode the escape at *pp (which points at the backslash), write its
 * UTF-8 bytes to out (at most 4) and advance *pp past the escape.
 * Returns the byte count, or -1 for an unknown escape, a lone surrogate
 * or a malformed \uXXXX.
 */
static int decode_escape(const char **pp, char out[4])
{
    const char *p = *pp + 1; /* skip the backslash */
    unsigned int code;

    switch (*p)
    {
    case '"':
        out[0] = '"';
        break;
    case '\\':
        out[0] = '\\';
        break;
    case '/':
        out[0] = '/';
        break;
    case 'b':
        out[0] = '\b';
        break;
    case 'f':
        out[0] = '\f';
        break;
    case 'n':
        out[0] = '\n';
        break;
    case 'r':
        out[0] = '\r';
        break;
    case 't':
        out[0] = '\t';
        break;
    case 'u':
        if (decode_hex4(p + 1, &code) < 0)
            return -1;
        p += 5; /* past "uXXXX" */
        if (code == 0)
            return -1; /* \u0000 cannot live in a C string */
        if (code >= 0xD800 && code <= 0xDBFF)
        {
            /* A high surrogate must be followed by the low half of its
             * pair; a lone surrogate is not valid UTF-8 and the state
             * writers never emit one. */
            unsigned int low;

            if (p[0] != '\\' || p[1] != 'u')
                return -1;
            if (decode_hex4(p + 2, &low) < 0 ||
                low < 0xDC00 || low > 0xDFFF)
                return -1;
            code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
            p += 6; /* past the low half's "\uXXXX" */
        }
        else if (code >= 0xDC00 && code <= 0xDFFF)
        {
            return -1; /* lone low surrogate */
        }
        *pp = p;
        return utf8_encode(code, out);
    default:
        return -1; /* unknown escape sequence */
    }

    *pp = p + 1;
    return 1;
}

int control_decode_field(const char *src, char *dst, size_t dst_size)
{
    const char *p = src;
    size_t j = 0;

    if (!src || !dst || dst_size == 0)
        return -1;

    while (*p != '\0')
    {
        char add[4];
        int add_len;

        if (*p != '\\')
        {
            /* Raw bytes pass through; a control byte is rejected because
             * a valid encoding never produces one unescaped. */
            if ((unsigned char)*p < 0x20)
                return -1;
            add[0] = *p++;
            add_len = 1;
        }
        else
        {
            add_len = decode_escape(&p, add);
            if (add_len < 0)
                return -1;
        }

        if (j + (size_t)add_len > dst_size - 1)
            return -1; /* value does not fit */
        memcpy(dst + j, add, (size_t)add_len);
        j += (size_t)add_len;
    }

    dst[j] = '\0';
    return (int)j;
}

/* ------------------------------------------------------------------ */
/* Response parsing                                                   */
/* ------------------------------------------------------------------ */

/* Offset of the next '\n' at or after 'from'; 0 on success. */
static int line_end(const char *text, size_t len, size_t from, size_t *nl_out)
{
    for (size_t i = from; i < len; i++)
    {
        if (text[i] == '\n')
        {
            *nl_out = i;
            return 0;
        }
    }
    return -1;
}

int control_response_parse(char *text, size_t len, ControlResponse *out)
{
    size_t pos;
    size_t end;

    if (!text || !out || len == 0)
        return -1;
    memset(out, 0, sizeof(*out));

    if (len >= 3 && memcmp(text, "OK\n", 3) == 0)
    {
        long count = 0;

        pos = 3;
        if (line_end(text, len, pos, &end) < 0 || end == pos)
            return -1; /* no count line, or an empty one */
        for (size_t i = pos; i < end; i++)
        {
            if (text[i] < '0' || text[i] > '9')
                return -1;
            if (count > (LONG_MAX - 9) / 10)
                return -1;
            count = count * 10 + (text[i] - '0');
        }
        if (count > CONTROL_PAYLOAD_MAX)
            return -1;
        text[end] = '\0';
        out->ok = 1;
        out->count = (int)count;

        pos = end + 1;
        for (int i = 0; i < out->count; i++)
        {
            if (line_end(text, len, pos, &end) < 0)
                return -1; /* fewer payload lines than promised */
            text[end] = '\0';
            out->lines[i] = text + pos;
            pos = end + 1;
        }
        if (pos != len)
            return -1; /* trailing bytes: not exactly <count> lines */
        return 0;
    }

    if (len >= 4 && memcmp(text, "ERR\n", 4) == 0)
    {
        pos = 4;
        if (line_end(text, len, pos, &end) < 0)
            return -1;
        text[end] = '\0';
        out->ok = 0;
        out->count = 0;
        out->message = text + pos;
        if (end + 1 != len)
            return -1; /* trailing bytes after the message line */
        return 0;
    }

    return -1;
}

long control_response_scalar(const ControlResponse *resp)
{
    const char *p;
    long value = 0;
    int digits = 0;

    if (!resp || !resp->ok || resp->count != 1 || !resp->lines[0])
        return -1;

    p = resp->lines[0];
    for (; *p != '\0'; p++)
    {
        if (*p < '0' || *p > '9')
            return -1; /* counts are non-negative plain decimals */
        if (value > (LONG_MAX - (*p - '0')) / 10)
            return -1;
        value = value * 10 + (*p - '0');
        digits++;
    }
    if (digits == 0)
        return -1;
    return value;
}

/* ------------------------------------------------------------------ */
/* Client                                                             */
/* ------------------------------------------------------------------ */

/* Test seam state (control_client_test_fail_with): while armed (non-zero),
 * every call fails with this errno before any socket or filesystem work;
 * 0 (the default) takes the normal path. */
static int g_test_fail_err;

void control_client_test_fail_with(int err)
{
    g_test_fail_err = err;
}

/* Test seam state (control_client_test_set_socket_path): when non-empty,
 * every call connects here instead of the sock_path argument so tests can
 * use a canned server under /tmp and never open CONTROL_SOCKET_PATH. */
static char g_test_sock_path[sizeof(((struct sockaddr_un *)0)->sun_path)];

void control_client_test_set_socket_path(const char *path)
{
    if (!path || path[0] == '\0')
    {
        g_test_sock_path[0] = '\0';
        return;
    }
    if (strlen(path) >= sizeof(g_test_sock_path))
        return; /* leave the previous redirect in effect */
    memcpy(g_test_sock_path, path, strlen(path) + 1);
}

/* Blocking send of the request plus its newline.  The CLI socket is
 * blocking: a stuck daemon must surface as a slow command, not as a
 * silently dropped request. */
static int client_send_line(int fd, const char *request)
{
    size_t len = strlen(request);
    size_t off = 0;

    while (off < len)
    {
        ssize_t n = send(fd, request + off, len - off, MSG_NOSIGNAL);

        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        off += (size_t)n;
    }
    if (send(fd, "\n", 1, MSG_NOSIGNAL) != 1)
        return -1;
    return 0;
}

/*
 * Read until EOF into buf, always NUL-terminated.  A response that does
 * not fit is ENOBUFS, never a silent truncation.  Returns 0, or -1 with
 * errno set.
 */
static int read_response(int fd, char *buf, size_t size, size_t *used_out)
{
    size_t used = 0;

    for (;;)
    {
        ssize_t got;

        if (used == size - 1)
        {
            /* Buffer full: one more byte decides between an exact fit
             * (EOF) and a response too large for the caller's buffer. */
            char extra;

            got = recv(fd, &extra, 1, 0);
            if (got < 0 && errno == EINTR)
                continue;
            if (got > 0)
            {
                errno = ENOBUFS;
                return -1;
            }
            if (got < 0)
                return -1;
            break;
        }

        got = recv(fd, buf + used, size - 1 - used, 0);
        if (got < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (got == 0)
            break;
        used += (size_t)got;
    }
    buf[used] = '\0';
    *used_out = used;
    return 0;
}

int control_client_call(const char *sock_path, const char *request,
                        char *resp_buf, size_t resp_size,
                        ControlResponse *out)
{
    struct sockaddr_un addr;
    size_t path_len;
    size_t used = 0;
    int fd;
    int rc = -1;

    /* Test seam first: fail before validation, socket() or connect(), so
     * an armed test can never reach the real control socket. */
    if (g_test_fail_err != 0)
    {
        errno = g_test_fail_err;
        return -1;
    }

    if (!sock_path || sock_path[0] == '\0' || !request || !resp_buf ||
        resp_size < 2 || !out)
        return -1;

    /* Socket-path redirect (also a test seam): after validation so a bad
     * argument still fails the same way in tests and production. */
    if (g_test_sock_path[0] != '\0')
        sock_path = g_test_sock_path;

    path_len = strlen(sock_path);
    if (path_len >= sizeof(addr.sun_path))
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, sock_path, path_len + 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        goto fail;

    if (client_send_line(fd, request) < 0)
        goto fail;

    /* Half-close: the request is complete, so the daemon must not see a
     * slow writer behind it.  Failures are harmless (the daemon reads
     * the newline either way). */
    (void)shutdown(fd, SHUT_WR);

    if (read_response(fd, resp_buf, resp_size, &used) < 0)
        goto fail;

    if (control_response_parse(resp_buf, used, out) < 0)
    {
        errno = EPROTO;
        goto fail;
    }
    rc = 0;

fail:
    /* Preserve the failing errno across close(): the CLI uses it to
     * tell "daemon absent" (ENOENT/ECONNREFUSED) from other failures. */
    {
        int saved_errno = errno;

        close(fd);
        errno = saved_errno;
    }
    return rc;
}
