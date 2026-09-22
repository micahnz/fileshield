#ifndef FILESHIELD_SHA512_H
#define FILESHIELD_SHA512_H

#include <sys/types.h>
/*
 * Compute the SHA-512 digest of the file at 'path' by running sha512sum(1)
 * (part of GNU coreutils, always available on Linux systems).
 *
 * On success, writes exactly 128 lower-case hex characters followed by a NUL
 * into hex_out[129] and returns 0.
 *
 * Returns -1 on error (binary not found, unreadable file, unexpected output).
 * hex_out is left untouched on error.
 */
int sha512_file(const char *path, char hex_out[129]);

/*
 * Compute the SHA-512 digest of the executable of process 'pid' by hashing
 * /proc/<pid>/exe directly.  This works even when the process runs inside a
 * container (Podman, Docker) and its binary path does not exist on the host
 * filesystem.
 *
 * Same return semantics as sha512_file().
 */
int sha512_proc_exe(pid_t pid, char hex_out[129]);

/*
 * Human-readable reason for the most recent sha512_file()/sha512_proc_exe()
 * failure, e.g. "sha512sum timed out" or "sha512sum returned no digest".
 * Empty when the last file/proc hash succeeded.  In-process string and
 * buffer hashing never touch it, so a caller can capture the reason after
 * a failed binary hash and use it later (e.g. in a dialog).  The daemon is
 * single-threaded; the buffer is overwritten by the next file hash.
 */
const char *sha512_last_failure(void);

/*
 * Register a callback invoked once per silent wait slice (about every
 * 100 ms) while a forked hash helper is running.  fanotify.c uses it to
 * service its event queue while the helper is blocked opening
 * /proc/<pid>/exe on a marked filesystem; the callback must not block
 * and must not call back into sha512_file()/sha512_proc_exe().  Pass
 * NULL to clear.
 */
void sha512_set_wait_hook(void (*hook)(void));

/*
 * Compute the SHA-512 digest of an in-memory string (used to fingerprint
 * command lines without persisting potentially secret arguments).
 * Same return semantics as sha512_file().
 */
int sha512_string(const char *str, char hex_out[129]);

/*
 * Compute the SHA-512 digest of a length-delimited memory buffer.  Unlike
 * sha512_string(), the buffer may contain NUL bytes: the raw
 * /proc/<pid>/cmdline bytes are NUL-separated, and fingerprinting them
 * as-is keeps the digest independent of any display truncation.
 * 'data' must be non-NULL (len may be 0).  Same return semantics as
 * sha512_file().
 */
int sha512_buf(const void *data, size_t len, char hex_out[129]);

/*
 * Test seam: override the sha512sum helper binary forked by
 * sha512_file()/sha512_proc_exe() (NULL or "" restores
 * /usr/bin/sha512sum).  Production never calls this; with the seam
 * unset the helper path, argv, timeout and reap behavior are identical
 * to a build without it.  Lets a test substitute a slow stand-in that
 * emits a digest and then stalls, exercising the bounded kill/reap
 * deadline (REAP_DEADLINE_S) without touching the reap loop itself.
 */
void sha512_test_set_helper(const char *path);

#endif /* FILESHIELD_SHA512_H */
