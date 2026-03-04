#include <string.h>

#include "include/b579_crypto_internal.h"


/* ══════════════════════════════════════════
 *  Linux Implementation
 * ══════════════════════════════════════════ 
 */

#ifdef B579_OS_LINUX

#include <sys/random.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

b579_result_t b579_entropy_fill(void *buf, size_t len) 
{
    B579_CHECK_NULL(buf);

    if (len == 0)
    {
        return B579_OK;
    }
    /*
     * Try getrandom() first — best option on modern Linux.
     * Available since kernel 3.17.
     * Flags: 0 = block if not enough entropy (safe default).
     */
    uint8_t *ptr = (uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) 
    {
        ssize_t got = getrandom(ptr, remaining, 0);
        if (got > 0) 
        {
            ptr       += got;
            remaining -= (size_t)got;
        } else if (got < 0) {
            if (errno == EINTR)
            {
                continue; /* Interrupted, retry */
            }

            /* getrandom not available — fallback to /dev/urandom */
            int fd = open("/dev/urandom", O_RDONLY);

            if (fd < 0) 
            {
                b579_error_set_errno("open(/dev/urandom)");
                return B579_ERR_IO;
            }

            while (remaining > 0) 
            {
                ssize_t r = read(fd, ptr, remaining);
                if (r > 0) 
                {
                    ptr       += r;
                    remaining -= (size_t)r;
                } else if (r < 0 && errno != EINTR) {
                    close(fd);
                    b579_error_set_errno("read(/dev/urandom)");
                    return B579_ERR_IO;
                }
            }
            close(fd);
            break;
        }
    }

    return B579_OK;
}

#endif /* B579_OS_LINUX */

/* ══════════════════════════════════════════
 *  macOS Implementation
 * ══════════════════════════════════════════ 
 */

#ifdef B579_OS_MACOS

#include <stdlib.h> /* arc4random_buf */

b579_result_t b579_entropy_fill(void *buf, size_t len) 
{
    B579_CHECK_NULL(buf);

    if (len == 0)
    {
        return B579_OK;
    }
    /*
     * arc4random_buf never fails on macOS.
     * Uses the kernel CSPRNG internally.
     */
    arc4random_buf(buf, len);
    return B579_OK;
}

#endif /* B579_OS_MACOS */

/* ══════════════════════════════════════════
 *  FreeBSD Implementation
 * ══════════════════════════════════════════ 
 */

#ifdef B579_OS_FREEBSD

#include <stdlib.h>

b579_result_t b579_entropy_fill(void *buf, size_t len) 
{
    B579_CHECK_NULL(buf);
    if (len == 0) return B579_OK;
    arc4random_buf(buf, len);
    return B579_OK;
}

#endif /* B579_OS_FREEBSD */

/* ══════════════════════════════════════════
 *  Windows Implementation
 * ══════════════════════════════════════════ 
 */

#ifdef B579_OS_WINDOWS

#ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

b579_result_t b579_entropy_fill(void *buf, size_t len) 
{
    B579_CHECK_NULL(buf);

    if (len == 0)
    {
        return B579_OK;
    }
    NTSTATUS status = BCryptGenRandom(NULL,(PUCHAR)buf,(ULONG)len,BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    if (!BCRYPT_SUCCESS(status)) 
    {
        b579_error_set(B579_ERR_IO,"BCryptGenRandom failed: 0x%08lx",(unsigned long)status);
        return B579_ERR_IO;
    }

    return B579_OK;
}

#endif /* B579_OS_WINDOWS */

/* ══════════════════════════════════════════
 *  Convenience Functions (cross-platform)
 * ══════════════════════════════════════════ 
 */

uint64_t b579_entropy_u64(void) 
{
    uint64_t val = 0;
    b579_entropy_fill(&val, sizeof(val));
    return val;
}

uint32_t b579_entropy_u32(void) 
{
    uint32_t val = 0;
    b579_entropy_fill(&val, sizeof(val));
    return val;
}

b579_result_t b579_entropy_siphash_key(b579_siphash_key_t *key) 
{
    B579_CHECK_NULL(key);
    return b579_entropy_fill(key, sizeof(*key));
}
