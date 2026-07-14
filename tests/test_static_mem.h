/*
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfCert.
 *
 * wolfCert is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfCert is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfCert.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Test helper for WOLFSSL_NO_MALLOC builds. With no dynamic allocator, wolfCert
 * can only allocate from a wolfSSL static-memory pool, so a test loads one and
 * registers it as wolfCert's default heap; every wolfcert_* call then draws
 * from it. On any other build test_static_mem_init() is a no-op. Call it once
 * from a test's main() before wolfcert_init(), so wolfSSL_Init() (invoked by
 * wolfcert_init) and every later NULL-heap allocation draw from the pool.
 */

#ifndef WOLFCERT_TEST_STATIC_MEM_H
#define WOLFCERT_TEST_STATIC_MEM_H

#include <wolfcert/wolfcert.h>

#include <wolfssl/options.h>

#if defined(WOLFSSL_STATIC_MEMORY) && defined(WOLFSSL_NO_MALLOC)

#include <wolfssl/wolfcrypt/memory.h>

/* Sized generously for the unit tests' peak concurrent use (RSA/ECC/ML-DSA
 * keygen, CSR + PKCS7 buffers, and a loopback TLS handshake). wolfSSL's
 * default, feature-aware bucket distribution partitions this buffer; only the
 * total size is tuned here, not the bucket layout. */
static unsigned char g_test_static_pool[4 * 1024 * 1024];
static WOLFSSL_HEAP_HINT* g_test_heap_hint = NULL;

static inline int test_static_mem_init(void)
{
    if (wc_LoadStaticMemory(&g_test_heap_hint, g_test_static_pool,
                            sizeof(g_test_static_pool), WOLFMEM_GENERAL, 1) != 0)
        return -1;
    /* Register the pool as wolfSSL's global heap so wolfSSL_Init() (invoked by
     * wolfcert_init) and any NULL-heap allocation draw from it. Must run before
     * wolfcert_init. */
    wolfSSL_SetGlobalHeapHint(g_test_heap_hint);
    wolfcert_set_default_heap(g_test_heap_hint);
    return 0;
}

#else

static inline int test_static_mem_init(void) { return 0; }

#endif /* WOLFSSL_STATIC_MEMORY && WOLFSSL_NO_MALLOC */

#endif /* WOLFCERT_TEST_STATIC_MEM_H */
