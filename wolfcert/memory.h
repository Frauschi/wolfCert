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

/**
 * @file memory.h
 * Heap-hint based memory allocation for wolfCert.
 *
 * All dynamic allocation in wolfCert goes through these macros so that an
 * application can route every byte through a wolfSSL static-memory pool or
 * a custom allocator. The semantics match wolfSSL's XMALLOC/XFREE/XREALLOC:
 * each call takes an opaque `heap` hint that the backing allocator can
 * interpret any way it likes (wolfSSL static memory uses it to select a
 * bucket; host builds ignore it).
 *
 * By default (`WOLFCERT_USE_WOLFSSL_HEAP` set at build time, which is the
 * case for every supported wolfSSL build) the macros expand to wolfSSL's
 * own XMALLOC/XFREE so wolfCert shares exactly the pool that the rest of
 * the application's wolfSSL code uses. When wolfSSL's static-memory option
 * is enabled the pool is hard-capped; wolfCert will honour that limit
 * instead of silently reaching past it with raw libc malloc.
 *
 * Callers that want to pin wolfCert's allocations to a specific heap
 * register the hint through wolfcert_set_default_heap(); individual APIs
 * also accept an explicit `heap` where the allocation needs to outlive
 * the default.
 */

#ifndef WOLFCERT_MEMORY_H
#define WOLFCERT_MEMORY_H

#include <stddef.h>

#include <wolfcert/api.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Pluggable allocator. If the application doesn't override it, we use
 * wolfSSL's XMALLOC family which in turn respects WOLFSSL_STATIC_MEMORY.
 * Embedded integrators that build wolfCert with WOLFCERT_NO_MALLOC can
 * replace the macros at compile time. */
#if defined(WOLFCERT_CUSTOM_ALLOC)
  /* Project defines these macros externally. */
#else
#  include <wolfssl/options.h>
#  include <wolfssl/wolfcrypt/types.h>
#  define WOLFCERT_XMALLOC(sz, heap)        XMALLOC((sz),  (heap), DYNAMIC_TYPE_TMP_BUFFER)
#  define WOLFCERT_XREALLOC(p, sz, heap)    XREALLOC((p), (sz), (heap), DYNAMIC_TYPE_TMP_BUFFER)
#  define WOLFCERT_XFREE(p, heap)           XFREE((p),    (heap), DYNAMIC_TYPE_TMP_BUFFER)
#endif

/* Strdup over the heap hint. Returns NULL if `s` is NULL or on allocation
 * failure. Free with WOLFCERT_XFREE(..., heap). */
WOLFCERT_API char* wolfcert_strdup(const char* s, void* heap);

/* Global default heap hint. Pass NULL to restore the library default. */
WOLFCERT_API void wolfcert_set_default_heap(void* heap);
WOLFCERT_API void* wolfcert_default_heap(void);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_MEMORY_H */
