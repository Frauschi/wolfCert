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
 * Heap-hint allocation macros. By default they expand to wolfSSL's XMALLOC
 * family, so wolfCert shares the application's wolfSSL heap or static pool.
 */

#ifndef WOLFCERT_MEMORY_H
#define WOLFCERT_MEMORY_H

#include <stddef.h>

#include <wolfcert/api.h>
#include <wolfcert/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(WOLFCERT_CUSTOM_ALLOC)
  /* The application defines WOLFCERT_XMALLOC, WOLFCERT_XREALLOC and
   * WOLFCERT_XFREE. */
#else
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
