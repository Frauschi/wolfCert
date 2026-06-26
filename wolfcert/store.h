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

#ifndef WOLFCERT_STORE_H
#define WOLFCERT_STORE_H

#include <wolfcert/types.h>
#include <wolfcert/keygen.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- pluggable storage backend -----------------------------------------
 *
 * wolfCert doesn't own your persistence: an embedded build stores certs
 * and keys in flash slots, a Linux build writes POSIX files, a test uses
 * an in-memory map. A backend is a small vtable plus an opaque context;
 * slots within a backend are addressed by caller-defined string keys
 * (e.g. "device.crt", "slot/3", "tpm:/handles/0x01800001"). */

typedef struct {
    /* Read the value associated with `key` into a freshly allocated buffer.
     * Return WOLFCERT_OK on success; WOLFCERT_ERR_NOT_FOUND if absent. */
    int  (*read) (void* ctx, const char* key, WolfCertBuffer* out);
    /* Write/replace `key` atomically. `sensitive` hints that the value is
     * secret and backends should enforce tight access modes. */
    int  (*write)(void* ctx, const char* key,
                  const uint8_t* data, size_t len, int sensitive);
    /* Remove `key` if present; not-an-error if already absent. */
    int  (*remove)(void* ctx, const char* key);
    /* Heap hint forwarded into wolfcert allocations done by the backend. */
    void* heap;
    /* Backend-private state. */
    void* ctx;
} WolfCertStoreOps;

/* Default POSIX-file backend. `root_dir` is prepended to every key and
 * must exist. Keys may contain '/' to create nested paths. Safe to
 * wolfcert_free() when the backend is no longer needed. Returns NULL on
 * host platforms that lack POSIX file I/O. */
WOLFCERT_API WolfCertStoreOps* wolfcert_store_posix_open(const char* root_dir,
                                                         void* heap);
WOLFCERT_API void wolfcert_store_posix_close(WolfCertStoreOps* ops);

/* In-memory backend, useful for tests and for hosts where the application
 * drives its own persistence (e.g. an MCU that wraps wolfCert's output
 * with its own flash-slot code). */
WOLFCERT_API WolfCertStoreOps* wolfcert_store_memory_open(void* heap);
WOLFCERT_API void wolfcert_store_memory_close(WolfCertStoreOps* ops);

/* ---- high-level cert / key helpers -------------------------------------- */

WOLFCERT_API int wolfcert_store_write_cert(WolfCertStoreOps* store,
                                           const char* key,
                                           const uint8_t* cert, size_t len);
WOLFCERT_API int wolfcert_store_read_cert(WolfCertStoreOps* store,
                                          const char* key,
                                          WolfCertBuffer* out);

WOLFCERT_API int wolfcert_store_write_key(WolfCertStoreOps* store,
                                          const char* key_name,
                                          const WolfCertKey* key);
WOLFCERT_API int wolfcert_store_read_key(WolfCertStoreOps* store,
                                         const char* key_name,
                                         WolfCertKey** out_key);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_STORE_H */
