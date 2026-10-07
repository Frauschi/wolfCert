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

#ifndef WOLFCERT_KEYGEN_H
#define WOLFCERT_KEYGEN_H

#include <wolfcert/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WolfCertKey WolfCertKey;

/* Generate a key per cfg. With cfg->dev_id != -1 the key lives in the
 * CryptoCb backend registered under that id and the handle only references
 * it. The handle is allocated from cfg->heap, or the default heap if NULL. */
WOLFCERT_API int wolfcert_key_generate(const WolfCertKeyCfg* cfg, WolfCertKey** out_key);

/* Load a software key from PEM or DER; the encoding is auto-detected. */
WOLFCERT_API int wolfcert_key_from_pem(const uint8_t* data, size_t data_len,
                                       void* heap, WolfCertKey** out_key);

/* Export a software key as PEM. Fails for keys that live behind a CryptoCb
 * that does not permit export. */
WOLFCERT_API int wolfcert_key_to_pem(const WolfCertKey* key, WolfCertBuffer* out_pem);

/* Export a software key as raw DER (same export constraints as
 * wolfcert_key_to_pem). */
WOLFCERT_API int wolfcert_key_to_der(const WolfCertKey* key, WolfCertBuffer* out_der);

WOLFCERT_API void wolfcert_key_free(WolfCertKey* key);

/* Accessors. wolfcert_key_type returns 0 on NULL. */
WOLFCERT_API WolfCertKeyType wolfcert_key_type(const WolfCertKey* key);
WOLFCERT_API int wolfcert_key_dev_id(const WolfCertKey* key);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_KEYGEN_H */
