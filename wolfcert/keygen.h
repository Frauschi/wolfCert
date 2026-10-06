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

/* Generate a new private key according to cfg. cfg->dev_id routes the
 * operations to the CryptoCb backend registered under that devId; with
 * cfg->key_id set as well, the backend generates and keeps the private key
 * under that id and the returned handle only references it. Ed25519 and
 * Ed448 keys cannot take a key_id. cfg->heap (or wolfcert_default_heap() if
 * NULL) is used for the handle's allocs. */
WOLFCERT_API int wolfcert_key_generate(const WolfCertKeyCfg* cfg, WolfCertKey** out_key);

/* Reference a private key that already lives in a CryptoCb backend under
 * cfg->key_id, for example after a reboot. `pub` is the key's public half as
 * a certificate or SubjectPublicKeyInfo, PEM or DER, since a backend need not
 * give it back. A non-zero cfg->param must match its curve or RSA size.
 * Nothing checks that `pub` belongs to the key under key_id. */
WOLFCERT_API int wolfcert_key_from_id(const WolfCertKeyCfg* cfg,
                                      const uint8_t* pub, size_t pub_len,
                                      WolfCertKey** out_key);

/* Load a software key from PEM or raw DER bytes. The encoding is
 * auto-detected, so the same entry point handles both. */
WOLFCERT_API int wolfcert_key_from_pem(const uint8_t* data, size_t data_len,
                                       void* heap, WolfCertKey** out_key);

/* Export a software key as PEM. Fails with WOLFCERT_ERR_UNSUPPORTED for a
 * key with a key_id. */
WOLFCERT_API int wolfcert_key_to_pem(const WolfCertKey* key, WolfCertBuffer* out_pem);

/* Export a software key as raw DER (same export constraints as
 * wolfcert_key_to_pem). */
WOLFCERT_API int wolfcert_key_to_der(const WolfCertKey* key, WolfCertBuffer* out_der);

/* Export the public half as a DER SubjectPublicKeyInfo, including for a key
 * with a key_id. Fails for an ML-DSA key loaded from a PKCS#8 v1 private key,
 * which carries no public half. */
WOLFCERT_API int wolfcert_key_public_to_der(const WolfCertKey* key,
                                            WolfCertBuffer* out_der);

WOLFCERT_API void wolfcert_key_free(WolfCertKey* key);

/* Accessors. wolfcert_key_type returns 0 on NULL. */
WOLFCERT_API WolfCertKeyType wolfcert_key_type(const WolfCertKey* key);
WOLFCERT_API int wolfcert_key_dev_id(const WolfCertKey* key);
/* Points *id at the key's backend id, or NULL with *id_len 0 if it has
 * none. The bytes stay owned by the key. */
WOLFCERT_API int wolfcert_key_id(const WolfCertKey* key, const uint8_t** id,
                                 size_t* id_len);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_KEYGEN_H */
