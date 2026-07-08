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

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <wolfcert/keygen.h>
#include <wolfcert/errors.h>
#include "internal.h"
#include "key_algs.h"

#include <wolfssl/wolfcrypt/memory.h>

#include <string.h>

static WolfCertKey* alloc_shell(WolfCertKeyType type, int dev_id,
                                const char* label, void* heap)
{
    WolfCertKey* k = (WolfCertKey*)WOLFCERT_XMALLOC(sizeof(*k), heap);
    if (k == NULL)
        return NULL;

    memset(k, 0, sizeof(*k));
    k->type   = type;
    k->dev_id = dev_id;
    k->heap   = heap;

    if (label != NULL) {
        k->label = wolfcert_strdup(label, heap);
        if (k->label == NULL) {
            WOLFCERT_XFREE(k, heap);
            return NULL;
        }
    }

    return k;
}

static void free_shell(WolfCertKey* k)
{
    if (k == NULL)
        return;

    const WolfCertKeyAlg* a = wolfcert_key_alg(k->type);
    if (a && a->free_)
        a->free_(k);

    WOLFCERT_XFREE(k->label, k->heap);
    WOLFCERT_XFREE(k, k->heap);
}

int wolfcert_key_generate(const WolfCertKeyCfg* cfg, WolfCertKey** out_key)
{
    if (cfg == NULL || out_key == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    const WolfCertKeyAlg* alg = wolfcert_key_alg(cfg->type);
    if (alg == NULL)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "keygen",
                            "unknown or disabled key type %d", (int)cfg->type);

    void* heap = cfg->heap ? cfg->heap : wolfcert_default_heap();
    WolfCertKey* k = alloc_shell(cfg->type, cfg->dev_id, cfg->key_label, heap);
    if (k == NULL)
        return WOLFCERT_ERR_MEMORY;

    /* Initialize the RNG before the algorithm's backing key struct. Two
     * reasons:
     *   1. We fail fast on a broken RNG without leaking a half-allocated
     *      key handle.
     *   2. ML-DSA's backing key is an 8 KiB struct; generation later
     *      allocates ~28 KiB of scratch. With some glibc versions,
     *      interleaving those mallocs with a small DRBG-state alloc in
     *      between tripped the malloc.c:2599 sysmalloc assertion.
     *      Allocating the DRBG first keeps the heap arena in a state
     *      where the larger dilithium allocations land cleanly.
     */
    WC_RNG rng;
    int rc = wc_InitRng_ex(&rng, heap, cfg->dev_id);
    if (rc != 0) {
        free_shell(k);
        return WOLFCERT_ERR_WC(rc, "keygen", "InitRng");
    }

    rc = alg->alloc_init(k);
    if (rc != WOLFCERT_OK) {
        wc_FreeRng(&rng);
        free_shell(k);
        return rc;
    }

    rc = alg->make(k, cfg, &rng);
    wc_FreeRng(&rng);
    if (rc != WOLFCERT_OK) {
        free_shell(k);
        return rc;
    }

    *out_key = k;
    return WOLFCERT_OK;
}

/* PEM -> DER -> iterate every registered algorithm's priv_decode; first win
 * defines the key type. This lets Ed25519 / Ed448 / ML-DSA slot in simply
 * by adding a row in key_algs.c. */
int wolfcert_key_from_pem(const uint8_t* data, size_t data_len,
                          void* heap, WolfCertKey** out_key)
{
    if (data == NULL || data_len == 0 || out_key == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (heap == NULL)
        heap = wolfcert_default_heap();

    /* The input may be raw DER or PEM. DER feeds the per-algorithm decoders
     * directly; PEM is first run through wc_PemToDer with a sequence of PEM
     * types (first one wolfSSL accepts gives us DER bytes). For ML-DSA we use
     * the canonical FIPS 204 PEM types. */
    static const int pem_try_types[] = {
        PRIVATEKEY_TYPE, ECC_PRIVATEKEY_TYPE
#ifdef WOLFCERT_HAVE_ED25519
        , ED25519_TYPE
#endif
#ifdef WOLFCERT_HAVE_ED448
        , ED448_TYPE
#endif
#ifdef WOLFCERT_HAVE_MLDSA
#ifndef WOLFSSL_NO_ML_DSA_44
        , ML_DSA_44_TYPE
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
        , ML_DSA_65_TYPE
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
        , ML_DSA_87_TYPE
#endif
#endif
    };

    DerBuffer*     der = NULL;       /* owned only when we convert from PEM */
    const uint8_t* der_bytes;
    word32         der_len;

    if (wolfcert_buffer_is_der(data, data_len)) {
        der_bytes = data;
        der_len   = (word32)data_len;
    }
    else {
        int rc = -1;
        for (size_t i = 0; i < sizeof(pem_try_types)/sizeof(pem_try_types[0]); ++i) {
            rc = wc_PemToDer(data, (long)data_len, pem_try_types[i], &der, NULL, NULL, NULL);
            if (rc == 0 && der != NULL && der->buffer != NULL)
                break;

            if (der != NULL) {
                wc_FreeDer(&der);
                der = NULL;
            }
        }

        if (rc != 0 || der == NULL) {
            if (der != NULL)
                wc_FreeDer(&der);
            return WOLFCERT_ERR_PARSE;
        }

        der_bytes = der->buffer;
        der_len   = der->length;
    }

    /* Now try each registered algorithm's private-key DER decoder. */
    const WolfCertKeyAlg* const* list = wolfcert_key_algs_all();
    for (; *list != NULL; ++list) {
        const WolfCertKeyAlg* a = *list;
        WolfCertKey* k = alloc_shell(a->type, WOLFCERT_DEVID_SOFTWARE, NULL, heap);
        if (k == NULL) {
            if (der != NULL)
                wc_FreeDer(&der);
            return WOLFCERT_ERR_MEMORY;
        }

        if (a->alloc_init(k) != WOLFCERT_OK) {
            free_shell(k);
            continue;
        }

        if (a->priv_decode(k, der_bytes, der_len) == WOLFCERT_OK) {
            if (der != NULL)
                wc_FreeDer(&der);
            *out_key = k;
            return WOLFCERT_OK;
        }

        free_shell(k);
    }
    if (der != NULL)
        wc_FreeDer(&der);

    return WOLFCERT_ERR_PARSE;
}

/* Serialize a software key's private DER into a freshly allocated buffer. */
static int key_export_der(const WolfCertKey* key, uint8_t** out_der,
                          int* out_len, void* heap)
{
    const WolfCertKeyAlg* alg = wolfcert_key_alg(key->type);
    if (alg == NULL)
        return WOLFCERT_ERR_UNSUPPORTED;

    size_t der_cap = alg->der_cap_hint;
    if (key->type == WOLFCERT_KEY_RSA) {
        /* DER size grows with modulus; give it head room. */
        size_t bits = key->rsa_bits ? (size_t)key->rsa_bits : 4096;
        der_cap = bits + 2048;
    }

    uint8_t* der = (uint8_t*)WOLFCERT_XMALLOC(der_cap, heap);
    if (der == NULL)
        return WOLFCERT_ERR_MEMORY;

    int der_len = alg->priv_to_der(key, der, (word32)der_cap);
    if (der_len <= 0) {
        wc_ForceZero(der, der_cap);
        WOLFCERT_XFREE(der, heap);
        return WOLFCERT_ERR_WC(der_len, "keygen", "priv_to_der");
    }

    *out_der = der;
    *out_len = der_len;

    return WOLFCERT_OK;
}

int wolfcert_key_to_der(const WolfCertKey* key, WolfCertBuffer* out_der)
{
    if (key == NULL || out_der == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    uint8_t* der = NULL;
    int      der_len = 0;
    int rc = key_export_der(key, &der, &der_len, key->heap);
    if (rc != WOLFCERT_OK)
        return rc;

    out_der->data = der;
    out_der->len  = (size_t)der_len;
    out_der->heap = key->heap;

    return WOLFCERT_OK;
}

int wolfcert_key_to_pem(const WolfCertKey* key, WolfCertBuffer* out_pem)
{
    if (key == NULL || out_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    const WolfCertKeyAlg* alg = wolfcert_key_alg(key->type);
    if (alg == NULL)
        return WOLFCERT_ERR_UNSUPPORTED;

    void* heap = key->heap;
    uint8_t* der = NULL;
    int      der_len = 0;
    int rc = key_export_der(key, &der, &der_len, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    size_t pem_cap = (size_t)der_len * 2 + 256;
    uint8_t* pem = (uint8_t*)WOLFCERT_XMALLOC(pem_cap, heap);
    if (pem == NULL) {
        wc_ForceZero(der, (word32)der_len);
        WOLFCERT_XFREE(der, heap);
        return WOLFCERT_ERR_MEMORY;
    }

    int pem_len = wc_DerToPem(der, (word32)der_len, pem, (word32)pem_cap, alg->pem_type);

    wc_ForceZero(der, (word32)der_len);
    WOLFCERT_XFREE(der, heap);
    if (pem_len <= 0) {
        /* wc_DerToPem may have written partial base64 of the private key
         * before failing, so scrub the buffer before releasing it. */
        wc_ForceZero(pem, (word32)pem_cap);
        WOLFCERT_XFREE(pem, heap);
        return WOLFCERT_ERR_WC(pem_len, "keygen", "DerToPem");
    }

    out_pem->data = pem;
    out_pem->len = (size_t)pem_len;
    out_pem->heap = heap;

    return WOLFCERT_OK;
}

void wolfcert_key_free(WolfCertKey* key)
{
    free_shell(key);
}

WolfCertKeyType wolfcert_key_type(const WolfCertKey* k)
{
    return k ? k->type   : 0;
}

int wolfcert_key_dev_id(const WolfCertKey* k)
{
    return k ? k->dev_id : 0;
}
