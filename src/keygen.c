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
                                const uint8_t* id, size_t id_len, void* heap)
{
    WolfCertKey* k = (WolfCertKey*)WOLFCERT_XMALLOC(sizeof(*k), heap);
    if (k == NULL)
        return NULL;

    memset(k, 0, sizeof(*k));
    k->type   = type;
    k->dev_id = dev_id;
    k->heap   = heap;

    if (id_len > 0) {
        memcpy(k->id, id, id_len);
        k->id_len = id_len;
    }

    return k;
}

/* A key_id names a key inside a backend, so it needs a devId to reach it. */
static int check_key_id(const WolfCertKeyCfg* cfg)
{
    if (cfg->key_id_len == 0)
        return cfg->key_id == NULL ? WOLFCERT_OK : WOLFCERT_ERR_BAD_ARG;

    if (cfg->key_id == NULL || cfg->key_id_len > WOLFCERT_KEY_ID_MAX_LEN)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "keygen",
                            "key_id must be 1..%d bytes",
                            WOLFCERT_KEY_ID_MAX_LEN);
    if (cfg->dev_id == WOLFCERT_DEVID_SOFTWARE || cfg->dev_id == INVALID_DEVID)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "keygen",
                            "key_id needs a CryptoCb dev_id");

    return WOLFCERT_OK;
}

static void free_shell(WolfCertKey* k)
{
    if (k == NULL)
        return;

    const WolfCertKeyAlg* a = wolfcert_key_alg(k->type);
    if (a && a->free_)
        a->free_(k);

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

    int rc = check_key_id(cfg);
    if (rc != WOLFCERT_OK)
        return rc;

    void* heap = cfg->heap ? cfg->heap : wolfcert_default_heap();
    WolfCertKey* k = alloc_shell(cfg->type, cfg->dev_id, cfg->key_id,
                                 cfg->key_id_len, heap);
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
    rc = wc_InitRng_ex(&rng, heap, cfg->dev_id);
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

    /* wolfCrypt falls back to software keygen when the device declines. */
    if (k->id_len > 0 && alg->host_priv != NULL && alg->host_priv(k)) {
        free_shell(k);
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "keygen",
                            "CryptoCb device %d did not generate the key",
                            cfg->dev_id);
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
        WolfCertKey* k = alloc_shell(a->type, WOLFCERT_DEVID_SOFTWARE, NULL, 0,
                                     heap);
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

static size_t pem_blocks(const uint8_t* in, size_t len)
{
    static const char marker[] = "-----BEGIN ";
    size_t n = 0;

    for (size_t i = 0; i + sizeof(marker) - 1 <= len; i++) {
        if (memcmp(in + i, marker, sizeof(marker) - 1) == 0)
            n++;
    }
    return n;
}

/* Size of the leading DER SEQUENCE including its header, or 0. */
static word32 der_outer_len(const uint8_t* in, word32 len)
{
    word32 idx = 1;
    int    body = 0;

    if (len < 2 || in[0] != 0x30 || GetLength(in, &idx, &body, len) < 0)
        return 0;
    return idx + (word32)body;
}

/* SubjectPublicKeyInfo DER from a certificate or a public key, PEM or DER,
 * into a fresh buffer. */
static int pub_to_spki(const uint8_t* in, size_t in_len, void* heap,
                       uint8_t** out, word32* out_len)
{
    DerBuffer*     der = NULL;
    const uint8_t* src = in;
    word32         src_len = (word32)in_len;
    uint8_t*       spki;
    word32         spki_len = 0;
    int            rc;

    if (!wolfcert_buffer_is_der(in, in_len)) {
        if (pem_blocks(in, in_len) != 1)
            return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "keygen",
                                "pass exactly one certificate or public key");
        rc = wc_PemToDer(in, (long)in_len, CERT_TYPE, &der, heap, NULL, NULL);
        if (rc != 0) {
            wc_FreeDer(&der);
            rc = wc_PemToDer(in, (long)in_len, PUBLICKEY_TYPE, &der, heap,
                             NULL, NULL);
        }
        if (rc != 0) {
            wc_FreeDer(&der);
            return WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "keygen",
                                "public key is neither a certificate nor "
                                "a PUBLIC KEY PEM");
        }
        src     = der->buffer;
        src_len = der->length;
    }

    if (der_outer_len(src, src_len) != src_len) {
        wc_FreeDer(&der);
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "keygen",
                            "pass exactly one certificate or public key");
    }

    int is_cert = wc_GetSubjectPubKeyInfoDerFromCert(src, src_len, NULL,
                                                     &spki_len) == 0 &&
                  spki_len > 0;
    if (!is_cert)
        spki_len = src_len;

    spki = (uint8_t*)WOLFCERT_XMALLOC(spki_len, heap);
    if (spki == NULL) {
        wc_FreeDer(&der);
        return WOLFCERT_ERR_MEMORY;
    }

    rc = 0;
    if (is_cert)
        rc = wc_GetSubjectPubKeyInfoDerFromCert(src, src_len, spki, &spki_len);
    else
        memcpy(spki, src, spki_len);
    wc_FreeDer(&der);
    if (rc != 0) {
        WOLFCERT_XFREE(spki, heap);
        return WOLFCERT_ERR_WC(rc, "keygen", "GetSubjectPubKeyInfoDerFromCert");
    }

    *out     = spki;
    *out_len = spki_len;
    return WOLFCERT_OK;
}

/* A non-zero param must name the curve or RSA size the public key has, and
 * an RSA key must have a size keygen would make. */
static int check_param(const WolfCertKey* k, int param)
{
    if (k->type == WOLFCERT_KEY_RSA && !wolfcert_rsa_bits_ok(k->rsa_bits))
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "keygen",
                            "RSA-%d is not 2048, 3072 or 4096", k->rsa_bits);
    if (param == 0)
        return WOLFCERT_OK;
    if (k->type == WOLFCERT_KEY_RSA && k->rsa_bits != param)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "keygen",
                            "public key is RSA-%d, not RSA-%d",
                            k->rsa_bits, param);
#ifdef WOLFCERT_HAVE_ECC
    int curve = 0, ksize = 0;
    if (k->type == WOLFCERT_KEY_ECC &&
        (wolfcert_ecc_curve_from_param(param, &curve, &ksize) != WOLFCERT_OK ||
         curve != k->curve_id))
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "keygen",
                            "public key is not on the curve param %d names",
                            param);
#endif
    return WOLFCERT_OK;
}

int wolfcert_key_from_id(const WolfCertKeyCfg* cfg,
                         const uint8_t* pub, size_t pub_len,
                         WolfCertKey** out_key)
{
    if (cfg == NULL || cfg->key_id_len == 0 || pub == NULL || pub_len == 0 ||
        out_key == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    int rc = check_key_id(cfg);
    if (rc != WOLFCERT_OK)
        return rc;

    const WolfCertKeyAlg* alg = wolfcert_key_alg(cfg->type);
    if (alg == NULL || alg->pub_decode == NULL)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "keygen",
                            "key type %d cannot take a key_id", (int)cfg->type);

    void* heap = cfg->heap ? cfg->heap : wolfcert_default_heap();
    uint8_t* spki = NULL;
    word32   spki_len = 0;
    rc = pub_to_spki(pub, pub_len, heap, &spki, &spki_len);
    if (rc != WOLFCERT_OK)
        return rc;

    WolfCertKey* k = alloc_shell(cfg->type, cfg->dev_id, cfg->key_id,
                                 cfg->key_id_len, heap);
    if (k == NULL) {
        WOLFCERT_XFREE(spki, heap);
        return WOLFCERT_ERR_MEMORY;
    }

    rc = alg->alloc_init(k);
    if (rc == WOLFCERT_OK)
        rc = alg->pub_decode(k, spki, spki_len);
    WOLFCERT_XFREE(spki, heap);
    if (rc == WOLFCERT_OK)
        rc = check_param(k, cfg->param);
    if (rc != WOLFCERT_OK) {
        free_shell(k);
        return rc;
    }

    *out_key = k;
    return WOLFCERT_OK;
}

/* Serialize a software key's private DER into a freshly allocated buffer. */
int wolfcert_key_export_der(const WolfCertKey* key, uint8_t** out_der,
                            int* out_len, void* heap)
{
    const WolfCertKeyAlg* alg = wolfcert_key_alg(key->type);
    if (alg == NULL)
        return WOLFCERT_ERR_UNSUPPORTED;
    if (key->id_len > 0)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "keygen",
                            "the private key stays in CryptoCb device %d",
                            key->dev_id);

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
    int rc = wolfcert_key_export_der(key, &der, &der_len, key->heap);
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
    int rc = wolfcert_key_export_der(key, &der, &der_len, heap);
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

int wolfcert_key_public_to_der(const WolfCertKey* key, WolfCertBuffer* out_der)
{
    if (key == NULL || out_der == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    const WolfCertKeyAlg* alg = wolfcert_key_alg(key->type);
    if (alg == NULL || alg->pub_to_der == NULL)
        return WOLFCERT_ERR_UNSUPPORTED;

    /* The private-key cap bounds the public encoding too. */
    size_t cap = alg->der_cap_hint;
    if (key->type == WOLFCERT_KEY_RSA)
        cap = (key->rsa_bits ? (size_t)key->rsa_bits : 4096) + 2048;

    uint8_t* der = (uint8_t*)WOLFCERT_XMALLOC(cap, key->heap);
    if (der == NULL)
        return WOLFCERT_ERR_MEMORY;

    int len = alg->pub_to_der(key, der, (word32)cap);
    if (len <= 0) {
        WOLFCERT_XFREE(der, key->heap);
        return WOLFCERT_ERR_WC(len, "keygen", "pub_to_der");
    }

    out_der->data = der;
    out_der->len  = (size_t)len;
    out_der->heap = key->heap;

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

int wolfcert_key_id(const WolfCertKey* k, const uint8_t** id, size_t* id_len)
{
    if (k == NULL || id == NULL || id_len == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    *id     = k->id_len > 0 ? k->id : NULL;
    *id_len = k->id_len;
    return WOLFCERT_OK;
}
