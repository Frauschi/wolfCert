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

#include <wolfcert/wolfcert.h>
#include "../test_static_mem.h"

#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <stdio.h>
#include <string.h>

#ifdef WOLFCERT_HAVE_ECC
    #define TEST_KEY_TYPE        WOLFCERT_KEY_ECC
    #define TEST_KEY_PARAM       256
    #define TEST_KEY_PARAM_OTHER 384
#else
    #define TEST_KEY_TYPE        WOLFCERT_KEY_RSA
    #define TEST_KEY_PARAM       2048
    #define TEST_KEY_PARAM_OTHER 3072
#endif

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static int roundtrip(WolfCertKeyType type, int param)
{
    WolfCertKeyCfg cfg = { .type = type, .param = param,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* k = NULL;
    REQUIRE(wolfcert_key_generate(&cfg, &k) == WOLFCERT_OK);
    REQUIRE(k != NULL);

    WolfCertBuffer pem = { 0 };
    REQUIRE(wolfcert_key_to_pem(k, &pem) == WOLFCERT_OK);
    REQUIRE(pem.len > 0);
    REQUIRE(memchr(pem.data, '-', pem.len) != NULL);

    WolfCertKey* k2 = NULL;
    REQUIRE(wolfcert_key_from_pem(pem.data, pem.len, NULL, &k2) == WOLFCERT_OK);
    REQUIRE(k2 != NULL);

    /* DER export + auto-detected DER re-import (wolfcert_key_from_pem accepts
     * either encoding). DER starts with an ASN.1 SEQUENCE tag. */
    WolfCertBuffer der = { 0 };
    REQUIRE(wolfcert_key_to_der(k, &der) == WOLFCERT_OK);
    REQUIRE(der.len > 0);
    REQUIRE(der.data[0] == 0x30);

    WolfCertKey* k3 = NULL;
    REQUIRE(wolfcert_key_from_pem(der.data, der.len, NULL, &k3) == WOLFCERT_OK);
    REQUIRE(k3 != NULL);

    /* A reloaded key exports the same public half; ML-DSA's PKCS#8 v1 form
     * carries none. */
    const uint8_t* id = (const uint8_t*)"x";
    size_t id_len = 1;
    REQUIRE(wolfcert_key_id(k, &id, &id_len) == WOLFCERT_OK);
    REQUIRE(id == NULL && id_len == 0);
    WolfCertBuffer pub = { 0 };
    WolfCertBuffer pub2 = { 0 };
    REQUIRE(wolfcert_key_public_to_der(k, &pub) == WOLFCERT_OK);
    if (type < WOLFCERT_KEY_MLDSA44) {
        REQUIRE(wolfcert_key_public_to_der(k2, &pub2) == WOLFCERT_OK);
        REQUIRE(pub2.len == pub.len &&
                memcmp(pub2.data, pub.data, pub.len) == 0);
    }
    wolfcert_buffer_free(&pub2);
    wolfcert_buffer_free(&pub);

    wolfcert_buffer_free(&pem);
    wolfcert_buffer_free(&der);
    wolfcert_key_free(k);
    wolfcert_key_free(k2);
    wolfcert_key_free(k3);
    return 0;
}

#define DECLINE_DEVID 0x6b69

static int decline_cb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)info;
    (void)ctx;
    return CRYPTOCB_UNAVAILABLE;
}

/* A device that declines keygen leaves wolfCrypt to generate in software,
 * which a key_id must refuse. */
static int key_id_declined(WolfCertKeyType type, int param)
{
    static const uint8_t id[] = { 0x01, 0x02 };
    WolfCertKeyCfg cfg = { .type = type, .param = param,
                           .dev_id = DECLINE_DEVID,
                           .key_id = id, .key_id_len = sizeof(id) };
    WolfCertKey* k = NULL;

    REQUIRE(wolfcert_key_generate(&cfg, &k) == WOLFCERT_ERR_UNSUPPORTED);
    REQUIRE(k == NULL);
    return 0;
}

#if defined(WOLFCERT_HAVE_MLDSA) && !defined(WOLFSSL_NO_ML_DSA_44)
static int key_id_mldsa(void)
{
    static const uint8_t id[] = { 0x03 };
    WolfCertKeyCfg sw = { .type = WOLFCERT_KEY_MLDSA44,
                          .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKeyCfg cfg = { .type = WOLFCERT_KEY_MLDSA44,
                           .dev_id = DECLINE_DEVID,
                           .key_id = id, .key_id_len = sizeof(id) };
    WolfCertKey* soft = NULL;
    WolfCertKey* k = NULL;
    WolfCertBuffer pub = { 0 };
    WolfCertBuffer pub2 = { 0 };

    REQUIRE(wolfcert_key_generate(&sw, &soft) == WOLFCERT_OK);
    REQUIRE(wolfcert_key_public_to_der(soft, &pub) == WOLFCERT_OK);
    REQUIRE(wolfcert_key_from_id(&cfg, pub.data, pub.len, &k) == WOLFCERT_OK);
    REQUIRE(wolfcert_key_public_to_der(k, &pub2) == WOLFCERT_OK);
    REQUIRE(pub2.len == pub.len && memcmp(pub2.data, pub.data, pub.len) == 0);
    wolfcert_key_free(k);
    k = NULL;
#ifndef WOLFSSL_NO_ML_DSA_65
    cfg.type = WOLFCERT_KEY_MLDSA65;
    REQUIRE(wolfcert_key_from_id(&cfg, pub.data, pub.len, &k) != WOLFCERT_OK);
    REQUIRE(k == NULL);
#endif

    wolfcert_buffer_free(&pub2);
    wolfcert_buffer_free(&pub);
    wolfcert_key_free(soft);
    return 0;
}
#endif

static int key_id_cases(void)
{
    static const uint8_t id[] = { 0x01, 0x02 };
    static const uint8_t junk[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    WolfCertKey* k = NULL;

    REQUIRE(wc_CryptoCb_RegisterDevice(DECLINE_DEVID, decline_cb, NULL) == 0);
    WolfCertKeyCfg cfg = { .type = TEST_KEY_TYPE, .param = TEST_KEY_PARAM,
                           .dev_id = INVALID_DEVID,
                           .key_id = id, .key_id_len = sizeof(id) };
    REQUIRE(wolfcert_key_generate(&cfg, &k) == WOLFCERT_ERR_BAD_ARG);

    if (key_id_declined(TEST_KEY_TYPE, TEST_KEY_PARAM))
        return 1;
#if defined(WOLFCERT_HAVE_MLDSA) && !defined(WOLFSSL_NO_ML_DSA_44)
    if (key_id_declined(WOLFCERT_KEY_MLDSA44, 0))
        return 1;
#endif

    /* from_id: argument errors, then a public key from a software key. */
    WolfCertKeyCfg sw = { .type = TEST_KEY_TYPE, .param = TEST_KEY_PARAM,
                          .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* soft = NULL;
    WolfCertBuffer pub = { 0 };
    REQUIRE(wolfcert_key_generate(&sw, &soft) == WOLFCERT_OK);
    REQUIRE(wolfcert_key_public_to_der(soft, &pub) == WOLFCERT_OK);

    cfg.dev_id = DECLINE_DEVID;
    cfg.key_id_len = 0;
    REQUIRE(wolfcert_key_from_id(&cfg, pub.data, pub.len, &k) ==
            WOLFCERT_ERR_BAD_ARG);
    cfg.key_id_len = sizeof(id);
    REQUIRE(wolfcert_key_from_id(&cfg, junk, sizeof(junk), &k) ==
            WOLFCERT_ERR_PARSE);
    REQUIRE(wolfcert_key_from_id(&cfg, pub.data, pub.len, &k) == WOLFCERT_OK);
    WolfCertBuffer pub2 = { 0 };
    REQUIRE(wolfcert_key_public_to_der(k, &pub2) == WOLFCERT_OK);
    REQUIRE(pub2.len == pub.len && memcmp(pub2.data, pub.data, pub.len) == 0);
    WolfCertBuffer priv = { 0 };
    REQUIRE(wolfcert_key_to_der(k, &priv) == WOLFCERT_ERR_UNSUPPORTED);
    wolfcert_buffer_free(&pub2);
    wolfcert_key_free(k);
    k = NULL;

    /* The same key as a PUBLIC KEY PEM; two blocks or trailing bytes are
     * refused. */
    uint8_t pem[1024];
    uint8_t two[2048];
    int pem_len = wc_DerToPem(pub.data, (word32)pub.len, pem, sizeof(pem),
                              PUBLICKEY_TYPE);
    REQUIRE(pem_len > 0);
    REQUIRE(wolfcert_key_from_id(&cfg, pem, (size_t)pem_len, &k) ==
            WOLFCERT_OK);
    wolfcert_key_free(k);
    k = NULL;
    memcpy(two, pem, (size_t)pem_len);
    memcpy(two + pem_len, pem, (size_t)pem_len);
    REQUIRE(wolfcert_key_from_id(&cfg, two, 2 * (size_t)pem_len, &k) ==
            WOLFCERT_ERR_BAD_ARG);
    memcpy(two, pub.data, pub.len);
    two[pub.len] = 0;
    REQUIRE(wolfcert_key_from_id(&cfg, two, pub.len + 1, &k) ==
            WOLFCERT_ERR_BAD_ARG);
    pem_len = wc_DerToPem(two, (word32)pub.len + 1, pem, sizeof(pem),
                          PUBLICKEY_TYPE);
    REQUIRE(pem_len > 0);
    REQUIRE(wolfcert_key_from_id(&cfg, pem, (size_t)pem_len, &k) ==
            WOLFCERT_ERR_BAD_ARG);

    cfg.param = TEST_KEY_PARAM_OTHER;
    REQUIRE(wolfcert_key_from_id(&cfg, pub.data, pub.len, &k) ==
            WOLFCERT_ERR_BAD_ARG);
#ifdef WOLFCERT_HAVE_RSA
    /* With param 0, a reload still refuses an RSA size keygen would not
     * make: an RSA-1024 SubjectPublicKeyInfo. */
    {
        static const uint8_t weak[] = {
            0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00,
            0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xae, 0xfa, 0xa4, 0x2b,
            0x75, 0x03, 0x2c, 0xcc, 0x13, 0x26, 0xae, 0x65, 0x81, 0x99, 0x1e,
            0x08, 0x02, 0x72, 0x4b, 0x9e, 0xb9, 0x7e, 0x16, 0x9e, 0x79, 0x77,
            0x69, 0x25, 0xcd, 0x9e, 0xd5, 0x66, 0xb5, 0x2a, 0x7f, 0x5d, 0xfb,
            0x35, 0x00, 0xb5, 0x3b, 0x0c, 0x7d, 0xba, 0xaa, 0xcb, 0xc9, 0x5f,
            0x77, 0xa2, 0x8d, 0xfc, 0x6c, 0x63, 0xf8, 0x11, 0x1b, 0xd5, 0xf6,
            0x9f, 0xf3, 0x45, 0x00, 0x49, 0xad, 0xff, 0x5d, 0x3e, 0x03, 0xbd,
            0x69, 0xd0, 0x02, 0x98, 0x98, 0xaf, 0x80, 0x34, 0xcb, 0x8b, 0x3e,
            0xa1, 0x36, 0xcb, 0x73, 0x8b, 0x58, 0xe5, 0xde, 0xae, 0x3a, 0x19,
            0x71, 0xcb, 0xf9, 0x94, 0x02, 0x22, 0xed, 0x48, 0x96, 0x8c, 0x28,
            0xba, 0x42, 0xcc, 0x95, 0x2a, 0x6c, 0x25, 0x81, 0x91, 0x9f, 0xd8,
            0xf4, 0x15, 0x95, 0x67, 0xa5, 0xa0, 0x0d, 0x81, 0x97, 0x28, 0xa1,
            0x08, 0x49, 0x5f, 0x02, 0x03, 0x01, 0x00, 0x01,
        };
        WolfCertKeyCfg rcfg = { .type = WOLFCERT_KEY_RSA,
                                .dev_id = DECLINE_DEVID,
                                .key_id = id, .key_id_len = sizeof(id) };

        REQUIRE(wolfcert_key_from_id(&rcfg, weak, sizeof(weak), &k) ==
                WOLFCERT_ERR_BAD_ARG);
    }
#endif
#ifdef WOLFCERT_HAVE_ED25519
    cfg.type = WOLFCERT_KEY_ED25519;
    cfg.param = 0;
    REQUIRE(wolfcert_key_from_id(&cfg, pub.data, pub.len, &k) ==
            WOLFCERT_ERR_UNSUPPORTED);
#endif
    REQUIRE(k == NULL);

    wolfcert_buffer_free(&pub);
    wolfcert_key_free(soft);
#if defined(WOLFCERT_HAVE_MLDSA) && !defined(WOLFSSL_NO_ML_DSA_44)
    if (key_id_mldsa())
        return 1;
#endif
    wc_CryptoCb_UnRegisterDevice(DECLINE_DEVID);
    return 0;
}

int main(void)
{
    REQUIRE(test_static_mem_init() == 0);
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);
#ifdef WOLFCERT_HAVE_ECC
    if (roundtrip(WOLFCERT_KEY_ECC, 256))
        return 1;
    if (roundtrip(WOLFCERT_KEY_ECC, 384))
        return 1;
#endif
#ifdef WOLFCERT_HAVE_RSA
    if (roundtrip(WOLFCERT_KEY_RSA, 2048))
        return 1;
#endif
#ifdef WOLFCERT_HAVE_ED25519
    if (roundtrip(WOLFCERT_KEY_ED25519, 0))
        return 1;
#endif
#ifdef WOLFCERT_HAVE_ED448
    if (roundtrip(WOLFCERT_KEY_ED448, 0))
        return 1;
#endif
#ifdef WOLFCERT_HAVE_MLDSA
    /* Each ML-DSA level can be disabled independently in wolfSSL
     * (WOLFSSL_NO_ML_DSA_{44,65,87}); only exercise the ones present. */
#ifndef WOLFSSL_NO_ML_DSA_44
    if (roundtrip(WOLFCERT_KEY_MLDSA44, 0))
        return 1;
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
    if (roundtrip(WOLFCERT_KEY_MLDSA65, 0))
        return 1;
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
    if (roundtrip(WOLFCERT_KEY_MLDSA87, 0))
        return 1;
#endif
#else
    /* Runtime rejection when the wolfSSL build lacks Dilithium. */
    {
        WolfCertKeyCfg cfg = { .type = WOLFCERT_KEY_MLDSA44, .param = 0,
                               .dev_id = WOLFCERT_DEVID_SOFTWARE };
        WolfCertKey* k = NULL;
        REQUIRE(wolfcert_key_generate(&cfg, &k) == WOLFCERT_ERR_UNSUPPORTED);
    }
#endif

    if (key_id_cases())
        return 1;

    WolfCertKeyCfg bad = { .type = WOLFCERT_KEY_ECC, .param = 123,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* k = NULL;
    REQUIRE(wolfcert_key_generate(&bad, &k) != WOLFCERT_OK);

    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
