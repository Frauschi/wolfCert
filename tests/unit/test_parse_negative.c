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
 * Negative-path tests for the parsers that ingest untrusted bytes:
 * the URL parser, base64 decoder, PKCS#7 certs-only extractor, and CSR
 * PEM->DER path. Each fuzz-style input should produce an error without
 * crashing, reading past the buffer, or allocating unboundedly.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <wolfcert/wolfcert.h>
#include "internal.h"

#include <stdio.h>
#include <string.h>

#if defined(WOLFCERT_HAVE_SCEP) && defined(WOLFCERT_HAVE_RSA)
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#endif

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static int test_url(void)
{
    WolfCertUrl u;
    /* A missing scheme is not an error - it defaults to TLS (see test_http);
     * but a schemeless URL with a bad port is still rejected. */
    REQUIRE(wolfcert_http_url_parse("no-scheme:0/p", &u, NULL) == WOLFCERT_ERR_PARSE);
    /* Empty bracketed IPv6. */
    REQUIRE(wolfcert_http_url_parse("http://[:/p", &u, NULL) == WOLFCERT_ERR_PARSE);
    /* Unknown scheme. */
    REQUIRE(wolfcert_http_url_parse("ftp://x/", &u, NULL) == WOLFCERT_ERR_UNSUPPORTED);
    /* Port out of range. */
    REQUIRE(wolfcert_http_url_parse("http://x:0/", &u, NULL) == WOLFCERT_ERR_PARSE);
    REQUIRE(wolfcert_http_url_parse("http://x:99999/", &u, NULL) == WOLFCERT_ERR_PARSE);
    /* Hostname longer than the cap. */
    char big[400];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    char url[512];
    snprintf(url, sizeof(url), "http://%s/", big);
    REQUIRE(wolfcert_http_url_parse(url, &u, NULL) == WOLFCERT_ERR_PARSE);
    return 0;
}

static int test_base64(void)
{
    WolfCertBuffer out = { 0 };
    /* Garbage chars. */
    const uint8_t bad[] = "!!!!";
    REQUIRE(wolfcert_base64_decode(bad, sizeof(bad) - 1, &out, NULL) != WOLFCERT_OK);
    return 0;
}

#if defined(WOLFCERT_HAVE_EST) || defined(WOLFCERT_HAVE_SCEP)
static int test_pkcs7(void)
{
    /* Zero-length input. */
    WolfCertBuffer out = { 0 };
    REQUIRE(wolfcert_pkcs7_certs_to_pem(NULL, 0, &out, NULL) == WOLFCERT_ERR_BAD_ARG);

    /* Garbage DER. */
    uint8_t buf[32];
    memset(buf, 0xFF, sizeof(buf));
    REQUIRE(wolfcert_pkcs7_certs_to_pem(buf, sizeof(buf), &out, NULL) != WOLFCERT_OK);

    /* Truncated SEQUENCE. */
    uint8_t trunc[] = { 0x30, 0x10, 0x06 };
    REQUIRE(wolfcert_pkcs7_certs_to_pem(trunc, sizeof(trunc), &out, NULL) != WOLFCERT_OK);

    /* certs_only build rejects non-SEQUENCE cert input. */
    const uint8_t junk[8] = { 0x00 };
    const uint8_t* certs[1] = { junk };
    size_t lens[1] = { sizeof(junk) };
    REQUIRE(wolfcert_pkcs7_build_certs_only(certs, lens, 1, &out, NULL)
            == WOLFCERT_ERR_PARSE);
    return 0;
}
#endif

#if defined(WOLFCERT_HAVE_SCEP) && defined(WOLFCERT_HAVE_RSA)
static int oid_present(const uint8_t* hay, size_t hl,
                       const uint8_t* needle, size_t nl)
{
    size_t i;
    if (nl > hl)
        return 0;

    for (i = 0; i + nl <= hl; ++i) {
        if (memcmp(hay + i, needle, nl) == 0)
            return 1;
    }

    return 0;
}

/* The RFC 8894 GetCACaps "AES" keyword advertises AES-128-CBC as the
 * content cipher. wolfcert_scep_envelop must emit exactly the cipher the
 * caller selects, not silently fall back to AES-256-CBC which a
 * minimally-compliant peer cannot decrypt. The non-AES fallback (a peer that
 * does not advertise "AES") selects triple DES-CBC, so verify that DES3b
 * emits the 3DES-CBC OID too. */
static int test_scep_envelop_alg(void)
{
    static const uint8_t OID_AES128_CBC[] =
        { 0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x02 };
    static const uint8_t OID_AES256_CBC[] =
        { 0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2A };
#ifndef NO_DES3
    static const uint8_t OID_DES3_CBC[] =
        { 0x06,0x08,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x03,0x07 };
#endif
    static const uint8_t payload[] = { 0x04, 0x03, 0x61, 0x62, 0x63 };

    RsaKey key;
    WC_RNG rng;
    uint8_t* ra_der = NULL;
    size_t ra_len = 0;
    WolfCertBuffer env = { 0 };

    REQUIRE(wc_InitRng(&rng) == 0);
    REQUIRE(wc_InitRsaKey(&key, NULL) == 0);
    REQUIRE(wc_MakeRsaKey(&key, 2048, 65537L, &rng) == 0);

    REQUIRE(wolfcert_scep_self_signed_rsa(&key, "scep-test",
                                          &ra_der, &ra_len, NULL) == WOLFCERT_OK);

    REQUIRE(wolfcert_scep_envelop(ra_der, ra_len, payload, sizeof(payload),
                                  AES128CBCb, &env, NULL) == WOLFCERT_OK);

    REQUIRE(oid_present(env.data, env.len,
                        OID_AES128_CBC, sizeof(OID_AES128_CBC)));
    REQUIRE(!oid_present(env.data, env.len,
                         OID_AES256_CBC, sizeof(OID_AES256_CBC)));

    wolfcert_buffer_free(&env);

#ifndef NO_DES3
    REQUIRE(wolfcert_scep_envelop(ra_der, ra_len, payload, sizeof(payload),
                                  DES3b, &env, NULL) == WOLFCERT_OK);

    REQUIRE(oid_present(env.data, env.len,
                        OID_DES3_CBC, sizeof(OID_DES3_CBC)));

    wolfcert_buffer_free(&env);
#endif

    WOLFCERT_XFREE(ra_der, NULL);
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    return 0;
}
#endif

static int test_csr_pem(void)
{
    WolfCertBuffer der = { 0 };
    REQUIRE(wolfcert_csr_pem_to_der((const uint8_t*)"not pem", 7, &der) == WOLFCERT_ERR_PARSE);
    return 0;
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);
    if (test_url())
        return 1;
    if (test_base64())
        return 1;
#if defined(WOLFCERT_HAVE_EST) || defined(WOLFCERT_HAVE_SCEP)
    if (test_pkcs7())
        return 1;
#endif
    if (test_csr_pem())
        return 1;
#if defined(WOLFCERT_HAVE_SCEP) && defined(WOLFCERT_HAVE_RSA)
    if (test_scep_envelop_alg())
        return 1;
#endif
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
