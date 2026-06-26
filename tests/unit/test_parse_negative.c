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
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
