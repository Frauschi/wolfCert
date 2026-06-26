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
 * Degenerate (certs-only) PKCS#7 / CMS SignedData helpers:
 *   - extract certificates from a certs-only SignedData blob, returning them
 *     concatenated as PEM or DER.
 *   - build a certs-only SignedData around a set of DER certificates.
 *
 * Both directions go through wolfSSL's wc_PKCS7 API: extraction via
 * wc_PKCS7_VerifySignedData(), encoding via a DEGENERATE_SID SignedData
 * (wc_PKCS7_EncodeSignedData() with no signer). Heap hints thread through for
 * wolfSSL static-memory builds.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "internal.h"
#include <wolfcert/errors.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <stdint.h>
#include <string.h>

/* ---- certs-only (degenerate) SignedData extraction --------------------- *
 *
 * wc_PKCS7_VerifySignedData validates the structure and populates
 * pkcs7->cert[] / certSz[]. The bundles we parse are degenerate certs-only
 * SignedData, so there is no signature to verify. */

/* Append `n` bytes to a growable WolfCertBuffer. */
static int acc_append(WolfCertBuffer* acc, size_t* cap, const uint8_t* data,
                      size_t n, void* heap)
{
    if (acc->len + n > *cap) {
        size_t nc = *cap ? *cap : 2048;
        while (nc < acc->len + n)
            nc *= 2;

        uint8_t* nb = (uint8_t*)WOLFCERT_XREALLOC(acc->data, nc, heap);
        if (nb == NULL)
            return WOLFCERT_ERR_MEMORY;

        acc->data = nb;
        *cap = nc;
    }

    memcpy(acc->data + acc->len, data, n);
    acc->len += n;

    return WOLFCERT_OK;
}

/* Append one certificate to `acc`, either as raw DER or PEM-encoded. */
static int append_cert(WolfCertBuffer* acc, size_t* cap, const uint8_t* der,
                       word32 der_len, int as_pem, void* heap)
{
    if (!as_pem)
        return acc_append(acc, cap, der, der_len, heap);

    size_t pem_cap = (size_t)der_len * 2 + 256;
    uint8_t* pem = (uint8_t*)WOLFCERT_XMALLOC(pem_cap, heap);
    if (pem == NULL)
        return WOLFCERT_ERR_MEMORY;

    int n = wc_DerToPem(der, der_len, pem, (word32)pem_cap, CERT_TYPE);
    if (n <= 0) {
        WOLFCERT_XFREE(pem, heap);
        return WOLFCERT_ERR_CRYPTO;
    }

    int rc = acc_append(acc, cap, pem, (size_t)n, heap);
    WOLFCERT_XFREE(pem, heap);

    return rc;
}

static int pkcs7_certs_extract(const uint8_t* p7_der, size_t p7_der_len,
                               WolfCertBuffer* out, void* heap, int as_pem)
{
    if (p7_der == NULL || p7_der_len == 0 || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    PKCS7* p7 = wc_PKCS7_New(heap, WOLFCERT_DEVID_SOFTWARE);
    if (p7 == NULL)
        return WOLFCERT_ERR_MEMORY;

    int rc = wc_PKCS7_VerifySignedData(p7, (byte*)p7_der, (word32)p7_der_len);
    if (rc != 0) {
        wc_PKCS7_Free(p7);
        return WOLFCERT_ERR_WC(rc, "pkcs7", "VerifySignedData");
    }

    WolfCertBuffer acc = { .heap = heap };
    size_t cap = 0;

    for (int i = 0; i < MAX_PKCS7_CERTS; ++i) {
        if (p7->cert[i] == NULL || p7->certSz[i] == 0)
            continue;

        rc = append_cert(&acc, &cap, p7->cert[i], p7->certSz[i], as_pem, heap);
        if (rc != WOLFCERT_OK) {
            WOLFCERT_XFREE(acc.data, heap);
            wc_PKCS7_Free(p7);
            return rc;
        }
    }

    wc_PKCS7_Free(p7);
    if (acc.len == 0) {
        WOLFCERT_XFREE(acc.data, heap);
        return WOLFCERT_ERR_NOT_FOUND;
    }

    *out = acc;
    return WOLFCERT_OK;
}

WOLFCERT_TEST_VIS int wolfcert_pkcs7_certs_to_pem(const uint8_t* p7_der,
    size_t p7_der_len, WolfCertBuffer* out_pem, void* heap)
{
    return pkcs7_certs_extract(p7_der, p7_der_len, out_pem, heap, 1);
}

WOLFCERT_TEST_VIS int wolfcert_pkcs7_certs_to_der(const uint8_t* p7_der,
    size_t p7_der_len, WolfCertBuffer* out_der, void* heap)
{
    return pkcs7_certs_extract(p7_der, p7_der_len, out_der, heap, 0);
}

/* ---- degenerate (certs-only) SignedData encoder ------------------------ *
 *
 * Driven through the public wc_PKCS7 API: a DEGENERATE_SID SignedData with no
 * signer, attributes or eContent (hashOID left 0). Certificates are loaded with
 * wc_PKCS7_AddCertificate() and emitted as the certs SET by
 * wc_PKCS7_EncodeSignedData(). We deliberately avoid wc_PKCS7_InitWithCert():
 * it parses the cert and sets pkcs7->publicKeyOID, which makes the encoder's
 * signer-path validation reject ECDSA/RSA-PSS certs (it demands a pre-computed
 * content hash) even though a degenerate bundle has no signer at all. */

/* Light validation: every cert DER must start with SEQUENCE tag 0x30. The full
 * decode happens inside wolfSSL; this just gives a stable WOLFCERT_ERR_PARSE for
 * obviously non-DER input ahead of the wc_PKCS7 calls. */
static int validate_certs(const uint8_t* const* certs, const size_t* lens, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        if (certs[i] == NULL || lens[i] < 2)
            return WOLFCERT_ERR_BAD_ARG;

        if (certs[i][0] != 0x30)
            return WOLFCERT_ERR_PARSE;
    }

    return WOLFCERT_OK;
}

WOLFCERT_TEST_VIS int wolfcert_pkcs7_build_certs_only(const uint8_t* const* certs_der,
    const size_t* certs_len, size_t count, WolfCertBuffer* out_der, void* heap)
{
    if (certs_der == NULL || certs_len == NULL || count == 0 || out_der == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    int rc = validate_certs(certs_der, certs_len, count);
    if (rc != WOLFCERT_OK)
        return rc;

    PKCS7* p7 = wc_PKCS7_New(heap, WOLFCERT_DEVID_SOFTWARE);
    if (p7 == NULL)
        return WOLFCERT_ERR_MEMORY;

    /* wc_PKCS7_AddCertificate() prepends, so add in reverse to keep the emitted
     * certs SET in the caller's order. */
    rc = 0;
    for (size_t i = count; rc == 0 && i-- > 0; ) {
        rc = wc_PKCS7_AddCertificate(p7, (byte*)certs_der[i], (word32)certs_len[i]);
    }

    if (rc == 0)
        rc = wc_PKCS7_SetSignerIdentifierType(p7, DEGENERATE_SID);

    if (rc != 0) {
        int e = WOLFCERT_ERR_WC(rc, "pkcs7", "certs-only setup");
        wc_PKCS7_Free(p7);
        return e;
    }

    /* No signer, no eContent: a degenerate certs-only bundle. */
    p7->detached   = 1;
    p7->contentOID = DATA;

    size_t certs_body = 0;
    for (size_t i = 0; i < count; ++i) {
        certs_body += certs_len[i];
    }

    /* Wrapper overhead (ContentInfo + SignedData + empty SETs) is a few dozen
     * bytes; 512 is a comfortable upper bound. */
    word32 cap = (word32)(certs_body + 512);
    uint8_t* buf = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
    if (buf == NULL) {
        wc_PKCS7_Free(p7);
        return WOLFCERT_ERR_MEMORY;
    }

    int n = wc_PKCS7_EncodeSignedData(p7, buf, cap);

    wc_PKCS7_Free(p7);
    if (n <= 0) {
        int e = WOLFCERT_ERR_WC(n, "pkcs7", "EncodeSignedData");
        WOLFCERT_XFREE(buf, heap);
        return e;
    }

    out_der->data = buf;
    out_der->len  = (size_t)n;
    out_der->heap = heap;

    return WOLFCERT_OK;
}
