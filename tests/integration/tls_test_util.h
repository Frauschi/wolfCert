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
 * Shared integration-test helper: mint a self-signed RSA server identity
 * (cert + key, PEM) with an iPAddress SAN for 127.0.0.1, used to stand up the
 * in-tree test server behind TLS. EST mandates TLS (RFC 7030), so the EST
 * integration tests run over HTTPS and pin this freshly-minted cert as their
 * bootstrap trust anchor.
 */

#ifndef WOLFCERT_TLS_TEST_UTIL_H
#define WOLFCERT_TLS_TEST_UTIL_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Generate a self-signed RSA cert + key as PEM. Returns 0 on success; the
 * caller frees *cert_pem / *key_pem with free(). */
static int gen_server_identity(uint8_t** cert_pem, size_t* cert_pem_len,
                               uint8_t** key_pem,  size_t* key_pem_len)
{
    RsaKey key;
    WC_RNG rng;
    if (wc_InitRng(&rng) != 0)
        return -1;
    if (wc_InitRsaKey(&key, NULL) != 0) {
        wc_FreeRng(&rng);
        return -1;
    }
    if (wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng) != 0)
        goto fail;

    Cert cert;
    wc_InitCert(&cert);
    strcpy(cert.subject.commonName, "127.0.0.1");
    cert.selfSigned = 1;
    cert.sigType = CTC_SHA256wRSA;
    cert.daysValid = 1;
    static const uint8_t san_seq[] = { 0x30, 0x06, 0x87, 0x04, 127, 0, 0, 1 };
    memcpy(cert.altNames, san_seq, sizeof(san_seq));
    cert.altNamesSz = (int)sizeof(san_seq);

    uint8_t cder[8192];
    int cs = wc_MakeSelfCert(&cert, cder, sizeof(cder), &key, &rng);
    if (cs <= 0)
        goto fail;
    uint8_t cpem[16384];
    int cp = wc_DerToPem(cder, cs, cpem, sizeof(cpem), CERT_TYPE);
    if (cp <= 0)
        goto fail;

    uint8_t kder[8192];
    int ks = wc_RsaKeyToDer(&key, kder, sizeof(kder));
    if (ks <= 0)
        goto fail;
    uint8_t kpem[16384];
    int kp = wc_DerToPem(kder, ks, kpem, sizeof(kpem), PRIVATEKEY_TYPE);
    if (kp <= 0)
        goto fail;

    *cert_pem = (uint8_t*)malloc((size_t)cp);
    memcpy(*cert_pem, cpem, (size_t)cp);
    *cert_pem_len = (size_t)cp;
    *key_pem  = (uint8_t*)malloc((size_t)kp);
    memcpy(*key_pem,  kpem, (size_t)kp);
    *key_pem_len  = (size_t)kp;
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    return 0;
fail:
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    return -1;
}

#endif /* WOLFCERT_TLS_TEST_UTIL_H */
