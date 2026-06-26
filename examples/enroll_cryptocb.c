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
 * CryptoCb offloading example.
 *
 * Demonstrates the integration pattern for running wolfCert with a
 * backend-resident private key: the application registers a wolfSSL
 * CryptoCb of its choice (PKCS#11 via wolfPKCS11, TPM, HSM, custom
 * accelerator, ...) and simply passes the returned devId into
 * WolfCertKeyCfg. wolfCert itself stays backend-agnostic.
 *
 * For demo purposes this example implements a pass-through CryptoCb that
 * does NOT actually offload - it returns CRYPTOCB_UNAVAILABLE for every
 * operation, letting wolfSSL fall back to software. Replace the callback
 * with a real backend to get true offloading. Real TPM integration
 * typically uses wolfTPM; real HSM/PKCS#11 integration typically uses
 * wolfPKCS11.
 */

#include <wolfcert/wolfcert.h>
#ifndef WOLFCERT_HAVE_EST
#  error "examples/enroll_cryptocb.c needs wolfCert built with EST enabled"
#endif

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <stdio.h>
#include <string.h>

#define MY_DEV_ID 42

static int passthrough_cb(int devIdIn, wc_CryptoInfo* info, void* ctx)
{
    (void)devIdIn;
    (void)ctx;
    fprintf(stderr, "[cryptocb] algo=%d falling back to software\n", info->algo_type);
    return CRYPTOCB_UNAVAILABLE;   /* tell wolfSSL to do it itself */
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s URL SUBJECT\n", argv[0]);
        return 1;
    }

    if (wolfcert_init(NULL) != WOLFCERT_OK)
        return 1;

    /* Register the CryptoCb once, application-side. */
    if (wc_CryptoCb_RegisterDevice(MY_DEV_ID, passthrough_cb, NULL) != 0) {
        fprintf(stderr, "wc_CryptoCb_RegisterDevice failed\n");
        return 1;
    }

    /* Now use the device id when asking wolfCert for a key. Everything
     * else is identical to the pure-software path. */
    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                            .dev_id = MY_DEV_ID,
                            .key_label = "demo/device-key" };
    WolfCertKey* key = NULL;
    if (wolfcert_key_generate(&kcfg, &key) != WOLFCERT_OK) {
        fprintf(stderr, "keygen failed\n");
        return 2;
    }

    WolfCertCertMeta meta = { .subject_dn = argv[2] };
    WolfCertBuffer csr = { 0 };
    if (wolfcert_csr_build(key, &meta, &csr) != WOLFCERT_OK)
        return 2;

    WolfCertServerCfg srv = { .protocol = WOLFCERT_PROTO_EST, .server_url = argv[1] };
    WolfCertBuffer cert = { 0 };
    int rc = wolfcert_est_simple_enroll(&srv, csr.data, csr.len, &cert);
    if (rc != WOLFCERT_OK) {
        fprintf(stderr, "enroll failed: %s\n", wolfcert_strerror(rc));
        return 2;
    }
    fwrite(cert.data, 1, cert.len, stdout);

    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&cert);
    wolfcert_key_free(key);
    wc_CryptoCb_UnRegisterDevice(MY_DEV_ID);
    wolfcert_cleanup();
    return 0;
}
