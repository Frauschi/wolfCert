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
 * End-to-end mutual-TLS EST roundtrip. Stands up wolfcert-server with
 *   --tls-cert + --tls-key         (server identity)
 *   --tls-client-ca                (mandate client-cert auth)
 * then runs wolfcert-client through wolfcert_est_simple_enroll with
 *   client_cert / client_key set on WolfCertServerCfg.
 *
 * Three assertions:
 *   1. mTLS works: a client that does NOT present a certificate is
 *      rejected by the TLS handshake.
 *   2. mTLS works: a client that DOES present a cert signed by the
 *      configured trust anchor enrolls successfully.
 *   3. /simplereenroll presents the cert being renewed even when
 *      client_cert names a different, untrusted identity.
 *
 * Exercises the TLS 1.3 negotiation path (wolfTLS_client_method /
 * wolfTLS_server_method) and the new client_cert plumbing on
 * WolfCertServerCfg, covering the "bootstrap with a factory identity"
 * deployment shape documented in NEWS.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/est.h>
#include <wolfcert/server.h>

#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>

#include "tls_test_util.h"
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

/* Build a self-signed RSA identity suitable for TLS usage. */

static void* server_thread(void* arg) { wolfcert_server_run((WolfCertServer*)arg); return NULL; }

/* Re-enroll the trusted cli_cert while cfg carries an identity the server
 * does not trust; the handshake must present the cert being renewed. */
static int test_reenroll_ignores_cfg_identity(const char* url,
                                              const uint8_t* tls_cert, size_t tls_cert_len,
                                              const uint8_t* cli_cert, size_t cli_cert_len,
                                              const uint8_t* cli_key, size_t cli_key_len)
{
    uint8_t* stale_cert = NULL;
    size_t stale_cert_len = 0;
    uint8_t* stale_key = NULL;
    size_t stale_key_len = 0;
    WolfCertKey* cur_key = NULL;
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertBuffer issued = { 0 };
    WolfCertBuffer ca_pem = { 0 };
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertCertMeta meta = { .subject_dn = "CN=factory-bootstrap" };
    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
    };
    int rc;

    REQUIRE(mint_self_id("stale-identity", 1, &stale_cert, &stale_cert_len,
                         &stale_key, &stale_key_len) == 0);
    cli.client_cert     = stale_cert;
    cli.client_cert_len = stale_cert_len;
    cli.client_key      = stale_key;
    cli.client_key_len  = stale_key_len;

    /* The server refuses the stale identity on its own */
    rc = wolfcert_est_get_cacerts(&cli, &ca_pem);
    wolfcert_buffer_free(&ca_pem);
    REQUIRE(rc != WOLFCERT_OK);

    REQUIRE(wolfcert_key_from_pem(cli_key, cli_key_len, NULL, &cur_key) == WOLFCERT_OK);
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    rc = wolfcert_est_simple_reenroll(&cli, cli_cert, cli_cert_len, cur_key,
                                      csr.data, csr.len, &issued);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "mtls reenroll rc=%d (%s)\n", rc, wolfcert_strerror(rc));
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(memmem(issued.data, issued.len, "BEGIN CERTIFICATE", 17) != NULL);

    wolfcert_buffer_free(&issued);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);
    wolfcert_key_free(cur_key);
    free(stale_cert);
    free(stale_key);
    return 0;
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    /* Server identity (CN=127.0.0.1 with IP SAN). */
    uint8_t* tls_cert = NULL;
    size_t tls_cert_len = 0;
    uint8_t* tls_key  = NULL;
    size_t tls_key_len  = 0;
    REQUIRE(mint_self_id("127.0.0.1", 0,
                        &tls_cert, &tls_cert_len, &tls_key, &tls_key_len) == 0);

    /* Self-signed "bootstrap CA" that we both pin as the server's
     * tls_client_ca_pem AND use as the client's presented cert - a
     * single self-signed cert trivially validates against itself. This
     * keeps the test self-contained without a separate issuing step. */
    uint8_t* cli_cert = NULL;
    size_t cli_cert_len = 0;
    uint8_t* cli_key  = NULL;
    size_t cli_key_len  = 0;
    REQUIRE(mint_self_id("factory-bootstrap", 1,
                        &cli_cert, &cli_cert_len, &cli_key, &cli_key_len) == 0);

    WolfCertServerCfgSrv cfg = {
        .protocol              = WOLFCERT_PROTO_EST,
        .bind_host             = "127.0.0.1",
        .bind_port             = 0,
        .tls_cert_pem          = tls_cert, .tls_cert_pem_len       = tls_cert_len,
        .tls_key_pem           = tls_key,  .tls_key_pem_len        = tls_key_len,
        .tls_client_ca_pem     = cli_cert, .tls_client_ca_pem_len  = cli_cert_len,
    };
    WolfCertServer* srv = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);

    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));

    /* --- Case 1: NO client identity -> TLS handshake must be refused. */
    {
        WolfCertServerCfg cli = {
            .protocol          = WOLFCERT_PROTO_EST,
            .server_url        = url,
            .trust_anchors = tls_cert, .trust_anchors_len = tls_cert_len,
            .verify_server     = 1,
        };
        WolfCertBuffer ca_pem = { 0 };
        int rc = wolfcert_est_get_cacerts(&cli, &ca_pem);
        REQUIRE(rc != WOLFCERT_OK);              /* handshake rejected */
        if (rc == WOLFCERT_OK)
            wolfcert_buffer_free(&ca_pem);
    }

    /* --- Case 2: with client identity -> enrollment succeeds. */
    {
        WolfCertServerCfg cli = {
            .protocol          = WOLFCERT_PROTO_EST,
            .server_url        = url,
            .trust_anchors     = tls_cert,
            .trust_anchors_len = tls_cert_len,
            .verify_server     = 1,
            .client_cert       = cli_cert,
            .client_cert_len   = cli_cert_len,
            .client_key        = cli_key,
            .client_key_len    = cli_key_len,
        };

        WolfCertBuffer ca_pem = { 0 };
        REQUIRE(wolfcert_est_get_cacerts(&cli, &ca_pem) == WOLFCERT_OK);
        REQUIRE(ca_pem.len > 0);
        wolfcert_buffer_free(&ca_pem);

        WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                                .dev_id = WOLFCERT_DEVID_SOFTWARE };
        WolfCertKey* dk = NULL;
        REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
        WolfCertCertMeta meta = { .subject_dn = "CN=mtls-est-client" };
        WolfCertBuffer csr = { 0 };
        REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

        WolfCertBuffer issued = { 0 };
        int rc = wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &issued);
        if (rc != WOLFCERT_OK)
            fprintf(stderr, "mtls enroll rc=%d (%s)\n", rc, wolfcert_strerror(rc));
        REQUIRE(rc == WOLFCERT_OK);
        REQUIRE(memmem(issued.data, issued.len, "BEGIN CERTIFICATE", 17) != NULL);

        wolfcert_buffer_free(&csr);
        wolfcert_buffer_free(&issued);
        wolfcert_key_free(dk);
    }

    /* --- Case 3: reenroll presents the cert being renewed, not cfg's. */
    REQUIRE(test_reenroll_ignores_cfg_identity(url, tls_cert, tls_cert_len,
                                               cli_cert, cli_cert_len,
                                               cli_key, cli_key_len) == 0);

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);

    free(tls_cert);
    free(tls_key);
    free(cli_cert);
    free(cli_key);
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
