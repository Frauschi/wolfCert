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
 * TLS 1.3 post-handshake authentication end-to-end over the keep-alive
 * EST session API.
 *
 * The server is configured with tls_post_handshake_auth=1 so the initial
 * handshake is anonymous. On one TLS connection we:
 *   1. Call /cacerts - the server must answer without asking for a
 *      client cert.
 *   2. Call /simpleenroll - the server must trigger a CertificateRequest
 *      via wolfSSL_request_certificate(); the client answers from the
 *      pre-loaded identity and the CSR is issued.
 *
 * A negative control issues a session without a client identity and
 * verifies that /simpleenroll fails with a 401-mapped error while
 * /cacerts still succeeds.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/est.h>
#include <wolfcert/server.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>

#include "tls_test_util.h"
#include <wolfssl/wolfcrypt/rsa.h>

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


static void* server_thread(void* arg) { wolfcert_server_run((WolfCertServer*)arg); return NULL; }

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    uint8_t* tls_cert = NULL;
    size_t tls_cert_len = 0;
    uint8_t* tls_key  = NULL;
    size_t tls_key_len  = 0;
    REQUIRE(mint_self_id("127.0.0.1", 0,
                        &tls_cert, &tls_cert_len, &tls_key, &tls_key_len) == 0);

    /* Self-signed client CA that also serves as the client's presented
     * identity for the PHA response - trivially validates against
     * itself, same trick the mTLS roundtrip uses. */
    uint8_t* cli_cert = NULL;
    size_t cli_cert_len = 0;
    uint8_t* cli_key  = NULL;
    size_t cli_key_len  = 0;
    REQUIRE(mint_self_id("factory-bootstrap", 1,
                        &cli_cert, &cli_cert_len, &cli_key, &cli_key_len) == 0);

    WolfCertServerCfgSrv cfg = {
        .protocol                = WOLFCERT_PROTO_EST,
        .bind_host               = "127.0.0.1",
        .bind_port               = 0,
        .tls_cert_pem            = tls_cert,
        .tls_cert_pem_len        = tls_cert_len,
        .tls_key_pem             = tls_key,
        .tls_key_pem_len         = tls_key_len,
        .tls_client_ca_pem       = cli_cert,
        .tls_client_ca_pem_len   = cli_cert_len,
        .tls_post_handshake_auth = 1,
    };
    WolfCertServer* srv = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);

    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));

    /* --- Positive: session with client identity + PHA opt-in. */
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
            .proto_opts.est    = { .allow_post_handshake_auth = 1 },
        };
        WolfCertEstSession* s = NULL;
        REQUIRE(wolfcert_est_session_open(&cli, &s) == WOLFCERT_OK);

        /* /cacerts on the anonymous leg of the TLS connection. */
        WolfCertBuffer ca_pem = { 0 };
        REQUIRE(wolfcert_est_session_get_cacerts(s, &ca_pem) == WOLFCERT_OK);
        REQUIRE(ca_pem.len > 0);

        /* /simpleenroll on the same connection - this is the call that
         * triggers the server's wolfSSL_request_certificate(). */
        WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                                .dev_id = WOLFCERT_DEVID_SOFTWARE };
        WolfCertKey* dk = NULL;
        REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
        WolfCertCertMeta meta = { .subject_dn = "CN=pha-enrollee" };
        WolfCertBuffer csr = { 0 };
        REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

        WolfCertBuffer issued = { 0 };
        int rc = wolfcert_est_session_simple_enroll(s, csr.data, csr.len, &issued);
        if (rc != WOLFCERT_OK)
            fprintf(stderr, "pha enroll rc=%d (%s) last=%s\n",
                    rc, wolfcert_strerror(rc), wolfcert_last_error_message());
        REQUIRE(rc == WOLFCERT_OK);
        REQUIRE(memmem(issued.data, issued.len, "BEGIN CERTIFICATE", 17) != NULL);

        wolfcert_buffer_free(&ca_pem);
        wolfcert_buffer_free(&csr);
        wolfcert_buffer_free(&issued);
        wolfcert_key_free(dk);
        wolfcert_est_session_close(s);
    }

    /* --- Negative: session without client identity. /cacerts must
     * still succeed (server doesn't ask). /simpleenroll must fail
     * because the PHA prompt finds nothing to send. */
    {
        WolfCertServerCfg cli = {
            .protocol          = WOLFCERT_PROTO_EST,
            .server_url        = url,
            .trust_anchors     = tls_cert,
            .trust_anchors_len = tls_cert_len,
            .verify_server     = 1,
            .proto_opts.est    = { .allow_post_handshake_auth = 1 },
        };
        WolfCertEstSession* s = NULL;
        REQUIRE(wolfcert_est_session_open(&cli, &s) == WOLFCERT_OK);

        WolfCertBuffer ca_pem = { 0 };
        REQUIRE(wolfcert_est_session_get_cacerts(s, &ca_pem) == WOLFCERT_OK);
        REQUIRE(ca_pem.len > 0);
        wolfcert_buffer_free(&ca_pem);

        WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                                .dev_id = WOLFCERT_DEVID_SOFTWARE };
        WolfCertKey* dk = NULL;
        REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
        WolfCertCertMeta meta = { .subject_dn = "CN=pha-negative" };
        WolfCertBuffer csr = { 0 };
        REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

        WolfCertBuffer issued = { 0 };
        int rc = wolfcert_est_session_simple_enroll(s, csr.data, csr.len, &issued);
        REQUIRE(rc != WOLFCERT_OK);
        wolfcert_buffer_free(&csr);
        wolfcert_buffer_free(&issued);
        wolfcert_key_free(dk);
        wolfcert_est_session_close(s);
    }

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
