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
 * End-to-end coverage for EST `/simpleenroll` with 202 Accepted +
 * Retry-After (RFC 7030 section 4.2.3). The test server is started with
 * est_require_approval=1 so the first POST for a given CSR parks
 * the request and returns 202; a matching second POST then completes.
 *
 * Exercises:
 *   - `wolfcert_est_simple_enroll_ex` returns WOLFCERT_EST_STATUS_PENDING
 *     with the configured Retry-After delta-seconds.
 *   - A second identical call flips to SUCCESS and carries the issued
 *     cert PEM.
 *   - The issued cert chains up to the server's CA.
 *   - The legacy `wolfcert_est_simple_enroll` flattens PENDING to
 *     `WOLFCERT_ERR_PENDING`.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/est.h>
#include <wolfcert/server.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include "tls_test_util.h"

#include <poll.h>
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

/* Server TLS trust anchor, pinned by the client (EST is TLS-only, RFC 7030). */
static const uint8_t* g_ca = NULL;
static size_t         g_ca_len = 0;

static void* server_thread(void* arg)
{
    wolfcert_server_run((WolfCertServer*)arg);
    return NULL;
}

/* Drive the non-blocking session enroll to a terminal result, polling the
 * session fd between WOLFCERT_ERR_WANT_READ / _WANT_WRITE returns. Returns the
 * terminal code as-is (WOLFCERT_OK, WOLFCERT_ERR_PENDING, or an error) so the
 * caller can assert the 202 -> PENDING mapping on the async path directly. */
static int pump_enroll_nb(WolfCertEstSession* s, const uint8_t* csr,
                          size_t csr_len, WolfCertBuffer* out)
{
    int fd = wolfcert_est_session_fd(s);
    for (;;) {
        int rc = wolfcert_est_session_simple_enroll_nb(s, csr, csr_len, out);
        if (rc != WOLFCERT_ERR_WANT_READ && rc != WOLFCERT_ERR_WANT_WRITE)
            return rc;

        struct pollfd p = { .fd = fd,
            .events = (rc == WOLFCERT_ERR_WANT_WRITE) ? POLLOUT : POLLIN };
        if (poll(&p, 1, 5000) <= 0)
            return WOLFCERT_ERR_IO;
    }
}

/* Produce a fresh CSR for a given subject so each sub-test works on an
 * independent entry in the server's pending queue. */
static int make_csr(const char* subject, WolfCertKey** out_key,
                    WolfCertBuffer* out_csr)
{
    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    if (wolfcert_key_generate(&kcfg, out_key) != WOLFCERT_OK)
        return 1;
    WolfCertCertMeta meta = { .subject_dn = subject };
    return wolfcert_csr_build(*out_key, &meta, out_csr) == WOLFCERT_OK ? 0 : 1;
}

static int pending_path(WolfCertServer* s)
{
    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(s));
    WolfCertServerCfg cli = { .protocol = WOLFCERT_PROTO_EST,
                              .server_url = url,
                              .trust_anchors = g_ca,
                              .trust_anchors_len = g_ca_len,
                              .verify_server = 1 };

    WolfCertBuffer ca_pem = { 0 };
    REQUIRE(wolfcert_est_get_cacerts(&cli, &ca_pem) == WOLFCERT_OK);

    /* ---- _ex API: PENDING -> SUCCESS with Retry-After hint ---- */
    WolfCertKey* dk_ex = NULL;
    WolfCertBuffer csr_ex = { 0 };
    REQUIRE(make_csr("CN=device-est-pending-ex", &dk_ex, &csr_ex) == 0);

    WolfCertEstResult r1 = { 0 };
    int rc = wolfcert_est_simple_enroll_ex(&cli, csr_ex.data, csr_ex.len, &r1);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(r1.status == WOLFCERT_EST_STATUS_PENDING);
    REQUIRE(r1.retry_after_sec == 1);
    REQUIRE(r1.cert_pem.data == NULL);
    wolfcert_est_result_free(&r1);

    WolfCertEstResult r2 = { 0 };
    rc = wolfcert_est_simple_enroll_ex(&cli, csr_ex.data, csr_ex.len, &r2);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(r2.status == WOLFCERT_EST_STATUS_SUCCESS);
    REQUIRE(r2.cert_pem.data != NULL);
    REQUIRE(memmem(r2.cert_pem.data, r2.cert_pem.len,
                   "BEGIN CERTIFICATE", 17) != NULL);

    /* Issued cert chains up to the test CA. */
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    REQUIRE(cm != NULL);
    REQUIRE(wolfSSL_CertManagerLoadCABuffer(cm, ca_pem.data, (long)ca_pem.len,
                                            WOLFSSL_FILETYPE_PEM)
            == WOLFSSL_SUCCESS);
    DerBuffer* issued_der = NULL;
    REQUIRE(wc_PemToDer(r2.cert_pem.data, (long)r2.cert_pem.len, CERT_TYPE,
                        &issued_der, NULL, NULL, NULL) == 0);
    REQUIRE(wolfSSL_CertManagerVerifyBuffer(cm, issued_der->buffer,
                                            (long)issued_der->length,
                                            WOLFSSL_FILETYPE_ASN1)
            == WOLFSSL_SUCCESS);
    wc_FreeDer(&issued_der);
    wolfSSL_CertManagerFree(cm);

    wolfcert_est_result_free(&r2);
    wolfcert_buffer_free(&csr_ex);
    wolfcert_key_free(dk_ex);

    /* ---- Legacy API surfaces PENDING as WOLFCERT_ERR_PENDING ----
     * Use a distinct CSR so this path starts with an empty queue for
     * this request, independent of the _ex test above. */
    WolfCertKey* dk_leg = NULL;
    WolfCertBuffer csr_leg = { 0 };
    REQUIRE(make_csr("CN=device-est-pending-legacy", &dk_leg, &csr_leg) == 0);

    WolfCertBuffer legacy_out = { 0 };
    int legacy_rc = wolfcert_est_simple_enroll(&cli, csr_leg.data, csr_leg.len,
                                               &legacy_out);
    REQUIRE(legacy_rc == WOLFCERT_ERR_PENDING);
    REQUIRE(legacy_out.data == NULL);

    /* Second legacy call issues normally. */
    legacy_rc = wolfcert_est_simple_enroll(&cli, csr_leg.data, csr_leg.len,
                                           &legacy_out);
    REQUIRE(legacy_rc == WOLFCERT_OK);
    REQUIRE(legacy_out.data != NULL);
    REQUIRE(memmem(legacy_out.data, legacy_out.len,
                   "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_buffer_free(&legacy_out);

    wolfcert_buffer_free(&csr_leg);
    wolfcert_key_free(dk_leg);

    /* ---- Keep-alive session enroll surfaces PENDING the same way ----
     * The blocking session API has no richer result struct, so a 202
     * Accepted must come back as WOLFCERT_ERR_PENDING rather than a
     * generic HTTP error. Use a distinct CSR so the queue starts empty. */
    WolfCertKey* dk_sess = NULL;
    WolfCertBuffer csr_sess = { 0 };
    REQUIRE(make_csr("CN=device-est-pending-session", &dk_sess, &csr_sess) == 0);

    WolfCertEstSession* sess = NULL;
    REQUIRE(wolfcert_est_session_open(&cli, &sess) == WOLFCERT_OK);

    WolfCertBuffer sess_out = { 0 };
    int sess_rc = wolfcert_est_session_simple_enroll(sess, csr_sess.data,
                                                     csr_sess.len, &sess_out);
    REQUIRE(sess_rc == WOLFCERT_ERR_PENDING);
    REQUIRE(sess_out.data == NULL);

    /* A second call on the same session completes the approval flow. */
    sess_rc = wolfcert_est_session_simple_enroll(sess, csr_sess.data,
                                                 csr_sess.len, &sess_out);
    REQUIRE(sess_rc == WOLFCERT_OK);
    REQUIRE(sess_out.data != NULL);
    REQUIRE(memmem(sess_out.data, sess_out.len,
                   "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_buffer_free(&sess_out);

    wolfcert_est_session_close(sess);
    wolfcert_buffer_free(&csr_sess);
    wolfcert_key_free(dk_sess);

    /* ---- Non-blocking session enroll surfaces PENDING the same way ----
     * The async variant applies the identical 202 -> WOLFCERT_ERR_PENDING
     * mapping and resets the in-flight request so the retry can reuse the
     * connection. Drive it through poll(2) with a distinct CSR. */
    WolfCertKey* dk_async = NULL;
    WolfCertBuffer csr_async = { 0 };
    REQUIRE(make_csr("CN=device-est-pending-async", &dk_async, &csr_async) == 0);

    WolfCertEstSession* asess = NULL;
    REQUIRE(wolfcert_est_session_open_async(&cli, &asess) == WOLFCERT_OK);

    WolfCertBuffer async_out = { 0 };
    int async_rc = pump_enroll_nb(asess, csr_async.data, csr_async.len,
                                  &async_out);
    REQUIRE(async_rc == WOLFCERT_ERR_PENDING);
    REQUIRE(async_out.data == NULL);

    /* A second drive on the same session completes the approval flow. */
    async_rc = pump_enroll_nb(asess, csr_async.data, csr_async.len, &async_out);
    REQUIRE(async_rc == WOLFCERT_OK);
    REQUIRE(async_out.data != NULL);
    REQUIRE(memmem(async_out.data, async_out.len,
                   "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_buffer_free(&async_out);

    wolfcert_est_session_close(asess);
    wolfcert_buffer_free(&csr_async);
    wolfcert_key_free(dk_async);

    wolfcert_buffer_free(&ca_pem);
    return 0;
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    uint8_t *tls_cert = NULL, *tls_key = NULL;
    size_t tls_cert_len = 0, tls_key_len = 0;
    REQUIRE(gen_server_identity(&tls_cert, &tls_cert_len,
                                &tls_key, &tls_key_len) == 0);
    g_ca = tls_cert;
    g_ca_len = tls_cert_len;

    WolfCertServerCfgSrv cfg = {
        .protocol               = WOLFCERT_PROTO_EST,
        .bind_host              = "127.0.0.1", .bind_port = 0,
        .est_require_approval   = 1,
        .est_retry_after_sec    = 1,
        .tls_cert_pem           = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem            = tls_key,  .tls_key_pem_len  = tls_key_len,
    };
    WolfCertServer* s = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &s) == WOLFCERT_OK);
    pthread_t t;
    REQUIRE(pthread_create(&t, NULL, server_thread, s) == 0);
    int rc = pending_path(s);
    wolfcert_server_stop(s);
    pthread_join(t, NULL);
    wolfcert_server_free(s);

    free(tls_cert);
    free(tls_key);
    wolfcert_cleanup();
    if (rc != 0)
        return rc;
    printf("OK\n");
    return 0;
}
