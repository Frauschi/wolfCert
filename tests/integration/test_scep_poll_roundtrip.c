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
 * End-to-end coverage for RFC 8894 polling (PKCSReq -> pkiStatus=PENDING
 * -> GetCertInitial -> pkiStatus=SUCCESS) and GetNextCACert (section 4.6.1).
 *
 * The test server is configured with scep_require_approval=1 so the
 * first PKCSReq is parked in the pending queue; GetCertInitial for the
 * same transactionID then releases it. A second server instance with
 * scep_enable_next_ca=1 is used to check that the roll-over CA is
 * generated on demand and returned as a distinct cert.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/scep.h>
#include <wolfcert/server.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>

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

static void* server_thread(void* arg)
{
    wolfcert_server_run((WolfCertServer*)arg);
    return NULL;
}

static int poll_path(WolfCertServer* s)
{
    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/scep", wolfcert_server_port(s));
    WolfCertServerCfg cli = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };

    WolfCertScepCaps caps = { 0 };
    REQUIRE(wolfcert_scep_get_ca_caps(&cli, &caps) == WOLFCERT_OK);

    WolfCertBuffer ca_pem = { 0 };
    REQUIRE(wolfcert_scep_get_ca_cert(&cli, &ca_pem) == WOLFCERT_OK);
    DerBuffer* ca_der = NULL;
    REQUIRE(wc_PemToDer(ca_pem.data, (long)ca_pem.len, CERT_TYPE,
                        &ca_der, NULL, NULL, NULL) == 0);

    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_RSA, .param = 2048,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    WolfCertCertMeta meta = { .subject_dn = "CN=device-poll-1" };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    /* Step 1: PKCSReq - must return PENDING with a transactionID. */
    WolfCertScepResult r1 = { 0 };
    int rc = wolfcert_scep_pkcs_req_ex(&cli, &caps,
                                       ca_der->buffer, ca_der->length,
                                       ca_der->buffer, ca_der->length,
                                       dk, csr.data, csr.len, &r1);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(r1.status == WOLFCERT_SCEP_STATUS_PENDING);
    REQUIRE(r1.transaction_id != NULL);
    REQUIRE(r1.transaction_id_len > 0);
    REQUIRE(r1.cert_pem.data == NULL);

    /* The legacy API maps PENDING -> WOLFCERT_ERR_PENDING. */
    WolfCertBuffer legacy_out = { 0 };
    int legacy_rc = wolfcert_scep_pkcs_req(&cli, &caps,
                                           ca_der->buffer, ca_der->length,
                                           dk, csr.data, csr.len, &legacy_out);
    REQUIRE(legacy_rc == WOLFCERT_ERR_PENDING);
    wolfcert_buffer_free(&legacy_out);

    /* Step 2: GetCertInitial with the same transactionID -> SUCCESS.
     * signer_cert=NULL so the client regenerates the transient
     * "SCEP Enrollee" self-signed cert that PKCSReq used. */
    WolfCertScepResult r2 = { 0 };
    rc = wolfcert_scep_get_cert_initial(&cli, &caps,
                                        ca_der->buffer, ca_der->length,
                                        ca_der->buffer, ca_der->length,
                                        NULL, 0,
                                        dk, csr.data, csr.len,
                                        r1.transaction_id, r1.transaction_id_len,
                                        &r2);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(r2.status == WOLFCERT_SCEP_STATUS_SUCCESS);
    REQUIRE(r2.cert_pem.data != NULL);
    REQUIRE(memmem(r2.cert_pem.data, r2.cert_pem.len,
                   "BEGIN CERTIFICATE", 17) != NULL);

    /* Verify the issued cert chains up to the test CA. */
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    REQUIRE(cm != NULL);
    REQUIRE(wolfSSL_CertManagerLoadCABuffer(cm, ca_pem.data, (long)ca_pem.len,
                                            WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS);
    DerBuffer* issued_der = NULL;
    REQUIRE(wc_PemToDer(r2.cert_pem.data, (long)r2.cert_pem.len, CERT_TYPE,
                        &issued_der, NULL, NULL, NULL) == 0);
    REQUIRE(wolfSSL_CertManagerVerifyBuffer(cm, issued_der->buffer,
                                            (long)issued_der->length,
                                            WOLFSSL_FILETYPE_ASN1) == WOLFSSL_SUCCESS);
    wc_FreeDer(&issued_der);
    wolfSSL_CertManagerFree(cm);

    /* Step 3: Polling an unknown transactionID -> FAILURE. */
    uint8_t bogus_tid[32];
    memset(bogus_tid, 0x5A, sizeof(bogus_tid));
    WolfCertScepResult r3 = { 0 };
    rc = wolfcert_scep_get_cert_initial(&cli, &caps,
                                        ca_der->buffer, ca_der->length,
                                        ca_der->buffer, ca_der->length,
                                        NULL, 0,
                                        dk, csr.data, csr.len,
                                        bogus_tid, sizeof(bogus_tid),
                                        &r3);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(r3.status == WOLFCERT_SCEP_STATUS_FAILURE);
    /* The server reports failInfo "4" (badCertId) for an unknown transaction;
     * the client must surface it in the result. */
    REQUIRE(r3.fail_info == 4);

    wolfcert_scep_result_free(&r1);
    wolfcert_scep_result_free(&r2);
    wolfcert_scep_result_free(&r3);
    wc_FreeDer(&ca_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);
    return 0;
}

static int next_ca_path(WolfCertServer* s)
{
    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/scep", wolfcert_server_port(s));
    WolfCertServerCfg cli = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };

    WolfCertScepCaps caps = { 0 };
    REQUIRE(wolfcert_scep_get_ca_caps(&cli, &caps) == WOLFCERT_OK);
    REQUIRE(caps.get_next_ca_cert);

    WolfCertBuffer current = { 0 };
    REQUIRE(wolfcert_scep_get_ca_cert(&cli, &current) == WOLFCERT_OK);
    DerBuffer* current_der = NULL;
    REQUIRE(wc_PemToDer(current.data, (long)current.len, CERT_TYPE,
                        &current_der, NULL, NULL, NULL) == 0);

    /* Bound to the current CA that signed the response: accepted. */
    WolfCertBuffer next = { 0 };
    REQUIRE(wolfcert_scep_get_next_ca_cert(&cli, current_der->buffer,
                                           current_der->length, &next)
            == WOLFCERT_OK);
    REQUIRE(memmem(next.data, next.len, "BEGIN CERTIFICATE", 17) != NULL);

    /* Roll-over CA must differ from the current CA. */
    REQUIRE(current.len != next.len ||
            memcmp(current.data, next.data, current.len) != 0);

    /* Second call must return the cached next CA (same bytes). */
    WolfCertBuffer next2 = { 0 };
    REQUIRE(wolfcert_scep_get_next_ca_cert(&cli, current_der->buffer,
                                           current_der->length, &next2)
            == WOLFCERT_OK);
    REQUIRE(next.len == next2.len);
    REQUIRE(memcmp(next.data, next2.data, next.len) == 0);

    /* Bound to a CA that did not sign the response (the roll-over CA itself,
     * which the current CA signs over): rejected. */
    DerBuffer* rollover_der = NULL;
    REQUIRE(wc_PemToDer(next.data, (long)next.len, CERT_TYPE,
                        &rollover_der, NULL, NULL, NULL) == 0);
    WolfCertBuffer reject = { 0 };
    REQUIRE(wolfcert_scep_get_next_ca_cert(&cli, rollover_der->buffer,
                                           rollover_der->length, &reject)
            != WOLFCERT_OK);

    wc_FreeDer(&rollover_der);
    wc_FreeDer(&current_der);
    wolfcert_buffer_free(&reject);
    wolfcert_buffer_free(&current);
    wolfcert_buffer_free(&next);
    wolfcert_buffer_free(&next2);
    return 0;
}

static int next_ca_disabled_path(void)
{
    /* Server without scep_enable_next_ca set: GetNextCACert -> 404 ->
     * WOLFCERT_ERR_NOT_FOUND, and GetCACaps must NOT advertise
     * GetNextCACert. */
    WolfCertServerCfgSrv cfg = { .protocol = WOLFCERT_PROTO_SCEP,
                                 .bind_host = "127.0.0.1", .bind_port = 0 };
    WolfCertServer* s = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &s) == WOLFCERT_OK);
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, s) == 0);

    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/scep", wolfcert_server_port(s));
    WolfCertServerCfg cli = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };
    WolfCertScepCaps caps = { 0 };
    REQUIRE(wolfcert_scep_get_ca_caps(&cli, &caps) == WOLFCERT_OK);
    REQUIRE(caps.get_next_ca_cert == 0);

    WolfCertBuffer ca = { 0 };
    REQUIRE(wolfcert_scep_get_ca_cert(&cli, &ca) == WOLFCERT_OK);
    DerBuffer* ca_der = NULL;
    REQUIRE(wc_PemToDer(ca.data, (long)ca.len, CERT_TYPE,
                        &ca_der, NULL, NULL, NULL) == 0);

    WolfCertBuffer next = { 0 };
    int rc = wolfcert_scep_get_next_ca_cert(&cli, ca_der->buffer,
                                            ca_der->length, &next);
    REQUIRE(rc == WOLFCERT_ERR_NOT_FOUND);

    wc_FreeDer(&ca_der);
    wolfcert_buffer_free(&ca);

    wolfcert_server_stop(s);
    pthread_join(tid, NULL);
    wolfcert_server_free(s);
    return 0;
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    /* ---- Pending queue (PKCSReq -> PENDING -> GetCertInitial -> issued) */
    WolfCertServerCfgSrv cfg_pending = {
        .protocol = WOLFCERT_PROTO_SCEP,
        .bind_host = "127.0.0.1", .bind_port = 0,
        .scep_require_approval = 1,
    };
    WolfCertServer* s1 = NULL;
    REQUIRE(wolfcert_server_start(&cfg_pending, &s1) == WOLFCERT_OK);
    pthread_t t1;
    REQUIRE(pthread_create(&t1, NULL, server_thread, s1) == 0);
    int rc = poll_path(s1);
    wolfcert_server_stop(s1);
    pthread_join(t1, NULL);
    wolfcert_server_free(s1);
    if (rc != 0)
        return rc;

    /* ---- GetNextCACert */
    WolfCertServerCfgSrv cfg_next = {
        .protocol = WOLFCERT_PROTO_SCEP,
        .bind_host = "127.0.0.1", .bind_port = 0,
        .scep_enable_next_ca = 1,
    };
    WolfCertServer* s2 = NULL;
    REQUIRE(wolfcert_server_start(&cfg_next, &s2) == WOLFCERT_OK);
    pthread_t t2;
    REQUIRE(pthread_create(&t2, NULL, server_thread, s2) == 0);
    rc = next_ca_path(s2);
    wolfcert_server_stop(s2);
    pthread_join(t2, NULL);
    wolfcert_server_free(s2);
    if (rc != 0)
        return rc;

    rc = next_ca_disabled_path();
    if (rc != 0)
        return rc;

    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
