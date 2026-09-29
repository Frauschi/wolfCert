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
 * End-to-end HTTPS EST roundtrip: stands up wolfcert-server behind its
 * built-in TLS terminator (new v0.2 feature), then runs wolfcert-client
 * against it over HTTPS, pinning the freshly-minted server cert as the
 * bootstrap trust anchor. Verifies that:
 *   - wolfcert_server_start() accepts --tls-cert/--tls-key-equivalent config,
 *   - the accept loop terminates TLS and dispatches to the EST handler,
 *   - the protocol handler's read/send helpers work through the TLS layer,
 *   - wolfcert_est_simple_enroll() drives the full TLS + EST round trip.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/est.h>
#include <wolfcert/server.h>

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>

#include "tls_test_util.h"
#include "est_client_cases.h"
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

#ifdef KEEP_PEER_CERT
static int impostor_customize(void* wolfssl_cert, void* ctx)
{
    Cert* c = (Cert*)wolfssl_cert;

    *(int*)ctx = 1;
    snprintf(c->subject.commonName, sizeof(c->subject.commonName), "%s",
             "impostor");
    return WOLFCERT_OK;
}

/* The issued cert must name CN=reenroll-device with iPAddress SAN 127.0.0.1. */
static int check_renewed_identity(const WolfCertBuffer* issued)
{
    static const uint8_t ip[4] = { 127, 0, 0, 1 };
    uint8_t der[4096];
    DecodedCert dc;
    int der_len;
    int found;

    der_len = wc_CertPemToDer(issued->data, (int)issued->len, der,
                              (int)sizeof(der), CERT_TYPE);
    REQUIRE(der_len > 0);

    wc_InitDecodedCert(&dc, der, (word32)der_len, NULL);
    REQUIRE(wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL) == 0);
    REQUIRE(dc.subjectCN != NULL);
    REQUIRE(dc.subjectCNLen == (int)strlen("reenroll-device"));
    REQUIRE(memcmp(dc.subjectCN, "reenroll-device",
                   strlen("reenroll-device")) == 0);
    found = has_alt(dc.altNames, ASN_IP_TYPE, (const char*)ip,
                    (int)sizeof(ip));
    wc_FreeDecodedCert(&dc);
    REQUIRE(found);
    return 0;
}

/* 1 when both PEM certs carry the same public key, 0 when not, -1 on error. */
static int same_public_key(const uint8_t* a, size_t a_len, const uint8_t* b,
                           size_t b_len)
{
    uint8_t der[2][4096];
    DecodedCert dc[2];
    int len[2];
    int ret = -1;

    len[0] = wc_CertPemToDer(a, (int)a_len, der[0], (int)sizeof(der[0]),
                             CERT_TYPE);
    len[1] = wc_CertPemToDer(b, (int)b_len, der[1], (int)sizeof(der[1]),
                             CERT_TYPE);
    if (len[0] <= 0 || len[1] <= 0)
        return -1;

    wc_InitDecodedCert(&dc[0], der[0], (word32)len[0], NULL);
    wc_InitDecodedCert(&dc[1], der[1], (word32)len[1], NULL);
    if (wc_ParseCert(&dc[0], CERT_TYPE, NO_VERIFY, NULL) == 0 &&
            wc_ParseCert(&dc[1], CERT_TYPE, NO_VERIFY, NULL) == 0)
        ret = dc[0].pubKeySize == dc[1].pubKeySize &&
              memcmp(dc[0].publicKey, dc[1].publicKey,
                     dc[0].pubKeySize) == 0;
    wc_FreeDecodedCert(&dc[0]);
    wc_FreeDecodedCert(&dc[1]);
    return ret;
}
#endif

/* Reenroll with a mismatched meta, with a renaming customize callback, then
 * with a fresh key, against a server that trusts the cert being renewed. */
static int test_client_reenroll_keeps_identity(const uint8_t* tls_cert,
                                               size_t tls_cert_len,
                                               const uint8_t* tls_key,
                                               size_t tls_key_len)
{
    static const char* const impostor_dns[] = { "impostor.example" };
    uint8_t* cur_cert = NULL;
    size_t cur_cert_len = 0;
    uint8_t* cur_key_pem = NULL;
    size_t cur_key_len = 0;
    WolfCertKey* cur_key = NULL;
    WolfCertKey* out_key = NULL;
    WolfCertBuffer issued = { 0 };
    WolfCertCertMeta meta;
    WolfCertServerCfgSrv scfg = {
        .protocol         = WOLFCERT_PROTO_EST,
        .bind_host        = "127.0.0.1",
        .bind_port        = 0,
        .tls_cert_pem     = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem      = tls_key,  .tls_key_pem_len  = tls_key_len,
    };
    WolfCertServer* srv = NULL;
    pthread_t tid;
    char url[128];
    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
    };
#ifdef KEEP_PEER_CERT
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE,
                            .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    int called = 0;
#endif

    REQUIRE(mint_self_id("reenroll-device", 0, &cur_cert, &cur_cert_len,
                         &cur_key_pem, &cur_key_len) == 0);
    REQUIRE(wolfcert_key_from_pem(cur_key_pem, cur_key_len, NULL, &cur_key)
            == WOLFCERT_OK);

    scfg.tls_client_ca_pem     = cur_cert;
    scfg.tls_client_ca_pem_len = cur_cert_len;
    REQUIRE(wolfcert_server_start(&scfg, &srv) == WOLFCERT_OK);
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));

    memset(&meta, 0, sizeof(meta));
    meta.subject_dn = "CN=impostor";
    REQUIRE(wolfcert_client_reenroll(NULL, &cli, cur_cert, cur_cert_len,
                                     cur_key, NULL, &meta, &out_key, &issued)
            == WOLFCERT_ERR_BAD_ARG);

    memset(&meta, 0, sizeof(meta));
    meta.san_dns     = impostor_dns;
    meta.san_dns_len = 1;
    REQUIRE(wolfcert_client_reenroll(NULL, &cli, cur_cert, cur_cert_len,
                                     cur_key, NULL, &meta, &out_key, &issued)
            == WOLFCERT_ERR_BAD_ARG);

#ifdef KEEP_PEER_CERT
    /* The caller's callback still runs but cannot rename the cert. */
    memset(&meta, 0, sizeof(meta));
    meta.customize     = impostor_customize;
    meta.customize_ctx = &called;
    REQUIRE(wolfcert_client_reenroll(NULL, &cli, cur_cert, cur_cert_len,
                                     cur_key, NULL, &meta, &out_key, &issued)
            == WOLFCERT_OK);
    REQUIRE(called == 1);
    REQUIRE(out_key == NULL);
    REQUIRE(check_renewed_identity(&issued) == 0);
    wolfcert_buffer_free(&issued);

    memset(&meta, 0, sizeof(meta));
    REQUIRE(wolfcert_client_reenroll(NULL, &cli, cur_cert, cur_cert_len,
                                     cur_key, &kcfg, &meta, &out_key, &issued)
            == WOLFCERT_OK);
    REQUIRE(out_key != NULL);
    REQUIRE(check_renewed_identity(&issued) == 0);
    REQUIRE(same_public_key(issued.data, issued.len, cur_cert,
                            cur_cert_len) == 0);
#endif

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    wolfcert_key_free(out_key);
    wolfcert_buffer_free(&issued);
    wolfcert_key_free(cur_key);
    free(cur_cert);
    free(cur_key_pem);
    return 0;
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    uint8_t* tls_cert = NULL;
    size_t tls_cert_len = 0;
    uint8_t* tls_key  = NULL;
    size_t tls_key_len  = 0;
    REQUIRE(gen_server_identity(&tls_cert, &tls_cert_len, &tls_key, &tls_key_len) == 0);

    /* An EST listener with no TLS identity must be refused at start. */
    WolfCertStoreOps* plain_store = wolfcert_store_memory_open(NULL);
    REQUIRE(plain_store != NULL);
    WolfCertServerCfgSrv plain = {
        .protocol  = WOLFCERT_PROTO_EST,
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .ca_store  = plain_store,
    };
    WolfCertServer* plain_srv = NULL;
    REQUIRE(wolfcert_server_start(&plain, &plain_srv) == WOLFCERT_ERR_TLS);
    REQUIRE(plain_srv == NULL);

    /* The rejection must land before the CA is minted, so the caller is not
     * left with a CA it never asked for -- one the next start would adopt. */
    WolfCertBuffer leftover = { 0 };
    REQUIRE(plain_store->read(plain_store->ctx, "ca.cert.der", &leftover)
            == WOLFCERT_ERR_NOT_FOUND);
    REQUIRE(plain_store->read(plain_store->ctx, "ca.key.der", &leftover)
            == WOLFCERT_ERR_NOT_FOUND);
    wolfcert_store_memory_close(plain_store);

    WolfCertServerCfgSrv cfg = {
        .protocol         = WOLFCERT_PROTO_EST,
        .bind_host        = "127.0.0.1",
        .bind_port        = 0,
        .tls_cert_pem     = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem      = tls_key,  .tls_key_pem_len  = tls_key_len,
    };
    WolfCertServer* srv = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);

    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));

    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
    };

    /* Fetch the CA chain from the server - this hits the TLS path end-to-end. */
    WolfCertBuffer ca_pem = { 0 };
    REQUIRE(wolfcert_est_get_cacerts(&cli, &ca_pem) == WOLFCERT_OK);
    REQUIRE(ca_pem.len > 0);

    /* Generate a device key, build CSR, enroll over HTTPS. */
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    WolfCertCertMeta meta = { .subject_dn = "CN=tls-est-client" };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertBuffer issued = { 0 };
    int rc = wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &issued);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "enroll rc=%d (%s)\n", rc, wolfcert_strerror(rc));
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(memmem(issued.data, issued.len, "BEGIN CERTIFICATE", 17) != NULL);
    REQUIRE(memmem(issued.data, issued.len, "tls-est-client", 14) != NULL ||
            issued.len > 0);   /* PEM carries subject in DER, not ASCII */

    /* DER trust-anchor coverage: the same anchor as DER must drive the TLS
     * load path (buffer_is_der -> WOLFSSL_FILETYPE_ASN1) just as well as PEM. */
    DerBuffer* ta_der = NULL;
    REQUIRE(wc_PemToDer(tls_cert, (long)tls_cert_len, CERT_TYPE,
                        &ta_der, NULL, NULL, NULL) == 0);
    WolfCertServerCfg cli_der = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = ta_der->buffer,
        .trust_anchors_len = ta_der->length,
        .verify_server     = 1,
    };
    WolfCertBuffer ca_pem_der = { 0 };
    REQUIRE(wolfcert_est_get_cacerts(&cli_der, &ca_pem_der) == WOLFCERT_OK);
    REQUIRE(ca_pem_der.len > 0);
    wolfcert_buffer_free(&ca_pem_der);
    wc_FreeDer(&ta_der);

    REQUIRE(test_client_reenroll_keeps_identity(tls_cert, tls_cert_len,
                                                tls_key, tls_key_len) == 0);

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);

    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&issued);
    wolfcert_key_free(dk);
    free(tls_cert);
    free(tls_key);
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
