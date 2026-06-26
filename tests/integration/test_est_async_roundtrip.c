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
 * End-to-end non-blocking EST session driven through a real poll(2)
 * loop. Exercises:
 *   - wolfcert_est_session_open_async (TLS handshake async),
 *   - wolfcert_est_session_get_cacerts_nb (anonymous /cacerts),
 *   - wolfcert_est_session_simple_enroll_nb (/simpleenroll under
 *     TLS 1.3 post-handshake auth),
 * all on a single TLS connection whose fd is fed to poll() between
 * WOLFCERT_ERR_WANT_READ / _WANT_WRITE returns.
 *
 * Mirrors test_est_pha_roundtrip's scenario but with the caller
 * explicitly owning the event loop.
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
#include <wolfssl/wolfcrypt/rsa.h>

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

static int mint_rsa_id(const char* cn, int is_ca,
                       uint8_t** cert_pem, size_t* cert_pem_len,
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
    strcpy(cert.subject.commonName, cn);
    cert.selfSigned = 1;
    cert.sigType = CTC_SHA256wRSA;
    cert.daysValid = 1;
    cert.isCA = is_ca ? 1 : 0;
    if (!is_ca) {
        static const uint8_t san_seq[] = { 0x30, 0x06, 0x87, 0x04, 127, 0, 0, 1 };
        memcpy(cert.altNames, san_seq, sizeof(san_seq));
        cert.altNamesSz = (int)sizeof(san_seq);
    }
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

    *cert_pem = malloc((size_t)cp);
    memcpy(*cert_pem, cpem, (size_t)cp);
    *cert_pem_len = (size_t)cp;
    *key_pem = malloc((size_t)kp);
    memcpy(*key_pem, kpem, (size_t)kp);
    *key_pem_len = (size_t)kp;
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    return 0;
fail:
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    return -1;
}

static void* server_thread(void* arg)
{
    wolfcert_server_run((WolfCertServer*)arg);
    return NULL;
}

/* Pump one call until it returns OK or an error. poll() in between. */
static int pump_get_cacerts(WolfCertEstSession* s, WolfCertBuffer* out)
{
    int fd = wolfcert_est_session_fd(s);
    for (;;) {
        int rc = wolfcert_est_session_get_cacerts_nb(s, out);
        if (rc == WOLFCERT_OK)
            return 0;
        if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE) {
            struct pollfd p = {
                .fd = fd,
                .events = (rc == WOLFCERT_ERR_WANT_WRITE) ? POLLOUT : POLLIN,
            };
            int pr = poll(&p, 1, 5000);
            if (pr <= 0)
                return -1;
            continue;
        }
        fprintf(stderr, "cacerts rc=%d (%s)\n", rc, wolfcert_strerror(rc));
        return -1;
    }
}

static int pump_simple_enroll(WolfCertEstSession* s,
                              const uint8_t* csr, size_t csr_len,
                              WolfCertBuffer* out)
{
    int fd = wolfcert_est_session_fd(s);
    for (;;) {
        int rc = wolfcert_est_session_simple_enroll_nb(s, csr, csr_len, out);
        if (rc == WOLFCERT_OK)
            return 0;
        if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE) {
            struct pollfd p = {
                .fd = fd,
                .events = (rc == WOLFCERT_ERR_WANT_WRITE) ? POLLOUT : POLLIN,
            };
            int pr = poll(&p, 1, 5000);
            if (pr <= 0)
                return -1;
            continue;
        }
        fprintf(stderr, "enroll rc=%d (%s) last=%s\n",
                rc, wolfcert_strerror(rc), wolfcert_last_error_message());
        return -1;
    }
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    uint8_t* tls_cert = NULL;
    size_t tls_cert_len = 0;
    uint8_t* tls_key  = NULL;
    size_t tls_key_len  = 0;
    REQUIRE(mint_rsa_id("127.0.0.1", 0,
                        &tls_cert, &tls_cert_len, &tls_key, &tls_key_len) == 0);
    uint8_t* cli_cert = NULL;
    size_t cli_cert_len = 0;
    uint8_t* cli_key  = NULL;
    size_t cli_key_len  = 0;
    REQUIRE(mint_rsa_id("async-bootstrap", 1,
                        &cli_cert, &cli_cert_len, &cli_key, &cli_key_len) == 0);

    WolfCertServerCfgSrv cfg = {
        .protocol                = WOLFCERT_PROTO_EST,
        .bind_host               = "127.0.0.1",
        .bind_port               = 0,
        .tls_cert_pem            = tls_cert, .tls_cert_pem_len       = tls_cert_len,
        .tls_key_pem             = tls_key,  .tls_key_pem_len        = tls_key_len,
        .tls_client_ca_pem       = cli_cert, .tls_client_ca_pem_len  = cli_cert_len,
        .tls_post_handshake_auth = 1,
    };
    WolfCertServer* srv = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);

    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));

    WolfCertServerCfg cli = {
        .protocol                  = WOLFCERT_PROTO_EST,
        .server_url                = url,
        .trust_anchors             = tls_cert,
        .trust_anchors_len         = tls_cert_len,
        .verify_server             = 1,
        .client_cert               = cli_cert,
        .client_cert_len           = cli_cert_len,
        .client_key                = cli_key,
        .client_key_len            = cli_key_len,
        .allow_post_handshake_auth = 1,
    };
    WolfCertEstSession* es = NULL;
    REQUIRE(wolfcert_est_session_open_async(&cli, &es) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_session_fd(es) >= 0);

    /* Anonymous /cacerts, pumped via poll(2). */
    WolfCertBuffer ca_pem = { 0 };
    REQUIRE(pump_get_cacerts(es, &ca_pem) == 0);
    REQUIRE(ca_pem.len > 0);

    /* Build a CSR off the event loop. */
    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    WolfCertCertMeta meta = { .subject_dn = "CN=async-enrollee" };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    /* /simpleenroll - server issues CertificateRequest via PHA mid-call,
     * wolfSSL answers from the pre-loaded identity. All of this is
     * pumped through poll() via WANT_READ/WANT_WRITE returns. */
    WolfCertBuffer issued = { 0 };
    REQUIRE(pump_simple_enroll(es, csr.data, csr.len, &issued) == 0);
    REQUIRE(memmem(issued.data, issued.len, "BEGIN CERTIFICATE", 17) != NULL);

    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&issued);
    wolfcert_key_free(dk);
    wolfcert_est_session_close(es);

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
