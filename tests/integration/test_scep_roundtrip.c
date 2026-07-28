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

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/scep.h>
#include <wolfcert/server.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>          /* SHA256h */
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>

#include "internal.h"                       /* whitebox SCEP pkiMessage helpers */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

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

/* Send a raw HTTP/1.1 GET to the plain-HTTP SCEP server on the loopback port
 * and return the numeric response status (or -1 on transport failure). An
 * optional body (with a matching Content-Length) is sent when `body` is
 * non-NULL. Used to exercise the server's malformed-GET rejection branches and
 * the GET-with-body free path, which the client API cannot produce. */
static int raw_http_status(uint16_t port, const char* target, const char* body)
{
    struct sockaddr_in addr;
    struct timeval tv;
    char req[512];
    char resp[128];
    size_t body_len = body != NULL ? strlen(body) : 0;
    int fd;
    int n;
    ssize_t r;
    int status = -1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    if (body_len > 0)
        n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
                     "Content-Length: %zu\r\n\r\n%s",
                     target, body_len, body);
    else
        n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                     target);
    if (n < 0 || (size_t)n >= sizeof(req)) {
        close(fd);
        return -1;
    }
    if (write(fd, req, (size_t)n) != (ssize_t)n) {
        close(fd);
        return -1;
    }

    r = read(fd, resp, sizeof(resp) - 1);
    if (r > 0) {
        resp[r] = '\0';
        if (strncmp(resp, "HTTP/1.1 ", 9) == 0)
            status = atoi(resp + 9);
    }

    close(fd);
    return status;
}

/* Exercise the HTTP GET PKIOperation fallback (RFC 8894 section 4.1): with a
 * caps set that does not advertise POSTPKIOperation the client carries the
 * pkiMessage base64-encoded in a GET query and the server decodes and issues
 * exactly as for POST. The issued cert is verified to chain to the CA that
 * answered the GET - the same trust check the POST path runs in main, not just
 * a PEM-marker match. The device key, CSR, issued buffer, cert manager and
 * decoded DER are owned here and freed on every return path, so a failing check
 * cannot leak them. Returns WOLFCERT_OK on success, a negative wolfCert error,
 * or -1 on a content/verification mismatch. */
static int check_get_fallback(const WolfCertServerCfg* cli,
                              const WolfCertScepCaps* caps,
                              const WolfCertKeyCfg* kcfg,
                              const uint8_t* ca_der_buf, size_t ca_der_len)
{
    WolfCertScepCaps      caps_get = *caps;
    WolfCertCertMeta      meta_get = { .subject_dn = "CN=device-scep-get" };
    WolfCertKey*          dkg = NULL;
    WolfCertBuffer        csr_get = { 0 };
    WolfCertBuffer        issued_get = { 0 };
    WOLFSSL_CERT_MANAGER* cm = NULL;
    DerBuffer*            issued_der = NULL;
    int rc;

    caps_get.post_pki_operation = 0;

    rc = wolfcert_key_generate(kcfg, &dkg);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_csr_build(dkg, &meta_get, &csr_get);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_scep_pkcs_req(cli, &caps_get, ca_der_buf, ca_der_len,
                                    dkg, csr_get.data, csr_get.len, &issued_get);

    /* The issued cert must chain to the CA that answered the GET, not merely
     * look like a PEM certificate. */
    if (rc == WOLFCERT_OK) {
        cm = wolfSSL_CertManagerNew();
        if (cm == NULL)
            rc = -1;
    }
    if (rc == WOLFCERT_OK &&
            wolfSSL_CertManagerLoadCABuffer(cm, ca_der_buf, (long)ca_der_len,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
        rc = -1;
    if (rc == WOLFCERT_OK &&
            wc_PemToDer(issued_get.data, (long)issued_get.len, CERT_TYPE,
                &issued_der, NULL, NULL, NULL) != 0)
        rc = -1;
    if (rc == WOLFCERT_OK &&
            wolfSSL_CertManagerVerifyBuffer(cm, issued_der->buffer,
                (long)issued_der->length, WOLFSSL_FILETYPE_ASN1)
                    != WOLFSSL_SUCCESS)
        rc = -1;

    wc_FreeDer(&issued_der);
    if (cm != NULL)
        wolfSSL_CertManagerFree(cm);
    wolfcert_buffer_free(&issued_get);
    wolfcert_buffer_free(&csr_get);
    wolfcert_key_free(dkg);
    return rc;
}

/* Minimal single-shot HTTP responder that answers any request with a
 * caller-supplied GetCACaps body, so a test can drive capability parsing
 * with a body the real server would never emit. */
struct caps_ctx { int listen_fd; const char* body; };

/* Bind a loopback listener and report the ephemeral port it landed on.
 * Callers run this before spawning the responder thread, so the port never
 * has to travel back across the thread boundary. */
static int listen_loopback(int* port)
{
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0)
        return -1;
    int yes = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(0),
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (bind(ls, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(ls);
        return -1;
    }
    if (listen(ls, 1) < 0) {
        close(ls);
        return -1;
    }
    socklen_t slen = sizeof(sa);
    if (getsockname(ls, (struct sockaddr*)&sa, &slen) < 0) {
        close(ls);
        return -1;
    }
    *port = ntohs(sa.sin_port);
    return ls;
}

static void* caps_srv_thread(void* arg)
{
    struct caps_ctx* cc = (struct caps_ctx*)arg;
    int cs = accept(cc->listen_fd, NULL, NULL);
    close(cc->listen_fd);
    if (cs < 0)
        return NULL;

    char buf[1024];
    size_t n = 0;
    while (n < sizeof(buf) - 1) {
        ssize_t r = recv(cs, buf + n, sizeof(buf) - 1 - n, 0);
        if (r <= 0)
            break;
        n += (size_t)r;
        buf[n] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL)
            break;
    }

    char resp[512];
    int rn = snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n%s",
        strlen(cc->body), cc->body);
    if (rn > 0)
        send(cs, resp, (size_t)rn, 0);
    shutdown(cs, SHUT_WR);
    close(cs);
    return NULL;
}

/* RFC 8894 section 3.5.2: GetCACaps is a newline-delimited list of exact
 * tokens. A future token that merely contains a known one as a substring
 * (Renewal-Extra, AESGCM) must not be read as advertising that capability. */
static int test_caps_token_matching(void)
{
    const char* caps_body =
        "POSTPKIOperation\r\n"
        "Renewal-Extra\r\n"
        "AESGCM\r\n";
    struct caps_ctx cc = { .listen_fd = -1, .body = caps_body };
    pthread_t tid;
    int port = 0;
    cc.listen_fd = listen_loopback(&port);
    REQUIRE(cc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, caps_srv_thread, &cc) == 0);

    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/scep", port);
    WolfCertServerCfg cli = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };
    WolfCertScepCaps caps = { 0 };
    REQUIRE(wolfcert_scep_get_ca_caps(&cli, &caps) == WOLFCERT_OK);
    pthread_join(tid, NULL);

    /* Exact token still matches; substring-only lines do not. */
    REQUIRE(caps.post_pki_operation == 1);
    REQUIRE(caps.renewal == 0);
    REQUIRE(caps.aes == 0);
    return 0;
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    if (test_caps_token_matching())
        return 1;

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
    REQUIRE(caps.post_pki_operation);
    REQUIRE(caps.sha256);

    WolfCertBuffer ca_pem = { 0 };
    REQUIRE(wolfcert_scep_get_ca_cert(&cli, &ca_pem) == WOLFCERT_OK);
    DerBuffer* ca_der = NULL;
    REQUIRE(wc_PemToDer(ca_pem.data, (long)ca_pem.len, CERT_TYPE,
                        &ca_der, NULL, NULL, NULL) == 0);

    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_RSA, .param = 2048,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    WolfCertCertMeta meta = { .subject_dn = "CN=device-scep-1" };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertBuffer issued = { 0 };
    int rc = wolfcert_scep_pkcs_req(&cli, &caps, ca_der->buffer, ca_der->length,
                                    dk, csr.data, csr.len, &issued);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "SCEP rc=%d (%s)\n", rc, wolfcert_strerror(rc));
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(memmem(issued.data, issued.len, "BEGIN CERTIFICATE", 17) != NULL);

    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    REQUIRE(cm != NULL);
    REQUIRE(wolfSSL_CertManagerLoadCABuffer(cm, ca_pem.data, (long)ca_pem.len,
                                            WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS);
    DerBuffer* issued_der = NULL;
    REQUIRE(wc_PemToDer(issued.data, (long)issued.len, CERT_TYPE,
                        &issued_der, NULL, NULL, NULL) == 0);
    REQUIRE(wolfSSL_CertManagerVerifyBuffer(cm, issued_der->buffer,
                                            (long)issued_der->length,
                                            WOLFSSL_FILETYPE_ASN1) == WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);

    /* ---- HTTP GET PKIOperation fallback (RFC 8894 section 4.1) ------------
     * Driven from a helper that owns and frees the device key, CSR and issued
     * buffer so a failing assertion cannot leak them. */
    REQUIRE(check_get_fallback(&cli, &caps, &kcfg,
                               ca_der->buffer, ca_der->length) == WOLFCERT_OK);

    /* Negative GET PKIOperation branches (RFC 8894 section 4.1): the server must
     * reject each malformed request with 400. These cannot be produced by the
     * client API, so drive the running server over a raw socket. */
    REQUIRE(raw_http_status(wolfcert_server_port(s),
                "/scep?operation=PKIOperation", NULL) == 400);              /* no message= */
    REQUIRE(raw_http_status(wolfcert_server_port(s),
                "/scep?operation=PKIOperation&message=%ZZ", NULL) == 400);  /* bad %-escape */
    REQUIRE(raw_http_status(wolfcert_server_port(s),
                "/scep?operation=PKIOperation&message=@@@@", NULL) == 400); /* bad base64  */

    /* A GET carrying a spurious Content-Length body: read_request allocates
     * req->body for it, and handle_pki_op_get must free that before installing
     * the decoded message or it leaks (caught under ASan). "QUJD" is valid
     * base64 so the decode succeeds and the free path runs; the payload is not a
     * real pkiMessage, so the request is rejected with 400. */
    REQUIRE(raw_http_status(wolfcert_server_port(s),
                "/scep?operation=PKIOperation&message=QUJD", "XYZ") == 400); /* body freed */

#ifdef WOLFCERT_HAVE_ED25519
    /* Ed25519 signer must be rejected cleanly (RFC 8894 requires RSA). */
    WolfCertKeyCfg edcfg = { .type = WOLFCERT_KEY_ED25519, .param = 0,
                             .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* edk = NULL;
    REQUIRE(wolfcert_key_generate(&edcfg, &edk) == WOLFCERT_OK);
    WolfCertCertMeta edmeta = { .subject_dn = "CN=ed-scep" };
    WolfCertBuffer edcsr = { 0 };
    REQUIRE(wolfcert_csr_build(edk, &edmeta, &edcsr) == WOLFCERT_OK);
    WolfCertBuffer edout = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req(&cli, &caps, ca_der->buffer, ca_der->length,
                                   edk, edcsr.data, edcsr.len, &edout)
            == WOLFCERT_ERR_UNSUPPORTED);
    wolfcert_buffer_free(&edcsr);
    wolfcert_key_free(edk);
#endif

    wolfcert_server_stop(s);
    pthread_join(tid, NULL);
    wolfcert_server_free(s);

    /* ---- Challenge password (RFC 8894 section 2.9) -------------------------
     * Fresh server configured to require a challenge. Enrolling without
     * it or with the wrong value must fail; the correct value must issue. */
    WolfCertServerCfgSrv cfg2 = { .protocol = WOLFCERT_PROTO_SCEP,
                                  .bind_host = "127.0.0.1", .bind_port = 0,
                                  .challenge_password = "correct-horse" };
    WolfCertServer* s2 = NULL;
    REQUIRE(wolfcert_server_start(&cfg2, &s2) == WOLFCERT_OK);
    pthread_t tid2;
    REQUIRE(pthread_create(&tid2, NULL, server_thread, s2) == 0);

    char url2[128];
    snprintf(url2, sizeof(url2), "http://127.0.0.1:%u/scep", wolfcert_server_port(s2));
    WolfCertServerCfg cli2 = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url2 };

    WolfCertScepCaps caps2 = { 0 };
    REQUIRE(wolfcert_scep_get_ca_caps(&cli2, &caps2) == WOLFCERT_OK);
    WolfCertBuffer ca2_pem = { 0 };
    REQUIRE(wolfcert_scep_get_ca_cert(&cli2, &ca2_pem) == WOLFCERT_OK);
    DerBuffer* ca2_der = NULL;
    REQUIRE(wc_PemToDer(ca2_pem.data, (long)ca2_pem.len, CERT_TYPE,
                        &ca2_der, NULL, NULL, NULL) == 0);

    WolfCertKey* dk2 = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk2) == WOLFCERT_OK);

    /* 1) no challenge in CSR -> server answers with a signed CertRep FAILURE
     * (RFC 8894 pkiStatus=2), which the client surfaces as ERR_PROTOCOL.
     * A plain HTTP 4xx here would instead read back as ERR_HTTP. */
    WolfCertCertMeta meta_none = { .subject_dn = "CN=chal-none" };
    WolfCertBuffer csr_none = { 0 };
    REQUIRE(wolfcert_csr_build(dk2, &meta_none, &csr_none) == WOLFCERT_OK);
    WolfCertBuffer out_none = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req(&cli2, &caps2, ca2_der->buffer, ca2_der->length,
                                    dk2, csr_none.data, csr_none.len, &out_none)
            == WOLFCERT_ERR_PROTOCOL);
    wolfcert_buffer_free(&csr_none);

    /* 2) wrong challenge -> same CertRep FAILURE path */
    WolfCertCertMeta meta_bad = { .subject_dn = "CN=chal-bad",
                                  .challenge_password = "battery-staple" };
    WolfCertBuffer csr_bad = { 0 };
    REQUIRE(wolfcert_csr_build(dk2, &meta_bad, &csr_bad) == WOLFCERT_OK);
    WolfCertBuffer out_bad = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req(&cli2, &caps2, ca2_der->buffer, ca2_der->length,
                                    dk2, csr_bad.data, csr_bad.len, &out_bad)
            == WOLFCERT_ERR_PROTOCOL);
    wolfcert_buffer_free(&csr_bad);

    /* 3) correct challenge -> issuance succeeds */
    WolfCertCertMeta meta_ok = { .subject_dn = "CN=chal-ok",
                                 .challenge_password = "correct-horse" };
    WolfCertBuffer csr_ok = { 0 };
    REQUIRE(wolfcert_csr_build(dk2, &meta_ok, &csr_ok) == WOLFCERT_OK);
    WolfCertBuffer out_ok = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req(&cli2, &caps2, ca2_der->buffer, ca2_der->length,
                                    dk2, csr_ok.data, csr_ok.len, &out_ok)
            == WOLFCERT_OK);
    REQUIRE(memmem(out_ok.data, out_ok.len, "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_buffer_free(&csr_ok);
    wolfcert_buffer_free(&out_ok);

    wolfcert_server_stop(s2);
    pthread_join(tid2, NULL);
    wolfcert_server_free(s2);
    wc_FreeDer(&ca2_der);
    wolfcert_buffer_free(&ca2_pem);
    wolfcert_key_free(dk2);

    /* ---- recipientNonce round-trips (RFC 8894 section 3.2.1.2) ------------
     * The SCEP server now always emits recipientNonce in its CertRep (on any
     * malloc-enabled wolfSSL), and the client rejects a CertRep whose
     * recipientNonce fails to echo the senderNonce it sent (exercised by the
     * successful enrollments above). This whitebox check asserts the encoder
     * actually puts the nonce on the wire and the parser recovers it intact. */
    {
        WC_RNG rng;
        REQUIRE(wc_InitRng(&rng) == 0);
        RsaKey rsa;
        REQUIRE(wc_InitRsaKey(&rsa, NULL) == 0);
        REQUIRE(wc_MakeRsaKey(&rsa, 2048, 65537, &rng) == 0);

        Cert sc;
        REQUIRE(wc_InitCert(&sc) == 0);
        strncpy(sc.subject.commonName, "scep-nonce", CTC_NAME_SIZE - 1);
        sc.sigType = CTC_SHA256wRSA;
        uint8_t signer_cert[2048];
        int cl = wc_MakeSelfCert(&sc, signer_cert, sizeof(signer_cert), &rsa, &rng);
        REQUIRE(cl > 0);

        uint8_t signer_key[2048];
        int kl = wc_RsaKeyToDer(&rsa, signer_key, sizeof(signer_key));
        REQUIRE(kl > 0);

        const uint8_t content[] = { 0x04, 0x02, 0xAB, 0xCD }; /* arbitrary signed content */
        uint8_t snonce[16], rnonce[16];
        memset(snonce, 0x5A, sizeof(snonce));
        memset(rnonce, 0xA5, sizeof(rnonce));
        const uint8_t wtid[16] = { 0 };
        WolfCertScepAttrs wattrs = {
            .transaction_id  = wtid,   .transaction_id_len  = sizeof(wtid),
            .sender_nonce    = snonce, .sender_nonce_len    = sizeof(snonce),
            .message_type    = "3",    .pki_status          = "0",
            .recipient_nonce = rnonce, .recipient_nonce_len = sizeof(rnonce),
        };
        WolfCertBuffer wmsg = { 0 };
        REQUIRE(wolfcert_scep_build_pki_message(content, sizeof(content),
                    signer_cert, (size_t)cl, signer_key, (size_t)kl,
                    SHA256h, &wattrs, &wmsg, NULL) == WOLFCERT_OK);

        WolfCertBuffer wenv = { 0 };
        uint8_t *w_tid = NULL, *w_sn = NULL, *w_rn = NULL, *w_sc = NULL;
        size_t   w_tidl = 0,   w_snl = 0,   w_rnl = 0,   w_scl = 0;
        char    *w_mt = NULL,  *w_st = NULL;
        REQUIRE(wolfcert_scep_parse_pki_message(wmsg.data, wmsg.len, &wenv,
                    &w_tid, &w_tidl, &w_sn, &w_snl, &w_rn, &w_rnl,
                    &w_mt, &w_st, &w_sc, &w_scl, NULL, NULL) == WOLFCERT_OK);
        REQUIRE(w_rn != NULL);                              /* present */
        REQUIRE(w_rnl == sizeof(rnonce));
        REQUIRE(memcmp(w_rn, rnonce, sizeof(rnonce)) == 0); /* unchanged */

        WOLFCERT_XFREE(w_tid, NULL); WOLFCERT_XFREE(w_sn, NULL);
        WOLFCERT_XFREE(w_rn,  NULL); WOLFCERT_XFREE(w_sc, NULL);
        WOLFCERT_XFREE(w_mt,  NULL); WOLFCERT_XFREE(w_st, NULL);
        wolfcert_buffer_free(&wenv);
        wolfcert_buffer_free(&wmsg);
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
    }

    /* ---- Absent recipientNonce in a CertRep must be rejected -------------
     * RFC 8894 section 3.2.1.2 requires the sender to verify the CertRep's
     * recipientNonce echoes the senderNonce it sent. A CertRep that carries
     * no recipientNonce cannot be verified, so the client must reject it.
     * Drive a server that deliberately omits the nonce and confirm the
     * enrollment fails instead of accepting the reply. */
    WolfCertServerCfgSrv cfg3 = { .protocol = WOLFCERT_PROTO_SCEP,
                                  .bind_host = "127.0.0.1", .bind_port = 0 };
    WolfCertServer* s3 = NULL;
    REQUIRE(wolfcert_server_start(&cfg3, &s3) == WOLFCERT_OK);
    wolfcert_scep_server_set_faults(s3, 1 /* omit recipientNonce */, 0, 0);
    pthread_t tid3;
    REQUIRE(pthread_create(&tid3, NULL, server_thread, s3) == 0);

    char url3[128];
    snprintf(url3, sizeof(url3), "http://127.0.0.1:%u/scep", wolfcert_server_port(s3));
    WolfCertServerCfg cli3 = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url3 };

    WolfCertScepCaps caps3 = { 0 };
    REQUIRE(wolfcert_scep_get_ca_caps(&cli3, &caps3) == WOLFCERT_OK);
    WolfCertBuffer ca3_pem = { 0 };
    REQUIRE(wolfcert_scep_get_ca_cert(&cli3, &ca3_pem) == WOLFCERT_OK);
    DerBuffer* ca3_der = NULL;
    REQUIRE(wc_PemToDer(ca3_pem.data, (long)ca3_pem.len, CERT_TYPE,
                        &ca3_der, NULL, NULL, NULL) == 0);

    WolfCertKey* dk3 = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk3) == WOLFCERT_OK);
    WolfCertCertMeta meta3 = { .subject_dn = "CN=scep-no-rnonce" };
    WolfCertBuffer csr3 = { 0 };
    REQUIRE(wolfcert_csr_build(dk3, &meta3, &csr3) == WOLFCERT_OK);
    WolfCertBuffer out3 = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req(&cli3, &caps3, ca3_der->buffer, ca3_der->length,
                                   dk3, csr3.data, csr3.len, &out3)
            == WOLFCERT_ERR_PROTOCOL);

    wolfcert_server_stop(s3);
    pthread_join(tid3, NULL);
    wolfcert_server_free(s3);
    wc_FreeDer(&ca3_der);
    wolfcert_buffer_free(&ca3_pem);
    wolfcert_buffer_free(&csr3);
    wolfcert_buffer_free(&out3);
    wolfcert_key_free(dk3);

    /* ---- CertRep signed by a non-CA key must be rejected ----------------
     * RFC 8894 authenticates the CertRep through its CMS signature. A reply
     * signed by a key other than the trusted CA (a rogue server or a man in
     * the middle) must be rejected. Drive a server that signs with a throwaway
     * key and confirm the enrollment fails with an auth error rather than
     * accepting the attacker-controlled certificate. */
    WolfCertServerCfgSrv cfg4 = { .protocol = WOLFCERT_PROTO_SCEP,
                                  .bind_host = "127.0.0.1", .bind_port = 0 };
    WolfCertServer* s4 = NULL;
    REQUIRE(wolfcert_server_start(&cfg4, &s4) == WOLFCERT_OK);
    wolfcert_scep_server_set_faults(s4, 0, 1 /* sign with wrong key */, 0);
    pthread_t tid4;
    REQUIRE(pthread_create(&tid4, NULL, server_thread, s4) == 0);

    char url4[128];
    snprintf(url4, sizeof(url4), "http://127.0.0.1:%u/scep", wolfcert_server_port(s4));
    WolfCertServerCfg cli4 = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url4 };

    WolfCertScepCaps caps4 = { 0 };
    REQUIRE(wolfcert_scep_get_ca_caps(&cli4, &caps4) == WOLFCERT_OK);
    WolfCertBuffer ca4_pem = { 0 };
    REQUIRE(wolfcert_scep_get_ca_cert(&cli4, &ca4_pem) == WOLFCERT_OK);
    DerBuffer* ca4_der = NULL;
    REQUIRE(wc_PemToDer(ca4_pem.data, (long)ca4_pem.len, CERT_TYPE,
                        &ca4_der, NULL, NULL, NULL) == 0);

    WolfCertKey* dk4 = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk4) == WOLFCERT_OK);
    WolfCertCertMeta meta4 = { .subject_dn = "CN=scep-wrong-signer" };
    WolfCertBuffer csr4 = { 0 };
    REQUIRE(wolfcert_csr_build(dk4, &meta4, &csr4) == WOLFCERT_OK);
    WolfCertBuffer out4 = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req(&cli4, &caps4, ca4_der->buffer, ca4_der->length,
                                   dk4, csr4.data, csr4.len, &out4)
            == WOLFCERT_ERR_AUTH);

    wolfcert_server_stop(s4);
    pthread_join(tid4, NULL);
    wolfcert_server_free(s4);
    wc_FreeDer(&ca4_der);
    wolfcert_buffer_free(&ca4_pem);
    wolfcert_buffer_free(&csr4);
    wolfcert_buffer_free(&out4);
    wolfcert_key_free(dk4);

    /* ---- senderNonce RNG failure must abort, not leak stack -------------
     * If the RNG draw for the CertRep senderNonce fails, the server must not
     * build a CertRep over an uninitialized buffer. It frees its scratch,
     * answers HTTP 500, and returns an error, which the client sees as a
     * transport failure. Drive a server whose nonce draw is forced to fail
     * and confirm the enrollment does not succeed. This also exercises the
     * error-path cleanup under the sanitizer builds. */
    WolfCertServerCfgSrv cfg5 = { .protocol = WOLFCERT_PROTO_SCEP,
                                  .bind_host = "127.0.0.1", .bind_port = 0 };
    WolfCertServer* s5 = NULL;
    REQUIRE(wolfcert_server_start(&cfg5, &s5) == WOLFCERT_OK);
    wolfcert_scep_server_set_faults(s5, 0, 0, 1 /* RNG draw fails */);
    pthread_t tid5;
    REQUIRE(pthread_create(&tid5, NULL, server_thread, s5) == 0);

    char url5[128];
    snprintf(url5, sizeof(url5), "http://127.0.0.1:%u/scep", wolfcert_server_port(s5));
    WolfCertServerCfg cli5 = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url5 };

    WolfCertScepCaps caps5 = { 0 };
    REQUIRE(wolfcert_scep_get_ca_caps(&cli5, &caps5) == WOLFCERT_OK);
    WolfCertBuffer ca5_pem = { 0 };
    REQUIRE(wolfcert_scep_get_ca_cert(&cli5, &ca5_pem) == WOLFCERT_OK);
    DerBuffer* ca5_der = NULL;
    REQUIRE(wc_PemToDer(ca5_pem.data, (long)ca5_pem.len, CERT_TYPE,
                        &ca5_der, NULL, NULL, NULL) == 0);

    WolfCertKey* dk5 = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk5) == WOLFCERT_OK);
    WolfCertCertMeta meta5 = { .subject_dn = "CN=scep-rng-fail" };
    WolfCertBuffer csr5 = { 0 };
    REQUIRE(wolfcert_csr_build(dk5, &meta5, &csr5) == WOLFCERT_OK);
    WolfCertBuffer out5 = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req(&cli5, &caps5, ca5_der->buffer, ca5_der->length,
                                   dk5, csr5.data, csr5.len, &out5)
            == WOLFCERT_ERR_HTTP);

    wolfcert_server_stop(s5);
    pthread_join(tid5, NULL);
    wolfcert_server_free(s5);
    wc_FreeDer(&ca5_der);
    wolfcert_buffer_free(&ca5_pem);
    wolfcert_buffer_free(&csr5);
    wolfcert_buffer_free(&out5);
    wolfcert_key_free(dk5);

    wc_FreeDer(&ca_der);
    wc_FreeDer(&issued_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&issued);
    wolfcert_key_free(dk);
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
