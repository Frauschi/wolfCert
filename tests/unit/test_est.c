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
 * End-to-end test of the EST client module against a single-shot loopback
 * HTTP responder.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include "internal.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>

#include "../integration/tls_test_util.h"

#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static int make_test_ca(uint8_t* out, size_t cap, size_t* out_len)
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
    strcpy(cert.subject.commonName, "wolfCert Test CA");
    strcpy(cert.subject.org,        "wolfCert");
    strcpy(cert.subject.country,    "US");
    cert.isCA       = 1;
    cert.sigType    = CTC_SHA256wRSA;
    cert.selfSigned = 1;
    int sz = wc_MakeSelfCert(&cert, out, (word32)cap, &key, &rng);
    if (sz <= 0)
        goto fail;
    *out_len = (size_t)sz;
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    return 0;
fail:
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    return -1;
}

/* EST is TLS-only (RFC 7030), so the mock responder terminates TLS using a
 * self-signed identity the client pins as its trust anchor. */
struct srv_ctx { int port; uint8_t* body; size_t len; WOLFSSL_CTX* ctx; };

static void tls_write_all(WOLFSSL* ssl, const void* buf, int len)
{
    const uint8_t* p = buf;
    int n = 0;
    while (n < len) {
        int r = wolfSSL_write(ssl, p + n, len - n);
        if (r <= 0)
            break;
        n += r;
    }
}

static void handle_conn(int cs, const struct srv_ctx* sc)
{
    WOLFSSL* ssl = wolfSSL_new(sc->ctx);
    if (ssl == NULL) {
        close(cs);
        return;
    }
    wolfSSL_set_fd(ssl, cs);
    if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {
        wolfSSL_free(ssl);
        close(cs);
        return;
    }

    /* Read the request headers, then drain the body. The canned response is
     * the same regardless of the request, but we must still consume the whole
     * request before responding + closing: a POST /simpleenroll carries the
     * CSR, and shutting the connection while the client is still writing that
     * body races the client's send and intermittently fails the enroll. */
    char buf[8192];
    int n = 0;
    char* hdr_end = NULL;
    while (n < (int)sizeof(buf) - 1) {
        int r = wolfSSL_read(ssl, buf + n, (int)sizeof(buf) - 1 - n);
        if (r <= 0)
            break;
        n += r;
        buf[n] = '\0';
        hdr_end = strstr(buf, "\r\n\r\n");
        if (hdr_end != NULL)
            break;
    }

    if (hdr_end != NULL) {
        int  header_len = (int)(hdr_end - buf) + 4;
        long content_length = 0;
        char* cl = strcasestr(buf, "Content-Length:");
        if (cl != NULL && cl < hdr_end)
            content_length = strtol(cl + 15, NULL, 10);

        while ((long)(n - header_len) < content_length &&
               n < (int)sizeof(buf) - 1) {
            int r = wolfSSL_read(ssl, buf + n, (int)sizeof(buf) - 1 - n);
            if (r <= 0)
                break;
            n += r;
        }
    }

    char hdr[256];
    int hn = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/pkcs7-mime; smime-type=certs-only\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n", sc->len);
    tls_write_all(ssl, hdr, hn);
    tls_write_all(ssl, sc->body, (int)sc->len);
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(cs);
}

static void* srv_thread(void* arg)
{
    struct srv_ctx* sc = (struct srv_ctx*)arg;
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0)
        return NULL;
    int yes = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(0),
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bind(ls, (struct sockaddr*)&sa, sizeof(sa));
    listen(ls, 2);
    socklen_t slen = sizeof(sa);
    getsockname(ls, (struct sockaddr*)&sa, &slen);
    sc->port = ntohs(sa.sin_port);

    for (int i = 0; i < 3; ++i) {
        int cs = accept(ls, NULL, NULL);
        if (cs < 0)
            break;
        handle_conn(cs, sc);
    }
    close(ls);
    return NULL;
}

/* wolfcert_oid_to_dotted must decode the first two arcs correctly even when
 * the leading byte is >= 120 (node1 == 2, node2 >= 40), not just for the
 * common OIDs whose first byte is < 80. */
static int test_oid_to_dotted(void)
{
    char out[128];

    const uint8_t high[] = { 0x78, 0x03 };   /* 40*2 + 40 = 120 -> 2.40.3 */
    wolfcert_oid_to_dotted(high, sizeof(high), out, sizeof(out));
    REQUIRE(strcmp(out, "2.40.3") == 0);

    const uint8_t low[] = { 0x2A, 0x03 };    /* 40*1 + 2 = 42 -> 1.2.3 */
    wolfcert_oid_to_dotted(low, sizeof(low), out, sizeof(out));
    REQUIRE(strcmp(out, "1.2.3") == 0);

    /* An empty OID must still leave a valid, empty C string. */
    memset(out, 'x', sizeof(out));
    wolfcert_oid_to_dotted(NULL, 0, out, sizeof(out));
    REQUIRE(out[0] == '\0');

    return 0;
}

int main(void)
{
    /* The mock TLS responder may wolfSSL_write() after the client has read its
     * response and closed the connection ("Connection: close"); don't die on
     * the resulting SIGPIPE. */
    signal(SIGPIPE, SIG_IGN);

    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    if (test_oid_to_dotted())
        return 1;

    uint8_t ca_der[4096];
    size_t ca_len = 0;
    REQUIRE(make_test_ca(ca_der, sizeof(ca_der), &ca_len) == 0);

    const uint8_t* certs_arr[1] = { ca_der };
    size_t certs_sz[1] = { ca_len };
    WolfCertBuffer p7 = { 0 };
    REQUIRE(wolfcert_pkcs7_build_certs_only(certs_arr, certs_sz, 1, &p7, NULL) == WOLFCERT_OK);

    WolfCertBuffer b64 = { 0 };
    REQUIRE(wolfcert_base64_encode(p7.data, p7.len, &b64, NULL) == WOLFCERT_OK);
    wolfcert_buffer_free(&p7);

    /* EST runs over TLS (RFC 7030): give the mock responder a self-signed
     * identity and pin it as the client trust anchor. */
    uint8_t *tls_cert = NULL, *tls_key = NULL;
    size_t tls_cert_len = 0, tls_key_len = 0;
    REQUIRE(gen_server_identity(&tls_cert, &tls_cert_len,
                                &tls_key, &tls_key_len) == 0);
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
    REQUIRE(ctx != NULL);
    REQUIRE(wolfSSL_CTX_use_certificate_buffer(ctx, tls_cert, (long)tls_cert_len,
            WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS);
    REQUIRE(wolfSSL_CTX_use_PrivateKey_buffer(ctx, tls_key, (long)tls_key_len,
            WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS);

    struct srv_ctx sc = { .body = b64.data, .len = b64.len, .ctx = ctx };
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, srv_thread, &sc) == 0);
    for (int i = 0; i < 200 && sc.port == 0; ++i) {
        const struct timespec ts = { 0, 5 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    REQUIRE(sc.port != 0);

    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%d/.well-known/est", sc.port);
    WolfCertServerCfg srv = { .protocol = WOLFCERT_PROTO_EST, .server_url = url,
                              .trust_anchors = tls_cert,
                              .trust_anchors_len = tls_cert_len,
                              .verify_server = 1 };

    WolfCertBuffer ca_pem = { 0 };
    REQUIRE(wolfcert_est_get_cacerts(&srv, &ca_pem) == WOLFCERT_OK);
    REQUIRE(memmem(ca_pem.data, ca_pem.len, "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_buffer_free(&ca_pem);

    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    WolfCertCertMeta meta = { .subject_dn = "CN=device-99" };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertBuffer enrolled = { 0 };
    REQUIRE(wolfcert_est_simple_enroll(&srv, csr.data, csr.len, &enrolled) == WOLFCERT_OK);
    REQUIRE(memmem(enrolled.data, enrolled.len, "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_buffer_free(&enrolled);

    WolfCertBuffer reenrolled = { 0 };
    REQUIRE(wolfcert_est_simple_reenroll(&srv, ca_der, ca_len, dk,
                                         csr.data, csr.len, &reenrolled) == WOLFCERT_OK);
    wolfcert_buffer_free(&reenrolled);

    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);
    wolfcert_buffer_free(&b64);
    pthread_join(tid, NULL);
    wolfSSL_CTX_free(ctx);
    free(tls_cert);
    free(tls_key);
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
