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
 * EST with a private key that never leaves its CryptoCb backend. A mock key
 * store keeps software keys by key_id and refuses to hand them out; the test
 * generates a key there, enrolls, reloads it by id from the issued
 * certificate, and re-enrolls over mTLS, checking the store performed every
 * private-key operation.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/est.h>
#ifdef WOLFCERT_HAVE_SCEP
#include <wolfcert/scep.h>
#endif
#include <wolfcert/server.h>

#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "tls_test_util.h"

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

#define MOCK_DEVID 0x6d6b
#define MOCK_SLOTS 4

typedef struct {
    byte id[WOLFCERT_KEY_ID_MAX_LEN];
    int  id_len;
    int  type;
#ifdef WOLFCERT_HAVE_ECC
    ecc_key ecc;
#endif
#ifdef WOLFCERT_HAVE_RSA
    RsaKey  rsa;
#endif
} MockSlot;

static MockSlot mock_slots[MOCK_SLOTS];
static int mock_keygens;
static int mock_private_ops;

static MockSlot* mock_find(const byte* id, int id_len)
{
    for (int i = 0; i < MOCK_SLOTS; i++) {
        if (mock_slots[i].id_len == id_len && id_len > 0 &&
            memcmp(mock_slots[i].id, id, (size_t)id_len) == 0)
            return &mock_slots[i];
    }
    return NULL;
}

static MockSlot* mock_new(const byte* id, int id_len, int type)
{
    if (mock_find(id, id_len) != NULL)
        return NULL;
    for (int i = 0; i < MOCK_SLOTS; i++) {
        if (mock_slots[i].id_len == 0) {
            memcpy(mock_slots[i].id, id, (size_t)id_len);
            mock_slots[i].id_len = id_len;
            mock_slots[i].type   = type;
            return &mock_slots[i];
        }
    }
    return NULL;
}

static int mock_cb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)ctx;

    if (info->algo_type != WC_ALGO_TYPE_PK)
        return CRYPTOCB_UNAVAILABLE;

    switch (info->pk.type) {
#ifdef WOLFCERT_HAVE_ECC
    case WC_PK_TYPE_EC_KEYGEN: {
        ecc_key* key = info->pk.eckg.key;
        byte pub[1 + 2 * MAX_ECC_BYTES];
        word32 pub_len = sizeof(pub);
        MockSlot* s = mock_new(key->id, key->idLen, ECC_TYPE);
        int rc;

        if (s == NULL)
            return BAD_STATE_E;
        rc = wc_ecc_init_ex(&s->ecc, NULL, INVALID_DEVID);
        if (rc == 0)
            rc = wc_ecc_make_key_ex(info->pk.eckg.rng, info->pk.eckg.size,
                                    &s->ecc, info->pk.eckg.curveId);
        if (rc == 0)
            rc = wc_ecc_export_x963(&s->ecc, pub, &pub_len);
        if (rc == 0)
            rc = wc_ecc_import_x963_ex(pub, pub_len, key,
                                       info->pk.eckg.curveId);
        if (rc == 0)
            mock_keygens++;
        return rc;
    }
    case WC_PK_TYPE_ECDSA_SIGN: {
        ecc_key* key = info->pk.eccsign.key;
        MockSlot* s = mock_find(key->id, key->idLen);
        int rc;

        if (s == NULL || s->type != ECC_TYPE)
            return CRYPTOCB_UNAVAILABLE;
        rc = wc_ecc_sign_hash(info->pk.eccsign.in, info->pk.eccsign.inlen,
                              info->pk.eccsign.out, info->pk.eccsign.outlen,
                              info->pk.eccsign.rng, &s->ecc);
        if (rc == 0)
            mock_private_ops++;
        return rc;
    }
#endif
#ifdef WOLFCERT_HAVE_RSA
    case WC_PK_TYPE_RSA_KEYGEN: {
        RsaKey* key = info->pk.rsakg.key;
        byte n[512], e[8];
        word32 n_len = sizeof(n), e_len = sizeof(e);
        MockSlot* s = mock_new(key->id, key->idLen, RSA_TYPE);
        int rc;

        if (s == NULL)
            return BAD_STATE_E;
        rc = wc_InitRsaKey_ex(&s->rsa, NULL, INVALID_DEVID);
        if (rc == 0)
            rc = wc_MakeRsaKey(&s->rsa, info->pk.rsakg.size,
                               info->pk.rsakg.e, info->pk.rsakg.rng);
        if (rc == 0)
            rc = wc_RsaFlattenPublicKey(&s->rsa, e, &e_len, n, &n_len);
        if (rc == 0)
            rc = wc_RsaPublicKeyDecodeRaw(n, n_len, e, e_len, key);
        if (rc == 0)
            mock_keygens++;
        return rc;
    }
    case WC_PK_TYPE_RSA: {
        RsaKey* key = info->pk.rsa.key;
        MockSlot* s = mock_find(key->id, key->idLen);
        int rc;

        if (s == NULL || s->type != RSA_TYPE)
            return CRYPTOCB_UNAVAILABLE;
        rc = wc_RsaFunction(info->pk.rsa.in, info->pk.rsa.inLen,
                            info->pk.rsa.out, info->pk.rsa.outLen,
                            info->pk.rsa.type, &s->rsa, info->pk.rsa.rng);
        if (rc == 0 && (info->pk.rsa.type == RSA_PRIVATE_ENCRYPT ||
                        info->pk.rsa.type == RSA_PRIVATE_DECRYPT))
            mock_private_ops++;
        return rc;
    }
#endif
    default:
        return CRYPTOCB_UNAVAILABLE;
    }
}

static void mock_reset(void)
{
    for (int i = 0; i < MOCK_SLOTS; i++) {
#ifdef WOLFCERT_HAVE_ECC
        if (mock_slots[i].id_len > 0 && mock_slots[i].type == ECC_TYPE)
            wc_ecc_free(&mock_slots[i].ecc);
#endif
#ifdef WOLFCERT_HAVE_RSA
        if (mock_slots[i].id_len > 0 && mock_slots[i].type == RSA_TYPE)
            wc_FreeRsaKey(&mock_slots[i].rsa);
#endif
    }
    memset(mock_slots, 0, sizeof(mock_slots));
}

static void* server_thread(void* arg) { wolfcert_server_run((WolfCertServer*)arg); return NULL; }

static int test_cfg_errors(void)
{
    static const uint8_t id[] = "dev-key";
    uint8_t long_id[WOLFCERT_KEY_ID_MAX_LEN + 1] = { 0 };
    WolfCertKeyCfg cfg = { .type = TEST_ENROLL_KEY_TYPE,
                           .param = TEST_ENROLL_KEY_PARAM,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE,
                           .key_id = id, .key_id_len = sizeof(id) - 1 };
    WolfCertKey* k = NULL;

    REQUIRE(wolfcert_key_generate(&cfg, &k) == WOLFCERT_ERR_BAD_ARG);

    cfg.dev_id     = MOCK_DEVID;
    cfg.key_id     = long_id;
    cfg.key_id_len = sizeof(long_id);
    REQUIRE(wolfcert_key_generate(&cfg, &k) == WOLFCERT_ERR_BAD_ARG);

    cfg.key_id     = NULL;
    cfg.key_id_len = 4;
    REQUIRE(wolfcert_key_generate(&cfg, &k) == WOLFCERT_ERR_BAD_ARG);

#ifdef WOLFCERT_HAVE_ED25519
    cfg.type       = WOLFCERT_KEY_ED25519;
    cfg.key_id     = id;
    cfg.key_id_len = sizeof(id) - 1;
    REQUIRE(wolfcert_key_generate(&cfg, &k) == WOLFCERT_ERR_UNSUPPORTED);
#endif

    REQUIRE(k == NULL);
    return 0;
}

/* Enroll a store-resident key over a bootstrap mTLS identity, reload it by id
 * from the issued certificate, then use it as the mTLS identity itself. */
static int run_key_type(const char* url, WolfCertKeyType type, int param,
                        const uint8_t* tls_cert, size_t tls_cert_len,
                        const uint8_t* boot_cert, size_t boot_cert_len,
                        const uint8_t* boot_key, size_t boot_key_len)
{
    static const uint8_t id[] = "wolfcert/device-key";
    const WolfCertCertMeta meta = { .subject_dn = "CN=devid-device,O=wolfSSL" };
    WolfCertKeyCfg kcfg = { .type = type, .param = param,
                            .dev_id = MOCK_DEVID,
                            .key_id = id, .key_id_len = sizeof(id) - 1 };
    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
        .client_cert       = boot_cert,
        .client_cert_len   = boot_cert_len,
        .client_key        = boot_key,
        .client_key_len    = boot_key_len,
    };
    WolfCertKey* key = NULL;
    WolfCertKey* reloaded = NULL;
    WolfCertBuffer out = { 0 };
    WolfCertBuffer pub1 = { 0 };
    WolfCertBuffer pub2 = { 0 };
    WolfCertBuffer csr = { 0 };
    WolfCertBuffer issued = { 0 };
    WolfCertBuffer renewed = { 0 };
    WolfCertBuffer second = { 0 };
    const uint8_t* got_id = NULL;
    size_t got_len = 0;
    int ops;
    int rc;

    mock_reset();
    mock_keygens = 0;
    mock_private_ops = 0;

    REQUIRE(wolfcert_key_generate(&kcfg, &key) == WOLFCERT_OK);
    REQUIRE(mock_keygens == 1);
    REQUIRE(wolfcert_key_id(key, &got_id, &got_len) == WOLFCERT_OK);
    REQUIRE(got_len == sizeof(id) - 1 && memcmp(got_id, id, got_len) == 0);
    REQUIRE(wolfcert_key_to_pem(key, &out) == WOLFCERT_ERR_UNSUPPORTED);
    REQUIRE(wolfcert_key_to_der(key, &out) == WOLFCERT_ERR_UNSUPPORTED);
    REQUIRE(out.data == NULL);

    REQUIRE(wolfcert_csr_build(key, &meta, &csr) == WOLFCERT_OK);
    REQUIRE(mock_private_ops == 1);
#ifdef WOLFCERT_HAVE_SCEP
    if (type == WOLFCERT_KEY_RSA) {
        static const uint8_t dummy[] = { 0x30, 0x00 };
        const WolfCertServerCfg scep = {
            .protocol   = WOLFCERT_PROTO_SCEP,
            .server_url = "http://127.0.0.1:9/scep",
        };
        WolfCertScepResult res;
        int before = mock_private_ops;
        int src;

        for (int call = 0; call < 4; call++) {
            if (call == 0)
                src = wolfcert_scep_pkcs_req_ex(&scep, NULL, dummy,
                        sizeof(dummy), dummy, sizeof(dummy), key, csr.data,
                        csr.len, &res);
            else if (call == 1)
                src = wolfcert_scep_renewal_req_ex(&scep, NULL, dummy,
                        sizeof(dummy), dummy, sizeof(dummy), dummy,
                        sizeof(dummy), key, csr.data, csr.len, &res);
            else if (call == 2)
                src = wolfcert_scep_get_cert_initial(&scep, NULL, dummy,
                        sizeof(dummy), dummy, sizeof(dummy), dummy,
                        sizeof(dummy), key, csr.data, csr.len, dummy,
                        sizeof(dummy), &res);
            else
                src = wolfcert_scep_get_cert(&scep, NULL, dummy,
                        sizeof(dummy), dummy, sizeof(dummy), dummy,
                        sizeof(dummy), key, dummy, sizeof(dummy), &res);
            if (src != WOLFCERT_ERR_UNSUPPORTED)
                fprintf(stderr, "SCEP call %d rc=%d\n", call, src);
            REQUIRE(src == WOLFCERT_ERR_UNSUPPORTED);
            REQUIRE(strstr(wolfcert_last_error_message(), "key_id") != NULL);
            REQUIRE(mock_private_ops == before);
            wolfcert_scep_result_free(&res);
        }
    }
#endif
    rc = wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &issued);
    wolfcert_buffer_free(&csr);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "enroll rc=%d (%s)\n", rc, wolfcert_last_error_message());
    REQUIRE(rc == WOLFCERT_OK);

    REQUIRE(wolfcert_key_from_id(&kcfg, issued.data, issued.len,
                                 &reloaded) == WOLFCERT_OK);
    REQUIRE(wolfcert_key_type(reloaded) == type);
    REQUIRE(wolfcert_key_public_to_der(key, &pub1) == WOLFCERT_OK);
    REQUIRE(wolfcert_key_public_to_der(reloaded, &pub2) == WOLFCERT_OK);
    REQUIRE(pub1.len == pub2.len && memcmp(pub1.data, pub2.data, pub1.len) == 0);
    wolfcert_buffer_free(&pub2);

    /* So does the certificate as DER, or its SubjectPublicKeyInfo alone. */
    {
        uint8_t cert_der[2048];
        int cert_der_len = wc_CertPemToDer(issued.data, (int)issued.len,
                                           cert_der, sizeof(cert_der),
                                           CERT_TYPE);
        WolfCertKey* from_der = NULL;

        REQUIRE(cert_der_len > 0);
        REQUIRE(wolfcert_key_from_id(&kcfg, cert_der, (size_t)cert_der_len,
                                     &from_der) == WOLFCERT_OK);
        REQUIRE(wolfcert_key_public_to_der(from_der, &pub2) == WOLFCERT_OK);
        REQUIRE(pub2.len == pub1.len &&
                memcmp(pub2.data, pub1.data, pub1.len) == 0);
        wolfcert_buffer_free(&pub2);
        wolfcert_key_free(from_der);
    }
    wolfcert_key_free(reloaded);
    reloaded = NULL;
    REQUIRE(wolfcert_key_from_id(&kcfg, pub1.data, pub1.len,
                                 &reloaded) == WOLFCERT_OK);
    REQUIRE(wolfcert_key_to_pem(reloaded, &out) == WOLFCERT_ERR_UNSUPPORTED);

#ifdef KEEP_PEER_CERT
    /* /simplereenroll authenticates with the store key: one signature for the
     * CSR, at least one more for the TLS handshake. */
    WolfCertClient* client = NULL;
    WolfCertKey* unused = NULL;
    const WolfCertCertMeta renew_meta = { 0 };

    REQUIRE(wolfcert_client_new(&client) == WOLFCERT_OK);
    ops = mock_private_ops;
    rc = wolfcert_client_reenroll(client, &cli, issued.data, issued.len,
                                  reloaded, NULL, &renew_meta, &unused,
                                  &renewed);
    wolfcert_client_free(client);
    REQUIRE(unused == NULL);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "reenroll rc=%d (%s)\n", rc, wolfcert_last_error_message());
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(mock_private_ops >= ops + 2);
#endif

    /* client_key_handle presents the store key on any request. */
    cli.client_cert       = issued.data;
    cli.client_cert_len   = issued.len;
    cli.client_key        = NULL;
    cli.client_key_len    = 0;
    cli.client_key_handle = reloaded;
    REQUIRE(wolfcert_csr_build(reloaded, &meta, &csr) == WOLFCERT_OK);
    ops = mock_private_ops;
    rc = wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &second);
    wolfcert_buffer_free(&csr);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "handle enroll rc=%d (%s)\n", rc,
                wolfcert_last_error_message());
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(mock_private_ops > ops);

    /* The keep-alive session carries the handle too. */
    WolfCertEstSession* sess = NULL;
    WolfCertBuffer third = { 0 };
    REQUIRE(wolfcert_csr_build(reloaded, &meta, &csr) == WOLFCERT_OK);
    ops = mock_private_ops;
    REQUIRE(wolfcert_est_session_open(&cli, &sess) == WOLFCERT_OK);
    rc = wolfcert_est_session_simple_enroll(sess, csr.data, csr.len, &third);
    wolfcert_est_session_close(sess);
    wolfcert_buffer_free(&csr);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(mock_private_ops > ops);
    wolfcert_buffer_free(&third);

    wolfcert_buffer_free(&second);
    wolfcert_buffer_free(&renewed);
    wolfcert_buffer_free(&issued);
    wolfcert_buffer_free(&pub1);
    wolfcert_key_free(reloaded);
    wolfcert_key_free(key);
    mock_reset();
    return 0;
}

int main(void)
{
    uint8_t* tls_cert = NULL; size_t tls_cert_len = 0;
    uint8_t* tls_key  = NULL; size_t tls_key_len  = 0;
    uint8_t* boot_cert = NULL; size_t boot_cert_len = 0;
    uint8_t* boot_key  = NULL; size_t boot_key_len  = 0;
    WolfCertStoreOps* store = NULL;
    WolfCertServer* srv = NULL;
    WolfCertBuffer ca_der = { 0 };
    uint8_t* bundle = NULL;
    size_t bundle_cap;
    pthread_t tid;
    char url[128];
    int pem_len;

    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);
    REQUIRE(wc_CryptoCb_RegisterDevice(MOCK_DEVID, mock_cb, NULL) == 0);
    REQUIRE(test_cfg_errors() == 0);

    REQUIRE(mint_self_id("127.0.0.1", 0, &tls_cert, &tls_cert_len,
                         &tls_key, &tls_key_len) == 0);
    REQUIRE(mint_self_id("factory-bootstrap", 1, &boot_cert, &boot_cert_len,
                         &boot_key, &boot_key_len) == 0);

    WolfCertServerCfgSrv cfg = {
        .protocol          = WOLFCERT_PROTO_EST,
        .bind_host         = "127.0.0.1",
        .bind_port         = 0,
        .tls_cert_pem      = tls_cert, .tls_cert_pem_len      = tls_cert_len,
        .tls_key_pem       = tls_key,  .tls_key_pem_len       = tls_key_len,
        .tls_client_ca_pem = boot_cert, .tls_client_ca_pem_len = boot_cert_len,
    };

    /* Mint the CA first so the server can also trust the certs it issues. */
    store = wolfcert_store_memory_open(NULL);
    REQUIRE(store != NULL);
    cfg.ca_store = store;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    wolfcert_server_free(srv);
    srv = NULL;
    REQUIRE(store->read(store->ctx, "ca.cert.der", &ca_der) == WOLFCERT_OK);

    bundle_cap = boot_cert_len + ca_der.len * 2 + 256;
    bundle = (uint8_t*)malloc(bundle_cap);
    REQUIRE(bundle != NULL);
    memcpy(bundle, boot_cert, boot_cert_len);
    pem_len = wc_DerToPem(ca_der.data, (word32)ca_der.len,
                          bundle + boot_cert_len,
                          (word32)(bundle_cap - boot_cert_len), CERT_TYPE);
    REQUIRE(pem_len > 0);
    cfg.tls_client_ca_pem     = bundle;
    cfg.tls_client_ca_pem_len = boot_cert_len + (size_t)pem_len;

    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));

#ifdef WOLFCERT_HAVE_ECC
    REQUIRE(run_key_type(url, WOLFCERT_KEY_ECC, 256, tls_cert, tls_cert_len,
                         boot_cert, boot_cert_len, boot_key, boot_key_len) == 0);
#endif
#ifdef WOLFCERT_HAVE_RSA
    REQUIRE(run_key_type(url, WOLFCERT_KEY_RSA, 2048, tls_cert, tls_cert_len,
                         boot_cert, boot_cert_len, boot_key, boot_key_len) == 0);
#endif

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    wolfcert_store_memory_close(store);
    wolfcert_buffer_free(&ca_der);
    free(bundle);
    free(tls_cert);
    free(tls_key);
    free(boot_cert);
    free(boot_key);
    wc_CryptoCb_UnRegisterDevice(MOCK_DEVID);
    wolfcert_cleanup();
    printf("est_devid_roundtrip: OK\n");
    return 0;
}
