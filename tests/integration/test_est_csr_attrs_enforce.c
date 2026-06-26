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
 * End-to-end coverage for server-side enforcement of the CsrAttrs
 * policy (RFC 7030 section 4.5.2). The test server advertises a bare-OID
 * challengePassword requirement + `est_require_csr_attributes = 1`:
 *
 *   - Client A sets meta.challenge_password so the CSR carries the
 *     attribute -> enrollment must succeed.
 *   - Client B omits it -> server rejects with HTTP 400 and the
 *     client surfaces WOLFCERT_ERR_HTTP.
 *
 * Enforcement happens presence-only in this phase (bare-OID items
 * only); Attribute-with-values items are advisory. See docs/TODO.md
 * for the value-comparison follow-up.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/est.h>
#include <wolfcert/client.h>
#include <wolfcert/server.h>

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

/* Server TLS trust anchor, pinned by the client (EST is TLS-only, RFC 7030). */
static const uint8_t* g_ca = NULL;
static size_t         g_ca_len = 0;

static void* server_thread(void* arg)
{
    wolfcert_server_run((WolfCertServer*)arg);
    return NULL;
}

static const uint8_t OID_CHALLENGE_PASSWORD[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07
};
static const uint8_t OID_EC_PUBLIC_KEY[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
};
static const uint8_t OID_SECP384R1[] = { 0x2B, 0x81, 0x04, 0x00, 0x22 };

/* Build a minimal CsrAttrs DER: one bare OID (challengePassword). */
static int build_policy(WolfCertBuffer* out)
{
    WolfCertCsrAttrItem items[1] = {
        { .kind = WOLFCERT_CSRATTR_BARE_OID,
          .oid = OID_CHALLENGE_PASSWORD,
          .oid_len = sizeof(OID_CHALLENGE_PASSWORD) },
    };
    return wolfcert_csr_attrs_build(items, 1, out);
}

/* Build a policy that contains ONLY an Attribute-with-values item
 * (id-ecPublicKey pinning secp384r1) and no bare OIDs. Phase-3
 * enforcement is presence-only on bare OIDs, so a CSR that doesn't
 * carry the attribute must still be accepted - this is the policy
 * used to prove that skip is intentional. */
static int build_values_only_policy(WolfCertBuffer* out)
{
    uint8_t curve_tlv[16];
    curve_tlv[0] = 0x06;
    curve_tlv[1] = (uint8_t)sizeof(OID_SECP384R1);
    memcpy(&curve_tlv[2], OID_SECP384R1, sizeof(OID_SECP384R1));
    size_t curve_tlv_len = 2 + sizeof(OID_SECP384R1);

    WolfCertCsrAttrItem items[1] = {
        { .kind = WOLFCERT_CSRATTR_ATTRIBUTE,
          .oid = OID_EC_PUBLIC_KEY,
          .oid_len = sizeof(OID_EC_PUBLIC_KEY),
          .values_der = curve_tlv, .values_len = curve_tlv_len },
    };
    return wolfcert_csr_attrs_build(items, 1, out);
}

/* Client A - CSR carries challengePassword -> enrollment succeeds. */
static int enroll_with_challenge(WolfCertServer* s)
{
    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(s));
    WolfCertServerCfg srv = { .protocol = WOLFCERT_PROTO_EST,
                              .server_url = url,
                              .trust_anchors = g_ca,
                              .trust_anchors_len = g_ca_len,
                              .verify_server = 1 };

    WolfCertClient* cli = NULL;
    REQUIRE(wolfcert_client_new(&cli) == WOLFCERT_OK);

    WolfCertKeyCfg  key_cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                                .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertCertMeta meta = {
        .subject_dn = "CN=enforce-ok",
        .challenge_password = "hunter2",
    };

    WolfCertKey* key = NULL;
    WolfCertBuffer cert_pem = { 0 };
    int rc = wolfcert_client_enroll(cli, &srv, &key_cfg, &meta,
                                    &key, &cert_pem);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(cert_pem.len > 0);

    wolfcert_buffer_free(&cert_pem);
    wolfcert_key_free(key);
    wolfcert_client_free(cli);
    return 0;
}

/* Client B - CSR omits challengePassword -> server returns 400. */
static int enroll_without_challenge(WolfCertServer* s)
{
    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(s));
    WolfCertServerCfg srv = { .protocol = WOLFCERT_PROTO_EST,
                              .server_url = url,
                              .trust_anchors = g_ca,
                              .trust_anchors_len = g_ca_len,
                              .verify_server = 1 };

    WolfCertClient* cli = NULL;
    REQUIRE(wolfcert_client_new(&cli) == WOLFCERT_OK);

    WolfCertKeyCfg  key_cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                                .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertCertMeta meta = {
        .subject_dn = "CN=enforce-reject",
        /* no challenge_password -> CSR lacks the required attribute */
    };

    WolfCertKey* key = NULL;
    WolfCertBuffer cert_pem = { 0 };
    int rc = wolfcert_client_enroll(cli, &srv, &key_cfg, &meta,
                                    &key, &cert_pem);
    REQUIRE(rc == WOLFCERT_ERR_HTTP);
    REQUIRE(cert_pem.len == 0);

    wolfcert_buffer_free(&cert_pem);
    if (key != NULL)
        wolfcert_key_free(key);
    wolfcert_client_free(cli);
    return 0;
}

/* Client C - server advertises ONLY an Attribute-with-values item
 * (no bare OIDs). The CSR doesn't carry anything matching it.
 * Enforcement is presence-only on bare OIDs, so this must still
 * succeed. Pins the "Attribute items are advisory" behaviour so a
 * future refactor flipping it to enforce-by-default breaks here. */
static int values_only_policy_does_not_block(WolfCertServer* s)
{
    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(s));
    WolfCertServerCfg srv = { .protocol = WOLFCERT_PROTO_EST,
                              .server_url = url,
                              .trust_anchors = g_ca,
                              .trust_anchors_len = g_ca_len,
                              .verify_server = 1 };

    WolfCertClient* cli = NULL;
    REQUIRE(wolfcert_client_new(&cli) == WOLFCERT_OK);

    WolfCertKeyCfg  key_cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                                .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertCertMeta meta = { .subject_dn = "CN=enforce-values-advisory" };

    WolfCertKey* key = NULL;
    WolfCertBuffer cert_pem = { 0 };
    int rc = wolfcert_client_enroll(cli, &srv, &key_cfg, &meta,
                                    &key, &cert_pem);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(cert_pem.len > 0);

    wolfcert_buffer_free(&cert_pem);
    wolfcert_key_free(key);
    wolfcert_client_free(cli);
    return 0;
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    WolfCertBuffer policy = { 0 };
    REQUIRE(build_policy(&policy) == WOLFCERT_OK);

    /* EST runs over TLS (RFC 7030): pin a freshly minted server identity. */
    uint8_t *tls_cert = NULL, *tls_key = NULL;
    size_t tls_cert_len = 0, tls_key_len = 0;
    REQUIRE(gen_server_identity(&tls_cert, &tls_cert_len,
                                &tls_key, &tls_key_len) == 0);
    g_ca = tls_cert;
    g_ca_len = tls_cert_len;

    WolfCertServerCfgSrv cfg = {
        .protocol = WOLFCERT_PROTO_EST,
        .bind_host = "127.0.0.1", .bind_port = 0,
        .csr_attributes_der = policy.data,
        .csr_attributes_len = policy.len,
        .est_require_csr_attributes = 1,
        .tls_cert_pem = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem  = tls_key,  .tls_key_pem_len  = tls_key_len,
    };
    WolfCertServer* srv = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);

    int rc = enroll_with_challenge(srv);
    if (rc == 0)
        rc = enroll_without_challenge(srv);

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    wolfcert_buffer_free(&policy);
    if (rc != 0)
        return rc;

    /* Second server with a values-only policy; any CSR must pass. */
    WolfCertBuffer policy2 = { 0 };
    REQUIRE(build_values_only_policy(&policy2) == WOLFCERT_OK);
    WolfCertServerCfgSrv cfg2 = {
        .protocol = WOLFCERT_PROTO_EST,
        .bind_host = "127.0.0.1", .bind_port = 0,
        .csr_attributes_der = policy2.data,
        .csr_attributes_len = policy2.len,
        .est_require_csr_attributes = 1,
        .tls_cert_pem = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem  = tls_key,  .tls_key_pem_len  = tls_key_len,
    };
    WolfCertServer* srv2 = NULL;
    REQUIRE(wolfcert_server_start(&cfg2, &srv2) == WOLFCERT_OK);
    pthread_t tid2;
    REQUIRE(pthread_create(&tid2, NULL, server_thread, srv2) == 0);

    rc = values_only_policy_does_not_block(srv2);

    wolfcert_server_stop(srv2);
    pthread_join(tid2, NULL);
    wolfcert_server_free(srv2);
    wolfcert_buffer_free(&policy2);
    free(tls_cert);
    free(tls_key);
    if (rc != 0)
        return rc;

    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
