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
#define _GNU_SOURCE

#include <wolfcert/scep.h>
#include <wolfcert/http.h>
#include <wolfcert/errors.h>
#include "../internal.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/memory.h>
#ifndef NO_SHA
#include <wolfssl/wolfcrypt/sha.h>
#endif
#include <wolfssl/wolfcrypt/sha256.h>
#ifdef WOLFSSL_SHA512
#include <wolfssl/wolfcrypt/sha512.h>
#endif

#include <stdio.h>
#include <string.h>
#include <strings.h>

static char* append_query(const char* base, const char* op, void* heap)
{
    size_t bl = strlen(base), ol = strlen(op);
    int has_q = (strchr(base, '?') != NULL);
    char* url = (char*)WOLFCERT_XMALLOC(bl + ol + 24, heap);
    if (url == NULL)
        return NULL;

    snprintf(url, bl + ol + 24, "%s%soperation=%s", base, has_q ? "&" : "?", op);

    return url;
}

static void fill_common(const WolfCertServerCfg* srv, WolfCertHttpRequest* req)
{
    req->basic_user         = srv->username;
    req->basic_pass         = srv->password;
    req->trust_anchors      = srv->trust_anchors;
    req->trust_anchors_len  = srv->trust_anchors_len;
    req->verify_server      = srv->verify_server;
    req->timeout_ms         = srv->timeout_ms;
    req->max_response_bytes = srv->max_response_bytes;
    req->heap               = srv->heap;

    /* mTLS identity for the outer transport. RFC 8894 authenticates the
     * pkiMessage via its signed-data wrapper, but some deployments still
     * require mTLS on the outer HTTPS connection. */
    req->client_cert        = srv->client_cert;
    req->client_cert_len    = srv->client_cert_len;
    req->client_key         = srv->client_key;
    req->client_key_len     = srv->client_key_len;
    req->connect_cb         = srv->connect_cb;
    req->connect_ctx        = srv->connect_ctx;
}

/* ---- GetCACaps ---------------------------------------------------------- */

static int has_cap(const char* body, size_t len, const char* needle)
{
    size_t nl = strlen(needle);
    for (size_t i = 0; i + nl <= len; ++i) {
        if (strncasecmp(body + i, needle, nl) == 0) {
            return 1;
        }
    }

    return 0;
}

int wolfcert_scep_get_ca_caps(const WolfCertServerCfg* srv, WolfCertScepCaps* out)
{
    if (srv == NULL || srv->server_url == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();
    memset(out, 0, sizeof(*out));

    char* url = append_query(srv->server_url, "GetCACaps", heap);
    if (url == NULL)
        return WOLFCERT_ERR_MEMORY;

    WolfCertHttpRequest req = { .method = "GET", .url = url };
    fill_common(srv, &req);

    WolfCertHttpResponse resp = { 0 };
    int rc = wolfcert_http_request(&req, &resp);

    WOLFCERT_XFREE(url, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    if (resp.status_code != 200) {
        wolfcert_http_response_free(&resp);
        return WOLFCERT_ERR_HTTP;
    }

    const char* b = (const char*)resp.body;
    out->post_pki_operation = has_cap(b, resp.body_len, "POSTPKIOperation");
    out->renewal            = has_cap(b, resp.body_len, "Renewal");
    out->sha256             = has_cap(b, resp.body_len, "SHA-256");
    out->sha384             = has_cap(b, resp.body_len, "SHA-384");
    out->sha512             = has_cap(b, resp.body_len, "SHA-512");
    out->aes                = has_cap(b, resp.body_len, "AES");
    out->scep_standard      = has_cap(b, resp.body_len, "SCEPStandard");
    out->get_next_ca_cert   = has_cap(b, resp.body_len, "GetNextCACert");

    wolfcert_http_response_free(&resp);

    return WOLFCERT_OK;
}

void wolfcert_scep_result_free(WolfCertScepResult* r)
{
    if (r == NULL)
        return;

    wolfcert_buffer_free(&r->cert_pem);
    WOLFCERT_XFREE(r->transaction_id, r->heap);

    r->transaction_id     = NULL;
    r->transaction_id_len = 0;
    r->fail_info          = -1;
}

int wolfcert_scep_get_ca_cert(const WolfCertServerCfg* srv, WolfCertBuffer* out_ca_pem)
{
    return wolfcert_scep_get_ca_cert_enc(srv, WOLFCERT_ENCODING_PEM, out_ca_pem);
}

int wolfcert_scep_get_ca_cert_enc(const WolfCertServerCfg* srv, WolfCertEncoding enc,
                                  WolfCertBuffer* out_ca)
{
    if (srv == NULL || srv->server_url == NULL || out_ca == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();

    char* url = append_query(srv->server_url, "GetCACert", heap);
    if (url == NULL)
        return WOLFCERT_ERR_MEMORY;

    WolfCertHttpRequest req = { .method = "GET", .url = url };
    fill_common(srv, &req);

    WolfCertHttpResponse resp = { 0 };
    int rc = wolfcert_http_request(&req, &resp);

    WOLFCERT_XFREE(url, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    if (resp.status_code != 200) {
        wolfcert_http_response_free(&resp);
        return WOLFCERT_ERR_HTTP;
    }

    int is_p7 = resp.content_type != NULL &&
                strstr(resp.content_type, "x-x509-ca-ra-cert") != NULL;
    if (is_p7) {
        if (enc == WOLFCERT_ENCODING_DER) {
            rc = wolfcert_pkcs7_certs_to_der(resp.body, resp.body_len, out_ca, heap);
        }
        else {
            rc = wolfcert_pkcs7_certs_to_pem(resp.body, resp.body_len, out_ca, heap);
        }
    }
    else if (enc == WOLFCERT_ENCODING_DER) {
        /* Single CA cert; the body is already DER - hand back a copy the
         * caller owns. */
        uint8_t* der = (uint8_t*)WOLFCERT_XMALLOC(resp.body_len, heap);
        if (der == NULL) {
            rc = WOLFCERT_ERR_MEMORY;
            goto out;
        }

        memcpy(der, resp.body, resp.body_len);
        out_ca->data = der;
        out_ca->len  = resp.body_len;
        out_ca->heap = heap;
        rc = WOLFCERT_OK;
    }
    else {
        size_t cap = resp.body_len * 2 + 256;
        uint8_t* pem = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
        if (pem == NULL) {
            rc = WOLFCERT_ERR_MEMORY;
            goto out;
        }

        int n = wc_DerToPem(resp.body, (word32)resp.body_len, pem, (word32)cap, CERT_TYPE);
        if (n <= 0) {
            WOLFCERT_XFREE(pem, heap);
            rc = WOLFCERT_ERR_CRYPTO;
            goto out;
        }

        out_ca->data = pem;
        out_ca->len  = (size_t)n;
        out_ca->heap = heap;
        rc = WOLFCERT_OK;
    }

out:
    wolfcert_http_response_free(&resp);
    return rc;
}

/* Constant-time buffer comparison: returns 0 iff the two buffers are equal.
 * Fingerprints are not secret, but a timing-independent compare keeps the
 * trust check uniform and avoids leaking match position. */
static int ct_diff(const uint8_t* a, const uint8_t* b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i)
        d |= (uint8_t)(a[i] ^ b[i]);
    return d;
}

int wolfcert_scep_verify_ca_fingerprint(const uint8_t* ca_der, size_t ca_der_len,
                                        const uint8_t* expected, size_t expected_len,
                                        WolfCertScepFpAlg alg)
{
    /* SHA-512 (64 bytes) is the widest digest we produce. */
    uint8_t digest[64];
    size_t  digest_len = 0;
    int     rc = 0;

    if (ca_der == NULL || ca_der_len == 0 || expected == NULL || expected_len == 0)
        return WOLFCERT_ERR_BAD_ARG;

    /* AUTO: identify the algorithm from the supplied fingerprint length. This
     * is a legacy convenience; a 20-byte value maps to collision-weak SHA-1, so
     * callers that know the digest should pass it explicitly (see scep.h). */
    if (alg == WOLFCERT_SCEP_FP_AUTO) {
        switch (expected_len) {
            case 20: alg = WOLFCERT_SCEP_FP_SHA1;   break; /* SHA-1 (legacy) */
            case 32: alg = WOLFCERT_SCEP_FP_SHA256; break; /* SHA-256 */
            case 64: alg = WOLFCERT_SCEP_FP_SHA512; break; /* SHA-512 */
            default:
                return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
                    "fingerprint length does not match SHA-1/SHA-256/SHA-512");
        }
    }

    switch (alg) {
        case WOLFCERT_SCEP_FP_SHA256:
            digest_len = WC_SHA256_DIGEST_SIZE;
            rc = wc_Sha256Hash(ca_der, (word32)ca_der_len, digest);
            break;
#ifndef NO_SHA
        case WOLFCERT_SCEP_FP_SHA1:
            digest_len = WC_SHA_DIGEST_SIZE;
            rc = wc_ShaHash(ca_der, (word32)ca_der_len, digest);
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WOLFCERT_SCEP_FP_SHA512:
            digest_len = WC_SHA512_DIGEST_SIZE;
            rc = wc_Sha512Hash(ca_der, (word32)ca_der_len, digest);
            break;
#endif
        default:
            return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
                "requested fingerprint digest is not compiled into wolfSSL");
    }

    if (rc != 0)
        return WOLFCERT_ERR_WC(rc, "scep", "fingerprint hash");

    /* An explicit algorithm with a mismatched length is a caller error. */
    if (expected_len != digest_len)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "expected fingerprint length does not match the digest size");

    if (ct_diff(expected, digest, digest_len) != 0)
        return WOLFCERT_ERR(WOLFCERT_ERR_AUTH, "scep",
            "CA certificate fingerprint mismatch");

    return WOLFCERT_OK;
}

/* ---- PKCSReq / RenewalReq ---------------------------------------------- */

static int pick_hash_oid(const WolfCertScepCaps* caps)
{
    if (caps == NULL)
        return SHA256h;
    if (caps->sha512)
        return SHA512h;
    if (caps->sha384)
        return SHA384h;

    return SHA256h;
}

static int run_pki_op(const WolfCertServerCfg* srv,
                      const uint8_t* pki_msg, size_t pki_len,
                      uint8_t** out_resp, size_t* out_resp_len)
{
    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();
    char* url = append_query(srv->server_url, "PKIOperation", heap);
    if (url == NULL)
        return WOLFCERT_ERR_MEMORY;

    WolfCertHttpRequest req = {
        .method       = "POST",
        .url          = url,
        .content_type = "application/x-pki-message",
        .body         = pki_msg,
        .body_len     = pki_len,
    };

    fill_common(srv, &req);
    WolfCertHttpResponse resp = { 0 };
    int rc = wolfcert_http_request(&req, &resp);

    WOLFCERT_XFREE(url, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    if (resp.status_code != 200) {
        wolfcert_http_response_free(&resp);
        return WOLFCERT_ERR_HTTP;
    }

    *out_resp     = resp.body;
    *out_resp_len = resp.body_len;
    resp.body = NULL;
    wolfcert_http_response_free(&resp);

    return WOLFCERT_OK;
}

/* Core round-trip used by PKCSReq / RenewalReq / GetCertInitial. Builds a
 * pkiMessage wrapping `envelope_content`, POSTs it, parses the CertRep,
 * and fills `out`. Caller retains ownership of `txid_override`; when NULL
 * a fresh 16-byte hex transactionID is generated. */
static int do_scep_round_trip(const WolfCertServerCfg* srv,
                              const WolfCertScepCaps*   caps,
                              const uint8_t* ra_cert, size_t ra_cert_len,
                              const uint8_t* ca_bundle, size_t ca_bundle_len,
                              const uint8_t* signer_cert, size_t signer_cert_len,
                              const uint8_t* signer_key,  size_t signer_key_len,
                              const char* msg_type,
                              const uint8_t* envelope_content, size_t envelope_content_len,
                              const uint8_t* txid_override, size_t txid_override_len,
                              WolfCertScepResult* out)
{
    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();
    int hash_oid = pick_hash_oid(caps);
    int enc_oid;
    out->heap = heap;
    out->fail_info = -1;

    /* RFC 8894: the GetCACaps "AES" keyword advertises AES-128-CBC as the
     * content cipher. Honour it when offered; otherwise fall back to the
     * mandatory-to-implement triple DES-CBC. A wolfSSL built without 3DES
     * cannot serve that fallback, so reject the legacy peer with a clear
     * error instead of a cryptic encoder failure. */
    if (caps != NULL && caps->aes) {
        enc_oid = AES128CBCb;
    }
    else {
#ifdef NO_DES3
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "peer does not advertise AES and wolfSSL lacks 3DES fallback");
#else
        enc_oid = DES3b;
#endif
    }

    WolfCertBuffer env = { 0 };
    int rc = wolfcert_scep_envelop(ra_cert, ra_cert_len,
                                    envelope_content, envelope_content_len,
                                    enc_oid, &env, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    WC_RNG rng;
    wc_InitRng_ex(&rng, heap, WOLFCERT_DEVID_SOFTWARE);

    uint8_t txid_gen[16], nonce[16];
    wc_RNG_GenerateBlock(&rng, txid_gen, sizeof(txid_gen));
    wc_RNG_GenerateBlock(&rng, nonce,    sizeof(nonce));

    wc_FreeRng(&rng);

    static const char HEX[] = "0123456789abcdef";
    char txid_generated[33];
    for (size_t i = 0; i < sizeof(txid_gen); ++i) {
        txid_generated[i*2]   = HEX[txid_gen[i] >> 4];
        txid_generated[i*2+1] = HEX[txid_gen[i] & 0x0F];
    }
    txid_generated[32] = '\0';

    const uint8_t* txid     = txid_override ? txid_override : (const uint8_t*)txid_generated;
    size_t         txid_len = txid_override ? txid_override_len : 32;

    WolfCertScepAttrs attrs = {
        .transaction_id     = txid, .transaction_id_len = txid_len,
        .sender_nonce       = nonce, .sender_nonce_len = sizeof(nonce),
        .message_type       = msg_type,
    };
    WolfCertBuffer pki = { 0 };
    rc = wolfcert_scep_build_pki_message(env.data, env.len,
                                          signer_cert, signer_cert_len,
                                          signer_key, signer_key_len,
                                          hash_oid, &attrs, &pki, heap);

    wolfcert_buffer_free(&env);
    if (rc != WOLFCERT_OK)
        return rc;

    uint8_t* resp = NULL;
    size_t resp_len = 0;
    rc = run_pki_op(srv, pki.data, pki.len, &resp, &resp_len);

    wolfcert_buffer_free(&pki);
    if (rc != WOLFCERT_OK)
        return rc;

    WolfCertBuffer resp_env = { 0 };
    WolfCertBuffer inner = { 0 };
    char*   status = NULL;
    char*   fail_info = NULL;
    char* resp_mt = NULL;
    uint8_t* rx_tid = NULL;
    size_t rx_tid_len = 0;
    uint8_t* rx_sn  = NULL;
    size_t rx_sn_len  = 0;
    uint8_t* rx_rn  = NULL;
    size_t rx_rn_len  = 0;
    uint8_t* rx_signer = NULL;
    size_t rx_signer_len = 0;
    rc = wolfcert_scep_parse_pki_message(resp, resp_len, &resp_env,
            &rx_tid, &rx_tid_len, &rx_sn, &rx_sn_len, &rx_rn, &rx_rn_len,
            &resp_mt, &status, &rx_signer, &rx_signer_len, &fail_info, heap);

    WOLFCERT_XFREE(resp,   heap);
    WOLFCERT_XFREE(rx_sn,  heap);

    /* RFC 8894: an enrollment response is a CertRep (messageType 3) whose
     * transactionID echoes the one we sent. Reject a response that claims a
     * different type or transaction before consuming it. */
    if (rc == WOLFCERT_OK) {
        rc = wolfcert_scep_check_cert_rep(resp_mt, rx_tid, rx_tid_len,
                                          txid, txid_len);
        if (rc != WOLFCERT_OK)
            rc = WOLFCERT_ERR(WOLFCERT_ERR_PROTOCOL, "scep",
                              "CertRep messageType or transactionID does not "
                              "match the request");
    }
    WOLFCERT_XFREE(resp_mt, heap);

    /* wolfcert_scep_parse_pki_message only verifies the CMS signature against
     * the cert embedded in the response, so a MITM on the (often plaintext)
     * SCEP transport could forge a fully signed CertRep. Authenticate the
     * response by requiring its signer to be one of the CA/RA certs from the
     * GetCACert bundle before trusting anything it carries. */
    if (rc == WOLFCERT_OK) {
        rc = wolfcert_scep_verify_rep_signer(rx_signer, rx_signer_len,
                                             ca_bundle, ca_bundle_len, heap);
        if (rc != WOLFCERT_OK)
            rc = WOLFCERT_ERR(WOLFCERT_ERR_AUTH, "scep",
                              "CertRep is not signed by the CA/RA certificate");
    }
    WOLFCERT_XFREE(rx_signer, heap);

    /* RFC 8894 section 3.2.1.2: the CertRep MUST carry a recipientNonce that
     * echoes the senderNonce we sent. An absent or mismatched recipientNonce
     * means the response cannot be tied to our request (stale / replayed /
     * cross-talk / cannot verify) -> reject. */
    if (rc == WOLFCERT_OK &&
        (rx_rn == NULL || rx_rn_len != sizeof(nonce) ||
         memcmp(rx_rn, nonce, sizeof(nonce)) != 0)) {
        rc = WOLFCERT_ERR(WOLFCERT_ERR_PROTOCOL, "scep",
                          "CertRep recipientNonce missing or does not echo "
                          "senderNonce");
    }
    WOLFCERT_XFREE(rx_rn, heap);

    if (rc == WOLFCERT_OK) {
        /* Echo the transactionID in the result so callers can poll later;
         * ownership of rx_tid moves to out. */
        out->transaction_id     = rx_tid;
        out->transaction_id_len = rx_tid_len;
        rx_tid = NULL;

        if (status != NULL && strcmp(status, "3") == 0) {
            out->status = WOLFCERT_SCEP_STATUS_PENDING;
        }
        else if (status == NULL || strcmp(status, "0") != 0) {
            out->status = WOLFCERT_SCEP_STATUS_FAILURE;
            /* RFC 8894 section 3.2.1.4: a FAILURE CertRep carries a failInfo
             * PrintableString of "0".."4". Surface it to the caller; leave the
             * default -1 when the server omitted the attribute. */
            if (fail_info != NULL &&
                fail_info[0] >= '0' && fail_info[0] <= '4' &&
                fail_info[1] == '\0') {
                out->fail_info = fail_info[0] - '0';
            }
        }
        else {
            /* status "0" is SUCCESS: de-envelop the CertRep and convert the
             * issued certificate(s) to PEM for the caller. */
            rc = wolfcert_scep_deenvelop(signer_cert, signer_cert_len,
                                          signer_key, signer_key_len,
                                          resp_env.data, resp_env.len, &inner,
                                          heap);
            if (rc == WOLFCERT_OK)
                rc = wolfcert_pkcs7_certs_to_pem(inner.data, inner.len,
                                                 &out->cert_pem, heap);
            if (rc == WOLFCERT_OK)
                out->status = WOLFCERT_SCEP_STATUS_SUCCESS;
        }
    }

    WOLFCERT_XFREE(rx_tid, heap);
    WOLFCERT_XFREE(status, heap);
    WOLFCERT_XFREE(fail_info, heap);
    wolfcert_buffer_free(&inner);
    wolfcert_buffer_free(&resp_env);
    return rc;
}

/* Serialize the private key half of a WolfCertKey to DER for PKCS#7 use.
 * SCEP requires RSA (RFC 8894), so the caller has already validated
 * key->type == WOLFCERT_KEY_RSA. */
static int rsa_key_to_der(const WolfCertKey* key, void* heap,
                          uint8_t** out_der, size_t* out_len)
{
    size_t cap = 2048;
    uint8_t* der = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
    if (der == NULL)
        return WOLFCERT_ERR_MEMORY;

    int n = wc_RsaKeyToDer((RsaKey*)key->impl, der, (word32)cap);
    if (n <= 0) {
        wc_ForceZero(der, (word32)cap);
        WOLFCERT_XFREE(der, heap);
        return WOLFCERT_ERR_CRYPTO;
    }

    *out_der = der;
    *out_len = (size_t)n;

    return WOLFCERT_OK;
}

int wolfcert_scep_pkcs_req_ex(const WolfCertServerCfg* srv,
                              const WolfCertScepCaps*  caps,
                              const uint8_t* ra_cert, size_t ra_cert_len,
                              const uint8_t* ca_bundle, size_t ca_bundle_len,
                              const WolfCertKey*       new_key,
                              const uint8_t* csr_der, size_t csr_der_len,
                              WolfCertScepResult*      out)
{
    if (srv == NULL || ra_cert == NULL || ca_bundle == NULL ||
        new_key == NULL || csr_der == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (new_key->type != WOLFCERT_KEY_RSA)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "SCEP (RFC 8894) requires an RSA signer for pkiMessage; "
            "Ed25519/Ed448/ML-DSA are not permitted");

    memset(out, 0, sizeof(*out));
    out->fail_info = -1;
    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();
    uint8_t* signer_der = NULL;
    size_t signer_len = 0;
    int rc = wolfcert_scep_self_signed_rsa((RsaKey*)new_key->impl,
                                            csr_der, csr_der_len,
                                            &signer_der, &signer_len, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    uint8_t* key_der = NULL;
    size_t key_der_len = 0;
    rc = rsa_key_to_der(new_key, heap, &key_der, &key_der_len);
    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(signer_der, heap);
        return rc;
    }

    rc = do_scep_round_trip(srv, caps, ra_cert, ra_cert_len,
                            ca_bundle, ca_bundle_len,
                            signer_der, signer_len, key_der, key_der_len,
                            "19", csr_der, csr_der_len,
                            NULL, 0, out);

    WOLFCERT_XFREE(signer_der, heap);
    wc_ForceZero(key_der, (word32)key_der_len);
    WOLFCERT_XFREE(key_der, heap);
    return rc;
}

int wolfcert_scep_pkcs_req(const WolfCertServerCfg* srv,
                           const WolfCertScepCaps*  caps,
                           const uint8_t* ra_cert, size_t ra_cert_len,
                           const WolfCertKey*       new_key,
                           const uint8_t* csr_der, size_t csr_der_len,
                           WolfCertBuffer*          out_cert_pem)
{
    if (out_cert_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    /* Single-cert form: the envelope target doubles as the one-cert trust
     * bundle. Callers with a CA/RA bundle should use the _ex form. */
    WolfCertScepResult r = { 0 };
    int rc = wolfcert_scep_pkcs_req_ex(srv, caps, ra_cert, ra_cert_len,
                                       ra_cert, ra_cert_len,
                                       new_key, csr_der, csr_der_len, &r);
    if (rc != WOLFCERT_OK) {
        wolfcert_scep_result_free(&r);
        return rc;
    }

    if (r.status == WOLFCERT_SCEP_STATUS_SUCCESS) {
        *out_cert_pem = r.cert_pem;
        r.cert_pem.data = NULL;
        r.cert_pem.len = 0;
        wolfcert_scep_result_free(&r);
        return WOLFCERT_OK;
    }

    int err = r.status == WOLFCERT_SCEP_STATUS_PENDING
              ? WOLFCERT_ERR_PENDING : WOLFCERT_ERR_PROTOCOL;

    wolfcert_scep_result_free(&r);
    return err;
}

int wolfcert_scep_renewal_req_ex(const WolfCertServerCfg* srv,
                                 const WolfCertScepCaps*  caps,
                                 const uint8_t* ra_cert, size_t ra_cert_len,
                                 const uint8_t* ca_bundle, size_t ca_bundle_len,
                                 const uint8_t* current_cert, size_t current_cert_len,
                                 const WolfCertKey* current_key,
                                 const uint8_t* csr_der, size_t csr_der_len,
                                 WolfCertScepResult* out)
{
    if (srv == NULL || ra_cert == NULL || ca_bundle == NULL ||
            current_cert == NULL || current_key == NULL || csr_der == NULL ||
            out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (current_key->type != WOLFCERT_KEY_RSA)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "SCEP (RFC 8894) requires an RSA signer for pkiMessage; "
            "Ed25519/Ed448/ML-DSA are not permitted");

    memset(out, 0, sizeof(*out));
    out->fail_info = -1;
    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();
    uint8_t* key_der = NULL;
    size_t key_der_len = 0;
    int rc = rsa_key_to_der(current_key, heap, &key_der, &key_der_len);
    if (rc != WOLFCERT_OK)
        return rc;

    rc = do_scep_round_trip(srv, caps, ra_cert, ra_cert_len,
                            ca_bundle, ca_bundle_len,
                            current_cert, current_cert_len,
                            key_der, key_der_len,
                            "17", csr_der, csr_der_len,
                            NULL, 0, out);

    wc_ForceZero(key_der, (word32)key_der_len);
    WOLFCERT_XFREE(key_der, heap);
    return rc;
}

int wolfcert_scep_renewal_req(const WolfCertServerCfg* srv,
                              const WolfCertScepCaps*  caps,
                              const uint8_t* ra_cert, size_t ra_cert_len,
                              const uint8_t* current_cert, size_t current_cert_len,
                              const WolfCertKey* current_key,
                              const uint8_t* csr_der, size_t csr_der_len,
                              WolfCertBuffer* out_cert_pem)
{
    if (out_cert_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    /* Single-cert form: the envelope target doubles as the one-cert trust
     * bundle. Callers with a CA/RA bundle should use the _ex form. */
    WolfCertScepResult r = { 0 };
    int rc = wolfcert_scep_renewal_req_ex(srv, caps, ra_cert, ra_cert_len,
                                          ra_cert, ra_cert_len,
                                          current_cert, current_cert_len,
                                          current_key,
                                          csr_der, csr_der_len, &r);

    if (rc != WOLFCERT_OK) {
        wolfcert_scep_result_free(&r);
        return rc;
    }

    if (r.status == WOLFCERT_SCEP_STATUS_SUCCESS) {
        *out_cert_pem = r.cert_pem;
        r.cert_pem.data = NULL;
        r.cert_pem.len = 0;
        wolfcert_scep_result_free(&r);
        return WOLFCERT_OK;
    }

    int err = r.status == WOLFCERT_SCEP_STATUS_PENDING
              ? WOLFCERT_ERR_PENDING : WOLFCERT_ERR_PROTOCOL;

    wolfcert_scep_result_free(&r);
    return err;
}

int wolfcert_scep_get_cert_initial(const WolfCertServerCfg* srv,
                                   const WolfCertScepCaps*  caps,
                                   const uint8_t* ra_cert, size_t ra_cert_len,
                                   const uint8_t* ca_bundle, size_t ca_bundle_len,
                                   const uint8_t* signer_cert, size_t signer_cert_len,
                                   const WolfCertKey* signer_key,
                                   const uint8_t* csr_der, size_t csr_der_len,
                                   const uint8_t* transaction_id,
                                   size_t transaction_id_len,
                                   WolfCertScepResult* out)
{
    if (srv == NULL || ra_cert == NULL || ca_bundle == NULL ||
            signer_key == NULL || csr_der == NULL ||
            transaction_id == NULL || transaction_id_len == 0 || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (signer_key->type != WOLFCERT_KEY_RSA)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "SCEP (RFC 8894) requires an RSA signer for pkiMessage");

    memset(out, 0, sizeof(*out));
    out->fail_info = -1;
    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();

    WolfCertBuffer ias = { 0 };
    uint8_t* key_der = NULL;
    size_t key_der_len = 0;
    uint8_t* derived_signer = NULL;
    size_t derived_signer_len = 0;
    const uint8_t* eff_signer     = signer_cert;
    size_t         eff_signer_len = signer_cert_len;

    int rc = wolfcert_scep_issuer_and_subject(ra_cert, ra_cert_len,
                                              csr_der, csr_der_len, &ias, heap);

    if (rc == WOLFCERT_OK)
        rc = rsa_key_to_der(signer_key, heap, &key_der, &key_der_len);

    /* For a pending PKCSReq the caller has no long-lived cert carrying
     * signer_key's pubkey, so we regenerate the same transient
     * self-signed cert (subject copied from the CSR) that pkcs_req_ex
     * wraps the original request with. RenewalReq callers supply their
     * existing cert directly. */
    if (rc == WOLFCERT_OK && signer_cert == NULL) {
        rc = wolfcert_scep_self_signed_rsa((RsaKey*)signer_key->impl,
                                            csr_der, csr_der_len,
                                            &derived_signer, &derived_signer_len,
                                            heap);
        if (rc == WOLFCERT_OK) {
            eff_signer     = derived_signer;
            eff_signer_len = derived_signer_len;
        }
    }

    if (rc == WOLFCERT_OK)
        rc = do_scep_round_trip(srv, caps, ra_cert, ra_cert_len,
                                ca_bundle, ca_bundle_len,
                                eff_signer, eff_signer_len,
                                key_der, key_der_len,
                                "20", ias.data, ias.len,
                                transaction_id, transaction_id_len, out);

    wolfcert_buffer_free(&ias);
    if (key_der != NULL) {
        wc_ForceZero(key_der, (word32)key_der_len);
        WOLFCERT_XFREE(key_der, heap);
    }
    WOLFCERT_XFREE(derived_signer, heap);
    return rc;
}

int wolfcert_scep_get_next_ca_cert(const WolfCertServerCfg* srv,
                                   const uint8_t* current_ca_der,
                                   size_t current_ca_len,
                                   WolfCertBuffer* out_next_ca_pem)
{
    if (srv == NULL || srv->server_url == NULL ||
            current_ca_der == NULL || out_next_ca_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();

    char* url = append_query(srv->server_url, "GetNextCACert", heap);
    if (url == NULL)
        return WOLFCERT_ERR_MEMORY;

    WolfCertHttpRequest req = { .method = "GET", .url = url };
    fill_common(srv, &req);

    WolfCertHttpResponse resp = { 0 };
    int rc = wolfcert_http_request(&req, &resp);

    WOLFCERT_XFREE(url, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    if (resp.status_code == 404) {
        wolfcert_http_response_free(&resp);
        return WOLFCERT_ERR_NOT_FOUND;
    }

    if (resp.status_code != 200) {
        wolfcert_http_response_free(&resp);
        return WOLFCERT_ERR_HTTP;
    }

    /* RFC 8894 section 4.6.1: the body is a SignedData signed by the current
     * CA whose content is a degenerate certs-only bundle carrying the next CA
     * certificate. Verify the signature, bind it to the trusted current CA,
     * then extract the certs from the signed content rather than the outer
     * signer certificate. */
    rc = wolfcert_scep_verify_next_ca_response(resp.body, resp.body_len,
            current_ca_der, current_ca_len, out_next_ca_pem, heap);

    wolfcert_http_response_free(&resp);
    return rc;
}
