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
 * Minimal SCEP (RFC 8894) test server. Shares the CA + issuance helpers
 * with the EST server via src/ca_issue.c.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <wolfcert/server.h>
#include <wolfcert/errors.h>
#include "../internal.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/random.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    char     method[8];
    char     path[WOLFCERT_HTTP_PATH_SZ];
    char     query[WOLFCERT_HTTP_PATH_SZ];
    size_t   content_length;
    uint8_t* body;
    size_t   body_len;
    int      connection_close;
    void*    heap;
} ScepRequest;

/* Pending-queue entry: one per PKCSReq / RenewalReq held under
 * scep_require_approval. We copy the CSR + signer cert because the
 * request's body buffer is freed before the next poll arrives. */
typedef struct {
    uint8_t* transaction_id;
    size_t   transaction_id_len;
    uint8_t* csr_der;
    size_t   csr_len;
    uint8_t* signer_cert_der;
    size_t   signer_cert_len;
    int      polls;   /* #GetCertInitial seen for this txid */
} ScepPending;

typedef struct {
    ScepPending* items;
    size_t       count;
    size_t       cap;
    /* Optional rolled-over "next" CA, generated on first GetNextCACert
     * when WolfCertServerCfgSrv::scep_enable_next_ca is set. Signed and
     * self-contained; NOT installed as the active issuing CA. */
    WolfCertCa   next_ca;
    int          next_ca_ready;
} ScepPriv;

static void free_req(ScepRequest* r)
{
    WOLFCERT_XFREE(r->body, r->heap);
    memset(r, 0, sizeof(*r));
}

static int read_line(const char** p, const char* end, char** ls, size_t* ll)
{
    const char* nl = memchr(*p, '\n', (size_t)(end - *p));
    if (nl == NULL)
        return -1;

    size_t len = (size_t)(nl - *p);
    if (len > 0 && (*p)[len - 1] == '\r')
        --len;

    *ls = (char*)*p;
    *ll = len;
    *p = nl + 1;

    return 0;
}

static int read_request(WolfCertServer* s, int fd, ScepRequest* out, void* heap)
{
    memset(out, 0, sizeof(*out));
    out->heap = heap;
    char buf[WOLFCERT_HTTP_REQ_BUF_SZ];
    size_t n = 0;
    while (n < sizeof(buf) - 1) {
        ssize_t r = wolfcert_io_recv(s, fd, buf + n, sizeof(buf) - 1 - n);
        if (r <= 0)
            return WOLFCERT_ERR_IO;

        n += (size_t)r;
        buf[n] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL)
            break;
    }

    const char* p = buf;
    const char* end = buf + n;
    char* line;
    size_t llen;
    if (read_line(&p, end, &line, &llen) != 0)
        return WOLFCERT_ERR_PROTOCOL;

    char* sp1 = memchr(line, ' ', llen);
    if (sp1 == NULL)
        return WOLFCERT_ERR_PROTOCOL;

    size_t mlen = (size_t)(sp1 - line);
    if (mlen >= sizeof(out->method))
        return WOLFCERT_ERR_PROTOCOL;

    memcpy(out->method, line, mlen);
    out->method[mlen] = '\0';

    char* sp2 = memchr(sp1 + 1, ' ', llen - mlen - 1);
    if (sp2 == NULL)
        return WOLFCERT_ERR_PROTOCOL;

    size_t pqlen = (size_t)(sp2 - sp1 - 1);
    char full[2 * WOLFCERT_HTTP_PATH_SZ];
    if (pqlen >= sizeof(full))
        return WOLFCERT_ERR_PROTOCOL;

    memcpy(full, sp1 + 1, pqlen);
    full[pqlen] = '\0';

    char* qs = strchr(full, '?');
    if (qs != NULL) {
        *qs = '\0';
        strncpy(out->query, qs + 1, sizeof(out->query) - 1);
        out->query[sizeof(out->query) - 1] = '\0';
    }
    strncpy(out->path, full, sizeof(out->path) - 1);
    out->path[sizeof(out->path) - 1] = '\0';

    while (read_line(&p, end, &line, &llen) == 0 && llen > 0) {
        if (llen > 14 && strncasecmp(line, "Content-Length", 14) == 0) {
            char* c = memchr(line, ':', llen);
            if (c)
                out->content_length = (size_t)strtoul(c + 1, NULL, 10);
        }
        else if (llen > 10 && strncasecmp(line, "Connection", 10) == 0) {
            char* colon = memchr(line, ':', llen);
            if (colon != NULL) {
                const char* v = colon + 1;
                while (v < line + llen && (*v == ' ' || *v == '\t'))
                    ++v;
                size_t vlen = (size_t)(line + llen - v);
                if (vlen >= 5 && strncasecmp(v, "close", 5) == 0)
                    out->connection_close = 1;
            }
        }
    }

    size_t have = (size_t)(end - p);
    if (out->content_length > 0) {
        if (out->content_length > 1 * 1024 * 1024)
            return WOLFCERT_ERR_PROTOCOL;

        out->body = (uint8_t*)WOLFCERT_XMALLOC(out->content_length, heap);
        if (out->body == NULL)
            return WOLFCERT_ERR_MEMORY;

        size_t take = have > out->content_length ? out->content_length : have;
        memcpy(out->body, p, take);
        size_t left = out->content_length - take;
        while (left > 0) {
            ssize_t r = wolfcert_io_recv(s, fd,
                         out->body + (out->content_length - left), left);
            if (r <= 0) {
                WOLFCERT_XFREE(out->body, heap);
                out->body = NULL;
                return WOLFCERT_ERR_IO;
            }
            left -= (size_t)r;
        }
        out->body_len = out->content_length;
    }

    return WOLFCERT_OK;
}

static void send_all(WolfCertServer* s, int fd, const void* buf, size_t len)
{
    const uint8_t* p = buf;
    size_t n = 0;
    while (n < len) {
        ssize_t r = wolfcert_io_send(s, fd, p + n, len - n);
        if (r <= 0)
            break;
        n += (size_t)r;
    }
}

static const char* conn_hdr(const WolfCertServer* s)
{
    return s->keep_alive ? "keep-alive" : "close";
}

static void send_text(WolfCertServer* s, int fd, int status, const char* phrase,
                      const char* content_type, const char* body)
{
    size_t bl = body ? strlen(body) : 0;
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
        "Connection: %s\r\n\r\n",
        status, phrase, content_type, bl, conn_hdr(s));

    send_all(s, fd, hdr, (size_t)n);
    if (bl > 0)
        send_all(s, fd, body, bl);
}

static void send_bin(WolfCertServer* s, int fd, const char* content_type,
                     const uint8_t* body, size_t bl)
{
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
        "Connection: %s\r\n\r\n",
        content_type, bl, conn_hdr(s));

    send_all(s, fd, hdr, (size_t)n);
    send_all(s, fd, body, bl);
}

static void handle_get_ca_caps(WolfCertServer* s, int fd)
{
    if (s->cfg.scep_enable_next_ca) {
        send_text(s, fd, 200, "OK", "text/plain",
                  "POSTPKIOperation\r\nSHA-256\r\nAES\r\nRenewal\r\n"
                  "SCEPStandard\r\nGetNextCACert\r\n");
    }
    else {
        send_text(s, fd, 200, "OK", "text/plain",
                  "POSTPKIOperation\r\nSHA-256\r\nAES\r\nRenewal\r\nSCEPStandard\r\n");
    }
}

static void handle_get_ca_cert(WolfCertServer* s, int fd)
{
    send_bin(s, fd, "application/x-x509-ca-cert", s->ca.cert_der, s->ca.cert_der_len);
}

/* Materialize the rolled-over CA on first request and return its cert as
 * a degenerate certs-only PKCS#7. Strict RFC 8894 section 4.6.1 wants the
 * response signed by the current CA; in practice all deployed SCEP
 * clients we've interoperated with accept the degenerate form, and this
 * keeps the test server honest about what it actually produces. */
static void handle_get_next_ca_cert(WolfCertServer* s, int fd)
{
    if (!s->cfg.scep_enable_next_ca) {
        send_text(s, fd, 404, "Not Found", "text/plain", "");
        return;
    }

    ScepPriv* p = (ScepPriv*)s->priv;
    if (!p->next_ca_ready) {
        WolfCertKeyType kt = s->cfg.ca_key_type ? s->cfg.ca_key_type : WOLFCERT_KEY_RSA;
        int kp = s->cfg.ca_key_param;
        if (wolfcert_ca_generate(&p->next_ca, kt, kp, s->heap) != WOLFCERT_OK) {
            send_text(s, fd, 500, "Server Error", "text/plain", "");
            return;
        }
        p->next_ca_ready = 1;
    }

    const uint8_t* cs[1] = { p->next_ca.cert_der };
    size_t         cl[1] = { p->next_ca.cert_der_len };
    WolfCertBuffer p7    = { 0 };

    if (wolfcert_pkcs7_build_certs_only(cs, cl, 1, &p7, s->heap) != WOLFCERT_OK) {
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return;
    }

    send_bin(s, fd, "application/x-x509-next-ca-cert", p7.data, p7.len);
    wolfcert_buffer_free(&p7);
}

/* ---- pending queue ----------------------------------------------------- */

#define SCEP_PENDING_MAX 16

static ScepPending* pending_find(ScepPriv* p, const uint8_t* tid, size_t tid_len)
{
    for (size_t i = 0; i < p->count; ++i) {
        ScepPending* e = &p->items[i];
        if (e->transaction_id_len == tid_len &&
                memcmp(e->transaction_id, tid, tid_len) == 0)
            return e;
    }
    return NULL;
}

static int pending_add(ScepPriv* p, void* heap,
                       const uint8_t* tid, size_t tid_len,
                       const uint8_t* csr, size_t csr_len,
                       const uint8_t* signer, size_t signer_len)
{
    if (p->count >= SCEP_PENDING_MAX)
        return WOLFCERT_ERR_MEMORY;

    if (p->items == NULL) {
        p->items = (ScepPending*)WOLFCERT_XMALLOC(
            sizeof(ScepPending) * SCEP_PENDING_MAX, heap);
        if (p->items == NULL)
            return WOLFCERT_ERR_MEMORY;

        p->cap = SCEP_PENDING_MAX;
        memset(p->items, 0, sizeof(ScepPending) * SCEP_PENDING_MAX);
    }

    ScepPending* e     = &p->items[p->count];
    e->transaction_id  = (uint8_t*)WOLFCERT_XMALLOC(tid_len, heap);
    e->csr_der         = (uint8_t*)WOLFCERT_XMALLOC(csr_len, heap);
    e->signer_cert_der = (uint8_t*)WOLFCERT_XMALLOC(signer_len, heap);

    if (e->transaction_id == NULL || e->csr_der == NULL ||
            e->signer_cert_der == NULL) {
        WOLFCERT_XFREE(e->transaction_id, heap);
        WOLFCERT_XFREE(e->csr_der, heap);
        WOLFCERT_XFREE(e->signer_cert_der, heap);
        memset(e, 0, sizeof(*e));
        return WOLFCERT_ERR_MEMORY;
    }

    memcpy(e->transaction_id, tid, tid_len);
    memcpy(e->csr_der, csr, csr_len);
    memcpy(e->signer_cert_der, signer, signer_len);
    e->transaction_id_len = tid_len;
    e->csr_len            = csr_len;
    e->signer_cert_len    = signer_len;
    e->polls = 0;
    p->count++;

    return WOLFCERT_OK;
}

static void pending_remove(ScepPriv* p, void* heap, ScepPending* e)
{
    size_t idx = (size_t)(e - p->items);
    if (idx >= p->count)
        return;

    WOLFCERT_XFREE(e->transaction_id,  heap);
    WOLFCERT_XFREE(e->csr_der,         heap);
    WOLFCERT_XFREE(e->signer_cert_der, heap);

    /* swap-with-last to avoid memmove of the whole array */
    if (idx != p->count - 1)
        p->items[idx] = p->items[p->count - 1];

    memset(&p->items[p->count - 1], 0, sizeof(ScepPending));
    p->count--;
}

/* Verify the CSR's embedded PKCS#9 challengePassword (RFC 8894 section 2.9)
 * matches `expected`. Returns WOLFCERT_OK on match (or when no challenge
 * is configured), WOLFCERT_ERR_AUTH on mismatch / missing / parse failure.
 * Constant-time compare on the common-length prefix to avoid trivial
 * timing side channel. */
static int check_challenge(const uint8_t* csr_der, size_t csr_len,
                           const char* expected, void* heap)
{
    if (expected == NULL || expected[0] == '\0')
        return WOLFCERT_OK;

    DecodedCert dc;
    wc_InitDecodedCert(&dc, (byte*)csr_der, (word32)csr_len, heap);

    int rc = wc_ParseCert(&dc, CERTREQ_TYPE, NO_VERIFY, NULL);
    if (rc != 0) {
        wc_FreeDecodedCert(&dc);
        return WOLFCERT_ERR_AUTH;
    }

    size_t elen = strlen(expected);
    int ok = (dc.cPwd != NULL) && ((size_t)dc.cPwdLen == elen);
    if (ok) {
        unsigned acc = 0;
        for (size_t i = 0; i < elen; ++i) {
            acc |= (unsigned)(dc.cPwd[i] ^ expected[i]);
        }
        ok = (acc == 0);
    }

    wc_FreeDecodedCert(&dc);
    return ok ? WOLFCERT_OK : WOLFCERT_ERR_AUTH;
}

/* Ensure signer cert's SPKI matches the CSR's SPKI. Trust boundary: do
 * NOT issue a cert whose subject public key differs from the one that
 * the request was signed with. */
static int signer_matches_csr(const uint8_t* signer_der, size_t signer_len,
                              const uint8_t* csr_der, size_t csr_len,
                              void* heap)
{
    uint8_t* sa = NULL;
    size_t sa_len = 0;
    uint8_t* sb = NULL;
    size_t sb_len = 0;
    int rc = wolfcert_extract_spki(signer_der, signer_len, 0, &sa, &sa_len, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    rc = wolfcert_extract_spki(csr_der, csr_len, 1, &sb, &sb_len, heap);
    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(sa, heap);
        return rc;
    }

    rc = (sa_len == sb_len && memcmp(sa, sb, sa_len) == 0) ?
            WOLFCERT_OK : WOLFCERT_ERR_AUTH;

    WOLFCERT_XFREE(sa, heap);
    WOLFCERT_XFREE(sb, heap);
    return rc;
}

/* Build + send a CertRep pkiMessage with the supplied pkiStatus.
 * When status==0 (success) the issued cert is enveloped for `env_target`;
 * when status==3 (pending) or status==2 (failure) the payload is empty. */
static int send_cert_rep(WolfCertServer* s, int fd,
                         const uint8_t* issued_cert, size_t issued_cert_len,
                         const uint8_t* env_target, size_t env_target_len,
                         const uint8_t* tid, size_t tid_len,
                         const uint8_t* snonce, size_t snonce_len,
                         const char* pki_status, const char* fail_info)
{
    int rc = WOLFCERT_OK;
    WolfCertBuffer resp_env = { 0 };

    if (strcmp(pki_status, "0") == 0) {
        const uint8_t* cs[1] = { issued_cert };
        size_t         cl[1] = { issued_cert_len };
        WolfCertBuffer p7 = { 0 };

        rc = wolfcert_pkcs7_build_certs_only(cs, cl, 1, &p7, s->heap);
        if (rc != WOLFCERT_OK) {
            send_text(s, fd, 500, "Server Error", "text/plain", "");
            return rc;
        }

        rc = wolfcert_scep_envelop(env_target, env_target_len,
                                    p7.data, p7.len, AES128CBCb, &resp_env,
                                    s->heap);

        wolfcert_buffer_free(&p7);
        if (rc != WOLFCERT_OK) {
            send_text(s, fd, 500, "Server Error", "text/plain", "");
            return rc;
        }
    }
    /* RFC 8894 section 3.2.2: a CertRep with pkiStatus PENDING ("3") or
     * FAILURE ("2") carries no enveloped messageData. resp_env is left empty
     * so the signed pkiMessage is built with an absent pkcsPKIEnvelope. */

    WC_RNG rng;
    wc_InitRng_ex(&rng, s->heap, WOLFCERT_DEVID_SOFTWARE);

    uint8_t my_nonce[16];
    wc_RNG_GenerateBlock(&rng, my_nonce, sizeof(my_nonce));
    wc_FreeRng(&rng);

    /* RFC 8894 section 3.1: CertRep MUST carry messageType, pkiStatus,
     * transactionID, senderNonce, recipientNonce (plus failInfo on failure).
     * Alongside the three CMS auto-defaults (contentType, messageDigest,
     * signingTime) that is up to 9 signed attributes. wolfSSL's PKCS#7
     * encoder grows its signed-attribute array on the heap past the inline
     * MAX_SIGNED_ATTRIBS_SZ (default 7), so the full set encodes fine on any
     * malloc-enabled build. Only a WOLFSSL_NO_MALLOC build with the default
     * inline cap can't fit it; there we drop recipientNonce/failInfo unless
     * wolfSSL was rebuilt with -DMAX_SIGNED_ATTRIBS_SZ>=9. */
    WolfCertScepAttrs attrs = {
        .transaction_id     = tid, .transaction_id_len = tid_len,
        .sender_nonce       = my_nonce, .sender_nonce_len = sizeof(my_nonce),
        .message_type       = "3",
        .pki_status         = pki_status,
#if !defined(WOLFSSL_NO_MALLOC) || (MAX_SIGNED_ATTRIBS_SZ >= 9)
        .fail_info          = fail_info,
        .recipient_nonce    = snonce, .recipient_nonce_len = snonce_len,
#endif
    };
#if defined(WOLFSSL_NO_MALLOC) && (MAX_SIGNED_ATTRIBS_SZ < 9)
    (void)snonce;
    (void)snonce_len;
    (void)fail_info;
#endif
    if (s->cfg.scep_omit_recipient_nonce) {
        attrs.recipient_nonce     = NULL;
        attrs.recipient_nonce_len = 0;
    }

    WolfCertBuffer pki_out = { 0 };
    rc = wolfcert_scep_build_pki_message(resp_env.data, resp_env.len,
                                          s->ca.cert_der, s->ca.cert_der_len,
                                          s->ca.key_der,  s->ca.key_der_len,
                                          SHA256h, &attrs, &pki_out, s->heap);

    wolfcert_buffer_free(&resp_env);
    if (rc != WOLFCERT_OK) {
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return rc;
    }

    send_bin(s, fd, "application/x-pki-message", pki_out.data, pki_out.len);
    wolfcert_buffer_free(&pki_out);

    return WOLFCERT_OK;
}

/* Issue the cert and answer with a success CertRep. */
static int issue_and_reply(WolfCertServer* s, int fd,
                           const uint8_t* csr, size_t csr_len,
                           const uint8_t* env_target, size_t env_target_len,
                           const uint8_t* tid, size_t tid_len,
                           const uint8_t* snonce, size_t snonce_len)
{
    uint8_t* issued = NULL;
    size_t issued_len = 0;
    int rc = wolfcert_ca_issue(&s->ca, csr, csr_len, &issued, &issued_len);
    if (rc != WOLFCERT_OK) {
        send_text(s, fd, 400, "Bad CSR", "text/plain", "");
        return rc;
    }

    rc = send_cert_rep(s, fd, issued, issued_len,
                       env_target, env_target_len,
                       tid, tid_len, snonce, snonce_len, "0", NULL);

    WOLFCERT_XFREE(issued, s->heap);
    return rc;
}

/* Handle messageType=19 (PKCSReq) or 17 (RenewalReq) freshly arrived. */
static int handle_enroll(WolfCertServer* s, int fd, const char* mt,
                         const WolfCertBuffer* csr,
                         const uint8_t* signer_cert, size_t signer_cert_len,
                         const uint8_t* tid, size_t tid_len,
                         const uint8_t* snonce, size_t snonce_len)
{
    (void)mt;
    const uint8_t* env_target     = signer_cert ? signer_cert : s->ca.cert_der;
    size_t         env_target_len = signer_cert ? signer_cert_len : s->ca.cert_der_len;

    /* Enforce signer/CSR SPKI match. */
    if (signer_cert != NULL &&
            signer_matches_csr(signer_cert, signer_cert_len,
                               csr->data, csr->len, s->heap) != WOLFCERT_OK) {
        send_text(s, fd, 400, "Signer/CSR Key Mismatch", "text/plain", "");
        return WOLFCERT_ERR_AUTH;
    }

    if (check_challenge(csr->data, csr->len, s->cfg_challenge,
                        s->heap) != WOLFCERT_OK) {
        send_text(s, fd, 403, "Invalid Challenge", "text/plain", "");
        return WOLFCERT_ERR_AUTH;
    }

    if (s->cfg.scep_require_approval) {
        /* Defer issuance; return pkiStatus=3 (PENDING). The client polls
         * with GetCertInitial (messageType 20) referencing this txid. */
        ScepPriv* p = (ScepPriv*)s->priv;
        if (pending_find(p, tid, tid_len) == NULL) {
            int add = pending_add(p, s->heap, tid, tid_len,
                                  csr->data, csr->len,
                                  signer_cert ? signer_cert : s->ca.cert_der,
                                  signer_cert ? signer_cert_len : s->ca.cert_der_len);

            if (add != WOLFCERT_OK) {
                /* Queue full - fail rather than silently losing requests. */
                return send_cert_rep(s, fd, NULL, 0, env_target, env_target_len,
                                     tid, tid_len, snonce, snonce_len,
                                     "2", "2" /* badRequest */);
            }
        }

        return send_cert_rep(s, fd, NULL, 0, env_target, env_target_len,
                             tid, tid_len, snonce, snonce_len, "3", NULL);
    }

    return issue_and_reply(s, fd, csr->data, csr->len,
                           env_target, env_target_len,
                           tid, tid_len, snonce, snonce_len);
}

/* Handle messageType=20 (GetCertInitial): poll for a pending enrollment.
 * Test-server policy: the first poll for a known transactionID issues
 * the cert and drains the queue entry; subsequent polls for unknown
 * transactionIDs return pkiStatus=2 (FAILURE) rather than pretending
 * to be pending forever. */
static int handle_get_cert_initial(WolfCertServer* s, int fd,
                                   const uint8_t* tid, size_t tid_len,
                                   const uint8_t* snonce, size_t snonce_len,
                                   const uint8_t* signer_cert, size_t signer_cert_len)
{
    ScepPriv* p = (ScepPriv*)s->priv;
    ScepPending* e = pending_find(p, tid, tid_len);
    if (e == NULL) {
        const uint8_t* env_target     = signer_cert ? signer_cert : s->ca.cert_der;
        size_t         env_target_len = signer_cert ? signer_cert_len : s->ca.cert_der_len;

        return send_cert_rep(s, fd, NULL, 0, env_target, env_target_len,
                             tid, tid_len, snonce, snonce_len,
                             "2", "4" /* badCertId: no such transaction */);
    }

    /* Approve on first poll. A production implementation would hold
     * requests until an admin acts on a queue; for the test server a
     * single round trip through pending is enough to exercise the
     * RFC 8894 section 3.3.2 flow end-to-end. */
    e->polls++;
    uint8_t* csr_copy = (uint8_t*)WOLFCERT_XMALLOC(e->csr_len, s->heap);
    if (csr_copy == NULL) {
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return WOLFCERT_ERR_MEMORY;
    }

    memcpy(csr_copy, e->csr_der, e->csr_len);
    size_t   csr_len_local = e->csr_len;
    uint8_t* tgt = (uint8_t*)WOLFCERT_XMALLOC(e->signer_cert_len, s->heap);
    if (tgt == NULL) {
        WOLFCERT_XFREE(csr_copy, s->heap);
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return WOLFCERT_ERR_MEMORY;
    }

    memcpy(tgt, e->signer_cert_der, e->signer_cert_len);
    size_t tgt_len = e->signer_cert_len;

    pending_remove(p, s->heap, e);

    int rc = issue_and_reply(s, fd, csr_copy, csr_len_local,
                             tgt, tgt_len,
                             tid, tid_len, snonce, snonce_len);

    WOLFCERT_XFREE(csr_copy, s->heap);
    WOLFCERT_XFREE(tgt,      s->heap);
    return rc;
}

static int handle_pki_op(WolfCertServer* s, int fd, const ScepRequest* req)
{
    WolfCertBuffer env = { 0 };
    uint8_t* tid = NULL;
    size_t tid_len = 0;
    uint8_t* snonce = NULL;
    size_t snonce_len = 0;
    uint8_t* rnonce = NULL;
    size_t rnonce_len = 0;
    char* mt = NULL;
    char* ps = NULL;
    uint8_t* signer_cert = NULL;
    size_t signer_cert_len = 0;
    WolfCertBuffer csr = { 0 };

    int rc = wolfcert_scep_parse_pki_message(req->body, req->body_len, &env,
            &tid, &tid_len, &snonce, &snonce_len, &rnonce, &rnonce_len,
            &mt, &ps, &signer_cert, &signer_cert_len, s->heap);
    if (rc != WOLFCERT_OK) {
        send_text(s, fd, 400, "Bad Request", "text/plain", "");
        goto out;
    }

    if (mt == NULL) {
        send_text(s, fd, 400, "Bad Message", "text/plain", "");
        goto out;
    }

    rc = wolfcert_scep_deenvelop(s->ca.cert_der, s->ca.cert_der_len,
                                  s->ca.key_der,  s->ca.key_der_len,
                                  env.data, env.len, &csr, s->heap);
    if (rc != WOLFCERT_OK && strcmp(mt, "20") != 0) {
        /* Decryption matters for 19/17 (CSR inside); for 20 the payload
         * is IssuerAndSubject which the server matches by txid anyway. */
        send_text(s, fd, 400, "Cannot Decrypt", "text/plain", "");
        goto out;
    }

    if (strcmp(mt, "19") == 0 || strcmp(mt, "17") == 0) {
        rc = handle_enroll(s, fd, mt, &csr, signer_cert, signer_cert_len,
                           tid, tid_len, snonce, snonce_len);
    }
    else if (strcmp(mt, "20") == 0) {
        rc = handle_get_cert_initial(s, fd, tid, tid_len, snonce, snonce_len,
                                     signer_cert, signer_cert_len);
    }
    else {
        send_text(s, fd, 400, "Bad Message", "text/plain", "");
        rc = WOLFCERT_ERR_PROTOCOL;
    }

out:
    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&env);
    WOLFCERT_XFREE(tid,    s->heap);
    WOLFCERT_XFREE(snonce, s->heap);
    WOLFCERT_XFREE(rnonce, s->heap);
    WOLFCERT_XFREE(mt,     s->heap);
    WOLFCERT_XFREE(ps,     s->heap);
    WOLFCERT_XFREE(signer_cert, s->heap);

    return rc;
}

static int handle_request(WolfCertServer* s, int fd)
{
    ScepRequest req = { 0 };
    int rc = read_request(s, fd, &req, s->heap);
    if (rc != WOLFCERT_OK) {
        s->keep_alive = 0;
        send_text(s, fd, 400, "Bad Request", "text/plain", "");
        free_req(&req);
        return rc;
    }

    if (req.connection_close)
        s->keep_alive = 0;

    const char* op = strstr(req.query, "operation=");
    if (op == NULL) {
        send_text(s, fd,400, "Bad Request", "text/plain", "");
        free_req(&req);
        return WOLFCERT_ERR_PROTOCOL;
    }
    op += 10;

    if (strncmp(op, "GetCACaps", 9) == 0 && strcmp(req.method, "GET") == 0) {
        handle_get_ca_caps(s, fd);
    }
    else if (strncmp(op, "GetNextCACert", 13) == 0 && strcmp(req.method, "GET") == 0) {
        handle_get_next_ca_cert(s, fd);
    }
    else if (strncmp(op, "GetCACert", 9) == 0 && strcmp(req.method, "GET") == 0) {
        handle_get_ca_cert(s, fd);
    }
    else if (strncmp(op, "PKIOperation", 12) == 0 && strcmp(req.method, "POST") == 0) {
        rc = handle_pki_op(s, fd, &req);
    }
    else {
        send_text(s, fd,404, "Not Found", "text/plain", "");
    }

    free_req(&req);
    return rc;
}

/* ---- vtable ------------------------------------------------------------ */

static int scep_start(const WolfCertServerCfgSrv* cfg, WolfCertServer* base)
{
    (void)cfg;
    ScepPriv* p = (ScepPriv*)WOLFCERT_XMALLOC(sizeof(*p), base->heap);
    if (p == NULL)
        return WOLFCERT_ERR_MEMORY;

    memset(p, 0, sizeof(*p));
    base->priv = p;

    return WOLFCERT_OK;
}

static int scep_serve_fd(WolfCertServer* srv, int fd)
{
    return handle_request(srv, fd);
}

static void scep_free_priv(WolfCertServer* srv)
{
    ScepPriv* p = (ScepPriv*)srv->priv;
    if (p == NULL)
        return;

    for (size_t i = 0; i < p->count; ++i) {
        WOLFCERT_XFREE(p->items[i].transaction_id,  srv->heap);
        WOLFCERT_XFREE(p->items[i].csr_der,         srv->heap);
        WOLFCERT_XFREE(p->items[i].signer_cert_der, srv->heap);
    }

    WOLFCERT_XFREE(p->items, srv->heap);
    if (p->next_ca_ready)
        wolfcert_ca_free(&p->next_ca);
    WOLFCERT_XFREE(p, srv->heap);
    srv->priv = NULL;
}

static const WolfCertServerOps SCEP_OPS = {
    .start     = scep_start,
    .serve_fd  = scep_serve_fd,
    .free_priv = scep_free_priv,
};

const WolfCertServerOps* wolfcert_scep_server_ops(void)
{
    return &SCEP_OPS;
}
