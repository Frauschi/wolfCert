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

#ifndef WOLFCERT_SCEP_H
#define WOLFCERT_SCEP_H

#include <wolfcert/types.h>
#include <wolfcert/keygen.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Low-level SCEP (RFC 8894) client primitives. SCEP messages are PKCS#7
 * structures; wolfCert builds them using wolfSSL's wc_PKCS7 API. */

typedef struct {
    int post_pki_operation;      /* GetCACaps: POSTPKIOperation */
    int renewal;                 /* GetCACaps: Renewal */
    int sha256;                  /* GetCACaps: SHA-256 */
    int sha384;                  /* GetCACaps: SHA-384 */
    int sha512;                  /* GetCACaps: SHA-512 */
    int aes;                     /* GetCACaps: AES */
    int scep_standard;           /* GetCACaps: SCEPStandard */
    int get_next_ca_cert;        /* GetCACaps: GetNextCACert */
} WolfCertScepCaps;

WOLFCERT_API int wolfcert_scep_get_ca_caps(const WolfCertServerCfg* srv,
                                           WolfCertScepCaps* out_caps);

WOLFCERT_API int wolfcert_scep_get_ca_cert(const WolfCertServerCfg* srv,
                                           WolfCertBuffer* out_ca_pem);

/* Like wolfcert_scep_get_ca_cert but returns the CA/RA certificate(s) in the
 * requested encoding. WOLFCERT_ENCODING_DER yields the whole GetCACert bundle
 * as concatenated DER, suitable as the ca_bundle trust set for the enroll and
 * GetNextCACert calls. */
WOLFCERT_API int wolfcert_scep_get_ca_cert_enc(const WolfCertServerCfg* srv,
                                               WolfCertEncoding enc,
                                               WolfCertBuffer* out_ca);

/* RFC 8894 section 3.2.1.3 pkiStatus values returned by the server in a CertRep
 * pkiMessage. PENDING means the enrollment was accepted but is waiting
 * for manual approval; the caller re-queries later via
 * wolfcert_scep_get_cert_initial using the returned transactionID.
 *
 * UNSET is the zero value so a caller who does `WolfCertScepResult r =
 * {0};` doesn't get something that looks like SUCCESS before the
 * library has populated anything. The SUCCESS / FAILURE / PENDING
 * values are wolfCert-internal and need not match RFC 8894's wire
 * encoding (which uses "0" / "2" / "3" printable strings); the library
 * maps between the two in do_scep_round_trip. */
typedef enum {
    WOLFCERT_SCEP_STATUS_UNSET   = 0,
    WOLFCERT_SCEP_STATUS_SUCCESS = 1,
    WOLFCERT_SCEP_STATUS_FAILURE = 2,
    WOLFCERT_SCEP_STATUS_PENDING = 3
} WolfCertScepStatus;

typedef struct {
    WolfCertScepStatus status;
    /* cert_pem is owned and populated iff status == SUCCESS. */
    WolfCertBuffer     cert_pem;
    /* transaction_id (binary) is owned and populated whenever the server
     * returns a CertRep; callers echo it back via get_cert_initial. */
    uint8_t*           transaction_id;
    size_t             transaction_id_len;
    /* RFC 8894 section 3.2.1.4 failInfo; meaningful only when status==FAILURE.
     * 0=badAlg, 1=badMessageCheck, 2=badRequest, 3=badTime, 4=badCertId.
     * -1 if the server did not include the attribute. */
    int                fail_info;
    void*              heap;
} WolfCertScepResult;

WOLFCERT_API void wolfcert_scep_result_free(WolfCertScepResult* r);

/* PKCSReq: enroll a new certificate. challengePassword is taken from
 * srv->password.
 *
 * `ra_cert` is the DER cert the request is enveloped to (the CA/RA encryption
 * cert). `ca_bundle` is the trusted GetCACert response (one or more
 * concatenated DER certs) the CertRep signer is checked against; in a split
 * CA/RA deployment the response signer differs from `ra_cert`, so pass the
 * whole bundle. For a single-cert CA, pass `ra_cert` as the bundle (the
 * wolfcert_scep_pkcs_req wrapper does this).
 *
 * Returns WOLFCERT_OK on any successful server round-trip; inspect
 * out->status to distinguish SUCCESS / PENDING / FAILURE. Transport-level
 * errors (TLS, HTTP, parse) surface as negative wolfCert error codes. */
WOLFCERT_API int wolfcert_scep_pkcs_req_ex(const WolfCertServerCfg* srv,
                                           const WolfCertScepCaps* caps,
                                           const uint8_t* ra_cert, size_t ra_cert_len,
                                           const uint8_t* ca_bundle, size_t ca_bundle_len,
                                           const WolfCertKey* new_key,
                                           const uint8_t* csr_der, size_t csr_der_len,
                                           WolfCertScepResult* out);

/* PKCSReq, simple-result form. Returns WOLFCERT_ERR_PENDING when the server
 * replies pkiStatus=3 and WOLFCERT_ERR_PROTOCOL on pkiStatus=2. For the richer
 * shape (transactionID etc.) use wolfcert_scep_pkcs_req_ex. */
WOLFCERT_API int wolfcert_scep_pkcs_req(const WolfCertServerCfg* srv,
                                        const WolfCertScepCaps* caps,
                                        const uint8_t* ra_cert, size_t ra_cert_len,
                                        const WolfCertKey* new_key,
                                        const uint8_t* csr_der, size_t csr_der_len,
                                        WolfCertBuffer* out_cert_pem);

/* RenewalReq: re-enroll using an existing cert/key to sign the pkiMessage.
 * `ra_cert` is the envelope target; `ca_bundle` is the trusted GetCACert bundle
 * the response signer is checked against (see wolfcert_scep_pkcs_req_ex). */
WOLFCERT_API int wolfcert_scep_renewal_req_ex(const WolfCertServerCfg* srv,
                                              const WolfCertScepCaps* caps,
                                              const uint8_t* ra_cert, size_t ra_cert_len,
                                              const uint8_t* ca_bundle, size_t ca_bundle_len,
                                              const uint8_t* current_cert, size_t current_cert_len,
                                              const WolfCertKey* current_key,
                                              const WolfCertKey* new_key,
                                              const uint8_t* csr_der, size_t csr_der_len,
                                              WolfCertScepResult* out);

WOLFCERT_API int wolfcert_scep_renewal_req(const WolfCertServerCfg* srv,
                                           const WolfCertScepCaps* caps,
                                           const uint8_t* ra_cert, size_t ra_cert_len,
                                           const uint8_t* current_cert, size_t current_cert_len,
                                           const WolfCertKey* current_key,
                                           const WolfCertKey* new_key,
                                           const uint8_t* csr_der, size_t csr_der_len,
                                           WolfCertBuffer* out_cert_pem);

/* GetCertInitial (RFC 8894 section 3.3.2, messageType 20): poll for a
 * previously-submitted PKCSReq/RenewalReq that returned PENDING.
 *
 * For a pending PKCSReq, pass signer_cert=NULL; the function will
 * generate the same transient self-signed cert that pkcs_req_ex uses,
 * since its public key already matches signer_key. For a pending
 * RenewalReq, pass the cert being renewed as signer_cert.
 *
 * `transaction_id` must be the value returned by the prior request.
 * `ra_cert` is the envelope target; `ca_bundle` is the trusted GetCACert bundle
 * the response signer is checked against (see wolfcert_scep_pkcs_req_ex). */
WOLFCERT_API int wolfcert_scep_get_cert_initial(const WolfCertServerCfg* srv,
                                                const WolfCertScepCaps*  caps,
                                                const uint8_t* ra_cert, size_t ra_cert_len,
                                                const uint8_t* ca_bundle, size_t ca_bundle_len,
                                                const uint8_t* signer_cert, size_t signer_cert_len,
                                                const WolfCertKey* signer_key,
                                                const uint8_t* csr_der, size_t csr_der_len,
                                                const uint8_t* transaction_id,
                                                size_t transaction_id_len,
                                                WolfCertScepResult* out);

/* GetNextCACert (RFC 8894 section 4.6.1): retrieve the roll-over CA cert ahead
 * of the current CA's expiry, so the device can install the new trust
 * anchor before the old one stops being honored. Returns
 * WOLFCERT_ERR_NOT_FOUND when the server has no roll-over configured
 * (HTTP 404).
 *
 * The response is a CMS SignedData signed by the current CA. current_ca_der is
 * the current CA certificate(s) in DER (one or more concatenated DER certs,
 * e.g. the whole GetCACert bundle, previously fetched and verified out of band)
 * and is required: the roll-over message is rejected unless its SignedData
 * signer shares a public key with one of them, so a substituted roll-over CA
 * over an untrusted transport is refused. */
WOLFCERT_API int wolfcert_scep_get_next_ca_cert(const WolfCertServerCfg* srv,
                                                const uint8_t* current_ca_der,
                                                size_t current_ca_len,
                                                WolfCertBuffer* out_next_ca_pem);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_SCEP_H */
