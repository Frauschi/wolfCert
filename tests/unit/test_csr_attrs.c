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
 * Unit coverage for wolfcert_est_parse_csr_attrs. We hand-build
 * CsrAttrs DER blobs to cover:
 *   - empty response (len==0),
 *   - bare OIDs (challengePassword + extensionRequest),
 *   - a full Attribute (id-ecPublicKey with a named-curve value),
 *   - a bare signature-algorithm OID (ecdsa-with-SHA384) that populates
 *     preferred_hash + preferred_key_type,
 *   - malformed inputs (truncated length, wrong outer tag).
 */

#define _POSIX_C_SOURCE 200809L

#include <wolfcert/wolfcert.h>
#include <wolfcert/est.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

/* Encode `body` as `tag | short-form-length | body` into `out`.
 * Always uses short-form length (len < 128). Returns bytes written. */
static size_t der_tlv(uint8_t tag, const uint8_t* body, size_t body_len,
                      uint8_t* out)
{
    out[0] = tag;
    out[1] = (uint8_t)body_len;
    memcpy(out + 2, body, body_len);
    return 2 + body_len;
}

static const uint8_t OID_CHALLENGE_PASSWORD[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07
};
static const uint8_t OID_EXTENSION_REQUEST[]  = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E
};
static const uint8_t OID_ECDSA_SHA384[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03
};
static const uint8_t OID_EC_PUBLIC_KEY[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
};
static const uint8_t OID_SECP384R1[] = { 0x2B, 0x81, 0x04, 0x00, 0x22 };

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    /* ---- Empty input -> OK, no items, all hint fields zero. */
    {
        WolfCertCsrAttrs a;
        REQUIRE(wolfcert_est_parse_csr_attrs(NULL, 0, &a) == WOLFCERT_OK);
        REQUIRE(a.count == 0);
        REQUIRE(a.require_challenge_password == 0);
        wolfcert_csr_attrs_free(&a);
    }

    /* ---- Two bare OIDs + one sig-alg bare OID + one id-ecPublicKey
     *      Attribute with P-384 value. Build the inner SEQUENCE body
     *      first, then wrap in the outer SEQUENCE header. */
    uint8_t body[256];
    size_t body_len = 0;

    /* (1) bare OID challengePassword */
    body_len += der_tlv(0x06, OID_CHALLENGE_PASSWORD,
                        sizeof(OID_CHALLENGE_PASSWORD), body + body_len);
    /* (2) bare OID extensionRequest */
    body_len += der_tlv(0x06, OID_EXTENSION_REQUEST,
                        sizeof(OID_EXTENSION_REQUEST), body + body_len);
    /* (3) bare OID ecdsa-with-SHA384 (signature algorithm hint) */
    body_len += der_tlv(0x06, OID_ECDSA_SHA384, sizeof(OID_ECDSA_SHA384),
                        body + body_len);

    /* (4) Attribute SEQUENCE { OID id-ecPublicKey, SET { OID secp384r1 } } */
    uint8_t set_body[64];
    size_t set_body_len = 0;
    set_body_len += der_tlv(0x06, OID_SECP384R1, sizeof(OID_SECP384R1),
                            set_body + set_body_len);
    uint8_t attr_body[128];
    size_t attr_body_len = 0;
    attr_body_len += der_tlv(0x06, OID_EC_PUBLIC_KEY,
                             sizeof(OID_EC_PUBLIC_KEY), attr_body + attr_body_len);
    attr_body_len += der_tlv(0x31, set_body, set_body_len,
                             attr_body + attr_body_len);
    body_len += der_tlv(0x30, attr_body, attr_body_len, body + body_len);

    uint8_t outer[320];
    size_t outer_len = der_tlv(0x30, body, body_len, outer);

    WolfCertCsrAttrs a;
    REQUIRE(wolfcert_est_parse_csr_attrs(outer, outer_len, &a) == WOLFCERT_OK);
    REQUIRE(a.count == 4);

    /* Recognised hints. */
    REQUIRE(a.require_challenge_password == 1);
    REQUIRE(a.require_extension_request  == 1);
    REQUIRE(a.preferred_hash             == 384);
    REQUIRE(a.preferred_key_type         == WOLFCERT_KEY_ECC);
    REQUIRE(a.preferred_ecc_curve_bits   == 384);

    /* Lookup. */
    const WolfCertCsrAttrItem* cp = wolfcert_csr_attrs_find(
        &a, OID_CHALLENGE_PASSWORD, sizeof(OID_CHALLENGE_PASSWORD));
    REQUIRE(cp != NULL);
    REQUIRE(cp->kind == WOLFCERT_CSRATTR_BARE_OID);

    const WolfCertCsrAttrItem* pk = wolfcert_csr_attrs_find(
        &a, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY));
    REQUIRE(pk != NULL);
    REQUIRE(pk->kind == WOLFCERT_CSRATTR_ATTRIBUTE);
    REQUIRE(pk->values_der != NULL);
    REQUIRE(pk->values_len > 0);

    /* An unknown OID must not be found. */
    static const uint8_t BOGUS[] = { 0x2A, 0x03, 0x04, 0x05 };
    REQUIRE(wolfcert_csr_attrs_find(&a, BOGUS, sizeof(BOGUS)) == NULL);

    wolfcert_csr_attrs_free(&a);

    /* ---- Malformed: outer tag is not SEQUENCE. */
    {
        uint8_t bad[] = { 0x31, 0x00 };
        WolfCertCsrAttrs b;
        REQUIRE(wolfcert_est_parse_csr_attrs(bad, sizeof(bad), &b)
                == WOLFCERT_ERR_PARSE);
    }

    /* ---- Malformed: truncated length byte. */
    {
        uint8_t bad[] = { 0x30, 0x82, 0x00 };  /* says 0x00?? but only one more */
        WolfCertCsrAttrs b;
        int rc = wolfcert_est_parse_csr_attrs(bad, sizeof(bad), &b);
        REQUIRE(rc == WOLFCERT_ERR_PARSE);
    }

    /* ---- Malformed: AttrOrOID tag we don't accept. */
    {
        uint8_t bad_body[] = { 0x04, 0x01, 0xAA };          /* OCTET STRING */
        uint8_t bad[8];
        size_t n = der_tlv(0x30, bad_body, sizeof(bad_body), bad);
        WolfCertCsrAttrs b;
        REQUIRE(wolfcert_est_parse_csr_attrs(bad, n, &b) == WOLFCERT_ERR_PARSE);
    }

    /* ---- Malformed: Attribute SEQUENCE missing the SET OF (RFC 2985
     *      says values is SIZE(1..MAX), so an OID-only Attribute is
     *      ill-formed and must be rejected; callers who want "this
     *      type must appear" should send a bare OID). */
    {
        uint8_t attr_only_oid[32];
        size_t al = der_tlv(0x06, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY),
                            attr_only_oid);
        uint8_t attr_seq[48];
        size_t tl = der_tlv(0x30, attr_only_oid, al, attr_seq);
        uint8_t outer_bad[64];
        size_t bl = der_tlv(0x30, attr_seq, tl, outer_bad);
        WolfCertCsrAttrs b;
        REQUIRE(wolfcert_est_parse_csr_attrs(outer_bad, bl, &b)
                == WOLFCERT_ERR_PARSE);
    }

    /* ---- Builder validation: bare OID with zero length is rejected. */
    {
        WolfCertCsrAttrItem bad_item = {
            .kind = WOLFCERT_CSRATTR_BARE_OID, .oid = NULL, .oid_len = 0,
        };
        WolfCertBuffer out = { 0 };
        REQUIRE(wolfcert_csr_attrs_build(&bad_item, 1, &out)
                == WOLFCERT_ERR_BAD_ARG);
        REQUIRE(out.data == NULL);
    }
    /* Attribute without values is rejected by the builder too. */
    {
        WolfCertCsrAttrItem bad_item = {
            .kind = WOLFCERT_CSRATTR_ATTRIBUTE,
            .oid = OID_EC_PUBLIC_KEY, .oid_len = sizeof(OID_EC_PUBLIC_KEY),
            .values_der = NULL, .values_len = 0,
        };
        WolfCertBuffer out = { 0 };
        REQUIRE(wolfcert_csr_attrs_build(&bad_item, 1, &out)
                == WOLFCERT_ERR_BAD_ARG);
    }
    /* Builder with count=0 produces a valid empty CsrAttrs (outer
     * SEQUENCE wrapping zero items). Round-trips through the parser
     * to zero items. */
    {
        WolfCertBuffer out = { 0 };
        REQUIRE(wolfcert_csr_attrs_build(NULL, 0, &out) == WOLFCERT_OK);
        WolfCertCsrAttrs b;
        REQUIRE(wolfcert_est_parse_csr_attrs(out.data, out.len, &b)
                == WOLFCERT_OK);
        REQUIRE(b.count == 0);
        wolfcert_csr_attrs_free(&b);
        wolfcert_buffer_free(&out);
    }

    /* ---- New OID coverage: Ed25519, Ed448, ML-DSA all decode into a
     *      preferred_key_type hint. Each test uses a single bare-OID
     *      attr-or-oid so the parser's sigalg-classification branch
     *      (which handles the edwards / ML-DSA OIDs) is the one under
     *      test. */
    {
        static const uint8_t OID_ED25519[]   = { 0x2B, 0x65, 0x70 };
        static const uint8_t OID_ED448[]     = { 0x2B, 0x65, 0x71 };
        static const uint8_t OID_ML_DSA_44[] = {
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 };
        static const uint8_t OID_ML_DSA_65[] = {
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12 };
        static const uint8_t OID_ML_DSA_87[] = {
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13 };

        const struct {
            const uint8_t* oid;
            size_t         oid_len;
            int            expect_type;
        } cases[] = {
            {
                OID_ED25519,   sizeof(OID_ED25519),   WOLFCERT_KEY_ED25519
            }
            ,
            {
                OID_ED448,     sizeof(OID_ED448),     WOLFCERT_KEY_ED448
            }
            ,
            {
                OID_ML_DSA_44, sizeof(OID_ML_DSA_44), WOLFCERT_KEY_MLDSA44
            }
            ,
            {
                OID_ML_DSA_65, sizeof(OID_ML_DSA_65), WOLFCERT_KEY_MLDSA65
            }
            ,
            {
                OID_ML_DSA_87, sizeof(OID_ML_DSA_87), WOLFCERT_KEY_MLDSA87
            }
            ,
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint8_t body2[64];
            size_t  body2_len = der_tlv(0x06, cases[i].oid, cases[i].oid_len, body2);
            uint8_t outer2[80];
            size_t  outer2_len = der_tlv(0x30, body2, body2_len, outer2);
            WolfCertCsrAttrs a2;
            REQUIRE(wolfcert_est_parse_csr_attrs(outer2, outer2_len, &a2)
                    == WOLFCERT_OK);
            REQUIRE(a2.preferred_key_type == cases[i].expect_type);
            /* Ed25519 / Ed448 / ML-DSA use no separate hash. */
            REQUIRE(a2.preferred_hash == 0);
            wolfcert_csr_attrs_free(&a2);
        }
    }

    /* ---- wolfcert_csr_attrs_apply: overlay onto empty configs ------ */
    {
        /* Re-parse the hint-rich blob we built up top (ECC + P-384 +
         * SHA-384 + challengePassword required) and apply it. */
        WolfCertCsrAttrs a3;
        REQUIRE(wolfcert_est_parse_csr_attrs(outer, outer_len, &a3)
                == WOLFCERT_OK);

        WolfCertKeyCfg   kc = { 0 };
        WolfCertCertMeta mm = { 0 };
        REQUIRE(wolfcert_csr_attrs_apply(&a3, &kc, &mm) == WOLFCERT_OK);
        REQUIRE(kc.type   == WOLFCERT_KEY_ECC);
        REQUIRE(kc.param  == 384);
        REQUIRE(mm.preferred_hash == 384);

        wolfcert_csr_attrs_free(&a3);
    }

    /* ---- wolfcert_csr_attrs_apply: explicit caller values win ----- */
    {
        WolfCertCsrAttrs a4;
        REQUIRE(wolfcert_est_parse_csr_attrs(outer, outer_len, &a4)
                == WOLFCERT_OK);

        /* Caller already wants RSA-2048 and SHA-256; the server-pinned
         * ECC-P384 + SHA-384 must NOT overwrite it. */
        WolfCertKeyCfg kc = {
            .type = WOLFCERT_KEY_RSA, .param = 2048,
        };
        WolfCertCertMeta mm = { .preferred_hash = 256 };
        REQUIRE(wolfcert_csr_attrs_apply(&a4, &kc, &mm) == WOLFCERT_OK);
        REQUIRE(kc.type           == WOLFCERT_KEY_RSA);
        REQUIRE(kc.param          == 2048);
        REQUIRE(mm.preferred_hash == 256);

        wolfcert_csr_attrs_free(&a4);
    }

    /* ---- wolfcert_csr_attrs_apply: type-only hint gets a default size ----
     *
     * A server can pin a key type with no accompanying size/curve: RSA
     * never carries a modulus hint, and a bare signature-algorithm OID
     * (e.g. ecdsa-with-SHA384) arrives without an id-ecPublicKey curve.
     * _apply must still hand keygen a usable `param`, not leave it 0. */
#ifdef WOLFCERT_HAVE_RSA
    {
        WolfCertCsrAttrs stub = { 0 };
        stub.preferred_key_type = WOLFCERT_KEY_RSA;
        WolfCertKeyCfg kc = { 0 };
        REQUIRE(wolfcert_csr_attrs_apply(&stub, &kc, NULL) == WOLFCERT_OK);
        REQUIRE(kc.type  == WOLFCERT_KEY_RSA);
        REQUIRE(kc.param == 2048);
    }
#endif
#ifdef WOLFCERT_HAVE_ECC
    {
        WolfCertCsrAttrs stub = { 0 };
        stub.preferred_key_type     = WOLFCERT_KEY_ECC;
        stub.preferred_ecc_curve_bits = 0;
        WolfCertKeyCfg kc = { 0 };
        REQUIRE(wolfcert_csr_attrs_apply(&stub, &kc, NULL) == WOLFCERT_OK);
        REQUIRE(kc.type  == WOLFCERT_KEY_ECC);
        REQUIRE(kc.param == 256);
    }
#endif

    /* ---- wolfcert_csr_attrs_apply: both args NULL-able --------- */
    {
        WolfCertCsrAttrs a5 = { 0 };
        REQUIRE(wolfcert_csr_attrs_apply(&a5, NULL, NULL) == WOLFCERT_OK);
    }

    /* ---- wolfcert_csr_attrs_apply: NULL attrs is bad_arg ----- */
    {
        WolfCertKeyCfg kc = { 0 };
        REQUIRE(wolfcert_csr_attrs_apply(NULL, &kc, NULL)
                == WOLFCERT_ERR_BAD_ARG);
    }

    /* ---- wolfcert_csr_attrs_apply: build-time-gated key types ----
     *
     * _apply returns WOLFCERT_ERR_UNSUPPORTED when it's about to leave
     * `key_cfg->type` pointing at a key algorithm the current build
     * wasn't compiled for. The exact outcome for each algorithm is
     * conditional on the matching WOLFCERT_HAVE_* define, so the test
     * mirrors the same conditional: if the feature is compiled in,
     * _apply succeeds; if not, it refuses with UNSUPPORTED. That way
     * the guard is exercised regardless of which knobs the build
     * harness flipped on. */
    {
        const WolfCertKeyType gated_types[] = {
            WOLFCERT_KEY_ED25519,
            WOLFCERT_KEY_ED448,
            WOLFCERT_KEY_MLDSA44,
            WOLFCERT_KEY_MLDSA65,
            WOLFCERT_KEY_MLDSA87,
        };
        const int expected_ok[] = {
#ifdef WOLFCERT_HAVE_ED25519
            1,
#else
            0,
#endif
#ifdef WOLFCERT_HAVE_ED448
            1,
#else
            0,
#endif
#ifdef WOLFCERT_HAVE_MLDSA
            1, 1, 1,
#else
            0, 0, 0,
#endif
        };
        for (size_t i = 0; i < sizeof(gated_types)/sizeof(gated_types[0]); ++i) {
            WolfCertCsrAttrs stub = { 0 };
            stub.preferred_key_type = (int)gated_types[i];
            WolfCertKeyCfg kc = { 0 };
            int rc = wolfcert_csr_attrs_apply(&stub, &kc, NULL);
            if (expected_ok[i]) {
                REQUIRE(rc == WOLFCERT_OK);
                REQUIRE(kc.type == gated_types[i]);
            } else {
                REQUIRE(rc == WOLFCERT_ERR_UNSUPPORTED);
            }
        }
    }

    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
