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
 * Structured decode of RFC 7030 section 4.5.2 CsrAttrs.
 *
 *   CsrAttrs  ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID
 *   AttrOrOID ::= CHOICE { oid OBJECT IDENTIFIER, attribute Attribute }
 *   Attribute ::= SEQUENCE { type OID, values SET OF AttributeValue }
 *
 * The parser walks the top-level SEQUENCE, splits each AttrOrOID by
 * tag (0x06 = OBJECT IDENTIFIER, 0x30 = SEQUENCE / Attribute), and
 * populates a caller-visible list of items plus a handful of
 * well-known-OID hint fields for the attributes wolfCert knows how to
 * act on (challenge password, extension request, pinned signature
 * algorithm, pinned key algorithm / curve). Everything else is left
 * for the caller to inspect via the `items` array.
 */

#define _POSIX_C_SOURCE 200809L

#include <wolfcert/est.h>
#include <wolfcert/errors.h>
#include <wolfcert/types.h>
#include "../internal.h"

#include <wolfssl/wolfcrypt/asn.h>

#include <string.h>

/* ---- minimal DER parsing helpers --------------------------------------- */

static int der_take_tl(const uint8_t* p, size_t avail,
                       uint8_t* out_tag, size_t* out_len, size_t* out_hdr)
{
    if (avail < 2)
        return WOLFCERT_ERR_PARSE;

    *out_tag = p[0];
    size_t len;
    size_t hdr;

    if ((p[1] & 0x80) == 0) {
        len = p[1];
        hdr = 2;
    }
    else {
        size_t n = p[1] & 0x7F;
        if (n == 0 || n > 4 || 2 + n > avail)
            return WOLFCERT_ERR_PARSE;

        len = 0;
        for (size_t i = 0; i < n; ++i)
            len = (len << 8) | p[2 + i];

        hdr = 2 + n;
    }

    if (hdr + len > avail)
        return WOLFCERT_ERR_PARSE;

    *out_len = len;
    *out_hdr = hdr;

    return WOLFCERT_OK;
}

/* ---- well-known OID table --------------------------------------------- */

#define OID_(...)  { __VA_ARGS__ }
static const uint8_t OID_CHALLENGE_PASSWORD[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07
};
static const uint8_t OID_EXTENSION_REQUEST[]  = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E
};

/* RSA signature algorithm OIDs - 1.2.840.113549.1.1.{11,12,13}. */
static const uint8_t OID_SHA256_RSA[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B
};
static const uint8_t OID_SHA384_RSA[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C
};
static const uint8_t OID_SHA512_RSA[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D
};

/* ECDSA signature algorithm OIDs - 1.2.840.10045.4.3.{2,3,4}. */
static const uint8_t OID_ECDSA_SHA256[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02
};
static const uint8_t OID_ECDSA_SHA384[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03
};
static const uint8_t OID_ECDSA_SHA512[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04
};

/* Public key algorithm OIDs. */
static const uint8_t OID_RSA_ENCRYPTION[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
};
static const uint8_t OID_EC_PUBLIC_KEY[]  = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
};

/* Named curves, body of the OID. */
static const uint8_t OID_SECP256R1[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t OID_SECP384R1[] = { 0x2B, 0x81, 0x04, 0x00, 0x22 };
static const uint8_t OID_SECP521R1[] = { 0x2B, 0x81, 0x04, 0x00, 0x23 };

/* Ed25519 / Ed448 are covered by a single OID that identifies both the
 * key algorithm and the signature algorithm (RFC 8410). No separate
 * hash - Ed25519 uses SHA-512 internally, Ed448 uses SHAKE256. */
static const uint8_t OID_ED25519[] = { 0x2B, 0x65, 0x70 };
static const uint8_t OID_ED448[]   = { 0x2B, 0x65, 0x71 };

/* FIPS 204 ML-DSA NIST OIDs (2.16.840.1.101.3.4.3.{17,18,19}).
 * Like Ed25519/Ed448 the OID doubles as key and signature algorithm. */
static const uint8_t OID_ML_DSA_44[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11
};
static const uint8_t OID_ML_DSA_65[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12
};
static const uint8_t OID_ML_DSA_87[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13
};

static int oid_eq(const uint8_t* a, size_t al,
                  const uint8_t* b, size_t bl)
{
    return al == bl && memcmp(a, b, al) == 0;
}

/* Apply a hint for a signature-algorithm OID (or a combined key+sig OID
 * for the edwards / ML-DSA families, where one OID identifies both). */
static void apply_sigalg(WolfCertCsrAttrs* out, const uint8_t* oid, size_t oid_len)
{
    if (oid_eq(oid, oid_len, OID_SHA256_RSA, sizeof(OID_SHA256_RSA))) {
        out->preferred_hash = 256;
        out->preferred_key_type = WOLFCERT_KEY_RSA;
    }
    else if (oid_eq(oid, oid_len, OID_SHA384_RSA, sizeof(OID_SHA384_RSA))) {
        out->preferred_hash = 384;
        out->preferred_key_type = WOLFCERT_KEY_RSA;
    }
    else if (oid_eq(oid, oid_len, OID_SHA512_RSA, sizeof(OID_SHA512_RSA))) {
        out->preferred_hash = 512;
        out->preferred_key_type = WOLFCERT_KEY_RSA;
    }
    else if (oid_eq(oid, oid_len, OID_ECDSA_SHA256, sizeof(OID_ECDSA_SHA256))) {
        out->preferred_hash = 256;
        out->preferred_key_type = WOLFCERT_KEY_ECC;
    }
    else if (oid_eq(oid, oid_len, OID_ECDSA_SHA384, sizeof(OID_ECDSA_SHA384))) {
        out->preferred_hash = 384;
        out->preferred_key_type = WOLFCERT_KEY_ECC;
    }
    else if (oid_eq(oid, oid_len, OID_ECDSA_SHA512, sizeof(OID_ECDSA_SHA512))) {
        out->preferred_hash = 512;
        out->preferred_key_type = WOLFCERT_KEY_ECC;
    }
    else if (oid_eq(oid, oid_len, OID_ED25519, sizeof(OID_ED25519))) {
        out->preferred_key_type = WOLFCERT_KEY_ED25519;
    }
    else if (oid_eq(oid, oid_len, OID_ED448, sizeof(OID_ED448))) {
        out->preferred_key_type = WOLFCERT_KEY_ED448;
    }
    else if (oid_eq(oid, oid_len, OID_ML_DSA_44, sizeof(OID_ML_DSA_44))) {
        out->preferred_key_type = WOLFCERT_KEY_MLDSA44;
    }
    else if (oid_eq(oid, oid_len, OID_ML_DSA_65, sizeof(OID_ML_DSA_65))) {
        out->preferred_key_type = WOLFCERT_KEY_MLDSA65;
    }
    else if (oid_eq(oid, oid_len, OID_ML_DSA_87, sizeof(OID_ML_DSA_87))) {
        out->preferred_key_type = WOLFCERT_KEY_MLDSA87;
    }
}

/* Walk the SET OF AttributeValue of an attribute whose type OID is a
 * public-key algorithm (rsaEncryption / id-ecPublicKey) and pull out
 * the hints. For rsaEncryption the pinned modulus size isn't typically
 * carried in the SET - leave preferred_rsa_bits at 0. For id-ecPublicKey
 * the values carry the named-curve OID. */
static void apply_pubkey_values(WolfCertCsrAttrs* out, int key_type,
                                const uint8_t* vals, size_t vals_len)
{
    out->preferred_key_type = key_type;
    if (key_type != WOLFCERT_KEY_ECC || vals == NULL || vals_len == 0)
        return;

    /* First value inside the SET. */
    uint8_t tag;
    size_t len, hdr;
    if (der_take_tl(vals, vals_len, &tag, &len, &hdr) != WOLFCERT_OK)
        return;

    if (tag != 0x06 /* OID */)
        return;

    const uint8_t* oid = vals + hdr;

    if (oid_eq(oid, len, OID_SECP256R1, sizeof(OID_SECP256R1))) {
        out->preferred_ecc_curve_bits = 256;
    }
    else if (oid_eq(oid, len, OID_SECP384R1, sizeof(OID_SECP384R1))) {
        out->preferred_ecc_curve_bits = 384;
    }
    else if (oid_eq(oid, len, OID_SECP521R1, sizeof(OID_SECP521R1))) {
        out->preferred_ecc_curve_bits = 521;
    }
}

static void classify(WolfCertCsrAttrs* out, const WolfCertCsrAttrItem* it)
{
    if (oid_eq(it->oid, it->oid_len,
               OID_CHALLENGE_PASSWORD, sizeof(OID_CHALLENGE_PASSWORD))) {
        out->require_challenge_password = 1;
    }
    else if (oid_eq(it->oid, it->oid_len,
                    OID_EXTENSION_REQUEST, sizeof(OID_EXTENSION_REQUEST))) {
        out->require_extension_request = 1;
    }
    else if (oid_eq(it->oid, it->oid_len,
                    OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION))) {
        apply_pubkey_values(out, WOLFCERT_KEY_RSA,
                            it->values_der, it->values_len);
    }
    else if (oid_eq(it->oid, it->oid_len,
                    OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY))) {
        apply_pubkey_values(out, WOLFCERT_KEY_ECC,
                            it->values_der, it->values_len);
    }
    else {
        /* Might be a sigalg OID (bare or as Attribute type). */
        apply_sigalg(out, it->oid, it->oid_len);
    }
}

/* ---- public API --------------------------------------------------------- */

int wolfcert_est_parse_csr_attrs(const uint8_t* der, size_t der_len,
                                 WolfCertCsrAttrs* out)
{
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    memset(out, 0, sizeof(*out));
    void* heap = wolfcert_default_heap();
    out->heap = heap;

    if (der == NULL || der_len == 0)
        return WOLFCERT_OK; /* empty attrs */

    /* Copy the source bytes so items can hold stable pointers. */
    uint8_t* copy = (uint8_t*)WOLFCERT_XMALLOC(der_len, heap);
    if (copy == NULL)
        return WOLFCERT_ERR_MEMORY;

    memcpy(copy, der, der_len);
    out->_backing     = copy;
    out->_backing_len = der_len;

    uint8_t tag;
    size_t len, hdr;
    int rc = der_take_tl(copy, der_len, &tag, &len, &hdr);
    if (rc != WOLFCERT_OK)
        goto fail;

    if (tag != 0x30) {
        rc = WOLFCERT_ERR_PARSE;
        goto fail;
    }

    if (hdr + len > der_len) {
        rc = WOLFCERT_ERR_PARSE;
        goto fail;
    }

    const uint8_t* p   = copy + hdr;
    const uint8_t* end = p + len;

    /* First pass: count items. */
    size_t n = 0;
    const uint8_t* scan = p;
    while (scan < end) {
        uint8_t t;
        size_t l, h;
        rc = der_take_tl(scan, (size_t)(end - scan), &t, &l, &h);
        if (rc != WOLFCERT_OK)
            goto fail;

        if (t != 0x06 && t != 0x30) {
            rc = WOLFCERT_ERR_PARSE;
            goto fail;
        }

        n++;
        scan += h + l;
    }

    if (scan != end) {
        rc = WOLFCERT_ERR_PARSE;
        goto fail;
    }

    if (n > 0) {
        out->items = (WolfCertCsrAttrItem*)WOLFCERT_XMALLOC(
                            sizeof(WolfCertCsrAttrItem) * n, heap);
        if (out->items == NULL) {
            rc = WOLFCERT_ERR_MEMORY;
            goto fail;
        }

        memset(out->items, 0, sizeof(WolfCertCsrAttrItem) * n);
    }

    /* Second pass: fill items + classify. */
    size_t idx = 0;
    while (p < end) {
        uint8_t t;
        size_t l, h;
        rc = der_take_tl(p, (size_t)(end - p), &t, &l, &h);
        if (rc != WOLFCERT_OK)
            goto fail;

        WolfCertCsrAttrItem* it = &out->items[idx++];
        if (t == 0x06) {
            it->kind    = WOLFCERT_CSRATTR_BARE_OID;
            it->oid     = p + h;
            it->oid_len = l;
        }
        else {
            /* 0x30 - Attribute SEQUENCE { OID, SET OF AttributeValue } */
            const uint8_t* inner = p + h;
            size_t         inner_len = l;

            uint8_t ot;
            size_t olen, ohdr;
            rc = der_take_tl(inner, inner_len, &ot, &olen, &ohdr);
            if (rc != WOLFCERT_OK)
                goto fail;

            if (ot != 0x06) {
                rc = WOLFCERT_ERR_PARSE;
                goto fail;
            }

            it->oid     = inner + ohdr;
            it->oid_len = olen;
            it->kind    = WOLFCERT_CSRATTR_ATTRIBUTE;

            /* RFC 2985: the `values SET OF AttributeValue` is mandatory
             * (SIZE(1..MAX)). An Attribute SEQUENCE that stops after
             * the type OID is malformed; reject it rather than silently
             * returning values_len=0. Callers who want "this attribute
             * type must appear" with no fixed value should send a
             * bare-OID AttrOrOID instead. */
            const uint8_t* after_oid = inner + ohdr + olen;
            size_t         remaining = inner_len - (ohdr + olen);
            if (remaining == 0) {
                rc = WOLFCERT_ERR_PARSE;
                goto fail;
            }

            uint8_t st;
            size_t slen, shdr;
            rc = der_take_tl(after_oid, remaining, &st, &slen, &shdr);
            if (rc != WOLFCERT_OK)
                goto fail;

            if (st != 0x31 || slen == 0) {
                rc = WOLFCERT_ERR_PARSE;
                goto fail;
            }

            it->values_der = after_oid + shdr;
            it->values_len = slen;
        }

        classify(out, it);
        p += h + l;
    }

    out->count = idx;
    return WOLFCERT_OK;

fail:
    wolfcert_csr_attrs_free(out);
    return rc;
}

void wolfcert_csr_attrs_free(WolfCertCsrAttrs* a)
{
    if (a == NULL)
        return;

    WOLFCERT_XFREE(a->items,    a->heap);
    WOLFCERT_XFREE(a->_backing, a->heap);
    memset(a, 0, sizeof(*a));
}

const WolfCertCsrAttrItem*
wolfcert_csr_attrs_find(const WolfCertCsrAttrs* a,
                        const uint8_t* oid, size_t oid_len)
{
    if (a == NULL || oid == NULL)
        return NULL;

    for (size_t i = 0; i < a->count; ++i) {
        if (a->items[i].oid_len == oid_len &&
                memcmp(a->items[i].oid, oid, oid_len) == 0) {
            return &a->items[i];
        }
    }

    return NULL;
}

/* ---- builder ----------------------------------------------------------- *
 * DER length headers are encoded with wolfSSL's public SetLength() (called
 * with a NULL buffer it just returns the header size). The single-byte tags
 * use wolfSSL's public ASN tag constants; they are written inline because the
 * matching SetSet / SetOctetString helpers are not part of the public API. */

/* Size of one AttrOrOID item on the wire. */
static size_t item_size(const WolfCertCsrAttrItem* it)
{
    if (it->kind == WOLFCERT_CSRATTR_BARE_OID) {
        /* OID TLV */
        return 1 + SetLength((word32)it->oid_len, NULL) + it->oid_len;
    }

    /* SEQUENCE { OID, SET OF values }. */
    size_t oid_tlv = 1 + SetLength((word32)it->oid_len, NULL) + it->oid_len;
    size_t set_tlv = 1 + SetLength((word32)it->values_len, NULL) + it->values_len;
    size_t body    = oid_tlv + set_tlv;

    return 1 + SetLength((word32)body, NULL) + body;
}

static size_t write_item(uint8_t* p, const WolfCertCsrAttrItem* it)
{
    if (it->kind == WOLFCERT_CSRATTR_BARE_OID) {
        uint8_t* q = p;
        *q++ = ASN_OBJECT_ID;
        q += SetLength((word32)it->oid_len, q);
        memcpy(q, it->oid, it->oid_len);
        q += it->oid_len;

        return (size_t)(q - p);
    }

    uint8_t* q = p;
    size_t oid_tlv = 1 + SetLength((word32)it->oid_len, NULL) + it->oid_len;
    size_t set_tlv = 1 + SetLength((word32)it->values_len, NULL) + it->values_len;
    size_t body    = oid_tlv + set_tlv;
    *q++ = ASN_SEQUENCE | ASN_CONSTRUCTED;
    q += SetLength((word32)body, q);

    /* type OID */
    *q++ = ASN_OBJECT_ID;
    q += SetLength((word32)it->oid_len, q);
    memcpy(q, it->oid, it->oid_len);
    q += it->oid_len;

    /* values SET OF */
    *q++ = ASN_SET | ASN_CONSTRUCTED;
    q += SetLength((word32)it->values_len, q);
    if (it->values_len > 0 && it->values_der != NULL) {
        memcpy(q, it->values_der, it->values_len);
    }
    q += it->values_len;

    return (size_t)(q - p);
}

int wolfcert_csr_attrs_build(const WolfCertCsrAttrItem* items, size_t count,
                             WolfCertBuffer* out_der)
{
    if (out_der == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (count > 0 && items == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    /* Every item must carry a non-empty OID; an Attribute (non-bare)
     * also needs at least one value, since RFC 2985's SET OF
     * AttributeValue has SIZE(1..MAX). Catching this here means the
     * builder can never emit DER the parser would reject. */
    for (size_t i = 0; i < count; ++i) {
        if (items[i].oid == NULL || items[i].oid_len == 0)
            return WOLFCERT_ERR_BAD_ARG;

        if (items[i].kind == WOLFCERT_CSRATTR_ATTRIBUTE &&
            (items[i].values_der == NULL || items[i].values_len == 0))
            return WOLFCERT_ERR_BAD_ARG;
    }
    void* heap = wolfcert_default_heap();

    size_t body = 0;
    for (size_t i = 0; i < count; ++i) {
        body += item_size(&items[i]);
    }
    size_t total = 1 + SetLength((word32)body, NULL) + body;

    uint8_t* buf = (uint8_t*)WOLFCERT_XMALLOC(total, heap);
    if (buf == NULL)
        return WOLFCERT_ERR_MEMORY;

    uint8_t* p = buf;
    *p++ = ASN_SEQUENCE | ASN_CONSTRUCTED;
    p += SetLength((word32)body, p);
    for (size_t i = 0; i < count; ++i) {
        p += write_item(p, &items[i]);
    }

    out_der->data = buf;
    out_der->len = total;
    out_der->heap = heap;

    return WOLFCERT_OK;
}

/* ---- _apply: overlay parsed hints onto caller's configs --------------- */

/* Translate an ECC curve size (in bits) into the `WolfCertKeyCfg.param`
 * our keygen expects. Returns 0 for unknown sizes. */
static int ecc_param_for_bits(int bits)
{
    switch (bits) {
        case 256:
            return 256;
        case 384:
            return 384;
        case 521:
            return 521;
        default:
            return 0;
    }
}

int wolfcert_csr_attrs_apply(const WolfCertCsrAttrs* attrs,
                             WolfCertKeyCfg* key_cfg,
                             WolfCertCertMeta* meta)
{
    if (attrs == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    /* Overlay the parsed hints onto the caller's `key_cfg` and `meta`,
     * but only where the caller didn't already set an explicit value.
     * Explicit caller values always win - this keeps the function safe
     * to call unconditionally on top of a partially-populated config. */

    if (key_cfg != NULL && key_cfg->type == 0 && attrs->preferred_key_type != 0) {
        key_cfg->type = (WolfCertKeyType)attrs->preferred_key_type;
        /* Pick up any algorithm-specific size / curve hint at the same
         * time - doing it here (rather than in a separate branch) keeps
         * the "caller-supplied type wins" rule intact. */
        if (key_cfg->param == 0) {
            if (attrs->preferred_key_type == WOLFCERT_KEY_RSA) {
                /* RSA hints never carry a modulus size, so fall back to
                 * a safe default rather than handing keygen a 0. */
                key_cfg->param = attrs->preferred_rsa_bits > 0 ?
                                    attrs->preferred_rsa_bits : 2048;
            }
            else if (attrs->preferred_key_type == WOLFCERT_KEY_ECC) {
                int ecc_param = ecc_param_for_bits(
                                    attrs->preferred_ecc_curve_bits);
                /* A bare sig-alg OID pins the curve to nothing usable;
                 * default to P-256 so keygen still has a curve. */
                key_cfg->param = ecc_param != 0 ? ecc_param : 256;
            }
            /* Ed25519 / Ed448 / ML-DSA 44/65/87: wolfCert's keygen
             * ignores `param` for these types, so leave it at 0. */
        }
    }

    if (meta != NULL) {
        /* Propagate the preferred signature hash into the richer CSR
         * metadata. `wolfcert_csr_build` honours meta->preferred_hash
         * only when set; 0 means "let choose_sig_type pick". */
        if (meta->preferred_hash == 0 && attrs->preferred_hash != 0) {
            meta->preferred_hash = attrs->preferred_hash;
        }

        /* require_challenge_password / require_extension_request are
         * informational on the client: the caller either populated
         * meta->challenge_password (or SANs / EKU / KU for extensionRequest)
         * or they didn't. We don't invent values here. */
    }

    /* Refuse to silently apply hints for a key type the current build
     * was compiled without - the caller will get a clearer error than
     * "WOLFCERT_ERR_UNSUPPORTED from keygen" later on. */
    if (key_cfg != NULL) {
        switch (key_cfg->type) {
#ifndef WOLFCERT_HAVE_ED25519
            case WOLFCERT_KEY_ED25519:
                return WOLFCERT_ERR_UNSUPPORTED;
#endif
#ifndef WOLFCERT_HAVE_ED448
            case WOLFCERT_KEY_ED448:
                return WOLFCERT_ERR_UNSUPPORTED;
#endif
#ifndef WOLFCERT_HAVE_MLDSA
            case WOLFCERT_KEY_MLDSA44:
            case WOLFCERT_KEY_MLDSA65:
            case WOLFCERT_KEY_MLDSA87:
                return WOLFCERT_ERR_UNSUPPORTED;
#endif
            default:
                break;
        }
    }

    return WOLFCERT_OK;
}
