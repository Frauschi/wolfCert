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
 * EST enrollment and re-enrollment with a private key on a PKCS#11 token,
 * such as wolfPKCS11. The key_id is the key's CKA_ID, given in hex.
 *
 * Usage:
 *   enroll_pkcs11 enroll   URL TRUST_PEM SUBJECT KEY_TYPE KEY_ID OUT_CERT
 *   enroll_pkcs11 reenroll URL TRUST_PEM KEY_TYPE KEY_ID CERT OUT_CERT
 *                          [NEW_KEY_ID]
 * KEY_TYPE is ecc:256, ecc:384, rsa:2048, mldsa:44, mldsa:65 or mldsa:87.
 * The token comes from PKCS11_MODULE (path of the PKCS#11 library),
 * PKCS11_TOKEN (token label) and PKCS11_PIN (user PIN). e.g.
 *   PKCS11_MODULE=/usr/local/lib/libwolfpkcs11.so PKCS11_TOKEN=wolfcert \
 *   PKCS11_PIN=1234 ./enroll_pkcs11 enroll \
 *       https://127.0.0.1:8443/.well-known/est ca.pem "CN=device-42" \
 *       ecc:256 01a2 dev.crt
 */

#define _POSIX_C_SOURCE 200809L

#include <wolfcert/wolfcert.h>
#ifndef WOLFCERT_HAVE_EST
#  error "examples/enroll_pkcs11.c needs wolfCert built with EST enabled"
#endif

#include <wolfssl/wolfcrypt/wc_pkcs11.h>
#if !defined(HAVE_PKCS11) || !defined(WOLF_PRIVATE_KEY_ID)
#  error "examples/enroll_pkcs11.c needs wolfSSL built with --enable-pkcs11"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PKCS11_DEVID 0x70313121

typedef struct {
    Pkcs11Dev   dev;
    Pkcs11Token token;
    int         dev_id;
} Pkcs11;

static uint8_t* read_whole(const char* path, size_t* out_len)
{
    FILE* f = fopen(path, "rb");
    if (!f)
        return NULL;

    long len = -1;
    if (fseek(f, 0, SEEK_END) == 0)
        len = ftell(f);
    if (len <= 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    uint8_t* b = (uint8_t*)malloc((size_t)len);
    if (!b || fread(b, 1, (size_t)len, f) != (size_t)len) {
        free(b);
        fclose(f);
        return NULL;
    }

    fclose(f);
    *out_len = (size_t)len;
    return b;
}

/* Writes through a synced temporary file, so a failure keeps the old file. */
static int write_whole(const char* path, const WolfCertBuffer* b)
{
    char tmp[4096];

    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
        return -1;
    remove(tmp);
    FILE* f = fopen(tmp, "wbx");
    if (!f)
        return -1;

    int ok = fwrite(b->data, 1, b->len, f) == b->len;
    ok = ok && fflush(f) == 0 && fsync(fileno(f)) == 0;
    ok = fclose(f) == 0 && ok;
    if (ok && rename(tmp, path) == 0)
        return 0;
    remove(tmp);
    return -1;
}

static const struct {
    const char*     name;
    WolfCertKeyType type;
    int             param;
} key_types[] = {
    { "ecc:256",  WOLFCERT_KEY_ECC,     256  },
    { "ecc:384",  WOLFCERT_KEY_ECC,     384  },
    { "rsa:2048", WOLFCERT_KEY_RSA,     2048 },
    { "mldsa:44", WOLFCERT_KEY_MLDSA44, 0    },
    { "mldsa:65", WOLFCERT_KEY_MLDSA65, 0    },
    { "mldsa:87", WOLFCERT_KEY_MLDSA87, 0    },
};

static int parse_key_type(const char* s, WolfCertKeyCfg* cfg)
{
    for (size_t i = 0; i < sizeof(key_types) / sizeof(key_types[0]); i++) {
        if (strcmp(s, key_types[i].name) == 0) {
            cfg->type  = key_types[i].type;
            cfg->param = key_types[i].param;
            return 0;
        }
    }
    fprintf(stderr, "unknown KEY_TYPE %s\n", s);
    return -1;
}

static int hex_val(char c)
{
    return (c >= '0' && c <= '9') ? c - '0'
         : (c >= 'a' && c <= 'f') ? c - 'a' + 10
         : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
}

static int parse_id(const char* s, uint8_t* id, size_t* id_len)
{
    size_t n = strlen(s);

    if (n == 0 || n % 2 != 0 || n / 2 > WOLFCERT_KEY_ID_MAX_LEN) {
        fprintf(stderr, "KEY_ID %s is not 1 to %d bytes of hex\n", s,
                WOLFCERT_KEY_ID_MAX_LEN);
        return -1;
    }
    for (size_t i = 0; i < n; i += 2) {
        int hi = hex_val(s[i]);
        int lo = hex_val(s[i + 1]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "KEY_ID %s is not hex\n", s);
            return -1;
        }
        id[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    *id_len = n / 2;
    return 0;
}

static int pkcs11_key_type(WolfCertKeyType type)
{
    switch (type) {
        case WOLFCERT_KEY_ECC:     return PKCS11_KEY_TYPE_EC;
        case WOLFCERT_KEY_RSA:     return PKCS11_KEY_TYPE_RSA;
        case WOLFCERT_KEY_MLDSA44:
        case WOLFCERT_KEY_MLDSA65:
        case WOLFCERT_KEY_MLDSA87: return PKCS11_KEY_TYPE_MLDSA;
        default:                   return -1;
    }
}

static void pkcs11_close(Pkcs11* p)
{
    if (p->dev_id != INVALID_DEVID)
        wc_CryptoCb_UnRegisterDevice(p->dev_id);
    wc_Pkcs11Token_Final(&p->token);
    wc_Pkcs11_Finalize(&p->dev);
}

static int pkcs11_open(Pkcs11* p)
{
    const char* module = getenv("PKCS11_MODULE");
    const char* label  = getenv("PKCS11_TOKEN");
    const char* pin    = getenv("PKCS11_PIN");

    char padded[32];

    memset(p, 0, sizeof(*p));
    p->dev_id = INVALID_DEVID;
    if (module == NULL || label == NULL || pin == NULL) {
        fprintf(stderr, "set PKCS11_MODULE, PKCS11_TOKEN and PKCS11_PIN\n");
        return -1;
    }
    if (strlen(label) > sizeof(padded)) {
        fprintf(stderr, "PKCS11_TOKEN is longer than 32 bytes\n");
        return -1;
    }
    /* Token labels are blank padded, so a shorter name would match a prefix. */
    memset(padded, ' ', sizeof(padded));
    memcpy(padded, label, strlen(label));

    int rc = wc_Pkcs11_Initialize(&p->dev, module, NULL);
    if (rc != 0) {
        fprintf(stderr, "cannot load PKCS#11 library %s (%d)\n", module, rc);
        return rc;
    }
    rc = wc_Pkcs11Token_InitName(&p->token, &p->dev, padded,
                                 (int)sizeof(padded), (const byte*)pin,
                                 (int)strlen(pin));
    /* Generated keys are session objects, so the session must stay open. */
    if (rc == 0)
        rc = wc_Pkcs11Token_Open(&p->token, 1);
    if (rc == 0) {
        rc = wc_CryptoCb_RegisterDevice(PKCS11_DEVID, wc_Pkcs11_CryptoDevCb,
                                        &p->token);
    }
    if (rc == 0) {
        p->dev_id = PKCS11_DEVID;
    }
    else {
        fprintf(stderr, "cannot open PKCS#11 token %s (%d)\n", label, rc);
        pkcs11_close(p);
    }
    return rc;
}

/* Counts the persistent objects of a class with this CKA_ID, up to 1 */
static CK_RV count_id(Pkcs11* p, CK_OBJECT_CLASS cls, const uint8_t* id,
                      size_t id_len, CK_ULONG* count)
{
    CK_BBOOL on_token = CK_TRUE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls,                       sizeof(cls)      },
        { CKA_TOKEN, &on_token,                  sizeof(on_token) },
        { CKA_ID,    (CK_VOID_PTR)(uintptr_t)id, (CK_ULONG)id_len },
    };
    CK_FUNCTION_LIST* f = p->token.func;
    CK_OBJECT_HANDLE obj;

    *count = 0;
    CK_RV rv = f->C_FindObjectsInit(p->token.handle, tmpl, 3);
    if (rv != CKR_OK)
        return rv;
    rv = f->C_FindObjects(p->token.handle, &obj, 1, count);
    CK_RV final_rv = f->C_FindObjectsFinal(p->token.handle);
    return rv != CKR_OK ? rv : final_rv;
}

static int new_id_ok(Pkcs11* p, const uint8_t* id, size_t id_len)
{
    CK_ULONG priv = 0;
    CK_ULONG pub = 0;
    CK_RV rv = count_id(p, CKO_PRIVATE_KEY, id, id_len, &priv);

    if (rv == CKR_OK)
        rv = count_id(p, CKO_PUBLIC_KEY, id, id_len, &pub);
    if (rv != CKR_OK)
        fprintf(stderr, "cannot search the token (CK_RV 0x%lx)\n",
                (unsigned long)rv);
    else if (priv != 0 || pub != 0)
        fprintf(stderr, "the token already holds a key with that KEY_ID\n");
    return rv == CKR_OK && priv == 0 && pub == 0;
}

static int persist(Pkcs11* p, WolfCertKey* key)
{
    int rc = wc_Pkcs11PersistKey(&p->token,
                                 pkcs11_key_type(wolfcert_key_type(key)),
                                 wolfcert_key_wolfssl_key(key));
    if (rc != 0)
        fprintf(stderr, "cannot make the key persistent (%d)\n", rc);
    return rc;
}

static int delete_key(Pkcs11* p, WolfCertKey* key)
{
    int rc = wc_Pkcs11DeleteKey(&p->token,
                                pkcs11_key_type(wolfcert_key_type(key)),
                                wolfcert_key_wolfssl_key(key));
    if (rc != 0)
        fprintf(stderr, "cannot delete the key from the token (%d); remove it "
                "by hand\n", rc);
    return rc;
}

static void report(const char* what, int rc)
{
    const char* m = wolfcert_last_error_message();
    if (rc == WOLFCERT_ERR_PENDING) {
        fprintf(stderr, "%s: the CA holds the request for approval; this "
                "example cannot wait for it, and a new key does not outlive "
                "this run\n", what);
        return;
    }
    fprintf(stderr, "%s failed: %s%s%s\n", what, wolfcert_strerror(rc),
            m != NULL && *m != '\0' ? ": " : "", m != NULL ? m : "");
}

/* Shows a certificate that was issued but could not be kept. */
static void show_cert(const char* why, const WolfCertBuffer* cert)
{
    fprintf(stderr, "%s:\n", why);
    fwrite(cert->data, 1, cert->len, stderr);
}

/* URL TRUST_PEM SUBJECT KEY_TYPE KEY_ID OUT_CERT */
static int cmd_enroll(Pkcs11* p, const WolfCertServerCfg* srv, char** argv)
{
    WolfCertKeyCfg kcfg = { .dev_id = p->dev_id };
    WolfCertCertMeta meta = { .subject_dn = argv[2] };
    WolfCertClient* client = NULL;
    WolfCertKey* key = NULL;
    WolfCertBuffer cert = { 0 };
    uint8_t id[WOLFCERT_KEY_ID_MAX_LEN];
    size_t id_len = 0;

    if (parse_key_type(argv[3], &kcfg) != 0 ||
            parse_id(argv[4], id, &id_len) != 0)
        return 1;
    kcfg.key_id     = id;
    kcfg.key_id_len = id_len;
    if (!new_id_ok(p, id, id_len))
        return 1;

    int rc = wolfcert_client_new(&client);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_client_enroll(client, srv, &kcfg, &meta, &key, &cert);
    if (rc != WOLFCERT_OK) {
        report("enroll", rc);
    }
    else if (persist(p, key) != 0) {
        show_cert("revoke this certificate, its key is lost", &cert);
        rc = WOLFCERT_ERR_CRYPTO;
    }
    else if (write_whole(argv[5], &cert) != 0) {
        fprintf(stderr, "cannot write %s\n", argv[5]);
        if (delete_key(p, key) == 0)
            show_cert("revoke this certificate, its key is deleted", &cert);
        rc = WOLFCERT_ERR_IO;
    }
    else {
        printf("enrolled: key %s on the token, certificate in %s\n", argv[4],
               argv[5]);
    }

    wolfcert_buffer_free(&cert);
    wolfcert_key_free(key);
    wolfcert_client_free(client);
    return rc == WOLFCERT_OK ? 0 : 2;
}

/* URL TRUST_PEM KEY_TYPE KEY_ID CERT OUT_CERT [NEW_KEY_ID] */
static int cmd_reenroll(Pkcs11* p, const WolfCertServerCfg* srv, int argc,
                        char** argv)
{
    WolfCertKeyCfg cur_cfg = { .dev_id = p->dev_id };
    WolfCertKeyCfg new_cfg;
    WolfCertCertMeta meta = { 0 };
    WolfCertClient* client = NULL;
    WolfCertKey* cur_key = NULL;
    WolfCertKey* new_key = NULL;
    WolfCertBuffer renewed = { 0 };
    uint8_t id[WOLFCERT_KEY_ID_MAX_LEN];
    uint8_t new_id[WOLFCERT_KEY_ID_MAX_LEN];
    size_t id_len = 0;
    size_t new_id_len = 0;
    size_t cert_len = 0;
    uint8_t* cert = NULL;
    int rekey = argc > 6;

    if (parse_key_type(argv[2], &cur_cfg) != 0 ||
            parse_id(argv[3], id, &id_len) != 0 ||
            (rekey && parse_id(argv[6], new_id, &new_id_len) != 0))
        return 1;
    if (rekey && !new_id_ok(p, new_id, new_id_len))
        return 1;
    cur_cfg.key_id     = id;
    cur_cfg.key_id_len = id_len;
    new_cfg            = cur_cfg;
    new_cfg.key_id     = new_id;
    new_cfg.key_id_len = new_id_len;

    cert = read_whole(argv[4], &cert_len);
    if (cert == NULL) {
        fprintf(stderr, "cannot read %s\n", argv[4]);
        return 1;
    }

    /* The certificate supplies the public half of the token key. */
    int rc = wolfcert_key_from_id(&cur_cfg, cert, cert_len, &cur_key);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_client_new(&client);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_client_reenroll(client, srv, cert, cert_len, cur_key,
                                      rekey ? &new_cfg : NULL, &meta,
                                      &new_key, &renewed);
    if (rc != WOLFCERT_OK) {
        report("reenroll", rc);
    }
    else if (rekey && persist(p, new_key) != 0) {
        show_cert("revoke this certificate, its key is lost", &renewed);
        rc = WOLFCERT_ERR_CRYPTO;
    }
    else if (write_whole(argv[5], &renewed) != 0) {
        fprintf(stderr, "cannot write %s\n", argv[5]);
        if (!rekey)
            show_cert("the renewed certificate", &renewed);
        else if (delete_key(p, new_key) == 0)
            show_cert("revoke this certificate, its key is deleted", &renewed);
        rc = WOLFCERT_ERR_IO;
    }
    else if (rekey) {
        printf("re-enrolled: new key %s on the token, certificate in %s\n",
               argv[6], argv[5]);
        if (delete_key(p, cur_key) == 0)
            printf("old key %s deleted\n", argv[3]);
    }
    else {
        printf("re-enrolled: key %s on the token, certificate in %s\n",
               argv[3], argv[5]);
    }

    wolfcert_buffer_free(&renewed);
    wolfcert_key_free(new_key);
    wolfcert_key_free(cur_key);
    wolfcert_client_free(client);
    free(cert);
    return rc == WOLFCERT_OK ? 0 : 2;
}

int main(int argc, char** argv)
{
    int enroll   = argc == 8 && strcmp(argv[1], "enroll") == 0;
    int reenroll = (argc == 8 || argc == 9) && strcmp(argv[1], "reenroll") == 0;

    if (!enroll && !reenroll) {
        fprintf(stderr,
            "usage: %s enroll   URL TRUST_PEM SUBJECT KEY_TYPE KEY_ID OUT_CERT\n"
            "       %s reenroll URL TRUST_PEM KEY_TYPE KEY_ID CERT OUT_CERT "
            "[NEW_KEY_ID]\n"
            "KEY_TYPE: ecc:256, ecc:384, rsa:2048, mldsa:44, mldsa:65, "
            "mldsa:87\n"
            "KEY_ID: CKA_ID in hex; the token comes from PKCS11_MODULE, "
            "PKCS11_TOKEN and PKCS11_PIN\n", argv[0], argv[0]);
        return 1;
    }

    size_t trust_len = 0;
    uint8_t* trust = read_whole(argv[3], &trust_len);
    if (trust == NULL) {
        fprintf(stderr, "cannot read %s\n", argv[3]);
        return 1;
    }

    WolfCertServerCfg srv = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = argv[2],
        .trust_anchors     = trust,
        .trust_anchors_len = trust_len,
        .verify_server     = 1,
    };
    Pkcs11 p11;
    int ret = 1;

    if (wolfcert_init(NULL) == WOLFCERT_OK && pkcs11_open(&p11) == 0) {
        ret = enroll ? cmd_enroll(&p11, &srv, argv + 2)
                     : cmd_reenroll(&p11, &srv, argc - 2, argv + 2);
        pkcs11_close(&p11);
    }

    wolfcert_cleanup();
    free(trust);
    return ret;
}
