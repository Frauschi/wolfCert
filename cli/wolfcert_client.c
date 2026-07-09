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
 * wolfcert-client - command-line enrollment client for wolfCert.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <wolfcert/wolfcert.h>
#ifdef WOLFCERT_HAVE_EST
#  include <wolfcert/est.h>
#endif
#ifdef WOLFCERT_HAVE_SCEP
#  include <wolfcert/scep.h>
#endif

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static uint8_t* read_whole(const char* path, size_t* out_len)
{
    FILE* f = fopen(path, "rb");
    if (!f)
        return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

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

static void print_usage(FILE* out)
{
    fprintf(out,
        "wolfcert-client %s\n"
        "Usage: wolfcert-client <command> [options]\n"
        "\n"
        "Commands:\n"
        "  getcacerts     Retrieve the CA chain and write it as PEM.\n"
        "  getnextca      SCEP GetNextCACert: fetch the roll-over CA (RFC 8894 section 4.6.1).\n"
        "  enroll         Generate a key + CSR and enroll a new certificate.\n"
        "  reenroll       Re-enroll an existing certificate (EST).\n"
        "\n"
        "Common options:\n"
        "  --proto est|scep           Enrollment protocol (required)\n"
        "  --url URL                  Server base URL (required)\n"
        "  --trust PEMFILE            Trust anchors for TLS; turns on server\n"
        "                             certificate verification. Required for EST\n"
        "                             (RFC 7030 mandates authenticating the server).\n"
        "  --user USER                HTTP Basic user (EST)\n"
        "  --pass PASS                HTTP Basic password (EST)\n"
        "  --challenge PASS           SCEP challengePassword (CSR attribute, RFC 8894 section 2.9)\n"
        "  --client-cert PEMFILE      Client certificate for mutual TLS\n"
        "  --client-key  PEMFILE      Private key for --client-cert\n"
        "  --pha                      Use TLS 1.3 post-handshake auth (EST only).\n"
        "                             Runs /cacerts and /simpleenroll on one keep-alive\n"
        "                             TLS connection; initial handshake is anonymous and\n"
        "                             the server requests the client cert mid-session.\n"
        "\n"
        "enroll options:\n"
        "  --key-type KT                   Key type (default ecc:256; SCEP needs rsa)\n"
        "                                  KT = rsa:BITS | ecc:CURVE | ed25519 |\n"
        "                                       ed448    | mldsa:44|65|87\n"
        "  --subject DN                    Subject DN\n"
        "  --san-dns NAME                  SAN dNSName (repeatable, EST)\n"
        "  --san-ip ADDR                   SAN iPAddress, IPv4 or IPv6 (repeatable, EST)\n"
        "  --san-uri URI                   SAN uniformResourceIdentifier (repeatable, EST)\n"
        "  --san-email ADDR                SAN rfc822Name (repeatable, EST)\n"
        "  --out-key FILE                  Write new private key (PEM)\n"
        "  --out-cert FILE                 Write issued certificate (PEM)\n"
        "  --poll-attempts N               Retry on PENDING up to N times (default 0). Applies\n"
        "                                  to SCEP GetCertInitial and to EST /simpleenroll /\n"
        "                                  /simplereenroll 202 Accepted (RFC 7030 section 4.2.3).\n"
        "  --poll-interval-ms N            Wait N ms between retries when the server did not\n"
        "                                  emit a Retry-After hint (default 2000). The server's\n"
        "                                  Retry-After delta-seconds takes precedence.\n"
        "  --csrattrs-auto                 EST only. Before key generation, GET\n"
        "                                  /.well-known/est/csrattrs, parse the response,\n"
        "                                  and apply the typed hints (preferred key\n"
        "                                  algorithm + curve / RSA bits, preferred\n"
        "                                  signature hash) onto the effective key\n"
        "                                  config + cert metadata. Explicit --key-type,\n"
        "                                  subject, etc. still win; /csrattrs only fills\n"
        "                                  fields the caller left at their defaults.\n"
        "\n"
        "reenroll options:\n"
        "  --cert FILE                     Current certificate (PEM)\n"
        "  --key  FILE                     Current private key (PEM)\n"
        "  plus the enroll options above to describe the renewed cert.\n",
        wolfcert_version_string());
}

typedef struct {
    const char*  proto;
    const char*  url;
    const char*  trust_file;
    const char*  user;
    const char*  pass;
    const char*  challenge;
    const char*  client_cert_file;
    const char*  client_key_file;
    const char*  key_type;
    const char*  subject;
    const char*  out_key;
    const char*  out_cert;
    const char*  cert_file;
    const char*  key_file;
    const char** san_dns;
    size_t       san_dns_len;
    const char** san_ip;
    size_t       san_ip_len;
    const char** san_uri;
    size_t       san_uri_len;
    const char** san_email;
    size_t       san_email_len;
    int          poll_attempts;
    int          poll_interval_ms;
    int          pha;
    int          csrattrs_auto;
} Opts;

/* Append a value to a growable string-pointer array (used for repeatable
 * --san-* options). cap tracks the current allocation. Returns -1 on OOM. */
static int opt_append(const char*** arr, size_t* len, size_t* cap,
                      const char* val)
{
    if (*len == *cap) {
        size_t ncap = *cap ? *cap * 2 : 4;
        const char** n = realloc(*arr, ncap * sizeof(char*));
        if (n == NULL)
            return -1;

        *arr = n;
        *cap = ncap;
    }

    (*arr)[(*len)++] = val;
    return 0;
}

static void opts_free(Opts* opts)
{
    free(opts->san_dns);
    free(opts->san_ip);
    free(opts->san_uri);
    free(opts->san_email);
}

static int parse_common(int argc, char** argv, Opts* opts)
{
    static const struct option long_opts[] = {
        { "proto",            required_argument, NULL, 'p' },
        { "url",              required_argument, NULL, 'u' },
        { "trust",            required_argument, NULL, 't' },
        { "user",             required_argument, NULL, 'U' },
        { "pass",             required_argument, NULL, 'P' },
        { "challenge",        required_argument, NULL, 'X' },
        { "client-cert",      required_argument, NULL, 'M' },
        { "client-key",       required_argument, NULL, 'N' },
        { "key-type",         required_argument, NULL, 'k' },
        { "subject",          required_argument, NULL, 's' },
        { "san-dns",          required_argument, NULL, 'd' },
        { "san-ip",           required_argument, NULL, 'i' },
        { "san-uri",          required_argument, NULL, 'r' },
        { "san-email",        required_argument, NULL, 'e' },
        { "out-key",          required_argument, NULL, 'K' },
        { "out-cert",         required_argument, NULL, 'C' },
        { "cert",             required_argument, NULL, 'c' },
        { "key",              required_argument, NULL, 'y' },
        { "poll-attempts",    required_argument, NULL, 'A' },
        { "poll-interval-ms", required_argument, NULL, 'I' },
        { "pha",              no_argument,       NULL, 'H' },
        { "csrattrs-auto",    no_argument,       NULL, 'Z' },
        { 0 }
    };
    memset(opts, 0, sizeof(*opts));

    /* Default key-type is deferred until enrolment so --csrattrs-auto
     * can let the server pin it via /csrattrs. When neither the flag
     * nor the server offer a hint, cmd_enroll falls back to ecc:256. */
    opts->key_type = NULL;
    opts->poll_interval_ms = 2000;
    size_t dns_cap = 0, ip_cap = 0, uri_cap = 0, email_cap = 0;
    int c;

    while ((c = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (c) {
            case 'p':
                opts->proto = optarg;
                break;
            case 'u':
                opts->url = optarg;
                break;
            case 't':
                opts->trust_file = optarg;
                break;
            case 'U':
                opts->user = optarg;
                break;
            case 'P':
                opts->pass = optarg;
                break;
            case 'X':
                opts->challenge = optarg;
                break;
            case 'M':
                opts->client_cert_file = optarg;
                break;
            case 'N':
                opts->client_key_file = optarg;
                break;
            case 'k':
                opts->key_type = optarg;
                break;
            case 's':
                opts->subject = optarg;
                break;
            case 'd':
                if (opt_append(&opts->san_dns, &opts->san_dns_len, &dns_cap,
                               optarg) != 0)
                    return -1;
                break;
            case 'i':
                if (opt_append(&opts->san_ip, &opts->san_ip_len, &ip_cap,
                               optarg) != 0)
                    return -1;
                break;
            case 'r':
                if (opt_append(&opts->san_uri, &opts->san_uri_len, &uri_cap,
                               optarg) != 0)
                    return -1;
                break;
            case 'e':
                if (opt_append(&opts->san_email, &opts->san_email_len, &email_cap,
                               optarg) != 0)
                    return -1;
                break;
            case 'K':
                opts->out_key = optarg;
                break;
            case 'C':
                opts->out_cert = optarg;
                break;
            case 'c':
                opts->cert_file = optarg;
                break;
            case 'y':
                opts->key_file = optarg;
                break;
            case 'A':
                opts->poll_attempts = atoi(optarg);
                break;
            case 'I':
                opts->poll_interval_ms = atoi(optarg);
                break;
            case 'H':
                opts->pha = 1;
                break;
            case 'Z':
                opts->csrattrs_auto = 1;
                break;
            default:
                return -1;
        }
    }

    if (opts->proto == NULL || opts->url == NULL) {
        fprintf(stderr, "wolfcert-client: --proto and --url are required\n");
        return -1;
    }

    return 0;
}

static int proto_of(const char* s, WolfCertProtocol* out)
{
#ifdef WOLFCERT_HAVE_EST
    if (strcmp(s, "est") == 0) {
        *out = WOLFCERT_PROTO_EST;
        return 0;
    }
#endif

#ifdef WOLFCERT_HAVE_SCEP
    if (strcmp(s, "scep") == 0) {
        *out = WOLFCERT_PROTO_SCEP;
        return 0;
    }
#endif

    fprintf(stderr, "wolfcert-client: unsupported --proto '%s' "
            "(this build was compiled without that protocol)\n", s);

    return -1;
}

static int write_file(const char* path, const uint8_t* data, size_t len,
                      int sensitive)
{
    FILE* f;
    size_t n;

    if (path == NULL) {
        fwrite(data, 1, len, stdout);
        return 0;
    }

    /* Private keys must never be left group/world readable on a shared host.
     * Create them owner-only and force the mode even when overwriting an
     * existing wider-permission file, matching the library filesystem store. */
    if (sensitive) {
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0)
            return -1;
        if (fchmod(fd, 0600) != 0) {
            close(fd);
            return -1;
        }
        f = fdopen(fd, "wb");
        if (f == NULL) {
            close(fd);
            return -1;
        }
    }
    else {
        f = fopen(path, "wb");
        if (f == NULL)
            return -1;
    }

    n = fwrite(data, 1, len, f);
    fclose(f);

    return n == len ? 0 : -1;
}

static int parse_key_type(const char* s, WolfCertKeyType* t, int* param)
{
    *param = 0;
    if (strncmp(s, "rsa:", 4) == 0) {
        *t = WOLFCERT_KEY_RSA;
        *param = atoi(s + 4);
        return 0;
    }

    if (strncmp(s, "ecc:", 4) == 0) {
        *t = WOLFCERT_KEY_ECC;
        const char* p = s + 4;
        *param = (strcmp(p, "p256") == 0 || strcmp(p, "256") == 0) ? 256
               : (strcmp(p, "p384") == 0 || strcmp(p, "384") == 0) ? 384
               : (strcmp(p, "p521") == 0 || strcmp(p, "521") == 0) ? 521 : 0;
        return *param ? 0 : -1;
    }

    if (strcmp(s, "ed25519") == 0) {
        *t = WOLFCERT_KEY_ED25519;
        return 0;
    }

    if (strcmp(s, "ed448")   == 0) {
        *t = WOLFCERT_KEY_ED448;
        return 0;
    }

    if (strncmp(s, "mldsa:", 6) == 0) {
        const char* lvl = s + 6;
        if (strcmp(lvl, "44") == 0) {
            *t = WOLFCERT_KEY_MLDSA44;
            return 0;
        }

        if (strcmp(lvl, "65") == 0) {
            *t = WOLFCERT_KEY_MLDSA65;
            return 0;
        }

        if (strcmp(lvl, "87") == 0) {
            *t = WOLFCERT_KEY_MLDSA87;
            return 0;
        }
    }

    return -1;
}

static void fill_trust(const Opts* opts, WolfCertServerCfg* cfg,
                       uint8_t** trust_hold)
{
    if (opts->trust_file == NULL)
        return;

    size_t tlen = 0;
    uint8_t* trust_buf = read_whole(opts->trust_file, &tlen);
    if (trust_buf == NULL)
        return;

    cfg->trust_anchors = trust_buf;
    cfg->trust_anchors_len = tlen;
    cfg->verify_server = 1;
    *trust_hold = trust_buf;
}

static int fill_client_ident(const Opts* opts, WolfCertServerCfg* cfg,
                             uint8_t** cert_hold, uint8_t** key_hold)
{
    if (opts->client_cert_file == NULL && opts->client_key_file == NULL)
        return 0;

    if (opts->client_cert_file == NULL || opts->client_key_file == NULL) {
        fprintf(stderr, "--client-cert and --client-key must be given together\n");
        return -1;
    }

    size_t cert_len = 0, key_len = 0;
    uint8_t* cert_buf = read_whole(opts->client_cert_file, &cert_len);
    uint8_t* key_buf = read_whole(opts->client_key_file,  &key_len);
    if (cert_buf == NULL || key_buf == NULL) {
        fprintf(stderr, "cannot read --client-cert / --client-key\n");
        free(cert_buf);
        free(key_buf);
        return -1;
    }

    cfg->client_cert = cert_buf;
    cfg->client_cert_len = cert_len;
    cfg->client_key  = key_buf;
    cfg->client_key_len  = key_len;
    *cert_hold = cert_buf;
    *key_hold = key_buf;

    return 0;
}

static int cmd_getcacerts(int argc, char** argv)
{
    Opts opts;
    if (parse_common(argc, argv, &opts) != 0) {
        opts_free(&opts);
        return 1;
    }

    WolfCertProtocol p;
    if (proto_of(opts.proto, &p) != 0) {
        opts_free(&opts);
        return 1;
    }

    uint8_t* trust_hold = NULL;
    uint8_t* mt_cert = NULL;
    uint8_t* mt_key = NULL;
    WolfCertServerCfg srv = { .protocol = p, .server_url = opts.url,
                              .username = opts.user, .password = opts.pass,
                              .connect_cb = wolfcert_posix_connect };

    fill_trust(&opts, &srv, &trust_hold);
    if (fill_client_ident(&opts, &srv, &mt_cert, &mt_key) != 0) {
        free(trust_hold);
        opts_free(&opts);
        return 1;
    }

    WolfCertBuffer pem = { 0 };
    int rc = WOLFCERT_ERR_UNSUPPORTED;

    if (p == WOLFCERT_PROTO_EST) {
#ifdef WOLFCERT_HAVE_EST
        rc = wolfcert_est_get_cacerts(&srv, &pem);
#endif
    }
    else {
#ifdef WOLFCERT_HAVE_SCEP
        rc = wolfcert_scep_get_ca_cert(&srv, &pem);
#endif
    }

    if (rc != WOLFCERT_OK) {
        fprintf(stderr, "getcacerts: %s\n", wolfcert_strerror(rc));
        free(trust_hold);
        free(mt_cert);
        free(mt_key);
        opts_free(&opts);
        return 2;
    }

    int wrc = write_file(opts.out_cert, pem.data, pem.len, 0);
    if (wrc != 0) {
        fprintf(stderr, "getcacerts: cannot write %s\n",
                opts.out_cert ? opts.out_cert : "<stdout>");
    }

    wolfcert_buffer_free(&pem);
    free(trust_hold);
    free(mt_cert);
    free(mt_key);
    opts_free(&opts);

    return wrc != 0 ? 2 : 0;
}

static int cmd_enroll(int argc, char** argv)
{
    Opts opts;
    if (parse_common(argc, argv, &opts) != 0) {
        opts_free(&opts);
        return 1;
    }

    WolfCertProtocol p;
    if (proto_of(opts.proto, &p) != 0) {
        opts_free(&opts);
        return 1;
    }

    if (opts.subject == NULL) {
        fprintf(stderr, "enroll: --subject required\n");
        opts_free(&opts);
        return 1;
    }

    /* Build the server cfg first - needed by --csrattrs-auto before we
     * pick a key type. The key cfg + meta are populated below, then
     * optionally overlaid with /csrattrs hints, then used to generate. */
    uint8_t* trust_hold = NULL;
    uint8_t* mt_cert = NULL;
    uint8_t* mt_key = NULL;
    WolfCertServerCfg srv = { .protocol = p, .server_url = opts.url,
                              .username = opts.user, .password = opts.pass,
                              .connect_cb = wolfcert_posix_connect };

    fill_trust(&opts, &srv, &trust_hold);
    if (fill_client_ident(&opts, &srv, &mt_cert, &mt_key) != 0) {
        free(trust_hold);
        opts_free(&opts);
        return 1;
    }

    WolfCertKeyCfg kcfg = { .dev_id = WOLFCERT_DEVID_SOFTWARE };
    if (opts.key_type != NULL) {
        WolfCertKeyType kt = 0;
        int kparam = 0;
        if (parse_key_type(opts.key_type, &kt, &kparam) != 0) {
            fprintf(stderr, "enroll: bad --key-type\n");
            free(trust_hold);
            free(mt_cert);
            free(mt_key);
            opts_free(&opts);
            return 1;
        }

        kcfg.type = kt;
        kcfg.param = kparam;
    }

    WolfCertCertMeta meta = { .subject_dn = opts.subject,
                              .san_dns = opts.san_dns, .san_dns_len = opts.san_dns_len,
                              .san_ip = opts.san_ip, .san_ip_len = opts.san_ip_len,
                              .san_uri = opts.san_uri, .san_uri_len = opts.san_uri_len,
                              .san_email = opts.san_email, .san_email_len = opts.san_email_len,
                              .challenge_password = opts.challenge };

    if (opts.csrattrs_auto && p == WOLFCERT_PROTO_EST) {
#ifdef WOLFCERT_HAVE_EST
        WolfCertBuffer raw = { 0 };
        int rc = wolfcert_est_get_csr_attrs(&srv, &raw);
        if (rc != WOLFCERT_OK) {
            fprintf(stderr, "csrattrs: %s\n", wolfcert_strerror(rc));
            free(trust_hold);
            free(mt_cert);
            free(mt_key);
            opts_free(&opts);
            return 2;
        }

        if (raw.data != NULL && raw.len > 0) {
            WolfCertCsrAttrs attrs;
            rc = wolfcert_est_parse_csr_attrs(raw.data, raw.len, &attrs);
            if (rc == WOLFCERT_OK)
                rc = wolfcert_csr_attrs_apply(&attrs, &kcfg, &meta);
            wolfcert_csr_attrs_free(&attrs);
        }

        wolfcert_buffer_free(&raw);
        if (rc != WOLFCERT_OK) {
            fprintf(stderr, "csrattrs: %s\n", wolfcert_strerror(rc));
            free(trust_hold);
            free(mt_cert);
            free(mt_key);
            opts_free(&opts);
            return 2;
        }
#endif
    }

    /* Fallback default when neither --key-type nor /csrattrs pinned one. */
    if (kcfg.type == 0) {
        WolfCertKeyType kt = 0;
        int kparam = 0;
        parse_key_type("ecc:256", &kt, &kparam);
        kcfg.type = kt;
        kcfg.param = kparam;
    }

    WolfCertKey* key = NULL;
    int rc = wolfcert_key_generate(&kcfg, &key);
    if (rc != WOLFCERT_OK) {
        fprintf(stderr, "keygen: %s\n", wolfcert_strerror(rc));
        free(trust_hold);
        free(mt_cert);
        free(mt_key);
        opts_free(&opts);
        return 2;
    }

    WolfCertBuffer csr = { 0 };
    rc = wolfcert_csr_build(key, &meta, &csr);
    if (rc != WOLFCERT_OK) {
        fprintf(stderr, "csr: %s\n", wolfcert_strerror(rc));
        wolfcert_key_free(key);
        free(trust_hold);
        free(mt_cert);
        free(mt_key);
        opts_free(&opts);
        return 2;
    }

    WolfCertBuffer issued = { 0 };
    rc = WOLFCERT_ERR_UNSUPPORTED;
    if (p == WOLFCERT_PROTO_EST) {
#ifdef WOLFCERT_HAVE_EST
        if (opts.pha) {
            /* Keep-alive + TLS 1.3 post-handshake auth: open one session,
             * fetch /cacerts anonymously, then let PHA drive /simpleenroll. */
            srv.allow_post_handshake_auth = 1;
            WolfCertEstSession* es = NULL;
            rc = wolfcert_est_session_open(&srv, &es);
            if (rc == WOLFCERT_OK) {
                WolfCertBuffer ca_pem = { 0 };
                rc = wolfcert_est_session_get_cacerts(es, &ca_pem);
                wolfcert_buffer_free(&ca_pem);
                if (rc == WOLFCERT_OK)
                    rc = wolfcert_est_session_simple_enroll(es, csr.data, csr.len, &issued);
                wolfcert_est_session_close(es);
            }
        }
        else {
            /* Richer-shape enroll so a 202 Accepted (RFC 7030 section 4.2.3)
             * becomes an explicit PENDING status the caller can poll. */
            WolfCertEstResult est_result = { 0 };
            rc = wolfcert_est_simple_enroll_ex(&srv, csr.data, csr.len, &est_result);
            int attempts = 0;
            while (rc == WOLFCERT_OK &&
                    est_result.status == WOLFCERT_EST_STATUS_PENDING &&
                    attempts < opts.poll_attempts) {
                long wait_ms = est_result.retry_after_sec > 0 ?
                                (long)est_result.retry_after_sec * 1000L :
                                opts.poll_interval_ms;

                struct timespec ts = {
                    .tv_sec  =  wait_ms / 1000,
                    .tv_nsec = (wait_ms % 1000) * 1000000L,
                };

                nanosleep(&ts, NULL);
                wolfcert_est_result_free(&est_result);
                rc = wolfcert_est_simple_enroll_ex(&srv, csr.data, csr.len, &est_result);
                attempts++;
            }

            if (rc == WOLFCERT_OK) {
                if (est_result.status == WOLFCERT_EST_STATUS_SUCCESS) {
                    issued = est_result.cert_pem;
                    est_result.cert_pem.data = NULL;
                    est_result.cert_pem.len = 0;
                }
                else if (est_result.status == WOLFCERT_EST_STATUS_PENDING) {
                    rc = WOLFCERT_ERR_PENDING;
                }
                else {
                    rc = WOLFCERT_ERR_PROTOCOL;
                }
            }

            wolfcert_est_result_free(&est_result);
        }
#endif
    }
    else {
#ifdef WOLFCERT_HAVE_SCEP
        WolfCertBuffer ca_pem = { 0 };
        rc = wolfcert_scep_get_ca_cert(&srv, &ca_pem);
        if (rc == WOLFCERT_OK) {
            DerBuffer* ca_der = NULL;
            if (wc_PemToDer(ca_pem.data, (long)ca_pem.len, CERT_TYPE,
                            &ca_der, NULL, NULL, NULL) == 0) {
                /* Envelope to the first CA cert, but trust the whole GetCACert
                 * bundle for the CertRep signer so a split CA/RA response is
                 * accepted. Fall back to the single cert if the bundle fetch
                 * fails. */
                WolfCertBuffer ca_bundle = { 0 };
                const uint8_t* bundle = ca_der->buffer;
                size_t bundle_len = ca_der->length;
                if (wolfcert_scep_get_ca_cert_enc(&srv, WOLFCERT_ENCODING_DER,
                                                  &ca_bundle) == WOLFCERT_OK) {
                    bundle = ca_bundle.data;
                    bundle_len = ca_bundle.len;
                }

                WolfCertScepCaps caps = { 0 };
                wolfcert_scep_get_ca_caps(&srv, &caps);
                WolfCertScepResult scep_result = { 0 };
                rc = wolfcert_scep_pkcs_req_ex(&srv, &caps,
                                               ca_der->buffer, ca_der->length,
                                               bundle, bundle_len,
                                               key, csr.data, csr.len, &scep_result);

                /* RFC 8894 section 3.3.2 polling: when the server returns
                 * PENDING, retry GetCertInitial up to poll_attempts
                 * times before giving up. The CLI surfaces a PENDING
                 * final response as a clear "still pending" error. */
                int attempts = 0;
                while (rc == WOLFCERT_OK &&
                        scep_result.status == WOLFCERT_SCEP_STATUS_PENDING &&
                        attempts < opts.poll_attempts) {
                    struct timespec ts = {
                        .tv_sec  =  opts.poll_interval_ms / 1000,
                        .tv_nsec = (opts.poll_interval_ms % 1000) * 1000000L,
                    };

                    nanosleep(&ts, NULL);
                    WolfCertScepResult poll_result = { 0 };
                    rc = wolfcert_scep_get_cert_initial(&srv, &caps,
                             ca_der->buffer, ca_der->length,
                             bundle, bundle_len,
                             NULL, 0, key, csr.data, csr.len,
                             scep_result.transaction_id, scep_result.transaction_id_len, &poll_result);

                    wolfcert_scep_result_free(&scep_result);
                    scep_result = poll_result;
                    attempts++;
                }

                if (rc == WOLFCERT_OK) {
                    if (scep_result.status == WOLFCERT_SCEP_STATUS_SUCCESS) {
                        issued = scep_result.cert_pem;
                        scep_result.cert_pem.data = NULL;
                        scep_result.cert_pem.len = 0;
                    }
                    else if (scep_result.status == WOLFCERT_SCEP_STATUS_PENDING) {
                        rc = WOLFCERT_ERR_PENDING;
                    }
                    else {
                        rc = WOLFCERT_ERR_PROTOCOL;
                    }
                }

                wolfcert_scep_result_free(&scep_result);
                wolfcert_buffer_free(&ca_bundle);
                wc_FreeDer(&ca_der);
            }
            else {
                rc = WOLFCERT_ERR_PARSE;
            }

            wolfcert_buffer_free(&ca_pem);
        }
#endif
    }

    if (rc != WOLFCERT_OK) {
        fprintf(stderr, "enroll: %s\n", wolfcert_strerror(rc));
        const char* m = wolfcert_last_error_message();
        if (m && *m) {
            fprintf(stderr, "enroll: detail (wolfssl_err=%d): %s\n",
                wolfcert_last_wolfssl_err(), m);
        }

        wolfcert_buffer_free(&csr);
        wolfcert_key_free(key);
        free(trust_hold);
        free(mt_cert);
        free(mt_key);
        opts_free(&opts);
        return 2;
    }

    int wrc = 0;
    if (opts.out_cert) {
        wrc = write_file(opts.out_cert, issued.data, issued.len, 0);
    }
    else {
        fwrite(issued.data, 1, issued.len, stdout);
    }

    if (wrc != 0) {
        fprintf(stderr, "enroll: cannot write %s\n", opts.out_cert);
    }

    if (opts.out_key) {
        WolfCertBuffer key_pem = { 0 };
        if (wolfcert_key_to_pem(key, &key_pem) == WOLFCERT_OK) {
            if (write_file(opts.out_key, key_pem.data, key_pem.len, 1) != 0) {
                fprintf(stderr, "enroll: cannot write %s\n", opts.out_key);
                wrc = -1;
            }
        }
        wolfcert_buffer_free(&key_pem);
    }

    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&issued);
    wolfcert_key_free(key);
    free(trust_hold);
    free(mt_cert);
    free(mt_key);
    opts_free(&opts);

    return wrc != 0 ? 2 : 0;
}

static int cmd_reenroll(int argc, char** argv)
{
    Opts opts;
    if (parse_common(argc, argv, &opts) != 0) {
        opts_free(&opts);
        return 1;
    }

    WolfCertProtocol p;
    if (proto_of(opts.proto, &p) != 0) {
        opts_free(&opts);
        return 1;
    }

    if (p != WOLFCERT_PROTO_EST) {
        fprintf(stderr, "reenroll: only EST is supported in the CLI today\n");
        opts_free(&opts);
        return 2;
    }

    if (opts.subject == NULL || opts.cert_file == NULL || opts.key_file == NULL) {
        fprintf(stderr, "reenroll: --subject, --cert, --key required\n");
        opts_free(&opts);
        return 1;
    }

    size_t cert_len = 0, key_len = 0;
    uint8_t* cert_pem = read_whole(opts.cert_file, &cert_len);
    uint8_t* key_pem  = read_whole(opts.key_file,  &key_len);
    if (cert_pem == NULL || key_pem == NULL) {
        fprintf(stderr, "reenroll: cannot read --cert/--key files\n");
        free(cert_pem);
        free(key_pem);
        opts_free(&opts);
        return 2;
    }

    WolfCertKey* current_key = NULL;
    if (wolfcert_key_from_pem(key_pem, key_len, NULL, &current_key) != WOLFCERT_OK) {
        fprintf(stderr, "reenroll: bad current key PEM\n");
        free(cert_pem);
        free(key_pem);
        opts_free(&opts);
        return 2;
    }

    WolfCertCertMeta meta = { .subject_dn = opts.subject,
                              .san_dns = opts.san_dns, .san_dns_len = opts.san_dns_len,
                              .san_ip = opts.san_ip, .san_ip_len = opts.san_ip_len,
                              .san_uri = opts.san_uri, .san_uri_len = opts.san_uri_len,
                              .san_email = opts.san_email, .san_email_len = opts.san_email_len,
                              .challenge_password = opts.challenge };
    WolfCertBuffer csr = { 0 };
    int rc = wolfcert_csr_build(current_key, &meta, &csr);

    if (rc != WOLFCERT_OK) {
        fprintf(stderr, "reenroll csr: %s\n", wolfcert_strerror(rc));
        wolfcert_key_free(current_key);
        free(cert_pem);
        free(key_pem);
        opts_free(&opts);
        return 2;
    }

    uint8_t* trust_hold = NULL;
    uint8_t* mt_cert = NULL;
    uint8_t* mt_key = NULL;
    WolfCertServerCfg srv = { .protocol = p, .server_url = opts.url,
                              .username = opts.user, .password = opts.pass,
                              .connect_cb = wolfcert_posix_connect };

    fill_trust(&opts, &srv, &trust_hold);
    if (fill_client_ident(&opts, &srv, &mt_cert, &mt_key) != 0) {
        wolfcert_buffer_free(&csr);
        wolfcert_key_free(current_key);
        free(cert_pem);
        free(key_pem);
        free(trust_hold);
        opts_free(&opts);
        return 1;
    }

    WolfCertBuffer issued = { 0 };
#ifdef WOLFCERT_HAVE_EST
    rc = wolfcert_est_simple_reenroll(&srv, cert_pem, cert_len, current_key,
                                      csr.data, csr.len, &issued);
#else
    rc = WOLFCERT_ERR_UNSUPPORTED;
#endif

    if (rc != WOLFCERT_OK) {
        fprintf(stderr, "reenroll: %s\n", wolfcert_strerror(rc));
        wolfcert_buffer_free(&csr);
        wolfcert_key_free(current_key);
        free(cert_pem);
        free(key_pem);
        free(trust_hold);
        free(mt_cert);
        free(mt_key);
        opts_free(&opts);
        return 2;
    }

    int wrc = 0;
    if (opts.out_cert) {
        wrc = write_file(opts.out_cert, issued.data, issued.len, 0);
    }
    else {
        fwrite(issued.data, 1, issued.len, stdout);
    }
    if (wrc != 0) {
        fprintf(stderr, "reenroll: cannot write %s\n", opts.out_cert);
    }

    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&issued);
    wolfcert_key_free(current_key);
    free(cert_pem);
    free(key_pem);
    free(trust_hold);
    free(mt_cert);
    free(mt_key);
    opts_free(&opts);

    return wrc != 0 ? 2 : 0;
}

static int cmd_getnextca(int argc, char** argv)
{
#ifndef WOLFCERT_HAVE_SCEP
    (void)argc;
    (void)argv;
    fprintf(stderr, "wolfcert-client: this build has no SCEP support\n");
    return 1;
#else
    Opts opts;
    if (parse_common(argc, argv, &opts) != 0) {
        opts_free(&opts);
        return 1;
    }

    WolfCertProtocol p;
    if (proto_of(opts.proto, &p) != 0) {
        opts_free(&opts);
        return 1;
    }

    if (p != WOLFCERT_PROTO_SCEP) {
        fprintf(stderr, "getnextca: only --proto scep is supported\n");
        opts_free(&opts);
        return 1;
    }

    uint8_t* trust_hold = NULL;
    uint8_t* mt_cert = NULL;
    uint8_t* mt_key = NULL;
    WolfCertServerCfg srv = { .protocol = p, .server_url = opts.url,
                              .username = opts.user, .password = opts.pass,
                              .connect_cb = wolfcert_posix_connect };

    fill_trust(&opts, &srv, &trust_hold);
    if (fill_client_ident(&opts, &srv, &mt_cert, &mt_key) != 0) {
        free(trust_hold);
        opts_free(&opts);
        return 1;
    }

    /* The roll-over message is signed by the current CA, which may be any cert
     * in the GetCACert bundle (some servers return the RA cert first). Fetch
     * the whole bundle in DER so verification matches the CA wherever it sits.
     *
     * Note: the standalone CLI holds no persistent trust state, so this
     * command fetches the current CA over the same (possibly plaintext)
     * transport it then authenticates against; an active MITM could supply a
     * consistent forged bundle and roll-over. An application integrating
     * wolfCert should pass a locally-trusted, out-of-band-verified CA to
     * wolfcert_scep_get_next_ca_cert instead. */
    WolfCertBuffer ca_bundle = { 0 };
    int rc = wolfcert_scep_get_ca_cert_enc(&srv, WOLFCERT_ENCODING_DER,
                                           &ca_bundle);
    if (rc != WOLFCERT_OK) {
        fprintf(stderr, "getnextca: %s\n", wolfcert_strerror(rc));
        free(trust_hold);
        free(mt_cert);
        free(mt_key);
        opts_free(&opts);
        return 2;
    }

    WolfCertBuffer pem = { 0 };
    rc = wolfcert_scep_get_next_ca_cert(&srv, ca_bundle.data, ca_bundle.len,
                                        &pem);
    wolfcert_buffer_free(&ca_bundle);
    if (rc != WOLFCERT_OK) {
        fprintf(stderr, "getnextca: %s\n", wolfcert_strerror(rc));
        free(trust_hold);
        free(mt_cert);
        free(mt_key);
        opts_free(&opts);
        return 2;
    }

    int wrc = write_file(opts.out_cert, pem.data, pem.len, 0);
    if (wrc != 0) {
        fprintf(stderr, "getnextca: cannot write %s\n",
                opts.out_cert ? opts.out_cert : "<stdout>");
    }

    wolfcert_buffer_free(&pem);
    free(trust_hold);
    free(mt_cert);
    free(mt_key);
    opts_free(&opts);

    return wrc != 0 ? 2 : 0;
#endif
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        print_usage(stderr);
        return 1;
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(stdout);
        return 0;
    }

    if (strcmp(argv[1], "--version") == 0) {
        printf("wolfcert-client %s\n", wolfcert_version_string());
        return 0;
    }

    if (wolfcert_init(NULL) != WOLFCERT_OK) {
        fprintf(stderr, "wolfcert_init failed\n");
        return 1;
    }

    int rc = 1;
    if (strcmp(argv[1], "getcacerts") == 0) {
        rc = cmd_getcacerts(argc - 1, argv + 1);
    }
    else if (strcmp(argv[1], "getnextca") == 0) {
        rc = cmd_getnextca(argc - 1, argv + 1);
    }
    else if (strcmp(argv[1], "enroll") == 0) {
        rc = cmd_enroll(argc - 1, argv + 1);
    }
    else if (strcmp(argv[1], "reenroll") == 0) {
        rc = cmd_reenroll(argc - 1, argv + 1);
    }
    else {
        fprintf(stderr, "wolfcert-client: unknown command '%s'\n\n", argv[1]);
        print_usage(stderr);
    }

    wolfcert_cleanup();
    return rc;
}
