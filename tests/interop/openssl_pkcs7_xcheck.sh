#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Cross-verify wolfCert's output against OpenSSL as an independent
# reference implementation. OpenSSL has no native SCEP/EST client, but its
# `x509`, `pkcs7`, `pkey`, `req` and `verify` commands independently parse
# and validate the PKCS#7 / X.509 / private-key artifacts wolfCert produces
# and consumes - a useful lower-bound conformance / interop sanity check.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib/common.sh"

need openssl        "Standard on most distros"

WC_SERVER="$(wolfcert_bin wolfcert-server)"
WC_CLIENT="$(wolfcert_bin wolfcert-client)"

cd "$WOLFCERT_INTEROP_WORK"
trap 'echo "--- work dir: $WOLFCERT_INTEROP_WORK"' EXIT

# ------------------------------------------------------------
# 0. EST mandates TLS (RFC 7030), so wolfcert-client refuses a plaintext
#    http:// URL. Stand wolfcert-server up behind TLS with a throwaway CA
#    and a server cert (SAN localhost / 127.0.0.1) that the client trusts
#    via --trust -- this drives wolfCert's real TLS transport, not a
#    curl-only shortcut. tls-* names keep these distinct from the EST CA
#    (ca.pem) fetched below.
# ------------------------------------------------------------

echo "[0] generating throwaway TLS CA + server certificate"
openssl req -x509 -newkey rsa:2048 -nodes -keyout tls-ca.key -out tls-ca.crt \
    -subj "/CN=wolfCert Interop Test CA" -days 2 \
    -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout tls-server.key -out tls-server.csr \
    -subj "/CN=localhost" >/dev/null 2>&1
openssl x509 -req -in tls-server.csr -CA tls-ca.crt -CAkey tls-ca.key \
    -CAcreateserial -out tls-server.crt -days 2 \
    -extfile <(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n') \
    >/dev/null 2>&1

# ------------------------------------------------------------
# 1. wolfcert-server's EST /cacerts response is a base64 PKCS#7
#    certs-only. Decode + verify OpenSSL can parse every cert and
#    cross-check its subject.
# ------------------------------------------------------------

echo "[1] EST /cacerts -> OpenSSL pkcs7 parse"
PORT=$(free_port)
"$WC_SERVER" --proto est --listen "127.0.0.1:$PORT" \
             --tls-cert tls-server.crt --tls-key tls-server.key \
             >wc-server.log 2>&1 &
WC_PID=$!
trap 'kill_if "$WC_PID"' EXIT
wait_port 127.0.0.1 "$PORT"

"$WC_CLIENT" getcacerts --proto est \
    --url "https://localhost:$PORT/.well-known/est" \
    --trust tls-ca.crt \
    --out-cert ca.pem >/dev/null
test -s ca.pem
# OpenSSL parses the PEM'd chain and prints each cert.
openssl x509 -in ca.pem -noout -subject \
    | grep -q "CN *= *wolfCert Test CA"
echo "    PASS  (OpenSSL parses wolfCert /cacerts output, CA subject matches)"

# ------------------------------------------------------------
# 2. Enroll one cert per supported key type and cross-check each against
#    OpenSSL: the issued cert parses + chains to the CA, and the private
#    key the client wrote out parses with its public half matching the
#    cert (proving the emitted key pair is internally consistent, not
#    merely well-formed ASN.1). Exercises wolfCert's per-algorithm key /
#    CSR / cert encoding against an independent implementation, not just ECC.
# ------------------------------------------------------------

# Classical + EdDSA key types OpenSSL has parsed since 1.1.1.
KEY_TYPES="rsa:2048 ecc:256 ecc:384 ecc:521 ed25519 ed448"
# ML-DSA (PQC) parsing needs OpenSSL >= 3.5. Probe for it and add the
# mldsa:* types only when supported, so the job stays green on older
# runners (ubuntu-24.04 ships OpenSSL 3.0) while an OpenSSL upgrade
# auto-enables the PQC cross-check with no change to this script.
if openssl list -signature-algorithms 2>/dev/null | grep -qi 'ml-dsa'; then
    KEY_TYPES="$KEY_TYPES mldsa:44 mldsa:65 mldsa:87"
else
    echo "[2] NOTE: OpenSSL lacks ML-DSA support -> skipping mldsa:* cross-check"
    echo "         (needs OpenSSL >= 3.5)"
fi

echo "[2] EST /simpleenroll across key types -> OpenSSL parse + verify"
kt_n=0
for kt in $KEY_TYPES; do
    kt_n=$((kt_n + 1))
    kt_cn="pkcs7-interop-$kt_n"
    "$WC_CLIENT" enroll --proto est \
        --url "https://localhost:$PORT/.well-known/est" \
        --trust tls-ca.crt \
        --key-type "$kt" --subject "CN=$kt_cn,O=wolfCert-interop" \
        --out-key "dev-$kt_n.key" --out-cert "dev-$kt_n.crt" >/dev/null
    openssl x509 -in "dev-$kt_n.crt" -noout -subject \
        | grep -q "CN *= *$kt_cn"
    # Chain-verify the issued cert against the CA we fetched above.
    openssl verify -CAfile ca.pem "dev-$kt_n.crt" >/dev/null
    # Parse the client's private key and match its public half to the cert.
    openssl pkey -in "dev-$kt_n.key" -noout
    key_pub="$(openssl pkey -in "dev-$kt_n.key" -pubout)"
    crt_pub="$(openssl x509 -in "dev-$kt_n.crt" -noout -pubkey)"
    if [ "$key_pub" != "$crt_pub" ]; then
        echo "ERROR: $kt client private key does not match enrolled cert" >&2
        exit 1
    fi
    echo "    PASS  $kt  (cert chains to CA; private key parses + matches)"
done

kill_if "$WC_PID"; WC_PID=""

# ------------------------------------------------------------
# 3. OpenSSL-built CSR -> wolfcert-server /simpleenroll.
#    Confirms wolfCert's server accepts an externally-produced CSR.
# ------------------------------------------------------------

echo "[3] OpenSSL-generated CSR -> wolfcert-server EST enroll"
PORT=$(free_port)
"$WC_SERVER" --proto est --listen "127.0.0.1:$PORT" \
             --tls-cert tls-server.crt --tls-key tls-server.key \
             >wc-server3.log 2>&1 &
WC_PID=$!
trap 'kill_if "$WC_PID"' EXIT
wait_port 127.0.0.1 "$PORT"

openssl req -new -newkey rsa:2048 -nodes \
    -keyout openssl.key -out openssl.csr \
    -subj "/CN=pkcs7-interop-csr/O=wolfCert-interop" \
    -batch >/dev/null 2>&1
openssl req -in openssl.csr -outform DER -out openssl.csr.der >/dev/null

# POST the OpenSSL-built CSR through curl (not through wolfcert-client,
# so the request body is independent of wolfCert code). curl trusts the
# throwaway TLS CA via --cacert.
# Encode with `openssl base64` rather than the base64(1) CLI: GNU wants
# `base64 -w0` while BSD/macOS wants `-i` and rejects a positional file,
# so neither is portable. `tr -d '\n'` strips openssl's line wrapping.
openssl base64 -e -in openssl.csr.der | tr -d '\n' > openssl.csr.b64
curl -s --cacert tls-ca.crt -o est.resp -w '%{http_code}' \
    -X POST -H "Content-Type: application/pkcs10" \
    --data-binary @openssl.csr.b64 \
    "https://localhost:$PORT/.well-known/est/simpleenroll" \
    | tee est.status | grep -q '^200$'

# Response is base64 PKCS#7 certs-only; decode and parse the cert.
openssl base64 -d -in est.resp -out est.p7.der
openssl pkcs7 -inform DER -in est.p7.der -print_certs -out est.crt.pem >/dev/null
openssl x509 -in est.crt.pem -noout -subject \
    | grep -q "CN *= *pkcs7-interop-csr"
echo "    PASS  (wolfcert-server enrolled an OpenSSL-generated CSR; response"
echo "           parses cleanly with openssl pkcs7)"

kill_if "$WC_PID"
echo "OK"
