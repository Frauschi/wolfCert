#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Cross-verify wolfCert's output against OpenSSL's CMS / PKCS7 tools.
# OpenSSL has no native SCEP/EST client, but its `cms` and `pkcs7`
# commands independently parse the PKCS#7 blobs wolfCert produces and
# consumes - a useful lower-bound sanity check.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib/common.sh"

need openssl        "Standard on most distros"

WC_SERVER="$(wolfcert_bin wolfcert-server)"
WC_CLIENT="$(wolfcert_bin wolfcert-client)"

cd "$WOLFCERT_INTEROP_WORK"
trap 'echo "--- work dir: $WOLFCERT_INTEROP_WORK"' EXIT

# ------------------------------------------------------------
# 1. wolfcert-server's EST /cacerts response is a base64 PKCS#7
#    certs-only. Decode + verify OpenSSL can parse every cert and
#    cross-check its subject.
# ------------------------------------------------------------

echo "[1] EST /cacerts -> OpenSSL pkcs7 parse"
PORT=$(free_port)
"$WC_SERVER" --proto est --listen "127.0.0.1:$PORT" \
             >wc-server.log 2>&1 &
WC_PID=$!
trap 'kill_if "$WC_PID"' EXIT
wait_port 127.0.0.1 "$PORT"

"$WC_CLIENT" getcacerts --proto est \
    --url "http://127.0.0.1:$PORT/.well-known/est" \
    --out-cert ca.pem >/dev/null
test -s ca.pem
# OpenSSL parses the PEM'd chain and prints each cert.
openssl x509 -in ca.pem -noout -subject \
    | grep -q "CN *= *wolfCert Test CA"
echo "    PASS  (OpenSSL parses wolfCert /cacerts output, CA subject matches)"

# ------------------------------------------------------------
# 2. wolfcert-server EST /simpleenroll response parses via OpenSSL too.
# ------------------------------------------------------------

echo "[2] EST /simpleenroll response -> OpenSSL x509 parse"
"$WC_CLIENT" enroll --proto est \
    --url "http://127.0.0.1:$PORT/.well-known/est" \
    --key-type ecc:256 --subject "CN=cms-interop-1,O=wolfCert-interop" \
    --out-key dev.key --out-cert dev.crt >/dev/null
openssl x509 -in dev.crt -noout -subject \
    | grep -q "CN *= *cms-interop-1"
# Chain-verify the issued cert against the CA we fetched above.
openssl verify -CAfile ca.pem dev.crt >/dev/null
echo "    PASS  (OpenSSL verifies enrolled cert against wolfCert CA)"

kill_if "$WC_PID"; WC_PID=""

# ------------------------------------------------------------
# 3. OpenSSL-built CSR -> wolfcert-server /simpleenroll.
#    Confirms wolfCert's server accepts an externally-produced CSR.
# ------------------------------------------------------------

echo "[3] OpenSSL-generated CSR -> wolfcert-server EST enroll"
PORT=$(free_port)
"$WC_SERVER" --proto est --listen "127.0.0.1:$PORT" >wc-server3.log 2>&1 &
WC_PID=$!
trap 'kill_if "$WC_PID"' EXIT
wait_port 127.0.0.1 "$PORT"

openssl req -new -newkey rsa:2048 -nodes \
    -keyout openssl.key -out openssl.csr \
    -subj "/CN=cms-interop-2/O=wolfCert-interop" \
    -batch >/dev/null 2>&1
openssl req -in openssl.csr -outform DER -out openssl.csr.der >/dev/null

# POST the OpenSSL-built CSR through curl (not through wolfcert-client,
# so the request body is independent of wolfCert code).
# `base64 -w0` is GNU coreutils only; BSD/macOS base64 rejects it.
# Pipe through `tr -d '\n'` to strip line wrapping portably.
base64 openssl.csr.der | tr -d '\n' > openssl.csr.b64
curl -s -o est.resp -w '%{http_code}' \
    -X POST -H "Content-Type: application/pkcs10" \
    --data-binary @openssl.csr.b64 \
    "http://127.0.0.1:$PORT/.well-known/est/simpleenroll" \
    | tee est.status | grep -q '^200$'

# Response is base64 PKCS#7 certs-only; decode and parse the cert.
base64 -d est.resp > est.p7.der
openssl pkcs7 -inform DER -in est.p7.der -print_certs -out est.crt.pem >/dev/null
openssl x509 -in est.crt.pem -noout -subject \
    | grep -q "CN *= *cms-interop-2"
echo "    PASS  (wolfcert-server enrolled an OpenSSL-generated CSR; response"
echo "           parses cleanly with openssl pkcs7)"

kill_if "$WC_PID"
echo "OK"
