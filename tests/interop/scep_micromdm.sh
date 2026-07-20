#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# SCEP interoperability against micromdm/scep (Debian/Ubuntu: `apt install
# scep`). Exercises both directions and REQUIRES both to succeed:
#
#   [D2]  wolfcert-client  ->  scepserver      : enroll against micromdm
#   [D1]  scepclient       ->  wolfcert-server : enroll against wolfCert
#
# Needs a wolfSSL built --enable-des3: micromdm content-encrypts its
# pkcsPKIEnvelope with single DES-CBC (1.3.14.3.2.7), which wolfSSL disables by
# default (NO_DES3). The `full` CI config enables it (build-wolfssl.sh).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib/common.sh"

need scepclient "Debian/Ubuntu: sudo apt install scep"
need scepserver "Debian/Ubuntu: sudo apt install scep"
need openssl    "Standard on most distros"

WC_SERVER="$(wolfcert_bin wolfcert-server)"
WC_CLIENT="$(wolfcert_bin wolfcert-client)"

cd "$WOLFCERT_INTEROP_WORK"
trap 'echo "--- work dir: $WOLFCERT_INTEROP_WORK"' EXIT

# ------------------------------------------------------------------------ D2
echo "[D2] wolfcert-client -> micromdm scepserver"
mkdir -p d2 && cd d2 && mkdir -p depot
scepserver ca -init -depot "$PWD/depot" -organization "wolfCert-interop" \
              -years 2 >ca-init.log 2>&1
PORT=$(free_port)
scepserver -depot "$PWD/depot" -port "$PORT" -allowrenew 0 >scepserver.log 2>&1 &
SRV_PID=$!
trap 'kill_if "$SRV_PID"' EXIT
wait_port 127.0.0.1 "$PORT"

"$WC_CLIENT" enroll \
    --proto scep \
    --url  "http://127.0.0.1:$PORT/scep" \
    --key-type rsa:2048 \
    --subject "CN=interop-wolfcert-1,O=wolfCert-interop" \
    --out-key  dev.key.pem \
    --out-cert dev.crt.pem \
    >wolfcert-client.log 2>&1 \
    || { echo "    FAIL (enroll failed):"; cat wolfcert-client.log; exit 1; }
kill_if "$SRV_PID"; SRV_PID=""

openssl x509 -in dev.crt.pem -noout -subject \
    | grep -q "CN *= *interop-wolfcert-1"
openssl verify -CAfile depot/ca.pem dev.crt.pem >/dev/null
echo "    PASS  (cert chains to scepserver CA)"
cd ..

# ------------------------------------------------------------------------ D1
echo "[D1] micromdm scepclient -> wolfcert-server"
PORT=$(free_port)
"$WC_SERVER" --proto scep --listen "127.0.0.1:$PORT" \
             >wolfcert-server.log 2>&1 &
WC_PID=$!
trap 'kill_if "$SRV_PID"; kill_if "$WC_PID"' EXIT
wait_port 127.0.0.1 "$PORT"

mkdir -p d1 && cd d1
scepclient \
    -server-url  "http://127.0.0.1:$PORT/scep" \
    -private-key client.key \
    -certificate client.crt \
    -cn "interop-scepclient-1" \
    -organization "wolfCert-interop" \
    -keySize 2048 \
    >scepclient.log 2>&1 \
    || { echo "    FAIL (scepclient failed):"; cat scepclient.log; exit 1; }
kill_if "$WC_PID"; WC_PID=""

# micromdm's scepclient writes the issued cert as PEM (older builds: DER).
d1_subject=$(openssl x509 -in client.crt -noout -subject 2>/dev/null) \
    || d1_subject=$(openssl x509 -inform DER -in client.crt -noout -subject)
echo "$d1_subject" | grep -q "CN *= *interop-scepclient-1"
echo "    PASS  (cert returned and subject matches)"

echo "OK"
