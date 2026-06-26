#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# SCEP interoperability against micromdm/scep (Debian/Ubuntu: `apt install
# scep`). Exercises:
#
#   [D2]  wolfcert-client  ->  scepserver      : expected PASS
#   [D1]  scepclient       ->  wolfcert-server : expected FAIL on stock wolfSSL
#                                               (MAX_SIGNED_ATTRIBS_SZ=7 limit,
#                                               see docs/INTEROP.md note 1).
#
# D1 is run to surface when/if a wolfSSL rebuild fixes it. Once wolfSSL is
# rebuilt with -DMAX_SIGNED_ATTRIBS_SZ>=8 AND wolfCert is configured with
#   cmake -DWOLFCERT_WOLFSSL_EXTENDED_SIGNED_ATTRIBS=ON
# (or ./configure --enable-wolfssl-extended-signed-attribs), D1 should PASS.
# Exit 0 on D2 OK regardless.

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

# ---------------------------------------------------------- D2 (expected OK)
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
    >wolfcert-client.log 2>&1

openssl x509 -in dev.crt.pem -noout -subject \
    | grep -q "CN *= *interop-wolfcert-1"
openssl verify -CAfile depot/ca.pem dev.crt.pem >/dev/null
echo "    PASS  (cert chains to scepserver CA)"

kill_if "$SRV_PID"; SRV_PID=""
cd ..

# ---------------------------------------------------------- D1 (informational)
echo "[D1] micromdm scepclient -> wolfcert-server"
PORT=$(free_port)
"$WC_SERVER" --proto scep --listen "127.0.0.1:$PORT" \
             >wolfcert-server.log 2>&1 &
WC_PID=$!
trap 'kill_if "$SRV_PID"; kill_if "$WC_PID"' EXIT
wait_port 127.0.0.1 "$PORT"

mkdir -p d1 && cd d1
set +e
scepclient \
    -server-url  "http://127.0.0.1:$PORT/scep" \
    -private-key client.key \
    -certificate client.crt \
    -cn "interop-scepclient-1" \
    -organization "wolfCert-interop" \
    -keySize 2048 \
    >scepclient.log 2>&1
RC=$?
set -e
kill_if "$WC_PID"; WC_PID=""

if [ -s client.crt ]; then
    openssl x509 -in client.crt -inform DER -noout -subject \
        | grep -q "CN *= *interop-scepclient-1"
    echo "    PASS  (cert returned and subject matches)"
else
    echo "    KNOWN-FAIL  (scepclient rc=$RC; wolfcert-server CertRep"
    echo "                drops recipientNonce to stay under wolfSSL's"
    echo "                MAX_SIGNED_ATTRIBS_SZ=7. Rebuild wolfSSL with"
    echo "                -DMAX_SIGNED_ATTRIBS_SZ>=8 to lift the limit -"
    echo "                see docs/INTEROP.md.)"
fi

echo "OK"
