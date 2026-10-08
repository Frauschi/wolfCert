#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# EST interoperability against GlobalSign's Go-based reference
# implementation at github.com/globalsign/est.
#
# Install (one-time, needs Go 1.25+):
#
#   go install github.com/globalsign/est/cmd/estserver@latest
#   go install github.com/globalsign/est/cmd/estclient@latest
#
# libest installs binaries of the same names; set GLOBALSIGN_EST_BIN_DIR when
# globalsign's are not first on PATH.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib/common.sh"

# Locate globalsign's binaries (not libest's)
pick_globalsign() {
    local bin="$1" probe="$2"
    local cand
    if [ -n "${GLOBALSIGN_EST_BIN_DIR:-}" ]; then
        cand="$GLOBALSIGN_EST_BIN_DIR/$bin"
    else
        cand="$(command -v "$bin" || true)"
    fi
    if [ -z "$cand" ] || ! [ -x "$cand" ]; then
        echo "SKIP: $bin not found (install: go install github.com/globalsign/est/cmd/$bin@latest)" >&2
        exit 77
    fi
    # Only globalsign's binaries accept sampleconfig.
    if ! eval "\"\$cand\" $probe" >/dev/null 2>&1; then
        echo "SKIP: '$cand' is not the globalsign $bin (libest also installs a" \
             "binary with this name). Set GLOBALSIGN_EST_BIN_DIR or reorder \$PATH." >&2
        exit 77
    fi
    echo "$cand"
}
GS_ESTSERVER="$(pick_globalsign estserver '-sampleconfig')"
GS_ESTCLIENT="$(pick_globalsign estclient 'sampleconfig')"
need openssl "Standard on most distros"

WC_CLIENT="$(wolfcert_bin wolfcert-client)"
WC_SERVER="$(wolfcert_bin wolfcert-server)"

cd "$WOLFCERT_INTEROP_WORK"
trap 'echo "--- work dir: $WOLFCERT_INTEROP_WORK"' EXIT

# Bootstrap a mock CA + server TLS identity
echo "[setup] bootstrap mock CA + server TLS identity"
mkdir -p ca srv
# Mock CA (used by estserver's mock_ca to sign enrolled certs).
openssl req -x509 -new -newkey rsa:2048 -nodes \
    -keyout ca/ca.key -out ca/ca.crt -days 30 \
    -subj "/CN=globalsign-est-interop-CA" -batch >/dev/null 2>&1
# estserver's TLS identity, valid for localhost and 127.0.0.1.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout srv/srv.key -out srv/srv.crt \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -batch >/dev/null 2>&1

# D1: wolfcert-client -> globalsign estserver
echo "[1] wolfcert-client -> globalsign estserver"
EST_PORT=$(free_port)

cat > estserver.json <<CFG
{
    "mock_ca": {
        "certificates": "$PWD/ca/ca.crt",
        "private_key":  "$PWD/ca/ca.key"
    },
    "tls": {
        "listen_address": "127.0.0.1:$EST_PORT",
        "certificates":   "$PWD/srv/srv.crt",
        "private_key":    "$PWD/srv/srv.key"
    },
    "allowed_hosts": ["localhost", "127.0.0.1"],
    "rate_limit": 150,
    "timeout": 30
}
CFG

"$GS_ESTSERVER" -config estserver.json >estserver.log 2>&1 &
ES_PID=$!
trap 'kill_if "$ES_PID"' EXIT
wait_port 127.0.0.1 "$EST_PORT"

# estserver's self-signed TLS identity has CN=localhost, so connect by name.
"$WC_CLIENT" enroll --proto est \
    --url   "https://localhost:$EST_PORT/.well-known/est" \
    --trust srv/srv.crt \
    --key-type ecc:256 \
    --subject "CN=globalsign-interop-client" \
    --out-key wc.key --out-cert wc.crt \
    >wc-client.log 2>&1

openssl x509 -in wc.crt -noout -subject \
    | grep -q "CN *= *globalsign-interop-client"
openssl verify -CAfile ca/ca.crt wc.crt >/dev/null
echo "    PASS  (cert chains to globalsign estserver mock CA)"
kill_if "$ES_PID"; ES_PID=""

# D2: globalsign estclient -> wolfcert-server
echo "[2] globalsign estclient -> wolfcert-server (HTTPS via built-in TLS)"
WC_PORT=$(free_port)

# wolfcert-server needs its own loopback identity for --tls-cert/--tls-key.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout srv/wc.key -out srv/wc.crt \
    -subj "/CN=127.0.0.1" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -batch >/dev/null 2>&1

"$WC_SERVER" --proto est --listen "127.0.0.1:$WC_PORT" \
             --tls-cert srv/wc.crt --tls-key srv/wc.key --est-allow-anonymous \
             >wc-server.log 2>&1 &
WC_PID=$!
trap 'kill_if "$WC_PID"' EXIT
wait_port 127.0.0.1 "$WC_PORT"

# estclient reads -key/-signingkey rather than generating a key.
openssl genrsa -out estcli.key 2048 2>/dev/null
"$GS_ESTCLIENT" csr -cn "globalsign-cli-1" -key estcli.key \
    -out estcli.csr >csr.log 2>&1

"$GS_ESTCLIENT" enroll -server "127.0.0.1:$WC_PORT" \
    -explicit srv/wc.crt \
    -csr estcli.csr -signingkey estcli.key \
    -out estcli.crt \
    >estclient.log 2>&1

openssl x509 -in estcli.crt -noout -subject 2>&1 \
    | grep -q "CN *= *globalsign-cli-1"
echo "    PASS  (wolfcert-server issued a cert to globalsign estclient)"
kill_if "$WC_PID"

echo "OK"
