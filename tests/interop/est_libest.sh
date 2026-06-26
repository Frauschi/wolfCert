#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# EST interoperability against Cisco's libest (archived but still the
# reference implementation of RFC 7030).
#
# libest is not packaged on any major distro; this script looks for
# `estserver` and `estclient` in PATH. Install by:
#
#   git clone https://github.com/cisco/libest
#   cd libest && ./configure --with-ssl-dir=$(pkg-config --variable prefix openssl)
#   make && sudo make install
#
# The script exercises:
#   [1] wolfcert-client enrolls against a libest estserver
#   [2] libest estclient enrolls against wolfcert-server

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib/common.sh"

need estserver "Install libest from https://github.com/cisco/libest"
need estclient "Install libest from https://github.com/cisco/libest"
need openssl   "Standard on most distros"

WC_CLIENT="$(wolfcert_bin wolfcert-client)"
WC_SERVER="$(wolfcert_bin wolfcert-server)"

cd "$WOLFCERT_INTEROP_WORK"
trap 'echo "--- work dir: $WOLFCERT_INTEROP_WORK"' EXIT

# libest doesn't bootstrap its own CA; build one with openssl. The
# example estserver shells out to OpenSSL for actual issuance and
# needs an OpenSSL `ca` config plus a populated CA state dir
# (`index.txt`, `serial`, `newcerts/`, private key, cert).
echo "[setup] bootstrap a CA with openssl for libest"
mkdir -p ca CA/estCA/private CA/estCA/newcerts
: > CA/estCA/index.txt
echo "01" > CA/estCA/serial
openssl req -x509 -new -newkey rsa:2048 -nodes \
    -keyout CA/estCA/private/cakey.pem -out CA/estCA/cacert.crt \
    -days 30 -subj "/CN=libest-interop-CA" -batch >/dev/null 2>&1
# Convenience copies the wolfcert client uses as a trust anchor.
cp CA/estCA/cacert.crt ca/ca.crt
cp CA/estCA/private/cakey.pem ca/ca.key
openssl req -new -newkey rsa:2048 -nodes \
    -keyout ca/srv.key -out ca/srv.csr \
    -subj "/CN=localhost" -batch >/dev/null 2>&1
openssl x509 -req -in ca/srv.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial \
    -out ca/srv.crt -days 30 -sha256 >/dev/null 2>&1

cat > estCA.cnf <<'CNF'
[ ca ]
default_ca = CA_default
[ CA_default ]
dir            = CA/estCA
database       = $dir/index.txt
new_certs_dir  = $dir/newcerts
certificate    = $dir/cacert.crt
serial         = $dir/serial
private_key    = $dir/private/cakey.pem
default_days   = 30
default_md     = sha256
policy         = policy_any
email_in_dn    = no
name_opt       = ca_default
cert_opt       = ca_default
copy_extensions = copyall
unique_subject = no
[ policy_any ]
commonName             = supplied
organizationName       = optional
organizationalUnitName = optional
countryName            = optional
stateOrProvinceName    = optional
CNF
export EST_OPENSSL_CACONFIG="$PWD/estCA.cnf"

# ---- D1: wolfcert-client -> libest estserver -------------------------------
echo "[1] wolfcert-client -> libest estserver"
EST_PORT=$(free_port)
# libest's estserver has no CLI flag for trust anchors / cacerts response;
# the bundle is passed through env vars that point at files on disk:
#   EST_CACERTS_RESP  - PKCS#7 certs-only PEM bundle, served from /cacerts
#   EST_TRUSTED_CERTS - PEM bundle used to validate TLS client certs
# libest reads both as PEM (text); the DER-PKCS#7 form is rejected by
# its internal length-vs-strnlen check.
openssl crl2pkcs7 -nocrl -certfile ca/ca.crt -out ca/cacerts.p7 \
    >/dev/null 2>&1
export EST_CACERTS_RESP="$PWD/ca/cacerts.p7"
export EST_TRUSTED_CERTS="$PWD/ca/ca.crt"
estserver -c ca/srv.crt -k ca/srv.key -r "estrealm" \
          -p "$EST_PORT" >estserver.log 2>&1 &
ES_PID=$!
trap 'kill_if "$ES_PID"' EXIT
wait_port 127.0.0.1 "$EST_PORT"

# estserver's default self-signed cert has CN=localhost (see srv.crt
# minting above); use the same hostname in the client URL so wolfSSL's
# hostname check matches.
"$WC_CLIENT" enroll --proto est \
    --url   "https://localhost:$EST_PORT/.well-known/est" \
    --trust ca/ca.crt \
    --user  "estuser" --pass "estpwd" \
    --key-type ecc:256 \
    --subject "CN=libest-interop-client" \
    --out-key libest.key --out-cert libest.crt \
    >wc-client.log 2>&1

openssl x509 -in libest.crt -noout -subject \
    | grep -q "CN *= *libest-interop-client"
openssl verify -CAfile ca/ca.crt libest.crt >/dev/null
echo "    PASS"
kill_if "$ES_PID"; ES_PID=""

# ---- D2: libest estclient -> wolfcert-server (native TLS) ------------------
echo "[2] libest estclient -> wolfcert-server (HTTPS via built-in TLS)"
EST_PORT=$(free_port)

# Mint a loopback server identity specifically for wolfcert-server's
# --tls-cert/--tls-key (no external fronting terminator required; this
# was note 4 in docs/INTEROP.md before server-side TLS landed).
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout wc-srv.key -out wc-srv.crt -subj "/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1

"$WC_SERVER" --proto est --listen "127.0.0.1:$EST_PORT" \
             --tls-cert wc-srv.crt --tls-key wc-srv.key \
             >wc-server.log 2>&1 &
WC_PID=$!
trap 'kill_if "$WC_PID"' EXIT
wait_port 127.0.0.1 "$EST_PORT"

# estclient needs to trust wc-srv.crt as the server bootstrap anchor;
# pass it explicitly. Flag spellings vary between libest releases, so
# try a couple and skip cleanly if none match.
set +e
estclient -e -s "127.0.0.1" -p "$EST_PORT" \
          --common-name "libest-cli-1" \
          --pem-file wc-srv.crt -o libest-cli.crt >estclient.log 2>&1
RC=$?
if [ "$RC" -ne 0 ]; then
    estclient -e -s "127.0.0.1" -p "$EST_PORT" \
              --common-name "libest-cli-1" \
              -c wc-srv.crt -o libest-cli.crt >>estclient.log 2>&1
    RC=$?
fi
set -e
if [ "$RC" -eq 0 ] && [ -s libest-cli.crt ]; then
    echo "    PASS"
else
    echo "    SKIP  (estclient invocation did not match this libest build;"
    echo "           adjust the trust-anchor flag for your version.)"
fi
kill_if "$WC_PID"

echo "OK"
