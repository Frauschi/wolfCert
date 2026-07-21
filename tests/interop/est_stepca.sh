#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# EST + SCEP interoperability against Smallstep's step-ca. Requires the
# `step-ca` and `step` binaries (https://smallstep.com/docs/step-ca).
# This script does NOT install them; it assumes they're in PATH.
#
# Install hints (do any ONE):
#   - apt keyring (Debian/Ubuntu): see https://smallstep.com/docs/step-ca/installation
#   - Homebrew:   brew install step step-ca
#   - go install: go install github.com/smallstep/certificates/cmd/step-ca@latest
#                 go install github.com/smallstep/cli/cmd/step@latest
#
# The script bootstraps a throwaway step-ca PKI in the interop work dir,
# starts step-ca with EST enabled, and drives wolfcert-client against
# both the EST and SCEP endpoints step-ca exposes. All output lands in
# $WOLFCERT_INTEROP_WORK.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib/common.sh"

need step     "Install step-cli (see script header for options)"
need step-ca  "Install step-ca  (see script header for options)"
need openssl  "Standard on most distros"

WC_CLIENT="$(wolfcert_bin wolfcert-client)"

export STEPPATH="$WOLFCERT_INTEROP_WORK/step"
mkdir -p "$STEPPATH"
cd "$WOLFCERT_INTEROP_WORK"
trap 'echo "--- work dir: $WOLFCERT_INTEROP_WORK"' EXIT

# ---- bootstrap a CA --------------------------------------------------------
echo "[setup] step ca init"
export STEP_PASSWORD="interop"
step ca init \
    --name      "wolfCert-interop-CA" \
    --dns       "localhost" \
    --address   "127.0.0.1:$(free_port)" \
    --provisioner "interop-admin" \
    --password-file <(echo -n "$STEP_PASSWORD") \
    --provisioner-password-file <(echo -n "$STEP_PASSWORD") \
    --deployment-type standalone \
    >init.log 2>&1

# RFC 8894 SCEP is RSA-only: the CA decrypts the pkcsPKIEnvelope with its
# private key, which step-ca's default ECDSA chain cannot do (see
# docs/INTEROP.md note 5). Swap in an RSA root + intermediate so the SCEP
# decrypter - and every cert GetCACert hands the client - is RSA. step-ca uses
# the intermediate as the SCEP decrypter when none is configured explicitly.
# The intermediate key stays encrypted under STEP_PASSWORD (step-ca loads it at
# startup); the throwaway root key is only needed here to sign the intermediate.
ROOT_CRT="$STEPPATH/certs/root_ca.crt"
ROOT_KEY="$STEPPATH/secrets/root_ca_key"
INT_CRT="$STEPPATH/certs/intermediate_ca.crt"
INT_KEY="$STEPPATH/secrets/intermediate_ca_key"
step certificate create "wolfCert-interop RSA Root" "$ROOT_CRT" "$ROOT_KEY" \
    --profile root-ca --kty RSA --size 2048 --not-after 87600h \
    --force --no-password --insecure >rsa-root.log 2>&1
step certificate create "wolfCert-interop RSA Intermediate" "$INT_CRT" "$INT_KEY" \
    --profile intermediate-ca --kty RSA --size 2048 --not-after 87600h \
    --ca "$ROOT_CRT" --ca-key "$ROOT_KEY" \
    --force --password-file <(echo -n "$STEP_PASSWORD") >rsa-int.log 2>&1

# Enable SCEP provisioner (EST is on by default in recent step-ca).
# Configure a challenge so we exercise RFC 8894 section 2.9 end-to-end.
# --encryption-algorithm-identifier 1 selects AES-128-CBC for the CertRep
# content encryption (step-ca defaults to legacy DES-CBC), matching what
# wolfcert-client advertises via GetCACaps.
SCEP_CHALLENGE="wolfcert-interop-challenge"
step ca provisioner add "SCEP" --type SCEP \
    --force-cn \
    --challenge "$SCEP_CHALLENGE" \
    --encryption-algorithm-identifier 1 \
    >scep-add.log 2>&1

CA_PORT=$(grep -oE '127\.0\.0\.1:[0-9]+' "$STEPPATH/config/ca.json" | cut -d: -f2 | head -1)
echo "[setup] step-ca will listen on :$CA_PORT"

step-ca --password-file <(echo -n "$STEP_PASSWORD") \
        "$STEPPATH/config/ca.json" >step-ca.log 2>&1 &
CA_PID=$!
trap 'kill_if "$CA_PID"' EXIT
wait_port 127.0.0.1 "$CA_PORT"

# Export the root cert so wolfcert-client can trust the TLS endpoint.
cp "$STEPPATH/certs/root_ca.crt" ca-root.pem

# ---- EST enrollment -------------------------------------------------------

# step-ca open-source (github.com/smallstep/certificates) does not ship
# RFC 7030 EST support; the EST endpoints are only available in the
# commercial "Smallstep Certificate Manager" build. A GET against
# /.well-known/est/* returns 404 on OSS step-ca regardless of the
# provisioner setup. We probe the endpoint rather than enroll and skip
# if it isn't present.
echo "[1] EST: probe /.well-known/est/cacerts on step-ca"
EST_HTTP=$(curl -sk -o /dev/null -w '%{http_code}' \
    "https://localhost:$CA_PORT/.well-known/est/cacerts" || echo "000")
if [ "$EST_HTTP" = "200" ] || [ "$EST_HTTP" = "204" ]; then
    "$WC_CLIENT" enroll --proto est \
        --url   "https://localhost:$CA_PORT/.well-known/est" \
        --trust ca-root.pem \
        --user  "interop-admin" --pass "$STEP_PASSWORD" \
        --key-type ecc:256 \
        --subject "CN=stepca-interop-est" \
        --out-key  est.key --out-cert est.crt \
        >wc-est.log 2>&1
    openssl x509 -in est.crt -noout -subject \
        | grep -q "CN *= *stepca-interop-est"
    openssl verify -CAfile ca-root.pem \
        -untrusted "$STEPPATH/certs/intermediate_ca.crt" est.crt >/dev/null
    echo "    PASS  (cert chains to step-ca root)"
else
    echo "    SKIP  (EST endpoint returns HTTP $EST_HTTP on this step-ca;"
    echo "           open-source step-ca does not implement RFC 7030 -"
    echo "           EST is only in Smallstep's commercial CM.)"
fi

# ---- SCEP enrollment ------------------------------------------------------

echo "[2] SCEP: wolfcert-client enroll against step-ca (RSA device key)"
# With the RSA chain in place the pkcsPKIEnvelope encrypts and step-ca issues
# the cert, but its CertRep is signed by github.com/smallstep/scep (the
# micromdm library), so verifying that signature hits the same wolfSSL PKCS#7
# gap as the micromdm interop (ASN_SIG_CONFIRM_E, -229). This is a STRICT
# assertion by design: it fails until wolfSSL PR #10928 (pkcs7_fix) reaches
# master, then self-heals to PASS. See docs/INTEROP.md note 5.
SCEP_URL="https://localhost:$CA_PORT/scep/SCEP"
"$WC_CLIENT" enroll --proto scep \
    --url  "$SCEP_URL" \
    --trust ca-root.pem \
    --challenge "$SCEP_CHALLENGE" \
    --key-type rsa:2048 \
    --subject "CN=stepca-interop-scep" \
    --out-key scep.key --out-cert scep.crt \
    >wc-scep.log 2>&1 \
    || { echo "    FAIL (scep enroll failed):"; cat wc-scep.log; exit 1; }
openssl x509 -in scep.crt -noout -subject \
    | grep -q "CN *= *stepca-interop-scep"
echo "    PASS  (cert returned; challengePassword accepted by step-ca)"

kill_if "$CA_PID"
echo "OK"
