#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Issue a TLS server certificate for wolfcert-server, signed by the example
# ECC CA in ecc/, for the addresses and host names given. See README.md.

set -eu

usage() {
    echo "usage: $0 -o <outdir> IP:<address>|DNS:<name>..." >&2
    exit 2
}

ca_dir="$(cd "$(dirname "$0")/ecc" && pwd -P)"
out=""
while getopts o: opt; do
    case "$opt" in
        o) out="$OPTARG" ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
if [ -z "$out" ] || [ $# -eq 0 ]; then
    usage
fi

san=""
for entry in "$@"; do
    case "$entry" in
        IP:?*|DNS:?*) ;;
        *) echo "$0: '$entry' is not IP:<address> or DNS:<name>" >&2; exit 2 ;;
    esac
    san="${san:+$san,}$entry"
done

if ! openssl x509 -help 2>&1 | grep -q -- -dateopt; then
    echo "$0: needs OpenSSL >= 3.0 ($(openssl version 2>/dev/null ||
        echo "no openssl on PATH"))" >&2
    exit 1
fi

mkdir -p "$out"
out="$(cd "$out" && pwd -P)"
if [ -e "$out/ca-key.pem" ]; then
    echo "$0: refusing to write into $out, which holds a CA key" >&2
    exit 2
fi

# openssl ca -startdate / -enddate take YYYYMMDDHHMMSSZ.
ca_date() {
    openssl x509 -in "$ca_dir/ca-cert.pem" -noout -dateopt iso_8601 "$1" |
        sed 's/.*=//; s/[^0-9]//g; s/$/Z/'
}

not_before="$(ca_date -startdate)"
not_after="$(ca_date -enddate)"
if printf '%s\n' "$not_before" "$not_after" | grep -Evq '^[0-9]{14}Z$'; then
    echo "$0: cannot read the validity period of $ca_dir/ca-cert.pem" >&2
    exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
trap 'rm -rf "$tmp"; exit 1' INT TERM
umask 077

# Build the pair in $tmp so a failed run leaves the files in $out untouched.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$tmp/server-key.pem"
openssl req -new -key "$tmp/server-key.pem" \
    -subj "/CN=wolfCert Example Server" -out "$tmp/server.csr"

cat > "$tmp/ext" <<EOF
subjectAltName=$san
extendedKeyUsage=serverAuth
basicConstraints=critical,CA:FALSE
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

# openssl ca gives the leaf the CA's dates on any OpenSSL 3.x.
: > "$tmp/index.txt"
openssl rand -hex 16 > "$tmp/serial"
cat > "$tmp/ca.cnf" <<EOF
[ ca ]
default_ca = local
[ local ]
database = $tmp/index.txt
serial = $tmp/serial
new_certs_dir = $tmp
default_md = sha256
policy = any
[ any ]
commonName = supplied
EOF
# Show openssl ca's output only when it fails.
if ! openssl ca -batch -notext -config "$tmp/ca.cnf" \
        -cert "$ca_dir/ca-cert.pem" -keyfile "$ca_dir/ca-key.pem" \
        -startdate "$not_before" -enddate "$not_after" \
        -extfile "$tmp/ext" -in "$tmp/server.csr" \
        -out "$tmp/server-cert.pem" > "$tmp/ca.log" 2>&1; then
    cat "$tmp/ca.log" >&2
    exit 1
fi

mv "$tmp/server-key.pem" "$tmp/server-cert.pem" "$out/"

echo "generated $out/server-cert.pem and server-key.pem ($san)"
