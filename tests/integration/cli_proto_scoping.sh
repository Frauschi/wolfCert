#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# wolfcert-client rejects an option belonging to the other protocol, and
# validates the keyword arguments of the SCEP options, rather than accepting
# either and quietly doing nothing. Both were only ever checked by hand.
#
# Every case here fails before any network access, so no server is needed.

set -u

# CMake passes the built binary as $1. Automake's test harness passes no
# arguments, so it exports WOLFCERT_CLI instead.
CLI="${1:-${WOLFCERT_CLI:-}}"
if [ -z "$CLI" ]; then
    echo "usage: cli_proto_scoping.sh /path/to/wolfcert-client" >&2
    echo "       (or set WOLFCERT_CLI)" >&2
    exit 1
fi
fails=0

# A wolfSSL built WOLFSSL_NO_MALLOC needs a static memory pool installed before
# anything can allocate, which the unit tests do and the CLI does not. There the
# binary cannot get past wolfcert_init, so there is nothing to assert about
# option scoping: skip rather than fail. 77 is the automake skip convention this
# repo already uses in tests/interop.
if "$CLI" getcacerts --proto scep --url "http://127.0.0.1:1/scep" 2>&1 \
        | grep -q "wolfcert_init failed"; then
    echo "SKIP: wolfcert-client cannot initialise in this build (no allocator)"
    exit 77
fi

# expect_reject <description> <substring the message must contain> <args...>
expect_reject() {
    local what="$1"; shift
    local want="$1"; shift
    local out rc
    out="$("$CLI" "$@" 2>&1)"
    rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "FAIL: $what was accepted (exit 0)"
        fails=$((fails + 1))
        return
    fi
    case "$out" in
        *"$want"*) echo "ok   $what" ;;
        *)
            echo "FAIL: $what rejected, but not for the expected reason"
            echo "      wanted substring: $want"
            echo "      got: $out"
            fails=$((fails + 1))
            ;;
    esac
}

EST_URL="https://127.0.0.1:1/.well-known/est"
SCEP_URL="http://127.0.0.1:1/scep"

# EST-only options must be refused under SCEP.
expect_reject "--user under scep"  "EST-only" \
    getcacerts --proto scep --url "$SCEP_URL" --user alice --pass hunter2
expect_reject "--pha under scep"   "EST-only" \
    getcacerts --proto scep --url "$SCEP_URL" --pha
expect_reject "--csrattrs-auto under scep" "EST-only" \
    getcacerts --proto scep --url "$SCEP_URL" --csrattrs-auto

# SCEP-only options must be refused under EST.
expect_reject "--ca-id under est"          "SCEP-only" \
    getcacerts --proto est --url "$EST_URL" --ca-id MyCA
expect_reject "--txid-mode under est"      "SCEP-only" \
    getcacerts --proto est --url "$EST_URL" --txid-mode pubkey
expect_reject "--content-cipher under est" "SCEP-only" \
    getcacerts --proto est --url "$EST_URL" --content-cipher aes256

# Keyword arguments are validated rather than silently defaulted.
expect_reject "bogus --txid-mode"      "must be random or pubkey" \
    getcacerts --proto scep --url "$SCEP_URL" --txid-mode bogus
expect_reject "bogus --content-cipher" "must be auto, aes128, aes256" \
    getcacerts --proto scep --url "$SCEP_URL" --content-cipher rc4

# --challenge is deliberately NOT scoped: a challengePassword is legitimate in
# an EST CSR that /csrattrs asked for. It must get past option validation and
# fail on the network instead, which is what the unreachable port produces.
out="$("$CLI" enroll --proto est --url "$EST_URL" --subject "CN=x" \
        --challenge secret --out-key /dev/null --out-cert /dev/null 2>&1)"
case "$out" in
    *EST-only*|*SCEP-only*)
        echo "FAIL: --challenge was scoped to one protocol"
        echo "      got: $out"
        fails=$((fails + 1))
        ;;
    *)  echo "ok   --challenge accepted under est" ;;
esac

if [ "$fails" -ne 0 ]; then
    echo "$fails case(s) failed"
    exit 1
fi
echo "OK"
