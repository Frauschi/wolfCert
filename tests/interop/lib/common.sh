# SPDX-License-Identifier: GPL-3.0-or-later
#
# Shared helpers for wolfCert interop scripts. Sourced, not executed.

set -euo pipefail

WOLFCERT_INTEROP_WORK="${WOLFCERT_INTEROP_WORK:-$(mktemp -d -t wolfcert-interop.XXXXXX)}"
WOLFCERT_BUILD="${WOLFCERT_BUILD:-$PWD/build}"

have() {
    command -v "$1" >/dev/null 2>&1
}

need() {
    if ! have "$1"; then
        echo "SKIP: $1 not found in PATH." >&2
        echo "      $2" >&2
        exit 77   # automake convention for "skipped"
    fi
}

kill_if() {
    local pid="${1:-}"
    [ -z "$pid" ] && return 0
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

wolfcert_bin() {
    local name="$1"
    if [ -x "$WOLFCERT_BUILD/$name" ]; then
        echo "$WOLFCERT_BUILD/$name"
    elif have "$name"; then
        echo "$name"
    else
        echo "ERROR: $name not found (looked in $WOLFCERT_BUILD and PATH)" >&2
        exit 1
    fi
}

# Bind a random free TCP port on 127.0.0.1.
free_port() {
    python3 -c '
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0))
print(s.getsockname()[1]); s.close()
'
}

wait_port() {
    local host="$1"; local port="$2"; local tries=50
    while [ "$tries" -gt 0 ]; do
        if (echo > "/dev/tcp/$host/$port") 2>/dev/null; then return 0; fi
        sleep 0.1; tries=$((tries-1))
    done
    echo "ERROR: $host:$port never came up" >&2
    return 1
}
