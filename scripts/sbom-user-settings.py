#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write the WOLFCERT_* macros of a user_settings.h build as a flat header.

    sbom-user-settings.py <out.h> <cc> [compiler flags...]

Needs a compiler that takes -E -dM, such as GCC or Clang.
"""

import re
import subprocess
import sys

DEFINE = re.compile(r"^#define (WOLFCERT_\w+)(?: (.*))?$", re.M)
BUILD_MARKERS = {"WOLFCERT_USER_SETTINGS", "WOLFCERT_BUILD_DLL",
                 "WOLFCERT_USE_DLL", "WOLFCERT_BUILD_TESTING"}


def macros(cmd, source):
    r = subprocess.run(cmd + ["-E", "-dM", "-x", "c", "-"], input=source,
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        sys.exit("error: the compiler could not preprocess user_settings.h")
    return {name: value or "" for name, value in DEFINE.findall(r.stdout)}


def strip_args(cmd, split, joined):
    out, skip = [], False
    for arg in cmd:
        if skip:
            skip = False
        elif arg in split:
            skip = True
        elif not arg.startswith(joined):
            out.append(arg)
    return out


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    out = sys.argv[1]
    cmd = strip_args(sys.argv[2:], ("-o",), ("-o",))
    base = macros(strip_args(cmd, ("-D", "-U", "-include", "-imacros"),
                             ("-D", "-U", "@")), "")
    full = macros(cmd, '#include "user_settings.h"\n')
    lines = [f"#define {n} {v}".rstrip() + "\n"
             for n, v in sorted(full.items())
             if base.get(n) != v and n not in BUILD_MARKERS
             and not n.endswith("_H")]
    if not any(line.startswith("#define WOLFCERT_HAVE_") for line in lines):
        sys.exit("error: no WOLFCERT_HAVE_* macro found for user_settings.h")
    with open(out, "w") as f:
        f.writelines(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
