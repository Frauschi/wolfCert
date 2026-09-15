#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Assert that named twister suites actually executed and passed.

twister exits 0 when every selected configuration is filtered out or built
only, so a fixture rename or a platform_allow typo turns a gate green without
running anything. Pass the twister.json and the suite names the step exists to
run; this fails when one is missing, skipped, built-only or failed. Suites
named after --built-only must instead have built and not run.

    twister-assert-ran.py <twister.json> <suite> ... [--built-only <suite> ...]
"""

import json
import sys


def main(argv):
    wanted, expect = [], "passed"
    for arg in argv[2:]:
        if arg == "--built-only":
            expect = "not run"
        else:
            wanted.append((arg, expect))
    if not wanted:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    report = argv[1]

    try:
        with open(report) as fh:
            suites = json.load(fh).get("testsuites", [])
    except (OSError, ValueError) as exc:
        print(f"::error::cannot read {report}: {exc}", file=sys.stderr)
        return 1

    # twister names a suite by its path; match on the trailing component, and
    # check every entry so one good status cannot mask a bad one.
    seen = {}
    for suite in suites:
        name = suite.get("name", "").rsplit("/", 1)[-1]
        seen.setdefault(name, []).append(suite.get("status"))

    rc = 0
    for name, expect in wanted:
        statuses = seen.get(name)
        if statuses is None:
            print(f"::error::{name} did not run (not in {report})", file=sys.stderr)
            rc = 1
            continue
        bad = [s for s in statuses if s != expect]
        if bad:
            print(f"::error::{name} status is '{bad[0]}', expected '{expect}'",
                  file=sys.stderr)
            rc = 1
        else:
            print(f"{name}: {expect}")

    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
