# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Sismo diff tests — a runner over suites.

Modeled on syntaqlite: each suite is a module in python/tools/diff_suites/
exposing NAME, DESCRIPTION, run(ctx) -> failure_count, and optionally
ENABLED_BY_DEFAULT (default True) and NEEDS_BINARY. Every case reduces to
"produce normalized text, diff against tests/diff/<suite>/<name>.txt", handled
by the shared core in diff_suites/common.py.

The default run executes the enabled-by-default suites; heavy suites are opt-in
via --suite.

  tools/difftest                       # enabled-by-default suites (cli, trace)
  tools/difftest --suite matrix        # the opt-in compatibility matrix
  tools/difftest --suite cli --suite matrix
  tools/difftest -k help               # only cases whose name contains "help"
  tools/difftest --rebaseline          # regenerate goldens for the run suites
  tools/difftest --list
"""

from __future__ import annotations

import argparse
import sys

from python.tools.diff_suites import cli, matrix, symbolize_mac, trace
from python.tools.diff_suites.common import SuiteContext

# Ordered registry. Order is the run order.
_SUITES = [cli, trace, symbolize_mac, matrix]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--suite", action="append", default=[],
                        help="run only these suites (default: enabled-by-default)")
    parser.add_argument("--rebaseline", "--rewrite", action="store_true",
                        dest="rebaseline", help="regenerate goldens for the run suites")
    parser.add_argument("-k", "--filter", default=None,
                        help="substring filter on case names")
    parser.add_argument("--list", action="store_true", help="list suites and exit")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    by_name = {s.NAME: s for s in _SUITES}

    if args.list:
        for s in _SUITES:
            tag = "(default)" if getattr(s, "ENABLED_BY_DEFAULT", True) else "(opt-in) "
            print(f"{s.NAME:<8} {tag}  {s.DESCRIPTION}")
        return 0

    if args.suite:
        unknown = [n for n in args.suite if n not in by_name]
        if unknown:
            print(f"unknown suite(s): {', '.join(unknown)} "
                  f"(have: {', '.join(by_name)})", file=sys.stderr)
            return 2
        selected = [by_name[n] for n in args.suite]
    else:
        selected = [s for s in _SUITES if getattr(s, "ENABLED_BY_DEFAULT", True)]

    ctx = SuiteContext(rebaseline=args.rebaseline, name_filter=args.filter,
                       verbose=args.verbose)

    total_fail = 0
    for s in selected:
        print(f"\n== {s.NAME}: {s.DESCRIPTION}")
        total_fail += s.run(ctx)

    verdict = "FAIL" if total_fail else "ok"
    print(f"\n{verdict} — {total_fail} failing case(s) across "
          f"{len(selected)} suite(s)")
    return 1 if total_fail else 0


if __name__ == "__main__":
    sys.exit(main())
