"""``python3 -m sanitext [--policy NAME] [FILE]`` — sanitise FILE (or stdin) to stdout."""

import argparse
import sys

from . import POLICIES, sanitize


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sanitext", description="Sanitise untrusted HTML")
    parser.add_argument("file", nargs="?", help="input file (default: stdin)")
    parser.add_argument("--policy", default="default", choices=sorted(POLICIES), help="policy name")
    args = parser.parse_args(argv)
    try:
        if args.file:
            with open(args.file, encoding="utf-8") as handle:
                html = handle.read()
        else:
            html = sys.stdin.read()
    except (OSError, UnicodeDecodeError) as err:
        print(f"sanitext: {err}", file=sys.stderr)
        return 1
    sys.stdout.write(sanitize(html, POLICIES[args.policy]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
