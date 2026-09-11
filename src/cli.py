from __future__ import annotations

import argparse
from pathlib import Path

from .analyzer import assess_all
from .loader import load_accounts
from .reporting import render


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline defensive AS-REP exposure assessment")
    parser.add_argument("input", help="JSON file containing approved/synthetic directory records")
    parser.add_argument("--output", help="Optional Markdown report path")
    args = parser.parse_args()

    findings = assess_all(load_accounts(args.input))
    report = render(findings)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report, encoding="utf-8")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
