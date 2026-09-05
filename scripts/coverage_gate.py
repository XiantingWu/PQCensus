from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _percentage(covered: int, total: int) -> float:
    return 100.0 if total == 0 else (covered / total) * 100.0


def evaluate(
    report: dict[str, Any], *, min_statement: float, min_branch: float
) -> tuple[float, float, list[str]]:
    totals = report.get("totals")
    if not isinstance(totals, dict):
        raise ValueError("coverage JSON is missing totals")

    try:
        covered_lines = int(totals["covered_lines"])
        statements = int(totals["num_statements"])
        covered_branches = int(totals["covered_branches"])
        branches = int(totals["num_branches"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("coverage JSON is missing line/branch counters") from exc

    statement_pct = _percentage(covered_lines, statements)
    branch_pct = _percentage(covered_branches, branches)
    failures: list[str] = []
    if statement_pct < min_statement:
        failures.append(
            f"statement coverage {statement_pct:.2f}% is below required {min_statement:.2f}%"
        )
    if branches == 0:
        failures.append("branch coverage cannot be gated because no branches were measured")
    elif branch_pct < min_branch:
        failures.append(f"branch coverage {branch_pct:.2f}% is below required {min_branch:.2f}%")
    return statement_pct, branch_pct, failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Enforce independent PQCensus coverage thresholds."
    )
    parser.add_argument("--report", type=Path, required=True, help="coverage.py JSON report")
    parser.add_argument("--min-statement", type=float, default=90.0)
    parser.add_argument("--min-branch", type=float, default=80.0)
    args = parser.parse_args(argv)

    if not 0 <= args.min_statement <= 100 or not 0 <= args.min_branch <= 100:
        parser.error("coverage thresholds must be between 0 and 100")

    try:
        payload = json.loads(args.report.read_text(encoding="utf-8"))
        statement_pct, branch_pct, failures = evaluate(
            payload,
            min_statement=args.min_statement,
            min_branch=args.min_branch,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"FAIL coverage gate: {exc}")
        return 2

    print(f"statement_coverage={statement_pct:.2f}% required={args.min_statement:.2f}%")
    print(f"branch_coverage={branch_pct:.2f}% required={args.min_branch:.2f}%")
    if failures:
        print("FAIL coverage gate")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("PASS coverage gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
