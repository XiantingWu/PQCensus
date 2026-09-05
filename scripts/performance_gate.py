from __future__ import annotations

import argparse
import json
import math
import resource
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from pqcensus import audit


def _peak_rss_mib() -> float:
    value = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if sys.platform == "darwin":
        return value / (1024 * 1024)
    return value / 1024


def _fixture_text(index: int, lines: int) -> str:
    if lines < 6:
        raise ValueError("performance fixture files require at least 6 lines")
    prefix = [
        "import hashlib",
        "",
        f"def workload_{index}():",
        "    value = 0",
    ]
    suffix = [
        f"    digest = hashlib.sha256(b'pqcensus-{index}').hexdigest()",
        "    return value, digest",
    ]
    body_count = lines - len(prefix) - len(suffix)
    body = [f"    value += {offset % 17}" for offset in range(body_count)]
    return "\n".join([*prefix, *body, *suffix]) + "\n"


def _generate(root: Path, requested_loc: int, *, lines_per_file: int) -> tuple[int, int]:
    file_count = math.ceil(requested_loc / lines_per_file)
    base_lines, extra_lines = divmod(requested_loc, file_count)
    if base_lines < 6:
        raise ValueError("requested corpus cannot be represented with valid fixture files")

    actual_loc = 0
    for index in range(file_count):
        line_count = base_lines + (1 if index < extra_lines else 0)
        text = _fixture_text(index, line_count)
        path = root / f"module_{index:05d}.py"
        path.write_text(text, encoding="utf-8")
        actual_loc += len(text.splitlines())
    if actual_loc != requested_loc:
        raise AssertionError(f"generated {actual_loc} LOC for requested tier {requested_loc}")
    return file_count, actual_loc


def run_tier(requested_loc: int, *, lines_per_file: int) -> dict[str, Any]:
    root = Path(tempfile.mkdtemp(prefix=f"pqcensus-perf-{requested_loc}-"))
    try:
        file_count, actual_loc = _generate(root, requested_loc, lines_per_file=lines_per_file)
        started = time.perf_counter()
        result = audit(root)
        elapsed = max(time.perf_counter() - started, 1e-9)
        return {
            "requested_loc": requested_loc,
            "loc": actual_loc,
            "files": file_count,
            "files_analyzed": result.files_analyzed,
            "findings": len(result.findings),
            "wall_clock_seconds": elapsed,
            "files_per_second": file_count / elapsed,
            "loc_per_second": actual_loc / elapsed,
            "peak_rss_mib": _peak_rss_mib(),
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Gate deterministic PQCensus repository-scan scaling without executing target code."
    )
    parser.add_argument(
        "--loc",
        action="append",
        type=int,
        dest="loc_tiers",
        help="requested LOC tier; may be repeated (default: 100000)",
    )
    parser.add_argument("--lines-per-file", type=int, default=500)
    parser.add_argument("--min-loc-per-second", type=float, default=1000.0)
    parser.add_argument("--min-files-per-second", type=float, default=1.0)
    parser.add_argument("--max-peak-rss-mib", type=float, default=1024.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    tiers = args.loc_tiers or [100_000]
    if any(value < 1_000 or value > 2_000_000 for value in tiers):
        parser.error("each --loc tier must be between 1,000 and 2,000,000")
    if not 50 <= args.lines_per_file <= 2_000:
        parser.error("--lines-per-file must be between 50 and 2,000")
    if args.min_loc_per_second < 0 or args.min_files_per_second < 0:
        parser.error("minimum throughput thresholds cannot be negative")
    if args.max_peak_rss_mib <= 0:
        parser.error("--max-peak-rss-mib must be positive")

    results = [run_tier(value, lines_per_file=args.lines_per_file) for value in tiers]
    failures: list[str] = []
    for tier in results:
        label = f"{tier['requested_loc']:,} LOC"
        print(
            f"{label}: {tier['files_per_second']:.2f} files/s, "
            f"{tier['loc_per_second']:.2f} LOC/s, "
            f"{tier['peak_rss_mib']:.2f} MiB peak RSS, "
            f"{tier['wall_clock_seconds']:.2f}s"
        )
        if tier["files_analyzed"] != tier["files"]:
            failures.append(
                f"{label}: analyzed {tier['files_analyzed']} files but generated {tier['files']}"
            )
        if tier["loc_per_second"] < args.min_loc_per_second:
            failures.append(
                f"{label}: {tier['loc_per_second']:.2f} LOC/s below "
                f"{args.min_loc_per_second:.2f} LOC/s"
            )
        if tier["files_per_second"] < args.min_files_per_second:
            failures.append(
                f"{label}: {tier['files_per_second']:.2f} files/s below "
                f"{args.min_files_per_second:.2f} files/s"
            )
        if tier["peak_rss_mib"] > args.max_peak_rss_mib:
            failures.append(
                f"{label}: {tier['peak_rss_mib']:.2f} MiB peak RSS exceeds "
                f"{args.max_peak_rss_mib:.2f} MiB"
            )

    payload = {
        "schema_version": 1,
        "method": "deterministic generated Python corpus; target source is parsed as data and never executed",
        "thresholds": {
            "min_loc_per_second": args.min_loc_per_second,
            "min_files_per_second": args.min_files_per_second,
            "max_peak_rss_mib": args.max_peak_rss_mib,
        },
        "tiers": results,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    if failures:
        print("FAIL performance gate")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("PASS performance gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
