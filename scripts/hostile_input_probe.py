from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from quantumguard import audit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Exercise scanner file-enumeration bounds with many tiny files."
    )
    parser.add_argument("--files", type=int, default=100_000)
    parser.add_argument("--max-files", type=int, default=10_000)
    args = parser.parse_args(argv)
    if args.files <= 0 or args.max_files <= 0:
        parser.error("--files and --max-files must be positive")
    with tempfile.TemporaryDirectory(prefix="pqcensus-hostile-files-") as directory:
        root = Path(directory)
        for index in range(args.files):
            (root / f"source-{index:06d}.py").write_text("value = 1\n", encoding="utf-8")
        result = audit(root, max_files=args.max_files)
    skipped = result.limits["skipped"]
    if result.files_analyzed > args.max_files or skipped["file_limit"] == 0:
        print("FAIL hostile input probe: file enumeration bound was not enforced")
        return 1
    print(
        "PASS hostile input probe: "
        f"created={args.files}, analyzed={result.files_analyzed}, "
        f"file_limit_skips={skipped['file_limit']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
