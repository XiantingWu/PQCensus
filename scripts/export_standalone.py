from __future__ import annotations

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IGNORED = shutil.ignore_patterns(
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".coverage",
    "coverage.xml",
    "coverage.json",
    "htmlcov",
    ".DS_Store",
    "*.py[cod]",
    "dist",
    "build",
    "*.egg-info",
    ".venv",
    "venv",
    "pqcensus-results",
    "quantumguard-results",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Copy PQCensus as an independent repository root.")
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    source = args.source.resolve()
    destination = args.destination.resolve()
    if not source.is_dir() or source.is_symlink():
        parser.error("source must be a regular directory")
    if destination == source or source in destination.parents:
        parser.error("destination must not be the source or inside it")
    if destination.exists():
        if not args.force:
            parser.error(
                "destination exists; pass --force only for an explicitly disposable destination"
            )
        if destination.is_symlink() or not destination.is_dir():
            parser.error("existing destination must be a real directory")
        shutil.rmtree(destination)
    shutil.copytree(source, destination, ignore=IGNORED)
    print(f"PASS standalone export: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
