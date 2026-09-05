from __future__ import annotations

import argparse
import tarfile
from pathlib import Path, PurePosixPath

FORBIDDEN_PREFIXES = (
    "benchmarks/",
    "tests/",
    ".github/",
    "docs/",
    "examples/",
    "scripts/",
)
REQUIRED_PATHS = {
    "LICENSE",
    "README.md",
    "pyproject.toml",
    "rules/quantumguard-rules.json",
    "schemas/finding.schema.json",
    "src/pqcensus/__init__.py",
    "src/pqcensus/py.typed",
    "src/quantumguard/__init__.py",
    "src/quantumguard/py.typed",
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate the PQCensus source-distribution surface."
    )
    parser.add_argument("sdist", type=Path)
    args = parser.parse_args()
    archive = args.sdist.resolve()
    if archive.is_symlink() or not archive.is_file():
        parser.error("sdist must be a regular archive file")

    failures: list[str] = []
    relative_paths: set[str] = set()
    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            members = tar.getmembers()
            roots = {
                PurePosixPath(member.name).parts[0]
                for member in members
                if PurePosixPath(member.name).parts
            }
            if len(roots) != 1:
                failures.append(f"sdist must have one root directory, found {sorted(roots)}")
                root = None
            else:
                root = next(iter(roots))
            for member in members:
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts:
                    failures.append(f"unsafe archive member: {member.name}")
                    continue
                if member.issym() or member.islnk():
                    failures.append(f"sdist must not contain links: {member.name}")
                if root and path.parts and path.parts[0] == root:
                    relative = PurePosixPath(*path.parts[1:]).as_posix()
                    if relative and relative != ".":
                        relative_paths.add(relative)
    except (OSError, tarfile.TarError) as exc:
        print(f"FAIL sdist surface: {exc}")
        return 1

    for prefix in FORBIDDEN_PREFIXES:
        leaked = sorted(path for path in relative_paths if path.startswith(prefix))
        if leaked:
            failures.append(f"forbidden source-tree material in sdist under {prefix}: {leaked[:3]}")
    missing = sorted(REQUIRED_PATHS - relative_paths)
    if missing:
        failures.append(f"required package source missing from sdist: {missing}")

    if failures:
        print("FAIL sdist surface")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"PASS sdist surface: {archive.name} ({len(relative_paths)} members)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
