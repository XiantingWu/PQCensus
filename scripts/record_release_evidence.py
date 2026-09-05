from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRODUCT_NAME = "PQCensus"
DISTRIBUTION_NAME = "pqcensus"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run release gates and record version-bound evidence."
    )
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--replace-existing",
        action="store_true",
        help="transactionally replace existing pre-release evidence after every gate and benchmark rerun passes",
    )
    args = parser.parse_args()
    version = _version()
    if args.version != version:
        parser.error(f"requested version {args.version} does not match package version {version}")
    if _git_dirty():
        print("FAIL: commit source changes before recording release evidence")
        return 1

    source_commit = _git_head()
    declared_source_head = os.environ.get("PQCENSUS_SOURCE_HEAD_SHA")
    if declared_source_head and declared_source_head != source_commit:
        print(
            "FAIL: declared PQCensus source head does not match checked-out source: "
            f"{declared_source_head} != {source_commit}"
        )
        return 1

    release_dir = ROOT / "benchmarks" / "releases" / version
    staging_dir = release_dir.with_name(f".{version}.evidence-next")
    backup_dir = release_dir.with_name(f".{version}.evidence-prev")
    for path, label in (
        (release_dir, "release evidence"),
        (staging_dir, "staging evidence"),
        (backup_dir, "backup evidence"),
    ):
        if path.is_symlink():
            print(f"FAIL: {label} path must not be a symlink: {path}")
            return 1
    if release_dir.exists() and not args.replace_existing:
        print(f"FAIL: evidence directory already exists: {release_dir}")
        return 1

    gate = subprocess.run(
        [sys.executable, str(ROOT / "scripts/release_check.py")], cwd=ROOT, text=True
    )
    if gate.returncode:
        print("FAIL: release_check did not pass; no evidence was written")
        return gate.returncode

    _remove_tree(staging_dir)
    _remove_tree(backup_dir)
    staging_dir.mkdir(parents=True)

    synthetic = staging_dir / "synthetic-results.json"
    real = staging_dir / "real-code-results.json"
    end_to_end = staging_dir / "end-to-end-results.json"
    commands = (
        [
            sys.executable,
            "scripts/run_quantumguardbench.py",
            "--manifest",
            "benchmarks/quantumguardbench.json",
            "--official-sarif",
            "--require-precision",
            "0.98",
            "--require-recall",
            "0.95",
            "--output",
            str(synthetic),
        ],
        [
            sys.executable,
            "scripts/run_quantumguardbench.py",
            "--manifest",
            "benchmarks/real-code.json",
            "--official-sarif",
            "--require-precision",
            "0.95",
            "--require-recall",
            "0.95",
            "--output",
            str(real),
        ],
        [
            sys.executable,
            "scripts/run_end_to_end.py",
            "--manifest",
            "benchmarks/end-to-end.json",
            "--official-sarif",
            "--output",
            str(end_to_end),
        ],
    )
    try:
        for command in commands:
            completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
            if completed.returncode:
                print(completed.stdout)
                print(completed.stderr)
                print("FAIL: evidence benchmark rerun")
                return completed.returncode

        manifest = {
            "schema_version": 1,
            "verdict": "RELEASE_GATES_PASSED",
            "product": PRODUCT_NAME,
            "distribution": DISTRIBUTION_NAME,
            "version": version,
            "source_commit": source_commit,
            "source_sha256": _source_fingerprint(),
            "rules_sha256": _sha(ROOT / "rules/quantumguard-rules.json"),
            "synthetic_corpus_sha256": _result(synthetic)["corpus_sha256"],
            "real_corpus_sha256": _result(real)["corpus_sha256"],
            "end_to_end_corpus_sha256": _result(end_to_end)["corpus_sha256"],
            "synthetic_result_sha256": _sha(synthetic),
            "real_result_sha256": _sha(real),
            "end_to_end_result_sha256": _sha(end_to_end),
            "scanner_version": _result(synthetic)["scanner_version"],
            "recorded_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "environment": {
                "python": sys.version,
                "implementation": platform.python_implementation(),
                "platform": platform.platform(),
                "machine": platform.machine(),
            },
            "toolchain": {
                "build": _distribution_version("build"),
                "cyclonedx-python-lib": _distribution_version("cyclonedx-python-lib"),
                "hatchling": _distribution_version("hatchling"),
                "jsonschema": _distribution_version("jsonschema"),
                "mypy": _distribution_version("mypy"),
                "pytest": _distribution_version("pytest"),
                "twine": _distribution_version("twine"),
                "zizmor": _distribution_version("zizmor"),
                "uv": _command_semantic_version(["uv", "--version"]),
            },
            "provenance": {
                "source_head_sha": declared_source_head or source_commit,
            },
            "gate_commands": [
                "python scripts/release_check.py",
                "python scripts/run_quantumguardbench.py --manifest benchmarks/quantumguardbench.json --official-sarif --require-precision 0.98 --require-recall 0.95",
                "python scripts/run_quantumguardbench.py --manifest benchmarks/real-code.json --official-sarif --require-precision 0.95 --require-recall 0.95",
                "python scripts/run_end_to_end.py --manifest benchmarks/end-to-end.json --official-sarif",
            ],
        }
        (staging_dir / "release-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        _commit_staged_evidence(release_dir, staging_dir, backup_dir)
        print(f"PASS release evidence: {release_dir}")
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0
    finally:
        _remove_tree(staging_dir)
        if backup_dir.exists() and not release_dir.exists():
            backup_dir.replace(release_dir)
        _remove_tree(backup_dir)


def _commit_staged_evidence(release_dir: Path, staging_dir: Path, backup_dir: Path) -> None:
    had_existing = release_dir.exists()
    if had_existing:
        release_dir.replace(backup_dir)
    try:
        staging_dir.replace(release_dir)
    except BaseException:
        if had_existing and backup_dir.exists() and not release_dir.exists():
            backup_dir.replace(release_dir)
        raise
    else:
        _remove_tree(backup_dir)


def _remove_tree(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"refusing to remove symlinked evidence path: {path}")
    if path.exists():
        shutil.rmtree(path)


def _distribution_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "not-installed"


def _command_semantic_version(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    value = (completed.stdout or completed.stderr).strip()
    parts = value.split()
    return parts[1] if len(parts) >= 2 else value


def _version() -> str:
    namespace: dict[str, object] = {}
    exec((ROOT / "src/quantumguard/_version.py").read_text(encoding="utf-8"), namespace)
    return str(namespace["__version__"])


def _git_head() -> str:
    return subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()


def _git_dirty() -> bool:
    result = subprocess.check_output(
        ["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all"],
        text=True,
    )
    dirty = []
    release_prefix = f"benchmarks/releases/{_version()}/"
    staging_prefix = f"benchmarks/releases/.{_version()}.evidence-next/"
    backup_prefix = f"benchmarks/releases/.{_version()}.evidence-prev/"
    for line in result.splitlines():
        path = line[3:].strip() if len(line) >= 4 else ""
        if path.startswith((release_prefix, staging_prefix, backup_prefix)):
            continue
        dirty.append(line)
    return bool(dirty)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _result(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _source_fingerprint() -> str:
    sys.path.insert(0, str(ROOT / "scripts"))
    from release_source_check import source_fingerprint

    return source_fingerprint(ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
