from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE_SOURCE_FILES = (
    ".gitattributes",
    ".gitignore",
    "pyproject.toml",
    "action.yml",
    "benchmarks/quantumguardbench.json",
    "benchmarks/real-code.json",
    "benchmarks/end-to-end.json",
    "benchmarks/end-to-end-provenance.json",
    "benchmarks/test-key-allowlist.json",
    "benchmarks/THIRD_PARTY_NOTICES.md",
    "benchmarks/third-party-corpus.json",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "docs/BENCHMARK_CORPUS_POLICY.md",
    "docs/COMPATIBILITY.md",
    "docs/DEPENDENCY_REVIEW.md",
    "docs/LIMITATIONS.md",
    "docs/MAINTAINERS.md",
    "docs/OSPS_BASELINE.md",
    "docs/PUBLISHING.md",
    "docs/RELEASE_ARTIFACTS.md",
    "docs/VERIFY_RELEASE.md",
    "src/pqcensus/py.typed",
    "src/quantumguard/py.typed",
)
RELEASE_SOURCE_GLOBS = (
    "src/pqcensus/**/*.py",
    "src/quantumguard/**/*.py",
    "scripts/*.py",
    "tests/**/*.py",
    "rules/*.json",
    "schemas/*.json",
    "examples/**/*",
    "benchmarks/corpus/synthetic/**/*",
    "benchmarks/corpus/real/**/*",
    "benchmarks/corpus/end-to-end/**/*",
)
REQUIRED_TOOLCHAIN_KEYS = {
    "build",
    "cyclonedx-python-lib",
    "hatchling",
    "jsonschema",
    "mypy",
    "pytest",
    "twine",
    "uv",
    "zizmor",
}
FORBIDDEN_PROVENANCE_KEYS = {
    "runner_name",
    "source_repository",
    "workflow_repository",
}
RESULT_EVIDENCE = {
    "synthetic-results.json": ("synthetic_result_sha256", "synthetic_corpus_sha256"),
    "real-code-results.json": ("real_result_sha256", "real_corpus_sha256"),
    "end-to-end-results.json": ("end_to_end_result_sha256", "end_to_end_corpus_sha256"),
}
CANONICAL_WORKFLOW = "PQCensus canonical release evidence"


def release_source_files(root: Path = ROOT) -> tuple[Path, ...]:
    root = root.resolve()
    selected: set[Path] = set()
    for relative in RELEASE_SOURCE_FILES:
        selected.add(_safe_regular(root, root / relative, relative))
    for pattern in RELEASE_SOURCE_GLOBS:
        for candidate in root.glob(pattern):
            if not candidate.is_file():
                continue
            relative = candidate.relative_to(root).as_posix()
            selected.add(_safe_regular(root, candidate, relative))
    if not selected:
        raise ValueError("release source set is empty")
    return tuple(sorted(selected, key=lambda path: path.relative_to(root).as_posix()))


def source_fingerprint(root: Path = ROOT) -> str:
    root = root.resolve()
    digest = hashlib.sha256()
    for path in release_source_files(root):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content_digest = hashlib.sha256(path.read_bytes()).digest()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(content_digest)
    return digest.hexdigest()


def current_identity(root: Path = ROOT) -> dict[str, str | None]:
    root = root.resolve()
    return {
        "version": _version(root),
        "source_sha256": source_fingerprint(root),
        "rules_sha256": _sha(root / "rules/quantumguard-rules.json"),
        "synthetic_corpus_sha256": _benchmark_corpus_sha(
            root / "benchmarks/quantumguardbench.json", root
        ),
        "real_corpus_sha256": _benchmark_corpus_sha(root / "benchmarks/real-code.json", root),
        "end_to_end_corpus_sha256": _end_to_end_corpus_sha(
            root / "benchmarks/end-to-end.json", root
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bind PQCensus release source, rules, benchmark inputs, and release toolchain."
    )
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--version")
    args = parser.parse_args()
    failures: list[str] = []
    version = _version(ROOT)
    if args.version and args.version != version:
        failures.append(f"version mismatch: expected {args.version}, found {version}")

    try:
        selected = release_source_files()
    except (OSError, ValueError) as exc:
        failures.append(f"release source set invalid: {exc}")
        selected = ()

    for path in selected:
        relative = path.relative_to(ROOT)
        if path.suffix == ".py" and relative.parts[:2] != ("benchmarks", "corpus"):
            text = path.read_text(encoding="utf-8")
            if re.search(r"(?:from|import)\s+Repository[123]", text):
                failures.append(f"sibling import: {relative}")

    try:
        current = (
            current_identity()
            if selected
            else {
                "version": version,
                "source_sha256": None,
                "rules_sha256": None,
                "synthetic_corpus_sha256": None,
                "real_corpus_sha256": None,
                "end_to_end_corpus_sha256": None,
            }
        )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        failures.append(f"release identity inputs are invalid: {exc}")
        current = {
            "version": version,
            "source_sha256": source_fingerprint() if selected else None,
            "rules_sha256": _sha(ROOT / "rules/quantumguard-rules.json"),
            "synthetic_corpus_sha256": None,
            "real_corpus_sha256": None,
            "end_to_end_corpus_sha256": None,
        }

    if args.evidence:
        evidence = args.evidence.resolve()
        try:
            evidence.relative_to(ROOT)
        except ValueError:
            failures.append("evidence path must stay inside the repository")
        manifest = evidence / "release-manifest.json"
        if manifest.is_symlink() or not manifest.is_file():
            failures.append("release-manifest.json is missing or unsafe")
        else:
            try:
                expected = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                failures.append(f"release-manifest.json is unreadable: {exc}")
            else:
                for key, value in current.items():
                    if expected.get(key) != value:
                        failures.append(f"evidence mismatch: {key}")
                _validate_manifest_contract(expected, failures)
                _validate_evidence_files(evidence, expected, failures)
                _validate_toolchain_matches(expected, failures)

    if failures:
        print("FAIL release source identity")
        print("\n".join(f"- {item}" for item in failures))
        return 1
    print(json.dumps(current, indent=2, sort_keys=True))
    print(f"PASS release source identity ({len(selected)} bound files)")
    return 0


def _validate_manifest_contract(manifest: object, failures: list[str]) -> None:
    if not isinstance(manifest, dict):
        failures.append("release manifest must be a JSON object")
        return
    if manifest.get("product") != "PQCensus" or manifest.get("distribution") != "pqcensus":
        failures.append("release manifest public identity is invalid")
    if manifest.get("verdict") != "RELEASE_GATES_PASSED":
        failures.append("release manifest verdict is not RELEASE_GATES_PASSED")
    provenance = manifest.get("provenance")
    if isinstance(provenance, dict):
        for key in sorted(FORBIDDEN_PROVENANCE_KEYS & provenance.keys()):
            failures.append(
                f"release manifest exposes repository/host-specific provenance field: {key}"
            )

    toolchain = manifest.get("toolchain")
    if not isinstance(toolchain, dict):
        failures.append("release manifest toolchain is missing or invalid")
    else:
        missing = REQUIRED_TOOLCHAIN_KEYS - toolchain.keys()
        for key in sorted(missing):
            failures.append(f"release manifest toolchain missing field: {key}")
        for key in sorted(REQUIRED_TOOLCHAIN_KEYS & toolchain.keys()):
            value = toolchain.get(key)
            if (
                not isinstance(value, str)
                or not value.strip()
                or value in {"not-installed", "unavailable"}
            ):
                failures.append(f"release manifest toolchain field is not reproducible: {key}")


def _validate_evidence_files(evidence: Path, manifest: object, failures: list[str]) -> None:
    if not isinstance(manifest, dict):
        return
    scanner_version = manifest.get("scanner_version")
    for filename, (result_hash_key, corpus_hash_key) in RESULT_EVIDENCE.items():
        path = evidence / filename
        if path.is_symlink() or not path.is_file():
            failures.append(f"release evidence result is missing or unsafe: {filename}")
            continue

        expected_hash = manifest.get(result_hash_key)
        if (
            not isinstance(expected_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
        ):
            failures.append(f"release manifest result hash is invalid: {result_hash_key}")
        elif _sha(path) != expected_hash:
            failures.append(f"release evidence result hash mismatch: {filename}")

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            failures.append(f"release evidence result is unreadable {filename}: {exc}")
            continue
        if not isinstance(payload, dict):
            failures.append(f"release evidence result must be a JSON object: {filename}")
            continue
        if payload.get("scanner_version") != scanner_version:
            failures.append(f"release evidence scanner version mismatch: {filename}")
        if payload.get("corpus_sha256") != manifest.get(corpus_hash_key):
            failures.append(f"release evidence corpus identity mismatch: {filename}")


def _validate_toolchain_matches(manifest: object, failures: list[str]) -> None:
    if not isinstance(manifest, dict):
        return
    expected = manifest.get("toolchain")
    if not isinstance(expected, dict):
        return
    actual = {
        "build": _distribution_version("build"),
        "cyclonedx-python-lib": _distribution_version("cyclonedx-python-lib"),
        "hatchling": _distribution_version("hatchling"),
        "jsonschema": _distribution_version("jsonschema"),
        "mypy": _distribution_version("mypy"),
        "pytest": _distribution_version("pytest"),
        "twine": _distribution_version("twine"),
        "zizmor": _distribution_version("zizmor"),
        "uv": _uv_version(),
    }
    for key in sorted(REQUIRED_TOOLCHAIN_KEYS):
        if expected.get(key) != actual.get(key):
            failures.append(
                f"release toolchain mismatch: {key}: evidence={expected.get(key)!r}, current={actual.get(key)!r}"
            )


def _distribution_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "not-installed"


def _uv_version() -> str:
    try:
        completed = subprocess.run(
            ["uv", "--version"],
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
    return parts[1] if len(parts) >= 2 and parts[0] == "uv" else value


def _safe_regular(root: Path, candidate: Path, label: str) -> Path:
    if candidate.is_symlink():
        raise ValueError(f"release source file must not be a symlink: {label}")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"release source path escapes root: {label}") from exc
    if not resolved.is_file():
        raise ValueError(f"release source file is missing or unsafe: {label}")
    return resolved


def _version(root: Path) -> str:
    namespace: dict[str, object] = {}
    exec((root / "src/quantumguard/_version.py").read_text(encoding="utf-8"), namespace)
    return str(namespace["__version__"])


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _benchmark_corpus_sha(manifest_path: Path, root: Path) -> str:
    manifest_path = manifest_path.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = manifest.get("cases")
    if not isinstance(cases, list):
        raise ValueError(f"benchmark manifest cases are invalid: {manifest_path.name}")
    scripts = str(root / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    from run_quantumguardbench import _corpus_digest

    return str(_corpus_digest(manifest_path, cases))


def _end_to_end_corpus_sha(manifest_path: Path, root: Path) -> str:
    scripts = str(root / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    from run_end_to_end import _corpus_digest

    return str(_corpus_digest(manifest_path.resolve()))


if __name__ == "__main__":
    raise SystemExit(main())
