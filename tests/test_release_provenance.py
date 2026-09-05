from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import scripts.record_release_evidence as recorder
import scripts.release_source_check as source_check
from scripts.release_source_check import ROOT, current_identity, release_source_files


def test_release_source_set_binds_runtime_gates_and_security_contract() -> None:
    paths = {path.relative_to(ROOT).as_posix() for path in release_source_files(ROOT)}
    assert ".gitattributes" in paths
    assert ".gitignore" in paths
    assert "pyproject.toml" in paths
    assert "action.yml" in paths
    assert not any(path.startswith(".github/") for path in paths)
    assert "scripts/release_check.py" in paths
    assert "scripts/record_release_evidence.py" in paths
    assert "src/quantumguard/cli.py" in paths
    assert "rules/quantumguard-rules.json" in paths
    assert "benchmarks/test-key-allowlist.json" in paths
    assert "src/pqcensus/py.typed" in paths
    assert "src/quantumguard/py.typed" in paths
    assert "benchmarks/quantumguardbench.json" in paths
    assert any(path.startswith("benchmarks/corpus/end-to-end/") for path in paths)
    assert "README.md" not in paths
    assert "docs/DEPENDENCY_REVIEW.md" in paths
    assert "docs/LIMITATIONS.md" in paths
    assert "docs/MAINTAINERS.md" in paths
    assert "docs/OSPS_BASELINE.md" in paths
    assert "docs/RELEASE_ARTIFACTS.md" in paths
    assert "docs/VERIFY_RELEASE.md" in paths
    assert not any(path.startswith("benchmarks/releases/") for path in paths)

    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert "* text=auto eol=lf" in attributes
    assert (
        "benchmarks/corpus/** -text "
        "whitespace=-blank-at-eol,-blank-at-eof,-conflict-marker,cr-at-eol"
    ) in attributes


def test_current_identity_uses_live_benchmark_inputs_not_development_result_cache() -> None:
    identity = current_identity(ROOT)
    assert identity["synthetic_corpus_sha256"] == source_check._benchmark_corpus_sha(
        ROOT / "benchmarks/quantumguardbench.json", ROOT
    )
    assert identity["real_corpus_sha256"] == source_check._benchmark_corpus_sha(
        ROOT / "benchmarks/real-code.json", ROOT
    )
    assert identity["end_to_end_corpus_sha256"] == source_check._end_to_end_corpus_sha(
        ROOT / "benchmarks/end-to-end.json", ROOT
    )

    # Development result files are ignored reporting caches, not identity
    # authorities. They are intentionally absent from a clean source tree;
    # release evidence is generated only under benchmarks/releases/<version>.
    assert not (ROOT / "benchmarks/latest-results.json").exists()
    assert not (ROOT / "benchmarks/real-code-results.json").exists()
    assert not (ROOT / "benchmarks/end-to-end-results.json").exists()


def test_release_recorder_git_helpers_use_standalone_root(tmp_path: Path, monkeypatch) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "pqcensus-test@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "PQCensus Test"], check=True)
    version_file = tmp_path / "src/quantumguard/_version.py"
    version_file.parent.mkdir(parents=True)
    version_file.write_text('__version__ = "0.1.0"\n', encoding="utf-8")
    (tmp_path / "tracked.txt").write_text("stable\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "fixture"], check=True)

    monkeypatch.setattr(recorder, "ROOT", tmp_path)
    expected = subprocess.check_output(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"], text=True
    ).strip()
    assert recorder._git_head() == expected
    assert recorder._git_dirty() is False

    release_file = tmp_path / "benchmarks/releases/0.1.0/release-manifest.json"
    release_file.parent.mkdir(parents=True)
    release_file.write_text("{}\n", encoding="utf-8")
    assert recorder._git_dirty() is False

    (tmp_path / "tracked.txt").write_text("changed\n", encoding="utf-8")
    assert recorder._git_dirty() is True


def test_evidence_commit_transaction_replaces_complete_directory(tmp_path: Path) -> None:
    release = tmp_path / "0.1.0"
    staging = tmp_path / ".0.1.0.evidence-next"
    backup = tmp_path / ".0.1.0.evidence-prev"
    release.mkdir()
    staging.mkdir()
    (release / "old.json").write_text("old\n", encoding="utf-8")
    (staging / "new.json").write_text("new\n", encoding="utf-8")

    recorder._commit_staged_evidence(release, staging, backup)

    assert (release / "new.json").read_text(encoding="utf-8") == "new\n"
    assert not (release / "old.json").exists()
    assert not staging.exists()
    assert not backup.exists()


def test_evidence_commit_transaction_restores_previous_directory_on_failure(
    tmp_path: Path, monkeypatch
) -> None:
    release = tmp_path / "0.1.0"
    staging = tmp_path / ".0.1.0.evidence-next"
    backup = tmp_path / ".0.1.0.evidence-prev"
    release.mkdir()
    staging.mkdir()
    (release / "old.json").write_text("old\n", encoding="utf-8")
    (staging / "new.json").write_text("new\n", encoding="utf-8")

    original_replace = Path.replace

    def fail_staging_replace(self: Path, target: Path) -> Path:
        if self == staging and Path(target) == release:
            raise OSError("simulated evidence rename failure")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_staging_replace)
    with pytest.raises(OSError, match="simulated evidence rename failure"):
        recorder._commit_staged_evidence(release, staging, backup)

    assert (release / "old.json").read_text(encoding="utf-8") == "old\n"
    assert not backup.exists()
    assert staging.exists()


def test_committed_result_files_are_cryptographically_bound_to_manifest(tmp_path: Path) -> None:
    evidence = tmp_path / "0.1.0"
    evidence.mkdir()
    corpora = {
        "synthetic-results.json": "synthetic-corpus",
        "real-code-results.json": "real-corpus",
        "end-to-end-results.json": "end-to-end-corpus",
    }
    for filename, corpus_sha in corpora.items():
        (evidence / filename).write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "scanner_version": "0.1.0",
                    "corpus_sha256": corpus_sha,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    manifest = {
        "scanner_version": "0.1.0",
        "synthetic_corpus_sha256": corpora["synthetic-results.json"],
        "real_corpus_sha256": corpora["real-code-results.json"],
        "end_to_end_corpus_sha256": corpora["end-to-end-results.json"],
        "synthetic_result_sha256": source_check._sha(evidence / "synthetic-results.json"),
        "real_result_sha256": source_check._sha(evidence / "real-code-results.json"),
        "end_to_end_result_sha256": source_check._sha(evidence / "end-to-end-results.json"),
    }
    failures: list[str] = []
    source_check._validate_evidence_files(evidence, manifest, failures)
    assert failures == []

    (evidence / "synthetic-results.json").write_text("{}\n", encoding="utf-8")
    failures = []
    source_check._validate_evidence_files(evidence, manifest, failures)
    assert "release evidence result hash mismatch: synthetic-results.json" in failures
    assert "release evidence scanner version mismatch: synthetic-results.json" in failures
    assert "release evidence corpus identity mismatch: synthetic-results.json" in failures


def test_manifest_contract_accepts_clean_release_manifest() -> None:
    manifest = {
        "product": "PQCensus",
        "distribution": "pqcensus",
        "verdict": "RELEASE_GATES_PASSED",
        "toolchain": {key: "1.0.0" for key in source_check.REQUIRED_TOOLCHAIN_KEYS},
    }
    failures: list[str] = []
    source_check._validate_manifest_contract(manifest, failures)
    assert failures == []


def test_manifest_contract_rejects_forbidden_provenance_keys() -> None:
    manifest = {
        "product": "PQCensus",
        "distribution": "pqcensus",
        "verdict": "RELEASE_GATES_PASSED",
        "provenance": {"runner_name": "host-123"},
        "toolchain": {key: "1.0.0" for key in source_check.REQUIRED_TOOLCHAIN_KEYS},
    }
    failures: list[str] = []
    source_check._validate_manifest_contract(manifest, failures)
    assert any("runner_name" in item for item in failures)
