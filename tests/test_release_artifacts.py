from __future__ import annotations

from pathlib import Path

from scripts.generate_release_artifacts import main as generate_release_artifacts
from scripts.validate_release_artifacts import main as validate_release_artifacts


def test_release_artifact_manifest_binds_exact_files(tmp_path: Path) -> None:
    wheel = tmp_path / "pqcensus-0.1.0-py3-none-any.whl"
    sdist = tmp_path / "pqcensus-0.1.0.tar.gz"
    wheel.write_bytes(b"wheel bytes")
    sdist.write_bytes(b"sdist bytes")
    assert (
        generate_release_artifacts(
            [
                "--dist",
                str(tmp_path),
                "--version",
                "0.1.0",
                "--source-commit",
                "a" * 40,
                "--evidence-commit",
                "b" * 40,
                "--workflow",
                "test workflow",
                "--run-id",
                "123",
            ]
        )
        == 0
    )
    assert validate_release_artifacts(["--dist", str(tmp_path), "--version", "0.1.0"]) == 0
