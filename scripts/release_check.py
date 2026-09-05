from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the PQCensus release candidate gates.")
    parser.add_argument(
        "--skip-standalone", action="store_true", help="only for the extracted-root child check"
    )
    args = parser.parse_args()
    temp_root = Path(tempfile.mkdtemp(prefix="pqcensus-release-"))
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    failures: list[str] = []

    def check(
        label: str,
        command: list[str],
        *,
        cwd: Path = ROOT,
        timeout: int = 300,
        custom_env: dict[str, str] | None = None,
    ) -> bool:
        run_env = env | (custom_env or {})
        try:
            completed = subprocess.run(
                command, cwd=cwd, env=run_env, text=True, capture_output=True, timeout=timeout
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            failures.append(f"{label}: {exc}")
            return False
        if completed.returncode:
            detail = (completed.stdout + "\n" + completed.stderr).strip()[-3000:]
            failures.append(f"{label} (exit {completed.returncode}):\n{detail}")
            return False
        print(f"PASS {label}")
        return True

    check("launch surface", [sys.executable, "scripts/launch_surface_check.py"])
    check("ruff check", [sys.executable, "-m", "ruff", "check", "src", "tests", "scripts"])
    check(
        "ruff format",
        [sys.executable, "-m", "ruff", "format", "--check", "src", "tests", "scripts"],
    )
    check("mypy typing", [sys.executable, "-m", "mypy"])
    check(
        "public consumer typing smoke",
        [sys.executable, "-m", "mypy", "tests/test_typing_surface.py"],
    )
    check(
        "test-key allowlist",
        [sys.executable, "scripts/validate_test_key_allowlist.py"],
    )
    check(
        "third-party notices",
        [sys.executable, "scripts/validate_third_party_notices.py"],
    )
    check(
        "action security contract",
        [sys.executable, "scripts/action_security_check.py"],
    )
    zizmor = Path(sys.executable).with_name("zizmor")
    if not zizmor.is_file() and os.name == "nt":
        zizmor = zizmor.with_suffix(".exe")
    if zizmor.is_file():
        check(
            "zizmor action security",
            [str(zizmor), "--pedantic", "action.yml"],
            timeout=120,
        )
    coverage_report = temp_root / "coverage.json"
    if check(
        "full tests with branch coverage",
        [
            sys.executable,
            "-m",
            "pytest",
            "--cov=quantumguard",
            "--cov=pqcensus",
            "--cov-branch",
            "--cov-report=term-missing",
            f"--cov-report=json:{coverage_report}",
        ],
        timeout=360,
    ):
        check(
            "coverage thresholds",
            [
                sys.executable,
                "scripts/coverage_gate.py",
                "--report",
                str(coverage_report),
                "--min-statement",
                "90",
                "--min-branch",
                "80",
            ],
        )
    check("doctor strict", [sys.executable, "-m", "pqcensus", "doctor", "--strict", "--json"])
    check("legacy module compatibility", [sys.executable, "-m", "quantumguard", "--version"])

    example_dir = temp_root / "examples"
    if check(
        "vulnerable example",
        [
            sys.executable,
            "-m",
            "pqcensus",
            "audit",
            "examples/vulnerable-app",
            "--fail-on",
            "none",
            "--quiet",
            "--output",
            str(example_dir / "vulnerable"),
        ],
    ):
        check(
            "pqc-aware example",
            [
                sys.executable,
                "-m",
                "pqcensus",
                "audit",
                "examples/pqc-aware",
                "--fail-on",
                "none",
                "--quiet",
                "--output",
                str(example_dir / "pqc-aware"),
            ],
        )
        check(
            "official SARIF",
            [
                sys.executable,
                "scripts/validate_sarif.py",
                str(example_dir / "vulnerable/quantumguard.sarif"),
            ],
            timeout=60,
        )
        check(
            "CycloneDX 1.7",
            [
                sys.executable,
                "scripts/validate_cyclonedx.py",
                str(example_dir / "vulnerable/quantumguard-cbom.cdx.json"),
            ],
            timeout=60,
        )

    synthetic_result = temp_root / "synthetic-results.json"
    real_result = temp_root / "real-code-results.json"
    end_to_end_result = temp_root / "end-to-end-results.json"
    if check(
        "synthetic benchmark",
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
            str(synthetic_result),
        ],
        timeout=360,
    ):
        _require_result(synthetic_result, failures, expected_findings=True)
    if check(
        "curated real-code benchmark",
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
            str(real_result),
        ],
        timeout=240,
    ):
        _require_result(real_result, failures, expected_findings=True)
    if check(
        "end-to-end public repositories",
        [
            sys.executable,
            "scripts/run_end_to_end.py",
            "--manifest",
            "benchmarks/end-to-end.json",
            "--official-sarif",
            "--output",
            str(end_to_end_result),
        ],
        timeout=600,
    ):
        _require_end_to_end(end_to_end_result, failures)
    check("release source identity", [sys.executable, "scripts/release_source_check.py"])

    dist = temp_root / "dist"
    if check("package build", [sys.executable, "-m", "build", "--outdir", str(dist)], timeout=300):
        check(
            "twine metadata",
            [
                sys.executable,
                "-m",
                "twine",
                "check",
                *[str(path) for path in sorted(dist.iterdir())],
            ],
            timeout=120,
        )
        sdists = sorted(dist.glob("pqcensus-*.tar.gz"))
        if len(sdists) == 1:
            check(
                "sdist package surface",
                [sys.executable, "scripts/validate_sdist.py", str(sdists[0])],
                timeout=60,
            )
        else:
            failures.append(
                f"sdist surface: expected exactly one pqcensus sdist, found {len(sdists)}"
            )
        wheels = sorted(dist.glob("pqcensus-*.whl"))
        if len(wheels) == 1:
            version = _version()
            current_commit = _git_head()
            if current_commit is None:
                print(
                    "SKIP release SBOM and artifact manifest: standalone export has no Git metadata"
                )
            else:
                artifact_dist = check(
                    "release SBOM and artifact manifest",
                    [
                        sys.executable,
                        "scripts/generate_release_artifacts.py",
                        "--dist",
                        str(dist),
                        "--version",
                        version,
                        "--source-commit",
                        current_commit,
                        "--evidence-commit",
                        current_commit,
                        "--workflow",
                        "PQCensus local release check",
                        "--run-id",
                        "0",
                    ],
                    timeout=120,
                )
                if artifact_dist:
                    check(
                        "release artifact manifest validation",
                        [
                            sys.executable,
                            "scripts/validate_release_artifacts.py",
                            "--dist",
                            str(dist),
                            "--version",
                            version,
                        ],
                        timeout=60,
                    )
                    check(
                        "release SBOM schema",
                        [
                            sys.executable,
                            "scripts/validate_cyclonedx.py",
                            str(dist / f"pqcensus-{version}.cdx.json"),
                        ],
                        timeout=60,
                    )
            _clean_wheel_gate(wheels[0], temp_root, failures)
        else:
            failures.append(
                f"clean wheel: expected exactly one pqcensus wheel, found {len(wheels)}"
            )

    if not args.skip_standalone:
        standalone = temp_root / "standalone"
        if check(
            "standalone export",
            [sys.executable, "scripts/export_standalone.py", "--destination", str(standalone)],
        ):
            check(
                "standalone launch surface",
                [sys.executable, "scripts/launch_surface_check.py"],
                cwd=standalone,
            )
            check(
                "standalone release gates",
                [sys.executable, "scripts/release_check.py", "--skip-standalone"],
                cwd=standalone,
                timeout=900,
            )

    if failures:
        print("FAIL release_check")
        print("\n".join(f"- {item}" for item in failures))
        return 1
    print("PASS release_check")
    return 0


def _require_result(path: Path, failures: list[str], *, expected_findings: bool) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        schema = payload["schema_validation"]
        if not schema["cyclonedx_1_7"]["valid"] or not schema["sarif_2_1_0_official"]["valid"]:
            failures.append(f"benchmark schema gate failed: {path.name}")
        if expected_findings and payload["summary"]["precision"] < 0.95:
            failures.append(f"benchmark precision gate failed: {path.name}")
        if payload["migration_mapping"]["dangerous_cross_class_errors"]:
            failures.append(f"dangerous migration mapping: {path.name}")
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        failures.append(f"benchmark result unreadable {path.name}: {exc}")


def _version() -> str:
    import tomllib

    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(metadata["project"]["version"])


def _git_head() -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout.strip()


def _require_end_to_end(path: Path, failures: list[str]) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not payload["deterministic"]:
            failures.append("end-to-end benchmark is not deterministic")
        if payload["summary"]["observation_coverage"] < 1.0:
            failures.append("end-to-end benchmark observation coverage is incomplete")
        if not payload["schema_validation"]["cyclonedx_1_7"]["valid"]:
            failures.append("end-to-end CycloneDX validation failed")
        if not payload["schema_validation"]["sarif_2_1_0_official"]["valid"]:
            failures.append("end-to-end official SARIF validation failed")
        for case in payload["cases"]:
            if (
                case["parser_errors"]
                or case["dependencies"]["missing"]
                or case["observations"]["missing"]
            ):
                failures.append(f"end-to-end case incomplete: {case['id']}")
            if not case["minimum_findings"]["passed"]:
                failures.append(f"end-to-end finding minimum failed: {case['id']}")
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        failures.append(f"end-to-end result unreadable: {exc}")


def _clean_wheel_gate(wheel: Path, temp_root: Path, failures: list[str]) -> None:
    venv = temp_root / "wheel-venv"
    try:
        subprocess.run(
            [sys.executable, "-m", "venv", str(venv)],
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )
        python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        pqcensus = venv / ("Scripts/pqcensus.exe" if os.name == "nt" else "bin/pqcensus")
        legacy = venv / ("Scripts/quantumguard.exe" if os.name == "nt" else "bin/quantumguard")
        commands = [
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-deps",
                str(wheel),
            ],
            [str(python), "-m", "pip", "check"],
            [str(pqcensus), "--version"],
            [str(legacy), "--version"],
            [str(python), "-m", "pqcensus", "--version"],
            [str(python), "-m", "quantumguard", "--version"],
            [str(pqcensus), "doctor", "--strict"],
            [
                str(pqcensus),
                "audit",
                str(ROOT / "examples/vulnerable-app"),
                "--fail-on",
                "none",
                "--quiet",
                "--output",
                str(temp_root / "wheel-example"),
            ],
            [
                str(python),
                "-c",
                (
                    "import importlib.metadata, pqcensus, quantumguard; "
                    "assert importlib.metadata.version('pqcensus') == pqcensus.__version__ == quantumguard.__version__; "
                    "assert pqcensus.audit is quantumguard.audit; "
                    "assert pqcensus.inventory is quantumguard.inventory; "
                    "assert pqcensus.plan is quantumguard.plan"
                ),
            ],
        ]
        for command in commands:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
            if completed.returncode:
                failures.append(
                    f"clean wheel command failed: {' '.join(command)}\n{(completed.stdout + completed.stderr)[-2000:]}"
                )
                return
        print("PASS clean wheel install and PQCensus/public-namespace/legacy compatibility surface")
    except (OSError, subprocess.SubprocessError) as exc:
        failures.append(f"clean wheel install: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
