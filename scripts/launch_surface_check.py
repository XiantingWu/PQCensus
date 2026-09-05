from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRODUCT_NAME = "PQCensus"
DISTRIBUTION_NAME = "pqcensus"
PRIMARY_CLI = "pqcensus"
LEGACY_CLI = "quantumguard"
CANONICAL_REPOSITORY = "https://github.com/XiantingWu/PQCensus"

REQUIRED = (
    "README.md",
    "pyproject.toml",
    "LICENSE",
    "SECURITY.md",
    "SUPPORT.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "CODE_OF_CONDUCT.md",
    "ROADMAP.md",
    "CITATION.cff",
    "CHANGELOG.md",
    "action.yml",
    ".gitattributes",
    ".gitignore",
    "benchmarks/THIRD_PARTY_NOTICES.md",
    "benchmarks/third-party-corpus.json",
    "scripts/validate_third_party_notices.py",
    "scripts/action_security_check.py",
    "scripts/generate_release_artifacts.py",
    "scripts/validate_release_artifacts.py",
    "scripts/hostile_input_probe.py",
    "benchmarks/test-key-allowlist.json",
    "rules/quantumguard-rules.json",
    "schemas/finding.schema.json",
    "scripts/coverage_gate.py",
    "scripts/performance_gate.py",
    "scripts/release_check.py",
    "scripts/validate_release_tag.py",
    "scripts/validate_sdist.py",
    "scripts/validate_test_key_allowlist.py",
    "docs/BENCHMARK_CORPUS_POLICY.md",
    "docs/COMPATIBILITY.md",
    "docs/DEPENDENCY_REVIEW.md",
    "docs/LIMITATIONS.md",
    "docs/MAINTAINERS.md",
    "docs/OSPS_BASELINE.md",
    "docs/RELEASE_ARTIFACTS.md",
    "docs/VERIFY_RELEASE.md",
    "src/pqcensus/__init__.py",
    "src/pqcensus/__main__.py",
    "src/pqcensus/py.typed",
    "src/quantumguard/__init__.py",
    "src/quantumguard/py.typed",
    "tests/test_typing_surface.py",
)

MUST_BE_ABSENT = (
    ".github",
    "benchmarks/releases/0.1.0",
    "docs/LAUNCH_READINESS_0.1.0.md",
    "docs/PUBLIC_RELEASE_CHECKLIST.md",
    "交接.md",
)

FORBIDDEN_PUBLIC_MARKERS = (
    "XiantingWu/" + "Repo4" + "-QuantumGuard",
    "Repo1-parity",
    "ActionsSelfHostedRunner",
    "Woods-M1-Experiments",
    "Woods2的MacBook",
)

EXPECTED_DEV_TOOLS = {
    "build==1.5.0",
    "coverage==7.15.4",
    "cyclonedx-python-lib[validation]==11.12.0",
    "hatchling==1.32.0",
    "jsonschema==4.26.0",
    "mypy==2.3.1",
    "pytest==9.1.1",
    "pytest-cov==7.1.0",
    "ruff==0.16.4",
    "twine==7.0.0",
    "zizmor==1.29.0",
}

EXPECTED_SDIST_INCLUDE = {
    "/src",
    "/rules",
    "/schemas",
    "/README.md",
    "/LICENSE",
    "/pyproject.toml",
}

LINK_RE = re.compile(r"\]\(([^)]+)\)")
USES_RE = re.compile(r"(?m)^\s*uses:\s*([^\s#]+)")
BAD_MARKERS = ("TODO", "FIXME", "PLACEHOLDER", "your-domain")
LOCAL_PATH_MARKERS = (
    "/" + "Users/",
    "/" + "home/",
    "C:" + "\\Users\\",
    "D:" + "\\Users\\",
)

OLD_PLATFORM_PATTERNS = (
    re.compile("135" + "0941152"),
    re.compile("135" + "8615613"),
    re.compile(r"\b" + "PQCensus2" + r"\b"),
    re.compile(r"\b" + "PQCensus3" + r"\b"),
    re.compile("github_actions_" + "run_id"),
    re.compile(r"actions/runs/[0-9]+"),
    re.compile(r"/pull/[0-9]+"),
    re.compile(r"pull request #[0-9]+", re.IGNORECASE),
    re.compile(r"\bPR #[0-9]+\b", re.IGNORECASE),
    re.compile("find" + "woods", re.IGNORECASE),
    re.compile("dependa" + r"bot\[bot\]", re.IGNORECASE),
    re.compile("github-actions" + r"\[bot\]", re.IGNORECASE),
    re.compile(r"\bweb-" + r"flow\b", re.IGNORECASE),
    re.compile(r"Co-authored-by", re.IGNORECASE),
    re.compile("22ce50cb5fadbef8fcb6e00b30723bf18a540f8e"),
    re.compile("1107596a9db3667ed59bd2ad2ab7836587fcb7b4"),
    re.compile(r"public pull.?request workflow", re.IGNORECASE),
    re.compile(r"public PR workflow", re.IGNORECASE),
    re.compile(r"github-hosted runner", re.IGNORECASE),
    re.compile(r"pull requests disabled", re.IGNORECASE),
)


def main() -> int:
    failures: list[str] = []

    # Required files
    for name in REQUIRED:
        path = ROOT / name
        if not path.is_file() or path.is_symlink():
            failures.append(f"missing regular file: {name}")

    # Files and directories that MUST be absent in the clean-room rebuild
    for name in MUST_BE_ABSENT:
        path = ROOT / name
        if path.exists():
            failures.append(f"forbidden file or directory must be absent: {name}")

    version = _version()
    try:
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = metadata["project"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        failures.append(f"invalid pyproject metadata: {exc}")
        metadata = {}
        project = {}
    if project.get("name") != DISTRIBUTION_NAME:
        failures.append(f"distribution name must be {DISTRIBUTION_NAME}")
    if str(project.get("version")) != version:
        failures.append("package and source versions differ")
    scripts = project.get("scripts", {}) if isinstance(project, dict) else {}
    expected_entrypoint = "quantumguard.cli:main"
    if scripts.get(PRIMARY_CLI) != expected_entrypoint:
        failures.append(f"primary CLI {PRIMARY_CLI} is missing or miswired")
    if scripts.get(LEGACY_CLI) != expected_entrypoint:
        failures.append(f"compatibility CLI {LEGACY_CLI} is missing or miswired")

    try:
        build_requires = metadata["build-system"]["requires"]
    except (KeyError, TypeError):
        build_requires = []
    if build_requires != ["hatchling==1.32.0"]:
        failures.append("PEP 517 build backend must remain exactly pinned to hatchling==1.32.0")
    dev_tools = (
        set(project.get("optional-dependencies", {}).get("dev", []))
        if isinstance(project, dict)
        else set()
    )
    if dev_tools != EXPECTED_DEV_TOOLS:
        failures.append(
            "direct release/dev toolchain must remain exactly pinned to the reviewed versions"
        )
    try:
        sdist_include = set(metadata["tool"]["hatch"]["build"]["targets"]["sdist"]["include"])
    except (KeyError, TypeError):
        sdist_include = set()
    if sdist_include != EXPECTED_SDIST_INCLUDE:
        failures.append(
            "PyPI sdist must remain limited to package source, rules, schemas, README, LICENSE, and pyproject"
        )

    urls = project.get("urls", {}) if isinstance(project, dict) else {}
    if (
        urls.get("Homepage") != CANONICAL_REPOSITORY
        or urls.get("Repository") != CANONICAL_REPOSITORY
    ):
        failures.append("pyproject canonical Homepage/Repository must point to XiantingWu/PQCensus")
    for key in ("Issues", "Documentation", "Changelog", "Security"):
        value = str(urls.get(key, ""))
        if value and not value.startswith(CANONICAL_REPOSITORY):
            failures.append(
                f"pyproject {key} URL must stay under the canonical PQCensus repository"
            )

    try:
        packages = metadata["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
    except (KeyError, TypeError):
        packages = []
    required_packages = {"src/pqcensus", "src/quantumguard"}
    if not isinstance(packages, list) or not required_packages.issubset(set(packages)):
        failures.append(
            "wheel must include both public pqcensus and compatibility quantumguard packages"
        )

    citation = _read_text("CITATION.cff", failures)
    if citation:
        for field in ("repository-code", "url"):
            if f'{field}: "{CANONICAL_REPOSITORY}"' not in citation:
                failures.append(f"CITATION.cff {field} must point to canonical PQCensus repository")
        if "Xianting Wu" not in citation:
            failures.append("CITATION.cff author must be Xianting Wu")

    action_text = _read_text("action.yml", failures)
    if action_text:
        if "self-hosted" in action_text:
            failures.append("self-hosted runner reference is forbidden in public Action source")
        if "github.event.repository.private" in action_text:
            failures.append("private-repository condition is forbidden in public Action source")
        _validate_uses(action_text, "action.yml", failures)
        if (
            "python -m venv" not in action_text
            or "PQCENSUS_ACTION_VENV" not in action_text
            or "-m quantumguard" not in action_text
            or "$GITHUB_PATH" in action_text
        ):
            failures.append(
                "composite Action must use a job-scoped isolated virtual environment without GITHUB_PATH"
            )
        if "author: XiantingWu" not in action_text:
            failures.append("action.yml author must be XiantingWu")

    # Global scan across all tracked files
    for path in ROOT.rglob("*"):
        if (
            not path.is_file()
            or path.is_symlink()
            or any(
                part
                in {
                    ".git",
                    ".venv",
                    "dist",
                    "build",
                    "__pycache__",
                    ".pytest_cache",
                    ".mypy_cache",
                    ".ruff_cache",
                }
                for part in path.parts
            )
        ):
            continue
        relative = path.relative_to(ROOT)
        # Upstream benchmark snapshots are excluded from provenance scans
        if relative.parts[:3] == ("benchmarks", "corpus", "end-to-end"):
            continue
        if relative.parts[:2] == ("benchmarks", "corpus"):
            continue
        if path.resolve() == Path(__file__).resolve():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        if any(marker in text for marker in BAD_MARKERS):
            failures.append(f"placeholder marker in {relative.as_posix()}")
        if any(token in text for token in LOCAL_PATH_MARKERS):
            failures.append(f"local path in {relative.as_posix()}")
        for marker in FORBIDDEN_PUBLIC_MARKERS:
            if marker in text:
                failures.append(
                    f"internal public-surface marker {marker!r} in {relative.as_posix()}"
                )
        if path.suffix.lower() in {".py", ".toml"} and re.search(r"Repository[123]-", text):
            failures.append(f"sibling source reference in {relative.as_posix()}")

        for pattern in OLD_PLATFORM_PATTERNS:
            match = pattern.search(text)
            if match:
                failures.append(
                    f"old platform pattern {match.group(0)!r} found in {relative.as_posix()}"
                )

        if path.suffix.lower() == ".md":
            for target in LINK_RE.findall(text):
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                target_path = target.split("#", 1)[0].split("?", 1)[0]
                if target_path and not (path.parent / target_path).resolve().is_file():
                    failures.append(f"broken link {relative} -> {target}")

    for result_name in (
        "benchmarks/latest-results.json",
        "benchmarks/real-code-results.json",
        "benchmarks/end-to-end-results.json",
    ):
        path = ROOT / result_name
        if path.is_file():
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("scanner_version") != version:
                failures.append(f"benchmark version mismatch: {result_name}")

    if failures:
        print("FAIL launch surface")
        print("\n".join(f"- {item}" for item in sorted(set(failures))))
        return 1
    print(f"PASS launch surface: {PRODUCT_NAME} {version} ({DISTRIBUTION_NAME})")
    return 0


def _validate_uses(text: str, relative: str, failures: list[str]) -> None:
    for match in USES_RE.finditer(text):
        target = match.group(1)
        if target.startswith("./"):
            continue
        if re.fullmatch(r"[^@]+@[0-9a-f]{40}", target) is None:
            failures.append(
                f"external Action is not pinned to a full commit SHA: {relative} -> {target}"
            )


def _read_text(relative: str, failures: list[str]) -> str:
    path = ROOT / relative
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        failures.append(f"cannot read {relative}: {exc}")
        return ""


def _version() -> str:
    namespace: dict[str, object] = {}
    source = (ROOT / "src/quantumguard/_version.py").read_text(encoding="utf-8")
    exec(compile(source, "_version.py", "exec"), namespace)  # trusted project metadata only
    return str(namespace["__version__"])


if __name__ == "__main__":
    raise SystemExit(main())
