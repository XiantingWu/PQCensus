from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import re
import subprocess
import tomllib
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.-]+)?\Z")
TOOL_VERSION = "1"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the exact release SBOM, checksums, and artifact manifest."
    )
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--evidence-commit", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)

    failures: list[str] = []
    if not VERSION_RE.fullmatch(args.version):
        failures.append("version is not a release version")
    for name, value in (
        ("source commit", args.source_commit),
        ("evidence commit", args.evidence_commit),
    ):
        if not SHA_RE.fullmatch(value):
            failures.append(f"{name} is not an exact Git SHA")
    if not args.run_id.isdigit():
        failures.append("workflow run id must be numeric")
    if not args.workflow.strip():
        failures.append("workflow name is empty")

    raw_dist = args.dist
    raw_output_dir = args.output_dir or args.dist
    if not raw_dist.is_dir() or raw_dist.is_symlink():
        failures.append("dist must be a regular directory")
    if not raw_output_dir.is_dir() or raw_output_dir.is_symlink():
        failures.append("output-dir must be a regular directory")
    dist = raw_dist.resolve()
    output_dir = raw_output_dir.resolve()
    try:
        output_dir.relative_to(dist)
    except ValueError:
        failures.append("output-dir must stay inside dist")

    metadata = _project_metadata(failures)
    wheels = sorted(dist.glob(f"pqcensus-{args.version}-*.whl"))
    sdists = sorted(dist.glob(f"pqcensus-{args.version}.tar.gz"))
    if len(wheels) != 1:
        failures.append(f"expected one exact wheel, found {len(wheels)}")
    if len(sdists) != 1:
        failures.append(f"expected one exact sdist, found {len(sdists)}")
    if failures:
        print("FAIL release artifacts")
        print("\n".join(f"- {failure}" for failure in failures))
        return 1

    wheel = wheels[0]
    sdist = sdists[0]
    wheel_sha = _sha256(wheel)
    sdist_sha = _sha256(sdist)
    sbom_path = output_dir / f"pqcensus-{args.version}.cdx.json"
    checksums_path = output_dir / "SHA256SUMS"
    artifact_manifest_path = output_dir / "release-artifacts.json"

    checksums_path.write_text(
        f"{wheel_sha}  {wheel.name}\n{sdist_sha}  {sdist.name}\n", encoding="utf-8"
    )
    sbom = _sbom(
        args.version,
        args.source_commit,
        args.evidence_commit,
        args.workflow,
        args.run_id,
        metadata,
        wheel,
        wheel_sha,
        sdist,
        sdist_sha,
    )
    sbom_path.write_text(
        json.dumps(sbom, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    manifest = {
        "schema_version": 1,
        "product": "PQCensus",
        "distribution": "pqcensus",
        "version": args.version,
        "source_commit": args.source_commit,
        "evidence_commit": args.evidence_commit,
        "license_spdx": metadata["license_spdx"],
        "requires_python": metadata["requires_python"],
        "runtime_dependencies": metadata["runtime_dependencies"],
        "wheel": {"filename": wheel.name, "sha256": wheel_sha},
        "sdist": {"filename": sdist.name, "sha256": sdist_sha},
        "sbom": {"filename": sbom_path.name, "sha256": _sha256(sbom_path)},
        "checksums": {"filename": checksums_path.name, "sha256": _sha256(checksums_path)},
        "build": {
            "workflow": args.workflow,
            "run_id": args.run_id,
            "runner_os": _env("RUNNER_OS"),
            "runner_arch": _env("RUNNER_ARCH"),
        },
        "tool": {"name": "generate_release_artifacts.py", "version": TOOL_VERSION},
        "toolchain": _toolchain(),
    }
    artifact_manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"PASS release artifacts: {artifact_manifest_path}")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def _project_metadata(failures: list[str]) -> dict[str, Any]:
    try:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        failures.append(f"pyproject metadata is unreadable: {exc}")
        return {
            "license_spdx": "",
            "requires_python": "",
            "runtime_dependencies": [],
        }
    dependencies = project.get("dependencies", [])
    if not isinstance(dependencies, list):
        failures.append("project.dependencies must be a list")
        dependencies = []
    license_value = project.get("license")
    if isinstance(license_value, dict):
        license_spdx = str(license_value.get("text") or license_value.get("id") or "")
    else:
        license_spdx = str(license_value or "")
    return {
        "license_spdx": license_spdx,
        "requires_python": str(project.get("requires-python") or ""),
        "runtime_dependencies": sorted(str(item) for item in dependencies),
    }


def _sbom(
    version: str,
    source_commit: str,
    evidence_commit: str,
    workflow: str,
    run_id: str,
    metadata: dict[str, Any],
    wheel: Path,
    wheel_sha: str,
    sdist: Path,
    sdist_sha: str,
) -> dict[str, Any]:
    application_ref = f"pkg:pypi/pqcensus@{version}"
    artifact_values = ((wheel, wheel_sha, "wheel"), (sdist, sdist_sha, "sdist"))
    components = []
    artifact_refs = []
    for path, digest, kind in artifact_values:
        ref = f"urn:pqcensus:release-artifact:{kind}:{digest[:20]}"
        artifact_refs.append(ref)
        components.append(
            {
                "bom-ref": ref,
                "type": "file",
                "name": path.name,
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "properties": [
                    {"name": "pqcensus:artifact-kind", "value": kind},
                    {"name": "pqcensus:source-commit", "value": source_commit},
                    {"name": "pqcensus:evidence-commit", "value": evidence_commit},
                ],
            }
        )
    serial_material = f"{version}|{source_commit}|{evidence_commit}|{wheel_sha}|{sdist_sha}"
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"pqcensus:release-sbom:{serial_material}")
    properties = [
        {"name": "pqcensus:product", "value": "PQCensus"},
        {"name": "pqcensus:distribution", "value": "pqcensus"},
        {"name": "pqcensus:source-commit", "value": source_commit},
        {"name": "pqcensus:evidence-commit", "value": evidence_commit},
        {"name": "pqcensus:build-workflow", "value": workflow},
        {"name": "pqcensus:build-run-id", "value": run_id},
        {"name": "pqcensus:requires-python", "value": metadata["requires_python"]},
        {
            "name": "pqcensus:runtime-dependency-count",
            "value": str(len(metadata["runtime_dependencies"])),
        },
        {"name": "pqcensus:runtime-components", "value": "pqcensus,quantumguard"},
        {"name": "pqcensus:runtime-dependencies", "value": "[]"},
    ]
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "tools": [
                {
                    "vendor": "PQCensus",
                    "name": "generate_release_artifacts.py",
                    "version": TOOL_VERSION,
                }
            ],
            "component": {
                "bom-ref": application_ref,
                "type": "application",
                "name": "pqcensus",
                "version": version,
                "purl": application_ref,
                "licenses": [{"license": {"id": metadata["license_spdx"]}}],
            },
            "properties": properties,
        },
        "components": sorted(components, key=lambda item: item["bom-ref"]),
        "dependencies": [{"ref": application_ref, "dependsOn": sorted(artifact_refs)}],
    }


def _toolchain() -> dict[str, str]:
    names = (
        "build",
        "cyclonedx-python-lib",
        "hatchling",
        "jsonschema",
        "mypy",
        "pytest",
        "twine",
        "uv",
        "zizmor",
    )
    values = {}
    for name in names:
        try:
            values[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            values[name] = _command_version(name)
    return values


def _command_version(name: str) -> str:
    command = "uv" if name == "uv" else name
    try:
        completed = subprocess.run(
            [command, "--version"], capture_output=True, text=True, check=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    tokens = (completed.stdout or completed.stderr).strip().split()
    return tokens[1] if len(tokens) >= 2 else (tokens[0] if tokens else "unavailable")


def _env(name: str) -> str | None:
    import os

    return os.environ.get(name)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
