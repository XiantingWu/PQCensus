from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate exact release files and their manifest.")
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    raw_dist = args.dist
    failures: list[str] = []
    if not raw_dist.is_dir() or raw_dist.is_symlink():
        failures.append("dist must be a regular directory")
    dist = raw_dist.resolve()
    manifest_path = dist / "release-artifacts.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        failures.append("release-artifacts.json is missing or unsafe")
        manifest: dict[str, Any] = {}
    else:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            failures.append(f"release-artifacts.json is unreadable: {exc}")
            manifest = {}
    if not isinstance(manifest, dict):
        failures.append("release-artifacts.json must be an object")
        manifest = {}
    if manifest.get("schema_version") != 1:
        failures.append("release-artifacts schema_version must be 1")
    if manifest.get("product") != "PQCensus" or manifest.get("distribution") != "pqcensus":
        failures.append("release-artifacts public identity is invalid")
    if manifest.get("version") != args.version:
        failures.append("release-artifacts version mismatch")
    for key in ("source_commit", "evidence_commit"):
        if not isinstance(manifest.get(key), str) or SHA_RE.fullmatch(manifest[key]) is None:
            failures.append(f"release-artifacts {key} is not an exact Git SHA")
    build = manifest.get("build")
    if not isinstance(build, dict) or not str(build.get("workflow") or "").strip():
        failures.append("release-artifacts build workflow is missing")
    if not isinstance(build, dict) or not str(build.get("run_id") or "").isdigit():
        failures.append("release-artifacts build run id is missing")

    for key in ("wheel", "sdist", "sbom", "checksums"):
        item = manifest.get(key)
        if not isinstance(item, dict):
            failures.append(f"release-artifacts {key} entry is missing")
            continue
        filename = item.get("filename")
        expected_hash = item.get("sha256")
        if not isinstance(filename, str) or Path(filename).name != filename:
            failures.append(f"release-artifacts {key} filename is unsafe")
            continue
        if not isinstance(expected_hash, str) or SHA256_RE.fullmatch(expected_hash) is None:
            failures.append(f"release-artifacts {key} hash is invalid")
            continue
        path = dist / filename
        if path.is_symlink() or not path.is_file():
            failures.append(f"release-artifacts {key} file is missing or unsafe")
            continue
        if _sha256(path) != expected_hash:
            failures.append(f"release-artifacts {key} hash mismatch")
    if manifest.get("runtime_dependencies") != []:
        failures.append("release-artifacts runtime dependency list must be exactly empty")
    sbom_entry = manifest.get("sbom")
    if isinstance(sbom_entry, dict):
        sbom_path = dist / str(sbom_entry.get("filename", ""))
        try:
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            components = sbom.get("components")
            if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.7":
                failures.append("release SBOM is not CycloneDX 1.7")
            if not isinstance(components, list) or len(components) != 2:
                failures.append("release SBOM must contain exactly wheel and sdist subjects")
            else:
                expected_components = {
                    (manifest.get(kind) or {}).get("filename"): (manifest.get(kind) or {}).get(
                        "sha256"
                    )
                    for kind in ("wheel", "sdist")
                }
                actual_components: dict[object, object] = {}
                for component in components:
                    if not isinstance(component, dict):
                        continue
                    hashes = component.get("hashes")
                    digest = (
                        hashes[0].get("content")
                        if isinstance(hashes, list)
                        and hashes
                        and isinstance(hashes[0], dict)
                        and hashes[0].get("alg") == "SHA-256"
                        else None
                    )
                    actual_components[component.get("name")] = digest
                if actual_components != expected_components:
                    failures.append(
                        "release SBOM subjects do not match wheel/sdist manifest hashes"
                    )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, AttributeError) as exc:
            failures.append(f"release SBOM is unreadable: {exc}")

    checksums_entry = manifest.get("checksums")
    if isinstance(checksums_entry, dict):
        checksums_path = dist / str(checksums_entry.get("filename", ""))
        try:
            lines = [
                line.split() for line in checksums_path.read_text(encoding="utf-8").splitlines()
            ]
            expected = {
                (manifest.get("wheel") or {}).get("filename"): (manifest.get("wheel") or {}).get(
                    "sha256"
                ),
                (manifest.get("sdist") or {}).get("filename"): (manifest.get("sdist") or {}).get(
                    "sha256"
                ),
            }
            actual = {parts[1]: parts[0] for parts in lines if len(parts) == 2}
            if actual != expected:
                failures.append("SHA256SUMS does not contain exactly wheel and sdist")
        except (OSError, UnicodeDecodeError, IndexError, AttributeError) as exc:
            failures.append(f"SHA256SUMS is unreadable: {exc}")
    if failures:
        print("FAIL release artifacts")
        print("\n".join(f"- {failure}" for failure in failures))
        return 1
    print("PASS release artifacts: exact wheel, sdist, SBOM, and checksums")
    return 0


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
