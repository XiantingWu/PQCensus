from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from quantumguard import __version__, audit
from quantumguard.models import canonical_json
from quantumguard.reporting import cyclonedx_cbom_document, sarif_document


def run(manifest_path: Path, *, official_sarif: bool = False) -> dict[str, Any]:
    manifest_path = manifest_path.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (
        manifest.get("schema_version") != 1
        or manifest.get("benchmark") != "QuantumGuardBench-EndToEnd"
    ):
        raise ValueError("unsupported end-to-end benchmark manifest")
    _validate_provenance(manifest_path, manifest)
    official_schema = None
    if official_sarif:
        from validate_sarif import fetch_schema

        official_schema = fetch_schema()

    started = time.perf_counter()
    cases: list[dict[str, Any]] = []
    all_deterministic = True
    all_cyclonedx_valid = True
    all_sarif_valid = True
    all_official_sarif_valid = official_schema is not None if official_sarif else True
    total_files = total_findings = total_expected = total_matched = 0
    for case in manifest["cases"]:
        case_root = (manifest_path.parent / case["path"]).resolve()
        if manifest_path.parent not in case_root.parents or case_root == manifest_path.parent:
            raise ValueError(f"case escapes benchmark root: {case['id']}")
        result = audit(case_root)
        repeated = audit(case_root)
        deterministic = canonical_json(result.to_dict()) == canonical_json(repeated.to_dict())
        all_deterministic = all_deterministic and deterministic
        active = [item for item in result.findings if item.status == "active"]
        result_summary = result.to_dict()["summary"]

        observations = []
        missing: list[dict[str, Any]] = []
        for expected in case.get("required_observations", []):
            match = next(
                (
                    item
                    for item in active
                    if item.source_path == expected["file"]
                    and item.span.start_line == expected["line"]
                    and item.algorithm == expected["algorithm"]
                    and item.purpose.value == expected["purpose"]
                ),
                None,
            )
            record = {**expected, "matched": match is not None}
            observations.append(record)
            if match is None:
                missing.append(expected)

        expected_dependencies = [
            str(item).lower() for item in case.get("expected_dependencies", [])
        ]
        observed_dependencies = sorted(item.name.lower() for item in result.dependencies)
        missing_dependencies = sorted(set(expected_dependencies) - set(observed_dependencies))
        cdx_valid = _valid_cyclonedx(cyclonedx_cbom_document(result))
        sarif_valid = _valid_sarif_contract(sarif_document(result))
        official_valid = True
        if official_schema is not None:
            from validate_sarif import validation_errors

            official_valid = not validation_errors(sarif_document(result), official_schema)
        all_cyclonedx_valid = all_cyclonedx_valid and cdx_valid
        all_sarif_valid = all_sarif_valid and sarif_valid
        all_official_sarif_valid = all_official_sarif_valid and official_valid
        total_files += int(result_summary["files_analyzed"])
        total_findings += len(active)
        total_expected += len(observations)
        matched_count = sum(1 for item in observations if item["matched"])
        total_matched += matched_count
        minimum_findings = int(case.get("minimum_findings", 0))
        cases.append(
            {
                "id": case["id"],
                "files": int(result_summary["files_analyzed"]),
                "findings": len(active),
                "deterministic": deterministic,
                "parser_errors": len(result.parser_errors),
                "observations": {
                    "expected": len(observations),
                    "matched": matched_count,
                    "missing": missing,
                    "items": observations,
                },
                "dependencies": {
                    "expected": expected_dependencies,
                    "observed": observed_dependencies,
                    "missing": missing_dependencies,
                },
                "schema_validation": {
                    "cyclonedx_1_7": cdx_valid,
                    "sarif_2_1_0_internal_contract": sarif_valid,
                    "sarif_2_1_0_official": official_valid if official_sarif else None,
                },
                "minimum_findings": {
                    "required": minimum_findings,
                    "observed": len(active),
                    "passed": len(active) >= minimum_findings,
                },
            }
        )

    elapsed = time.perf_counter() - started
    return {
        "schema_version": 1,
        "benchmark": "QuantumGuardBench-EndToEnd",
        "scanner_version": __version__,
        "corpus_sha256": _corpus_digest(manifest_path),
        "label_policy": manifest["label_policy"],
        "deterministic": all_deterministic,
        "summary": {
            "repositories": len(cases),
            "files": total_files,
            "findings": total_findings,
            "observations_expected": total_expected,
            "observations_matched": total_matched,
            "observation_coverage": total_matched / total_expected if total_expected else 1.0,
        },
        "schema_validation": {
            "cyclonedx_1_7": {"valid": all_cyclonedx_valid},
            "sarif_2_1_0_internal_contract": {"valid": all_sarif_valid},
            "sarif_2_1_0_official": {
                "performed": official_sarif,
                "valid": all_official_sarif_valid,
            },
        },
        "performance": {
            "wall_clock_seconds": elapsed,
            "repositories_per_second": len(cases) / elapsed if elapsed else 0.0,
            "python": platform.python_version(),
            "platform": platform.system(),
        },
        "cases": cases,
    }


def _validate_provenance(manifest_path: Path, manifest: dict[str, Any]) -> None:
    provenance_path = (manifest_path.parent / manifest["provenance"]).resolve()
    if (
        provenance_path.parent != manifest_path.parent
        or not provenance_path.is_file()
        or provenance_path.is_symlink()
    ):
        raise ValueError("end-to-end provenance must be a regular file beside the manifest")
    sources = json.loads(provenance_path.read_text(encoding="utf-8")).get("sources", {})
    repository_root = ROOT.resolve()
    for case in manifest["cases"]:
        source = sources.get(case["provenance_id"], {})
        required = {
            "repository",
            "commit",
            "source_path",
            "source_tree_sha256",
            "license",
            "label_basis",
        }
        if not required.issubset(source) or len(str(source["commit"])) != 40:
            raise ValueError(f"incomplete provenance for {case['id']}")
        source_path = Path(str(source["source_path"]))
        if source_path.is_absolute() or ".." in source_path.parts:
            raise ValueError(f"unsafe provenance source path for {case['id']}")
        root = (repository_root / source_path).resolve()
        try:
            root.relative_to(repository_root)
        except ValueError as exc:
            raise ValueError(f"provenance source path escapes repository for {case['id']}") from exc
        actual_hash = _tree_sha256(root) if root.is_dir() and not root.is_symlink() else None
        if actual_hash != source["source_tree_sha256"]:
            raise ValueError(
                f"source snapshot hash mismatch for {case['id']}: "
                f"expected {source['source_tree_sha256']}, actual {actual_hash}"
            )


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(
        item for item in root.rglob("*") if item.is_file() and not item.is_symlink()
    ):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _corpus_digest(manifest_path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(manifest_path.read_bytes())
    provenance = manifest_path.parent / "end-to-end-provenance.json"
    digest.update(provenance.read_bytes())
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for case in sorted(manifest["cases"], key=lambda item: item["id"]):
        root = (manifest_path.parent / case["path"]).resolve()
        for path in sorted(
            item for item in root.rglob("*") if item.is_file() and not item.is_symlink()
        ):
            digest.update(path.relative_to(manifest_path.parent).as_posix().encode("utf-8"))
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
    return digest.hexdigest()


def _valid_cyclonedx(payload: dict[str, Any]) -> bool:
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator

        return (
            JsonStrictValidator(SchemaVersion.V1_7).validate_str(
                json.dumps(payload, sort_keys=True)
            )
            is None
        )
    except (ImportError, RuntimeError):
        return False


def _valid_sarif_contract(payload: dict[str, Any]) -> bool:
    return (
        payload.get("version") == "2.1.0"
        and isinstance(payload.get("runs"), list)
        and all(
            ((run.get("tool") or {}).get("driver") or {}).get("name")
            and isinstance(run.get("results"), list)
            for run in payload["runs"]
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the pinned public-repository QuantumGuardBench layer."
    )
    parser.add_argument("--manifest", type=Path, default=ROOT / "benchmarks" / "end-to-end.json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--official-sarif", action="store_true")
    parser.add_argument("--require-coverage", type=float, default=1.0)
    args = parser.parse_args()
    result = run(args.manifest, official_sarif=args.official_sarif)
    encoded = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    if (
        not result["deterministic"]
        or result["summary"]["observation_coverage"] < args.require_coverage
        or not result["schema_validation"]["cyclonedx_1_7"]["valid"]
        or not result["schema_validation"]["sarif_2_1_0_internal_contract"]["valid"]
        or args.official_sarif
        and not result["schema_validation"]["sarif_2_1_0_official"]["valid"]
        or any(
            case["parser_errors"]
            or case["dependencies"]["missing"]
            or not case["minimum_findings"]["passed"]
            or case["observations"]["missing"]
            for case in result["cases"]
        )
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
