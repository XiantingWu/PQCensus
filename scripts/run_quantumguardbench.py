from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
import tracemalloc
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from quantumguard import __version__, audit
from quantumguard.models import canonical_json
from quantumguard.reporting import cyclonedx_cbom_document, sarif_document


def run_benchmark(
    manifest_path: Path,
    *,
    max_cases: int | None = None,
    official_sarif: bool = False,
) -> dict[str, Any]:
    manifest_path = manifest_path.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1 or manifest.get("benchmark") != "QuantumGuardBench":
        raise ValueError("unsupported QuantumGuardBench manifest")
    label_policy = manifest.get("label_policy") or {}
    authority = label_policy.get("authority")
    if authority not in {"deterministic-fixture-intent", "manual-curated-third-party"}:
        raise ValueError("benchmark must declare an accepted ground-truth authority")
    unit = label_policy.get("unit", "semantic-use")
    if unit not in {"semantic-use", "call-site"}:
        raise ValueError("benchmark label unit must be semantic-use or call-site")
    if authority == "manual-curated-third-party":
        _validate_provenance(manifest_path, manifest)

    cases = manifest.get("cases", [])
    if max_cases is not None:
        cases = cases[:max_cases]
    counts = {"true_positive": 0, "false_positive": 0, "false_negative": 0}
    breakdown_counts: dict[str, dict[str, dict[str, int]]] = {
        field: defaultdict(lambda: {"true_positive": 0, "false_positive": 0, "false_negative": 0})
        for field in ("language", "algorithm", "purpose", "analyzer", "severity")
    }
    parse_failures = 0
    predictions = 0
    unknown_predictions = 0
    deterministic = True
    migration_total = migration_correct = dangerous_mapping_errors = 0
    migration_failures: list[dict[str, Any]] = []
    severity_total = severity_correct = 0
    severity_failures: list[dict[str, str]] = []
    asset_total = asset_correct = 0
    invalid_cbom_cases: list[str] = []
    invalid_sarif_contract_cases: list[str] = []
    official_sarif_schema = None
    if official_sarif:
        from validate_sarif import fetch_schema

        official_sarif_schema = fetch_schema()
    invalid_official_sarif_cases: list[str] = []
    per_case = []

    tracemalloc.start()
    started = time.perf_counter()
    for case in cases:
        case_root = (manifest_path.parent / case["path"]).resolve()
        result = audit(case_root)
        repeated = audit(case_root)
        same = canonical_json(result.to_dict()) == canonical_json(repeated.to_dict())
        deterministic = deterministic and same
        parse_failures += len(result.parser_errors)
        if not _valid_cyclonedx(cyclonedx_cbom_document(result)):
            invalid_cbom_cases.append(case["id"])
        sarif = sarif_document(result)
        if not _valid_sarif_contract(sarif):
            invalid_sarif_contract_cases.append(case["id"])
        if official_sarif_schema is not None:
            from validate_sarif import validation_errors

            if validation_errors(sarif, official_sarif_schema):
                invalid_official_sarif_cases.append(case["id"])
        active = [item for item in result.findings if item.status == "active"]
        predictions += len(active)
        unknown_predictions += sum(item.purpose.value == "UNKNOWN" for item in active)

        expected = {_label_key(item, unit): item for item in case.get("labels", [])}
        observed = {_finding_key(item, unit): item for item in active}
        true_keys = expected.keys() & observed.keys()
        false_positive_keys = observed.keys() - expected.keys()
        false_negative_keys = expected.keys() - observed.keys()
        case_counts = {
            "true_positive": len(true_keys),
            "false_positive": len(false_positive_keys),
            "false_negative": len(false_negative_keys),
        }
        for key, value in case_counts.items():
            counts[key] += value

        for key in true_keys:
            label = expected[key]
            finding = observed[key]
            _increment(breakdown_counts, "language", case["language"], "true_positive")
            for field, value in (
                ("algorithm", label["algorithm"]),
                ("purpose", label["purpose"]),
                ("analyzer", finding.analyzer),
                ("severity", finding.severity.value),
            ):
                _increment(breakdown_counts, field, str(value), "true_positive")
            severity_total += 1
            if finding.severity.value == label["severity"]:
                severity_correct += 1
            else:
                severity_failures.append(
                    {
                        "case": case["id"],
                        "algorithm": label["algorithm"],
                        "purpose": label["purpose"],
                        "expected": label["severity"],
                        "actual": finding.severity.value,
                    }
                )
            if "migration_targets" in label:
                migration_total += 1
                plan = next(
                    (
                        item
                        for item in result.migration_plans
                        if item.finding_id == finding.finding_id
                    ),
                    None,
                )
                actual_targets = plan.recommended_targets if plan else []
                if actual_targets == label["migration_targets"]:
                    migration_correct += 1
                else:
                    migration_failures.append(
                        {
                            "case": case["id"],
                            "algorithm": label["algorithm"],
                            "purpose": label["purpose"],
                            "expected": label["migration_targets"],
                            "actual": actual_targets,
                        }
                    )
                    if (
                        label["purpose"] == "SIGNATURE"
                        and "ML-KEM" in actual_targets
                        or label["purpose"] in {"KEY_ESTABLISHMENT", "ENCRYPTION"}
                        and any(item in actual_targets for item in ("ML-DSA", "SLH-DSA"))
                    ):
                        dangerous_mapping_errors += 1

        for key in false_positive_keys:
            finding = observed[key]
            _increment(breakdown_counts, "language", case["language"], "false_positive")
            for field, value in (
                ("algorithm", finding.algorithm),
                ("purpose", finding.purpose.value),
                ("analyzer", finding.analyzer),
                ("severity", finding.severity.value),
            ):
                _increment(breakdown_counts, field, str(value), "false_positive")

        for key in false_negative_keys:
            label = expected[key]
            _increment(breakdown_counts, "language", case["language"], "false_negative")
            for field in ("algorithm", "purpose", "analyzer", "severity"):
                _increment(breakdown_counts, field, str(label[field]), "false_negative")

        for expected_asset in case.get("assets", []):
            asset_total += 1
            if any(
                item.asset_type == expected_asset["asset_type"]
                and item.name == expected_asset["name"]
                for item in result.assets
            ):
                asset_correct += 1
        per_case.append(
            {
                "id": case["id"],
                **case_counts,
                "deterministic": same,
                "parser_errors": len(result.parser_errors),
            }
        )

    elapsed = time.perf_counter() - started
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    summary = _metrics(counts)
    return {
        "schema_version": 1,
        "benchmark": "QuantumGuardBench",
        "scanner_version": __version__,
        "corpus_sha256": _corpus_digest(manifest_path, cases),
        "rules_sha256": hashlib.sha256(
            (ROOT / "rules" / "quantumguard-rules.json").read_bytes()
        ).hexdigest(),
        "label_policy": manifest["label_policy"],
        "summary": summary,
        "breakdowns": {
            field: {name: _metrics(values) for name, values in sorted(groups.items())}
            for field, groups in breakdown_counts.items()
        },
        "unknown_rate": unknown_predictions / predictions if predictions else 0.0,
        "parse_failure_rate": parse_failures / len(cases) if cases else 0.0,
        "deterministic": deterministic,
        "migration_mapping": {
            "cases": migration_total,
            "correct": migration_correct,
            "accuracy": migration_correct / migration_total if migration_total else 1.0,
            "dangerous_cross_class_errors": dangerous_mapping_errors,
            "failures": migration_failures,
        },
        "severity_mapping": {
            "cases": severity_total,
            "correct": severity_correct,
            "accuracy": severity_correct / severity_total if severity_total else 1.0,
            "failures": severity_failures,
        },
        "asset_discovery": {
            "expected": asset_total,
            "correct": asset_correct,
            "accuracy": asset_correct / asset_total if asset_total else 1.0,
        },
        "schema_validation": {
            "cyclonedx_1_7": {
                "valid": not invalid_cbom_cases,
                "invalid_cases": invalid_cbom_cases,
            },
            "sarif_2_1_0_internal_contract": {
                "valid": not invalid_sarif_contract_cases,
                "invalid_cases": invalid_sarif_contract_cases,
                "official_schema_claimed": False,
            },
            "sarif_2_1_0_official": {
                "performed": official_sarif_schema is not None,
                "valid": official_sarif_schema is not None and not invalid_official_sarif_cases,
                "invalid_cases": invalid_official_sarif_cases,
            },
        },
        "performance": {
            "cases": len(cases),
            "wall_clock_seconds": elapsed,
            "cases_per_second": len(cases) / elapsed if elapsed else 0.0,
            "peak_memory_bytes": peak_memory,
            "python": platform.python_version(),
            "platform": platform.system(),
        },
        "cases": per_case,
    }


def _label_key(item: dict[str, Any], unit: str) -> tuple[Any, ...]:
    key: tuple[Any, ...] = str(item["file"]), str(item["algorithm"]), str(item["purpose"])
    return (*key, int(item["line"])) if unit == "call-site" else key


def _finding_key(item: Any, unit: str) -> tuple[Any, ...]:
    key: tuple[Any, ...] = item.source_path, item.algorithm, item.purpose.value
    return (*key, item.span.start_line) if unit == "call-site" else key


def _validate_provenance(manifest_path: Path, manifest: dict[str, Any]) -> None:
    name = manifest.get("provenance")
    if not isinstance(name, str):
        raise ValueError("real-code benchmark must bind a provenance file")
    path = (manifest_path.parent / name).resolve()
    if path.parent != manifest_path.parent or not path.is_file() or path.is_symlink():
        raise ValueError("benchmark provenance must be a regular file beside the manifest")
    sources = json.loads(path.read_text(encoding="utf-8")).get("sources", {})
    for case in manifest.get("cases", []):
        source = sources.get(case.get("provenance_id"), {})
        required = {"repository", "commit", "source_path", "license", "label_basis"}
        if not required.issubset(source) or len(str(source.get("commit", ""))) != 40:
            raise ValueError(f"incomplete provenance for {case.get('id')}")


def _increment(
    groups: dict[str, dict[str, dict[str, int]]],
    field: str,
    value: str,
    outcome: str,
) -> None:
    groups[field][value][outcome] += 1


def _metrics(counts: dict[str, int]) -> dict[str, int | float]:
    tp = counts["true_positive"]
    fp = counts["false_positive"]
    fn = counts["false_negative"]
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _corpus_digest(manifest_path: Path, cases: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    digest.update(manifest_path.read_bytes())
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("provenance"):
        digest.update((manifest_path.parent / manifest["provenance"]).read_bytes())
    for case in sorted(cases, key=lambda item: item["id"]):
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

        error = JsonStrictValidator(SchemaVersion.V1_7).validate_str(
            json.dumps(payload, sort_keys=True)
        )
    except (ImportError, RuntimeError):
        return False
    return error is None


def _valid_sarif_contract(payload: dict[str, Any]) -> bool:
    if payload.get("version") != "2.1.0" or not isinstance(payload.get("runs"), list):
        return False
    for run in payload["runs"]:
        driver = (run.get("tool") or {}).get("driver") or {}
        if not driver.get("name") or not isinstance(run.get("results"), list):
            return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run independently labeled QuantumGuardBench cases."
    )
    parser.add_argument(
        "--manifest", type=Path, default=ROOT / "benchmarks" / "quantumguardbench.json"
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-cases", type=int)
    parser.add_argument("--require-precision", type=float)
    parser.add_argument("--require-recall", type=float)
    parser.add_argument("--official-sarif", action="store_true")
    args = parser.parse_args()
    result = run_benchmark(
        args.manifest, max_cases=args.max_cases, official_sarif=args.official_sarif
    )
    encoded = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    if (
        args.require_precision is not None
        and result["summary"]["precision"] < args.require_precision
    ):
        return 1
    if args.require_recall is not None and result["summary"]["recall"] < args.require_recall:
        return 1
    if (
        not result["deterministic"]
        or result["migration_mapping"]["dangerous_cross_class_errors"]
        or not result["schema_validation"]["cyclonedx_1_7"]["valid"]
        or not result["schema_validation"]["sarif_2_1_0_internal_contract"]["valid"]
        or (
            args.official_sarif and not result["schema_validation"]["sarif_2_1_0_official"]["valid"]
        )
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
