from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _runner():
    path = ROOT / "scripts" / "run_quantumguardbench.py"
    spec = importlib.util.spec_from_file_location("quantumguardbench", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _e2e_runner():
    path = ROOT / "scripts" / "run_end_to_end.py"
    spec = importlib.util.spec_from_file_location("quantumguard_end_to_end", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_synthetic_benchmark_contract_and_thresholds() -> None:
    result = _runner().run_benchmark(ROOT / "benchmarks" / "quantumguardbench.json")
    assert result["summary"]["precision"] >= 0.95
    assert result["summary"]["recall"] >= 0.95
    assert result["deterministic"] is True
    assert result["migration_mapping"]["dangerous_cross_class_errors"] == 0
    assert result["asset_discovery"]["accuracy"] == 1.0
    assert result["schema_validation"]["cyclonedx_1_7"]["valid"] is True
    assert result["schema_validation"]["sarif_2_1_0_internal_contract"]["valid"] is True


def test_relative_manifest_path_is_supported(monkeypatch) -> None:
    monkeypatch.chdir(ROOT)
    result = _runner().run_benchmark(Path("benchmarks/quantumguardbench.json"), max_cases=1)
    assert result["performance"]["cases"] == 1


def test_curated_real_code_has_call_site_recall_without_registry_noise() -> None:
    result = _runner().run_benchmark(ROOT / "benchmarks" / "real-code.json")
    assert result["summary"] == {
        "true_positive": 6,
        "false_positive": 0,
        "false_negative": 0,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    }
    assert result["migration_mapping"]["dangerous_cross_class_errors"] == 0
    assert result["severity_mapping"]["accuracy"] == 1.0


def test_pinned_end_to_end_repositories_are_deterministic_and_covered() -> None:
    result = _e2e_runner().run(ROOT / "benchmarks" / "end-to-end.json")
    assert result["deterministic"] is True
    assert result["summary"]["observation_coverage"] == 1.0
    assert all(case["parser_errors"] == 0 for case in result["cases"])
    assert all(case["minimum_findings"]["passed"] for case in result["cases"])
    assert result["schema_validation"]["cyclonedx_1_7"]["valid"] is True
