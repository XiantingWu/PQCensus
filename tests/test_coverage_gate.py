from __future__ import annotations

import json
from pathlib import Path

from scripts import coverage_gate


def _report(tmp_path: Path, **totals) -> Path:
    payload = {
        "totals": {
            "covered_lines": 90,
            "num_statements": 100,
            "covered_branches": 80,
            "num_branches": 100,
            **totals,
        }
    }
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_missing_coverage_file_fails(capsys, tmp_path: Path) -> None:
    assert coverage_gate.main(["--report", str(tmp_path / "missing.json")]) == 2
    assert "FAIL coverage gate" in capsys.readouterr().out


def test_malformed_coverage_file_fails(capsys, tmp_path: Path) -> None:
    path = tmp_path / "coverage.json"
    path.write_text("not json", encoding="utf-8")
    assert coverage_gate.main(["--report", str(path)]) == 2
    assert "FAIL coverage gate" in capsys.readouterr().out


def test_below_threshold_fails(capsys, tmp_path: Path) -> None:
    report = _report(tmp_path, covered_lines=80, num_statements=100)
    assert coverage_gate.main(["--report", str(report)]) == 1
    output = capsys.readouterr().out
    assert "FAIL coverage gate" in output
    assert "statement coverage" in output


def test_exact_threshold_passes(capsys, tmp_path: Path) -> None:
    report = _report(tmp_path, covered_lines=90, num_statements=100)
    assert coverage_gate.main(["--report", str(report)]) == 0
    assert "PASS coverage gate" in capsys.readouterr().out


def test_above_threshold_passes(capsys, tmp_path: Path) -> None:
    report = _report(tmp_path, covered_lines=98, num_statements=100)
    assert coverage_gate.main(["--report", str(report)]) == 0


def test_missing_branch_totals_fail_closed(capsys, tmp_path: Path) -> None:
    path = tmp_path / "coverage.json"
    path.write_text(
        json.dumps({"totals": {"covered_lines": 95, "num_statements": 100}}), encoding="utf-8"
    )
    assert coverage_gate.main(["--report", str(path)]) == 2
    assert "missing line/branch counters" in capsys.readouterr().out


def test_zero_branch_measurement_fails(capsys, tmp_path: Path) -> None:
    report = _report(tmp_path, covered_branches=0, num_branches=0)
    assert coverage_gate.main(["--report", str(report)]) == 1
    assert "branch coverage cannot be gated" in capsys.readouterr().out


def test_nan_values_fail_closed(capsys, tmp_path: Path) -> None:
    payload = {
        "totals": {
            "covered_lines": float("nan"),
            "num_statements": 100,
            "covered_branches": 50,
            "num_branches": 100,
        }
    }
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert coverage_gate.main(["--report", str(path)]) == 2
    assert "FAIL coverage gate" in capsys.readouterr().out


def test_invalid_threshold_argument_is_rejected(tmp_path: Path) -> None:
    report = _report(tmp_path)
    try:
        coverage_gate.main(["--report", str(report), "--min-statement", "150"])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("invalid threshold was accepted")
