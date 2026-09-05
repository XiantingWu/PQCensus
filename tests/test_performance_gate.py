from __future__ import annotations

from pathlib import Path

from scripts.performance_gate import _fixture_text, _generate, run_tier


def test_generated_performance_fixture_has_exact_requested_line_count() -> None:
    text = _fixture_text(7, 500)
    assert len(text.splitlines()) == 500
    assert "hashlib.sha256" in text
    assert "def workload_7" in text


def test_generate_hits_requested_loc_without_executing_fixture(tmp_path: Path) -> None:
    files, loc = _generate(tmp_path, 1_200, lines_per_file=500)
    assert files == 3
    assert loc == 1_200
    assert len(list(tmp_path.glob("*.py"))) == 3


def test_small_tier_reports_files_loc_throughput_and_rss() -> None:
    result = run_tier(1_000, lines_per_file=500)
    assert result["requested_loc"] == 1_000
    assert result["loc"] == 1_000
    assert result["files"] == 2
    assert result["files_analyzed"] == 2
    assert result["findings"] == 2
    assert result["wall_clock_seconds"] > 0
    assert result["files_per_second"] > 0
    assert result["loc_per_second"] > 0
    assert result["peak_rss_mib"] > 0


def test_non_multiple_tier_is_still_exact(tmp_path: Path) -> None:
    files, loc = _generate(tmp_path, 1_001, lines_per_file=500)
    assert files == 3
    assert loc == 1_001
    assert (
        sum(len(path.read_text(encoding="utf-8").splitlines()) for path in tmp_path.glob("*.py"))
        == 1_001
    )
