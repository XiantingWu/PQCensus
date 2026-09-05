from __future__ import annotations

import json
from pathlib import Path

from quantumguard.cli import EXIT_OK, build_parser, main
from quantumguard.doctor import run_doctor


def test_doctor_strict_passes() -> None:
    payload = run_doctor(strict=True)
    assert payload["ok"] is True
    assert payload["tool"]["name"] == "PQCensus"


def test_primary_cli_identity() -> None:
    assert build_parser().prog == "pqcensus"


def test_cli_json_and_verify(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text("import hashlib\nhashlib.sha256(b'x')\n", encoding="utf-8")
    assert main(["audit", str(tmp_path), "--json", "--fail-on", "none"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"]["name"] == "PQCensus"
    assert main(["verify", str(tmp_path), "--json"]) == EXIT_OK
    verify = json.loads(capsys.readouterr().out)
    assert verify["deterministic"] is True
