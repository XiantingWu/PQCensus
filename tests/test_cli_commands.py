from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import quantumguard.cli as cli


def _repo(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "app.py").write_text("import hashlib\nhashlib.sha256(b'data')\n", encoding="utf-8")
    return tmp_path


def test_rules_and_explain_support_console_and_json(capsys) -> None:
    assert cli.main(["rules"]) == cli.EXIT_OK
    console = capsys.readouterr().out
    assert "QG-RSA-SIGNATURE" in console

    assert cli.main(["rules", "--json"]) == cli.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["policy_version"] == "0.1.0"

    assert cli.main(["explain", "QG-RSA-SIGNATURE", "--json"]) == cli.EXIT_OK
    explained = json.loads(capsys.readouterr().out)
    assert explained["type"] == "rule"
    assert explained["rule"]["id"] == "QG-RSA-SIGNATURE"

    assert cli.main(["explain", "missing-rule"]) == cli.EXIT_ERROR
    assert "unknown rule/finding identifier" in capsys.readouterr().err


def test_inventory_cbom_plan_agility_and_baseline_write_files(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")

    cases = [
        (["inventory", str(root)], "inventory.json", "assets"),
        (["cbom", str(root), "--format", "native"], "cbom-native.json", "components"),
        (["cbom", str(root), "--format", "cyclonedx"], "cbom.cdx.json", "bomFormat"),
        (["plan", str(root)], "plan.json", "plans"),
        (["agility", str(root)], "agility.json", "overall_score"),
        (["baseline", str(root)], "baseline.json", "finding_ids"),
    ]
    for command, filename, key in cases:
        output = tmp_path / filename
        assert cli.main([*command, "--output", str(output)]) == cli.EXIT_OK
        payload = json.loads(output.read_text(encoding="utf-8"))
        assert key in payload


def test_audit_output_directory_preserves_legacy_compatibility_files(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(
        "import jwt\njwt.encode({'sub': 'x'}, 'key', algorithm='RS256')\n", encoding="utf-8"
    )
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "tool_version": "0.1.0",
                "repository": "repo",
                "finding_ids": [],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "out"
    assert (
        cli.main(
            [
                "audit",
                str(root),
                "--output",
                str(output),
                "--baseline",
                str(baseline),
                "--fail-on",
                "none",
                "--quiet",
            ]
        )
        == cli.EXIT_OK
    )
    expected = {
        "quantumguard-audit.json",
        "quantumguard-inventory.json",
        "quantumguard-cbom.json",
        "quantumguard-cbom.cdx.json",
        "quantumguard-migration-plan.json",
        "quantumguard.sarif",
        "quantumguard-baseline-diff.json",
    }
    assert {path.name for path in output.iterdir()} == expected
    diff = json.loads((output / "quantumguard-baseline-diff.json").read_text(encoding="utf-8"))
    assert diff["new"]


def test_audit_formats_and_fail_thresholds_are_user_visible(tmp_path: Path, capsys) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(
        "import jwt\njwt.encode({'sub': 'x'}, 'key', algorithm='RS256')\n", encoding="utf-8"
    )

    assert cli.main(["audit", str(root), "--format", "console", "--fail-on", "none"]) == cli.EXIT_OK
    assert "PQCensus" in capsys.readouterr().out

    assert (
        cli.main(["audit", str(root), "--format", "markdown", "--fail-on", "none"]) == cli.EXIT_OK
    )
    assert "# PQCensus" in capsys.readouterr().out

    assert cli.main(["audit", str(root), "--format", "sarif", "--fail-on", "none"]) == cli.EXIT_OK
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"

    assert cli.main(["audit", str(root), "--json", "--fail-on", "high"]) == cli.EXIT_FINDINGS
    json.loads(capsys.readouterr().out)


def test_baseline_limits_failures_to_new_findings(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    app = root / "app.py"
    app.write_text(
        "import jwt\njwt.encode({'sub': 'x'}, 'key', algorithm='RS256')\n", encoding="utf-8"
    )
    baseline = tmp_path / "baseline.json"
    assert cli.main(["baseline", str(root), "--output", str(baseline)]) == cli.EXIT_OK

    assert (
        cli.main(
            [
                "audit",
                str(root),
                "--baseline",
                str(baseline),
                "--fail-on",
                "high",
                "--quiet",
            ]
        )
        == cli.EXIT_OK
    )
    app.write_text(
        "import jwt\n"
        "jwt.encode({'sub': 'x'}, 'key', algorithm='RS256')\n"
        "jwt.encode({'sub': 'y'}, 'key', algorithm='PS256')\n",
        encoding="utf-8",
    )
    assert (
        cli.main(
            [
                "audit",
                str(root),
                "--baseline",
                str(baseline),
                "--fail-on",
                "high",
                "--quiet",
            ]
        )
        == cli.EXIT_FINDINGS
    )


def test_invalid_baseline_and_invalid_scan_path_return_runtime_error(
    tmp_path: Path, capsys
) -> None:
    root = _repo(tmp_path)
    bad = tmp_path / "bad-baseline.json"
    bad.write_text('{"schema_version":2,"finding_ids":[]}', encoding="utf-8")
    assert (
        cli.main(["audit", str(root), "--baseline", str(bad), "--fail-on", "none", "--quiet"])
        == cli.EXIT_ERROR
    )
    assert "baseline must be" in capsys.readouterr().err

    assert cli.main(["inventory", str(tmp_path / "missing")]) == cli.EXIT_ERROR
    assert "scan path is not a directory" in capsys.readouterr().err


def test_doctor_and_tls_dispatch_without_network(monkeypatch, capsys) -> None:
    healthy = {
        "ok": True,
        "tool": {"name": "PQCensus", "version": "0.1.0"},
        "checks": [{"name": "runtime", "ok": True, "detail": "ready"}],
    }
    monkeypatch.setattr(cli, "run_doctor", lambda strict=False: healthy)
    assert cli.main(["doctor"]) == cli.EXIT_OK
    assert "PASS runtime: ready" in capsys.readouterr().out

    unhealthy = {
        "ok": False,
        "tool": {"name": "PQCensus", "version": "0.1.0"},
        "checks": [{"name": "runtime", "ok": False, "detail": "bad"}],
    }
    monkeypatch.setattr(cli, "run_doctor", lambda strict=False: unhealthy)
    assert cli.main(["doctor", "--json", "--strict"]) == cli.EXIT_ERROR
    assert json.loads(capsys.readouterr().out)["ok"] is False

    monkeypatch.setattr(
        cli,
        "inspect_tls",
        lambda host, port, timeout: {
            "host": host,
            "port": port,
            "timeout": timeout,
            "pqc_readiness": "UNKNOWN",
        },
    )
    assert (
        cli.main(["tls", "localhost", "--port", "8443", "--timeout", "1.5", "--json"])
        == cli.EXIT_OK
    )
    report = json.loads(capsys.readouterr().out)
    assert report == {
        "host": "localhost",
        "port": 8443,
        "pqc_readiness": "UNKNOWN",
        "timeout": 1.5,
    }


def test_explain_finding_from_audit_document(tmp_path: Path, capsys) -> None:
    audit_file = tmp_path / "audit.json"
    audit_file.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "finding_id": "QG-demo-finding",
                        "rule_id": "QG-RSA-SIGNATURE",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    assert (
        cli.main(
            [
                "explain",
                "QG-demo-finding",
                "--input",
                str(audit_file),
                "--json",
            ]
        )
        == cli.EXIT_OK
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["type"] == "finding"
    assert payload["finding"]["finding_id"] == "QG-demo-finding"


def test_help_version_and_usage_exit_codes_are_stable(capsys) -> None:
    assert cli.main(["--help"]) == cli.EXIT_OK
    assert "audit" in capsys.readouterr().out

    assert cli.main(["--version"]) == cli.EXIT_OK
    assert "PQCensus" in capsys.readouterr().out

    assert cli.main([]) == cli.EXIT_USAGE
    assert "usage" in capsys.readouterr().err.lower()

    assert cli.main(["--definitely-not-an-option"]) == cli.EXIT_USAGE
    assert "usage" in capsys.readouterr().err.lower()

    assert cli.main(["audit", "--format", "bogus"]) == cli.EXIT_USAGE


def test_internal_failure_is_a_distinct_error_not_a_findings_exit(monkeypatch, capsys) -> None:
    def boom(path, **kwargs):
        raise RuntimeError("analyzer exploded")

    monkeypatch.setattr(cli, "audit", boom)
    assert cli.main(["audit", ".", "--fail-on", "none", "--quiet"]) == cli.EXIT_ERROR
    captured = capsys.readouterr()
    assert "internal error" in captured.err
    assert "Traceback" not in captured.err


def test_keyboard_interrupt_exits_130_without_traceback(monkeypatch, capsys) -> None:
    def interrupt(path, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "audit", interrupt)
    assert cli.main(["audit", "."]) == cli.EXIT_INTERRUPTED
    captured = capsys.readouterr()
    assert "interrupted" in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.skipif(os.geteuid() == 0, reason="permission checks are meaningless as root")
def test_unreadable_file_is_reported_not_swallowed(tmp_path: Path, capsys) -> None:
    root = _repo(tmp_path / "repo")
    locked = root / "locked.py"
    locked.write_text("import hashlib\nhashlib.sha256(b'x')\n", encoding="utf-8")
    locked.chmod(0)
    try:
        assert cli.main(["audit", str(root), "--fail-on", "none"]) == cli.EXIT_OK
        captured = capsys.readouterr()
        assert "Permission errors: 1" in captured.err
    finally:
        locked.chmod(0o644)


def test_malformed_quantumguard_toml_is_visible_in_output(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    (root / "quantumguard.toml").write_text("[[suppressions]\nbroken = [\n", encoding="utf-8")
    assert cli.main(["audit", str(root), "--fail-on", "none", "--quiet"]) == cli.EXIT_OK
    output = tmp_path / "out"
    assert (
        cli.main(["audit", str(root), "--output", str(output), "--fail-on", "none", "--quiet"])
        == cli.EXIT_OK
    )
    payload = json.loads((output / "quantumguard-audit.json").read_text(encoding="utf-8"))
    assert any(item["path"] == "quantumguard.toml" for item in payload["parser_errors"])
