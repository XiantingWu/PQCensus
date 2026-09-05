from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ._version import __version__
from .api import audit
from .doctor import run_doctor
from .models import AuditResult, canonical_json
from .policy import explain_rule, load_rules
from .reporting import (
    cbom_document,
    cyclonedx_cbom_document,
    inventory_document,
    markdown_report,
    migration_document,
    sarif_document,
)
from .tls import inspect_tls
from .util import severity_rank

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_ERROR = 3
EXIT_INTERRUPTED = 130
PRODUCT_NAME = "PQCensus"
PRIMARY_CLI = "pqcensus"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PRIMARY_CLI,
        description="Evidence-grounded cryptographic inventory and post-quantum migration planning.",
    )
    parser.add_argument("--version", action="version", version=f"{PRODUCT_NAME} {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help=f"validate the local {PRODUCT_NAME} runtime")
    doctor.add_argument("--json", action="store_true")
    doctor.add_argument("--strict", action="store_true")

    for name, help_text in (
        ("audit", "scan, assess, prioritize, and plan"),
        ("inventory", "write the cryptographic inventory"),
        ("cbom", "write the native cryptographic bill of materials"),
        ("plan", "write context-aware migration plans"),
        ("agility", "score observable crypto-agility signals"),
        ("verify", "run the deterministic scan twice and compare bytes"),
        ("baseline", "record stable finding IDs for later diff mode"),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("path", nargs="?", default=".")
        command.add_argument("--json", action="store_true")
        command.add_argument("--output", type=Path)
        if name == "audit":
            command.add_argument(
                "--format", choices=("console", "json", "markdown", "sarif"), default="console"
            )
            command.add_argument(
                "--fail-on", choices=("none", "low", "medium", "high", "critical"), default="high"
            )
            command.add_argument("--baseline", type=Path)
            command.add_argument("--quiet", action="store_true")
        if name == "cbom":
            command.add_argument("--format", choices=("cyclonedx", "native"), default="cyclonedx")
        if name in {"audit", "inventory", "cbom", "plan", "agility"}:
            _context_arguments(command)

    rules = sub.add_parser("rules", help="list public policy rules")
    rules.add_argument("--json", action="store_true")

    explain = sub.add_parser("explain", help="explain a rule or finding from an audit JSON file")
    explain.add_argument("identifier")
    explain.add_argument("--input", type=Path)
    explain.add_argument("--json", action="store_true")

    tls = sub.add_parser("tls", help="perform one bounded TLS handshake")
    tls.add_argument("host")
    tls.add_argument("--port", type=int, default=443)
    tls.add_argument("--timeout", type=float, default=5.0)
    tls.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return _dispatch(args)
    except KeyboardInterrupt:
        print(f"{PRODUCT_NAME} interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except SystemExit as exc:
        if isinstance(exc.code, int):
            return exc.code
        raise
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"{PRODUCT_NAME} error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # pragma: no cover - defensive boundary
        print(f"{PRODUCT_NAME} internal error: {exc}", file=sys.stderr)
        return EXIT_ERROR


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "doctor":
        payload = run_doctor(strict=args.strict)
        _emit_json(payload) if args.json else _doctor_console(payload)
        return EXIT_OK if payload["ok"] else EXIT_ERROR
    if args.command == "rules":
        payload = load_rules()
        if args.json:
            _emit_json(payload)
        else:
            for rule in payload["rules"]:
                print(
                    f"{rule['id']:<32} {rule['algorithm_family']:<16} {','.join(rule['purposes'])}"
                )
        return EXIT_OK
    if args.command == "explain":
        payload = _explain(args.identifier, args.input)
        _emit_json(payload) if args.json else print(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)
        )
        return EXIT_OK
    if args.command == "tls":
        payload = inspect_tls(args.host, port=args.port, timeout=args.timeout)
        _emit_json(payload) if args.json else print(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)
        )
        return EXIT_OK

    kwargs = _context_kwargs(args)
    result = audit(args.path, **kwargs)
    if args.command == "verify":
        second = audit(args.path, **kwargs)
        first_json = canonical_json(result.to_dict())
        second_json = canonical_json(second.to_dict())
        payload = {
            "schema_version": 1,
            "deterministic": first_json == second_json,
            "first_sha256": __import__("hashlib").sha256(first_json.encode()).hexdigest(),
            "second_sha256": __import__("hashlib").sha256(second_json.encode()).hexdigest(),
        }
        _write_or_print(payload, args.output, args.json)
        return EXIT_OK if payload["deterministic"] else EXIT_ERROR
    if args.command == "inventory":
        _write_or_print(inventory_document(result), args.output, True)
        return EXIT_OK
    if args.command == "cbom":
        payload = (
            cyclonedx_cbom_document(result) if args.format == "cyclonedx" else cbom_document(result)
        )
        _write_or_print(payload, args.output, True)
        return EXIT_OK
    if args.command == "plan":
        _write_or_print(migration_document(result), args.output, True)
        return EXIT_OK
    if args.command == "agility":
        _write_or_print(result.agility, args.output, True)
        return EXIT_OK
    if args.command == "baseline":
        payload = _baseline_document(result)
        _write_or_print(payload, args.output, True)
        return EXIT_OK
    return _audit_command(result, args)


def _audit_command(result: AuditResult, args: argparse.Namespace) -> int:
    baseline = _load_baseline(args.baseline) if args.baseline else None
    diff = _baseline_diff(result, baseline) if baseline is not None else None
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        _write_json(args.output / "quantumguard-audit.json", result.to_dict())
        _write_json(args.output / "quantumguard-inventory.json", inventory_document(result))
        _write_json(args.output / "quantumguard-cbom.json", cbom_document(result))
        _write_json(
            args.output / "quantumguard-cbom.cdx.json",
            cyclonedx_cbom_document(result),
        )
        _write_json(args.output / "quantumguard-migration-plan.json", migration_document(result))
        _write_json(args.output / "quantumguard.sarif", sarif_document(result))
        if diff is not None:
            _write_json(args.output / "quantumguard-baseline-diff.json", diff)
    format_name = "json" if args.json else args.format
    if not args.quiet:
        if format_name == "json":
            _emit_json(result.to_dict())
        elif format_name == "sarif":
            _emit_json(sarif_document(result))
        elif format_name == "markdown":
            print(markdown_report(result), end="")
        else:
            _audit_console(result, diff)
    threshold = args.fail_on.upper()
    if threshold == "NONE":
        return EXIT_OK
    candidates = (
        [item for item in result.findings if item.finding_id in set(diff["new"])]
        if diff is not None
        else result.findings
    )
    return (
        EXIT_FINDINGS
        if any(
            item.status == "active"
            and severity_rank(item.severity.value) >= severity_rank(threshold)
            for item in candidates
        )
        else EXIT_OK
    )


def _audit_console(result: AuditResult, diff: dict[str, Any] | None) -> None:
    active = [item for item in result.findings if item.status == "active"]
    print(f"{PRODUCT_NAME} {result.generated_by}")
    print(f"Repository: {result.repository}")
    print(f"Files analyzed: {result.files_analyzed}")
    print(f"Crypto assets: {len(result.assets)}")
    print(f"Crypto agility: {result.agility['overall_score']}/100")
    print(f"HNDL: {result.hndl['status']}")
    if result.parser_errors:
        print(f"Parse/config errors: {len(result.parser_errors)}")
    if result.limits["skipped"].get("permission"):
        print(
            f"Permission errors: {result.limits['skipped']['permission']} file(s) unreadable",
            file=sys.stderr,
        )
    if diff is not None:
        print(
            f"Baseline: {len(diff['new'])} new, {len(diff['fixed'])} fixed, {len(diff['unchanged'])} unchanged"
        )
    print("")
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        items = [item for item in active if item.severity.value == severity]
        if not items:
            continue
        print(severity.title())
        for item in items:
            print(
                f"  {item.source_path}:{item.span.start_line}  {item.algorithm}/{item.purpose.value}  {item.rule_id}"
            )
        print("")
    print(f"Suppressed: {len(result.suppressions)}")
    print(f"Migration plans: {len(result.migration_plans)}")


def _doctor_console(payload: dict[str, Any]) -> None:
    print(f"{PRODUCT_NAME} {payload['tool']['version']} doctor")
    for check in payload["checks"]:
        print(f"{'PASS' if check['ok'] else 'FAIL'} {check['name']}: {check['detail']}")
    print("PASS" if payload["ok"] else "FAIL")


def _context_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--exposure", choices=("internal", "external", "internet", "public"))
    parser.add_argument("--data-sensitivity")
    parser.add_argument("--confidentiality-lifetime-years", type=int)
    parser.add_argument("--system-context")


def _context_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    return {
        key: getattr(args, key, None)
        for key in (
            "exposure",
            "data_sensitivity",
            "confidentiality_lifetime_years",
            "system_context",
        )
        if hasattr(args, key)
    }


def _write_or_print(payload: dict[str, Any], output: Path | None, force_json: bool) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        _write_json(output, payload)
    else:
        _emit_json(payload)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _emit_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True, allow_nan=False))


def _baseline_document(result: AuditResult) -> dict[str, Any]:
    active = sorted(item.finding_id for item in result.findings if item.status == "active")
    return {
        "schema_version": 1,
        "tool_version": result.generated_by,
        "repository": result.repository,
        "finding_ids": active,
    }


def _load_baseline(path: Path) -> set[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1 or not isinstance(payload.get("finding_ids"), list):
        raise ValueError("baseline must be a schema_version=1 PQCensus baseline")
    return {str(value) for value in payload["finding_ids"]}


def _baseline_diff(result: AuditResult, baseline: set[str]) -> dict[str, Any]:
    current = {item.finding_id for item in result.findings if item.status == "active"}
    return {
        "schema_version": 1,
        "new": sorted(current - baseline),
        "fixed": sorted(baseline - current),
        "unchanged": sorted(current & baseline),
    }


def _explain(identifier: str, input_path: Path | None) -> dict[str, Any]:
    rule = explain_rule(identifier)
    if rule:
        return {"type": "rule", "rule": rule}
    if input_path:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
        for finding in payload.get("findings", []):
            if finding.get("finding_id") == identifier:
                return {"type": "finding", "finding": finding}
    raise ValueError(f"unknown rule/finding identifier: {identifier}")
