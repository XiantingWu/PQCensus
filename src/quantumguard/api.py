from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable, cast

from ._version import __version__
from .agility import evaluate_agility
from .analyzers.base import Analyzer, AnalyzerContext
from .analyzers.config import ConfigAnalyzer
from .analyzers.python import PythonAnalyzer
from .analyzers.textual import ExperimentalTextAnalyzer
from .dependencies import crypto_dependency, discover_dependencies
from .hndl import assess_hndl
from .migration import build_migration_plans
from .models import (
    AuditResult,
    Confidence,
    CryptoAsset,
    Purpose,
)
from .policy import algorithm_status
from .reporting import inventory_document, migration_document
from .risk import RiskContext, assess_finding
from .suppression import apply_suppressions
from .util import iter_source_files, relative_posix

DEFAULT_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".java",
    ".rs",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".cxx",
    ".hpp",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
}
DEFAULT_MAX_FILES = 10_000
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 100 * 1024 * 1024


def audit(
    path: str | Path,
    *,
    analyzers: Iterable[Analyzer] | None = None,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    exposure: str | None = None,
    data_sensitivity: str | None = None,
    confidentiality_lifetime_years: int | None = None,
    system_context: str | None = None,
) -> AuditResult:
    raw_root = Path(path).expanduser()
    if raw_root.is_symlink():
        raise ValueError(f"scan path must not be a symlink: {path}")
    root = raw_root.resolve()
    if not root.is_dir():
        raise ValueError(f"scan path is not a directory: {path}")
    if min(max_files, max_file_bytes, max_total_bytes) <= 0:
        raise ValueError("scan limits must be positive")
    if confidentiality_lifetime_years is not None and confidentiality_lifetime_years < 0:
        raise ValueError("confidentiality lifetime must be zero or greater")

    files, scan_stats = iter_source_files(
        root,
        extensions=DEFAULT_EXTENSIONS,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
    )
    context = AnalyzerContext(root=root, rules_root=_project_root())
    selected_analyzers = list(
        analyzers or (PythonAnalyzer(), ExperimentalTextAnalyzer(), ConfigAnalyzer())
    )
    findings = []
    source_texts = []
    for file_path, source in files:
        rel = relative_posix(file_path, root)
        source_texts.append((rel, source))
        for analyzer in selected_analyzers:
            if isinstance(analyzer, PythonAnalyzer) and file_path.suffix.lower() != ".py":
                continue
            if (
                isinstance(analyzer, ExperimentalTextAnalyzer)
                and file_path.suffix.lower() not in analyzer.extensions
            ):
                continue
            if (
                isinstance(analyzer, ConfigAnalyzer)
                and file_path.suffix.lower() not in analyzer.extensions
            ):
                continue
            findings.extend(analyzer.analyze(file_path, source, context))

    unique = {finding.finding_id: finding for finding in findings}
    findings = sorted(
        unique.values(),
        key=lambda item: (
            item.source_path,
            item.span.start_line,
            item.span.start_column,
            item.finding_id,
        ),
    )
    for finding in findings:
        assess_finding(
            finding,
            RiskContext(
                exposure=exposure or "unknown",
                public_reachability=exposure or "unknown",
                data_lifetime_years=confidentiality_lifetime_years,
                production=finding.environment != "test",
                hndl_relevant=(
                    True
                    if confidentiality_lifetime_years is not None
                    and confidentiality_lifetime_years >= 10
                    and exposure in {"public", "internet", "external"}
                    else None
                ),
            ),
        )
    suppressions = apply_suppressions(findings, root, context.parser_errors)
    dependencies = discover_dependencies(root, max_file_bytes=max_file_bytes)
    assets = _assets(findings, dependencies)
    plans = build_migration_plans(findings)
    agility = evaluate_agility(findings, dependencies, source_texts)
    hndl = assess_hndl(
        findings,
        data_sensitivity=data_sensitivity,
        confidentiality_lifetime_years=confidentiality_lifetime_years,
        system_context=system_context,
        exposure=exposure,
    )
    return AuditResult(
        repository=root.name,
        files_analyzed=len(files),
        bytes_analyzed=scan_stats["bytes"],
        parser_errors=sorted(context.parser_errors, key=lambda item: item["path"]),
        findings=findings,
        assets=assets,
        dependencies=dependencies,
        migration_plans=plans,
        agility=agility,
        hndl=hndl,
        suppressions=suppressions,
        limits={
            "max_files": max_files,
            "max_file_bytes": max_file_bytes,
            "max_total_bytes": max_total_bytes,
            "skipped": {
                key: value for key, value in scan_stats.items() if key not in {"selected", "bytes"}
            },
        },
        generated_by=__version__,
    )


def inventory(path: str | Path, **kwargs: object) -> dict[str, object]:
    return inventory_document(audit(path, **cast(Any, kwargs)))


def plan(path: str | Path, **kwargs: object) -> dict[str, object]:
    return migration_document(audit(path, **cast(Any, kwargs)))


def _assets(findings: list, dependencies: list) -> list[CryptoAsset]:
    assets: dict[str, CryptoAsset] = {}
    for finding in findings:
        dependency = _finding_dependency(finding, dependencies)
        asset_type = (
            "signing-workflow"
            if finding.purpose == Purpose.SIGNATURE
            else "kem-key-establishment-workflow"
            if finding.purpose == Purpose.KEY_ESTABLISHMENT
            else "protocol-configuration"
            if finding.category == "protocol-configuration"
            else "algorithm-use"
        )
        material = f"{asset_type}|{finding.algorithm}|{finding.purpose.value}|{finding.source_path}|{finding.span.start_line}"
        asset_id = "QGA-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]
        assets[asset_id] = CryptoAsset(
            asset_id=asset_id,
            asset_type=asset_type,
            name=f"{finding.algorithm} {finding.purpose.value.lower()}",
            algorithm=finding.algorithm,
            purpose=finding.purpose,
            source_path=finding.source_path,
            span=finding.span,
            dependency=dependency,
            quantum_status=algorithm_status(finding.algorithm),
            provenance=[finding.finding_id, finding.analyzer],
            confidence=finding.confidence,
        )
    for dependency in dependencies:
        if not crypto_dependency(dependency.name):
            continue
        material = f"crypto-library|{dependency.ecosystem}|{dependency.name}|{dependency.version}|{dependency.manifest}"
        asset_id = "QGA-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]
        assets[asset_id] = CryptoAsset(
            asset_id=asset_id,
            asset_type="crypto-library",
            name=dependency.name,
            algorithm=None,
            purpose=Purpose.UNKNOWN,
            source_path=dependency.manifest,
            span=None,
            dependency=dependency.name,
            quantum_status="unknown",
            provenance=[f"dependency:{dependency.manifest}"],
            confidence=Confidence.HIGH,
        )
    return sorted(assets.values(), key=lambda item: (item.asset_type, item.name, item.asset_id))


def _finding_dependency(finding: object, dependencies: list) -> str | None:
    detail = " ".join(evidence.detail.lower() for evidence in getattr(finding, "evidence", []))
    candidates = []
    for dependency in dependencies:
        name = dependency.name.lower()
        if "call=jwt." in detail and name in {"pyjwt", "jwt"}:
            candidates.append(dependency.name)
        elif "call=crypto." in detail and "pycryptodome" in name:
            candidates.append(dependency.name)
        elif "call=cryptography." in detail and name == "cryptography":
            candidates.append(dependency.name)
    if candidates:
        return sorted(candidates, key=str.lower)[0]
    crypto_dependencies = sorted(
        {dependency.name for dependency in dependencies if crypto_dependency(dependency.name)},
        key=str.lower,
    )
    return crypto_dependencies[0] if len(crypto_dependencies) == 1 else None


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]
