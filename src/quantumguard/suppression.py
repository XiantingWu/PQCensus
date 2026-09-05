from __future__ import annotations

import datetime as dt
import fnmatch
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .models import Finding

_INLINE = re.compile(
    r"quantumguard:\s*ignore\s+(?P<rule>QG-[A-Z0-9-]+)\s+reason=(?P<reason>[^;#]+?)(?:\s+expires=(?P<expires>\d{4}-\d{2}-\d{2}))?\s*$",
    re.I,
)


@dataclass(frozen=True)
class Suppression:
    rule_id: str
    reason: str
    source: str
    path: str | None = None
    expires: str | None = None

    def active(self, today: dt.date | None = None) -> bool:
        if not self.expires:
            return True
        try:
            return dt.date.fromisoformat(self.expires) >= (today or dt.date.today())
        except ValueError:
            return False

    def matches(self, finding: Finding) -> bool:
        return (
            self.active()
            and self.rule_id.upper() in {"ALL", finding.rule_id.upper()}
            and (not self.path or fnmatch.fnmatch(finding.source_path, self.path))
        )

    def to_dict(self) -> dict[str, str | None]:
        return {
            "rule_id": self.rule_id,
            "reason": self.reason,
            "source": self.source,
            "path": self.path,
            "expires": self.expires,
        }


def load_config_suppressions(
    root: Path, parser_errors: list[dict[str, str]] | None = None
) -> list[Suppression]:
    path = root / "quantumguard.toml"
    if not path.is_file() or path.is_symlink():
        return []
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        if parser_errors is not None:
            parser_errors.append({"path": "quantumguard.toml", "error": str(exc)})
        return []
    result = []
    for item in payload.get("suppressions", []):
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("rule_id") or item.get("rule") or "").strip()
        reason = str(item.get("reason") or "").strip()
        if not rule_id or not reason:
            continue
        result.append(
            Suppression(
                rule_id=rule_id,
                reason=reason,
                source="quantumguard.toml",
                path=str(item.get("path") or "").strip() or None,
                expires=str(item.get("expires") or "").strip() or None,
            )
        )
    return result


def inline_suppression(finding: Finding, root: Path) -> Suppression | None:
    path = root / finding.source_path
    if not path.is_file() or path.is_symlink():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    candidates = {
        finding.span.start_line,
        max(1, finding.span.start_line - 1),
    }
    for line_number in sorted(candidates):
        if line_number > len(lines):
            continue
        match = _INLINE.search(lines[line_number - 1])
        if not match:
            continue
        suppression = Suppression(
            rule_id=match.group("rule").upper(),
            reason=match.group("reason").strip(),
            source=f"{finding.source_path}:{line_number}",
            expires=match.group("expires"),
        )
        if suppression.matches(finding):
            return suppression
    return None


def apply_suppressions(
    findings: list[Finding],
    root: Path,
    parser_errors: list[dict[str, str]] | None = None,
) -> list[dict[str, str | None]]:
    configured = load_config_suppressions(root, parser_errors)
    audit_log: list[dict[str, str | None]] = []
    for finding in findings:
        matched = inline_suppression(finding, root)
        if matched is None:
            matched = next((item for item in configured if item.matches(finding)), None)
        if matched is None:
            continue
        finding.status = "suppressed"
        finding.suppression = matched.to_dict()
        audit_log.append({"finding_id": finding.finding_id, **matched.to_dict()})
    return sorted(audit_log, key=lambda item: str(item["finding_id"]))
