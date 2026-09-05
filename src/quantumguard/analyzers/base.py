from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ..models import CryptoAsset, Finding


@dataclass
class AnalyzerContext:
    root: Path
    rules_root: Path | None = None
    parser_errors: list[dict[str, str]] = field(default_factory=list)
    assets: list[CryptoAsset] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class Analyzer(Protocol):
    name: str

    def analyze(self, path: Path, source: str, context: AnalyzerContext) -> list[Finding]: ...
