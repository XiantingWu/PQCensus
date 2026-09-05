from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

SCHEMA_URL = (
    "https://raw.githubusercontent.com/microsoft/sarif-python-om/"
    "f99b8edb126e2a4ad8a61ffee63113887a6af035/sarif-schema-2.1.0.json"
)
SCHEMA_SHA256 = "6352a05f9d03f181b8d9c71a46bdacc4fcff9d8ade5364858b425ba0c0994ed7"
MAX_SCHEMA_BYTES = 2 * 1024 * 1024
MAX_SARIF_BYTES = 32 * 1024 * 1024


def fetch_schema(*, timeout: float = 20.0) -> dict[str, Any]:
    request = Request(SCHEMA_URL, headers={"User-Agent": "QuantumGuard-schema-validator/0.1"})
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - pinned HTTPS + hash
        body = response.read(MAX_SCHEMA_BYTES + 1)
    if len(body) > MAX_SCHEMA_BYTES:
        raise ValueError("official SARIF schema exceeds the safety limit")
    observed = hashlib.sha256(body).hexdigest()
    if observed != SCHEMA_SHA256:
        raise ValueError(f"official SARIF schema hash mismatch: {observed}")
    return json.loads(body)


def validation_errors(payload: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    try:
        from jsonschema import Draft7Validator, FormatChecker
    except ImportError as exc:  # pragma: no cover - release environment check
        raise RuntimeError(
            "install QuantumGuard with the 'dev' extra for schema validation"
        ) from exc
    Draft7Validator.check_schema(schema)
    validator = Draft7Validator(schema, format_checker=FormatChecker())
    return [error.message for error in sorted(validator.iter_errors(payload), key=str)]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate SARIF against the pinned official 2.1.0 schema."
    )
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    if not args.path.is_file() or args.path.is_symlink():
        parser.error("path must be a regular, non-symlink SARIF file")
    if args.path.stat().st_size > MAX_SARIF_BYTES:
        parser.error("SARIF file exceeds the 32 MiB safety limit")
    payload = json.loads(args.path.read_text(encoding="utf-8"))
    errors = validation_errors(payload, fetch_schema())
    if errors:
        print(f"FAIL: {errors[0]}")
        return 1
    print(f"PASS: SARIF 2.1.0 official schema ({SCHEMA_SHA256})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
