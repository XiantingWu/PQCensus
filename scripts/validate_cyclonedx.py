from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a CycloneDX 1.7 JSON document.")
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    if not args.path.is_file() or args.path.is_symlink():
        parser.error("path must be a regular, non-symlink file")
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError as exc:
        print(f"FAIL: install the dev extra for CycloneDX validation: {exc}")
        return 1
    payload = json.loads(args.path.read_text(encoding="utf-8"))
    error = JsonStrictValidator(SchemaVersion.V1_7).validate_str(
        json.dumps(payload, sort_keys=True)
    )
    if error is not None:
        print(f"FAIL: {error}")
        return 1
    print("PASS: CycloneDX 1.7 schema")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
