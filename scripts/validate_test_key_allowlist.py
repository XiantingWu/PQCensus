from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "benchmarks/test-key-allowlist.json"
PRIVATE_KEY_MARKER = re.compile(rb"-----BEGIN " + rb"(?:RSA |EC |OPENSSH )?" + rb"PRIVATE KEY-----")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular_file(relative: str) -> Path:
    candidate = (ROOT / relative).resolve()
    try:
        candidate.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"allowlisted path escapes repository: {relative}") from exc
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"allowlisted path is missing or not a regular file: {relative}")
    return candidate


def main() -> int:
    failures: list[str] = []
    try:
        payload = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"FAIL test-key allowlist: {exc}")
        return 2

    if payload.get("schema_version") != 1:
        failures.append("schema_version must be 1")
    entries = payload.get("entries")
    if not isinstance(entries, list) or not entries:
        failures.append("entries must be a non-empty list")
        entries = []

    allowed: dict[str, str] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            failures.append(f"entry {index} is not an object")
            continue
        path_text = entry.get("path")
        expected_hash = entry.get("sha256")
        if not isinstance(path_text, str) or not path_text or Path(path_text).is_absolute():
            failures.append(f"entry {index} has an invalid relative path")
            continue
        if path_text in allowed:
            failures.append(f"duplicate allowlist path: {path_text}")
            continue
        if (
            not isinstance(expected_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
        ):
            failures.append(f"invalid SHA256 for allowlist path: {path_text}")
            continue
        try:
            path = _regular_file(path_text)
        except ValueError as exc:
            failures.append(str(exc))
            continue
        actual_hash = _sha256(path)
        if actual_hash != expected_hash:
            failures.append(f"SHA256 mismatch: {path_text}")
        allowed[path_text] = expected_hash
        if not PRIVATE_KEY_MARKER.search(path.read_bytes()):
            failures.append(f"allowlisted file has no private-key marker: {path_text}")

    discovered: set[str] = set()
    for path in ROOT.rglob("*"):
        if (
            not path.is_file()
            or path.is_symlink()
            or ".git" in path.parts
            or any(
                part in {"__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"}
                for part in path.parts
            )
        ):
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            failures.append(f"cannot scan {path.relative_to(ROOT)}: {exc}")
            continue
        if PRIVATE_KEY_MARKER.search(data):
            discovered.add(path.relative_to(ROOT).as_posix())

    unexpected = discovered - set(allowed)
    missing = set(allowed) - discovered
    failures.extend(f"unregistered private-key marker: {path}" for path in sorted(unexpected))
    failures.extend(
        f"allowlist entry no longer contains marker: {path}" for path in sorted(missing)
    )

    if failures:
        print("FAIL test-key allowlist")
        print("\n".join(f"- {failure}" for failure in sorted(set(failures))))
        return 1
    print(f"PASS test-key allowlist: {len(allowed)} exact upstream fixture files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
