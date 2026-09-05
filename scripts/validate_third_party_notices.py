from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "benchmarks/third-party-corpus.json"
END_TO_END = ROOT / "benchmarks/end-to-end.json"
PROVENANCE = ROOT / "benchmarks/end-to-end-provenance.json"
NOTICE = ROOT / "benchmarks/THIRD_PARTY_NOTICES.md"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")


def main() -> int:
    failures: list[str] = []
    inventory = _load_json(INVENTORY, failures, "inventory")
    manifest = _load_json(END_TO_END, failures, "end-to-end manifest")
    provenance = _load_json(PROVENANCE, failures, "end-to-end provenance")
    if not NOTICE.is_file() or NOTICE.is_symlink():
        failures.append("third-party notice file is missing or unsafe")

    sources = inventory.get("sources") if isinstance(inventory, dict) else None
    if not isinstance(sources, list) or not sources:
        failures.append("inventory sources must be a non-empty list")
        sources = []
    if not isinstance(inventory, dict) or inventory.get("schema_version") != 1:
        failures.append("inventory schema_version must be 1")

    expected: dict[str, dict[str, Any]] = {}
    if isinstance(manifest, dict):
        for case in manifest.get("cases", []):
            if isinstance(case, dict) and isinstance(case.get("provenance_id"), str):
                expected[case["provenance_id"]] = case
    upstream = provenance.get("sources", {}) if isinstance(provenance, dict) else {}
    seen: set[str] = set()
    for index, entry in enumerate(sources):
        label = f"sources[{index}]"
        if not isinstance(entry, dict):
            failures.append(f"{label} must be an object")
            continue
        required = (
            "project",
            "version",
            "upstream_repository",
            "upstream_commit",
            "upstream_tag",
            "source_url",
            "snapshot_path",
            "source_tree_sha256",
            "license_spdx",
            "copyright_holder",
            "license_file",
            "license_sha256",
            "notice_file",
            "snapshot_purpose",
            "modified",
            "modifications",
        )
        for key in required:
            if key not in entry:
                failures.append(f"{label} missing {key}")

        project = str(entry.get("project", ""))
        version = str(entry.get("version", ""))
        identity = f"{project}-{version}"
        if identity in seen:
            failures.append(f"duplicate inventory identity: {identity}")
        seen.add(identity)
        commit = entry.get("upstream_commit")
        if not isinstance(commit, str) or COMMIT_RE.fullmatch(commit) is None:
            failures.append(f"{label} upstream_commit is not an exact Git SHA")
        source_tree = entry.get("source_tree_sha256")
        if not isinstance(source_tree, str) or SHA256_RE.fullmatch(source_tree) is None:
            failures.append(f"{label} source_tree_sha256 is invalid")
        license_hash = entry.get("license_sha256")
        if not isinstance(license_hash, str) or SHA256_RE.fullmatch(license_hash) is None:
            failures.append(f"{label} license_sha256 is invalid")
        for key in ("source_url", "upstream_repository", "license_spdx", "copyright_holder"):
            if not isinstance(entry.get(key), str) or not str(entry[key]).strip():
                failures.append(f"{label} {key} is empty")
        if entry.get("modified") is not False:
            failures.append(f"{label} modified must be false for the pinned snapshot")
        if "non-executed" not in str(entry.get("snapshot_purpose", "")).lower():
            failures.append(f"{label} snapshot purpose must document non-execution")

        snapshot = _safe_path(entry.get("snapshot_path"), label, failures)
        license_file = _safe_path(entry.get("license_file"), label, failures)
        notice_file = _safe_path(entry.get("notice_file"), label, failures)
        if snapshot is not None and (not snapshot.is_dir() or snapshot.is_symlink()):
            failures.append(f"{label} snapshot_path is not a regular directory")
        if license_file is not None:
            if not license_file.is_file() or license_file.is_symlink():
                failures.append(f"{label} license_file is missing or unsafe")
            else:
                actual = _sha256(license_file)
                if actual != license_hash:
                    failures.append(
                        f"{label} license hash mismatch: expected {license_hash}, actual {actual}"
                    )
        if notice_file is None or not notice_file.is_file() or notice_file.is_symlink():
            failures.append(f"{label} notice_file is missing or unsafe")
        elif not any(
            marker in notice_file.read_text(encoding="utf-8")
            for marker in (f"{project} {version}", f"{project}-{version}")
        ):
            failures.append(f"{label} notice does not identify {project} {version}")

        provenance_entry = upstream.get(project + "-" + version)
        if not isinstance(provenance_entry, dict):
            failures.append(f"{label} is not linked to end-to-end provenance")
        else:
            for key in ("commit", "source_path", "source_tree_sha256", "license"):
                if provenance_entry.get(key) != (
                    commit
                    if key == "commit"
                    else entry.get("snapshot_path")
                    if key == "source_path"
                    else source_tree
                    if key == "source_tree_sha256"
                    else entry.get("license_spdx")
                ):
                    failures.append(f"{label} disagrees with end-to-end provenance: {key}")
            if snapshot is not None and snapshot.is_dir() and not snapshot.is_symlink():
                actual_tree = _tree_sha256(snapshot)
                if actual_tree != source_tree:
                    failures.append(
                        f"{label} snapshot tree hash mismatch: expected {source_tree}, actual {actual_tree}"
                    )

    if expected and set(expected) != set(upstream):
        failures.append("end-to-end manifest/provenance source identities disagree")
    if expected and set(expected) != seen:
        failures.append("third-party inventory does not cover every registered end-to-end snapshot")

    if failures:
        print("FAIL third-party notices")
        print("\n".join(f"- {failure}" for failure in failures))
        return 1
    print(
        "PASS third-party notices: "
        f"{len(sources)} snapshots, {len(sources)} license files, "
        f"inventory_sha256={_sha256(INVENTORY)}"
    )
    return 0


def _load_json(path: Path, failures: list[str], label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        failures.append(f"{label} is unreadable: {exc}")
        return {}
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return {}
    return value


def _safe_path(value: object, label: str, failures: list[str]) -> Path | None:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        failures.append(f"{label} path must be repository-relative")
        return None
    relative = Path(value)
    if ".." in relative.parts:
        failures.append(f"{label} path contains parent traversal")
        return None
    raw_candidate = ROOT / relative
    if raw_candidate.is_symlink():
        failures.append(f"{label} path must not be a symlink")
        return None
    candidate = raw_candidate.resolve()
    try:
        candidate.relative_to(ROOT)
    except ValueError:
        failures.append(f"{label} path escapes repository")
        return None
    return candidate


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(
        item for item in root.rglob("*") if item.is_file() and not item.is_symlink()
    ):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
