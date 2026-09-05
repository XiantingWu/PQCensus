from __future__ import annotations

import argparse
import json
import re
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHA_RE = re.compile(r"[0-9a-f]{40}")
TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$")


def _run(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True).strip()


def _version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate that a release tag points to the authenticated evidence commit."
    )
    parser.add_argument("--tag", required=True)
    parser.add_argument("--main-ref", default="refs/remotes/origin/main")
    args = parser.parse_args(argv)

    failures: list[str] = []
    version = _version()
    expected_tag = f"v{version}"
    if TAG_RE.fullmatch(args.tag) is None:
        failures.append("tag must use the vMAJOR.MINOR.PATCH[- or . prerelease] format")
    if args.tag != expected_tag:
        failures.append(f"tag must be {expected_tag}, found {args.tag}")

    try:
        tag_commit = _run("rev-parse", "--verify", f"{args.tag}^{{commit}}")
        head = _run("rev-parse", "HEAD")
    except subprocess.CalledProcessError as exc:
        print(f"FAIL release tag authority: git lookup failed ({exc})")
        return 2
    if tag_commit != head:
        failures.append("checked-out HEAD is not the requested tag commit")
    if _run("describe", "--tags", "--exact-match", "HEAD") != args.tag:
        failures.append("HEAD does not have the requested exact tag")

    evidence = ROOT / "benchmarks" / "releases" / version
    manifest_path = evidence / "release-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        failures.append(f"release manifest is unreadable: {exc}")
        manifest = {}
    source_commit = manifest.get("source_commit") if isinstance(manifest, dict) else None
    if not isinstance(source_commit, str) or SHA_RE.fullmatch(source_commit) is None:
        failures.append("release manifest source_commit is not an exact Git SHA")
    else:
        parents = _run("rev-list", "--parents", "-n", "1", head).split()
        if len(parents) != 2 or parents[1] != source_commit:
            failures.append("tag commit must be a direct evidence-only child of source_commit")

    try:
        changed = {
            path
            for path in _run("diff-tree", "--no-commit-id", "--name-only", "-r", head).splitlines()
            if path
        }
    except subprocess.CalledProcessError as exc:
        failures.append(f"cannot inspect tag commit diff: {exc}")
        changed = set()
    evidence_prefix = f"benchmarks/releases/{version}/"
    if not changed:
        failures.append("tag commit has no evidence changes")
    elif any(not path.startswith(evidence_prefix) for path in changed):
        failures.append("tag commit changes files outside its versioned release evidence directory")
    expected_files = {
        f"{evidence_prefix}synthetic-results.json",
        f"{evidence_prefix}real-code-results.json",
        f"{evidence_prefix}end-to-end-results.json",
        f"{evidence_prefix}release-manifest.json",
    }
    if changed != expected_files:
        failures.append("tag commit must change exactly the four canonical evidence files")

    try:
        main_commit = _run("rev-parse", "--verify", f"{args.main_ref}^{{commit}}")
        ancestor = subprocess.run(
            ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", head, main_commit],
            text=True,
            capture_output=True,
        )
        if ancestor.returncode:
            failures.append("tag commit is not an ancestor of canonical main history")
    except subprocess.CalledProcessError as exc:
        failures.append(f"canonical main reference is unavailable: {args.main_ref}: {exc}")

    if failures:
        print("FAIL release tag authority")
        print("\n".join(f"- {failure}" for failure in sorted(set(failures))))
        return 1
    print(f"PASS release tag authority: {args.tag} -> evidence commit {head}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
