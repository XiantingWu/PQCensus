from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS_PREFIX = "benchmarks/corpus/"
CONFLICT_START = "<" * 7
CONFLICT_SEPARATOR = "=" * 7
CONFLICT_END = ">" * 7


def _git(*args: str, text: bool = False) -> subprocess.CompletedProcess[bytes | str]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=text,
    )


def _index_files() -> list[str]:
    result = _git("ls-files", "-z")
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"cannot enumerate the staged index: {detail}")
    return [os.fsdecode(item) for item in result.stdout.split(b"\0") if item]


def _staged_bytes(relative: str) -> bytes:
    result = _git("show", f":{relative}")
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"cannot read staged blob {relative}: {detail}")
    return result.stdout


def _check_conflict_blocks(relative: str, data: bytes) -> list[str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return []

    failures: list[str] = []
    start_line: int | None = None
    has_separator = False
    for line_number, line in enumerate(text.splitlines(), start=1):
        marker = line.strip()
        if marker.startswith(CONFLICT_START):
            if start_line is not None:
                failures.append(f"{relative}:{start_line}: nested conflict marker")
            start_line = line_number
            has_separator = False
        elif marker == CONFLICT_SEPARATOR:
            if start_line is not None:
                has_separator = True
            # A standalone RST heading underline is intentionally ignored.
        elif marker.startswith(CONFLICT_END):
            if start_line is None:
                failures.append(f"{relative}:{line_number}: unmatched conflict end marker")
            elif not has_separator:
                failures.append(f"{relative}:{start_line}: conflict block has no separator")
            else:
                failures.append(f"{relative}:{start_line}: complete conflict block")
            start_line = None
            has_separator = False

    if start_line is not None:
        failures.append(f"{relative}:{start_line}: unterminated conflict block")
    return failures


def main() -> int:
    failures: list[str] = []

    current_root = Path.cwd().resolve()
    if current_root != ROOT:
        failures.append(f"cwd is {current_root}, expected repository root {ROOT}")

    root_result = _git("rev-parse", "--show-toplevel", text=True)
    git_root = Path(root_result.stdout.strip()).resolve() if root_result.returncode == 0 else None
    if git_root != ROOT:
        detail = root_result.stderr.strip() if root_result.returncode else str(git_root)
        failures.append(f"git toplevel is {detail}, expected {ROOT}")

    if failures:
        _report_failures(failures)
        return 1

    try:
        index_files = _index_files()
    except RuntimeError as exc:
        _report_failures([str(exc)])
        return 1

    corpus_files = [relative for relative in index_files if relative.startswith(CORPUS_PREFIX)]
    normal_files = [relative for relative in index_files if not relative.startswith(CORPUS_PREFIX)]

    unstaged = _git("diff", "--quiet")
    if unstaged.returncode:
        failures.append("working tree has unstaged changes")

    normal_diff = _git(
        "diff",
        "--cached",
        "--check",
        "--",
        ".",
        ":(exclude)" + CORPUS_PREFIX + "**",
        text=True,
    )
    if normal_diff.returncode:
        detail = (normal_diff.stdout + "\n" + normal_diff.stderr).strip()
        failures.append(f"normal staged diff check failed:\n{detail}")

    attr_failures: list[str] = []
    byte_failures: list[str] = []
    for relative in corpus_files:
        attr = _git("check-attr", "text", "--", relative, text=True)
        value = attr.stdout.rsplit(":", 1)[-1].strip() if attr.returncode == 0 else "error"
        if attr.returncode or value != "unset":
            attr_failures.append(f"{relative}: text attribute is {value!r}, expected 'unset'")

        working_path = ROOT / relative
        try:
            working_bytes = working_path.read_bytes()
            staged = _staged_bytes(relative)
        except (OSError, RuntimeError) as exc:
            byte_failures.append(f"{relative}: {exc}")
        else:
            if working_bytes != staged:
                byte_failures.append(f"{relative}: working tree bytes differ from staged blob")

    if attr_failures:
        failures.extend(attr_failures)
    if byte_failures:
        failures.extend(byte_failures)

    conflict_failures: list[str] = []
    try:
        for relative in normal_files:
            conflict_failures.extend(_check_conflict_blocks(relative, _staged_bytes(relative)))
    except RuntimeError as exc:
        conflict_failures.append(str(exc))
    failures.extend(conflict_failures)

    tracked_ds_store = [relative for relative in index_files if Path(relative).name == ".DS_Store"]
    if tracked_ds_store:
        failures.append("tracked .DS_Store files: " + ", ".join(tracked_ds_store))

    if failures:
        _report_failures(failures)
        return 1

    print(f"PASS true repository root ({ROOT})")
    print("PASS no unstaged changes")
    print(f"PASS normal staged diff check ({len(normal_files)} files; corpus excluded)")
    print(f"PASS corpus Git attributes ({len(corpus_files)} files; text=unset)")
    print(f"PASS corpus byte equality ({len(corpus_files)} files; mismatches=0)")
    print(f"PASS semantic conflict scan ({len(normal_files)} non-corpus files; complete blocks=0)")
    print("PASS no tracked .DS_Store")
    return 0


def _report_failures(failures: list[str]) -> None:
    print("FAIL staged snapshot validation")
    for failure in failures:
        print(f"- {failure}")


if __name__ == "__main__":
    sys.exit(main())
