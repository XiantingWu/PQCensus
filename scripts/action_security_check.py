from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTION_FILE = ROOT / "action.yml"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
UNTRUSTED_EXPRESSION = re.compile(
    r"\$\{\{\s*(?:"
    r"github\.event\.(?:pull_request\.(?:title|body|head\.ref|head\.sha)|issue\.(?:title|body)|head_commit\.message)"
    r"|github\.head_ref|github\.ref_name"
    r")"
)


def main() -> int:
    if not ACTION_FILE.is_file() or ACTION_FILE.is_symlink():
        print("FAIL action security contract: action.yml missing or unsafe")
        return 1

    failures = audit_action(ACTION_FILE.read_text(encoding="utf-8"), "action.yml")
    if failures:
        print("FAIL action security contract")
        print("\n".join(f"- {failure}" for failure in sorted(set(failures))))
        return 1
    print("PASS action security contract: action.yml")
    return 0


def audit_action(text: str, label: str) -> list[str]:
    failures: list[str] = []
    if "pull_request_target:" in text:
        failures.append(f"{label}: pull_request_target is forbidden")
    if "self-hosted" in text:
        failures.append(f"{label}: self-hosted runner reference is forbidden")
    if "github.event.repository.private" in text:
        failures.append(f"{label}: private-repository condition is forbidden")

    failures.extend(_direct_shell_expression_failures(text, label))
    failures.extend(_action_pin_failures(text, label))
    return failures


def _direct_shell_expression_failures(text: str, label: str) -> list[str]:
    failures: list[str] = []
    lines = text.splitlines()
    run_indent: int | None = None
    for number, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if re.match(r"(?:-\s+)?run:\s*", stripped):
            run_indent = indent
            if UNTRUSTED_EXPRESSION.search(stripped):
                failures.append(
                    f"{label}:{number}: attacker-controlled expression is embedded in run"
                )
            if re.search(
                r"\beval\b|\bbash\s+-c\b|\bsh\s+-c\b|xargs[^\n]*\b(?:sh|bash)\b", stripped
            ):
                failures.append(f"{label}:{number}: dynamic shell evaluation is forbidden")
            continue
        if run_indent is not None and indent > run_indent:
            if UNTRUSTED_EXPRESSION.search(line):
                failures.append(
                    f"{label}:{number}: attacker-controlled expression is embedded in run"
                )
            if re.search(r"\beval\b|\bbash\s+-c\b|\bsh\s+-c\b|xargs[^\n]*\b(?:sh|bash)\b", line):
                failures.append(f"{label}:{number}: dynamic shell evaluation is forbidden")
            continue
        run_indent = None
    return failures


def _action_pin_failures(text: str, label: str) -> list[str]:
    failures: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^\s*(?:-\s+)?uses:\s*([^\s#]+)", line)
        if not match:
            continue
        reference = match.group(1)
        if reference.startswith("./") or reference.startswith("$"):
            continue
        if reference.startswith("docker://"):
            failures.append(
                f"{label}:{number}: container action must not be used without an immutable digest"
            )
            continue
        if "@" not in reference:
            failures.append(f"{label}:{number}: external Action is missing an immutable commit SHA")
            continue
        _, revision = reference.rsplit("@", 1)
        if FULL_SHA.fullmatch(revision) is None:
            failures.append(f"{label}:{number}: external Action is not pinned to a full commit SHA")
    return failures


if __name__ == "__main__":
    raise SystemExit(main())
