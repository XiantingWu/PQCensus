from __future__ import annotations

from scripts.action_security_check import ROOT, audit_action


def test_untrusted_expression_in_run_is_rejected() -> None:
    action = """
runs:
  using: composite
  steps:
    - run: echo '${{ github.event.pull_request.title }}'
"""
    failures = audit_action(action, "fixture.yml")
    assert any("embedded in run" in item for item in failures)


def test_untrusted_input_in_env_is_allowed() -> None:
    action = """
runs:
  using: composite
  steps:
    - name: print
      env:
        TITLE: ${{ github.event.pull_request.title }}
      run: printf '%s\\n' "$TITLE"
"""
    assert audit_action(action, "fixture.yml") == []


def test_self_hosted_and_unpinned_actions_are_rejected() -> None:
    action = """
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
      with:
        runner: self-hosted
"""
    failures = audit_action(action, "fixture.yml")
    assert any("runner" in item for item in failures)
    assert any("commit SHA" in item for item in failures)


def test_private_repository_conditions_are_rejected() -> None:
    action = """
runs:
  using: composite
  steps:
    - if: ${{ !github.event.repository.private }}
      run: echo "ok"
"""
    failures = audit_action(action, "fixture.yml")
    assert any("private-repository" in item for item in failures)


def test_clean_action_passes() -> None:
    action_text = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert audit_action(action_text, "action.yml") == []
