"""Wraps demo/run.py so the prompt-injection battery runs under pytest.

Each attack in demo/attacks.json becomes a parametrized test case. We
verify both static scoring (does Preflight assign the right tier?) and
runtime gating (does the GuardedShell actually refuse to execute it?).

We also exercise the v0.3 session graph: each `compositions` entry is a
sequence of commands run through one shell instance, asserting the final
command is escalated by the session state from prior commands.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import List

import pytest

from preflight.audit import AuditLog
from preflight.models import Decision, SourceContext
from preflight.scorer import score_command
from preflight.shell import GuardedShell


ATTACKS_PATH = Path(__file__).resolve().parent.parent / "demo" / "attacks.json"


DECISION_RANK = {
    Decision.ALLOW: 0,
    Decision.ALLOW_AND_LOG: 1,
    Decision.WARN: 2,
    Decision.CONFIRM_REQUIRED: 3,
    Decision.HARD_STOP: 4,
    Decision.OVERRIDE_REQUIRED: 4,
}


def _load():
    with ATTACKS_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def _load_attacks():
    return _load()["attacks"]


def _load_compositions():
    return _load().get("compositions", [])


@pytest.mark.parametrize("attack", _load_attacks(), ids=lambda a: a["id"])
def test_attack_scoring(attack):
    scored = score_command(attack["command"], source=SourceContext(attack["source"]))
    expected = Decision(attack["expected_decision"])
    assert DECISION_RANK[scored.decision] >= DECISION_RANK[expected], (
        f"{attack['id']}: decision {scored.decision.value} weaker than expected {expected.value} "
        f"(score={scored.stored_potential})"
    )
    assert scored.stored_potential >= attack["expected_min_score"], (
        f"{attack['id']}: score {scored.stored_potential} below expected min {attack['expected_min_score']}"
    )


@pytest.mark.parametrize("attack", _load_attacks(), ids=lambda a: a["id"])
def test_attack_runtime_gating(attack, tmp_path, monkeypatch):
    """Prove the GuardedShell refuses to execute every HARD_STOP attack and prompts on CONFIRM/WARN.

    We monkey-patch subprocess.run so even a bug that allowed execution wouldn't let the
    attack actually fire. Each call is recorded so we can assert it was never invoked
    on the malicious command.
    """
    invoked: List = []

    def fake_run(cmd, **kwargs):
        invoked.append(cmd)
        class P:
            returncode = 0
        return P()

    monkeypatch.setattr(subprocess, "run", fake_run)

    audit = AuditLog(path=tmp_path / "audit.jsonl", session_id="sess_demo")
    shell = GuardedShell(
        source=SourceContext(attack["source"]),
        audit=audit,
        cwd=str(tmp_path),
        # Always answer "n" / wrong phrase so even prompted decisions don't proceed.
        prompt_fn=lambda _: "n",
        out=lambda _: None,
        allow_overrides=False,
    )
    result = shell.run(attack["command"])

    expected = Decision(attack["expected_decision"])
    if expected == Decision.HARD_STOP:
        assert result.executed is False, (
            f"{attack['id']}: HARD_STOP attack was executed by the shell"
        )
        assert invoked == [], (
            f"{attack['id']}: subprocess.run was called for a HARD_STOP attack"
        )
        # And the audit record must say so.
        entries = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()[-1])
        assert entries["outcome"] == "blocked", (
            f"{attack['id']}: audit log did not record block (got {entries['outcome']})"
        )
    elif expected in (Decision.CONFIRM_REQUIRED, Decision.WARN):
        # User declined the prompt — must not have executed.
        assert result.executed is False, (
            f"{attack['id']}: attack ran despite declined prompt"
        )
        assert invoked == [], (
            f"{attack['id']}: subprocess.run was called despite declined prompt"
        )


@pytest.mark.parametrize("composition", _load_compositions(), ids=lambda c: c["id"])
def test_composition_escalates(composition, tmp_path, monkeypatch):
    """Run a sequence of commands through one shell; verify session-graph escalation.

    For each step we feed the prescribed `answer` (if any) to the prompt, run the
    command, and check the outcome. The final step is expected to be escalated:
    its decision must be at least as strict as `expected_final_decision`, and if
    `must_escalate_from_lower_decision` is true, the static (un-escalated) score
    must be lower than the achieved score, proving the session graph caused the
    escalation rather than the static scorer alone.
    """
    invoked: List = []

    def fake_run(cmd, **kwargs):
        invoked.append(cmd[-1] if isinstance(cmd, list) else cmd)
        class P:
            returncode = 0
        return P()

    monkeypatch.setattr(subprocess, "run", fake_run)

    # Apply per-composition repo scaffolding so RepoContext.detect picks it up.
    setup = composition.get("setup") or {}
    for d in setup.get("dirs", []):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
    for f in setup.get("files", []):
        path = tmp_path / f
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text("")

    answers: List[str] = []

    def prompt_fn(_):
        if not answers:
            raise EOFError("scripted prompt exhausted")
        return answers.pop(0)

    audit = AuditLog(path=tmp_path / "audit.jsonl", session_id="sess_composition")
    shell = GuardedShell(
        source=SourceContext(composition["source"]),
        cwd=str(tmp_path),
        audit=audit,
        prompt_fn=prompt_fn,
        out=lambda _: None,
    )

    last_step = None
    last_result = None
    for step in composition["sequence"]:
        if step.get("answer"):
            answers.append(step["answer"])
        result = shell.run(step["command"])
        last_step = step
        last_result = result

        if "expected_outcome" in step:
            assert result.outcome == step["expected_outcome"], (
                f"{composition['id']}: step `{step['command']}` "
                f"expected outcome {step['expected_outcome']}, got {result.outcome}"
            )

    # Verify the final step's escalation
    if "expected_final_decision" in last_step:
        expected = Decision(last_step["expected_final_decision"])
        assert DECISION_RANK[last_result.scored.decision] >= DECISION_RANK[expected], (
            f"{composition['id']}: final decision {last_result.scored.decision.value} "
            f"weaker than expected {expected.value}"
        )

    if "expected_min_score" in last_step:
        assert last_result.scored.stored_potential >= last_step["expected_min_score"], (
            f"{composition['id']}: final score {last_result.scored.stored_potential} "
            f"below expected min {last_step['expected_min_score']}"
        )

    # Prove the escalation came from the session graph, not just the static scorer.
    if last_step.get("must_escalate_from_lower_decision"):
        static = score_command(last_step["command"], source=SourceContext(composition["source"]))
        assert DECISION_RANK[last_result.scored.decision] > DECISION_RANK[static.decision], (
            f"{composition['id']}: final command's decision is {last_result.scored.decision.value} "
            f"but its static decision was already {static.decision.value} — session graph did not "
            f"escalate it. Pick a final command that is below CRITICAL on its own."
        )
        assert any("session:" in t for t in last_result.scored.triggers), (
            f"{composition['id']}: no session: trigger present on final command"
        )
