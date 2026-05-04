"""Demo battery runner.

Loads demo/attacks.json. Scores each individual attack (static), then
runs each composition sequence through a GuardedShell to verify the
session graph escalates the final command. Reports a per-row summary
and a session ledger for each composition.

Exit codes:
  0  all attacks and compositions met expectations
  1  one or more failed
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from preflight.audit import AuditLog
from preflight.models import Decision, RiskTier, SourceContext
from preflight.scorer import score_command
from preflight.shell import GuardedShell


HERE = Path(__file__).resolve().parent
ATTACKS_PATH = HERE / "attacks.json"


DECISION_RANK = {
    Decision.ALLOW: 0,
    Decision.ALLOW_AND_LOG: 1,
    Decision.WARN: 2,
    Decision.CONFIRM_REQUIRED: 3,
    Decision.HARD_STOP: 4,
    Decision.OVERRIDE_REQUIRED: 4,
}


@dataclass
class Result:
    attack_id: str
    surface: str
    category: str
    command: str
    score: int
    tier: RiskTier
    decision: Decision
    expected_decision: Decision
    expected_min_score: int
    passed: bool
    reason: str


def _load(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _load_attacks(path: Path):
    return _load(path)["attacks"]


def _load_compositions(path: Path):
    return _load(path).get("compositions", [])


def _meets_decision(actual: Decision, expected: Decision) -> bool:
    return DECISION_RANK[actual] >= DECISION_RANK[expected]


@dataclass
class CompositionResult:
    composition_id: str
    final_score: int
    final_tier: RiskTier
    final_decision: Decision
    static_decision: Decision
    expected_decision: Decision
    expected_min_score: int
    capabilities_at_end: List[str]
    passed: bool
    reason: str


def run(filter_id: str | None = None, verbose: bool = False) -> int:
    attacks = _load_attacks(ATTACKS_PATH)
    results: List[Result] = []

    for atk in attacks:
        if filter_id and atk["id"] != filter_id:
            continue
        scored = score_command(atk["command"], source=SourceContext(atk["source"]))
        expected_decision = Decision(atk["expected_decision"])
        expected_min_score = int(atk["expected_min_score"])

        decision_ok = _meets_decision(scored.decision, expected_decision)
        score_ok = scored.stored_potential >= expected_min_score
        passed = decision_ok and score_ok

        if not decision_ok:
            reason = (
                f"decision {scored.decision.value} weaker than expected "
                f"{expected_decision.value}"
            )
        elif not score_ok:
            reason = (
                f"score {scored.stored_potential} below expected min "
                f"{expected_min_score}"
            )
        else:
            reason = "ok"

        results.append(
            Result(
                attack_id=atk["id"],
                surface=atk["surface"],
                category=atk["category"],
                command=atk["command"],
                score=scored.stored_potential,
                tier=scored.risk_tier,
                decision=scored.decision,
                expected_decision=expected_decision,
                expected_min_score=expected_min_score,
                passed=passed,
                reason=reason,
            )
        )

    composition_results = _run_compositions(filter_id)
    _print_report(results, verbose=verbose)
    _print_composition_report(composition_results, verbose=verbose)

    failed_attacks = [r for r in results if not r.passed]
    failed_comps = [c for c in composition_results if not c.passed]
    return 0 if not failed_attacks and not failed_comps else 1


def _run_compositions(filter_id: Optional[str]) -> List[CompositionResult]:
    out: List[CompositionResult] = []
    compositions = _load_compositions(ATTACKS_PATH)
    for comp in compositions:
        if filter_id and comp["id"] != filter_id:
            continue
        with tempfile.TemporaryDirectory() as td:
            answers: List[str] = []

            def prompt_fn(_):
                return answers.pop(0) if answers else ""

            # Mock subprocess so we never actually run anything
            invoked: List = []
            orig = subprocess.run

            def fake_run(cmd, **kwargs):
                invoked.append(cmd[-1] if isinstance(cmd, list) else cmd)
                class P:
                    returncode = 0
                return P()

            subprocess.run = fake_run
            try:
                # Apply per-composition repo scaffolding (e.g., .git/, package-lock.json).
                td_path = Path(td)
                setup = comp.get("setup") or {}
                for d in setup.get("dirs", []):
                    (td_path / d).mkdir(parents=True, exist_ok=True)
                for f in setup.get("files", []):
                    fp = td_path / f
                    fp.parent.mkdir(parents=True, exist_ok=True)
                    if not fp.exists():
                        fp.write_text("")

                audit = AuditLog(path=td_path / "audit.jsonl", session_id=f"sess_{comp['id']}")
                shell = GuardedShell(
                    source=SourceContext(comp["source"]),
                    cwd=td,
                    audit=audit,
                    prompt_fn=prompt_fn,
                    out=lambda _: None,
                )
                last_step = None
                last_result = None
                for step in comp["sequence"]:
                    if step.get("answer"):
                        answers.append(step["answer"])
                    last_result = shell.run(step["command"])
                    last_step = step

                expected_decision = Decision(last_step.get("expected_final_decision", last_step.get("expected_initial_decision", "WARN")))
                expected_min_score = int(last_step.get("expected_min_score", 0))
                static = score_command(last_step["command"], source=SourceContext(comp["source"]))

                decision_ok = _meets_decision(last_result.scored.decision, expected_decision)
                score_ok = last_result.scored.stored_potential >= expected_min_score
                escalated = (
                    DECISION_RANK[last_result.scored.decision] > DECISION_RANK[static.decision]
                    if last_step.get("must_escalate_from_lower_decision")
                    else True
                )
                passed = decision_ok and score_ok and escalated
                reason = (
                    "ok" if passed
                    else f"final decision={last_result.scored.decision.value} "
                         f"score={last_result.scored.stored_potential} "
                         f"static_decision={static.decision.value}"
                )
                out.append(
                    CompositionResult(
                        composition_id=comp["id"],
                        final_score=last_result.scored.stored_potential,
                        final_tier=last_result.scored.risk_tier,
                        final_decision=last_result.scored.decision,
                        static_decision=static.decision,
                        expected_decision=expected_decision,
                        expected_min_score=expected_min_score,
                        capabilities_at_end=sorted(shell.session.capabilities),
                        passed=passed,
                        reason=reason,
                    )
                )
            finally:
                subprocess.run = orig
    return out


DECISION_RANK = {
    Decision.ALLOW: 0,
    Decision.ALLOW_AND_LOG: 1,
    Decision.WARN: 2,
    Decision.CONFIRM_REQUIRED: 3,
    Decision.HARD_STOP: 4,
    Decision.OVERRIDE_REQUIRED: 4,
}


def _print_composition_report(results: List[CompositionResult], verbose: bool) -> None:
    if not results:
        return
    print("Session-graph compositions")
    print("=" * 64)
    print()
    width = max((len(r.composition_id) for r in results), default=10)
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        escalation = (
            f"{r.static_decision.value} -> {r.final_decision.value}"
            if r.static_decision != r.final_decision
            else f"{r.final_decision.value} (no change)"
        )
        print(
            f"  {status}  {r.composition_id:<{width}}  "
            f"{r.final_score:>3}/100  {r.final_tier.value:<8}  {escalation}"
        )
        if verbose or not r.passed:
            print(f"        capabilities: {', '.join(r.capabilities_at_end) or '(none)'}")
            if not r.passed:
                print(f"        reason: {r.reason}")
            print()
    passed = sum(1 for r in results if r.passed)
    print()
    print(f"  total compositions: {len(results)}  passed: {passed}  failed: {len(results) - passed}")
    print()


def _print_report(results: List[Result], verbose: bool) -> None:
    total = len(results)
    blocked = sum(1 for r in results if r.decision == Decision.HARD_STOP)
    confirmed = sum(1 for r in results if r.decision == Decision.CONFIRM_REQUIRED)
    passed = sum(1 for r in results if r.passed)

    print()
    print("Preflight prompt-injection battery")
    print("=" * 64)
    print()

    width_id = max((len(r.attack_id) for r in results), default=10)
    fmt = "  {status}  {id:<{w}}  {score:>3}/100  {tier:<8}  {decision}"

    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(
            fmt.format(
                status=status,
                id=r.attack_id,
                w=width_id,
                score=r.score,
                tier=r.tier.value,
                decision=r.decision.value,
            )
        )
        if not r.passed or verbose:
            print(f"        surface : {r.surface}")
            print(f"        command : {r.command}")
            print(f"        expected: >= {r.expected_min_score} / {r.expected_decision.value}")
            if not r.passed:
                print(f"        reason  : {r.reason}")
            print()

    print()
    print(f"  total    : {total}")
    print(f"  passed   : {passed}")
    print(f"  blocked  : {blocked}")
    print(f"  confirm  : {confirmed}")
    print(f"  failures : {total - passed}")
    print()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run the Preflight prompt-injection demo battery.")
    parser.add_argument("--id", default=None, help="Run only the attack with this id.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show command text for every attack.")
    args = parser.parse_args(argv)
    return run(filter_id=args.id, verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())
