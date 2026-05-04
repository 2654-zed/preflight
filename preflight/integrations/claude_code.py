"""Claude Code PreToolUse hook adapter.

Claude Code's hook system invokes a configured command before each tool
call, piping a JSON payload describing the proposed action. The hook can
respond with `permissionDecision` of `allow`, `ask`, or `deny` plus a
human-readable reason.

This module reads the hook payload from stdin, synthesizes a "virtual
command" string from the tool input (so the existing Preflight scorer
can decompose it across the five dimensions), scores it with full v0.3
session-graph and v0.4 repo-awareness, and emits a JSON hook response.

Session state is persisted to ~/.preflight/sessions/<session_id>.json
between hook invocations, so the session graph still composes across
Claude Code's many separate tool calls within one conversation.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from ..audit import AuditLog, default_audit_path
from ..models import Decision, RiskTier, ScoredCommand, SourceContext
from ..policy import apply_profile, get_profile
from ..repo import RepoContext
from ..scorer import score_command
from ..session import SessionGraph


def session_state_path(session_id: str) -> Path:
    return Path("~/.preflight/sessions").expanduser() / f"{_safe_session_id(session_id)}.json"


def _safe_session_id(s: str) -> str:
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in s)
    return safe[:128] or "default"


def synthesize_command(tool_name: str, tool_input: Dict[str, Any]) -> Optional[str]:
    """Translate a Claude Code tool invocation into a shell-command-shaped
    string the existing scorer can read.

    Returns None for tool types we don't handle — the hook then defers to
    Claude Code's default permission flow (no decision emitted).

    The synthesized strings don't have to be runnable. They only have to
    expose the same risk-relevant features (file paths, redirects, network
    URLs, sensitive-keyword content) that the scorer's detectors look for.
    """
    if not isinstance(tool_input, dict):
        return None

    tn = tool_name or ""

    if tn == "Bash":
        return tool_input.get("command")

    if tn == "Read":
        path = tool_input.get("file_path")
        if not path:
            return None
        return f"cat {shlex.quote(path)}"

    if tn == "Write":
        path = tool_input.get("file_path")
        content = tool_input.get("content") or ""
        if not path:
            return None
        # Truncate to keep the synthesized command bounded; persistence-write
        # detection only needs to spot network verbs / shell metacharacters
        # in the content, which a 1KB sample is plenty for.
        snippet = content[:1024]
        return f"echo {shlex.quote(snippet)} > {shlex.quote(path)}"

    if tn in ("Edit", "MultiEdit"):
        path = tool_input.get("file_path")
        if not path:
            return None
        return f"sed -i 's/old/new/g' {shlex.quote(path)}"

    if tn == "NotebookEdit":
        path = tool_input.get("notebook_path") or tool_input.get("file_path")
        if not path:
            return None
        return f"sed -i 's/old/new/g' {shlex.quote(path)}"

    if tn == "Grep":
        pattern = tool_input.get("pattern", "")
        path = tool_input.get("path", ".")
        # Always synthesize as recursive so the scorer evaluates broad scope.
        return f"grep -R {shlex.quote(pattern)} {shlex.quote(path)}"

    if tn == "Glob":
        pattern = tool_input.get("pattern", "*")
        path = tool_input.get("path", ".")
        return f"find {shlex.quote(path)} -name {shlex.quote(pattern)}"

    if tn == "WebFetch":
        url = tool_input.get("url", "")
        if not url:
            return None
        return f"curl {shlex.quote(url)}"

    if tn == "WebSearch":
        # Search itself doesn't fetch URLs the user can act on. Allow.
        return None

    return None


def hook_response(scored: ScoredCommand) -> Dict[str, Any]:
    """Map a Preflight decision into a Claude Code PreToolUse hook response."""
    if scored.decision == Decision.HARD_STOP:
        permission = "deny"
    elif scored.decision in (Decision.CONFIRM_REQUIRED, Decision.WARN):
        permission = "ask"
    else:
        permission = "allow"

    reason = _format_reason(scored)
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission,
            "permissionDecisionReason": reason,
        }
    }


def _format_reason(scored: ScoredCommand) -> str:
    d = scored.dimensions
    lines = [
        f"Preflight: {scored.stored_potential}/100 — {scored.risk_tier.value.upper()}",
        (
            f"  position={d.position}/5 permissions={d.permissions}/5 "
            f"trust={d.trust_bindings}/5 mutability={d.mutability}/5 "
            f"observation={d.observation}/5"
        ),
    ]
    for r in scored.reasons[:5]:
        lines.append(f"  • {r}")
    return "\n".join(lines)


def _resolve_source(env_value: Optional[str]) -> SourceContext:
    if env_value:
        try:
            return SourceContext(env_value)
        except ValueError:
            pass
    return SourceContext.MODEL_GENERATED


def run_hook(
    payload: Dict[str, Any],
    *,
    session_dir: Optional[Path] = None,
    audit_path: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Process one PreToolUse hook payload and return the response dict.

    The function is split out from main() so tests can drive it directly
    without subprocess plumbing or stdin mocking. Returns an empty dict
    when no decision should be emitted (Claude Code falls back to default
    permission behavior in that case).
    """
    env = env if env is not None else dict(os.environ)
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    cwd = payload.get("cwd") or os.getcwd()
    session_id = payload.get("session_id") or "default"

    command = synthesize_command(tool_name, tool_input)
    if not command:
        return {}

    repo = RepoContext.detect(cwd)
    source = _resolve_source(env.get("PREFLIGHT_SOURCE"))
    profile = get_profile(env.get("PREFLIGHT_PROFILE"))

    sess_dir = session_dir or Path("~/.preflight/sessions").expanduser()
    state_path = sess_dir / f"{_safe_session_id(session_id)}.json"
    session = SessionGraph.load(state_path)

    scored = score_command(command, source=source, repo=repo, cwd=cwd)
    if profile is not None:
        scored = apply_profile(scored, profile)
    scored = session.evaluate(scored)

    # Outcome label for capability bookkeeping. Claude Code will or won't
    # actually execute based on our response; we record the *decision*, not
    # the execution result, here.
    if scored.decision == Decision.HARD_STOP:
        outcome = "blocked"
    elif scored.decision in (Decision.CONFIRM_REQUIRED, Decision.WARN):
        # We pass the decision to the user via "ask"; we'll only know later
        # whether they approved. Persist conservatively as "asked" — the
        # capability is *not* granted yet.
        outcome = "asked"
    else:
        outcome = "allowed"

    # We grant capabilities only on outcomes that imply execution. "asked"
    # and "blocked" do not. This is the same rule SessionGraph.record uses
    # internally.
    session.record(scored, outcome=outcome if outcome == "allowed" else "blocked")
    session.save(state_path)

    audit = AuditLog(
        path=audit_path or default_audit_path(),
        session_id=session_id,
    )
    audit.write(
        scored,
        cwd=cwd,
        outcome=outcome,
        profile=profile.name if profile else None,
    )

    return hook_response(scored)


def main(argv=None) -> int:
    """Entry point for the `preflight hook` subcommand. Reads JSON from
    stdin, writes JSON to stdout, exits 0 for allow/ask decisions and 0
    for deny too — Claude Code reads `permissionDecision` from JSON, not
    from exit code, when the response shape is hookSpecificOutput.
    """
    raw = sys.stdin.read()
    if not raw.strip():
        return 0
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        sys.stderr.write("preflight hook: invalid JSON on stdin\n")
        return 1

    response = run_hook(payload)
    if response:
        sys.stdout.write(json.dumps(response))
    return 0
