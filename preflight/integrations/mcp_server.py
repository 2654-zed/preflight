"""Minimal MCP (Model Context Protocol) server — stdio JSON-RPC.

MCP is a JSON-RPC 2.0 protocol over stdio. A server responds to:

  initialize         handshake; advertise protocolVersion + capabilities
  tools/list         list the tools this server exposes
  tools/call         run a tool by name with structured arguments

This module implements the protocol directly so Preflight has zero
runtime dependency on a third-party MCP library — the existing scorer,
session graph, repo detector, and audit log all become available to any
MCP-compatible client (Claude Desktop, Cursor, custom agents) without
adding another packaging surface.

Three tools are exposed:

  preflight_score_command   one-shot scoring of a shell command
  preflight_attest_action   simulate the Claude Code hook flow for any
                            tool call, returning a permission decision
                            with full decomposition
  preflight_session_state   inspect the current session graph

Sessions are keyed by `session_id` argument and persist to disk under
~/.preflight/sessions/<id>.json — same storage that the Claude Code
adapter uses, so the two integrations share session state when given
the same id.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .. import __version__
from ..audit import AuditLog, default_audit_path
from ..models import Decision, SourceContext
from ..policy import apply_profile, get_profile
from ..repo import RepoContext
from ..scorer import score_command
from ..session import SessionGraph
from .claude_code import _safe_session_id, hook_response, synthesize_command


PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "preflight"


def _session_path(session_id: str, base: Optional[Path] = None) -> Path:
    base = base or Path("~/.preflight/sessions").expanduser()
    return base / f"{_safe_session_id(session_id)}.json"


# ---------- tool definitions (advertised via tools/list) ----------


TOOL_DEFINITIONS = [
    {
        "name": "preflight_score_command",
        "description": (
            "Score a shell command across the five Preflight dimensions "
            "(Position, Permissions, Trust Bindings, Mutability, "
            "Observation). Returns the stored-potential score, risk "
            "tier, decision, and human-readable reasons."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to score."},
                "source": {
                    "type": "string",
                    "enum": ["user_request", "model_generated", "untrusted_content"],
                    "default": "model_generated",
                },
                "profile": {
                    "type": "string",
                    "enum": ["solo_developer", "open_source_maintainer", "enterprise", "regulated"],
                },
                "cwd": {"type": "string", "description": "Working directory used for repo detection."},
            },
            "required": ["command"],
        },
    },
    {
        "name": "preflight_attest_action",
        "description": (
            "Score a proposed Claude Code-style tool call (Bash, Read, "
            "Write, Edit, Grep, WebFetch, etc.) and return a permission "
            "decision (allow / ask / deny). The session graph composes "
            "across multiple calls when the same `session_id` is reused."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string"},
                "tool_input": {"type": "object"},
                "session_id": {"type": "string"},
                "cwd": {"type": "string"},
                "source": {"type": "string", "enum": ["user_request", "model_generated", "untrusted_content"]},
                "profile": {"type": "string"},
            },
            "required": ["tool_name", "tool_input", "session_id"],
        },
    },
    {
        "name": "preflight_session_state",
        "description": (
            "Return the current session graph for `session_id`: the list "
            "of capabilities accumulated so far and the recent ledger of "
            "scored commands."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
        },
    },
]


# ---------- tool handlers ----------


def tool_score_command(args: Dict[str, Any]) -> Dict[str, Any]:
    command = args.get("command", "")
    if not command:
        raise ValueError("missing required argument: command")
    source = SourceContext(args.get("source", "model_generated"))
    profile = get_profile(args.get("profile"))
    cwd = args.get("cwd") or os.getcwd()
    repo = RepoContext.detect(cwd)
    scored = score_command(command, source=source, repo=repo, cwd=cwd)
    if profile is not None:
        scored = apply_profile(scored, profile)
    return scored.to_dict()


def tool_attest_action(
    args: Dict[str, Any],
    *,
    session_dir: Optional[Path] = None,
    audit_path: Optional[Path] = None,
) -> Dict[str, Any]:
    tool_name = args.get("tool_name", "")
    tool_input = args.get("tool_input", {})
    session_id = args.get("session_id", "default")
    cwd = args.get("cwd") or os.getcwd()
    source = SourceContext(args.get("source", "model_generated"))
    profile = get_profile(args.get("profile"))

    command = synthesize_command(tool_name, tool_input)
    if not command:
        return {"permissionDecision": "allow", "permissionDecisionReason": "No-op for this tool type."}

    repo = RepoContext.detect(cwd)
    state_path = _session_path(session_id, session_dir)
    session = SessionGraph.load(state_path)

    scored = score_command(command, source=source, repo=repo, cwd=cwd)
    if profile is not None:
        scored = apply_profile(scored, profile)
    scored = session.evaluate(scored)

    outcome = (
        "blocked" if scored.decision == Decision.HARD_STOP
        else "asked" if scored.decision in (Decision.CONFIRM_REQUIRED, Decision.WARN)
        else "allowed"
    )
    session.record(scored, outcome=outcome if outcome == "allowed" else "blocked")
    session.save(state_path)

    audit = AuditLog(
        path=audit_path or default_audit_path(),
        session_id=session_id,
    )
    audit.write(scored, cwd=cwd, outcome=outcome, profile=profile.name if profile else None)

    return hook_response(scored)["hookSpecificOutput"]


def tool_session_state(
    args: Dict[str, Any],
    *,
    session_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    session_id = args.get("session_id", "default")
    state_path = _session_path(session_id, session_dir)
    session = SessionGraph.load(state_path)
    return session.to_dict()


def dispatch_tool_call(
    name: str,
    arguments: Dict[str, Any],
    *,
    session_dir: Optional[Path] = None,
    audit_path: Optional[Path] = None,
) -> Dict[str, Any]:
    if name == "preflight_score_command":
        return tool_score_command(arguments)
    if name == "preflight_attest_action":
        return tool_attest_action(arguments, session_dir=session_dir, audit_path=audit_path)
    if name == "preflight_session_state":
        return tool_session_state(arguments, session_dir=session_dir)
    raise ValueError(f"unknown tool: {name}")


# ---------- JSON-RPC plumbing ----------


def handle_request(
    request: Dict[str, Any],
    *,
    session_dir: Optional[Path] = None,
    audit_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Process one JSON-RPC request; return a response dict (or None for notifications)."""
    method = request.get("method")
    request_id = request.get("id")
    params = request.get("params") or {}

    # Notifications (no id) get no response.
    is_notification = "id" not in request

    try:
        if method == "initialize":
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": __version__},
            }
        elif method == "notifications/initialized":
            return None  # notification, no response
        elif method == "tools/list":
            result = {"tools": TOOL_DEFINITIONS}
        elif method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments") or {}
            payload = dispatch_tool_call(
                tool_name,
                arguments,
                session_dir=session_dir,
                audit_path=audit_path,
            )
            result = {
                "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                "structuredContent": payload,
                "isError": False,
            }
        elif method == "ping":
            result = {}
        else:
            if is_notification:
                return None
            return _error(request_id, -32601, f"method not found: {method}")
    except ValueError as e:
        if is_notification:
            return None
        return _error(request_id, -32602, str(e))
    except Exception as e:
        if is_notification:
            return None
        return _error(request_id, -32000, f"internal error: {e}")

    if is_notification:
        return None
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def run_server(
    stdin=None,
    stdout=None,
    *,
    session_dir: Optional[Path] = None,
    audit_path: Optional[Path] = None,
) -> int:
    """Read newline-delimited JSON-RPC requests from stdin, write responses to stdout."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            stdout.flush()
            continue
        response = handle_request(request, session_dir=session_dir, audit_path=audit_path)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()
    return 0


def main(argv=None) -> int:
    return run_server()
