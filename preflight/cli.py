from __future__ import annotations

import argparse
import json
import sys
from typing import List

from . import __version__
from .models import Decision, RiskTier, ScoredCommand, SourceContext
from .policy import PROFILES, apply_profile, diff_profiles, get_profile, render_profile
from .scorer import score_command


TIER_LABEL = {
    RiskTier.LOW: "LOW",
    RiskTier.ELEVATED: "ELEVATED",
    RiskTier.MEDIUM: "MEDIUM",
    RiskTier.HIGH: "HIGH",
    RiskTier.CRITICAL: "CRITICAL",
}

DECISION_LABEL = {
    Decision.ALLOW: "ALLOW",
    Decision.ALLOW_AND_LOG: "ALLOW & LOG",
    Decision.WARN: "WARN",
    Decision.CONFIRM_REQUIRED: "CONFIRM REQUIRED",
    Decision.HARD_STOP: "HARD STOP",
    Decision.OVERRIDE_REQUIRED: "OVERRIDE REQUIRED",
}


def _format_human(scored: ScoredCommand) -> str:
    lines: List[str] = []
    lines.append(f"Command:")
    lines.append(f"  {scored.command}")
    lines.append("")
    lines.append(
        f"Stored Potential: {scored.stored_potential} / 100 — {TIER_LABEL[scored.risk_tier]}"
    )
    lines.append("")
    lines.append("Risk decomposition:")
    d = scored.dimensions
    lines.append(f"  Position        {d.position}/5")
    lines.append(f"  Permissions     {d.permissions}/5")
    lines.append(f"  Trust Binding   {d.trust_bindings}/5")
    lines.append(f"  Mutability      {d.mutability}/5")
    lines.append(f"  Observation     {d.observation}/5")
    lines.append("")
    if scored.reasons:
        lines.append("Composition signals:")
        for r in scored.reasons:
            lines.append(f"  - {r}")
        lines.append("")
    if scored.explanation:
        lines.append("Why:")
        for e in scored.explanation:
            lines.append(f"  - {e}")
        lines.append("")
    lines.append(f"Decision: {DECISION_LABEL[scored.decision]}")
    return "\n".join(lines)


def _exit_code(decision: Decision) -> int:
    return {
        Decision.ALLOW: 0,
        Decision.ALLOW_AND_LOG: 0,
        Decision.WARN: 10,
        Decision.CONFIRM_REQUIRED: 20,
        Decision.HARD_STOP: 30,
        Decision.OVERRIDE_REQUIRED: 30,
    }[decision]


def cmd_score(args) -> int:
    command = args.command if isinstance(args.command, str) else " ".join(args.command)
    source = SourceContext(args.source)
    scored = score_command(command, source=source)
    profile = get_profile(args.profile)
    if profile:
        scored = apply_profile(scored, profile)
    if args.json:
        print(json.dumps(scored.to_dict(), indent=2))
    else:
        print(_format_human(scored))
    return _exit_code(scored.decision)


def cmd_check(args) -> int:
    """Score a command and return non-zero if blocked or needing confirmation."""
    command = args.command if isinstance(args.command, str) else " ".join(args.command)
    source = SourceContext(args.source)
    scored = score_command(command, source=source)
    profile = get_profile(args.profile)
    if profile:
        scored = apply_profile(scored, profile)
    if args.quiet:
        return _exit_code(scored.decision)
    print(f"{TIER_LABEL[scored.risk_tier]}\t{scored.stored_potential}\t{DECISION_LABEL[scored.decision]}\t{command}")
    return _exit_code(scored.decision)


def cmd_shell(args) -> int:
    from pathlib import Path
    from .audit import AuditLog
    from .shell import GuardedShell
    profile = get_profile(args.profile)
    audit = AuditLog(path=Path(args.audit_log).expanduser() if args.audit_log else None)
    shell = GuardedShell(
        source=SourceContext(args.source),
        profile=profile,
        audit=audit,
        allow_overrides=args.allow_overrides,
    )
    return shell.repl()


def cmd_hook(args) -> int:
    from .integrations.claude_code import main as claude_code_main
    return claude_code_main()


def cmd_mcp(args) -> int:
    from .integrations.mcp_server import main as mcp_main
    return mcp_main()


def cmd_tui(args) -> int:
    from pathlib import Path
    from .tui import run_tui
    return run_tui(
        audit_path=Path(args.audit_log).expanduser() if args.audit_log else None,
        session_dir=Path(args.session_dir).expanduser() if args.session_dir else None,
        interval=args.interval,
    )


def cmd_profile(args) -> int:
    if args.action == "list":
        for p in PROFILES.values():
            print(f"  {p.name:<25} {p.description.splitlines()[0] if p.description else ''}")
        return 0
    if args.action == "show":
        p = get_profile(args.name)
        if p is None:
            print(f"unknown profile: {args.name}", file=sys.stderr)
            return 1
        print(render_profile(p))
        return 0
    if args.action == "diff":
        a = get_profile(args.a)
        b = get_profile(args.b)
        if a is None or b is None:
            print("unknown profile name(s)", file=sys.stderr)
            return 1
        print(diff_profiles(a, b))
        return 0
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="preflight",
        description="Capability-aware risk scoring for AI coding agent tool calls.",
    )
    parser.add_argument("--version", action="version", version=f"preflight {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--source",
        choices=[s.value for s in SourceContext],
        default=SourceContext.MODEL_GENERATED.value,
        help="Origin of the proposed command (default: model_generated).",
    )
    common.add_argument(
        "--profile",
        choices=["solo_developer", "open_source_maintainer", "enterprise", "regulated"],
        default=None,
        help="Apply a policy profile that shifts confirm/block thresholds.",
    )

    p_score = sub.add_parser("score", parents=[common], help="Score a single command.")
    p_score.add_argument("command", nargs="+", help="The command to score.")
    p_score.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    p_score.set_defaults(func=cmd_score)

    p_check = sub.add_parser(
        "check", parents=[common], help="Score and exit with a code reflecting the decision."
    )
    p_check.add_argument("command", nargs="+", help="The command to check.")
    p_check.add_argument("--quiet", action="store_true", help="Suppress output; use exit code only.")
    p_check.set_defaults(func=cmd_check)

    p_shell = sub.add_parser(
        "shell", parents=[common], help="Guarded interactive REPL: scores, gates, and runs each command."
    )
    p_shell.add_argument(
        "--audit-log",
        default=None,
        help="Override the audit log path (default: ~/.preflight/audit.jsonl).",
    )
    p_shell.add_argument(
        "--allow-overrides",
        action="store_true",
        help="Allow CRITICAL commands to be overridden with a strong-phrase confirmation. "
             "Credential-exfil patterns remain non-overridable regardless.",
    )
    p_shell.set_defaults(func=cmd_shell)

    p_hook = sub.add_parser(
        "hook",
        help="Run as a Claude Code PreToolUse hook (reads JSON from stdin, writes JSON to stdout).",
    )
    p_hook.set_defaults(func=cmd_hook)

    p_mcp = sub.add_parser(
        "mcp",
        help="Run as an MCP (Model Context Protocol) stdio server exposing Preflight tools.",
    )
    p_mcp.set_defaults(func=cmd_mcp)

    p_tui = sub.add_parser(
        "tui",
        help="Real-time dashboard: live audit-log tail and session-graph state.",
    )
    p_tui.add_argument("--audit-log", default=None, help="Override the audit log path.")
    p_tui.add_argument("--session-dir", default=None, help="Override the sessions directory.")
    p_tui.add_argument("--interval", type=float, default=1.0, help="Poll interval (seconds).")
    p_tui.set_defaults(func=cmd_tui)

    p_profile = sub.add_parser("profile", help="Inspect, list, or diff policy profiles.")
    profile_sub = p_profile.add_subparsers(dest="action", required=True)
    profile_sub.add_parser("list", help="List built-in profiles.")
    p_show = profile_sub.add_parser("show", help="Show a profile's full ruleset.")
    p_show.add_argument("name", choices=list(PROFILES.keys()))
    p_diff = profile_sub.add_parser("diff", help="Diff two profiles' rulesets.")
    p_diff.add_argument("a", choices=list(PROFILES.keys()))
    p_diff.add_argument("b", choices=list(PROFILES.keys()))
    p_profile.set_defaults(func=cmd_profile)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
