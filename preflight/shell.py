from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .audit import AuditLog
from .models import Decision, RiskTier, ScoredCommand, SourceContext
from .policy import Profile, apply_profile
from .repo import RepoContext
from .scorer import score_command
from .session import SessionGraph


PromptFn = Callable[[str], str]


# Outcome tags written to the audit log.
OUTCOME_ALLOWED = "allowed"
OUTCOME_LOGGED = "allowed_logged"
OUTCOME_CONFIRMED = "confirmed"
OUTCOME_OVERRIDDEN = "overridden"
OUTCOME_BLOCKED = "blocked"
OUTCOME_DECLINED = "declined"
OUTCOME_PHRASE_MISMATCH = "phrase_mismatch"
OUTCOME_BUILTIN = "builtin"
OUTCOME_ERROR = "error"


# Patterns whose semantic exfiltration risk is high enough that critical
# decisions are non-overridable by default.
_NON_OVERRIDABLE_TRIGGERS = {
    "reads_sensitive_path",
    "env_dump",
}


@dataclass
class ShellResult:
    command: str
    scored: Optional[ScoredCommand]
    outcome: str
    executed: bool
    exit_code: Optional[int] = None
    duration_ms: Optional[int] = None
    blocked_reason: Optional[str] = None


def strong_phrase(scored: ScoredCommand) -> str:
    triggers = scored.triggers
    raw = scored.command.lower()
    network_present = "curl" in raw or "wget" in raw or "scp " in raw
    # Agent control plane changes are categorically distinct — the strong
    # phrase names *what is being changed* (persistent agent behavior), not
    # what command is being run.
    if any(t.startswith("agent_control_plane_modified") for t in triggers) or \
       any(t.startswith("agent_control_plane_deleted") for t in triggers):
        if "agent_instruction_secret_reference" in triggers:
            return "bind agent behavior to credentials"
        if "agent_instruction_production_reference" in triggers:
            return "bind agent behavior to production"
        if "agent_instruction_destructive_workflow" in triggers:
            return "encode destructive workflow in agent instructions"
        return "modify persistent agent instructions"
    if any(t.startswith("reads_sensitive_path") for t in triggers) and network_present:
        return "transmit credential to external domain"
    if any(t.startswith("reads_sensitive_path") for t in triggers):
        return "read credential file"
    if any(t == "env_dump" for t in triggers) and network_present:
        return "transmit environment to external domain"
    if any(t == "env_dump" for t in triggers):
        return "dump environment to disk"
    if any(t.startswith("rm_rf_broad") for t in triggers):
        return "recursively delete broad target"
    if any(t.startswith("persistence_write") for t in triggers):
        return "modify shell startup configuration"
    if any(t == "git_push" for t in triggers):
        return "push to remote branch"
    if any(t == "package_publish" for t in triggers):
        return "publish package to public registry"
    if any(t == "mutates_external_state" for t in triggers):
        return "mutate external infrastructure state"
    if "session:staged_exfiltration" in triggers or "session:secret_grep_then_publish" in triggers:
        return "act on previously observed sensitive data"
    return "proceed with critical action"


def _is_non_overridable(scored: ScoredCommand) -> bool:
    triggers = set(scored.triggers)
    return bool(triggers & _NON_OVERRIDABLE_TRIGGERS) and any(
        t.startswith("network:") or t == "pipe_to_shell" for t in triggers
    )


def _format_block(scored: ScoredCommand) -> str:
    d = scored.dimensions
    lines = [
        f"Stored Potential: {scored.stored_potential}/100 — {scored.risk_tier.value.upper()}",
        f"  Position {d.position}/5  Permissions {d.permissions}/5  "
        f"Trust {d.trust_bindings}/5  Mutability {d.mutability}/5  Observation {d.observation}/5",
    ]
    for r in scored.reasons:
        lines.append(f"  - {r}")
    return "\n".join(lines)


class GuardedShell:
    def __init__(
        self,
        source: SourceContext = SourceContext.MODEL_GENERATED,
        profile: Optional[Profile] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        audit: Optional[AuditLog] = None,
        prompt_fn: Optional[PromptFn] = None,
        out: Optional[Callable[[str], None]] = None,
        allow_overrides: bool = False,
    ) -> None:
        self.source = source
        self.profile = profile
        self.cwd = os.path.abspath(cwd or os.getcwd())
        self.env: Dict[str, str] = dict(env) if env is not None else dict(os.environ)
        self.audit = audit if audit is not None else AuditLog()
        self.prompt_fn: PromptFn = prompt_fn or input
        self.out: Callable[[str], None] = out or (lambda s: print(s))
        self.allow_overrides = allow_overrides
        self.session = SessionGraph()
        self.repo: Optional[RepoContext] = RepoContext.detect(self.cwd)
        self._bash = shutil.which("bash")
        self._stop = False

    # ---- public API ----

    def run(self, raw: str) -> ShellResult:
        raw = raw.strip()
        if not raw:
            return ShellResult(command=raw, scored=None, outcome=OUTCOME_BUILTIN, executed=False)

        if raw.startswith(":"):
            return self._handle_meta(raw)

        scored = score_command(raw, source=self.source, repo=self.repo, cwd=self.cwd)
        if self.profile is not None:
            scored = apply_profile(scored, self.profile)
        scored = self.session.evaluate(scored)

        if scored.decision == Decision.HARD_STOP:
            result = self._handle_hard_stop(scored)
        elif scored.decision == Decision.CONFIRM_REQUIRED:
            result = self._handle_confirm(scored)
        elif scored.decision == Decision.WARN:
            result = self._handle_warn(scored)
        elif scored.decision == Decision.ALLOW_AND_LOG:
            result = self._execute(scored, OUTCOME_LOGGED, announce=False)
        else:
            result = self._execute(scored, OUTCOME_ALLOWED, announce=False)

        self.session.record(scored, result.outcome)
        return result

    def repl(self) -> int:
        try:
            import readline  # noqa: F401
        except Exception:
            pass

        self.out("preflight shell v0.2 — type :help for meta commands, :quit to exit.\n")
        while not self._stop:
            try:
                prompt = self._prompt_string()
                line = self.prompt_fn(prompt)
            except (EOFError, KeyboardInterrupt):
                self.out("")
                return 0
            self.run(line)
        return 0

    # ---- decision handlers ----

    def _handle_hard_stop(self, scored: ScoredCommand) -> ShellResult:
        self.out(_format_block(scored))
        self.out("Decision: HARD STOP")

        if _is_non_overridable(scored) or not self.allow_overrides:
            self.out("This action is blocked. Override is disabled for this command.\n")
            self.audit.write(
                scored,
                cwd=self.cwd,
                outcome=OUTCOME_BLOCKED,
                profile=self.profile.name if self.profile else None,
            )
            return ShellResult(
                command=scored.command,
                scored=scored,
                outcome=OUTCOME_BLOCKED,
                executed=False,
                blocked_reason="hard_stop",
            )

        phrase = strong_phrase(scored)
        self.out(f"To override, type exactly:  {phrase}")
        try:
            answer = self.prompt_fn("> ").strip()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        matched = (answer == phrase)
        if not matched:
            self.out("Phrase did not match. Action blocked.\n")
            self.audit.write(
                scored,
                cwd=self.cwd,
                outcome=OUTCOME_PHRASE_MISMATCH,
                profile=self.profile.name if self.profile else None,
                confirmation_phrase_required=phrase,
                confirmation_matched=False,
            )
            return ShellResult(
                command=scored.command,
                scored=scored,
                outcome=OUTCOME_PHRASE_MISMATCH,
                executed=False,
                blocked_reason="phrase_mismatch",
            )
        return self._execute(
            scored,
            OUTCOME_OVERRIDDEN,
            announce=True,
            phrase=phrase,
            matched=True,
        )

    def _handle_confirm(self, scored: ScoredCommand) -> ShellResult:
        self.out(_format_block(scored))
        self.out("Decision: CONFIRM REQUIRED")
        phrase = strong_phrase(scored)
        self.out(f"To proceed, type exactly:  {phrase}")
        try:
            answer = self.prompt_fn("> ").strip()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        matched = (answer == phrase)
        if not matched:
            self.out("Phrase did not match. Action skipped.\n")
            self.audit.write(
                scored,
                cwd=self.cwd,
                outcome=OUTCOME_PHRASE_MISMATCH,
                profile=self.profile.name if self.profile else None,
                confirmation_phrase_required=phrase,
                confirmation_matched=False,
            )
            return ShellResult(
                command=scored.command,
                scored=scored,
                outcome=OUTCOME_PHRASE_MISMATCH,
                executed=False,
                blocked_reason="phrase_mismatch",
            )
        return self._execute(
            scored,
            OUTCOME_CONFIRMED,
            announce=True,
            phrase=phrase,
            matched=True,
        )

    def _handle_warn(self, scored: ScoredCommand) -> ShellResult:
        self.out(_format_block(scored))
        self.out("Decision: WARN")
        try:
            answer = self.prompt_fn("Proceed? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer not in {"y", "yes"}:
            self.audit.write(
                scored,
                cwd=self.cwd,
                outcome=OUTCOME_DECLINED,
                profile=self.profile.name if self.profile else None,
            )
            self.out("Skipped.\n")
            return ShellResult(
                command=scored.command,
                scored=scored,
                outcome=OUTCOME_DECLINED,
                executed=False,
                blocked_reason="user_declined",
            )
        return self._execute(scored, OUTCOME_CONFIRMED, announce=True)

    # ---- execution ----

    def _execute(
        self,
        scored: ScoredCommand,
        outcome: str,
        announce: bool,
        phrase: Optional[str] = None,
        matched: Optional[bool] = None,
    ) -> ShellResult:
        builtin = self._maybe_builtin(scored.command)
        if builtin is not None:
            self.audit.write(
                scored,
                cwd=self.cwd,
                outcome=OUTCOME_BUILTIN,
                profile=self.profile.name if self.profile else None,
                exit_code=builtin,
                duration_ms=0,
                confirmation_phrase_required=phrase,
                confirmation_matched=matched,
            )
            return ShellResult(
                command=scored.command,
                scored=scored,
                outcome=OUTCOME_BUILTIN,
                executed=True,
                exit_code=builtin,
                duration_ms=0,
            )

        if announce:
            self.out("[approved] running...\n")

        start = time.monotonic()
        try:
            if self._bash:
                proc = subprocess.run(
                    [self._bash, "-c", scored.command],
                    cwd=self.cwd,
                    env=self.env,
                )
            else:
                proc = subprocess.run(
                    scored.command,
                    shell=True,
                    cwd=self.cwd,
                    env=self.env,
                )
            exit_code = proc.returncode
        except Exception as exc:
            self.out(f"execution error: {exc}\n")
            exit_code = -1
            outcome = OUTCOME_ERROR
        duration_ms = int((time.monotonic() - start) * 1000)

        self.audit.write(
            scored,
            cwd=self.cwd,
            outcome=outcome,
            profile=self.profile.name if self.profile else None,
            exit_code=exit_code,
            duration_ms=duration_ms,
            confirmation_phrase_required=phrase,
            confirmation_matched=matched,
        )

        return ShellResult(
            command=scored.command,
            scored=scored,
            outcome=outcome,
            executed=True,
            exit_code=exit_code,
            duration_ms=duration_ms,
        )

    # ---- shell builtins handled in-process so cd/export persist ----

    def _maybe_builtin(self, command: str) -> Optional[int]:
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            return None
        if not tokens:
            return None
        if "|" in tokens or "&&" in tokens or "||" in tokens or ";" in tokens:
            return None
        verb = tokens[0]
        if verb == "cd":
            # Use the raw remainder for cd so Windows backslash paths survive
            # shlex's posix-mode escape handling.
            raw_arg = command[len("cd"):].strip()
            if (raw_arg.startswith('"') and raw_arg.endswith('"')) or (
                raw_arg.startswith("'") and raw_arg.endswith("'")
            ):
                raw_arg = raw_arg[1:-1]
            return self._builtin_cd([raw_arg] if raw_arg else [])
        if verb == "export":
            return self._builtin_export(tokens[1:])
        if verb == "unset":
            return self._builtin_unset(tokens[1:])
        if verb == "pwd" and len(tokens) == 1:
            self.out(self.cwd)
            return 0
        return None

    def _builtin_cd(self, args: List[str]) -> int:
        if not args:
            target = os.path.expanduser("~")
        else:
            target = os.path.expanduser(args[0])
        target = self._resolve_env_in_path(target)
        new_cwd = target if os.path.isabs(target) else os.path.normpath(os.path.join(self.cwd, target))
        if not os.path.isdir(new_cwd):
            self.out(f"cd: no such directory: {args[0] if args else '~'}")
            return 1
        self.cwd = os.path.abspath(new_cwd)
        self.repo = RepoContext.detect(self.cwd)
        return 0

    def _builtin_export(self, args: List[str]) -> int:
        for a in args:
            if "=" not in a:
                continue
            key, value = a.split("=", 1)
            value = self._resolve_env_in_path(value)
            self.env[key] = value
        return 0

    def _builtin_unset(self, args: List[str]) -> int:
        for a in args:
            self.env.pop(a, None)
        return 0

    def _resolve_env_in_path(self, value: str) -> str:
        def repl(m):
            name = m.group(1) or m.group(2)
            return self.env.get(name, "")
        value = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", repl, value)
        return value

    # ---- meta commands (`:help`, `:quit`, `:cwd`, `:source`, `:profile`, `:audit`) ----

    def _handle_meta(self, line: str) -> ShellResult:
        parts = line.split()
        cmd = parts[0]
        args = parts[1:]
        if cmd in (":quit", ":exit"):
            self._stop = True
            return ShellResult(command=line, scored=None, outcome=OUTCOME_BUILTIN, executed=True, exit_code=0)
        if cmd == ":help":
            self.out(
                "Meta commands:\n"
                "  :help                 show this message\n"
                "  :quit / :exit         exit the shell\n"
                "  :cwd                  print current working directory\n"
                "  :source <ctx>         set source context (user_request | model_generated | untrusted_content)\n"
                "  :profile <name>       set policy profile (none | solo_developer | open_source_maintainer | enterprise | regulated)\n"
                "  :audit [N]            show last N audit entries (default 5)\n"
                "  :session              show session capabilities and ledger\n"
                "  :repo                 show detected repo root and kind\n"
            )
            return ShellResult(command=line, scored=None, outcome=OUTCOME_BUILTIN, executed=True, exit_code=0)
        if cmd == ":cwd":
            self.out(self.cwd)
            return ShellResult(command=line, scored=None, outcome=OUTCOME_BUILTIN, executed=True, exit_code=0)
        if cmd == ":source" and args:
            try:
                self.source = SourceContext(args[0])
                self.out(f"source set to {self.source.value}")
                return ShellResult(command=line, scored=None, outcome=OUTCOME_BUILTIN, executed=True, exit_code=0)
            except ValueError:
                self.out(f"unknown source: {args[0]}")
                return ShellResult(command=line, scored=None, outcome=OUTCOME_BUILTIN, executed=False, exit_code=1)
        if cmd == ":profile" and args:
            from .policy import get_profile
            if args[0] == "none":
                self.profile = None
                self.out("profile cleared")
            else:
                p = get_profile(args[0])
                if p is None:
                    self.out(f"unknown profile: {args[0]}")
                    return ShellResult(command=line, scored=None, outcome=OUTCOME_BUILTIN, executed=False, exit_code=1)
                self.profile = p
                self.out(f"profile set to {p.name}")
            return ShellResult(command=line, scored=None, outcome=OUTCOME_BUILTIN, executed=True, exit_code=0)
        if cmd == ":audit":
            n = int(args[0]) if args else 5
            for entry in self.audit.tail(n):
                self.out(
                    f"  [{entry['seq']}] {entry['stored_potential_score']}/100 "
                    f"{entry['risk_tier']:<8} {entry['outcome']:<14} {entry['command']}"
                )
            return ShellResult(command=line, scored=None, outcome=OUTCOME_BUILTIN, executed=True, exit_code=0)
        if cmd == ":session":
            self.out(self.session.summary())
            return ShellResult(command=line, scored=None, outcome=OUTCOME_BUILTIN, executed=True, exit_code=0)
        if cmd == ":repo":
            if self.repo is None:
                self.out("no repo context (no .git or project marker found by walking up from cwd)")
            else:
                self.out(f"repo kind: {self.repo.kind}")
                self.out(f"repo root: {self.repo.root}")
            return ShellResult(command=line, scored=None, outcome=OUTCOME_BUILTIN, executed=True, exit_code=0)
        self.out(f"unknown meta command: {cmd}")
        return ShellResult(command=line, scored=None, outcome=OUTCOME_BUILTIN, executed=False, exit_code=1)

    # ---- prompt rendering ----

    def _prompt_string(self) -> str:
        try:
            home = os.path.expanduser("~")
            display = self.cwd
            if display.startswith(home):
                display = "~" + display[len(home):]
        except Exception:
            display = self.cwd
        src_tag = {
            SourceContext.USER_REQUEST: "",
            SourceContext.MODEL_GENERATED: "",
            SourceContext.UNTRUSTED_CONTENT: " [untrusted]",
        }[self.source]
        repo_tag = ""
        if self.repo is not None:
            repo_tag = f" ({self.repo.kind})"
        return f"preflight {display}{repo_tag}{src_tag}> "
