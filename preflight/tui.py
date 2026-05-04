"""Real-time TUI for Preflight (v1.0).

Reads ~/.preflight/audit.jsonl and ~/.preflight/sessions/*.json on a
poll interval and renders a dashboard:

  - the last N audit decisions with their tier and outcome
  - the active sessions with their accumulated capabilities
  - per-session ledger of recent commands

The rendering core is a pure function (state -> string) so it's
trivially testable. The terminal loop uses ANSI escape codes for
clear-and-redraw, which works on every modern terminal (Windows 10+
ships with VT100 support enabled by default) without pulling in curses.
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"
_FG_GREEN = "\x1b[32m"
_FG_YELLOW = "\x1b[33m"
_FG_RED = "\x1b[31m"
_FG_CYAN = "\x1b[36m"
_FG_GRAY = "\x1b[90m"
_BG_RED = "\x1b[41m"
_CLEAR_AND_HOME = "\x1b[2J\x1b[H"
_HIDE_CURSOR = "\x1b[?25l"
_SHOW_CURSOR = "\x1b[?25h"


_TIER_COLOR = {
    "low": _FG_GREEN,
    "elevated": _FG_GREEN,
    "medium": _FG_YELLOW,
    "high": _FG_RED,
    "critical": _BOLD + _FG_RED,
}


@dataclass
class TuiState:
    audit_tail: List[Dict[str, Any]] = field(default_factory=list)
    sessions: List[Dict[str, Any]] = field(default_factory=list)
    now: str = ""

    @classmethod
    def empty(cls) -> "TuiState":
        return cls(now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))


# ---------- state gathering (pure-ish; reads disk) ----------


def _read_jsonl_tail(path: Path, n: int) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return []
    out: List[Dict[str, Any]] = []
    for line in lines[-n:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _read_sessions(session_dir: Path) -> List[Dict[str, Any]]:
    if not session_dir.exists() or not session_dir.is_dir():
        return []
    out: List[Dict[str, Any]] = []
    try:
        files = sorted(
            session_dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return []
    for path in files[:8]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        out.append({
            "id": path.stem,
            "capabilities": data.get("capabilities", []),
            "seq": data.get("seq", 0),
            "ledger": data.get("ledger", []),
            "mtime": path.stat().st_mtime,
        })
    return out


def gather_state(
    audit_path: Optional[Path] = None,
    session_dir: Optional[Path] = None,
    audit_tail_size: int = 15,
) -> TuiState:
    audit_path = audit_path or Path("~/.preflight/audit.jsonl").expanduser()
    session_dir = session_dir or Path("~/.preflight/sessions").expanduser()
    return TuiState(
        audit_tail=_read_jsonl_tail(audit_path, audit_tail_size),
        sessions=_read_sessions(session_dir),
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


# ---------- rendering (pure) ----------


def _color_tier(tier: str, text: str, color: bool) -> str:
    if not color:
        return text
    code = _TIER_COLOR.get(tier, "")
    return f"{code}{text}{_RESET}" if code else text


def _truncate(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    return text[: width - 1] + "…"


def render_audit_row(entry: Dict[str, Any], width: int = 80, color: bool = True) -> str:
    seq = entry.get("seq", "?")
    score = entry.get("stored_potential_score", 0)
    tier = entry.get("risk_tier", "low")
    outcome = entry.get("outcome", "?")
    command = entry.get("command", "")
    head = f"  [{seq:>3}] {score:>3}/100 "
    tier_part = _color_tier(tier, f"{tier:<8}", color)
    rest = f" {outcome:<14} "
    available = max(20, width - len(head) - 8 - len(rest))
    cmd = _truncate(command, available)
    return head + tier_part + rest + cmd


def render_session_block(sess: Dict[str, Any], width: int = 80, color: bool = True) -> List[str]:
    sid = sess.get("id", "?")
    caps = sess.get("capabilities", [])
    seq = sess.get("seq", 0)
    ledger = sess.get("ledger", [])
    lines: List[str] = []
    header = f"  {sid}  ({seq} commands, {len(caps)} capabilities)"
    if color:
        header = f"{_FG_CYAN}{header}{_RESET}"
    lines.append(header)
    if caps:
        cap_text = ", ".join(caps)
        lines.append(_truncate(f"    capabilities: {cap_text}", width))
    if ledger:
        last = ledger[-1]
        lcmd = _truncate(last.get("command", ""), width - 12)
        tier = last.get("tier", "low")
        outcome = last.get("outcome", "?")
        tier_str = _color_tier(tier, tier, color)
        lines.append(f"    last: [{tier_str}/{outcome}] {lcmd}")
    return lines


def render_screen(state: TuiState, width: int = 80, color: bool = True) -> str:
    lines: List[str] = []
    title = " Preflight v1.0 — capability-aware risk firewall "
    timestamp = f" {state.now} "
    pad = max(0, width - len(title) - len(timestamp))
    sep = "─" * pad
    header = f"{title}{sep}{timestamp}"
    if color:
        header = f"{_BOLD}{header}{_RESET}"
    lines.append(header)
    lines.append("")

    section = " Recent decisions"
    if color:
        section = f"{_BOLD}{section}{_RESET}"
    lines.append(section)
    if not state.audit_tail:
        lines.append("  (no audit entries yet — run preflight shell or wire up the Claude Code hook)")
    else:
        for entry in state.audit_tail[-10:]:
            lines.append(render_audit_row(entry, width=width, color=color))
    lines.append("")

    section2 = " Active sessions"
    if color:
        section2 = f"{_BOLD}{section2}{_RESET}"
    lines.append(section2)
    if not state.sessions:
        lines.append("  (no sessions found)")
    else:
        for sess in state.sessions[:5]:
            lines.extend(render_session_block(sess, width=width, color=color))
            lines.append("")

    footer = " Polling every 1s. Ctrl-C to exit."
    if color:
        footer = f"{_DIM}{footer}{_RESET}"
    lines.append(footer)

    return "\n".join(lines)


# ---------- terminal driver ----------


def _terminal_width(default: int = 100) -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return default


def run_tui(
    audit_path: Optional[Path] = None,
    session_dir: Optional[Path] = None,
    interval: float = 1.0,
    color: Optional[bool] = None,
    out=None,
) -> int:
    """Poll-and-redraw loop. Exit cleanly on Ctrl-C or EOF."""
    out = out or sys.stdout
    if color is None:
        color = out.isatty()
    if color:
        out.write(_HIDE_CURSOR)
        out.flush()
    try:
        while True:
            state = gather_state(audit_path, session_dir)
            width = _terminal_width()
            screen = render_screen(state, width=width, color=color)
            if color:
                out.write(_CLEAR_AND_HOME)
            else:
                out.write("\n\n")
            out.write(screen + "\n")
            out.flush()
            time.sleep(interval)
    except (KeyboardInterrupt, EOFError):
        return 0
    finally:
        if color:
            out.write(_SHOW_CURSOR)
            out.flush()


def main(argv=None) -> int:
    return run_tui()
