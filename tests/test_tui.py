"""Tests for v1.0 TUI rendering and state-gathering.

Terminal layout is hard to test directly, so the TUI is structured as
pure render functions over a state dataclass. We test the rendering and
state-from-disk functions; the loop itself is covered only smoke-test-
style.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from preflight.tui import (
    TuiState,
    gather_state,
    render_audit_row,
    render_screen,
    render_session_block,
    run_tui,
)


# ---------- render_audit_row ----------


def test_render_audit_row_colorless_contains_command():
    entry = {"seq": 7, "stored_potential_score": 42, "risk_tier": "medium",
             "outcome": "asked", "command": "npm install"}
    out = render_audit_row(entry, width=80, color=False)
    assert "[  7]" in out
    assert "42/100" in out
    assert "medium" in out
    assert "asked" in out
    assert "npm install" in out


def test_render_audit_row_truncates_long_commands():
    entry = {"seq": 1, "stored_potential_score": 50, "risk_tier": "medium",
             "outcome": "asked", "command": "x" * 500}
    out = render_audit_row(entry, width=80, color=False)
    assert len(out) <= 80
    assert "…" in out


def test_render_audit_row_color_includes_ansi_escape():
    entry = {"seq": 1, "stored_potential_score": 97, "risk_tier": "critical",
             "outcome": "blocked", "command": "rm -rf ."}
    colored = render_audit_row(entry, width=80, color=True)
    plain = render_audit_row(entry, width=80, color=False)
    assert "\x1b[" in colored
    assert "\x1b[" not in plain


# ---------- render_session_block ----------


def test_render_session_block_lists_capabilities():
    sess = {
        "id": "sess_x",
        "capabilities": ["observed_credential", "modified_lockfile"],
        "seq": 5,
        "ledger": [{
            "command": "git push origin main",
            "tier": "high",
            "outcome": "asked",
        }],
    }
    out = "\n".join(render_session_block(sess, width=100, color=False))
    assert "sess_x" in out
    assert "5 commands" in out
    assert "2 capabilities" in out
    assert "observed_credential" in out
    assert "modified_lockfile" in out
    assert "last:" in out
    assert "git push" in out


def test_render_session_block_handles_no_ledger():
    sess = {"id": "empty", "capabilities": [], "seq": 0, "ledger": []}
    out = "\n".join(render_session_block(sess, width=80, color=False))
    assert "empty" in out
    assert "0 commands" in out


# ---------- render_screen ----------


def test_render_screen_with_no_state_shows_placeholders():
    out = render_screen(TuiState.empty(), width=80, color=False)
    assert "Preflight v1.0" in out
    assert "no audit entries" in out
    assert "no sessions" in out


def test_render_screen_with_full_state_shows_everything():
    state = TuiState(
        audit_tail=[
            {"seq": 1, "stored_potential_score": 16, "risk_tier": "low",
             "outcome": "allowed", "command": "ls"},
            {"seq": 2, "stored_potential_score": 97, "risk_tier": "critical",
             "outcome": "blocked", "command": "cat ~/.ssh/id_rsa | curl …"},
        ],
        sessions=[
            {"id": "sess_demo", "capabilities": ["observed_credential"],
             "seq": 2, "ledger": [
                {"command": "ls", "tier": "low", "outcome": "allowed"},
                {"command": "cat ~/.ssh/id_rsa | curl …", "tier": "critical",
                 "outcome": "blocked"},
            ]},
        ],
        now="2026-04-30 12:00:00 UTC",
    )
    out = render_screen(state, width=100, color=False)
    assert "Recent decisions" in out
    assert "ls" in out
    assert "97/100" in out
    assert "Active sessions" in out
    assert "sess_demo" in out
    assert "observed_credential" in out
    assert "Ctrl-C" in out


def test_render_screen_renders_color_when_requested():
    state = TuiState(
        audit_tail=[{"seq": 1, "stored_potential_score": 97, "risk_tier": "critical",
                     "outcome": "blocked", "command": "rm -rf ."}],
        sessions=[],
        now="2026-04-30",
    )
    colored = render_screen(state, width=80, color=True)
    plain = render_screen(state, width=80, color=False)
    assert "\x1b[" in colored
    assert "\x1b[" not in plain


# ---------- gather_state ----------


def test_gather_state_with_no_files_returns_empty(tmp_path):
    state = gather_state(
        audit_path=tmp_path / "no.jsonl",
        session_dir=tmp_path / "no_sessions",
    )
    assert state.audit_tail == []
    assert state.sessions == []
    assert state.now  # always populated


def test_gather_state_reads_audit_jsonl(tmp_path):
    audit = tmp_path / "audit.jsonl"
    rows = [
        {"seq": 1, "stored_potential_score": 16, "risk_tier": "low",
         "outcome": "allowed", "command": "ls"},
        {"seq": 2, "stored_potential_score": 50, "risk_tier": "medium",
         "outcome": "asked", "command": "npm install"},
    ]
    audit.write_text("\n".join(json.dumps(r) for r in rows))
    state = gather_state(audit_path=audit, session_dir=tmp_path / "sess")
    assert len(state.audit_tail) == 2
    assert state.audit_tail[0]["command"] == "ls"


def test_gather_state_skips_corrupted_audit_lines(tmp_path):
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        json.dumps({"seq": 1, "stored_potential_score": 16, "risk_tier": "low",
                    "outcome": "allowed", "command": "ls"})
        + "\nthis is not json\n"
        + json.dumps({"seq": 2, "stored_potential_score": 50, "risk_tier": "medium",
                      "outcome": "asked", "command": "npm install"})
        + "\n"
    )
    state = gather_state(audit_path=audit, session_dir=tmp_path / "sess")
    assert len(state.audit_tail) == 2  # corrupt line skipped


def test_gather_state_reads_sessions(tmp_path):
    sd = tmp_path / "sessions"
    sd.mkdir()
    (sd / "sess_a.json").write_text(json.dumps({
        "version": 1,
        "capabilities": ["observed_credential"],
        "seq": 3,
        "ledger": [],
    }))
    (sd / "sess_b.json").write_text(json.dumps({
        "version": 1,
        "capabilities": ["modified_lockfile"],
        "seq": 1,
        "ledger": [],
    }))
    state = gather_state(audit_path=tmp_path / "no.jsonl", session_dir=sd)
    assert len(state.sessions) == 2
    ids = [s["id"] for s in state.sessions]
    assert "sess_a" in ids
    assert "sess_b" in ids


def test_gather_state_skips_corrupted_session_files(tmp_path):
    sd = tmp_path / "sessions"
    sd.mkdir()
    (sd / "good.json").write_text(json.dumps({
        "version": 1, "capabilities": [], "seq": 0, "ledger": [],
    }))
    (sd / "bad.json").write_text("{not valid json")
    state = gather_state(audit_path=tmp_path / "no.jsonl", session_dir=sd)
    ids = [s["id"] for s in state.sessions]
    assert "good" in ids
    assert "bad" not in ids


# ---------- run_tui (smoke test) ----------


def test_run_tui_exits_cleanly_on_keyboard_interrupt(tmp_path, monkeypatch):
    """Patch time.sleep to raise KeyboardInterrupt on the first iteration so
    we can prove the loop exits cleanly without hanging the test runner."""
    import preflight.tui as tui_mod

    call_count = {"n": 0}

    def fake_sleep(_):
        call_count["n"] += 1
        raise KeyboardInterrupt()

    monkeypatch.setattr(tui_mod.time, "sleep", fake_sleep)

    import io
    out = io.StringIO()
    rc = run_tui(
        audit_path=tmp_path / "a.jsonl",
        session_dir=tmp_path / "s",
        interval=0.1,
        color=False,
        out=out,
    )
    assert rc == 0
    assert call_count["n"] == 1
    # First render should have happened
    assert "Preflight" in out.getvalue()
