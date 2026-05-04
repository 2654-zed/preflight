from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .models import Decision, RiskTier, ScoredCommand


def default_audit_path() -> Path:
    return Path("~/.preflight/audit.jsonl").expanduser()


@dataclass
class AuditEntry:
    event_id: str
    timestamp: str
    session_id: str
    seq: int
    cwd: str
    command: str
    source: str
    profile: Optional[str]
    risk_dimensions: Dict[str, int]
    stored_potential_score: int
    risk_tier: str
    decision: str
    outcome: str  # allowed | blocked | confirmed | overridden | skipped | error
    confirmation_phrase_required: Optional[str] = None
    confirmation_matched: Optional[bool] = None
    exit_code: Optional[int] = None
    duration_ms: Optional[int] = None
    triggers: list = field(default_factory=list)
    reasons: list = field(default_factory=list)


class AuditLog:
    """JSONL audit log. Append-only; one file per machine, one line per event."""

    def __init__(self, path: Optional[Path] = None, session_id: Optional[str] = None):
        self.path = Path(path) if path is not None else default_audit_path()
        self.session_id = session_id or self._mk_session_id()
        self.seq = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _mk_session_id() -> str:
        return f"sess_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:6]}"

    def write(
        self,
        scored: ScoredCommand,
        cwd: str,
        outcome: str,
        profile: Optional[str] = None,
        confirmation_phrase_required: Optional[str] = None,
        confirmation_matched: Optional[bool] = None,
        exit_code: Optional[int] = None,
        duration_ms: Optional[int] = None,
    ) -> AuditEntry:
        self.seq += 1
        entry = AuditEntry(
            event_id=f"evt_{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            session_id=self.session_id,
            seq=self.seq,
            cwd=cwd,
            command=scored.command,
            source=scored.source.value,
            profile=profile,
            risk_dimensions={
                "position": scored.dimensions.position,
                "permissions": scored.dimensions.permissions,
                "trust_bindings": scored.dimensions.trust_bindings,
                "mutability": scored.dimensions.mutability,
                "observation": scored.dimensions.observation,
            },
            stored_potential_score=scored.stored_potential,
            risk_tier=scored.risk_tier.value,
            decision=scored.decision.value,
            outcome=outcome,
            confirmation_phrase_required=confirmation_phrase_required,
            confirmation_matched=confirmation_matched,
            exit_code=exit_code,
            duration_ms=duration_ms,
            triggers=scored.triggers,
            reasons=scored.reasons,
        )
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        return entry

    def tail(self, n: int = 10) -> list:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        return [json.loads(line) for line in lines[-n:]]
