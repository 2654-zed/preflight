from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class RiskTier(str, Enum):
    LOW = "low"
    ELEVATED = "elevated"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_AND_LOG = "ALLOW_AND_LOG"
    WARN = "WARN"
    CONFIRM_REQUIRED = "CONFIRM_REQUIRED"
    HARD_STOP = "HARD_STOP"
    OVERRIDE_REQUIRED = "OVERRIDE_REQUIRED"


class SourceContext(str, Enum):
    """Where a proposed action came from — its authority origin.

    The enum is ordered from highest authority (system policy, direct user)
    down to lowest (untrusted external content). Preflight's confused-deputy
    rule keys off this ordering: when low-authority sources propose
    privileged actions, the action is flagged regardless of base score.
    """
    SYSTEM_POLICY = "system_policy"          # the platform itself
    USER_REQUEST = "user_request"            # direct user instruction
    DEVELOPER_POLICY = "developer_policy"    # team config, settings.json, profile
    AGENT_CONTROL_PLANE = "agent_control_plane"  # CLAUDE.md / AGENTS.md / .cursor/rules
    MODEL_GENERATED = "model_generated"      # model proposed it autonomously
    REPO_CONTENT = "repo_content"            # README, source comments, project docs
    LOG_CONTENT = "log_content"              # error logs, build output, traces
    ISSUE_CONTENT = "issue_content"          # GitHub issues, PR descriptions, comments
    UNTRUSTED_CONTENT = "untrusted_content"  # generic untrusted bucket
    EXTERNAL_WEBPAGE = "external_webpage"    # content fetched from the web
    UNKNOWN = "unknown"                      # provenance not tracked


@dataclass
class Segment:
    raw: str
    tokens: List[str]
    verb: str = ""

    def __post_init__(self):
        if not self.verb and self.tokens:
            self.verb = self.tokens[0]


@dataclass
class NormalizedCommand:
    raw: str
    segments: List[Segment]
    has_pipe: bool = False
    has_chain: bool = False
    has_command_substitution: bool = False


@dataclass
class RiskDimensions:
    position: int = 0
    permissions: int = 0
    trust_bindings: int = 0
    mutability: int = 0
    observation: int = 0

    def sum(self) -> int:
        return self.position + self.permissions + self.trust_bindings + self.mutability + self.observation


@dataclass
class ScoredCommand:
    command: str
    source: SourceContext
    normalized: NormalizedCommand
    dimensions: RiskDimensions
    stored_potential: int
    risk_tier: RiskTier
    decision: Decision
    reasons: List[str] = field(default_factory=list)
    triggers: List[str] = field(default_factory=list)
    explanation: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "command": self.command,
            "source": self.source.value,
            "stored_potential_score": self.stored_potential,
            "risk_tier": self.risk_tier.value,
            "decision": self.decision.value,
            "risk_dimensions": {
                "position": self.dimensions.position,
                "permissions": self.dimensions.permissions,
                "trust_bindings": self.dimensions.trust_bindings,
                "mutability": self.dimensions.mutability,
                "observation": self.dimensions.observation,
            },
            "triggers": self.triggers,
            "reasons": self.reasons,
            "explanation": self.explanation,
            "segments": [seg.raw for seg in self.normalized.segments],
        }
