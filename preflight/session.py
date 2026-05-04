"""Session graph — accumulated capability tracking across commands.

A single tool call may be safe in isolation. The harm emerges from the
sequence: read a credential, then make a network call. Each step is
permitted; the composition is exfiltration.

SessionGraph remembers which sensitive capabilities a session has
already exercised and re-scores subsequent commands in light of those
capabilities. It does not reduce friction; it adds it where the static
scorer cannot see the link.

State is in-memory and per-shell-instance. Restarting the shell resets
the graph. Capabilities are added only when a command actually executes
(allowed, allowed_logged, confirmed, or overridden) — blocked, declined,
and phrase-mismatched commands do not grant capability.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .models import Decision, RiskTier, ScoredCommand


# Capability tags — what a session has exercised so far.
CAP_OBSERVED_CREDENTIAL = "observed_credential"          # SSH key, .env, AWS creds, etc.
CAP_OBSERVED_ENV_SECRET = "observed_env_secret"          # `env` / `printenv`
CAP_OBSERVED_SECRET_GREP = "observed_secret_grep"        # recursive grep keyed on secret terms
CAP_NETWORK_EGRESS = "network_egress_external"           # outbound network call to external host
CAP_PACKAGE_INSTALLED = "package_installed"              # npm/pip/cargo install
CAP_MUTATION_EXTERNAL = "mutation_external_state"        # git push, terraform apply, kubectl apply
CAP_PERSISTENCE_WRITE = "mutation_persistence"           # wrote to ~/.bashrc etc.
CAP_MODIFIED_LOCKFILE = "modified_lockfile"              # edited package-lock.json / Cargo.lock / etc.
CAP_MODIFIED_CI_CONFIG = "modified_ci_config"            # edited .github/workflows/ etc.
CAP_MODIFIED_BUILD_SCRIPT = "modified_build_script"      # edited Makefile / build.sh / scripts/
CAP_MODIFIED_CONTROL_PLANE = "modified_agent_control_plane"  # edited CLAUDE.md / AGENTS.md / .cursor/rules/
CAP_CONSUMED_INSTRUCTION_CONTENT = "consumed_instruction_content"  # read README / CONTRIBUTING / *.log / issue body


_EXECUTED_OUTCOMES = {"allowed", "allowed_logged", "confirmed", "overridden"}


@dataclass
class LedgerEntry:
    seq: int
    command: str
    score: int
    tier: str
    decision: str
    outcome: str
    capabilities_added: List[str] = field(default_factory=list)
    escalated_from: Optional[Dict[str, object]] = None


class SessionGraph:
    def __init__(self) -> None:
        self.capabilities: Set[str] = set()
        self.ledger: List[LedgerEntry] = []
        self.seq = 0
        # Disk-payload tracking — paths the session has written to, tagged
        # by what kind of payload landed there. Used by the v1.1 cross-
        # command compositions: download-then-execute and buffer-then-exfil.
        self.network_payload_paths: Set[str] = set()
        self.sensitive_buffer_paths: Set[str] = set()

    # ---------- capability extraction ----------

    @staticmethod
    def _granted_by(scored: ScoredCommand) -> Set[str]:
        triggers = scored.triggers
        granted: Set[str] = set()
        if any(t.startswith("reads_sensitive_path") for t in triggers):
            granted.add(CAP_OBSERVED_CREDENTIAL)
        if "env_dump" in triggers:
            granted.add(CAP_OBSERVED_ENV_SECRET)
        if "recursive_secret_search" in triggers:
            granted.add(CAP_OBSERVED_SECRET_GREP)
        if "network_external" in triggers:
            granted.add(CAP_NETWORK_EGRESS)
        if "package_install" in triggers:
            granted.add(CAP_PACKAGE_INSTALLED)
        if "mutates_external_state" in triggers:
            granted.add(CAP_MUTATION_EXTERNAL)
        if any(t.startswith("persistence_write") for t in triggers):
            granted.add(CAP_PERSISTENCE_WRITE)
        if any(t.startswith("lockfile_write") for t in triggers):
            granted.add(CAP_MODIFIED_LOCKFILE)
        if any(t.startswith("ci_config_write") for t in triggers):
            granted.add(CAP_MODIFIED_CI_CONFIG)
        if any(t.startswith("build_script_write") for t in triggers):
            granted.add(CAP_MODIFIED_BUILD_SCRIPT)
        if any(t.startswith("agent_control_plane_modified") or t.startswith("agent_control_plane_deleted") for t in triggers):
            granted.add(CAP_MODIFIED_CONTROL_PLANE)
        if any(t.startswith("consumed_instruction_content") for t in triggers):
            granted.add(CAP_CONSUMED_INSTRUCTION_CONTENT)
        return granted

    @staticmethod
    def _new_command_does_egress(scored: ScoredCommand) -> bool:
        return "network_external" in scored.triggers

    @staticmethod
    def _new_command_observes_sensitive(scored: ScoredCommand) -> bool:
        triggers = scored.triggers
        return any(
            t.startswith("reads_sensitive_path") or t == "env_dump" or t == "recursive_secret_search"
            for t in triggers
        )

    @staticmethod
    def _new_command_external_mutation(scored: ScoredCommand) -> bool:
        return "mutates_external_state" in scored.triggers or "package_publish" in scored.triggers

    @staticmethod
    def _paths_from_triggers(scored: ScoredCommand, prefix: str) -> List[str]:
        out: List[str] = []
        for t in scored.triggers:
            if t.startswith(prefix):
                out.append(t.split(":", 1)[1])
        return out

    @staticmethod
    def _matches_known_path(candidate: str, known: Set[str]) -> bool:
        """Path equivalence between two strings without filesystem access.

        Strips a `./` prefix and matches by basename plus full string. This is
        intentionally loose — the goal is to catch obvious staging like
        `curl url > foo; bash foo` (where the second command writes `foo`,
        not `./foo`) without doing brittle absolute-path resolution.
        """
        c = candidate.lstrip("./")
        for k in known:
            kk = k.lstrip("./")
            if c == kk:
                return True
            if c.endswith("/" + kk) or kk.endswith("/" + c):
                return True
        return False

    def _read_targets(self, scored: ScoredCommand) -> List[str]:
        """Path arguments to read-style verbs, used to detect reads of buffered paths."""
        targets: List[str] = []
        from .scorer import READ_VERBS, SEARCH_VERBS
        for seg in scored.normalized.segments:
            if not seg.tokens:
                continue
            verb = seg.tokens[0]
            if verb in READ_VERBS or verb in SEARCH_VERBS:
                for t in seg.tokens[1:]:
                    if t.startswith("-"):
                        continue
                    if t in {">", ">>", "<", "2>", "2>&1", "&>", "|"}:
                        continue
                    targets.append(t)
        return targets

    # ---------- evaluation ----------

    def evaluate(self, scored: ScoredCommand) -> ScoredCommand:
        """Return a (possibly escalated) ScoredCommand based on session state.

        The original score, tier, and decision are bumped — never relaxed.
        Reasons and triggers are appended so the decomposition stays legible.
        """
        new_score = scored.stored_potential
        new_tier = scored.risk_tier
        new_decision = scored.decision
        added_reasons: List[str] = []
        added_triggers: List[str] = []
        escalated_from: Optional[Dict[str, object]] = None

        # Rule 1: prior sensitive observation + new external network call
        # = staged credential exfiltration (CRITICAL).
        prior_sensitive = (
            CAP_OBSERVED_CREDENTIAL in self.capabilities
            or CAP_OBSERVED_ENV_SECRET in self.capabilities
        )
        prior_grep = CAP_OBSERVED_SECRET_GREP in self.capabilities

        if (prior_sensitive or prior_grep) and self._new_command_does_egress(scored):
            floor = 95 if prior_sensitive else 92
            new_score = max(new_score, floor)
            added_reasons.append(
                "Session has already observed sensitive data; this network call could exfiltrate it."
            )
            added_triggers.append("session:staged_exfiltration")

        # Rule 2: prior egress to a destination + new sensitive read
        # = inbound staging for follow-up exfil. Bump but not critical on its own.
        if (
            CAP_NETWORK_EGRESS in self.capabilities
            and self._new_command_observes_sensitive(scored)
            and scored.risk_tier not in (RiskTier.CRITICAL,)
        ):
            new_score = max(new_score, 70)
            added_reasons.append(
                "Session has already made an external network call; reading sensitive data now creates an exfiltration path."
            )
            added_triggers.append("session:staging_after_egress")

        # Rule 3: prior secret-grep + external state mutation
        # = secrets observed, now publishing externally. CRITICAL.
        if prior_grep and self._new_command_external_mutation(scored):
            new_score = max(new_score, 90)
            added_reasons.append(
                "Session previously ran a recursive secret search; this external mutation could publish what was found."
            )
            added_triggers.append("session:secret_grep_then_publish")

        # Rule 4: prior package install + first external mutation it enables
        # = newly-trusted code now affecting external state. HIGH.
        if (
            CAP_PACKAGE_INSTALLED in self.capabilities
            and self._new_command_external_mutation(scored)
            and scored.risk_tier == RiskTier.MEDIUM
        ):
            new_score = max(new_score, 65)
            added_reasons.append(
                "A package was installed earlier in this session; its scripts may be influencing this external mutation."
            )
            added_triggers.append("session:installed_package_mutation")

        # Rule 5: prior lockfile edit + external state mutation
        # = supply-chain change being published. CRITICAL.
        if CAP_MODIFIED_LOCKFILE in self.capabilities and self._new_command_external_mutation(scored):
            new_score = max(new_score, 92)
            added_reasons.append(
                "Lockfile was modified earlier in this session; this external mutation publishes that change."
            )
            added_triggers.append("session:lockfile_then_publish")

        # Rule 6: prior CI config edit + external state mutation
        # = remote pipeline modification being pushed. CRITICAL.
        if CAP_MODIFIED_CI_CONFIG in self.capabilities and self._new_command_external_mutation(scored):
            new_score = max(new_score, 90)
            added_reasons.append(
                "CI configuration was modified earlier in this session; this external mutation deploys the new pipeline."
            )
            added_triggers.append("session:ci_config_then_publish")

        # Rule 6b (Control Plane Doctrine): prior agent-control-plane edit
        # + external state mutation = persistent agent-instruction change
        # being propagated to the remote repo, where every future agent
        # session will read it. CRITICAL.
        if CAP_MODIFIED_CONTROL_PLANE in self.capabilities and self._new_command_external_mutation(scored):
            new_score = max(new_score, 92)
            added_reasons.append(
                "Agent control plane file was modified earlier in this session; this push propagates the new persistent agent instructions to the remote repository."
            )
            added_triggers.append("session:control_plane_then_publish")

        # Rule 6c (Confused Deputy Doctrine): prior read of an
        # instruction-bearing file (README, CONTRIBUTING, *.log, issue body)
        # + new privileged action = the agent may have been induced to act
        # by content it just consumed. The classic language-mediated
        # confused-deputy pattern. Escalate to HIGH at minimum so the user
        # gets a chance to verify the action wasn't planted by a malicious
        # README.
        if CAP_CONSUMED_INSTRUCTION_CONTENT in self.capabilities:
            from . import authority as _authority
            if _authority.is_privileged_action(scored.triggers):
                new_score = max(new_score, 78)
                added_reasons.append(
                    "Session previously read content from an instruction-bearing source "
                    "(README, CONTRIBUTING, log, issue body); this privileged action may "
                    "have been induced by what was read. Confused-deputy risk."
                )
                added_triggers.append("session:post_instruction_confused_deputy")

        # Rule 7 (v1.1): downloaded code is now being executed.
        # Prior `downloads_to_path:<p>` granted by an executed command, then
        # a new command runs `<p>` (or its absolute equivalent). This is the
        # multi-step `curl X > foo; bash foo` attack pattern.
        if self.network_payload_paths:
            for executed in self._paths_from_triggers(scored, "executes_local_script:"):
                if self._matches_known_path(executed, self.network_payload_paths):
                    new_score = max(new_score, 92)
                    added_reasons.append(
                        f"Path `{executed}` was downloaded from the network earlier in this "
                        f"session and is now being executed."
                    )
                    added_triggers.append("session:download_then_execute")
                    break

        # Rule 8 (v1.1): buffered sensitive data is now being read and egressed.
        # Prior `writes_buffered_sensitive:<p>` (e.g., `env > /tmp/x`), then a
        # new command both reads `<p>` and makes an external network call.
        if self.sensitive_buffer_paths and "network_external" in scored.triggers:
            read_paths = self._read_targets(scored)
            for rp in read_paths:
                if self._matches_known_path(rp, self.sensitive_buffer_paths):
                    new_score = max(new_score, 95)
                    added_reasons.append(
                        f"Path `{rp}` holds sensitive data buffered earlier in this session; "
                        f"reading it now alongside an external network call is exfiltration."
                    )
                    added_triggers.append("session:buffered_sensitive_exfil")
                    break

        if not added_reasons:
            return scored

        new_score = min(new_score, 100)
        new_tier = _tier_for(new_score)
        new_decision = _decision_for(new_tier)

        if new_score > scored.stored_potential or new_decision != scored.decision:
            escalated_from = {
                "stored_potential": scored.stored_potential,
                "risk_tier": scored.risk_tier.value,
                "decision": scored.decision.value,
            }

        return dataclasses.replace(
            scored,
            stored_potential=new_score,
            risk_tier=new_tier,
            decision=new_decision,
            reasons=list(scored.reasons) + added_reasons,
            triggers=sorted(set(scored.triggers) | set(added_triggers)),
        )

    # ---------- recording ----------

    def record(self, scored: ScoredCommand, outcome: str) -> LedgerEntry:
        self.seq += 1
        added: List[str] = []
        if outcome in _EXECUTED_OUTCOMES:
            new_caps = self._granted_by(scored) - self.capabilities
            if new_caps:
                self.capabilities |= new_caps
                added = sorted(new_caps)
            # Disk-payload tracking: only update on actual execution.
            for p in self._paths_from_triggers(scored, "downloads_to_path:"):
                self.network_payload_paths.add(p)
            for p in self._paths_from_triggers(scored, "writes_buffered_sensitive:"):
                self.sensitive_buffer_paths.add(p)
        entry = LedgerEntry(
            seq=self.seq,
            command=scored.command,
            score=scored.stored_potential,
            tier=scored.risk_tier.value,
            decision=scored.decision.value,
            outcome=outcome,
            capabilities_added=added,
        )
        self.ledger.append(entry)
        return entry

    # ---------- persistence ----------

    def to_dict(self) -> dict:
        return {
            "version": 2,
            "capabilities": sorted(self.capabilities),
            "seq": self.seq,
            "network_payload_paths": sorted(self.network_payload_paths),
            "sensitive_buffer_paths": sorted(self.sensitive_buffer_paths),
            "ledger": [
                {
                    "seq": e.seq,
                    "command": e.command,
                    "score": e.score,
                    "tier": e.tier,
                    "decision": e.decision,
                    "outcome": e.outcome,
                    "capabilities_added": list(e.capabilities_added),
                }
                for e in self.ledger
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SessionGraph":
        g = cls()
        g.capabilities = set(data.get("capabilities", []))
        g.seq = int(data.get("seq", 0))
        g.network_payload_paths = set(data.get("network_payload_paths", []))
        g.sensitive_buffer_paths = set(data.get("sensitive_buffer_paths", []))
        for entry in data.get("ledger", []):
            g.ledger.append(
                LedgerEntry(
                    seq=int(entry["seq"]),
                    command=entry["command"],
                    score=int(entry["score"]),
                    tier=entry["tier"],
                    decision=entry["decision"],
                    outcome=entry["outcome"],
                    capabilities_added=list(entry.get("capabilities_added", [])),
                )
            )
        return g

    def save(self, path) -> None:
        import json
        from pathlib import Path
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(p)

    @classmethod
    def load(cls, path) -> "SessionGraph":
        import json
        from pathlib import Path
        p = Path(path)
        if not p.exists():
            return cls()
        try:
            return cls.from_dict(json.loads(p.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, KeyError, ValueError):
            return cls()

    # ---------- inspection ----------

    def summary(self) -> str:
        if not self.capabilities and not self.ledger:
            return "session: empty"
        lines = ["session capabilities:"]
        if self.capabilities:
            for cap in sorted(self.capabilities):
                lines.append(f"  - {cap}")
        else:
            lines.append("  (none)")
        lines.append("session ledger (last 10):")
        for entry in self.ledger[-10:]:
            tag = "+" + ",".join(entry.capabilities_added) if entry.capabilities_added else ""
            lines.append(
                f"  [{entry.seq:>3}] {entry.score:>3}/100 {entry.tier:<8} "
                f"{entry.outcome:<14} {entry.command}  {tag}"
            )
        return "\n".join(lines)


def _tier_for(score: int) -> RiskTier:
    if score <= 20:
        return RiskTier.LOW
    if score <= 40:
        return RiskTier.ELEVATED
    if score <= 60:
        return RiskTier.MEDIUM
    if score <= 80:
        return RiskTier.HIGH
    return RiskTier.CRITICAL


def _decision_for(tier: RiskTier) -> Decision:
    return {
        RiskTier.LOW: Decision.ALLOW,
        RiskTier.ELEVATED: Decision.ALLOW_AND_LOG,
        RiskTier.MEDIUM: Decision.WARN,
        RiskTier.HIGH: Decision.CONFIRM_REQUIRED,
        RiskTier.CRITICAL: Decision.HARD_STOP,
    }[tier]
