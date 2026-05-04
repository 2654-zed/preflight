"""Policy profiles — packaged risk thresholds, allowlists, and blocklists.

A profile shifts the friction Preflight applies to a session. Two types
of rules ride on top of the static scorer:

  threshold shifts        confirm/block tiers move up or down so the same
                          score gets a stricter or laxer decision
  allowlist               regex patterns that, when matched, downgrade
                          the decision to ALLOW (escape hatch for the
                          handful of commands the team trusts blindly)
  blocklist               regex patterns that, when matched, upgrade
                          the decision to HARD_STOP (escape hatch for
                          the handful of patterns nobody should ever run)
  network_allowlist       URL prefixes the team has approved; commands
                          that only egress to allowlisted hosts have
                          their `network_external` trigger suppressed
                          and the decision re-evaluated

The four built-in profiles are tuned for distinct contexts. They are
data, not code — `preflight profile show <name>` prints the full ruleset
and `preflight profile diff a b` shows what changes between them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from .models import Decision, RiskTier, ScoredCommand


@dataclass
class Profile:
    name: str
    description: str = ""

    # Threshold shifts. Default values match the un-profiled baseline.
    confirm_threshold: int = 61
    block_threshold: int = 81

    # Regex patterns evaluated against the command string.
    command_allowlist: List[str] = field(default_factory=list)
    command_blocklist: List[str] = field(default_factory=list)

    # URL prefixes / regexes; if every external network target in the
    # command matches one of these, the network_external risk is suppressed.
    network_allowlist: List[str] = field(default_factory=list)


SOLO_DEVELOPER = Profile(
    name="solo_developer",
    description=(
        "Permissive profile for personal projects and experimentation. "
        "Focuses on credential exfiltration, destructive commands, and "
        "external-state mutation. Other actions tend to pass silently."
    ),
    confirm_threshold=65,
    block_threshold=85,
    network_allowlist=[
        r"^https?://localhost",
        r"^https?://127\.0\.0\.1",
        r"^https?://0\.0\.0\.0",
        r"^https?://(api\.)?github\.com\b",
        r"^https?://raw\.githubusercontent\.com\b",
        r"^https?://(registry\.)?npmjs\.org\b",
        r"^https?://pypi\.org\b",
        r"^https?://files\.pythonhosted\.org\b",
        r"^https?://crates\.io\b",
    ],
)

OPEN_SOURCE_MAINTAINER = Profile(
    name="open_source_maintainer",
    description=(
        "Tight on package publishing, dependency changes, and release "
        "scripts. Force-push to mainline branches is non-negotiable."
    ),
    confirm_threshold=55,
    block_threshold=78,
    command_blocklist=[
        r"\bnpm publish\b.*--force",
        r"\byarn publish\b.*--force",
        r"\bgit push\b.*--force\b.*\b(main|master)\b",
        r"\bgit push\b.*-f\b.*\b(main|master)\b",
    ],
    network_allowlist=[
        r"^https?://localhost",
        r"^https?://127\.0\.0\.1",
        r"^https?://(api\.)?github\.com\b",
        r"^https?://raw\.githubusercontent\.com\b",
        r"^https?://uploads\.github\.com\b",
        r"^https?://(registry\.)?npmjs\.org\b",
        r"^https?://pypi\.org\b",
        r"^https?://files\.pythonhosted\.org\b",
    ],
)

ENTERPRISE = Profile(
    name="enterprise",
    description=(
        "Stricter network egress, branch protection, audit logging, "
        "CI/CD controls. Suitable for company repositories and internal "
        "engineering teams."
    ),
    confirm_threshold=50,
    block_threshold=72,
    command_blocklist=[
        r"\bgit push\b.*--force\b.*\b(main|master|prod|production|release)\b",
        r"\bgit push\b.*-f\b.*\b(main|master|prod|production|release)\b",
        r"\bkubectl\b.*\s--insecure-skip-tls-verify\b",
        r"\bcurl\b.*(?<!\S)-k(?!\S)",
        r"\bcurl\b.*--insecure\b",
    ],
    network_allowlist=[
        # Empty by default — enterprises configure their own internal
        # registries, package proxies, and ingress hosts.
    ],
)

REGULATED = Profile(
    name="regulated",
    description=(
        "Strict audit logs, explicit confirmations on every external "
        "mutation, blocklist of dangerous patterns. For finance, "
        "healthcare, defense, legal, critical infrastructure."
    ),
    confirm_threshold=40,
    block_threshold=68,
    command_blocklist=[
        r"\bgit push\b.*--force\b",
        r"\bgit push\b.*-f\b",
        r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b.*\.\.",
        r"\bcurl\b.*\b-k\b",
        r"\bcurl\b.*--insecure\b",
        r"\bnpm install\b.*--ignore-scripts\s*=\s*false",
        r"\bsudo\b",
    ],
    network_allowlist=[],
)


PROFILES = {
    p.name: p
    for p in (SOLO_DEVELOPER, OPEN_SOURCE_MAINTAINER, ENTERPRISE, REGULATED)
}


def get_profile(name: Optional[str]) -> Optional[Profile]:
    if not name:
        return None
    return PROFILES.get(name)


def _match_any(patterns: List[str], text: str) -> Optional[str]:
    for pat in patterns:
        try:
            if re.search(pat, text):
                return pat
        except re.error:
            continue
    return None


def _extract_urls(text: str) -> List[str]:
    return re.findall(r"\bhttps?://[^\s\"'`<>]+", text)


def _all_urls_allowlisted(text: str, allowlist: List[str]) -> bool:
    urls = _extract_urls(text)
    if not urls:
        return False
    for url in urls:
        if not _match_any(allowlist, url):
            return False
    return True


def apply_profile(scored: ScoredCommand, profile: Profile) -> ScoredCommand:
    """Apply a profile's allowlist, blocklist, threshold shifts, and
    network allowlist to a freshly scored command. The original score and
    triggers are preserved; only the decision (and tier) move.

    Order of application:
      1. command_blocklist  → HARD_STOP regardless of score
      2. command_allowlist  → ALLOW regardless of score (after blocklist)
      3. network_allowlist  → if every URL is allowlisted, suppress
                              network_external from the decision (we
                              recompute decision against the threshold
                              with that trigger ignored)
      4. threshold shifts   → confirm/block tiers move up or down
    """
    cmd = scored.command

    if _match_any(profile.command_blocklist, cmd):
        scored.decision = Decision.HARD_STOP
        scored.risk_tier = RiskTier.CRITICAL
        scored.reasons = list(scored.reasons) + [
            f"Profile `{profile.name}` blocklist matched."
        ]
        return scored

    if _match_any(profile.command_allowlist, cmd):
        scored.decision = Decision.ALLOW
        scored.risk_tier = RiskTier.LOW
        scored.reasons = list(scored.reasons) + [
            f"Profile `{profile.name}` allowlist matched."
        ]
        return scored

    # Network allowlist — only relevant when the command actually does
    # external egress (network_external trigger present). If every URL in
    # the command matches the allowlist, drop the egress concern by
    # cutting the score that the network composition floor produced.
    # Sensitive observations + egress remain critical regardless: an
    # allowlisted destination doesn't make a credential exfil safe.
    sensitive_observation_present = any(
        t.startswith("reads_sensitive_path") or t == "env_dump" or t == "recursive_secret_search"
        for t in scored.triggers
    )
    if (
        "network_external" in scored.triggers
        and profile.network_allowlist
        and not sensitive_observation_present
        and _all_urls_allowlisted(cmd, profile.network_allowlist)
    ):
        # Soft re-score: the egress is no longer "external" from the team's
        # point of view. Drop the score by 25 (the typical egress-floor
        # contribution) but never below the dimensional sum.
        dim_floor = scored.dimensions.sum() * 4
        scored.stored_potential = max(dim_floor, scored.stored_potential - 25)
        scored.risk_tier = _tier_for(scored.stored_potential)
        scored.decision = _decision_for(scored.risk_tier)
        scored.reasons = list(scored.reasons) + [
            f"Profile `{profile.name}` network allowlist matched all URLs."
        ]

    # Threshold shifts.
    score = scored.stored_potential
    if score >= profile.block_threshold:
        scored.decision = Decision.HARD_STOP
        scored.risk_tier = RiskTier.CRITICAL
    elif score >= profile.confirm_threshold:
        if scored.decision in (Decision.ALLOW, Decision.ALLOW_AND_LOG, Decision.WARN):
            scored.decision = Decision.CONFIRM_REQUIRED
            if scored.risk_tier in (RiskTier.LOW, RiskTier.ELEVATED, RiskTier.MEDIUM):
                scored.risk_tier = RiskTier.HIGH

    return scored


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


# ---------- Profile inspection helpers (CLI) ----------


def render_profile(profile: Profile) -> str:
    lines = [
        f"Profile: {profile.name}",
        f"  description: {profile.description}",
        f"  confirm_threshold: {profile.confirm_threshold}",
        f"  block_threshold: {profile.block_threshold}",
    ]
    lines.append(f"  command_allowlist ({len(profile.command_allowlist)}):")
    for p in profile.command_allowlist:
        lines.append(f"    - {p}")
    lines.append(f"  command_blocklist ({len(profile.command_blocklist)}):")
    for p in profile.command_blocklist:
        lines.append(f"    - {p}")
    lines.append(f"  network_allowlist ({len(profile.network_allowlist)}):")
    for p in profile.network_allowlist:
        lines.append(f"    - {p}")
    return "\n".join(lines)


def diff_profiles(a: Profile, b: Profile) -> str:
    lines = [f"Diff: {a.name} -> {b.name}", ""]
    if a.confirm_threshold != b.confirm_threshold:
        lines.append(f"  confirm_threshold: {a.confirm_threshold} -> {b.confirm_threshold}")
    if a.block_threshold != b.block_threshold:
        lines.append(f"  block_threshold:   {a.block_threshold} -> {b.block_threshold}")

    def _list_diff(label: str, la: List[str], lb: List[str]) -> List[str]:
        added = [x for x in lb if x not in la]
        removed = [x for x in la if x not in lb]
        out = []
        if added or removed:
            out.append(f"  {label}:")
            for x in added:
                out.append(f"    + {x}")
            for x in removed:
                out.append(f"    - {x}")
        return out

    lines.extend(_list_diff("command_allowlist", a.command_allowlist, b.command_allowlist))
    lines.extend(_list_diff("command_blocklist", a.command_blocklist, b.command_blocklist))
    lines.extend(_list_diff("network_allowlist", a.network_allowlist, b.network_allowlist))
    if len(lines) <= 2:
        lines.append("  (no differences)")
    return "\n".join(lines)
