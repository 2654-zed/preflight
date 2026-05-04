"""Agent control plane file detection.

A source file tells the program what to do.
An agent control plane file tells the *agent* what to do to the program.

Files like CLAUDE.md, AGENTS.md, .cursor/rules/*.mdc, .aider.conf.yml, and
.github/copilot-instructions.md shape future AI-agent behavior. They carry
high stored potential even when they contain no secrets, because:

  - the agent treats them as privileged guidance (Trust Bindings)
  - they persist across sessions (Mutability)
  - they often sit at project root (Position)
  - they can indirectly authorize future privileged tool calls (Permissions)
  - they may reveal internal workflows (Observation)

This module supplies two things:

  is_control_plane_path(path)        whether a path is an agent instruction file
  scan_content(text)                 triggers found in the proposed contents

Composition floors that key off these triggers live in scorer.py.
"""

from __future__ import annotations

import re
from typing import List


# ---- Path detection ----

# Each pattern matches the full path or a trailing path segment. Matched at
# any depth; a workspace can have CLAUDE.md at the root, in subprojects, or
# (less common) in nested module directories.
CONTROL_PLANE_PATH_PATTERNS = [
    # Foundation models / generic agent files
    r"(^|/)CLAUDE\.md$",
    r"(^|/)AGENT\.md$",
    r"(^|/)AGENTS\.md$",
    r"(^|/)CONVENTIONS\.md$",
    # Cursor
    r"(^|/)\.cursor/rules/[^/]+\.mdc$",
    r"(^|/)\.cursorrules$",
    # Aider
    r"(^|/)\.aider\.conf\.yml$",
    r"(^|/)\.aider\.conf\.yaml$",
    # Continue
    r"(^|/)\.continuerules$",
    # Windsurf / Codeium
    r"(^|/)\.windsurfrules$",
    r"(^|/)\.codeiumignore$",
    # GitHub Copilot
    r"(^|/)\.github/copilot-instructions\.md$",
    # Generic agent memory / persistent instruction directories
    r"(^|/)\.claude/rules/[^/]+\.md$",
    r"(^|/)\.claude/CLAUDE\.md$",
    r"(^|/)\.agent/[^/]+\.md$",
]


def is_control_plane_path(path: str) -> bool:
    """True iff `path` is recognized as an agent instruction file."""
    if not path:
        return False
    p = path.replace("\\", "/")
    for pattern in CONTROL_PLANE_PATH_PATTERNS:
        if re.search(pattern, p):
            return True
    return False


# ---- Content scanning ----

# Detection is intentionally conservative: false positives mean a CONFIRM
# prompt where ALLOW would have done. False negatives mean a malicious
# instruction sneaks through. We err toward false positives for content-
# heavy patterns.

EXECUTION_INSTRUCTION_PATTERNS = [
    r"(?i)\b(run|execute|invoke|launch)\b\s+(\S*\.(sh|py|js|ts|rb|pl)|scripts?/\S+|bin/\S+)",
    r"(?i)\b(after|when|if)\b.{1,40}\b(fail|error|crash|break|red)\b.{1,40}\b(run|execute|invoke|trigger)\b",
    r"(?i)\bautomatically\s+(run|execute|invoke|trigger|deploy|push|publish)\b",
    r"(?i)\b(deploy|publish|push|release)\s+(automatically|after|whenever|when|on)\b",
    r"(?i)\b(npm|yarn|pnpm)\s+publish\b",
    r"(?i)\bgit\s+push\b.*\b(main|master|prod|production|release)\b",
    r"(?i)\brm\s+-[a-z]*r[a-z]*f\b",
    r"(?i)\bkubectl\s+(apply|delete|create|patch)\b",
    r"(?i)\bterraform\s+(apply|destroy)\b",
    r"(?i)\bcurl\s+\S*\s*\|\s*(bash|sh)\b",
]

SECRET_REFERENCE_PATTERNS = [
    r"\b[A-Z][A-Z0-9_]{2,}_(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL|CRED)\b",
    r"\bPROD_[A-Z0-9_]+\b",
    r"\bADMIN_[A-Z0-9_]+\b",
    r"(^|[^\w/])\.env(\.[a-zA-Z]+)?(\s|$|[^\w])",
    r"~/\.ssh/",
    r"~/\.aws/",
    r"~/\.kube/",
    r"~/\.npmrc",
    r"~/\.pypirc",
    r"\bcredentials?\.(json|ya?ml|toml)\b",
    r"(?i)\b(api[\s_-]?key|access[\s_-]?token|private[\s_-]?key|service[\s_-]?account)\b",
    r"(?i)\b(use|read|with)\s+(the\s+)?(prod|production|admin|root)[-_\s]?(token|key|secret|credential)\b",
]

PRODUCTION_REFERENCE_PATTERNS = [
    r"(?i)\b(deploy|push|release|publish)\b.{0,20}\b(to\s+)?prod(uction)?\b",
    r"(?i)\bproduction\b.{0,20}\b(database|db|cluster|namespace|environment|env)\b",
    r"(?i)\b(reset|wipe|drop|destroy|delete)\b.{0,30}\bproduction\b",
    r"(?i)\b(prod-only|live\s+system|customer-facing)\b",
    r"(?i)\bmain\s+branch\b.*\b(deploy|push|release|publish)\b",
]

DESTRUCTIVE_WORKFLOW_PATTERNS = [
    r"(?i)\b(reset|wipe|drop|destroy|purge|truncate)\b.{0,30}\b(database|db|table|schema|namespace|cluster)\b",
    r"(?i)\brm\s+-[a-z]*r[a-z]*f\b.{0,30}\b(\.\.|\/|\$home|~)\b",
    r"(?i)\bgit\s+push\b.*\b(--force|-f)\b",
    r"(?i)\bgit\s+reset\s+--hard\b",
    r"(?i)\bkubectl\s+delete\s+(namespace|deployment|secret|all)\b",
    r"(?i)\bterraform\s+destroy\b",
]


def _matches_any(patterns: List[str], text: str) -> bool:
    return any(re.search(p, text) for p in patterns)


def scan_content(text: str) -> List[str]:
    """Return the trigger names found in the proposed contents.

    Triggers emitted (each at most once):
      agent_instruction_exec_path_added
      agent_instruction_secret_reference
      agent_instruction_production_reference
      agent_instruction_destructive_workflow
    """
    triggers: List[str] = []
    if not text:
        return triggers
    if _matches_any(EXECUTION_INSTRUCTION_PATTERNS, text):
        triggers.append("agent_instruction_exec_path_added")
    if _matches_any(SECRET_REFERENCE_PATTERNS, text):
        triggers.append("agent_instruction_secret_reference")
    if _matches_any(PRODUCTION_REFERENCE_PATTERNS, text):
        triggers.append("agent_instruction_production_reference")
    if _matches_any(DESTRUCTIVE_WORKFLOW_PATTERNS, text):
        triggers.append("agent_instruction_destructive_workflow")
    return triggers
