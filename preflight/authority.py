"""Confused-deputy doctrine for Preflight.

Agentic AI turns the classic confused deputy problem into a *language-mediated*
confused deputy problem:

  attacker-controlled language
        ↓
  AI agent interprets it as instruction
        ↓
  AI agent uses user-granted tools/credentials
        ↓
  system sees authenticated agent action
        ↓
  unauthorized outcome via authorized pathways

The deeper vulnerability is **authority confusion under delegated agency**.
The agent cannot reliably distinguish user authority from system authority
from repo text from log text from external content. When those collapse
into one instruction stream, the agent becomes a confused deputy.

Preflight's response:

    Untrusted content can inform the agent.
    Untrusted content cannot authorize the agent.

This module supplies:

  AUTHORITY_RANK            ordered hierarchy of SourceContext values
  is_privileged_action(...) whether the triggers indicate a privileged tool call
  is_low_authority(src)     whether a source is below the threshold to authorize
                            privileged actions on its own
  is_instruction_bearing(p) whether a path is a file an agent is likely to
                            *consume as instructions* (README, CONTRIBUTING,
                            INSTALL, log files, etc.)

Composition rules that key off these helpers live in scorer.py and
session.py.
"""

from __future__ import annotations

import re
from typing import Iterable

from .models import SourceContext


# Higher rank = higher authority. Sources at rank ≤ 1 cannot, on their
# own, authorize a privileged action without escalation.
AUTHORITY_RANK = {
    SourceContext.SYSTEM_POLICY: 5,
    SourceContext.USER_REQUEST: 5,
    SourceContext.DEVELOPER_POLICY: 4,
    SourceContext.AGENT_CONTROL_PLANE: 3,
    SourceContext.MODEL_GENERATED: 2,
    SourceContext.REPO_CONTENT: 1,
    SourceContext.LOG_CONTENT: 1,
    SourceContext.ISSUE_CONTENT: 1,
    SourceContext.UNTRUSTED_CONTENT: 1,
    SourceContext.EXTERNAL_WEBPAGE: 0,
    SourceContext.UNKNOWN: 0,
}


# Triggers (or trigger prefixes) that indicate a privileged tool-call —
# something an attacker who controls the language stream would actually
# benefit from inducing. Reading a credential, calling external network,
# installing a package, mutating external state, etc.
_PRIVILEGED_TRIGGER_PATTERNS = (
    "reads_sensitive_path",
    "env_dump",
    "recursive_secret_search",
    "network_external",
    "package_install",
    "package_publish",
    "mutates_external_state",
    "sudo",
    "persistence_write",
    "rm_rf_broad",
    "destructive_pattern",
    "dotgit_write",
    "lockfile_write",
    "ci_config_write",
    "agent_control_plane_modified",
    "agent_control_plane_deleted",
    "downloads_to_path",
    "writes_buffered_sensitive",
    "executes_local_script",
    "git_push",
    "package_lifecycle_install",
)


def is_privileged_action(triggers: Iterable[str]) -> bool:
    """Whether the trigger set indicates this action exercises privileged authority."""
    for t in triggers:
        for pat in _PRIVILEGED_TRIGGER_PATTERNS:
            if t == pat or t.startswith(pat + ":") or t.startswith(pat):
                return True
    return False


_LOW_AUTHORITY_THRESHOLD = 1


def is_low_authority(source: SourceContext) -> bool:
    """Whether `source` is too low-authority to authorize a privileged action alone."""
    return AUTHORITY_RANK.get(source, 0) <= _LOW_AUTHORITY_THRESHOLD


def authority_label(source: SourceContext) -> str:
    """Human-readable label for use in reasons."""
    return source.value.replace("_", " ")


# Files an agent is likely to *consume as instructions*. Reading these
# doesn't itself grant capability, but it primes the session-graph rule:
# if the agent later does a privileged action, that action becomes
# suspicious because it may have been induced by content in the file.
_INSTRUCTION_BEARING_PATTERNS = [
    r"(^|/)README(\.[a-z0-9_]+)?$",
    r"(^|/)CONTRIBUTING(\.[a-z0-9_]+)?$",
    r"(^|/)INSTALL(\.[a-z0-9_]+)?$",
    r"(^|/)SETUP(\.[a-z0-9_]+)?$",
    r"(^|/)NOTES(\.[a-z0-9_]+)?$",
    r"(^|/)ROADMAP(\.[a-z0-9_]+)?$",
    r"(^|/)USAGE(\.[a-z0-9_]+)?$",
    r"(^|/)HISTORY(\.[a-z0-9_]+)?$",
    r"(^|/)CHANGELOG(\.[a-z0-9_]+)?$",
    r"(^|/)RELEASE(_NOTES)?(\.[a-z0-9_]+)?$",
    r"(^|/)MIGRATION(_GUIDE)?(\.[a-z0-9_]+)?$",
    r"(^|/)DEPLOY(MENT)?(\.[a-z0-9_]+)?$",
    r"(^|/)\.github/ISSUE_TEMPLATE/",
    r"(^|/)issues/",
    r"\.log$",
    r"\.log\.\d+$",
]


def is_instruction_bearing(path: str) -> bool:
    """Whether reading this path is likely to expose an agent to attacker-supplied
    natural-language instructions (README, CONTRIBUTING, logs, issue bodies, ...)."""
    if not path:
        return False
    p = path.replace("\\", "/")
    for pattern in _INSTRUCTION_BEARING_PATTERNS:
        if re.search(pattern, p, re.IGNORECASE):
            return True
    return False
