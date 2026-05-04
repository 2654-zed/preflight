from __future__ import annotations

import re
from typing import Iterable, List

SENSITIVE_PATH_PATTERNS = [
    r"(^|/)\.env(\.[^/]+)?$",
    r"(^|/)\.env\.local$",
    r"(^|/)id_rsa(\.pub)?$",
    r"(^|/)id_ed25519(\.pub)?$",
    r"(^|/)id_ecdsa(\.pub)?$",
    r"(^|/)id_dsa(\.pub)?$",
    r"\.pem$",
    r"\.key$",
    r"\.pfx$",
    r"\.p12$",
    r"(^|/)\.aws/credentials$",
    r"(^|/)\.aws/config$",
    r"(^|/)\.ssh(/|$)",
    r"(^|/)\.ssh/known_hosts$",
    r"(^|/)\.npmrc$",
    r"(^|/)\.pypirc$",
    r"(^|/)\.kube/config$",
    r"(^|/)\.docker/config\.json$",
    r"(^|/)\.git-credentials$",
    r"(^|/)\.netrc$",
    r"(^|/)credentials(\.json|\.yaml|\.yml)?$",
    r"(^|/)secrets?(\.json|\.yaml|\.yml|\.toml)?$",
    r"service[-_]account.*\.json$",
]

CREDENTIAL_KEYWORDS = [
    "API_KEY", "SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY",
    "AWS_SECRET", "AWS_ACCESS", "GITHUB_TOKEN", "NPM_TOKEN",
    "DATABASE_URL", "DB_PASSWORD",
]

BOUNDARY_PREFIXES = [
    "/etc/", "/var/", "/private/", "/Users/", "/home/", "/root/",
    "/sys/", "/proc/", "/boot/", "/opt/",
    "~/", "$HOME/",
]

PERSISTENCE_PATH_PATTERNS = [
    r"(^|/)\.bashrc$",
    r"(^|/)\.bash_profile$",
    r"(^|/)\.zshrc$",
    r"(^|/)\.zprofile$",
    r"(^|/)\.profile$",
    r"(^|/)\.gitconfig$",
    r"(^|/)\.config/fish/",
    r"(^|/)\.config/autostart/",
    r"crontab",
    r"/etc/cron",
    r"LaunchAgents/",
    r"LaunchDaemons/",
    r"/etc/systemd/",
    r"\.service$",
]

DESTRUCTIVE_PATTERNS = [
    r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b",
    r"\bgit\s+reset\s+--hard\b",
    r"\bgit\s+clean\s+-[a-zA-Z]*f",
    r"\bgit\s+push\s+.*--force\b",
    r"\bgit\s+push\s+.*-f\b",
    r"\bgit\s+branch\s+-D\b",
    r"\bdrop\s+(table|database|schema)\b",
    r"\btruncate\s+table\b",
    r"\bdelete\s+from\b(?!.*\bwhere\b)",
    r"\bkubectl\s+delete\b",
    r"\bterraform\s+destroy\b",
    r"\bdocker\s+system\s+prune\b",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r":\(\)\{",
]

NETWORK_VERBS = {"curl", "wget", "scp", "rsync", "nc", "ncat", "telnet", "ftp"}
NETWORK_REMOTE_VERBS = {"ssh", "sftp"}

PACKAGE_INSTALL_PATTERNS = [
    r"\bnpm\s+(install|i|add)\b",
    r"\bpnpm\s+(install|i|add)\b",
    r"\byarn\s+(add|install)\b",
    r"\bpip\s+install\b",
    r"\bpip3\s+install\b",
    r"\bpoetry\s+(add|install)\b",
    r"\buv\s+(add|pip\s+install)\b",
    r"\bcargo\s+install\b",
    r"\bgem\s+install\b",
    r"\bgo\s+install\b",
    r"\bbrew\s+install\b",
    r"\bapt(-get)?\s+install\b",
    r"\byum\s+install\b",
    r"\bdnf\s+install\b",
]

PACKAGE_PUBLISH_PATTERNS = [
    r"\bnpm\s+publish\b",
    r"\bpnpm\s+publish\b",
    r"\byarn\s+publish\b",
    r"\bcargo\s+publish\b",
    r"\bgem\s+push\b",
    r"\btwine\s+upload\b",
    r"\bdocker\s+push\b",
]

EXTERNAL_STATE_PATTERNS = [
    r"\bgit\s+push\b",
    r"\bvercel\s+(deploy|--prod)\b",
    r"\bnetlify\s+deploy\b",
    r"\bterraform\s+(apply|destroy)\b",
    r"\bkubectl\s+(apply|delete|create|patch)\b",
    r"\bhelm\s+(install|upgrade|uninstall)\b",
    r"\baws\s+(s3\s+rm|s3\s+cp|secretsmanager|iam|ec2|rds|lambda)\b",
    r"\bgcloud\s+(deploy|run|compute|sql)\b",
    r"\baz\s+(deploy|vm|webapp|sql)\b",
    r"\bfly\s+deploy\b",
    r"\brailway\s+up\b",
]

PRODUCTION_KEYWORDS = ["prod", "production", "main", "master", "live"]

PIPE_TO_SHELL_PATTERNS = [
    r"\|\s*(bash|sh|zsh|fish|python|python3|node|ruby|perl)\b",
    r"<\(\s*curl\b",
    r"<\(\s*wget\b",
    r"\$\(curl\b",
    r"`curl",
]

DB_VERBS = {"psql", "mysql", "mongosh", "mongo", "redis-cli", "sqlite3"}
SUDO_VERBS = {"sudo", "doas"}


def matches_any(text: str, patterns: Iterable[str]) -> bool:
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


def first_match(text: str, patterns: Iterable[str]) -> str:
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(0)
    return ""


def is_sensitive_path(path: str) -> bool:
    expanded = path.replace("\\", "/")
    return matches_any(expanded, SENSITIVE_PATH_PATTERNS)


def is_persistence_path(path: str) -> bool:
    expanded = path.replace("\\", "/")
    return matches_any(expanded, PERSISTENCE_PATH_PATTERNS)


def crosses_boundary(path: str) -> bool:
    if path.startswith(("..", "~", "$HOME", "/")):
        if path.startswith("./") or path.startswith("/tmp"):
            return path.startswith("/tmp") is False and False
    p = path.replace("\\", "/")
    if p.startswith("../") or p == ".." or "/../" in p:
        return True
    if p.startswith("~") or p.startswith("$HOME"):
        return True
    for prefix in BOUNDARY_PREFIXES:
        if p.startswith(prefix):
            return True
    return False


def has_destructive(text: str) -> bool:
    return matches_any(text, DESTRUCTIVE_PATTERNS)


def has_network_call(tokens: List[str], raw: str) -> bool:
    if not tokens:
        return False
    if tokens[0] in NETWORK_VERBS or tokens[0] in NETWORK_REMOTE_VERBS:
        return True
    return False


def has_remote_url(tokens: List[str]) -> bool:
    for t in tokens:
        if re.match(r"^https?://", t) or re.match(r"^ftp://", t) or re.match(r"^ssh://", t):
            return True
    return False


def has_package_install(text: str) -> bool:
    return matches_any(text, PACKAGE_INSTALL_PATTERNS)


def has_package_publish(text: str) -> bool:
    return matches_any(text, PACKAGE_PUBLISH_PATTERNS)


def has_external_state_mutation(text: str) -> bool:
    return matches_any(text, EXTERNAL_STATE_PATTERNS)


def hits_production(text: str) -> bool:
    lower = text.lower()
    if "git push" in lower:
        if re.search(r"\borigin\s+(main|master|prod|production|release)\b", lower):
            return True
    for kw in PRODUCTION_KEYWORDS:
        if re.search(rf"\b(prod|production|live)\b", lower):
            return True
    return False


def has_pipe_to_shell(raw: str) -> bool:
    return matches_any(raw, PIPE_TO_SHELL_PATTERNS)


def is_sudo(tokens: List[str]) -> bool:
    return bool(tokens) and tokens[0] in SUDO_VERBS


def is_db_verb(tokens: List[str]) -> bool:
    return bool(tokens) and tokens[0] in DB_VERBS


def references_credential_keyword(text: str) -> bool:
    upper = text.upper()
    return any(kw in upper for kw in CREDENTIAL_KEYWORDS)


def has_recursive_search_for_secrets(tokens: List[str], raw: str) -> bool:
    if not tokens:
        return False
    if tokens[0] in {"grep", "rg", "ag", "find"}:
        if any(kw.lower() in raw.lower() for kw in ("api_key", "secret", "token", "password", ".env", "id_rsa")):
            if "-r" in tokens or "-R" in tokens or any("--recursive" in t for t in tokens) or tokens[0] == "find":
                return True
    return False


def env_dump(tokens: List[str]) -> bool:
    if not tokens or tokens[0] not in ("env", "printenv"):
        return False
    args: List[str] = []
    i = 1
    while i < len(tokens):
        t = tokens[i]
        if t in (">", ">>", "<", "2>", "2>&1", "&>"):
            i += 2  # skip operator and its target
            continue
        args.append(t)
        i += 1
    if not args:
        return True
    return all(a.startswith("-") for a in args)
