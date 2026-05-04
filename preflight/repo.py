"""Repo awareness — detect project root and classify paths.

The generic boundary heuristic in v0.3 fires on prefixes like `~/`, `/etc/`,
or relative `..` traversal. That's blunt: walking `cd ..` inside a deeply
nested project doesn't actually escape the project, and editing
`package-lock.json` inside the repo isn't a "boundary" issue at all even
though it's high-leverage.

v0.4 walks up from the current directory to find a real repo root (a
`.git/` directory, or a recognised project manifest like `pyproject.toml`,
`package.json`, `Cargo.toml`, `go.mod`, ...) and then classifies any path
argument as one of:

  in_repo                 normal project file
  in_repo_dotgit          modifying .git/ internals (corruption surface)
  in_repo_lockfile        package-lock.json / Cargo.lock / poetry.lock / ...
  in_repo_ci_config       .github/workflows/, .gitlab-ci.yml, Jenkinsfile, ...
  in_repo_build_script    Makefile, scripts/, build.sh, noxfile.py, ...
  in_repo_manifest        package.json, pyproject.toml (declarative scripts)
  out_of_repo             resolves outside the detected root
  sensitive               credential-bearing path (~/.ssh/id_rsa, .env, ...)
  unknown                 no repo context, or no path arg
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from . import detectors as D


_PROJECT_MARKERS = (
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Gemfile",
    "composer.json",
    "mix.exs",
    "setup.py",
    "setup.cfg",
    "deno.json",
    "deno.jsonc",
)

_LOCKFILE_NAMES = frozenset({
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Cargo.lock",
    "poetry.lock",
    "Pipfile.lock",
    "Gemfile.lock",
    "composer.lock",
    "go.sum",
    "mix.lock",
    "uv.lock",
})

_MANIFEST_NAMES = frozenset(_PROJECT_MARKERS)

_CI_CONFIG_PREFIXES = (
    ".github/workflows/",
    ".github/actions/",
    ".gitlab/",
    ".circleci/",
)

_CI_CONFIG_FILENAMES = frozenset({
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    "Jenkinsfile",
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    "bitbucket-pipelines.yml",
    ".drone.yml",
    ".travis.yml",
    "buildkite.yml",
    "buildspec.yml",
    "cloudbuild.yaml",
    "cloudbuild.yml",
})

_CI_CONFIG_PATH_FRAGMENTS = (
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
)

_BUILD_SCRIPT_FILENAMES = frozenset({
    "Makefile",
    "makefile",
    "GNUmakefile",
    "Justfile",
    "justfile",
    "Taskfile.yml",
    "Taskfile.yaml",
    "noxfile.py",
    "tox.ini",
    "build.sh",
    "build.bash",
    "setup.sh",
    "install.sh",
    "bootstrap.sh",
})


# Classification constants. Imported by scorer for trigger emission.
PATH_IN_REPO = "in_repo"
PATH_IN_REPO_DOTGIT = "in_repo_dotgit"
PATH_IN_REPO_LOCKFILE = "in_repo_lockfile"
PATH_IN_REPO_CI_CONFIG = "in_repo_ci_config"
PATH_IN_REPO_BUILD_SCRIPT = "in_repo_build_script"
PATH_IN_REPO_MANIFEST = "in_repo_manifest"
PATH_OUT_OF_REPO = "out_of_repo"
PATH_SENSITIVE = "sensitive"
PATH_UNKNOWN = "unknown"


@dataclass(frozen=True)
class RepoContext:
    root: Path           # absolute, resolved
    kind: str            # "git" | "project"

    @classmethod
    def detect(cls, cwd) -> Optional["RepoContext"]:
        """Walk up from cwd looking for a .git/ directory or a project marker."""
        cwd_path = Path(cwd)
        try:
            cwd_path = cwd_path.resolve()
        except OSError:
            return None
        if not cwd_path.exists() or not cwd_path.is_dir():
            return None
        for current in [cwd_path] + list(cwd_path.parents):
            if (current / ".git").exists():
                return cls(root=current, kind="git")
            for marker in _PROJECT_MARKERS:
                if (current / marker).is_file():
                    return cls(root=current, kind="project")
        return None


def _normalize(path_str: str, cwd) -> str:
    """Resolve a path string to an absolute, normalized path without requiring it to exist."""
    expanded = os.path.expanduser(path_str)
    expanded = os.path.expandvars(expanded)
    if os.path.isabs(expanded):
        return os.path.normpath(expanded)
    return os.path.normpath(os.path.join(str(cwd), expanded))


def _is_under(child: str, parent: str) -> bool:
    """True if `child` is `parent` or strictly inside it (string-based, normalized)."""
    child_n = os.path.normcase(os.path.normpath(child))
    parent_n = os.path.normcase(os.path.normpath(parent))
    if child_n == parent_n:
        return True
    sep = os.sep
    return child_n.startswith(parent_n + sep)


def classify_path(path_str: str, repo: Optional[RepoContext], cwd) -> str:
    """Classify a single path argument.

    Sensitive paths win regardless of repo (a credential file is sensitive
    even if it happens to live inside a repo). Otherwise, if a repo is
    given, return the in_repo / out_of_repo classification; if not, fall
    back to PATH_UNKNOWN so the legacy heuristics in scorer apply.
    """
    if not path_str:
        return PATH_UNKNOWN
    if D.is_sensitive_path(path_str):
        return PATH_SENSITIVE

    if repo is None:
        return PATH_UNKNOWN

    resolved = _normalize(path_str, cwd)
    if not _is_under(resolved, str(repo.root)):
        return PATH_OUT_OF_REPO

    rel = os.path.relpath(resolved, str(repo.root)).replace("\\", "/")
    if rel == "." or rel == "":
        return PATH_IN_REPO

    if rel == ".git" or rel.startswith(".git/"):
        return PATH_IN_REPO_DOTGIT

    name = os.path.basename(rel)
    if name in _LOCKFILE_NAMES:
        return PATH_IN_REPO_LOCKFILE

    for prefix in _CI_CONFIG_PREFIXES:
        if rel.startswith(prefix):
            return PATH_IN_REPO_CI_CONFIG
    if name in _CI_CONFIG_FILENAMES:
        return PATH_IN_REPO_CI_CONFIG
    for frag in _CI_CONFIG_PATH_FRAGMENTS:
        if rel == frag:
            return PATH_IN_REPO_CI_CONFIG

    if name in _BUILD_SCRIPT_FILENAMES:
        return PATH_IN_REPO_BUILD_SCRIPT
    if rel.startswith("scripts/") and (name.endswith(".sh") or name.endswith(".py") or name.endswith(".js")):
        return PATH_IN_REPO_BUILD_SCRIPT

    if name in _MANIFEST_NAMES:
        return PATH_IN_REPO_MANIFEST

    return PATH_IN_REPO


def describe(repo: Optional[RepoContext]) -> str:
    if repo is None:
        return "no repo context"
    return f"repo:{repo.kind} root={repo.root}"
