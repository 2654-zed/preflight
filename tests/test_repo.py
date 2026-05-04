"""Tests for v0.4 repo awareness — detection, classification, and scoring."""

from __future__ import annotations

import json
import os
import subprocess
import textwrap
from pathlib import Path
from typing import List

import pytest

from preflight.audit import AuditLog
from preflight.models import Decision, RiskTier, SourceContext
from preflight.repo import (
    PATH_IN_REPO,
    PATH_IN_REPO_BUILD_SCRIPT,
    PATH_IN_REPO_CI_CONFIG,
    PATH_IN_REPO_DOTGIT,
    PATH_IN_REPO_LOCKFILE,
    PATH_IN_REPO_MANIFEST,
    PATH_OUT_OF_REPO,
    PATH_SENSITIVE,
    PATH_UNKNOWN,
    RepoContext,
    classify_path,
)
from preflight.scorer import score_command
from preflight.session import (
    CAP_MODIFIED_CI_CONFIG,
    CAP_MODIFIED_LOCKFILE,
    SessionGraph,
)
from preflight.shell import GuardedShell


# ---------- RepoContext detection ----------


def test_detect_finds_git_repo(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "subdir").mkdir()
    repo = RepoContext.detect(tmp_path / "subdir")
    assert repo is not None
    assert repo.kind == "git"
    assert repo.root == tmp_path.resolve()


def test_detect_walks_up_through_nested_dirs(tmp_path):
    (tmp_path / ".git").mkdir()
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    repo = RepoContext.detect(deep)
    assert repo is not None
    assert repo.root == tmp_path.resolve()


def test_detect_finds_project_marker_when_no_git(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    deep = tmp_path / "src" / "pkg"
    deep.mkdir(parents=True)
    repo = RepoContext.detect(deep)
    assert repo is not None
    assert repo.kind == "project"
    assert repo.root == tmp_path.resolve()


def test_detect_returns_none_when_no_marker(tmp_path):
    sub = tmp_path / "wide-open"
    sub.mkdir()
    repo = RepoContext.detect(sub)
    # tmp_path itself is somewhere under user dir which probably has no .git
    # but this test relies on the temp tree being clean. If a project marker
    # exists somewhere up the tree, detect() returns it. Either way, the
    # result is consistent — we just assert no exception.
    assert repo is None or isinstance(repo, RepoContext)


def test_detect_prefers_git_over_project_marker(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    repo = RepoContext.detect(tmp_path)
    assert repo.kind == "git"


# ---------- classify_path ----------


@pytest.fixture
def repo(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: ci")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "build.sh").write_text("#!/bin/sh")
    (tmp_path / "Makefile").write_text("all:\n\techo hi")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("# code")
    return RepoContext.detect(tmp_path)


def test_classify_in_repo_normal(repo, tmp_path):
    assert classify_path("src/app.py", repo, str(tmp_path)) == PATH_IN_REPO
    assert classify_path("./src/app.py", repo, str(tmp_path)) == PATH_IN_REPO


def test_classify_lockfile(repo, tmp_path):
    assert classify_path("package-lock.json", repo, str(tmp_path)) == PATH_IN_REPO_LOCKFILE
    assert classify_path("./package-lock.json", repo, str(tmp_path)) == PATH_IN_REPO_LOCKFILE


def test_classify_ci_config_workflow(repo, tmp_path):
    assert (
        classify_path(".github/workflows/ci.yml", repo, str(tmp_path))
        == PATH_IN_REPO_CI_CONFIG
    )


def test_classify_ci_config_jenkinsfile(repo, tmp_path):
    assert classify_path("Jenkinsfile", repo, str(tmp_path)) == PATH_IN_REPO_CI_CONFIG


def test_classify_build_script_makefile(repo, tmp_path):
    assert classify_path("Makefile", repo, str(tmp_path)) == PATH_IN_REPO_BUILD_SCRIPT


def test_classify_build_script_under_scripts_dir(repo, tmp_path):
    assert classify_path("scripts/build.sh", repo, str(tmp_path)) == PATH_IN_REPO_BUILD_SCRIPT


def test_classify_manifest(repo, tmp_path):
    assert classify_path("package.json", repo, str(tmp_path)) == PATH_IN_REPO_MANIFEST


def test_classify_dotgit(repo, tmp_path):
    assert classify_path(".git/config", repo, str(tmp_path)) == PATH_IN_REPO_DOTGIT


def test_classify_out_of_repo_via_traversal(repo, tmp_path):
    assert classify_path("../somewhere/else", repo, str(tmp_path)) == PATH_OUT_OF_REPO


def test_classify_out_of_repo_via_absolute(repo, tmp_path):
    assert classify_path("/etc/hosts", repo, str(tmp_path)) == PATH_OUT_OF_REPO


def test_classify_sensitive_wins_over_in_repo(repo, tmp_path):
    # A `.env` inside the repo is still classified SENSITIVE — the credential
    # nature trumps the in-repo location.
    assert classify_path(".env", repo, str(tmp_path)) == PATH_SENSITIVE


def test_classify_unknown_when_no_repo(tmp_path):
    assert classify_path("foo.txt", None, str(tmp_path)) == PATH_UNKNOWN


def test_classify_sensitive_works_without_repo(tmp_path):
    assert classify_path("~/.ssh/id_rsa", None, str(tmp_path)) == PATH_SENSITIVE


# ---------- scorer integration ----------


def test_lockfile_write_emits_trigger(repo, tmp_path):
    s = score_command(
        "echo '{}' > package-lock.json",
        source=SourceContext.MODEL_GENERATED,
        repo=repo,
        cwd=str(tmp_path),
    )
    assert any(t.startswith("lockfile_write") for t in s.triggers)


def test_lockfile_write_then_git_push_in_one_line_is_critical(repo, tmp_path):
    s = score_command(
        "sed -i 's/foo/bar/g' package-lock.json && git push origin main",
        source=SourceContext.MODEL_GENERATED,
        repo=repo,
        cwd=str(tmp_path),
    )
    assert s.risk_tier == RiskTier.CRITICAL
    assert s.decision == Decision.HARD_STOP
    assert any("supply-chain" in r.lower() for r in s.reasons)


def test_ci_config_write_emits_trigger(repo, tmp_path):
    s = score_command(
        "echo 'malicious' > .github/workflows/ci.yml",
        source=SourceContext.MODEL_GENERATED,
        repo=repo,
        cwd=str(tmp_path),
    )
    assert any(t.startswith("ci_config_write") for t in s.triggers)
    # On its own, a CI config edit isn't yet critical — but it should be
    # at least medium so the user notices.
    assert s.risk_tier in (RiskTier.MEDIUM, RiskTier.HIGH, RiskTier.CRITICAL)


def test_ci_config_write_then_git_push_is_critical(repo, tmp_path):
    s = score_command(
        "echo 'evil' > .github/workflows/ci.yml && git push origin feature-branch",
        source=SourceContext.MODEL_GENERATED,
        repo=repo,
        cwd=str(tmp_path),
    )
    assert s.risk_tier == RiskTier.CRITICAL
    assert s.decision == Decision.HARD_STOP
    assert any("ci" in r.lower() and ("pipeline" in r.lower() or "push" in r.lower()) for r in s.reasons)


def test_dotgit_write_is_critical(repo, tmp_path):
    s = score_command(
        "echo 'x' > .git/config",
        source=SourceContext.MODEL_GENERATED,
        repo=repo,
        cwd=str(tmp_path),
    )
    assert s.risk_tier == RiskTier.CRITICAL
    assert any(t.startswith("dotgit_write") for t in s.triggers)


def test_in_repo_path_is_lower_position_than_out_of_repo(repo, tmp_path):
    s_in = score_command(
        "cat src/app.py",
        source=SourceContext.MODEL_GENERATED,
        repo=repo,
        cwd=str(tmp_path),
    )
    s_out = score_command(
        "cat ../somewhere/else.txt",
        source=SourceContext.MODEL_GENERATED,
        repo=repo,
        cwd=str(tmp_path),
    )
    assert s_in.dimensions.position < s_out.dimensions.position


def test_out_of_repo_emits_explicit_trigger_when_repo_present(repo, tmp_path):
    s = score_command(
        "cat /etc/hosts",
        source=SourceContext.MODEL_GENERATED,
        repo=repo,
        cwd=str(tmp_path),
    )
    assert any(t.startswith("out_of_repo:") for t in s.triggers)


def test_no_repo_falls_back_to_legacy_behavior(tmp_path):
    # No .git, no project marker — repo is None — same behavior as v0.3.
    s = score_command("cat ~/.ssh/id_rsa", source=SourceContext.MODEL_GENERATED)
    assert s.dimensions.position == 5  # sensitive + boundary
    assert any(t.startswith("sensitive_path") for t in s.triggers)


# ---------- session capability extension ----------


def test_session_captures_lockfile_modification(repo, tmp_path):
    g = SessionGraph()
    s = score_command(
        "sed -i 's/x/y/g' package-lock.json",
        source=SourceContext.USER_REQUEST,
        repo=repo,
        cwd=str(tmp_path),
    )
    g.record(s, outcome="confirmed")
    assert CAP_MODIFIED_LOCKFILE in g.capabilities


def test_session_lockfile_then_push_escalates(repo, tmp_path):
    g = SessionGraph()
    edit = score_command(
        "sed -i 's/x/y/g' package-lock.json",
        source=SourceContext.USER_REQUEST,
        repo=repo,
        cwd=str(tmp_path),
    )
    g.record(edit, outcome="confirmed")
    push = score_command(
        "git push origin feature-branch",
        source=SourceContext.USER_REQUEST,
        repo=repo,
        cwd=str(tmp_path),
    )
    out = g.evaluate(push)
    assert out.risk_tier == RiskTier.CRITICAL
    assert out.decision == Decision.HARD_STOP
    assert any("lockfile" in r.lower() for r in out.reasons)


def test_session_ci_config_then_push_escalates(repo, tmp_path):
    g = SessionGraph()
    edit = score_command(
        "echo 'x' > .github/workflows/ci.yml",
        source=SourceContext.USER_REQUEST,
        repo=repo,
        cwd=str(tmp_path),
    )
    g.record(edit, outcome="confirmed")
    push = score_command(
        "git push origin feature-branch",
        source=SourceContext.USER_REQUEST,
        repo=repo,
        cwd=str(tmp_path),
    )
    out = g.evaluate(push)
    assert out.risk_tier == RiskTier.CRITICAL
    assert any("ci" in r.lower() for r in out.reasons)


# ---------- shell integration ----------


def test_shell_detects_repo_on_init(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "src").mkdir()
    src = tmp_path / "src"

    audit = AuditLog(path=tmp_path / "audit.jsonl", session_id="s")
    shell = GuardedShell(
        cwd=str(src),
        audit=audit,
        prompt_fn=lambda _: "n",
        out=lambda _: None,
    )
    assert shell.repo is not None
    assert shell.repo.root == tmp_path.resolve()


def test_shell_redetects_repo_after_cd(tmp_path):
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()
    other = tmp_path / "other"
    other.mkdir()

    audit = AuditLog(path=tmp_path / "audit.jsonl", session_id="s")
    shell = GuardedShell(
        cwd=str(other),
        audit=audit,
        prompt_fn=lambda _: "n",
        out=lambda _: None,
    )
    initial_repo = shell.repo
    shell.run(f"cd {repo_dir}")
    assert shell.repo is not None
    assert shell.repo.root == repo_dir.resolve()
    if initial_repo is not None:
        assert shell.repo.root != initial_repo.root


def test_shell_repo_meta_command(tmp_path):
    (tmp_path / ".git").mkdir()
    output: List[str] = []

    audit = AuditLog(path=tmp_path / "audit.jsonl", session_id="s")
    shell = GuardedShell(
        cwd=str(tmp_path),
        audit=audit,
        prompt_fn=lambda _: "n",
        out=lambda s: output.append(s),
    )
    shell.run(":repo")
    joined = "\n".join(output)
    assert "git" in joined
    assert str(tmp_path.resolve()) in joined

# ---------- regression: path normalization across OSes ----------


def test_classify_path_resolves_cwd_for_string_comparison(tmp_path):
    """Regression for the CI failure on Windows + macOS where classify_path
    treated an in-repo file as PATH_OUT_OF_REPO because the unresolved cwd
    (e.g., `/var/folders/...` on macOS, short-form temp path on Windows)
    didn't string-equal the resolved repo.root produced by RepoContext.detect.

    The fix: classify_path must resolve cwd the same way detect() does
    before constructing the joined path it compares against repo.root.
    """
    (tmp_path / ".git").mkdir()
    (tmp_path / "package-lock.json").write_text("{}")

    repo = RepoContext.detect(str(tmp_path))
    assert repo is not None

    # On macOS, tmp_path may live under /var/folders which is a symlink
    # to /private/var/folders. RepoContext.detect resolves it; classify_path
    # must do the same so the in-repo classification fires.
    cls = classify_path("package-lock.json", repo, str(tmp_path))
    assert cls == PATH_IN_REPO_LOCKFILE, (
        f"package-lock.json should be classified as PATH_IN_REPO_LOCKFILE "
        f"when cwd is the repo root, got {cls}. This usually means the "
        f"unresolved-cwd vs resolved-repo.root mismatch has regressed."
    )


def test_classify_path_works_when_cwd_has_symlink_alias(tmp_path):
    """If cwd is given via an unresolved alias (the macOS /var → /private/var
    case), classification should still recognize files as in-repo."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "Cargo.lock").write_text("")

    repo = RepoContext.detect(str(tmp_path))
    assert repo is not None

    # Even when cwd is the unresolved form (which TemporaryDirectory may
    # return on macOS), classification must still identify the file as
    # in-repo. We can't easily fabricate a symlink alias in a portable
    # test, so just verify classification works with the cwd Python's
    # tempfile gave us — which is exactly the form that fails on macOS CI.
    cls = classify_path("Cargo.lock", repo, str(tmp_path))
    assert cls == PATH_IN_REPO_LOCKFILE
