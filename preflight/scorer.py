from __future__ import annotations

import os
import re
from typing import List, Optional, Tuple

from . import authority as A
from . import control_plane as CP
from . import detectors as D
from .models import (
    NormalizedCommand,
    RiskDimensions,
    RiskTier,
    ScoredCommand,
    Segment,
    SourceContext,
    Decision,
)
from .normalizer import normalize
from . import repo as R
from .repo import (
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
)


READ_VERBS = {"cat", "less", "more", "head", "tail", "view", "type"}
SEARCH_VERBS = {"grep", "rg", "ag", "find", "locate", "fd"}
LIST_VERBS = {"ls", "dir", "stat", "file", "tree"}
WRITE_REDIRECTS = {">", ">>"}
EDIT_VERBS = {"sed", "awk", "perl", "tr"}
DESTRUCTIVE_FS_VERBS = {"rm", "rmdir", "shred", "unlink"}
GIT_VERB = "git"
INTERPRETER_VERBS = {"bash", "sh", "zsh", "fish", "dash", "ksh",
                     "python", "python3", "python2",
                     "node", "deno", "bun",
                     "ruby", "perl", "lua", "php"}
SOURCE_VERBS = {"source", "."}


def _expand_path(p: str) -> str:
    return p.replace("\\", "/")


_PATH_TAKING_VERBS = (
    READ_VERBS | SEARCH_VERBS | LIST_VERBS | EDIT_VERBS | DESTRUCTIVE_FS_VERBS
    | {"find", "cd", "tree", "touch", "cp", "mv", "ln", "chmod", "chown",
       "tar", "zip", "unzip"}
)


def _extract_paths(seg: Segment) -> List[str]:
    paths: List[str] = []
    tokens = seg.tokens
    if not tokens:
        return paths
    verb_takes_paths = tokens[0] in _PATH_TAKING_VERBS
    skip_next = False
    for i, t in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue
        if i == 0:
            continue
        if t in WRITE_REDIRECTS or t in {"<", "2>", "2>&1", "&>", "|"}:
            skip_next = t in WRITE_REDIRECTS or t == "<"
            continue
        if t.startswith("-") and len(t) > 1 and not t.startswith("/"):
            continue
        if re.match(r"^[a-z][a-z0-9+\-.]*://", t):
            continue
        if "/" in t or t.startswith(".") or t.startswith("~") or t.startswith("$HOME"):
            paths.append(t)
        elif verb_takes_paths:
            # Arguments to path-taking verbs (cat, head, rm, sed, grep, find,
            # ls, ...) are paths even when they don't contain a slash. Catches
            # `cat CLAUDE.md`, `rm token.txt`, `sed -i 's/x/y/' file`.
            paths.append(t)
    return paths


def _write_targets(seg: Segment) -> List[str]:
    targets: List[str] = []
    for i, t in enumerate(seg.tokens):
        if t in WRITE_REDIRECTS and i + 1 < len(seg.tokens):
            targets.append(seg.tokens[i + 1])
    # In-place edit verbs (sed -i, perl -i, awk -i inplace) write to their
    # positional file args, after the script.
    if seg.tokens and seg.tokens[0] in EDIT_VERBS and any(
        t == "-i" or t.startswith("-i") for t in seg.tokens
    ):
        positionals = [t for t in seg.tokens[1:] if not t.startswith("-")]
        if len(positionals) >= 2:
            targets.extend(positionals[1:])
    return targets


def _score_position(
    seg: Segment,
    raw: str,
    repo: Optional[RepoContext] = None,
    cwd: Optional[str] = None,
) -> Tuple[int, List[str]]:
    triggers: List[str] = []
    paths = _extract_paths(seg) + _write_targets(seg)
    if not paths:
        return 1, triggers

    write_targets = set(_write_targets(seg))
    cwd_str = cwd or os.getcwd()
    score = 1

    has_sensitive = False
    has_out_of_repo = False

    for p in paths:
        is_write = p in write_targets
        cls = R.classify_path(p, repo, cwd_str)
        is_sensitive = D.is_sensitive_path(p)
        is_repo_oor = cls == PATH_OUT_OF_REPO
        is_legacy_boundary = D.crosses_boundary(p)

        if is_sensitive:
            has_sensitive = True
            triggers.append(f"sensitive_path:{p}")

        if is_repo_oor or is_legacy_boundary:
            has_out_of_repo = True
            triggers.append(f"boundary_crossed:{p}")
            if is_repo_oor:
                triggers.append(f"out_of_repo:{p}")

        if cls == PATH_IN_REPO_DOTGIT:
            triggers.append(f"dotgit_access:{p}")
            if is_write:
                triggers.append(f"dotgit_write:{p}")
            score = max(score, 4 if is_write else 3)
        elif cls == PATH_IN_REPO_LOCKFILE:
            if is_write:
                triggers.append(f"lockfile_write:{p}")
                score = max(score, 3)
            else:
                triggers.append(f"lockfile_path:{p}")
        elif cls == PATH_IN_REPO_CI_CONFIG:
            if is_write:
                triggers.append(f"ci_config_write:{p}")
                score = max(score, 3)
            else:
                triggers.append(f"ci_config_path:{p}")
        elif cls == PATH_IN_REPO_BUILD_SCRIPT and is_write:
            triggers.append(f"build_script_write:{p}")
            score = max(score, 2)
        elif cls == PATH_IN_REPO_MANIFEST and is_write:
            triggers.append(f"manifest_write:{p}")
            score = max(score, 2)
        elif cls == PATH_UNKNOWN:
            ep = _expand_path(p)
            if ep.startswith("/") and not ep.startswith("/tmp"):
                score = max(score, 3)
            elif "../" in ep or ep == "..":
                score = max(score, 4)
                triggers.append(f"parent_traversal:{p}")

    if has_sensitive and has_out_of_repo:
        score = 5
    elif has_sensitive:
        score = max(score, 4)
    elif has_out_of_repo:
        score = max(score, 4)

    # Agent control plane files — files that shape future agent behavior.
    # These are high-position even when they sit at the project root, because
    # the *kind* of authority they carry (persistent agent instruction) is
    # categorically distinct from ordinary docs.
    for p in paths:
        if CP.is_control_plane_path(p):
            score = max(score, 4)
            triggers.append(f"agent_control_plane_path:{p}")

    return score, triggers


def _score_permissions(seg: Segment, raw: str) -> Tuple[int, List[str]]:
    triggers: List[str] = []
    if not seg.tokens:
        return 0, triggers
    verb = seg.tokens[0]

    score = 0

    if D.is_sudo(seg.tokens):
        triggers.append("sudo")
        score = max(score, 5)

    if verb in READ_VERBS or verb in SEARCH_VERBS or verb in LIST_VERBS:
        score = max(score, 1)
    if verb in EDIT_VERBS:
        score = max(score, 3)
        if "-i" in seg.tokens:
            triggers.append("in_place_edit")
    if verb in DESTRUCTIVE_FS_VERBS:
        score = max(score, 4)
        triggers.append(f"destructive_fs:{verb}")
    if D.has_destructive(raw):
        score = max(score, 4)
        triggers.append("destructive_pattern")
    if _write_targets(seg):
        score = max(score, 2)
    if D.has_network_call(seg.tokens, raw):
        score = max(score, 4)
        triggers.append(f"network:{verb}")
    if D.has_remote_url(seg.tokens) and verb in {"curl", "wget", "scp", "rsync"}:
        score = max(score, 4)
    if D.has_package_install(raw):
        score = max(score, 4)
        triggers.append("package_install")
    if D.has_package_publish(raw):
        score = max(score, 5)
        triggers.append("package_publish")
    if D.has_external_state_mutation(raw):
        score = max(score, 4)
        triggers.append("external_state_mutation")
    if D.is_db_verb(seg.tokens):
        score = max(score, 4)
        triggers.append(f"db_client:{verb}")
    if verb == "chmod" or verb == "chown":
        score = max(score, 3)
    if verb in {"bash", "sh", "zsh", "fish", "python", "python3", "node"} and len(seg.tokens) > 1:
        score = max(score, 3)
        triggers.append(f"interpreter:{verb}")

    if score == 0:
        score = 1
    return score, triggers


_TRUST_BASELINE = {
    SourceContext.SYSTEM_POLICY: 0,
    SourceContext.USER_REQUEST: 0,
    SourceContext.DEVELOPER_POLICY: 1,
    SourceContext.AGENT_CONTROL_PLANE: 2,
    SourceContext.MODEL_GENERATED: 2,
    SourceContext.REPO_CONTENT: 4,
    SourceContext.LOG_CONTENT: 4,
    SourceContext.ISSUE_CONTENT: 4,
    SourceContext.UNTRUSTED_CONTENT: 4,
    SourceContext.EXTERNAL_WEBPAGE: 5,
    SourceContext.UNKNOWN: 4,
}


def _score_trust_bindings(
    seg: Segment, raw: str, source: SourceContext
) -> Tuple[int, List[str]]:
    triggers: List[str] = []
    base = _TRUST_BASELINE.get(source, 4)
    score = base
    triggers.append(f"source:{source.value}")

    if D.has_pipe_to_shell(raw):
        score = max(score, 4)
        triggers.append("pipe_to_shell")
    if D.has_package_install(raw):
        score = max(score, max(3, base))
        triggers.append("untrusted_lifecycle")
    if D.references_credential_keyword(raw) and not (
        seg.tokens and seg.tokens[0] in {"export", "set", "unset"}
    ):
        score = max(score, 3)

    # Agent control plane files carry an extra layer of trust: agents treat
    # them as privileged guidance even though they are just files. Touching
    # one bumps trust regardless of the source baseline.
    paths = _extract_paths(seg) + _write_targets(seg)
    if any(CP.is_control_plane_path(p) for p in paths):
        score = max(score, 4)

    return min(score, 5), triggers


def _score_mutability(seg: Segment, raw: str) -> Tuple[int, List[str]]:
    triggers: List[str] = []
    if not seg.tokens:
        return 0, triggers
    verb = seg.tokens[0]
    score = 0

    if verb in READ_VERBS or verb in SEARCH_VERBS or verb in LIST_VERBS:
        score = 0
    if _write_targets(seg):
        targets = _write_targets(seg)
        score = max(score, 1)
        for t in targets:
            if D.is_persistence_path(t):
                score = max(score, 5)
                triggers.append(f"persistence_write:{t}")
            elif D.crosses_boundary(t) or D.is_sensitive_path(t):
                score = max(score, 4)
                triggers.append(f"external_write:{t}")
            else:
                score = max(score, 2)
    if verb in EDIT_VERBS and "-i" in seg.tokens:
        score = max(score, 2)
    if verb in DESTRUCTIVE_FS_VERBS:
        score = max(score, 3)
    if D.has_destructive(raw):
        score = max(score, 4)
    if re.search(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b", raw, re.IGNORECASE):
        score = max(score, 4)
        for t in seg.tokens[1:]:
            if t in {".", "/", "~", "/*", "~/"} or t.startswith("../") or t == "..":
                score = 5
                triggers.append(f"rm_rf_broad:{t}")
                break
    if D.has_external_state_mutation(raw):
        score = max(score, 5)
        triggers.append("mutates_external_state")
    if D.has_package_publish(raw):
        score = 5
        triggers.append("package_publish")
    if verb == GIT_VERB and len(seg.tokens) > 1:
        sub = seg.tokens[1]
        if sub in {"add", "stage"}:
            score = max(score, 1)
        elif sub == "commit":
            score = max(score, 2)
        elif sub == "push":
            score = max(score, 5)
            triggers.append("git_push")
        elif sub in {"reset", "clean", "rebase"} and "--hard" in seg.tokens:
            score = max(score, 4)
        elif sub == "checkout" and "--" in seg.tokens:
            score = max(score, 3)
    if D.has_package_install(raw):
        score = max(score, 3)

    # Agent control plane mutations are persistent across future sessions —
    # any write to one of these files is mutation=5, and explicit deletion
    # is treated the same way.
    for t in _write_targets(seg):
        if CP.is_control_plane_path(t):
            score = max(score, 5)
            triggers.append(f"agent_control_plane_modified:{t}")
    if verb in DESTRUCTIVE_FS_VERBS:
        for t in seg.tokens[1:]:
            if not t.startswith("-") and CP.is_control_plane_path(t):
                score = max(score, 5)
                triggers.append(f"agent_control_plane_deleted:{t}")
    if verb in EDIT_VERBS and "-i" in seg.tokens:
        for t in seg.tokens[1:]:
            if not t.startswith("-") and CP.is_control_plane_path(t):
                score = max(score, 5)
                triggers.append(f"agent_control_plane_modified:{t}")

    return min(score, 5), triggers


def _curl_or_wget_output_target(seg: Segment) -> List[str]:
    """Detect explicit output flags for network verbs: `curl -o file`, `curl --output file`, `wget -O file`."""
    targets: List[str] = []
    tokens = seg.tokens
    if not tokens or tokens[0] not in ("curl", "wget"):
        return targets
    flags = ("-o", "--output") if tokens[0] == "curl" else ("-O", "--output-document")
    for i, t in enumerate(tokens[:-1]):
        if t in flags:
            targets.append(tokens[i + 1])
    return targets


def _executed_script_paths(seg: Segment) -> List[str]:
    """Detect when the segment runs a local script (./foo, bash foo, source foo, ...).

    Returns the script path(s) that would be executed. Empty list when the
    verb takes a `-c` flag (running inline code, no script path).
    """
    paths: List[str] = []
    tokens = seg.tokens
    if not tokens:
        return paths
    verb = tokens[0]

    # Direct execution: `./script.sh`, `/path/to/bin`
    if verb.startswith("./") or verb.startswith("/"):
        paths.append(verb)
        return paths

    # Interpreter dispatch: `bash foo`, `python foo.py`. Skip if -c is present
    # (running inline code instead of a file).
    if verb in INTERPRETER_VERBS:
        if any(t == "-c" or t == "--command" for t in tokens):
            return paths
        for t in tokens[1:]:
            if t.startswith("-"):
                continue
            paths.append(t)
            break  # first positional after the interpreter is the script
        return paths

    # `source foo` / `. foo`
    if verb in SOURCE_VERBS and len(tokens) >= 2:
        for t in tokens[1:]:
            if not t.startswith("-"):
                paths.append(t)
                break

    return paths


def _emit_dataflow_triggers(seg: Segment, raw: str, segment_triggers: List[str]) -> List[str]:
    """Emit triggers that capture the data-flow shape of a single segment:

      downloads_to_path:<p>          a network verb is writing fetched data to disk
      writes_buffered_sensitive:<p>  sensitive observation paired with a write target
      executes_local_script:<p>      running a script/binary path

    These power the v1.1 cross-command session compositions (download
    here, execute later; observe sensitive data here, exfiltrate later).
    """
    triggers: List[str] = []
    if not seg.tokens:
        return triggers

    write_targets = list(_write_targets(seg)) + _curl_or_wget_output_target(seg)

    is_network = D.has_network_call(seg.tokens, raw) or seg.tokens[0] in ("curl", "wget")
    if is_network and write_targets:
        for t in write_targets:
            triggers.append(f"downloads_to_path:{t}")

    sensitive_observation_in_segment = any(
        st.startswith("reads_sensitive_path") or st == "env_dump" or st == "recursive_secret_search"
        for st in segment_triggers
    )
    if sensitive_observation_in_segment and write_targets:
        for t in write_targets:
            triggers.append(f"writes_buffered_sensitive:{t}")

    # Agent control plane content scanning. When the segment writes to a
    # control plane file, scan the raw command text for instructions that
    # would shift agent behavior in a high-risk direction (auto-execution,
    # secret references, production references, destructive workflows).
    cp_writes = [t for t in write_targets if CP.is_control_plane_path(t)]
    if cp_writes:
        for ct in CP.scan_content(raw):
            triggers.append(ct)

    # Confused-deputy priming: reading instruction-bearing files (README,
    # CONTRIBUTING, *.log, issue bodies) doesn't itself grant capability,
    # but it marks the session — any later privileged action becomes
    # suspicious because the agent may have been instructed by what it just
    # read. Only count READS, not writes (writing your own README is fine).
    is_read = bool(seg.tokens) and (
        seg.tokens[0] in READ_VERBS or seg.tokens[0] in SEARCH_VERBS
    )
    if is_read:
        for p in _extract_paths(seg):
            if A.is_instruction_bearing(p):
                triggers.append(f"consumed_instruction_content:{p}")

    for p in _executed_script_paths(seg):
        triggers.append(f"executes_local_script:{p}")

    return triggers


def _score_observation(seg: Segment, raw: str) -> Tuple[int, List[str]]:
    triggers: List[str] = []
    if not seg.tokens:
        return 0, triggers
    verb = seg.tokens[0]
    paths = _extract_paths(seg)
    score = 0

    if verb in READ_VERBS or verb in {"strings", "xxd", "hexdump", "od"}:
        score = max(score, 1)
    if verb in LIST_VERBS:
        score = max(score, 1)
    if verb in SEARCH_VERBS:
        score = max(score, 2)
        if D.has_recursive_search_for_secrets(seg.tokens, raw):
            score = max(score, 4)
            triggers.append("recursive_secret_search")
    if D.env_dump(seg.tokens):
        score = max(score, 4)
        triggers.append("env_dump")
    if any(D.is_sensitive_path(p) for p in paths):
        score = 5
        triggers.append("reads_sensitive_path")
    if any(D.crosses_boundary(p) and verb in READ_VERBS for p in paths):
        score = max(score, 3)
    return min(score, 5), triggers


def _aggregate(dims_list: List[RiskDimensions]) -> RiskDimensions:
    if not dims_list:
        return RiskDimensions()
    return RiskDimensions(
        position=max(d.position for d in dims_list),
        permissions=max(d.permissions for d in dims_list),
        trust_bindings=max(d.trust_bindings for d in dims_list),
        mutability=max(d.mutability for d in dims_list),
        observation=max(d.observation for d in dims_list),
    )


def _has_sensitive_observation(triggers: List[str]) -> bool:
    return any(
        t.startswith("reads_sensitive_path")
        or t.startswith("env_dump")
        or t.startswith("recursive_secret_search")
        for t in triggers
    )


def _has_external_network(segments: List[Segment]) -> bool:
    for seg in segments:
        if D.has_network_call(seg.tokens, seg.raw) and D.has_remote_url(seg.tokens):
            return True
        if seg.tokens and seg.tokens[0] in D.NETWORK_VERBS and len(seg.tokens) > 1:
            for t in seg.tokens[1:]:
                if not t.startswith("-") and re.search(r"\.[a-z]{2,}", t):
                    return True
    return False


def _composition_bonuses(
    norm: NormalizedCommand, all_triggers: List[str], source: SourceContext = SourceContext.MODEL_GENERATED
) -> Tuple[int, int, List[str]]:
    """Returns (bonus_points, critical_floor, reasons)."""
    bonus = 0
    floor = 0
    reasons: List[str] = []

    sensitive_obs = _has_sensitive_observation(all_triggers)
    external_net = _has_external_network(norm.segments)
    if external_net:
        all_triggers.append("network_external")
    pipe_to_shell = D.has_pipe_to_shell(norm.raw)
    has_persistence = any(t.startswith("persistence_write") for t in all_triggers)
    has_external_state = any(t == "mutates_external_state" for t in all_triggers)
    has_package_publish = any(t == "package_publish" for t in all_triggers)
    has_package_install = any(t == "package_install" for t in all_triggers)
    has_destructive = any(
        t.startswith("destructive_fs") or t == "destructive_pattern" for t in all_triggers
    )
    rm_rf_broad = any(t.startswith("rm_rf_broad") for t in all_triggers)
    boundary = any(t.startswith("boundary_crossed") for t in all_triggers)
    sensitive_path = any(t.startswith("sensitive_path") for t in all_triggers)
    production = D.hits_production(norm.raw)

    # Agent control plane composition (Preflight Doctrine — Control Plane Files):
    # writing to CLAUDE.md / AGENTS.md / .cursor/rules/ is itself notable;
    # if the proposed contents introduce execution paths, secret references,
    # production references, or destructive workflows, the action becomes
    # CRITICAL because it persistently shifts how every future agent in this
    # repo behaves.
    cp_modified = any(t.startswith("agent_control_plane_modified") for t in all_triggers)
    cp_deleted = any(t.startswith("agent_control_plane_deleted") for t in all_triggers)
    cp_path = any(t.startswith("agent_control_plane_path") for t in all_triggers)
    cp_exec_added = "agent_instruction_exec_path_added" in all_triggers
    cp_secret_ref = "agent_instruction_secret_reference" in all_triggers
    cp_prod_ref = "agent_instruction_production_reference" in all_triggers
    cp_destructive = "agent_instruction_destructive_workflow" in all_triggers

    if sensitive_obs and external_net:
        floor = max(floor, 97)
        reasons.append("Sensitive observation composed with external network transmission.")
    if any(t == "env_dump" for t in all_triggers) and external_net:
        floor = max(floor, 95)
        reasons.append("Environment dump composed with external network transmission.")
    if pipe_to_shell:
        floor = max(floor, 92)
        reasons.append("Untrusted output piped directly into a shell or interpreter.")
    if rm_rf_broad:
        floor = max(floor, 90)
        reasons.append("Recursive deletion targeting a broad path (`.`, `/`, `~`, `..`).")
    if has_persistence:
        bonus += 12
        reasons.append("Persistent shell or system configuration is being modified.")
        if re.search(r"\b(curl|wget|eval|bash|sh|python|nc)\b", norm.raw, re.IGNORECASE) or "$(" in norm.raw or "`" in norm.raw:
            floor = max(floor, 90)
            reasons.append("Persistence write embeds shell or network commands — installs a backdoor.")
    if has_external_state and production:
        bonus += 22
        reasons.append("Mutates production-tier external state.")
    elif has_external_state:
        bonus += 15
        reasons.append("Mutates external persistent state.")
    if has_destructive and production and has_external_state:
        floor = max(floor, 88)
        reasons.append("Destructive operation targeting production-tier infrastructure.")
    if has_package_publish:
        floor = max(floor, 85)
        reasons.append("Publishes a package to a public registry.")
    if has_package_install:
        bonus += 6
        reasons.append("Package installation may execute third-party lifecycle scripts.")
    if has_destructive and not rm_rf_broad:
        bonus += 8
        reasons.append("Destructive command pattern detected.")
    if boundary:
        bonus += 5
        reasons.append("Action reaches outside the project boundary.")
    if sensitive_path:
        bonus += 10
        reasons.append("Touches a credential-bearing path.")
    if any(t == "recursive_secret_search" for t in all_triggers):
        bonus += 8
        reasons.append("Recursive search keyed on secret-like terms.")

    # ---- Agent control plane bonuses & floors ----
    if cp_modified:
        bonus += 12
        reasons.append(
            "Modifies an agent control plane file — persistent change to future agent behavior."
        )
    if cp_deleted:
        bonus += 12
        reasons.append(
            "Deletes an agent control plane file — removes persistent agent guidance."
        )
    if cp_modified and cp_exec_added:
        floor = max(floor, 75)
        reasons.append(
            "Agent instruction file is being given a future execution path."
        )
    if cp_modified and cp_secret_ref:
        floor = max(floor, 92)
        reasons.append(
            "Agent instruction file is being made to reference secrets or credentials."
        )
    if cp_modified and cp_prod_ref:
        floor = max(floor, 92)
        reasons.append(
            "Agent instruction file is being made to reference production resources."
        )
    if cp_modified and cp_destructive:
        floor = max(floor, 95)
        reasons.append(
            "Agent instruction file is being made to encode a destructive workflow."
        )

    has_lockfile_write = any(t.startswith("lockfile_write") for t in all_triggers)
    has_ci_config_write = any(t.startswith("ci_config_write") for t in all_triggers)
    has_dotgit_write = any(t.startswith("dotgit_write") for t in all_triggers)
    if has_lockfile_write and has_external_state:
        floor = max(floor, 90)
        reasons.append("Lockfile modified and now being published — supply-chain mutation.")
    elif has_lockfile_write:
        bonus += 6
        reasons.append("Lockfile modification — supply-chain attack surface.")
    if has_ci_config_write and has_external_state:
        floor = max(floor, 88)
        reasons.append("CI configuration modified and now being pushed — remote pipeline mutation.")
    elif has_ci_config_write:
        bonus += 8
        reasons.append("CI configuration modification — remote execution surface.")
    if has_dotgit_write:
        floor = max(floor, 85)
        reasons.append("Direct write into .git/ — repository internals are not meant to be hand-edited.")
    if any(t == "pipe_to_shell" for t in all_triggers):
        bonus += 0  # already covered by floor

    # ---- Confused-deputy composition (Preflight Doctrine: Authority Confusion) ----
    # If the action is privileged and the source proposing it has too little
    # authority to authorize a privileged action on its own (repo content,
    # log content, issue content, external webpages, untrusted content, or
    # unknown), this is the language-mediated confused deputy pattern:
    # untrusted text is using the agent's delegated authority to act.
    if A.is_low_authority(source) and A.is_privileged_action(all_triggers):
        floor = max(floor, 88)
        all_triggers.append("confused_deputy:privileged_action_from_low_authority")
        reasons.append(
            f"Privileged action proposed by {A.authority_label(source)} — "
            f"untrusted content cannot authorize delegated authority."
        )

    return bonus, floor, reasons


def _tier(score: int) -> RiskTier:
    if score <= 20:
        return RiskTier.LOW
    if score <= 40:
        return RiskTier.ELEVATED
    if score <= 60:
        return RiskTier.MEDIUM
    if score <= 80:
        return RiskTier.HIGH
    return RiskTier.CRITICAL


def _decision(tier: RiskTier, all_triggers: List[str], floor: int) -> Decision:
    if tier == RiskTier.CRITICAL:
        if floor >= 95:
            return Decision.HARD_STOP
        return Decision.HARD_STOP
    if tier == RiskTier.HIGH:
        return Decision.CONFIRM_REQUIRED
    if tier == RiskTier.MEDIUM:
        return Decision.WARN
    if tier == RiskTier.ELEVATED:
        return Decision.ALLOW_AND_LOG
    return Decision.ALLOW


def score_command(
    raw: str,
    source: SourceContext = SourceContext.MODEL_GENERATED,
    repo: Optional[RepoContext] = None,
    cwd: Optional[str] = None,
) -> ScoredCommand:
    norm = normalize(raw)

    per_seg_dims: List[RiskDimensions] = []
    triggers: List[str] = []
    for seg in norm.segments:
        pos, t1 = _score_position(seg, seg.raw, repo=repo, cwd=cwd)
        perm, t2 = _score_permissions(seg, seg.raw)
        trust, t3 = _score_trust_bindings(seg, seg.raw, source)
        mut, t4 = _score_mutability(seg, seg.raw)
        obs, t5 = _score_observation(seg, seg.raw)
        seg_triggers = t1 + t2 + t3 + t4 + t5
        seg_triggers += _emit_dataflow_triggers(seg, seg.raw, seg_triggers)
        per_seg_dims.append(RiskDimensions(pos, perm, trust, mut, obs))
        triggers.extend(seg_triggers)

    dims = _aggregate(per_seg_dims)
    base = dims.sum() * 4
    bonus, floor, reasons = _composition_bonuses(norm, triggers, source=source)
    score = min(100, max(base + bonus, floor))

    tier = _tier(score)
    decision = _decision(tier, triggers, floor)

    explanation: List[str] = []
    if dims.position >= 4:
        explanation.append(f"Position: {dims.position}/5 — reaches sensitive or out-of-project terrain.")
    if dims.permissions >= 4:
        explanation.append(f"Permissions: {dims.permissions}/5 — exercises high authority (write/network/destroy).")
    if dims.trust_bindings >= 3:
        explanation.append(
            f"Trust: {dims.trust_bindings}/5 — significant unverified trust extended to the action source."
        )
    if dims.mutability >= 4:
        explanation.append(f"Mutability: {dims.mutability}/5 — mutates state that is hard or impossible to reverse.")
    if dims.observation >= 4:
        explanation.append(f"Observation: {dims.observation}/5 — exposes sensitive or credential-bearing data.")

    if not explanation:
        explanation.append("No high-risk dimensions detected.")

    return ScoredCommand(
        command=raw,
        source=source,
        normalized=norm,
        dimensions=dims,
        stored_potential=score,
        risk_tier=tier,
        decision=decision,
        reasons=reasons,
        triggers=sorted(set(triggers)),
        explanation=explanation,
    )
