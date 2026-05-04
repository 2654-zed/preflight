# Preflight × Claude Code

This is the Preflight adapter for [Claude Code](https://claude.com/claude-code). When configured as a `PreToolUse` hook, Preflight intercepts every Claude Code tool call (Bash, Read, Write, Edit, Grep, WebFetch, ...), scores it across the five-dimensional risk model, and emits a permission decision before the tool runs.

What this gives you on top of Claude Code's built-in permission prompts:

- **Stored-potential scoring** — every action is decomposed across Position, Permissions, Trust Bindings, Mutability, Observation. You see *why* something is risky, not just that it asked.
- **Session-graph composition** — risk accumulates across tool calls. A `Grep "API_KEY"` followed by a `WebFetch` becomes CRITICAL even though either alone is benign.
- **Repo awareness** — Preflight detects your repo root and treats lockfile / CI-config / `.git/` writes as supply-chain attack surfaces.
- **Hard-stops on credential exfiltration** — patterns like SSH-key read piped to `curl` are non-overridable.
- **JSONL audit log** — every decision (allowed, blocked, asked) is appended to `~/.preflight/audit.jsonl` with the full risk decomposition.

## Install

```bash
pip install -e /path/to/Preflight
```

Verify the CLI is on PATH:

```bash
preflight --version
```

## Wire up the hook

Open `~/.claude/settings.json` (or `.claude/settings.json` for project-local) and merge in the contents of [settings.example.json](./settings.example.json):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|Grep|Glob|WebFetch",
        "hooks": [
          {
            "type": "command",
            "command": "preflight hook"
          }
        ]
      }
    ]
  }
}
```

Restart Claude Code. From now on, every matched tool call is scored before execution.

## What you'll see

When Preflight scores a tool call as ALLOW, nothing visible — Claude Code proceeds normally.

When Preflight scores it as WARN or HIGH, Claude Code shows you a permission prompt with Preflight's reason embedded:

```
Preflight: 70/100 — HIGH
  position=1/5 permissions=4/5 trust=2/5 mutability=5/5 observation=0/5
  • Mutates production-tier external state.

Allow this command? [y/n]
```

When Preflight scores it as CRITICAL, the tool call is denied outright with the same decomposition shown:

```
Preflight: 97/100 — CRITICAL
  position=5/5 permissions=4/5 trust=2/5 mutability=0/5 observation=5/5
  • Sensitive observation composed with external network transmission.
  • Action reaches outside the project boundary.
  • Touches a credential-bearing path.
```

## Configuration

Configure via environment variables (set in your shell profile or in `~/.claude/settings.json` env block):

| Variable | Values | Default | Effect |
|---|---|---|---|
| `PREFLIGHT_SOURCE` | `user_request` / `model_generated` / `untrusted_content` | `model_generated` | The trust baseline for scoring. Set to `untrusted_content` if you're operating on a repo you don't own. |
| `PREFLIGHT_PROFILE` | `solo_developer` / `open_source_maintainer` / `enterprise` / `regulated` | (none) | Shifts confirm/block thresholds. `enterprise` and `regulated` are stricter. |

## Session state

Preflight persists session capabilities to `~/.preflight/sessions/<claude_session_id>.json`. The Claude Code session_id is the key, so two simultaneous Claude Code conversations stay isolated. Sessions accumulate within one conversation; restarting Claude Code starts a fresh state.

If you want to reset a session manually:

```bash
rm -rf ~/.preflight/sessions/
```

## Audit log

`~/.preflight/audit.jsonl` is append-only JSONL. Each line is one hook decision with full decomposition, timestamp, session_id, working directory, exit code, and the triggers / composition reasons. Tail it during a session to watch decisions stream in:

```bash
tail -f ~/.preflight/audit.jsonl | jq -c '{seq, decision, score: .stored_potential_score, cmd: .command}'
```

## Limitations of the v0.6 integration

- **Strong-phrase confirmation isn't available.** Preflight's standalone shell asks the user to type a semantic phrase (e.g., `transmit credential to external domain`) for HIGH-tier actions. Claude Code's permission UX is just `y/n`. HIGH and MEDIUM map to `ask`; the user gates the action with a single keystroke. CRITICAL still maps to `deny`.

- **MCP tools and other custom tools.** The synthesizer covers the built-in Claude Code tools (Bash, Read, Write, Edit, MultiEdit, NotebookEdit, Grep, Glob, WebFetch). Unknown tools fall through with no decision — Claude Code's default permission flow applies. To add coverage for an MCP tool, edit [`preflight/integrations/claude_code.py`](../../preflight/integrations/claude_code.py) `synthesize_command()`.

- **Source context inference.** Preflight defaults every Claude Code tool call to `model_generated`. It can't tell from the hook payload alone whether the model was just nudged by a malicious README it read. The session graph still catches *staged* exfiltration (read + later network call), but the trust baseline for a single command is fixed unless you set `PREFLIGHT_SOURCE`.

## Uninstall

Remove the hook block from `~/.claude/settings.json` and restart Claude Code. Preflight's audit log and session state remain on disk; delete `~/.preflight/` if you want a clean wipe.
