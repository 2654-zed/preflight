# Preflight — Claude Code plugin

Capability-aware risk scoring for Claude Code. This plugin ships:

- **A PreToolUse hook** matching `Bash | Read | Write | Edit | MultiEdit | NotebookEdit | Grep | Glob | WebFetch`. Every matched tool call is scored by Preflight before it runs.
- **An MCP server** (`preflight_score_command`, `preflight_attest_action`, `preflight_session_state`) so you can ask Preflight questions about any action mid-session.
- **Five slash commands** for inspecting state and dry-scoring actions:
  - `/preflight-audit` — recent decisions from the audit log
  - `/preflight-session` — current session capabilities and ledger
  - `/preflight-score <cmd>` — score a command without running it
  - `/preflight-profile [list|show|diff]` — inspect policy profiles
  - `/preflight-attest <tool> <args>` — ask Preflight if a proposed action would be allowed

## Prerequisite

The `preflight` CLI must be on your `PATH`. Install from the project root:

```
pip install -e /path/to/preflight
preflight --version    # should print 0.1.0
```

## Install the plugin

Plugins can be installed locally by path:

```
claude plugin install /path/to/preflight/integrations/claude-code-plugin
```

Or install from this repo's marketplace:

```
claude plugin marketplace add /path/to/preflight/integrations/claude-code-plugin
claude plugin install preflight
```

Then restart Claude Code. Verify with:

```
/plugin list
```

You should see `preflight` enabled.

## What you'll see

When the plugin is active, every matching tool call is scored by Preflight first.

- LOW / ELEVATED → silent. The tool runs.
- WARN / HIGH → Claude Code shows a permission prompt with Preflight's decomposition embedded as the reason. You approve / decline.
- CRITICAL → tool is denied outright. The model sees the rejection reason and adapts.

The five-dimensional decomposition (Position / Permissions / Trust Bindings / Mutability / Observation) is the centerpiece — when Preflight pushes back, you see *which dimension* is responsible and *which composition rule* fired. No black-box "this looks bad."

## Configuration

Set environment variables in your shell profile (or in `~/.claude/settings.json` env block):

| Variable | Values | Default | Effect |
|---|---|---|---|
| `PREFLIGHT_SOURCE` | `user_request` / `model_generated` / `untrusted_content` | `model_generated` | Trust baseline. Use `untrusted_content` when working on a repo you don't own. |
| `PREFLIGHT_PROFILE` | `solo_developer` / `open_source_maintainer` / `enterprise` / `regulated` | (none) | Policy preset that shifts confirm/block thresholds and adds rules. |

Run `/preflight-profile show enterprise` to see what each preset contains, or `/preflight-profile diff solo_developer regulated` to see what changes between the most permissive and strictest options.

## Session state

Preflight persists session capabilities to `~/.preflight/sessions/<claude_session_id>.json` so risk composes across Claude Code's many separate tool calls in one conversation. A grep for `API_KEY` followed five tool calls later by a `WebFetch` is correctly recognized as staged exfiltration and hard-stopped.

The `/preflight-session` command shows the current session's accumulated capabilities and recent ledger.

To clear all session state:

```
rm -rf ~/.preflight/sessions/
```

## Audit log

Every decision is appended as JSONL to `~/.preflight/audit.jsonl`. Each line carries the full decomposition, triggers, composition reasons, exit code, duration, session id, and sequence number. Tail it during a session to watch decisions stream in:

```
tail -f ~/.preflight/audit.jsonl | jq -c '{seq, decision, score: .stored_potential_score, cmd: .command}'
```

Or use `/preflight-audit` for a summarized view inside Claude Code.

## Limitations

- **Strong-phrase confirmation isn't available** in Claude Code's permission UX — HIGH and MEDIUM map to `ask` (a single y/n), and CRITICAL maps to `deny`. The standalone `preflight shell` supports the strong-phrase flow.
- **MCP and other custom tools** outside the matched tool list fall through with no Preflight decision. Add coverage by extending `synthesize_command()` in `preflight/integrations/claude_code.py`.

## Uninstall

```
claude plugin uninstall preflight
```

This removes the hook and the MCP server registration. Audit log and session state remain on disk; delete `~/.preflight/` if you want a clean wipe.

## Source

The plugin's hook and MCP server are thin wrappers around Preflight's CLI:

- Hook handler: [`preflight/integrations/claude_code.py`](../../preflight/integrations/claude_code.py)
- MCP server: [`preflight/integrations/mcp_server.py`](../../preflight/integrations/mcp_server.py)
- Five-dim scorer: [`preflight/scorer.py`](../../preflight/scorer.py)
- Session graph: [`preflight/session.py`](../../preflight/session.py)
- Repo awareness: [`preflight/repo.py`](../../preflight/repo.py)
- Policy profiles: [`preflight/policy.py`](../../preflight/policy.py)
