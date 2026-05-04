---
description: Ask Preflight to attest a proposed action before running it (mirrors the hook flow)
argument-hint: <tool name> <args as JSON>
---

The user wants you to ask Preflight whether a proposed action would be allowed *before* you take it. This is a dry-run of the same logic Preflight applies in the PreToolUse hook.

Parse `$ARGUMENTS`:
- First word is the Claude Code tool name (e.g., `Bash`, `Read`, `Write`, `Edit`, `Grep`, `WebFetch`).
- Remainder is a JSON object describing the tool input.

Then call the Preflight MCP server's `preflight_attest_action` tool with `{tool_name, tool_input, session_id}` (use the current Claude Code session_id from the conversation context, or `default` if unknown).

Present the response:
- `permissionDecision` (allow / ask / deny)
- `permissionDecisionReason` (the full decomposition)

If decision is `deny`, also state what the user would need to do to make it safe — e.g., remove the network call, restrict the path, drop the credential read.

Do NOT execute the tool itself. This is purely an attestation.
