---
description: Show the most recent Preflight risk decisions from the audit log
---

Read the last 20 entries from `~/.preflight/audit.jsonl` (one JSON record per line) and present them as a readable table.

For each entry, show:

- `seq` (sequence number within the session)
- `stored_potential_score` / 100
- `risk_tier` (low / elevated / medium / high / critical)
- `outcome` (allowed / allowed_logged / asked / blocked / declined / phrase_mismatch / overridden)
- `command` (truncated to 80 chars)
- top 1–2 entries from `reasons` if present

Highlight any `blocked` or `asked` rows so the user sees what Preflight pushed back on. End with a one-line summary of how many of each outcome appeared in the tail.

If `~/.preflight/audit.jsonl` does not exist or is empty, say so explicitly and recommend running `preflight shell` or wiring the Claude Code hook.
