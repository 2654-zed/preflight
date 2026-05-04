---
description: Show or compare Preflight policy profiles
argument-hint: [show <name> | diff <a> <b> | list]
---

Inspect Preflight's policy profiles. Pick the action from `$ARGUMENTS`:

- `list` (or no args) → run `preflight profile list` and present the four built-in profiles with their one-line descriptions.

- `show <name>` → run `preflight profile show <name>` and present the full ruleset: confirm/block thresholds, command_allowlist, command_blocklist, network_allowlist. Note that profile choice is set per-session via the `PREFLIGHT_PROFILE` env var.

- `diff <a> <b>` → run `preflight profile diff <a> <b>` and present the additions / removals between the two profiles. Useful for change-management when comparing your team's stance against a stricter baseline.

Valid profile names: `solo_developer`, `open_source_maintainer`, `enterprise`, `regulated`.
