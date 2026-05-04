---
description: Score a shell command through Preflight without running it
argument-hint: <command to score>
---

Run `preflight score "$ARGUMENTS" --json` and parse the JSON output. Present:

- The command itself
- Stored Potential score (X / 100) and risk tier in CAPS
- Five-dimensional decomposition (Position, Permissions, Trust Bindings, Mutability, Observation), each 0–5
- Composition signals (the `reasons` array) — these are the most informative items, surface them prominently
- Decision (ALLOW / ALLOW_AND_LOG / WARN / CONFIRM_REQUIRED / HARD_STOP)

If decision is HARD_STOP or CONFIRM_REQUIRED, end with a one-line note about what would need to change for this command to be safer (e.g., "scope the path to inside the repo" or "drop the network call"). Don't run the command — this is a dry-score.
