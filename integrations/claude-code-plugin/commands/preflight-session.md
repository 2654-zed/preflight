---
description: Show the current Preflight session graph (capabilities accumulated, recent ledger)
---

List `~/.preflight/sessions/` and read the most recently modified `*.json` file (this is the active session). Parse its JSON and present:

1. **Capabilities** (from `capabilities`): the set of risky things this session has already exercised. Common values:
   - `observed_credential` — read a sensitive path (SSH key, .env, etc.)
   - `observed_env_secret` — ran `env` / `printenv`
   - `observed_secret_grep` — recursive grep for credential terms
   - `network_egress_external` — outbound network call to external host
   - `package_installed` — npm/pip/cargo install
   - `mutation_external_state` — git push, terraform apply, kubectl apply
   - `mutation_persistence` — wrote to ~/.bashrc / launchd / systemd
   - `modified_lockfile`, `modified_ci_config`, `modified_build_script` — repo-level mutations

2. **Ledger** (from `ledger`, last 10): each entry has `seq`, `command`, `score`, `tier`, `decision`, `outcome`, `capabilities_added`. Render compactly. Mark entries that *added* capabilities so the user sees the staging happen.

3. **Compositional risk warning** — if the session has both `observed_credential` (or `observed_env_secret`, `observed_secret_grep`) AND `network_egress_external`, surface a clear warning that Preflight will hard-stop any further egress because the session has already staged exfiltration material.

If the sessions directory is empty, say so. Don't speculate about state that isn't on disk.
