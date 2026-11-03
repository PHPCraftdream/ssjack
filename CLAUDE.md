# Project priorities

- Deliver universal secret placeholder hydration through ssjack, usable by Nix and Clawwright through external adapters. Isolated helpers are not end-to-end readiness.
- Never expose secret values to model context, logs, argv, environment or plaintext staging files. Preserve the agreed cryptographic profiles and authorization boundaries.

# Verification cadence

- Ordinary feature pushes and pull requests use automatic diff-based test selection. Do not add commit-message markers to choose individual test suites.
- At sprint completion, put `[ci:full]` in the pushed HEAD commit message to request the full gate instead of scoped checks. GitHub's `contains` comparison is case-insensitive; use this lowercase spelling consistently. Do not include the token incidentally in ordinary commit messages.
- Manual full verification remains available through Actions -> Full sprint CI -> Run workflow, or `gh workflow run ci.yml --ref <branch> -f source_ref=<commit-sha>`.
- A branch name alone does not request full verification. A pull request uses scoped checks; the commit token is evaluated for push events.
- Release still requires the full gate. Scoped CI success does not establish full readiness.
- Run tests, builds, lint and typechecks in public GitHub CI, not locally. Formatting is allowed. Watch each launched CI run with background `gh run watch <run-id> --exit-status` and consume its result.
