# SecureScan Source v1.5.1

Status: COMPLETE - FROZEN

V1.5.1 is a bounded operator-bootstrap usability hotfix over immutable
`source-v1.5.0`. It changes no scanner, finding, lifecycle, governance,
baseline, delta, intelligence, policy, CI, AI, or database semantics.

## Corrections

- `system configure` now identifies its output as SecureScan application JSON
  and explicitly says not to source it.
- Fresh configured profiles receive the independently packaged frozen V1.5
  Enry helper digest when the controlled input does not provide or resolve an
  explicit trusted digest. The runtime file never establishes its own trust.
- `doctor` reports missing identity, missing path, unreadable path, untrusted
  permissions/type, digest mismatch, and unstable verification distinctly.
- `system config [--json]` provides a read-only, credential-free inventory of
  the selected profile, deployment, storage, and scanner trust state.
- Fresh operator image builds include the already-declared migration, Compose,
  documentation, and example inputs before Python package installation instead
  of depending on a previously cached image layer.
- Managed API image tags are derived from the validated Compose project name,
  so an isolated project cannot move the legacy `securescan-core:d1` tag used
  by preserved deployments.

The profile remains the backward-compatible V1 JSON format. Export
`SECURESCAN_OPERATOR_PROFILE` to select it; never source it.

## Release evidence

- 3,704 distinct tests collect on the V1.5.1 branch. The 62 historical
  benchmark nodes remain intentionally branch-bound to their frozen
  `source/v0.3-semgrep` and Gitleaks checkpoints. The 3,642-node
  release-relevant selection exits with no failure under the frozen Enry
  identity; opt-in external-environment nodes remain skips in that aggregate
  run and retain their frozen V1.5 evidence.
- The directly impacted operator, profile, scanner identity, CLI, API, UI,
  runtime-storage, and V1.5 product partition passes 252 tests.
- A fresh disposable profile omitted the Enry digest, was never sourced, and
  reached `doctor READY`. A fresh Docker image build, PostgreSQL migration,
  API/UI readiness, managed worker, and real three-finding scan passed on
  isolated ports and storage. Only its exact disposable resources were
  removed; preserved deployments remained running.
- Fresh sdist and wheel builds pass. A clean wheel installation from `/tmp`
  loads only site-packages, configures and reloads a fresh profile, reports all
  scanner identities `VALID`, reaches `doctor READY`, initializes storage, and
  serves installed API and Web assets.
- Ruff lint and changed-file format checks, Python byte compilation,
  `git diff --check`, redacted staged-diff Gitleaks, and the single Alembic head
  `1a5c7e9d2b04` pass. V1.5.1 adds no migration.
