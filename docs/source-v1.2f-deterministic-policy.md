# SecureScan Source V1.2F deterministic policy

Status: `COMPLETE - FROZEN`
Parent: `11baeb30ceb5de70d70686ac25adf692240d5c0e`
Branch: `source/v1.2F-deterministic-policy`

## Authority and scope

Policy definitions are trusted control-plane state scoped to a project lineage.
The built-in version 1 policy is available without a database seed. An operator
can create immutable version 2 and later definitions through the trusted-host
API using an expected-version check. A candidate run cannot choose a policy or
baseline; the service loads the latest trusted definition and latest trusted
baseline in one PostgreSQL `REPEATABLE READ` transaction. Repository content,
scanner output, SARIF, guidance, AI, and free-form scanner text are not policy
definition sources.

Policy does not promote a baseline or change S4, finding identity, lifecycle,
priority, governance, suppression, or Security Delta. Existing scan-only CLI
exit behavior is unchanged. V1.2F adds no CLI enforcement command; explicit
policy evaluation is available through the API. No guidance is implemented.

## Typed policy schema

Schema ID: `securescan-source-policy-v1`. Extra fields are rejected. The
definition has a nonempty sorted set of required authorities from `checkov`,
`gitleaks`, `osv.dev`, and `semgrep-ce`; complete `INTRODUCED`, `PRESENT`, and
`REOPENED` action maps for `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, and
`UNRANKED`; one boolean for introduced secret enforcement; and booleans for
effective false-positive, accepted-risk, and suppression exclusions. Actions
are `ALLOW`, `WARN`, or `FAIL`. There is no arbitrary expression language.

The built-in default requires all four authorities. `INTRODUCED` and
`REOPENED` CRITICAL/HIGH fail, MEDIUM warns, and lower bands allow. `PRESENT`
allows every priority by explicit configuration. Introduced Gitleaks secret
exposure fails independent of priority. All three effective governance forms
may exclude a proven failure. `REMOVED` has no ordinary failure rule.

`policy_id` is a deterministic UUID derived from lineage identity. Version 1
is built in; operator revisions are immutable rows with monotonically
increasing versions. `policy_digest` is SHA-256 over compact, key-sorted,
ASCII JSON of the validated typed definition. Authority ordering is
canonicalized, so whitespace and input order do not change semantic identity.

## Evaluation contract

Each evaluation produces exactly `PASS`, `FAIL`, or `ERROR` and sorted,
structured decisions. `PASS` means all required authority comparisons were
complete and no active failure rule was violated. `FAIL` means at least one
proven rule violation. `ERROR` takes precedence when required evidence cannot
be safely determined, including an absent trusted baseline, incomplete
required coverage, scanner failure, gaps, `NOT_COMPARABLE`, or unavailable
trusted facts. An unrelated authority outside the trusted policy's required
set does not by itself create an error.

Violation/warning rule IDs are `INTRODUCED_<priority>`,
`PRESENT_<priority>`, `REOPENED_<priority>`, and `SECRET_INTRODUCED`.
Exclusion reason codes are `EXCLUDED_EFFECTIVE_FALSE_POSITIVE`,
`EXCLUDED_EFFECTIVE_ACCEPTED_RISK`, and `EXCLUDED_EFFECTIVE_SUPPRESSION`.
Error reason codes are `BASELINE_UNAVAILABLE`, `REQUIRED_FACTS_UNAVAILABLE`,
`REQUIRED_AUTHORITY_MISSING`, `REQUIRED_AUTHORITY_NOT_COMPARABLE`,
`REQUIRED_COVERAGE_INCOMPLETE`, and `REQUIRED_FINDING_NOT_COMPARABLE`.
Source delta reason codes remain attached to error decisions.

Effective governance affects enforcement only. The evaluation retains the
original delta state and candidate finding metadata in its decisions. Expired,
revoked, or pre-reopen dormant governance cannot exclude a violation. The
candidate lifecycle state is read from that candidate run's verified lifecycle
event, even when the current aggregate lifecycle state has advanced. Governance
effectiveness is read at the one evaluation timestamp, so a risk that expired
after the candidate run but before evaluation is ineffective.

## Consistency and persistence

The policy service owns one UTC `evaluated_at` and one PostgreSQL
`REPEATABLE READ` transaction. It loads trusted policy, current promotion,
candidate and baseline reports through the existing Security Delta calculation,
candidate occurrences and verified run lifecycle events, and required-finding
EffectiveGovernance through bounded 200-ID queries in that transaction. The
same transaction inserts an immutable evaluation record with exact
`baseline_id`, revision, candidate run, policy identity/version/digest, result,
decisions, and evaluation time. Content-addressed S4 artifacts are verified
against snapshot-bound persisted digests and canonical JSON.

Migration `f8c2d6e1a305`, based on V1.2E `e7a1b3c5d902`, adds only
`source_policy_definitions` and `source_policy_evaluations`. It changes no
frozen tables. The built-in default requires no seed; both tables start empty
on upgrade. The API exposes historical evaluations read-only after insertion.
Repeated evaluation may create a distinct evaluation ID. The semantic result
is identical for the same baseline, candidate facts, policy digest, governance
state, and `evaluated_at`.

## API and CLI

The trusted-host API adds:

```text
GET  /v1/projects/{project_id}/lineages/{lineage_id}/policy
PUT  /v1/projects/{project_id}/lineages/{lineage_id}/policy
POST /v1/projects/{project_id}/lineages/{lineage_id}/runs/{candidate_run_id}/policy-evaluations
GET  /v1/projects/{project_id}/lineages/{lineage_id}/policy-evaluations/{evaluation_id}
```

The PUT body contains only `expected_version` and the typed definition.
Candidate evaluation requests carry no policy or baseline selector. Existing
scan-only CLI exit codes and SARIF output are unchanged. For future explicit
CLI enforcement, the result contract maps `PASS` to success, `FAIL` to a
policy failure exit, and `ERROR` to operational inability; V1.2H owns that UX.

## Validation evidence

The bounded V1.2F acceptance matrix selected 988 unique cases. It produced
984 passes, four classified opt-in real-Syft replay skips, and zero failures.
This consists of 864 non-PostgreSQL cases (841 passes, 19 PostgreSQL-only
skips, four opt-in Syft skips), all 19 skipped S6A PostgreSQL cases rerun and
passed against the isolated database, 67 PostgreSQL B–F migration/concurrency
cases passed, and 57 additional API/navigation/operator CLI cases passed. The
single new 401-finding bulk bound test was added after the long non-PostgreSQL
run and passed separately. The matrix covers Product Core, lifecycle,
governance, suppression, baseline/delta, dependency semantics, S4/S6D,
scanner-native identity/parsers, API, CLI, SARIF, and the existing Web UI.

PostgreSQL 16 races prove one exact policy version/digest, baseline ID/revision,
and governance/suppression view under concurrent updates. Simultaneous policy
definition revisions have exactly one winner; stale expected versions conflict.
No-baseline evaluation persists `ERROR` without promotion. The additive
migration passes round trip, V1.1/B/C/D/E upgrade tests, and `alembic check`.

The actual-state gate streamed a read-only dump from the preserved V1.1
PostgreSQL deployment into a separate disposable tmpfs container. It upgraded
from `f7c2d4e8a901` through `f8c2d6e1a305`. Before and after, the copy had
two projects, four analysis runs, and 450 lifecycle rows; canonical row-content
digests for all three sets matched the source. Both new policy tables began
empty, and Alembic reported no metadata drift. The preserved deployment was
not modified or stopped.

An unrestricted root-level `pytest -q` run is not the freeze matrix: historical
Gitleaks maturity/acquisition tests assert the repository is on the old
`source/v0.3-semgrep` branch and fail by design on this V1.2F branch (four
failures and six fixture errors before that diagnostic run was interrupted).
These branch-bound benchmark evidence tests were not changed or counted as
V1.2F regressions. The only warning in the passing acceptance matrix was the
pre-existing Starlette/httpx test-client deprecation warning.
