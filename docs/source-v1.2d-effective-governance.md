# SecureScan Source V1.2D effective governance and inheritance

Status: `COMPLETE - FROZEN`

## Baseline and boundary

V1.2D starts at frozen V1.2C commit
`fe09fd754e51462d10bc8f24b07ac62d0b68a8a2` on branch
`source/v1.2D-effective-governance`. It adds a read-time projection that answers
which exact finding-specific analyst decisions are effective at one trusted
evaluation time.

The projection does not mutate scanner evidence, S4, finding identity,
lifecycle, priority, analyst disposition, suppression, SARIF, CLI, or UI state.
It does not decide policy or whether a finding is actionable.

## Additive lifecycle anchor migration

The pre-D schema could order events within lifecycle, governance, and
suppression independently, but could not durably order governance or
suppression against a `REOPENED` boundary. Lifecycle event timestamps are scan
publication times rather than cross-feature commit ordinals, so timestamp
comparison and equality rules were insufficient.

Migration `d6f9b2c7a104`, based on V1.2C head `c4e8a1f6b203`, adds only nullable
`lifecycle_transition_version` columns to:

- `source_finding_governance_events`;
- `source_finding_suppression_events`.

New B/C mutations capture the exact lifecycle row's current
`transition_version` while holding the existing lineage lock. Legacy event
anchors remain `NULL`; migration never guesses or timestamp-backfills them.
Current governance and suppression rows, lifecycle tables, and all prior audit
material are unchanged.

## Current lifecycle episode

The current episode boundary is derived from immutable lifecycle history:

```text
no REOPENED event     -> transition version 1
one or more REOPENED  -> greatest REOPENED transition version
```

A current governance or suppression decision belongs to that episode when its
matching current-revision event has a non-null lifecycle transition version at
or after the boundary. Before any reopen, a legacy `NULL` anchor remains
eligible because only the first lifecycle episode exists. After any reopen, a
legacy `NULL` anchor is conservatively historical and dormant.

Random UUIDs and timestamps are never used to infer cross-feature ordering.

## Lifecycle inheritance matrix

| Current lifecycle | Governance and suppression behavior |
|---|---|
| `NEW` | Current first-episode decisions may be effective. |
| `EXISTING` | Decisions from the current active episode remain eligible; ordinary repeated observation requires no reaffirmation. |
| `RESOLVED` | False positive, accepted risk, and suppression are all dormant without changing stored state or history. |
| `REOPENED` | Decisions before the latest reopen are dormant. Otherwise-valid historical exclusion sets `review_required`; a new audited decision is required. |

After a reopened finding later becomes `EXISTING`, pre-reopen decisions remain
dormant because episode membership still uses the latest reopen boundary. The
narrow `review_required` flag is emitted only while the current lifecycle state
is `REOPENED`; it is not a general workflow status.

## Reaffirmation

The V1.2B mutation path already records same-value changes, so reaffirming
`FALSE_POSITIVE` or `ACCEPTED_RISK` increments governance revision, appends an
event anchored to the current lifecycle version, and makes the decision
eligible again if its other conditions hold.

V1.2C suppression receives the minimum integration adjustment: when the latest
suppression event predates the current episode or has an unknown legacy anchor,
`PUT` creates a new suppression episode and `suppression_id`, even if the old
episode remains temporally unexpired. Active updates within the same lifecycle
episode retain their ID.

## EffectiveGovernance projection

The read model exposes:

```text
lineage_id
finding_id
lifecycle_state
current_episode_transition_version

disposition
disposition_revision
governance_lifecycle_transition_version
false_positive_effective
accepted_risk_effective
accepted_risk_expires_at
governance_last_changed_at

suppression_present
suppression_effective
suppression_id
suppression_revision
suppression_lifecycle_transition_version
suppression_expires_at
suppression_revoked_at
suppression_last_changed_at

review_required
reason_codes
evaluated_at
```

There is deliberately no `actionable`, CI pass/fail, policy-excluded, or
priority field.

False positive is effective only for an active lifecycle in the current
episode. Accepted risk additionally requires `evaluated_at < expires_at`.
Suppression additionally requires no revocation and
`evaluated_at < expires_at`. Exactly at expiry, the temporal control is
inactive. Time passage never writes a row or event.

## Reason codes

The closed deterministic set is:

```text
ACCEPTED_RISK_EFFECTIVE
ACCEPTED_RISK_EXPIRED
FALSE_POSITIVE_EFFECTIVE
FINDING_RESOLVED
NO_GOVERNANCE
PRE_REOPEN_GOVERNANCE_DORMANT
PRE_REOPEN_SUPPRESSION_DORMANT
REOPENED_REVIEW_REQUIRED
SUPPRESSION_EFFECTIVE
SUPPRESSION_EXPIRED
SUPPRESSION_REVOKED
```

Responses order codes lexically and do not generate free-form explanations.

## Consistency model

Each projection obtains one timezone-aware UTC `evaluated_at` and uses it for
all temporal decisions. Target ownership, lifecycle state, latest reopen,
current governance plus matching audit event, and current suppression plus
matching audit event are read through one SQL statement.

On PostgreSQL's configured default `READ COMMITTED` isolation, this provides
one statement-level transaction snapshot: the projection observes a complete
state before or after a committed lifecycle/governance/suppression transaction,
not a mixture assembled by separate reads. It does not claim serializable
ordering across separate API calls or transactions.

Missing current-revision audit events, invalid lifecycle versions, impossible
expiry material, or anchors later than current lifecycle fail closed as
persistence unavailability.

## Public API

The only new route is:

```text
GET /v1/projects/{project_id}/lineages/{lineage_id}/findings/{finding_id}/effective-governance
```

It validates exact project/lineage/finding ownership, performs one read-only
projection, and returns stable 404, 422, or 503 errors. It creates no governance,
suppression, or lifecycle row or event.

## Validation and PostgreSQL evidence

The unique non-PostgreSQL regression surface passed 460 tests:

- 238 Product Core, lifecycle, API, CLI, SARIF, V1.2B, V1.2C, and V1.2D tests;
- 157 S4 and Semgrep, Gitleaks, OSV, and Checkov identity/parser tests;
- 65 frozen Web UI tests with one dependency deprecation warning.

The mandatory PostgreSQL 16 selection passed 18 tests with no failures or
skips. It covers migration round-trip and V1.1/B/C upgrades, B/C concurrency,
equal-timestamp reopen ordering, legacy `NULL` anchors, same-value reaffirmation,
new suppression episode after reopen, lifecycle/governance and
lifecycle/suppression races, concurrent effective reads, revocation, identity
isolation, and existing lifecycle concurrency.

The actual-state gate streamed a read-only V1.1 dump into a tmpfs-backed
disposable database. Its 2 projects, 4 analysis runs, and 450 lifecycle rows
survived upgrade through V1.2C and D. One legacy governance decision/event and
one legacy suppression episode/event retained identical counts and canonical
material digests. Their new anchors remained `NULL`. New post-D governance and
suppression events then recorded anchors equal to the current lifecycle
transition version. `alembic check` reported no drift. The preserved deployment
was never migrated, reset, stopped, or mutated.

Together the executed suites contain 478 unique passing tests. Ruff,
byte-compilation, SQLite migration-to-head, Alembic metadata comparison, and
diff hygiene also passed.

## Known limitations and non-goals

This is a per-finding trusted-host read API, not a bulk policy engine. Legacy
decisions with unknown anchors become conservatively dormant after a reopen and
require explicit reaffirmation. The projection does not implement baseline,
Security Delta, policy, CI decisions, guidance, remediation, intelligence,
authentication, RBAC, multi-tenancy, global/rule/path suppression, or automated
analyst decisions.

The exact next phase is **V1.2E Trusted Baseline + Security Delta**. It has not
started.
