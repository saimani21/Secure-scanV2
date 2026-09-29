# SecureScan Source V1.2B governance core and audit

Status: `COMPLETE - FROZEN`

## Baseline and boundary

V1.2B starts at frozen V1.2A commit
`3cf60c60c3bd365d96b3f5c6d74936a7c91b5469` on branch
`source/v1.2B-governance-core`. It implements the first mutable local-analyst
governance capability without changing scanner evidence, S4 identity, Product
Core lifecycle, priority, dependency semantics, SARIF, existing CLI behavior,
or Web UI behavior.

The previous shorthand name "Analyst Disposition" is refined to
"Governance Core + Audit + Basic Concurrency." This is additive and does not
alter the frozen V1.2A identity or lifecycle contract.

## Identity and existence

Governance is keyed only by:

```text
(lineage_id, canonical S4 finding_id)
```

`project_id` is not identity. Each operation loads the lineage, validates its
project ownership, and requires the exact `source_finding_lifecycles` row. An
arbitrary 64-character digest, a finding from another lineage, and a lineage
from another project are rejected. No registry, fingerprint, fuzzy match,
cross-tool merge, or run-specific governance identity was added.

## Disposition semantics

The only dispositions are:

- `UNREVIEWED`: default/no-row state. After a prior mutation, clearing retains
  an `UNREVIEWED` current row so its revision cannot reset.
- `FALSE_POSITIVE`: requires a nonblank analyst reason of at most 1000
  characters and never carries expiry.
- `ACCEPTED_RISK`: requires the same bounded reason and an explicit,
  timezone-aware future `expires_at` normalized to UTC.

Expiry is data, not an `active` Boolean. There is no scheduler, automatic
mutation, policy effect, global hiding, or suppression. Analyst text is stored
and returned as untrusted data; no scanner material is copied into it.

`FALSE_POSITIVE` and `ACCEPTED_RISK` do not mean `RESOLVED`. Clearing governance
does not change evidence or lifecycle.

## Schema and migration

Migration `a2b7c4d9e105`, based on frozen V1.1 head `f7c2d4e8a901`, adds only:

### `source_finding_governance`

Primary key `(lineage_id, finding_id)` and composite foreign key to
`source_finding_lifecycles`. It stores disposition, bounded reason, optional
accepted-risk expiry, positive revision, fixed actor type `LOCAL_OPERATOR`, and
creation/update timestamps. Database checks enforce disposition material,
reason length, revision, actor, and timestamp order.

No default rows are created by migration or read. The first mutation creates
one row at revision 1.

### `source_finding_governance_events`

Primary key `event_id`; composite foreign key to the governed lifecycle; unique
`(lineage_id, finding_id, resulting_revision)`. Each event stores `SET` or
`CLEAR`, complete previous/new disposition, reason and expiry material,
`LOCAL_OPERATOR`, occurrence time, and resulting revision. Events are appended
by the service and never updated by the application.

No existing table or column is redesigned.

## Atomic audit and revision contract

The first no-row state has revision 0. Every successful mutation requires
`expected_revision`, increments revision exactly once, updates/inserts current
state, and appends exactly one event in one database transaction. Event failure
rolls back the current-state change. A stale revision raises deterministic
conflict; it never silently overwrites state or creates an event.

The mutation first takes a PostgreSQL row lock on the lineage, then validates
the lifecycle and locks current governance when present. Locking the lineage
also serializes two first writes when no governance row exists: one may create
revision 1 and the other must observe a stale expected revision. Lifecycle
`transition_version` is not reused.

Exact duplicate requests with their original expected revision receive the
same stable conflict after the first commit. V1.2B intentionally adds no
distributed idempotency subsystem.

## Public API

The trusted-host API adds:

```text
GET /v1/projects/{project_id}/lineages/{lineage_id}/findings/{finding_id}/governance
PUT /v1/projects/{project_id}/lineages/{lineage_id}/findings/{finding_id}/governance
GET /v1/projects/{project_id}/lineages/{lineage_id}/findings/{finding_id}/governance/events
```

`PUT` accepts only `disposition`, conditional `reason`, conditional
`expires_at`, and required nonnegative `expected_revision`. The response is the
current deterministic state. Event history is revision-ordered and bounded to
1-200 rows per request. Stable application errors distinguish 404 unknown/scope
failure, 409 revision conflict, 422 invalid governance, and 503 persistence
unavailability. FastAPI UUID and lowercase SHA-256 path validation rejects
malformed identifiers before service execution.

The actor is honestly `LOCAL_OPERATOR`; no user, email, OAuth, organization,
team, role, or multi-tenant identity is fabricated.

## Rescan boundary

Persistence uses the exact lifecycle key, so future exact observations can see
the same history. V1.2B does not implement final effective inheritance. In
particular, a prior exclusionary disposition is not automatically reactivated
on `REOPENED`; V1.2D owns that rule.

## Validation completed here

- focused governance service/API: 14 passed;
- Product Core, lifecycle, public API, CLI, SARIF, and governance regressions:
  206 passed;
- S4, Semgrep, Gitleaks, OSV, and Checkov identity regressions: 157 passed;
- existing Web UI regressions: 65 passed with one dependency deprecation
  warning;
- Ruff and compile validation passed for changed Python/migration files;
- fresh disposable SQLite migration reached `a2b7c4d9e105` with both tables;
- a disposable SQLite database first migrated to frozen V1.1 head, populated
  with existing project data, copied, then upgraded to `a2b7c4d9e105`; the old
  row remained readable.

These executed non-PostgreSQL runs total 428 unique passing tests.

## PostgreSQL freeze evidence

A dedicated PostgreSQL 16 container with tmpfs-backed storage and two databases
whose names ended in `_test` was used for the mandatory freeze gate. The
preserved V1.1 deployment remained running and was never migrated, reset, or
otherwise mutated.

The complete PostgreSQL selection passed 5 tests with no failures or skips:

```bash
cd ~/projects/securescan-core-step1
source .venv/bin/activate

export SECURESCAN_TEST_POSTGRES_URL='postgresql+psycopg://USER:PASSWORD@127.0.0.1:PORT/securescan_v12b_test'
export SECURESCAN_REQUIRE_POSTGRES_TESTS=1

pytest -o addopts='' -q \
  tests/test_postgres_migrations.py \
  tests/test_postgres_source_governance_v12b.py \
  tests/test_postgres_source_product_core_pc2.py
```

The selection proves fresh migration round-trip, a seeded V1.1-head upgrade,
two concurrent first writes converging to one success and one revision
conflict, two concurrent writes from the same existing revision converging the
same way, exact cross-project isolation, atomic current-state/event counts, and
continued lifecycle-evaluator convergence.

The separate actual-state gate copied the running V1.1 database with a
read-only `pg_dump` and restored it only into the disposable V1.2B database.
Before upgrade the copy was at `f7c2d4e8a901` with 2 projects, 4 analysis runs,
and 450 lifecycle rows. After `alembic upgrade head` it was at
`a2b7c4d9e105` with all three counts unchanged and both new governance tables
empty. `alembic check` reported no new upgrade operations. No credential was
printed or retained in this evidence.

Together with the 428 non-PostgreSQL regressions, the freeze evidence totals
433 unique passing tests. V1.2B is complete and frozen.

## Explicit non-goals and limitations

No suppression, path/rule ignore, baseline, Security Delta, policy,
fail-on-findings, remediation, guidance, KEV, EPSS, SSVC, intelligence, AI,
remote Git, OAuth, RBAC, UI redesign, governance CLI, fuzzy identity, merging,
or automatic editing is implemented. This remains a trusted-host,
single-local-operator API. Effective expiry and reopen inheritance remain later
phases.

The exact next phase is **V1.2C Suppression + Expiry**. It has not started.
