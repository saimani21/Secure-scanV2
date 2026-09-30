# SecureScan Source V1.2C suppression and expiry

Status: `COMPLETE - FROZEN`

## Baseline and boundary

V1.2C starts at frozen V1.2B commit
`2c7503edff17515df24c1b472c45432953088217` on branch
`source/v1.2C-suppression-expiry`. It adds one temporary, auditable suppression
control for one exact governed finding.

Suppression remains separate from analyst disposition, lifecycle, scanner-native
suppression, policy, and evidence. A suppressed finding continues to exist. It
is not made `RESOLVED`, removed from S4, hidden from reports, excluded from
counts, or changed in scanner truth.

## Identity and episodes

Suppression attaches only to the frozen Product Core identity:

```text
(lineage_id, canonical S4 finding_id)
```

Project ownership is derived and validated through the lineage, and the exact
lifecycle row must exist. Suppression does not attach to a run, project plus
finding ID, rule, CWE, path, scanner, or fuzzy identity.

Each activation episode has a stable UUID `suppression_id`. Updating the reason
or expiry of an active episode retains that ID. Creating a suppression after
expiry or revocation creates a new ID while continuing the finding-level
revision sequence. No global or multi-finding suppression exists.

## State and expiry

Every suppression requires:

- a nonblank reason of at most 1000 characters;
- an explicit timezone-aware future expiry, normalized to UTC;
- a nonnegative expected revision.

There is no permanent suppression. Active state is never persisted and is
derived for each read:

```text
active = revoked_at is null and expires_at > evaluation_time
```

At the exact expiry instant the suppression is inactive. This requires no
scheduler, background mutation, or audit event. Explicit early revocation sets
`revoked_at`, increments revision, and appends an event; it never deletes state
or history. Revoking an absent, expired, or already revoked suppression is a
state conflict.

## Persistence and migration

Migration `c4e8a1f6b203`, based on V1.2B head `a2b7c4d9e105`, adds only:

- `source_finding_suppressions`, the current episode keyed by
  `(lineage_id, finding_id)`;
- `source_finding_suppression_events`, immutable revision-ordered audit events.

The current table stores the episode ID, reason, expiry, optional revocation,
revision, fixed actor type `LOCAL_OPERATOR`, and timestamps. The event table
stores `CREATE`, `UPDATE`, or `REVOKE`, previous/resulting material, episode ID,
actor, timestamp, and resulting revision. Database constraints enforce bounded
material, temporal ordering, actor identity, and revision integrity. The
existing governance and lifecycle tables are unchanged.

## Atomic revision and concurrency contract

No-row state is inactive at revision 0. Every successful mutation requires the
exact current revision, increments it once, changes current state, and appends
one audit event in the same transaction. Event failure rolls back state.

Mutations lock the lineage before locking current suppression state. This
serializes simultaneous first writes even when no suppression row exists. For
two writers using the same revision, exactly one commits and the other receives
a deterministic conflict. This applies to active updates, new episodes after
expiry, and revoke-versus-update races. Lifecycle `transition_version` and V1.2B
governance revision remain independent.

## Trusted-host API

The API adds only:

```text
GET  /v1/projects/{project_id}/lineages/{lineage_id}/findings/{finding_id}/suppression
PUT  /v1/projects/{project_id}/lineages/{lineage_id}/findings/{finding_id}/suppression
POST /v1/projects/{project_id}/lineages/{lineage_id}/findings/{finding_id}/suppression/revoke
GET  /v1/projects/{project_id}/lineages/{lineage_id}/findings/{finding_id}/suppression/events
```

The read response exposes derived `active`; no corresponding database column
exists. Event reads are ordered and bounded to 1-200 rows. Stable errors
distinguish missing or cross-scope targets, revision conflicts, inactive-state
conflicts, invalid material, and persistence unavailability. Analyst reason
text remains untrusted data.

## Validation and freeze evidence

The unique non-PostgreSQL regression surface passed 447 tests:

- 225 Product Core, lifecycle, public API, CLI, SARIF, V1.2B governance, and
  V1.2C suppression tests;
- 157 S4 and Semgrep, Gitleaks, OSV, and Checkov identity/parser tests;
- 65 frozen Web UI tests with one dependency deprecation warning.

The mandatory PostgreSQL 16 selection passed 11 tests with no failures or
skips. It proves fresh migration downgrade/upgrade, upgrades from V1.1 and
V1.2B, simultaneous first suppression, simultaneous active update, one new
episode after expiry, revoke-versus-update, stale revoke, new activation after
revocation, exact project/lineage isolation, V1.2B governance concurrency, and
existing lifecycle concurrency.

A separate actual-state gate streamed a read-only dump from the preserved V1.1
database into a tmpfs-backed disposable database. Its 2 projects, 4 analysis
runs, and 450 lifecycle rows survived. The copy was upgraded to V1.2B and given
one valid governance decision/event, then upgraded from `a2b7c4d9e105` to
`c4e8a1f6b203`. The governance row count, event count, and canonical material
digest remained identical; both suppression tables began empty. `alembic check`
reported no new upgrade operations. The preserved deployment was only read and
was never migrated, reset, stopped, or mutated.

Together the executed test suites contain 458 unique passing tests. Ruff,
byte-compilation, SQLite migration-to-head, Alembic metadata comparison, and
diff hygiene also passed.

## Explicit non-goals

V1.2C does not decide whether a finding is actionable, excluded from policy, or
removed from any count. It does not implement lifecycle-aware effectiveness,
`REOPENED` inheritance, baselines, Security Delta, policy, remediation,
guidance, intelligence, AI, OAuth, RBAC, UI, CLI, SARIF projection, scanner
configuration, global suppression, or background expiry processing.

The exact next phase is **V1.2D Effective Governance + Inheritance**. It has not
started.
