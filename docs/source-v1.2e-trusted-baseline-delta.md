# SecureScan Source V1.2E trusted baseline and Security Delta

Status: `COMPLETE - FROZEN`

## Baseline and boundary

V1.2E starts at frozen V1.2D commit
`6f4e4b2fbb258b79ee46d7224fbede86aa244e89` on branch
`source/v1.2E-trusted-baseline-delta`. It adds an explicit trusted-operator
baseline and a read-only candidate-versus-baseline Security Delta.

The trusted baseline is control-plane state. Repository contents, scan input,
scanner output, SARIF, CI input, and repository policy cannot select or promote
it. Promotion is never automatic. A baseline is accepted comparison evidence,
not a claim that its findings are clean or approved.

V1.2E does not alter scanner behavior, S4, canonical finding identity,
lifecycle, priority, governance, suppression, dependency semantics, SARIF, CLI
exit behavior, or the existing Web UI. It implements no policy or enforcement.

## Arbitrary-run comparability audit

The opening audit found the existing frozen persistence sufficient; no
pre-feature persistence correction was required.

- `source_lineage_runs.sequence_number` is the authoritative per-lineage order.
  It proves equal, later, and earlier relationships without UUID, timestamp, or
  lexical ordering.
- Run IDs and lineage membership are immutable. Product Core occurrences retain
  the canonical, run-independent S4 `finding_id` plus authority, category, and
  native identity schema.
- Historical S4 is reconstructed from the persisted planning snapshot,
  orchestration nodes and selected paths, accepted scanner attempts and native
  artifacts, dependency coordination, coverage, gaps, suppressions, and
  containment state.
- Reconstructed typed S4 bytes must exactly match both the content-addressed
  published artifact and canonical `analysis_runs.report_json`. The persisted
  S4 schema version must also match the lineage membership.
- Analyzer ID, scanner contract digest, normalized selected scope, accepted
  result, clean containment, completion, coverage, gaps, and the OSV dependency
  prerequisite are therefore available for a direct historical B-to-C
  comparison even when B is not C's immediate predecessor.

The sequential lifecycle result is not used as a delta shortcut. V1.2E reuses
only the frozen authority-safe absence-proof primitives and applies them in the
correct baseline/candidate direction.

## Additive promotion migration

Migration `e7a1b3c5d902`, based on V1.2D head `d6f9b2c7a104`, adds only:

```text
source_trusted_baseline_promotions
----------------------------------
baseline_id   UUID string, primary key
lineage_id    lineage foreign key
run_id        composite lineage/run foreign key
revision      positive integer
actor_type    LOCAL_OPERATOR
promoted_at   timezone-aware timestamp
```

Each row is an immutable promotion record. `(lineage_id, revision)` is unique,
and the composite foreign key prevents cross-lineage baseline attachment. There
is no mutable `is_current` flag. The current baseline is the row with greatest
revision in that lineage. Every promotion receives a new stable `baseline_id`;
earlier IDs and history remain unchanged, including a deliberate repeat
promotion of the same run.

## Promotion, revision, and run order

The first promotion requires `expected_revision = 0` and creates revision 1.
Thereafter a request must present the exact observed revision N and creates
revision N+1. Promotion holds the authoritative lineage lock and locks the
selected membership/current promotion as needed. A stale request receives a
deterministic conflict; PostgreSQL uniqueness is a final convergence guard.

Promotions are monotonic by `source_lineage_runs.sequence_number`. A run equal
to or later than the current baseline may be promoted; an earlier run cannot be
used as a rollback. Candidate self-comparison is valid. A candidate later than
the current baseline is evaluated normally. A candidate earlier than the
current baseline returns an explicit all-`NOT_COMPARABLE` delta with
`CANDIDATE_BEFORE_BASELINE`.

## Baseline eligibility

Promotion verifies all of the following:

- exact project, lineage, and run ownership;
- a verified published S4 report with the frozen schema version;
- `INDEXED` Product Core membership and completed lifecycle evaluation digest
  and event metadata;
- finalized trusted Source submission with matching sequence membership;
- terminal, published orchestration whose outcome and `AnalysisRun` status are
  both `COMPLETED` or both `PARTIAL`;
- materialized finding occurrences whose priority fields are populated.

`FAILED`, `CANCELLED`, unfinalized, unpublished, unindexed, integrity-invalid,
cross-project, and cross-lineage runs are rejected. A structurally valid
`PARTIAL` run is eligible because per-authority delta results still fail closed.
`NOT_APPLICABLE` authorities and findings in the baseline are allowed. Security
cleanliness and analyst governance are not eligibility rules.

## Security Delta contract

Comparison identity is exactly the frozen canonical S4 `finding_id` within the
same lineage and authority context. V1.2E adds no fingerprint, fuzzy matching,
cross-tool merge, path/line fallback, or AI equivalence.

The closed per-finding states are:

| State | Meaning |
|---|---|
| `INTRODUCED` | Candidate contains F, baseline does not, and baseline-side comparable evidence proves F absent. |
| `PRESENT` | Exact F is observed in both baseline and candidate. This is positive evidence and needs no absence proof. |
| `REMOVED` | Baseline contains F, candidate does not, and candidate-side comparable evidence proves F absent. |
| `NOT_COMPARABLE` | The required baseline relationship cannot be established safely. |

A finding present in candidate 1, 2, and 3 remains `INTRODUCED` against a clean
trusted baseline even though sequential lifecycle moves from `NEW` to
`EXISTING`. It becomes `PRESENT` only after a baseline containing that exact
finding is promoted.

Absence proof checks compatible S4 schema, authority/capability/framework/
component/selected-scope identity, analyzer and contract identity, accepted
native evidence, clean containment, terminal completion, sufficiently complete
coverage, and absence of relevant gaps or S4 suppressions. OSV additionally
uses the frozen dependency-prerequisite and zero-package proof. Scanner failure,
partial relevant coverage, scope or contract mismatch, missing authority state,
or an unsafe dependency prerequisite can never silently produce `INTRODUCED`
or `REMOVED`.

## Per-authority isolation and summary

Checkov, Gitleaks, OSV, and Semgrep are summarized independently. An unrelated
authority failure cannot poison a safely comparable finding. Each authority and
the whole response use this closed status model:

- `COMPLETE`: every applicable required comparison succeeded;
- `PARTIAL`: at least one meaningful comparison is valid and some comparison is
  not comparable;
- `NOT_COMPARABLE`: no safe meaningful comparison is available.

An exact shared finding remains `PRESENT` positive evidence even if another
absence question under the same authority is unsafe; that authority summary is
then `PARTIAL`. Reason codes are deterministic and sorted. Delta reads never
consult governance or suppression tables, so false-positive, accepted-risk,
suppression, expiry, revocation, and reopen inheritance cannot rewrite scanner
truth.

## Read consistency

On PostgreSQL, current-baseline lookup, exact promotion identity, both lineage
memberships, finalized run state, reconstruction of both S4 reports, authority
coverage/contracts/scope, and delta derivation use one explicit
`REPEATABLE READ` transaction. The frozen S4 builder accepts the caller's read
session for this path; normal assembly continues to use its existing owned
session. Content-addressed artifacts are read outside PostgreSQL but are bound
to the same snapshot's immutable digests and sizes and must match canonical
published JSON byte-for-byte.

A concurrent promotion can therefore cause a delta request to observe either
the complete old revision or the complete new revision, never a mixture. The
response always returns the exact `baseline_id`, baseline run, and revision it
used. This is a coherent read guarantee, not serializable ordering across API
requests.

## Public API

The strict trusted-host API adds:

```text
GET /v1/projects/{project_id}/lineages/{lineage_id}/baseline
PUT /v1/projects/{project_id}/lineages/{lineage_id}/baseline
GET /v1/projects/{project_id}/lineages/{lineage_id}/baseline/history
GET /v1/projects/{project_id}/lineages/{lineage_id}/runs/{candidate_run_id}/security-delta
```

The only promotion body fields are `run_id` and `expected_revision`; extra
fields are rejected. The delta route is GET-only and offers no caller-supplied
baseline selector. Stable errors distinguish not found, revision conflict,
ineligible/invalid input, and persistence unavailability.

## PostgreSQL and upgrade evidence

The mandatory PostgreSQL 16 B/C/D/E selection passed 24 tests with no failures
or skips. It covers migration round-trip and V1.1/B/C/D upgrades; governance,
suppression, lifecycle, and effective-governance concurrency; simultaneous
initial and later promotions with exactly one winner; stale revision handling;
publication/finalization versus promotion; stable current-baseline reads;
delta evaluation versus concurrent promotion with exact baseline ID/revision;
self-comparison; read-only behavior; and project/lineage isolation. The separate
PostgreSQL stage/read-model parity case also passed.

The actual-state gate used a streamed read-only dump of the preserved V1.1
database, restored into a disposable PostgreSQL 16 tmpfs database. The copy was
upgraded through V1.2D, seeded with one valid legacy governance decision/event
and one suppression episode/event, then upgraded from `d6f9b2c7a104` to
`e7a1b3c5d902`. Before and after the E migration it retained 2 projects, 4
analysis runs, 450 lifecycle rows, one governance row/event, and one suppression
row/event with identical canonical material digest. Both legacy D anchors
remained `NULL`; the new promotion table began empty. `alembic check` found no
drift. A normal `LOCAL_OPERATOR` promotion on the upgraded copy then created
revision 1 and appeared exactly once in history. The preserved deployment and
artifact store were never mutated.

## Regression evidence

The final unique freeze matrix selected 903 cases:

- 428 non-PostgreSQL Product Core, lifecycle, dependency, V1.2B/C/D/E, API,
  CLI, SARIF, and CI cases: 424 passed and four unchanged V1.1P real-Syft
  binary replays were explicitly skipped because that external replay is
  opt-in;
- 25 PostgreSQL migration, B/C/D/E concurrency, and stage-parity cases passed;
- 385 S4, S6D assembly, scanner-native identity/parser, and trusted adapter
  registry cases passed;
- 65 frozen Web UI cases passed.

That is 899 passing tests, four classified opt-in skips, and zero failures.
Focused V1.2E API/delta tests, Ruff, byte-compilation, diff hygiene, SQLite
migration-to-head, and Alembic metadata comparison also passed. The only emitted
warning was the pre-existing Starlette/httpx test-client deprecation warning.

## Known limitations and non-goals

V1.2E exposes per-lineage trusted-host APIs, not UI or CLI baseline management.
It does not persist delta rows; callers retain the exact baseline ID/revision if
they need historical interpretation. It has no baseline rollback, policy
engine, PASS/FAIL/WARN decision, CI enforcement, automatic promotion,
repository-selected baseline, governance filtering, guidance/remediation,
KEV/EPSS/reachability/VEX, SBOM feature, new scanner or language, remote Git,
OAuth, RBAC, multi-tenancy, fuzzy matching, or AI.

The exact next phase is **V1.2F Deterministic Policy Engine**. It has not
started.
