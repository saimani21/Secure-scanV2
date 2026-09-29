# SecureScan Source V1.2A governance contract

Status: `COMPLETE - CONTRACT FROZEN`

## 1. Baseline

V1.2A audits the frozen SecureScan Source v1.1.0 Evidence/Product Plane. The
annotated `source-v1.1.0` tag, starting branch HEAD, and expected parent all
resolved to `ee7e81cfc2596e34645fdc46542b357e3c88669d`. The working branch was
`source/v1.2A-governance-contract-audit`; its starting worktree was clean. No
preserved v1.1 runtime, database, data root, artifact, operator profile, or
volume was migrated or mutated.

## 2. Current architecture

```text
immutable snapshot -> validated authority-native results -> immutable S4 report
  -> Product Core occurrence index -> exact per-lineage lifecycle comparison
  -> read models, API, CLI, UI, and SARIF
```

S4 is the canonical cross-authority evidence representation. Product Core
indexes it without creating another finding identity. Lifecycle compares exact
identities along one logical Source lineage. Deterministic priority is stored on
the per-run occurrence; it is not analyst state.

The future Governance Plane starts from an existing `(lineage_id, finding_id)`
and adds mutable analyst decisions plus immutable governance mutation history.
It may control treatment of scanner truth, but must not rewrite or feed back
into scanner, S4, occurrence, lifecycle, coverage, gap, dependency, priority,
or SARIF identity semantics.

## 3. Canonical finding identity

`src/securescan/evidence/models.py::build_finding_id` returns a
domain-separated SHA-256 digest of canonical JSON containing:

```text
[authority.value, native_identity_schema, native_identity]
```

`SecureScanFinding.__post_init__` recomputes and verifies it. The ID is
authority-qualified and run-independent. Project, lineage, run, report digest,
priority, message, and lifecycle state are not generic inputs. Authority-native
identity may itself contain path, location, package, rule, resource, or scanner
version data.

Product Core persists the ID in `source_finding_occurrences` and
`source_finding_lifecycles`, alongside authority, category, and native identity
schema, and fails closed on disagreement. It calculates no fuzzy, cross-tool,
or inferred logical fingerprint.

## 4. Per-run occurrence identity

`SourceFindingOccurrenceRow` maps to `source_finding_occurrences`, keyed by
`(run_id, finding_id)`. It binds the occurrence to `lineage_id`, the exact S4
report digest, authority/category/schema, ordinal, safe subject/location
summaries, and deterministic priority. A unique `(run_id, finding_ordinal)`
preserves report ordering integrity. The same exact S4 finding may occur in
multiple runs as separate occurrences. This run-scoped key is not suitable for
persistent governance.

## 5. Logical lineage identity and isolation

`SourceTargetLineageRow` maps to `source_target_lineages`. Its server-created
`lineage_id` UUID is the primary key and `project_id` is a required foreign key.
A lineage is the durable comparison domain for one logical Source target
history. Product Core and submission services lock and validate the lineage and
reject a run whose target project differs. HTTP submission checks ownership and
maps contradictory durable state to 409.

Therefore the same `finding_id` in unrelated projects cannot share governance;
two lineages in one project cannot share governance; project ownership must be
derived and checked through the lineage; and a run remains only an occurrence
context.

## 6. Predecessor/comparison model

`source_scan_submissions` is keyed by `run_id` and uniquely orders
`(lineage_id, submission_sequence_number)`. Sequence one has no predecessor;
later reservations name the immediately preceding run and sequence. Reservation
locks the lineage and both submission and finalized-lineage tails.

`source_lineage_runs` is keyed by `run_id`, uniquely constrains lineage order
and membership, and uses a composite foreign key for predecessor lineage, run,
and sequence. Final membership must match reserved order. Completion time cannot
reorder a lineage.

Lifecycle requires an indexed membership, an evaluated predecessor, and no
already-evaluated later membership. Re-evaluation of a completed run is
idempotent. Comparison follows durable predecessor order, never timestamp or
"latest" guessing.

## 7. Lifecycle state machine and persistence

Current state is in `source_finding_lifecycles`, keyed by
`(lineage_id, finding_id)`, with first/last seen runs/times, optional resolution
run/time, and monotonic `transition_version`. Immutable events are in
`source_finding_lifecycle_events`, keyed by `(run_id, finding_id)` and foreign
keyed to the lifecycle. Each evaluated lineage run stores its event count and
canonical evaluation digest.

`SourceFindingLifecycleService.evaluate` implements:

| Result | Implemented condition | Reason |
|---|---|---|
| `NEW` | Exact ID observed with no row in this lineage | `FIRST_OBSERVATION` |
| `EXISTING` | Exact ID observed; prior state is not `RESOLVED` | `OBSERVED_AGAIN` |
| `REOPENED` | Exact ID observed; prior state is `RESOLVED` | `RETURNED_AFTER_RESOLUTION` |
| `RESOLVED` | Active exact ID absent and comparison has no withholding reason | `COMPARABLE_SCOPE_ABSENCE` or exact OSV zero-package proof |

A changed authority-native identity yields another S4 ID and another lifecycle.

`RESOLUTION_WITHHELD` is an immutable event, not a fifth current state. It
records sorted reasons, keeps previous/resulting state equal, and neither
changes current state nor increments `transition_version`. History is
replay-validated and never rewritten.

## 8. Resolution proof

Absence proves resolution only within the same lineage when all relevant facts
hold:

1. durable predecessor relationship and equal S4 report schema;
2. current parent neither cancelled nor deadline-exceeded;
3. exactly one relevant predecessor coverage outcome;
4. an exact current match for authority, capability, framework, component,
   selected scope, and relevant selected paths;
5. predecessor and current relevant coverage complete;
6. no relevant gap or scanner-authored suppression;
7. exactly one relevant orchestration node per compared run;
8. equal analyzer identity and contract digest;
9. both relevant nodes terminal `COMPLETE` with `CLEAN` containment;
10. matching accepted attempts with clean containment and native result digest;
11. for OSV, equally comparable and complete Syft prerequisite nodes/results.

An unrelated authority failure does not block proof. Relevant failure,
partial/nonterminal execution, blocked dependency, cancellation, deadline,
scope or contract drift, gap, suppression, missing accepted result, containment
uncertainty, or predecessor inconsistency withholds resolution.

OSV has one narrow removal proof: exact
`NOT_APPLICABLE/NO_PACKAGES_OBSERVED`, zero findings/gaps, the matching terminal
OSV node, exact-scope complete Syft zero-package evidence, and a valid empty
dependency-evaluation artifact with no observations, candidates, or mixed-scope
gaps. Mere finding/request absence is insufficient.

## 9. Authority-specific identity

### Semgrep

Schema `semgrep-structural-fingerprint-v1` uses scanner producer ID, rule ID,
normalized path, and exact start/end line and column
(`scanners/semgrep/source_result.py::_fingerprint`). Changes to any of these
produce a new finding. Message, severity, and sanitized CWE do not. Line
movement is intentionally identity-changing.

### Gitleaks

`scanners/gitleaks/identity.py` hashes schema/scope, scanner ID and version,
rule ID, path, and detection kind. Content detections include exact start/end
line and column; path detections do not. Secret, match, snippet, and private raw
fields are excluded. Indistinguishable native duplicates coalesce to one S4
finding while `native_occurrence_count` preserves multiplicity. There is no
fuzzy deduplication.

### OSV

Syft supplies package observations and `package_key`. An eligible candidate
binds exact package key and versioned PURL. `advisories/osv/models.py`
transitively groups records by IDs/aliases, hashes package key plus sorted record
IDs and aliases into `advisory_group_key`, then derives the native dependency
finding ID. S4 authority-qualifies that ID. Package or advisory group changes
change identity; locations, summaries, scores, modified timestamps, and
fixed-version presentation do not. Alias-set revision may create a new identity;
governance must not guess equivalence.

### Checkov

`scanners/checkov/parser.py::_identity` hashes framework, check ID, normalized
path, and resource. Those changes change identity; line movement, check name,
and severity do not. Checkov suppressions are separate S4 evidence, not finding
identity or analyst governance.

These differences are frozen authority contracts, not a reason to add a generic
fingerprint.

## 10. Dependency relationship

```text
Syft observation -> package_key/versioned PURL -> dependency evaluation
  -> eligible OSV candidate -> validated advisory records -> alias group
  -> S4 OSV finding -> Product Core occurrence and per-lineage lifecycle
```

`SourceDependencyProjectionService` read-correlates verified S4,
Syft/dependency-evaluation artifacts, and accepted OSV results. It creates no
alternate finding identity. Package/components are supporting evidence; only
the canonical S4 OSV finding receives lifecycle and future finding governance.
Governance must not alter eligibility, grouping, applicability, exact-pin
handling, nullability/counts, or zero-package proof.

## 11. SARIF identity

`src/securescan/cli/sarif.py` fully traverses Product Core findings, verifies
one-to-one S4 correlation, and emits the canonical ID as
`properties.securescanFindingId` and
`partialFingerprints["securescanFindingId/v1"]`. Authority-qualified `ruleId`
is presentation/classification, not a second fingerprint. SARIF invents no
secondary identity and imports no GitHub dismissal state. Governance shares the
S4 ID but also requires lineage scope; SARIF represents one run occurrence.

## 12. Governance attachment decision

Future mutable governance shall bind to exactly:

```text
(lineage_id, canonical S4 finding_id)
```

This matches the existing lifecycle key. The lifecycle row is the authoritative
existence target and natural composite foreign key. Every read/write must derive
and validate `project_id` through the lineage; project must not broaden state
across its lineages.

Rejected: run plus finding (scan-specific), global finding (cross-project and
cross-lineage leakage), project plus finding (cross-lineage leakage), and any
new fuzzy, cross-tool, path/line/CWE, message, or LLM-derived identity.

## 13. Future rescan inheritance

- The same exact finding in the same lineage reads the same governance record.
- `RESOLVED` does not delete or rewrite governance history.
- The exact ID returning as `REOPENED` sees the same governance record, subject
  to later explicit expiry/revocation.
- Changed native identity, another lineage in the same project, or another
  project receives no automatic inheritance.
- Scanner lifecycle and governance may change concurrently but remain
  independent facts.

Copying a decision between different keys must be an explicit audited future
action, never automatic equivalence inference.

## 14. Mutation boundary

Immutable/scanner-authoritative: accepted native evidence; S4 findings,
components, coverage, gaps, and suppressions; canonical identity; report/CAS
provenance; execution truth; per-run occurrence and deterministic priority; and
Product Core lifecycle/event history already produced.

Future mutable governance: analyst disposition, false-positive/accepted-risk
decisions, suppression/expiry/revocation, bounded analyst reasons/notes, and
derived baseline/delta/policy views. Governance changes append governance audit
material and never edit Evidence/Product Plane rows or artifacts.

## 15. Persistence map

| Concept | Table / model | Identity | Scope / mutability / authority |
|---|---|---|---|
| Project | `projects` / `ProjectRow` | `id` | durable Product API boundary |
| Target/run | `targets`, `analysis_runs` | respective `id` | intake/execution; durable orchestration state |
| Lineage | `source_target_lineages` | `lineage_id`; FK project | durable Product Core comparison scope |
| Submission | `source_scan_submissions` | PK run; unique lineage sequence | reserved/finalized submission order |
| Membership | `source_lineage_runs` | PK run; unique lineage order/membership/report | indexed/lifecycle markers advance once |
| Occurrence/priority | `source_finding_occurrences` | `(run_id, finding_id)` | S4 occurrence plus one deterministic priority enrichment |
| Lifecycle current | `source_finding_lifecycles` | `(lineage_id, finding_id)` | Product Core-only deterministic mutation |
| Lifecycle events | `source_finding_lifecycle_events` | `(run_id, finding_id)` | append-only Product Core evidence |
| Node dependency | `source_orchestration_dependencies` | run/node/prerequisite | durable planned edge |
| Dependency evaluation | `source_orchestration_dependency_evaluations` | `(run_id, osv_node_id)` | accepted Syft-to-OSV reference |
| Coverage/gaps | published S4 report in CAS | report/S4 identities | immutable; no parallel table |
| Dependency read model | no projection table | verified source artifacts | read-only Product Core derivation |

No existing table represents analyst disposition, accepted risk,
false-positive state, or governance suppression. Scanner-authored S4
suppressions must not be repurposed.

## 16. Concurrency preparation

Current Product Core uses transactions, uniqueness/foreign-key constraints,
and PostgreSQL `SELECT ... FOR UPDATE` for lineage, submission tail, run,
membership, and lifecycle coordination. Idempotent retries return durable
results; contradictory submissions map to 409. Lifecycle `transition_version`
must not be reused as an analyst edit revision.

The smallest compatible future strategy is: lock the exact governance row and
lineage boundary; maintain an independent positive `revision`; require
`expected_revision` (or `If-Match`, with zero for create); atomically append one
governance event and update current state; use a unique idempotency key; return
the prior result for an exact retry; and return stable 409 for stale/conflicting,
missing-target, or cross-project/lineage writes. Expiry is a governance mutation,
not a lifecycle mutation.

## 17. Minimal V1.2B proposal

- `source_finding_governance`: current row keyed by
  `(lineage_id, finding_id)`, composite FK to the lifecycle, disposition
  material, independent revision, and creation/update metadata; no copied
  scanner truth.
- `source_finding_governance_events`: immutable rows uniquely ordered per
  governance key/revision with previous/resulting material, actor/source,
  reason, idempotency key, and timestamp.
- One project-authorized lineage/finding read and one conditional update API,
  deriving ownership from lineage, requiring expected revision/idempotency,
  returning revision, and using stable 409 conflicts.

Disposition vocabulary, authentication model, note limits, and route spelling
remain V1.2B decisions. V1.2A creates no migration or endpoint.

## 18. Non-goals

V1.2A implements no analyst disposition, false-positive handling, accepted
risk, suppression/expiry, baseline, delta, policy, KEV, EPSS, SSVC, AI,
remediation, fuzzy identity, or cross-tool deduplication. It changes no scanner,
planner, parser, adapter, dependency, S4, Product Core, lifecycle, priority,
API, CLI, UI, SARIF, worker, containment, CAS, or secret semantics.

## 19. Test evidence and gaps

Executed on 2026-09-29:

- focused S4 model/adapter, Semgrep, Gitleaks, OSV, Checkov, PC1, PC2, PC3A,
  PC3B, and SARIF suites: **284 passed** in 235.38 seconds;
- supplemental PC3C, PC3D, and projection-lifecycle suites: **89 passed** in
  45.41 seconds.

Total: **373 passed, 0 failed, 0 skipped**. This covers run-independent S4
identity, per-run occurrences, no-fuzzy lifecycle identity, all four current
states, resolution withholding cases, unrelated-authority isolation,
predecessor/finalization rules, deterministic replay, project-lineage rejection,
OSV/Syft proof, and SARIF correlation.

The existing PostgreSQL test
`test_concurrent_lifecycle_evaluators_converge_on_one_durable_result` proves two
evaluators converge on one lifecycle row/event. It was inspected but not rerun:
Docker/local PostgreSQL were unavailable and no `SECURESCAN_TEST_POSTGRES_URL`
was configured. No preserved database was substituted. V1.2B must rerun it and
new governance concurrency tests against a fresh isolated test database.

No dedicated current test names the exact hostile case "same `finding_id` in
two projects/two lineages." The composite lifecycle key, lineage-project FK,
service ownership validation, and wrong-project/lineage tests enforce the
boundary structurally and operationally. V1.2B should add the explicit hostile
governance case when that persistence exists.

## 20. Acceptance

**PASS.** The exact existing attachment key is selected, mutation boundaries
are frozen, no duplicate fingerprint/migration/production change was added, and
all executable focused and broader non-PostgreSQL gates passed. The unexecuted
PostgreSQL rerun is recorded as a V1.2B requirement, not claimed as a pass.

Next phase: **V1.2B Analyst Disposition**. This document does not begin it.
