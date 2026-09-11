# Source v0.10 Product Core

## PC1: logical lineage and finding occurrence index

PC1 adds a thin query index over the already-published S4 report. The canonical
S4 document in the final content-addressed artifact and `AnalysisRun.report_json`
remains authoritative. Product Core does not copy evidence, components,
scanner-native output, or complete finding documents.

A `source_target_lineage` is an explicit server-owned identity for Source runs
that belong to the same logical target across content revisions. It is linked
to a Project for ownership, but it is never inferred from a project name,
repository path, target name, content digest, Git metadata, or filesystem
location. Each published run is attached once, receives a sequence under a
lineage-row lock, and records the immediately preceding lineage run explicitly.

After S6D publication, one transaction verifies the terminal orchestration,
published report, frozen schema, artifact digest and size, canonical CAS bytes,
published JSON, run identity, and the report rebuilt through the frozen typed S4
assembly boundary. It then writes compact finding occurrences and marks the run
indexed atomically. Repeating an exact operation is idempotent; changed report,
membership, predecessor, or occurrence material fails closed.

Occurrences reuse S4 `finding_id` exactly and contain only authority, category,
native identity schema, optional severity, canonical subject/primary-location
summaries, report SHA, and ordinal. Expected S4 identity churn from moved spans,
changed package versions, changed resource identity, or changed native identity
is preserved. PC1 adds no fuzzy or cross-run fingerprint.

The index does not store source snippets, secrets, stdout/stderr, raw HTTP,
absolute workspace paths, native reports, Evidence objects, Component objects,
or package inventories. Rich data is loaded from authoritative S4 evidence when
needed.

PC1 does not implement finding lifecycle, first/last seen state, resolution,
priority, API, CLI, reporting UI, or final-report changes. Those remain later
Product Core slices.

## PC2: comparable-scope lifecycle and deterministic priority

PC2 adds a current lifecycle row keyed by the explicit PC1
`(lineage_id, finding_id)` identity and an immutable per-run event. The states
are `NEW`, `EXISTING`, `RESOLVED`, and `REOPENED`. First observation is `NEW`;
another observation of the exact same S4 identity is `EXISTING`; an exact
identity returning after `RESOLVED` is `REOPENED`. There is no fuzzy matching.
Consequently, a moved span, changed package version, changed resource identity,
or other native-identity change creates a new `finding_id` and therefore a new
`NEW` lifecycle. The old identity is considered for resolution independently.

Absence never proves resolution by itself. PC2 resolves an active identity only
when the current run is the explicitly linked, PC1-indexed successor and the
last-seen and current S4 reports have the same frozen schema and an exactly
matching authority coverage identity: capability, framework, component, and
canonical selected scope. Repository/profile/plan digests are deliberately not
used because content revisions are the point of lifecycle comparison.

For Semgrep, Gitleaks, and Checkov, the matching orchestration nodes must retain
the same analyzer ID, contract digest, and exact normalized selected-path set.
Both last-seen and current nodes must be terminal `COMPLETE`, have clean
containment, and reference an accepted clean attempt with a durable native
result. Current S4 coverage must be `COMPLETE`, `COMPLETE_WITH_FINDINGS`, or
`COMPLETE_WITH_SUPPRESSIONS` and must have no gap relevant to the finding
authority/capability/framework/path. For Checkov, a suppression matching the
same authority, subject, and location also withholds resolution; unrelated
suppressions do not. For OSV, all of those checks apply to the OSV node,
and the corresponding Syft prerequisite must independently retain the same
analyzer, contract, and selected paths with complete accepted clean execution.

OSV has one narrow successful-absence alternative. When comparable predecessor
OSV evidence exists, the current accepted clean Syft result and frozen dependency
evaluation may prove a complete zero-package inventory under the exact same
dependency scope. In that case, the current OSV node and S4 coverage must both
be `NOT_APPLICABLE` with exactly `NO_PACKAGES_OBSERVED`, the dependency
evaluation must be the complete `NOT_APPLICABLE_NO_PACKAGES` decision, and no
OSV Job may exist. The prior dependency finding then resolves with
`DEPENDENCY_REMOVED_ZERO_PACKAGE_PROOF`. `NO_PACKAGES_IN_ADVISORY_SCOPE`,
unsupported coordinates, mixed scope, partial or blocked prerequisites, changed
Syft contract/scope, unclean containment, missing accepted Syft evidence, or any
other not-applicable reason remains non-comparable and withholds resolution.

Cancellation, deadline expiry, failure, partial execution, dependency blocking,
reconciliation/unclean containment, missing accepted output, changed contract,
changed scope, incomplete coverage, a relevant gap, or a relevant suppression
records `RESOLUTION_WITHHELD` with stable reason codes. It does not alter the
last-known active state. Failure by an unrelated authority does not prevent a
transition whose own authority has complete comparable proof.

Lifecycle evaluation locks the lineage, current run, explicit predecessor, and
current lifecycle material; verifies PC1 and S4 again; writes priorities,
events, current state, and a deterministic completion digest in one transaction.
Re-evaluation validates that durable material against the full event history and
returns the existing result. Finding/event transition timestamps come from each
authoritative orchestration `published_at`: they describe when the scan
established the state. The lineage run's `lifecycle_evaluated_at` separately
records Product Core processing wall-clock time. Previously evaluated history is
never selected by timestamp or rewritten.

Priority is deterministic triage ordering, not exploitability or business risk.
The bands are `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, and `UNRANKED`:

- Semgrep and Checkov use their normalized severity with
  `SCANNER_NORMALIZED_SEVERITY`; missing or `UNKNOWN` severity is `UNRANKED`
  with `NO_NORMALIZED_SEVERITY`.
- OSV uses the maximum validated applicable CVSS base score: at least 9.0 is
  `CRITICAL`, at least 7.0 `HIGH`, at least 4.0 `MEDIUM`, greater than zero
  `LOW`, and an explicitly validated zero score is `INFO`; this zero-to-INFO
  mapping is a deterministic triage policy, not evidence of no business risk.
  Missing validated CVSS is `UNRANKED`. The reason is
  `VALIDATED_CVSS_BASE_SCORE` or `NO_VALIDATED_CVSS`.
- Gitleaks findings are `HIGH` under the transparent Source-v1 category policy
  `CATEGORY_POLICY_SECRET_EXPOSURE`. This does not claim that every secret is
  exploitable or has the same business impact.

PC2 persists only the priority band and reason codes on the compact occurrence
row. It adds no universal numeric risk score, EPSS, KEV, reachability, evidence
blob, API, CLI, final-report field, or presentation behavior.

The priority vocabulary includes `CRITICAL` for cross-authority consistency.
Frozen S4 Semgrep normalization currently emits only `HIGH`, `MEDIUM`, `LOW`,
or `INFORMATIONAL`, so the Semgrep-to-`CRITICAL` branch is reserved and is not
reachable from the current frozen Semgrep contract.

## PC3A: durable submission intent and trusted asynchronous intake

PC3A reserves Product Core lineage order when a scan is submitted, rather than
when it happens to publish. Each durable submission binds one AnalysisRun to an
explicit PC1 lineage, an allocated sequence, its exact predecessor, and an
opaque managed-workspace reference. Allocation locks the lineage and considers
both pending submissions and already-finalized PC1 memberships. Completion
timestamps and publication order never select lifecycle order.

The intake reference is the existing opaque
`securescan-workspace-<random-hex>` identity. It is not the caller's repository
path and cannot select an alternate workspace root. The manager resolves it
only as a direct child of its configured server-owned root and verifies the
ownership marker and directory shape. The Product Core resolver reconstructs
the expected manifest from the frozen orchestration planning snapshot and
verifies the immutable files before returning the workspace to asynchronous
coordination. Managed workspaces persist until explicit, ownership-checked
cleanup, so process exit does not invalidate this handoff.

Finalization is restart-safe and ordered: it requires authoritative S6D
publication and a finalized predecessor, invokes PC1 attachment with the
reserved predecessor, requires the resulting PC1 sequence to equal the
reserved submission sequence, indexes the S4 findings, runs PC2 lifecycle
evaluation, and only then records `finalized_at`. Each lower layer is already
idempotent, so a retry after interruption converges. If a later submission
publishes first, it remains not ready until its reserved predecessor has
completed Product Core finalization; it cannot become lineage sequence one.

PC3A adds no public API or CLI and changes no scanner, orchestration, S4,
lifecycle, or priority semantics. Those product interfaces remain PC3 scope.

Source v1 does not automatically skip a submission whose predecessor never
publishes. A permanently cancelled or otherwise unpublishable predecessor
therefore blocks later submissions in that lineage; continuing requires an
explicit new lineage. PC3 must expose this blocked state rather than presenting
later submissions as clean or silently rewriting their reserved order.

## PC3B: bounded finalization runner and reusable Source read model

PC3B provides an explicit application-layer finalization runner. Each bounded
pass selects at most 50 submissions by default (200 maximum) whose authoritative
S6D publication exists and whose PC3A `finalized_at` is still null. Candidates
whose exact predecessor has completed Product Core are considered before
blocked candidates; each readiness tier is then ordered only by `lineage_id`
and reserved `submission_sequence_number`. This prevents a blocked lineage from
monopolizing a bounded window without assigning any cross-lineage lifecycle
meaning. The runner calls `SourceScanSubmissionService.finalize()` as the final
readiness authority and relies on PC3A's existing idempotent PC1/PC2 guarantees.
A blocked successor remains `NOT_READY`; the runner never skips or rewrites its
predecessor. Per-run failure is isolated and does not alter the already-published
S4 result.

There is no suitable post-publication application hook outside the frozen
orchestration implementation today. PC3B therefore exposes the runner as an
explicit service for a later deployment scheduler. It does not add a daemon or
change S6D. Automatic bounded invocation remains a Product Core deployment
integration requirement.

`SourceScanQueryService` is the single read-only application boundary intended
for both the later HTTP API and CLI. GET-style reads never invoke finalization,
attach lineage membership, index findings, evaluate lifecycle, or mutate Source
orchestration. Published report-derived views use PC1's strict read-only S4
boundary: the report is rebuilt through the frozen typed S6D assembly logic,
then its canonical bytes must exactly equal both the content-addressed artifact
and canonical `AnalysisRun.report_json`. No second report or component database
is created. Existing PC1 membership must also agree exactly with the PC3A
submission lineage, sequence, and predecessor identity before it is trusted.

Product status is based on durable facts. `COMPLETED` requires publication,
PC3A finalization, an indexed PC1 membership, and completed PC2 lifecycle
evaluation. A published run lacking those facts is
`PUBLISHED_PENDING_FINALIZATION`, or `BLOCKED_BY_PREDECESSOR` when its reserved
predecessor is not ready. Durable terminal cancellation and failure remain
`CANCELLED` and `FAILED`; a prepared run is `QUEUED`, and other unpublished work
is `RUNNING`.

Product completion is deliberately separate from analysis coverage. A
`COMPLETED` Product Core run may still have `PARTIAL`, `FAILED`, or
`NOT_APPLICABLE` authority coverage and analysis gaps. The read model exposes
coverage outcomes and gaps independently. Findings are bounded current-run PC1
occurrences joined to PC2 lifecycle and priority summaries. Components,
dependencies, coverage, gaps, and the report are safe projections of the
authoritative S4 document; no raw scanner stream, source snippet, secret value,
lease identity, attempt token, or filesystem artifact path is exposed.

## PC3C: public Source HTTP API

PC3C exposes the Product Core through `/v1/scans`: asynchronous submission,
status, findings, components, dependencies, coverage, gaps, the verified S4
report, and durable cancellation. Submission accepts only a project ID, an
opaque PC3A-managed trusted target ID, an optional explicit lineage ID, a
deadline, and an idempotency key. The server verifies the target's exact PC3A
managed-workspace binding and re-resolves its frozen planning snapshot and
workspace before invoking `SourceScanSubmissionService`; callers cannot supply
a host path or workspace root.

All GET operations delegate to `SourceScanQueryService` and are read-only. They
never finalize Product Core, attach lineage membership, index findings,
evaluate lifecycle, or mutate orchestration. Consequently
`PUBLISHED_PENDING_FINALIZATION` and `BLOCKED_BY_PREDECESSOR` remain visible
instead of being silently advanced. Product completion remains distinct from
coverage: a completed scan may expose partial, failed, or not-applicable
authority outcomes and explicit gaps.

Cancellation uses the existing durable Source orchestration coordinator. It
does not update Job, attempt, or lease rows directly. Public errors use the
existing `{\"detail\": {\"code\", \"message\"}}` API shape and replace internal
exceptions with fixed messages. Explicit response schemas exclude managed
workspace paths, artifact paths, native results, scanner streams, cleanup
receipts, attempt and lease tokens, and secret values. The report endpoint uses
only `SourceScanQueryService.get_report()`, preserving the typed S4/CAS/database
byte-equality trust boundary.

## PC3D: local Source CLI

PC3D exposes four local commands through the existing `securescan` Typer
application:

```bash
securescan scan . --project-id <project-uuid>
securescan status <run-id>
securescan findings <run-id>
securescan report <run-id>
```

Only `scan` accepts a local filesystem path. It resolves and validates the
directory, copies it through `RepositoryWorkspaceManager.prepare_repository()`,
profiles that immutable managed snapshot, builds the frozen five-authority
Source plan, creates an explicit PC1/PC3A lineage (or uses an explicitly
supplied `--lineage-id`), and calls
`SourceScanSubmissionService.submit_prepared()`. The caller's live path is
never submitted to a worker or stored in the durable Target; the Target retains
only the opaque managed-workspace identity. The managed workspace deliberately
survives CLI process exit because orchestration and scanner execution are
asynchronous. Cleanup remains an explicit ownership-checked lifecycle
operation.

An existing durable project must be selected with `--project-id`; PC3D does not
derive project or lineage identity from a path, directory name, content digest,
or timestamp. Each invocation generates a cryptographically random PC3A
idempotency key, so repeating the shell command intentionally creates a new
scan; PC3D does not expose a misleading path-based replay identity. The durable
parent deadline defaults to the bounded
`SECURESCAN_SOURCE_SCAN_DEADLINE_SECONDS` setting (1,800 seconds) and may be
overridden between 300 and 86,400 seconds with `--deadline-seconds`.

Submission returns immediately after durable activation and reports the
non-analytical acknowledgement `SUBMITTED`; it does not perform a post-commit
Product Core read that could turn durable success into an apparent CLI failure.
It never waits for a scanner or invokes Product Core finalization. `status`,
`findings`, and `report`
delegate only to `SourceScanQueryService`; they do not attach lineage
membership, index findings, evaluate lifecycle, finalize, or mutate
orchestration. Findings retain PC3B filter and pagination validation. Reports
cross the same typed S4/CAS/published-database byte-equality boundary as the
HTTP API. Product `COMPLETED` and complete analysis coverage remain visibly
separate.

Expected CLI failures use fixed codes and nonzero exit classes: input errors
use 2, missing or not-ready Product Core state uses 3, durable submission
conflict uses 4, and unavailable infrastructure uses 5. Normal failures do not
render tracebacks or internal exceptions. CLI output omits managed workspace
and artifact paths, worker/lease/attempt identities, scanner streams, native
artifacts, source snippets, and secret values. `--json` emits only explicit
Product Core response fields.

The project already declares `securescan = "securescan.cli.main:app"`. In a
source checkout use the editable project environment
(`./.venv/bin/python -m pip install -e '.[dev]'`) or activate `.venv`; no
alternate console command or CLI-only persistence stack is introduced. Before
local submission, configure `SECURESCAN_SOURCE_ENRY_HELPER_SHA256` with the
independently trusted lowercase SHA-256 identity for the configured Enry helper;
PC3D will not manufacture trust by hashing an untrusted local helper and then
accepting that same digest.

PC3D deliberately requires an existing durable Project UUID and does not add a
project-creation workflow. Repeating `securescan scan` intentionally creates a
new scan because each invocation uses a fresh random idempotency key. Deployment
must separately provide all trusted runtime scanner and toolchain identities;
PC3D does not weaken or synthesize those identities.

Before Source v1 release, the Semgrep production contract was refrozen from an
undeployable development placeholder to the verified immutable image
`semgrep/semgrep@sha256:bdf7013b2c3634a487671158da77c554f531742326b543a9464d2adf6c433ac8`.
New runs use only that image-bound contract, with no mutable-image fallback or
free-form image selection. Historical Git checkpoints remain immutable, but
pre-v1 local durable runs created with the placeholder contract are not
supported for resume under the corrected runtime and must fail closed.

## Source Runtime R1A/R1B: bounded production composition

Source submission remains asynchronous. The API and `securescan scan` persist a
trusted managed-workspace submission and return without executing scanners. The
production runtime is the separate process boundary that advances those durable
submissions:

```bash
securescan worker --once
```

One invocation constructs a single canonical stack from `Settings`: database
sessions, CAS, managed-workspace and projection managers, the frozen coordinator,
attempt and leasing services, all five frozen authority runners, the S6D
assembler/publisher, and the Product Core finalization runner. Construction does
not execute a scanner or contact OSV. The bounded cycle quarantines expired
leases, uses one shared budget of at most 25 coordinator advances across its pre-
and post-worker phases, dispatches at most four mapped jobs, attempts at most ten
S6D publications, and gives at most 25 published submissions to the existing
finalizer. Each mutation remains owned by those authoritative services. A bounded
200-row actionable discovery window prevents queued no-op runs from starving later
runnable work without allowing an unbounded database walk. Failed managed-workspace
or coordinator validation aborts the cycle before its worker batch.

Runnable work is discovered from database state, ordered deterministically, and
restricted to Product Core submissions whose intake kind is
`MANAGED_WORKSPACE_V1`. Active runs obtain their workspace only through
`SourceScanSubmissionService.resolve_workspace()`, which reopens the opaque PC3A
workspace and verifies it against the frozen planning snapshot. An absent or
invalid workspace prevents that run from advancing; neither the Target's stored
value nor the original caller path is treated as an arbitrary filesystem path.

The cycle does not loop until the database is empty. Repeated `worker --once`
invocations may therefore be used by cron, smoke tests, and controlled operations;
every invocation reconstructs progress from DB/CAS state. Existing job identity,
lease/attempt containment, cancellation, parent deadline, Syft-to-OSV dependency,
S6D single-publication, and Product Core predecessor/finalization rules remain the
authorities for idempotency and recovery. OSV remains a mapped job behind its
existing permit-controlled helper—there is no direct HTTP path or special pause
state in the runtime.

The command prints only aggregate cycle counts. It omits run IDs, source and
managed-workspace paths, artifact paths, scanner streams, findings, secret values,
tokens, cleanup receipts, worker identities, and attempt identities. This bounded
worker slice is not yet a continuous daemon or deployment-readiness claim.
