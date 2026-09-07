# Source v0.8 S6A Durable Orchestration Foundation

## Scope

S6A adds the durable control-plane skeleton for one Source orchestration per
`AnalysisRun`. It persists the trusted planning truth, five-authority roster,
deterministic runnable nodes, the Syft-to-OSV dependency edge, lifecycle state,
cancellation state/version, and a caller-supplied parent deadline.

S6A does not execute scanners, call OSV, create scanner jobs or tool executions,
accept native results, assemble S4 evidence, or publish `report_json`. It does not
implement retry or local-process containment. S6B owns the trusted supervisor and
orphan-reconciliation contract; S6C and S6D own dependency/result processing and
final assembly/publication.

## Durable parent identity

`source_orchestrations.run_id` is both the primary key and a cascading foreign key
to `analysis_runs.id`. There is no second orchestration identifier. An AnalysisRun
can therefore have at most one Source orchestration, while legacy AnalysisRuns may
continue to have none.

Creation commits the AnalysisRun, parent, roster, nodes, dependency edge, and CAS
reference in one database transaction. A unique 64-character idempotency key and a
domain-separated creation-request digest make identical retries return the same
run. A changed target, profile, plan, roster, or deadline under that key fails as a
conflict. A losing transaction may leave an unreferenced content-addressed object;
it cannot leave a committed partial topology.

## Canonical planning snapshot

The planning snapshot schema is
`securescan-source-orchestration-planning-s6a-v1`. Its canonical UTF-8 JSON contains:

- the immutable repository digest and complete canonical `RepositoryProfile`;
- file-relative path, size, SHA-256, role, flags, language, and component identity;
- canonical components, manifests, lockfiles, language support, and capability surfaces;
- the complete canonical `SourceAnalysisPlan`, including every plan entry, action,
  reason, analyzer, support state, surface/selected paths, and exclusions;
- the exact five-authority trusted roster;
- canonical node identities and immutable scopes; and
- canonical dependency edges.

The snapshot contains no source bytes, absolute workspace path, repository
credentials, environment, scanner output, or scanner-controlled configuration. It
uses sorted collections, sorted JSON keys, `allow_nan=False`, a trailing newline,
and SHA-256 of the exact canonical bytes.

The existing content-addressed artifact store writes the snapshot under
`sha256/<prefix>/<digest>` with the orchestration-specific artifact kind and media
type. The durable row records digest, exact byte count, media type, schema version,
and canonical relative locator. Every accepted write is read back by digest and
size. Every load repeats that verification, rejects noncanonical JSON, duplicate
keys, nonfinite values, unknown fields/schema, invalid paths, or mismatched typed
reconstruction, then independently correlates the database topology.

The persisted snapshot, not the current filesystem, is the restart authority. A
later workspace reconstruction must prove it matches this truth.

## Trusted authority roster

Every orchestration persists exactly these server-owned authorities:

| Authority | Capability | Analyzer/service contract |
|---|---|---|
| `semgrep-ce` | `python_sast` | `python-semgrep-v1`, Semgrep 1.171.0 trusted binding |
| `gitleaks` | `secret_detection` | `gitleaks-source-v1`, Gitleaks 8.30.1 trusted binding |
| `syft` | `package_inventory` | `syft-source-v1`, Syft 1.51.0 trusted binding |
| `osv.dev` | `dependency_advisory_matching` | `osv-dependency-advisory-v1`, OSV v1 service contract |
| `checkov` | `configuration_security` | `checkov-source-v1`, Checkov 3.3.16 trusted binding |

The versioned roster digest covers authority, capability, analyzer, contract kind,
contract digest, implementation version, and roster schema. It excludes run,
worker, job, attempt, and timestamp identity. User input cannot choose any roster
field or endpoint. `securescan-source` is an assembler identity, not a scanner
authority, and is not present.

Skipped or not-applicable capabilities remain represented in this roster even when
they produce no runnable node.

## Node identity and immutable scope

Node IDs are domain-separated SHA-256 values over exactly:

```text
run_id + authority + capability + component_id/null
```

They exclude selected paths, timestamps, workers, leases, jobs, attempts, findings,
and results. Selected paths are instead part of an immutable node-scope digest,
along with repository/profile/plan identity, analyzer, trusted contract, component,
and the referenced plan entries. Loading fails closed if any duplicated row,
component, analyzer, contract, selected path, plan reference, or scope digest does
not equal the canonical snapshot.

Runnable Source-v1 topology is:

- one Semgrep node per runnable Python SAST component plan entry;
- one repository-wide Gitleaks node when runnable;
- one repository-wide Syft node when runnable;
- one repository-wide Checkov node when runnable; and
- one aggregated OSV node when dependency advisory matching is runnable.

The OSV node starts in `WAITING_DEPENDENCY`; independent runnable nodes start in
`READY`. S6A creates no scanner Job for either state.

## Dependency DAG

The only Source-v1 semantic edge is `Syft -> OSV`, represented as “OSV node requires
Syft node.” Both node foreign keys include the same run ID, duplicate edges are
prevented by the primary key, and self-edges are rejected. Typed reconstruction
accepts only the exact planner-derived topology, so cycles, missing Syft, or any
additional user-defined edge fail closed.

S6A stores this dependency but does not schedule or evaluate it. Zero-package,
mixed-scope, accepted-result, and blocked-dependency decisions remain later-phase
work under the frozen S1/S2 semantics.

## State and concurrency model

Parent lifecycle vocabulary is `PREPARED`, `ACTIVE`, `CANCELLATION_REQUESTED`,
`ASSEMBLY_READY`, `ASSEMBLING`, `COMMITTING`, and `TERMINAL`. Terminal security
outcome is a separate nullable value: `COMPLETED`, `PARTIAL`, `FAILED`, or
`CANCELLED`. S6A implements only `PREPARED -> ACTIVE` and the transition from a
nonterminal, non-cancelled state into `CANCELLATION_REQUESTED`.

Node lifecycle vocabulary is `PLANNED`, `WAITING_DEPENDENCY`, `READY`,
`NOT_APPLICABLE`, `QUEUED`, `RUNNING`, `RETRY_PENDING`,
`RECONCILIATION_REQUIRED`, and `TERMINAL`. Terminal disposition is separately one
of `COMPLETE`, `PARTIAL`, `NOT_APPLICABLE`, `FAILED`, `BLOCKED_BY_DEPENDENCY`, or
`CANCELLED`. Containment state is separately `NOT_STARTED`, `ACTIVE`,
`RECONCILIATION_REQUIRED`, or `CLEAN`. S6A defines and validates these boundaries
but does not advance scanner nodes.

The parent row carries a monotonic `state_version`. A coordinator locks the parent,
revalidates the CAS snapshot, trusted roster, every node, and every dependency,
checks the caller's expected version, and updates with a version-guarded statement.
Every successful transition increments the version once. Stale concurrent callers
fail; they cannot silently skip cancellation or mutate topology.

Cancellation is linearized by the parent database row and version, not timestamps.
The winning cancellation transaction sets `cancel_requested`, advances lifecycle
and version, and records `cancel_requested_at` only as audit metadata. S6B result
acceptance must lock this same row and reject if cancellation already won.

## Deadline and restart boundary

`deadline_at` is a finite, timezone-aware caller value normalized to UTC. S6A does
not choose a production duration; a future trusted submission boundary supplies
it. Deadline is included in idempotent request correlation but excluded from the
planning snapshot and node IDs.

After restart, a fresh service opens the database and CAS, reloads canonical bytes
by exact digest and size, reconstructs the typed profile/plan/roster/topology, and
compares those values with every durable row. Current filesystem state and in-memory
objects are neither required nor trusted.

## Explicit exclusions

S6A provides no scanner execution, OSV network operation, process supervisor,
PID/process-group receipt, containment cleanup, Job, ToolExecution, attempt/result
table, retry, native artifact acceptance, S4 assembly, completeness decision,
public report, or API behavior change. In particular, S6A does not solve local child
or descendant survival after worker death. Retry remains unsafe until S6B proves
containment reconciliation.
