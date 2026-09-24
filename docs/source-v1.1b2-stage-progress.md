# SecureScan Source V1.1B2 stage progress

## Scope

V1.1B2 adds one read-only Product Core/API projection:

```text
GET /v1/scans/{run_id}/stages
```

It translates the existing durable planning, orchestration, publication, and
coverage truth into one stable product stage per trusted authority/capability.
It does not add a mutation, change scanner execution, alter coverage semantics,
or require a database migration.

## Public contract

The response contains the run identifier, established Product Core status,
publication and finalization timestamps, and the complete frozen Source v1 stage
roster. Each stage contains only:

```text
authority
capability
progress_state
coverage_states
reason_code
```

The public progress vocabulary is deliberately smaller than the orchestration
engine vocabulary:

```text
PENDING
WAITING
RUNNING
COMPLETE
PARTIAL
NOT_APPLICABLE
FAILED
CANCELLED
```

`PLANNED`, `READY`, and `QUEUED` project to `PENDING`.
`WAITING_DEPENDENCY` projects to `WAITING`. `RUNNING`, `RETRY_PENDING`, and
`RECONCILIATION_REQUIRED` project to `RUNNING`. Terminal dispositions project to
the corresponding product result, with `BLOCKED_BY_DEPENDENCY` represented as
`FAILED` plus a safe normalized reason.

`WAITING` is not failure. In particular, OSV can be `WAITING` for Syft package
inventory while other scanners continue. `NOT_APPLICABLE` is also not failure.

## Planning and multiple-node truth

The endpoint derives its complete five-stage roster from the validated planning
snapshot and trusted authority roster; it does not list raw orchestration rows or
invent a second roster. A capability legitimately omitted by planning remains
visible as `NOT_APPLICABLE`. If a node expected by the validated snapshot is
missing, or durable topology disagrees with planning, the query fails safely.

Several component-scoped nodes may belong to one authority/capability. They are
reduced to exactly one progress stage using the existing parent-terminal
semantics as the consistency boundary: active work takes precedence over waiting,
waiting over pending, and incomplete terminal mixtures remain visible as
`PARTIAL` or `FAILED`. Internal node counts and identities are not exposed.

## Published coverage

Progress and published coverage are independent dimensions:

```text
coverage_states = null
```

means no authoritative published coverage is available yet.

```text
coverage_states = []
```

means a published report exists but contains no coverage outcome for that
stage. The endpoint does not synthesize `NOT_APPLICABLE` coverage from planning.

When outcomes exist, `coverage_states` is the sorted, unique tuple of their exact
published states. Mixed framework or component outcomes are preserved as a set
of states and are never collapsed into an invented worst-state result. The
detailed `GET /v1/scans/{run_id}/coverage` endpoint remains authoritative and is
unchanged.

## Safety and performance

Only explicitly allowlisted product reason codes can be returned. Raw scanner
failures, exception text, job or attempt identifiers, node identifiers, process
state, paths, commands, digests, artifact references, source content, stdout,
stderr, and database configuration are excluded.

Malformed UUIDs are rejected by API validation. Unknown and non-Source runs
return 404. Persistence, planning, report, or topology integrity failures return
a generic 503 response.

The projection uses bounded reads for one run: validated planning is loaded once,
nodes are read in bulk, and a published report is reconstructed once. It performs
no SQL query or artifact read per node.
