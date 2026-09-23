# SecureScan Source V1.1B1 project navigation

## Scope

V1.1B1 is a read-only Product Core/API slice for navigating:

```text
Projects -> Project -> Project scan history -> Scan
```

It also provides a recent-scans view across projects. It does not add a new
frontend, run-stage projection, suppression, triage, or any scanner/evidence
semantic change.

## Public endpoints

| Endpoint | Result |
|---|---|
| `GET /v1/projects` | Bounded page of recent projects |
| `GET /v1/projects/{project_id}` | One durable project identity |
| `GET /v1/projects/{project_id}/scans` | Bounded scan history for one known project |
| `GET /v1/scans` | Bounded recent scans across projects |

The existing `GET /v1/scans/{run_id}` and all existing finding, component,
dependency, coverage, gap, report, submission, and cancellation operations are
unchanged.

Project responses contain only `project_id`, `name`, and `created_at`. Scan-list
items contain safe Product Core identifiers, product status, durable timestamps,
and the established indexing/lifecycle completion flags. They intentionally omit
report reconstruction and finding aggregates; the existing per-run endpoint
remains the detailed summary contract.

A public Source scan is an analysis run with a canonical managed Source
submission, Source orchestration, Source-repository target, and Source lineage
whose project and managed-intake identities agree. Generic, legacy, fake, and
non-Source analysis runs are outside this collection.

## Pagination and ordering

Both collections use `limit` and `offset`, return the exact `total`, `limit`, and
`offset`, and accept limits from 1 through 200 with non-negative offsets. The
default limit is 50. An offset beyond the result set returns an empty `items`
array with the unchanged total.

Projects are ordered by `ProjectRow.created_at DESC`, then `project_id DESC`.
The existing `SourceProjectService.list(limit)` CLI ordering is preserved.

Scans are ordered by `AnalysisRunRow.created_at DESC`, then `run_id DESC`.
Project history applies the project predicate before counting and paging. A known
project with no scans returns 200 with an empty page; an unknown project returns
404.

This ordering is deterministic for a stable dataset. Offset pagination is not a
snapshot or cursor guarantee: a concurrent insertion between page requests can
shift later offsets. V1.1B1 does not add cursor pagination.

The scan page is assembled with a fixed small number of bulk SQL statements: a
count, one joined page read, and, only when required, one bulk predecessor read.
Project-filtered history adds one project-existence read so an unknown project
remains distinct from a known empty project. It never calls the detailed per-run
query once per item.

## Truth and security boundaries

List status derives from the same persisted orchestration, publication,
finalization, indexing, and lifecycle material used by the existing detailed
scan summary. A running or unpublished scan is not represented as clean, and
unknown result aggregates are not converted to zero.

The navigation responses do not expose host paths, runtime roots, database
configuration, credentials, scanner executable paths, process details, command
lines, raw scanner output, source content, jobs, orchestration nodes, tool
executions, or content-addressed storage paths.

Browser/API clients can now discover projects and runs. They still cannot submit
arbitrary host filesystem paths. Repository submission remains the trusted-host
`securescan scan` CLI workflow in this phase. Existing evidence and scanner
semantics are unchanged.
