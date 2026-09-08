# Source v0.8 S6C-A dependency evaluation

S6C-A is the durable, network-free release decision between an accepted Syft
native result and future OSV execution. It does not create the OSV Job or invoke
OSV.

The evaluator locks the parent orchestration first, then validates the exact
S6A OSV-to-Syft edge, selected accepted Syft attempt, clean containment, trusted
scanner/analyzer/binding/context/projection identities, and content-addressed
native result. It reconstructs advisory scope solely from canonical `RUN`
entries for `dependency_advisory_matching` and requires the result to equal the
OSV node's frozen paths and scope digest.

Each immutable Syft `PackageObservation` is classified using its complete
location set:

- `IN_SCOPE`: every location is in the planned advisory scope.
- `OUTSIDE_SCOPE`: no location is in the scope.
- `MIXED_SCOPE`: some, but not all, locations are in scope.

Mixed observations are excluded whole and recorded as
`MIXED_SCOPE_PACKAGE_OBSERVATION`; they are never split or rewritten. Only
unchanged in-scope observations reach the frozen S2 candidate builder.

One canonical artifact using schema
`securescan-source-dependency-evaluation-s6c-v1` and media type
`application/vnd.securescan.source-dependency-evaluation+json` binds the scope,
Syft prerequisite, classification, mixed gaps, eligible observation IDs,
candidate IDs, coordinate gaps, decision, and coverage limitation. Exactly one
durable row may reference that artifact for each OSV node/run.

The only node transitions are `WAITING_DEPENDENCY` to `READY`, or to terminal
`NOT_APPLICABLE`/`PARTIAL`. Complete zero-package evidence is
`NO_PACKAGES_OBSERVED`; outside-scope-only evidence is
`NO_PACKAGES_IN_ADVISORY_SCOPE`; unsupported-only evidence is
`NO_SUPPORTED_OSV_COORDINATES`; mixed-only evidence is
`MIXED_SCOPE_PACKAGE_OBSERVATION`. An accepted partial Syft result is explicitly
recorded as incomplete and always limits coverage.

S6C-A never reads repository files, calls OSV, creates an OSV `Job` or
`ToolExecution`, modifies `AnalysisRun.report_json`, or assembles S4 evidence.
OSV transport, request permits, cancellation, retries, and deadline termination
remain S6C-B/S6C-C work.
