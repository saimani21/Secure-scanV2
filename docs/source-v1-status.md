# SecureScan Source Repository Analysis v1

## Current Status

### Core

Status: COMPLETE

### Source Intelligence Foundation

| Version | Capability | Status |
|---|---|---|
| v0.2.1 | Source contracts | COMPLETE |
| v0.2.2 | Repository inventory | COMPLETE |
| v0.2.3A | Trusted Enry helper | COMPLETE |
| v0.2.3B | Bounded process input | COMPLETE |
| v0.2.3C | Trusted Enry protocol/client | COMPLETE |
| v0.2.3D1 | Language profiling | COMPLETE |
| v0.2.3D2 | Evidence enrichment | COMPLETE |
| v0.2.4 | Component detection | COMPLETE |
| v0.2.5A | Support policy and language support | COMPLETE |
| v0.2.5B | Capability surfaces and RepositoryProfile | COMPLETE |
| v0.2.6 | Deterministic Source analysis planner | COMPLETE |

### Source Semgrep Integration

| Version | Capability | Status |
|---|---|---|
| v0.3A | Semgrep architecture audit | COMPLETE |
| v0.3B1 | Semgrep confidentiality hardening | COMPLETE |
| v0.3B2 | Trusted Source Semgrep analyzer | COMPLETE |
| v0.3C0 | Source/Semgrep bridge audit | COMPLETE |
| v0.3C1 | Durable execution context | COMPLETE |
| v0.3C2 | Deterministic selected-file projection | COMPLETE |
| v0.3C3 | Trusted projection → Semgrep execution bridge | COMPLETE |
| v0.3C4 | Terminal projection lifecycle + hostile bridge validation | COMPLETE |

## Source Intelligence Foundation Freeze

Source v0.2.6 is the frozen repository-intelligence foundation.

Pre-Git project fingerprint:

56a33c326d33cbdcaea42e040bb2869f920eb1d3fb20618a62b22cef5611fb58

## Pipeline

Repository intake
→ immutable workspace
→ repository inventory
→ language profiling
→ evidence enrichment
→ component detection
→ support policy
→ capability surfaces
→ RepositoryProfile
→ deterministic SourceAnalysisPlan

## Important Truth Boundaries

Applicability, support maturity, analyzer availability, planning,
execution, observations, findings, and actual coverage are distinct states.

A planned RUN entry does not prove execution succeeded.

Zero findings does not prove absence of vulnerabilities.

## Analyzer Registry

At the v0.2.6 foundation freeze, the production Source analyzer registry
was intentionally empty. v0.3B2 adds a trusted `python-semgrep-v1`
declaration that can populate an immutable availability snapshot only after
the exact Core adapter binding, ruleset provenance, Docker runtime, and local
digest-pinned image are verified.

Planned scanners are not considered registered or product-supported
until their adapter acceptance and benchmark gates pass.

## Durable Execution Context

v0.3C1 preallocates the run and job UUIDs, writes the immutable canonical
context to content-addressed storage, and then commits the run, job, fixed
adapter, target-digest check, and reserved context reference in one existing
database transaction. No schema migration is required because the job payload
reference is committed atomically with the job. A database failure can leave
only an unreferenced content-addressed object; it cannot publish a job without
its context reference.

The public job boundary rejects the reserved internal payload namespace. A
trusted resolver verifies the artifact, context digest, durable job identity,
and current Semgrep binding before returning the typed context.

Source submission retries derive domain-separated UUIDv5 run and job
identifiers from the idempotency key. These UUIDs are stable identifiers, not
secrets or authorization. Identical retries reproduce the same canonical
context and content address, so the artifact store reuses the existing object;
the existing exact submission comparison still rejects changed semantics.

v0.3C2 materializes the exact approved selected-file identities into a
separate durable, read-only scanner-visible source tree. Its independently
verified manifest and projection digest enforce scope without repository
ignore/config behavior. The trusted Settings boundary normalizes the configured
projection root to an absolute path. A new root is created privately and marked
as a dedicated SecureScan projection root; every manager construction requires
the exact root marker, private root and marker permissions, single-link marker,
and current effective-user ownership where POSIX exposes it. Existing unmarked
directories and marked roots with incorrect permissions are rejected without
permission repair. v0.3C2 does not execute Semgrep or Docker.

v0.3C3 connects a validated durable Source job and its exact C2 projection to
the existing trusted Semgrep execution path. Each attempt reopens and
reinventories the durable projection, correlates it with the frozen C1 context
and current trusted binding, then creates a fresh identity-preserving Semgrep
attempt workspace. This repository does not yet contain a production worker
startup/registry composition module. Its trusted C3 composition seam is
`create_source_aware_semgrep_trusted_definition`: any worker registry that can
lease Source jobs must register the definition returned by that helper. The
adapter itself fails closed if a reserved Source envelope reaches a definition
without the Source-aware resolver, preventing miscomposition from falling back
to mutable generic input. The fixed reference baseline ruleset is the only
scanner configuration. Selected `.semgrepignore` and `.gitignore` files are
conservatively rejected before Docker, while unselected ignore, vendor, and
test files never enter the attempt workspace.

v0.3C4 ensures durable Source projections remain available through retry and
lease windows and become cleanup-eligible only after durable terminal job
commitment. Projection cleanup failure is operational lifecycle state and does
not rewrite an already committed analysis result. A trusted terminal observer
provides best-effort immediate cleanup, while the same lifecycle service can
reconcile a durable terminal job after worker restart. Reconciliation is
given only job identity and re-fetches status, payload, run, and adapter truth
from the job repository before authorizing cleanup. It does not sweep
unreferenced filesystem directories; garbage collection for a crash before DB
publication remains deferred to deployment or bounded maintenance design.

v0.3C4 does not yet calculate actual Source coverage or promote `PYTHON_SAST`
maturity.

## Next Phase

Source coverage/result aggregation remains deferred to v0.3D. v0.3C4 does not
claim actual Source coverage, benchmarked support, or product support.

## Known Non-Blocking Maintenance

FastAPI/Starlette emits the existing TestClient/httpx deprecation warning.

## Environment-Gated Tests

Some tests may skip when supporting services or tools are unavailable,
including Docker, PostgreSQL, Semgrep, and strict release environments.
