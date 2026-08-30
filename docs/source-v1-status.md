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

## Next Phase

Source v0.3C execution integration remains deferred. v0.3B2 does not execute
plan entries, project selected paths, create findings, or claim actual Source
coverage, benchmarked support, or product support.

## Known Non-Blocking Maintenance

FastAPI/Starlette emits the existing TestClient/httpx deprecation warning.

## Environment-Gated Tests

Some tests may skip when supporting services or tools are unavailable,
including Docker, PostgreSQL, Semgrep, and strict release environments.
