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
| v0.3D | Source Semgrep result + actual coverage correlation | COMPLETE |
| v0.3E | Production Python SAST ruleset | COMPLETE |
| v0.3F1 | Controlled local Python SAST benchmark | COMPLETE |
| v0.3F2A | External benchmark methodology/source selection | COMPLETE |
| v0.3F2B | Pinned external candidate acquisition | COMPLETE |
| v0.3F2C | Claim-aligned external applicability review | COMPLETE |
| v0.3F2D | Controlled external Python SAST evaluation | COMPLETE |
| v0.3F2 | External pinned Python SAST validation | IN PROGRESS |

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

v0.3D derives a frozen Source capability execution assessment from durable
state only: the terminal job, its C1 context artifact, the canonical run
report, and the tool execution identified by the job's final attempt number.
It adds no assessment table or database migration, requires no retained C2
projection, and performs no scanner execution, workspace preparation,
repository inspection, profiling, planning, or support rediscovery. The
current one-Source-job-per-run submission model is enforced when correlating
the durable run aggregate; multi-job Source assessment is not generalized in
this checkpoint.

`FULL_FOR_DECLARED_SCOPE` means the trusted analyzer completed over the
entire exact filesystem scope authorized by that Source plan entry without
SecureScan-reported analysis gaps. It does not mean the repository is
vulnerability-free, that all execution paths were analyzed, or that Semgrep
has 100% recall. It is categorical execution coverage, not a numeric semantic
coverage or security score.

Zero observations with `FULL_FOR_DECLARED_SCOPE` means only that this analyzer
produced no observations for its declared scope in this execution. It is not a
"clean repository" or "secure repository" claim. Observations remain scanner
findings requiring triage, and automated assessments remain
`OBSERVATIONS_ONLY`.

Completed-result assessment authenticates and validates the original durable
C1 context but does not require today's scanner binding to equal the historical
binding. The original binding digest and final durable tool version remain in
the reconstructed assessment. The report ruleset ID/version must also exactly
match the identity embedded in its content-addressed sanitized Semgrep artifact;
cross-version report metadata substitution fails assessment integrity.
Authorization for a new execution continues to require the current trusted
binding and rejects a mismatch.

v0.3E replaces the three-rule demonstration baseline with 17 deterministic,
project-owned Python rules. The compact ruleset covers direct Python code
execution, dangerous shell command forms, unsafe pickle and YAML
deserialization, disabled TLS and host-key verification, insecure temporary
filenames, Flask debug exposure, disabled Jinja autoescaping, f-string SQL
execution, disabled JWT signature verification, and XML external-entity
resolution. Every rule has a dedicated vulnerable fixture, safe fixture, and
adversarial near-miss fixture; these are correctness checks, not a detection
quality benchmark.

The `eval`, `exec`, `os.system`, `os.popen`, and pickle rules are dangerous-API
audit matches. They do not claim that matched input is attacker-controlled;
v0.3E adds no taint or dataflow analysis. The YAML rule matches only
`yaml.unsafe_load` and explicitly named `Loader`, `UnsafeLoader`, or `CLoader`
forms. `safe_load`, `SafeLoader`, and `CSafeLoader` are negative cases, while
`FullLoader` is intentionally unclassified by this rule.

The trusted ruleset identity is `securescan-python-baseline-v2`, version `2`.
Rules use only fixed messages, supported severity values, and CWE metadata;
there are no autofixes or network-resolved configurations. `PYTHON_SAST`
remains `SCANNABLE`. v0.3E makes no precision, recall, F1, benchmarked, or
product-support claim.

v0.3F adds a deterministic, controlled independent local benchmark corpus and
evaluation harness for the frozen v0.3E ruleset. The corpus is separate from
the 51 v0.3E correctness fixtures and contains 102 explicit case/rule
relations: three positive and three negative cases for each of the 17 rules.
Its content and ground truth are identified by corpus digest
`2a3b3a3b001ce251a5fceafc82cfd1a1599cd9d8d3d6a81de424ae393113adec`.

Valid controlled evidence requires scanner `semgrep-ce`, declared engine
version `1.171.0`, and `securescan-python-baseline-v2` version `2` with digest
`e10fb04e6b5abb35e0b83bdd718c2e973a8026e3630e420dc398db95e59d01a5`.
The earlier local `1.145.0` observation is preserved separately as uncontrolled
history; it measured TP/FP/FN/TN `51/0/0/51`, with precision, recall, and F1
each `1.0000`, and no cross-rule matches. The separately recorded controlled
`1.171.0` baseline produced the same `51/0/0/51` and `1.0000` results, with
scanner identity embedded in the canonical report. Those measurements apply
only to this corpus. This is not a public-corpus, ecosystem-wide,
taint/dataflow, production-accuracy, or production-readiness benchmark.

## Next Phase

v0.3F remains pending methodology and metric review. The benchmark harness does
not automatically promote maturity or encode production thresholds.
`PYTHON_SAST` remains `SCANNABLE`.

v0.3F2A selects OWASP BenchmarkPython and the BenchProctor Python quicktest
bundle as complementary external synthetic sources. v0.3F2B pins and
authenticates their immutable source identities, parses their external ground
truth, and commits only a deterministic candidate inventory and count summary.
External code remains in an ignored cache and is not vendored.

v0.3F2C establishes a proposed claim relation before scanning by independently
inspecting Python syntax and semantic API identities against a human-reviewable
catalog of the 17 frozen claims. CWE overlap alone is insufficient. Dangerous
API observation claims are distinct from vulnerability-pattern claims, so an
arbitrary safe-labeled case that still uses an audited API is not converted into
a negative. Ambiguous, shadowed, multi-claim, or unparsable cases remain
unresolved and unscored; the 33 known-contaminated cases remain excluded. Every
non-excluded proposal remains pending hostile/human approval.

v0.3F2D evaluates all 1,460 frozen candidates with only the isolated Semgrep CE
1.171.0 executable and the unchanged production v2 ruleset. The F2C
expectations were frozen before scanner execution. Only the 400 applicable
positive and 179 applicable negative relations enter the 579-relation confusion
matrix. Findings on 848 OUT_OF_SCOPE and 33 EXCLUDED candidates are retained as
separate non-scoring observations, as are unexpected cross-rule relations.

This external corpus is synthetic. Rules without external positive or negative
evidence remain explicitly unvalidated even though all 17 frozen rules execute
together. PySASTBench and any real-world CVE challenge remain later work. The
evaluation does not promote maturity: `PYTHON_SAST` remains `SCANNABLE`.

OWASP BenchmarkPython pull request 6 is represented as known cross-category
XSS contamination in 33 deserialization files, not as a dispute of their
published CWE-502 labels. The original CWEs and vulnerable/safe labels remain
accepted, while the affected cases are explicitly excluded from later scoring
pending applicability review.

PySASTBench remains deferred as a possible real-world CVE discovery/index source
only. Its 6.2 GB archive has not been acquired, and prior scanner-result columns
may not influence any later case selection. v0.3F2 is not complete.

## Known Non-Blocking Maintenance

FastAPI/Starlette emits the existing TestClient/httpx deprecation warning.

## Environment-Gated Tests

Some tests may skip when supporting services or tools are unavailable,
including Docker, PostgreSQL, Semgrep, and strict release environments.
