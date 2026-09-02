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
| v0.3F2E1 | Real-world Python CVE discovery and upstream pinning | COMPLETE |
| v0.3F2E2 | Real-world Python CVE claim applicability | COMPLETE |
| v0.3F2E3 | Controlled real-world Python SAST evaluation | PROVISIONAL - SUPERSEDED |
| v0.3F2E4 | Production rule-claim contract reconciliation | COMPLETE |
| v0.3F2E5 | Corrected controlled real-world Python SAST evaluation | COMPLETE |
| v0.3F2F | Final Python SAST maturity decision | COMPLETE |
| v0.3F2 | External pinned Python SAST validation | COMPLETE |

### Source Gitleaks Integration

| Version | Capability | Status |
|---|---|---|
| v0.4A | Gitleaks trusted binding and current-snapshot execution contract | COMPLETE |
| v0.4B | Gitleaks Source execution lifecycle integration | COMPLETE |
| v0.4C | Defensive Gitleaks parsing and secret-safe normalization | COMPLETE |

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

v0.3F adds a deterministic, controlled project-owned handcrafted local benchmark corpus and
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

At the v0.3F1 checkpoint, methodology and metric review remained pending. The
benchmark harness does not automatically promote maturity or encode production
thresholds. The later completed review retained `PYTHON_SAST` at `SCANNABLE`.

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
together. The evaluation does not promote maturity: `PYTHON_SAST` remains
`SCANNABLE`.

OWASP BenchmarkPython pull request 6 is represented as known cross-category
XSS contamination in 33 deserialization files, not as a dispute of their
published CWE-502 labels. The original CWEs and vulnerable/safe labels remain
accepted, while the affected cases are explicitly excluded from later scoring
pending applicability review.

v0.3F2E1 uses a pinned PySASTBench `RealworldDataset.csv` only as a discovery
index and supplements it with independent official-advisory and original
upstream evidence. Prior scanner-result columns are forbidden from selection.
The large source archive is not acquired, PySASTBench repository copies are not
used, and original upstream Git repositories remain authoritative in an ignored
cache. The canonical ledger retains every reviewed seed, including explicit
deferrals, while the accepted lock requires exact vulnerable/fixed revisions,
license identity, bounded relevant Python source hashes, and fix provenance.

F2E1 performs source acquisition only. It does not execute acquired code,
Semgrep, or SecureScan. The frozen F2D synthetic results did not influence case
selection.

v0.3F2E2 performs a location-aware, scanner-independent applicability review of
all 13 F2E1 CVEs against only the frozen human-readable claim catalog. Same-CWE
similarity is insufficient: each vulnerable and fixed region is independently
bound to its F2E1 path, revision role, and source hash. A fixed revision may
legitimately remain claim-positive for a dangerous-API observation.
`OUTSIDE_FROZEN_RULE_CLAIMS` records legitimate CVEs whose implementation is
outside the current rule semantics; those cases are not future false negatives.
F2E2 did not execute Semgrep or SecureScan and produced no metrics. Its approved
proposal is an immutable historical v1 record, not the expectation input for a
corrected execution. Historical v1 classified six CVEs as applicable and seven
outside, with six relations, 12 revision expectations, and three of 17 rules
represented. At the F2E2 checkpoint, `PYTHON_SAST` remained `SCANNABLE` and
v0.3F2 was not yet complete.

The provisional F2E3 execution exposed drift between the historical v1 claim
prose and the frozen production patterns. Those metrics are superseded and not
frozen evidence. F2E4 leaves the production Semgrep rules byte-identical,
preserves the historical v1 claim/applicability artifacts, and records a
versioned 17-rule conformance audit plus corrected claim contract v2.

Applicability v2 was regenerated scanner-blind from the frozen F2E1 Git blobs.
It does not import the evaluation implementation and cannot read the provisional
F2E3 report or review. Its explicit v1-to-v2 delta independently reclassifies
CVE-2023-40581 because the vulnerable revision uses
`subprocess.call(..., shell=True)` and the fixed revision removes that frozen
pattern. Current v2 applicability reviews 13 CVEs: seven are applicable, six
are outside, and zero are unresolved. Seven relations produce 14 revision
expectations—11 expected-positive and three expected-negative—with three
`SHOULD_DISCRIMINATE` and four `NOT_EXPECTED_TO_DISCRIMINATE`. Four of 17 rules
are represented: `dangerous-eval`, `os-system`, `subprocess-shell-true`, and
`unsafe-pickle-load`.

F2E5 is the authoritative corrected execution against the frozen F2E4 v2
claim and applicability inputs. It scans only the F2E1-bounded source
projection with the pinned local Semgrep CE 1.171.0 executable and unchanged
production rules. The historical F2E3 metrics remain provisional and
superseded; they are not current evidence. The F2E5 evidence covers 13 CVEs and
26 revisions, with seven claim-applicable relations and 14 revision
expectations. Its claim-conformance matrix is TP/FP/FN/TN `11/0/0/3`; all seven
applicable vulnerable CVEs were detected, all three discrimination pairs
succeeded, and all four expected-persistent pairs persisted. These results
apply only to this frozen claim-applicable case set, not universal Python SAST
accuracy. F2E5 is complete. At its freeze, `PYTHON_SAST` remained `SCANNABLE`,
the v0.3F2 parent had not yet been closed, and the maturity decision belonged to
F2F.

F2F aggregates the frozen F1, F2D, F2E4, and F2E5 evidence without executing
Semgrep or changing production behavior. The final evidence decision retains
`PYTHON_SAST` at `SCANNABLE`: deterministic execution and bounded rule behavior
are evidence-backed, but only four of 17 rules currently have applicable
real-world CVE evidence. F2D remains valid for its frozen historical-v1
expectations and is not presented as complete proof of current production
semantics. Perfect results on the bounded corpora do not establish universal
Python SAST accuracy or comprehensive vulnerability coverage. F2F is complete;
`PYTHON_SAST` remains `SCANNABLE`, and its maturity decision is frozen.

## Gitleaks v0.4A Boundary

v0.4A binds the existing `SECRET_DETECTION` capability to a deterministic,
pre-provisioned Gitleaks 8.30.1 Linux x64 executable and a project-owned
configuration that extends that version's built-in defaults. It introduces no
parser, normalized findings, benchmark, scoring, reporting integration, or
planner registration, so the capability remains `DETECTED`.

Gitleaks scans the immutable current source snapshot only. The fixed contract
uses Gitleaks `dir`; the separate history-oriented `git` mode and all Git-log,
remote-clone, and network-acquisition behavior are unavailable through this
binding. Production scans do not download or install tooling, execute repository
code, or invoke Git against an acquired repository.

Raw secret material must not be logged, included in API or exception text, used
as finding identity, placed in metrics labels, or included directly in
provenance digests. A detected secret is evidence of secret-like material in
source, not proof that the credential is currently valid, exploitable, or
active. Provider validation, revocation, and rotation are outside Source v1.

The exact official Gitleaks 8.30.1 Linux x64 binary passed the deterministic
positive and empty-directory functionality sentinel under this command
contract: `PINNED_BINARY_FUNCTIONALITY_SENTINEL_PASS`. This is a tool
functionality check, not benchmark, scoring, or maturity evidence.

## Gitleaks v0.4B Execution Boundary

v0.4B descends from the frozen `source-v0.4A-gitleaks-binding` baseline at
`6f8e5002e14385e095af8784a91afc4a1618b017`. It resolves the existing durable
Source execution context and reopens its C2 immutable projection through the
authoritative projection manager before the frozen v0.4A binding may launch
Gitleaks. Callers cannot supply a filesystem path, remote target, Git revision,
or scanner option through this bridge.

The bounded process result distinguishes completed scans with no findings
(exit 0), completed scans with opaque findings present (exit 1), scanner
failure, cancellation, timeout, and output-limit exhaustion. Exit 1 is a
successful completed scan at this layer. No JSON fields are inspected and no
finding count or normalized finding is produced in v0.4B.

Raw stdout and stderr remain opaque sensitive bytes in an immutable in-memory
result envelope for the future parser boundary. They are not logged, placed in
exception or job-failure text, written to generic database fields, or persisted
to the generic artifact store. v0.4B adds no protected raw-output persistence;
v0.4C must either consume the envelope in-process or introduce an explicitly
protected scanner-evidence boundary.

The shared cancellable process handle supplies graceful termination followed by
the existing force-kill path. Incomplete output from cancellation, timeout,
forced termination, or output-limit exhaustion cannot be classified as clean.
The existing durable Source projection lifecycle retains projections while jobs
are non-terminal and authorizes cleanup only after terminal durable job truth,
including success, failure, cancellation, and timeout failure. Secret detection
remains `DETECTED`; this checkpoint is execution integration, not quality
evidence or maturity promotion.

## Gitleaks v0.4C Parsing Boundary

v0.4C descends from `source-v0.4B-gitleaks-source-execution` at
`4ac76be1ff8b2e2d9081cde4f689c5dae1808080`. Its parser schema is
`securescan-gitleaks-parser-v0.4C`. Parsing is permitted only for completed
v0.4B envelopes: exit 0 must decode to an empty JSON array, while exit 1 must
decode to one or more valid findings. Failed, cancelled, timed-out,
output-limited, malformed, or contradictory results fail closed with fixed
messages.

The minimum required Gitleaks fields are `RuleID`, `File`, and `StartLine`.
`EndLine`, columns, `Description`, `Tags`, `Entropy`, `Secret`, `Match`,
`SymlinkFile`, `Fingerprint`, and history-related fields are optional but, when
present, must have their expected bounded types. Unknown fields are rejected.
The observed Gitleaks 8.30.1 `--redact=100` representation is exactly
`Secret: "REDACTED"`; any other present value is rejected. `Match` is treated
as sensitive regardless of its content and is type-checked but discarded.

The normalized intermediate finding contains only scanner identity, detector
rule ID, manifest-authorized repository-relative path, validated line/column
location, and projection/context digests. Description, tags, entropy,
fingerprint, symlink metadata, Git/history metadata, `Secret`, and `Match` are
validated where applicable but deliberately omitted. Absolute scanner paths
are accepted only after a lexical proof that they are inside the trusted
projection root; the normalized result contains only the matching manifest
path. Projection files are reopened without following a final symlink and are
checked against their frozen size and digest before location validation.

The exact Gitleaks 8.30.1 built-in configuration contains one path-only rule:
`pkcs12-file`, with path syntax `(?i)(?:^|/)[^/]+\.p(?:12|fx)$` and no content
regex. (`nuget-config-password` is the only other built-in rule with a `path`
property, and it also has a content regex.) The parser therefore freezes the
complete path-only rule-ID set as `{pkcs12-file}`. A finding for that rule is
accepted only for a manifest-authorized `.p12` or `.pfx` path with the exact
scanner location shape `StartLine=0`, `EndLine=0`, `StartColumn=0`, and
`EndColumn=0`; the normalized finding records `detection_kind=PATH` and all
four normalized location fields as null. All other rules remain `CONTENT` and
retain positive bounded line/column validation. Unknown zero-location rules,
mixed zero/nonzero shapes, and nonzero `pkcs12-file` locations fail closed.

Gitleaks 8.30.1 declares optional `Link` and `Fragment` fields on its report
finding type. The frozen `dir` producer cannot create `Link` because filesystem
fragments have no Git commit metadata, and the detector does not assign
`Fragment`; both fields remain rejected as unreachable scanner states rather
than broadening the trusted parser schema.

The parse result contains no raw stdout or stderr and is safe to represent.
Raw bytes remain only in the caller-owned v0.4B envelope and are not copied to
generic artifacts, database fields, normalized evidence, or errors. Normal
downstream flow should release that envelope after parsing; Python does not
provide guaranteed byte-buffer zeroization. Duplicate scanner observations are
preserved in input order, with no v0.4C identity or deduplication policy.
`SECRET_DETECTION` remains `DETECTED`.

## Known Non-Blocking Maintenance

FastAPI/Starlette emits the existing TestClient/httpx deprecation warning.

## Environment-Gated Tests

Some tests may skip when supporting services or tools are unavailable,
including Docker, PostgreSQL, Semgrep, and strict release environments.
