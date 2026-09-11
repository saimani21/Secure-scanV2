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
| v0.4D | Gitleaks applicability, Source support, and planning integration | COMPLETE |
| v0.4E | Stable secret-safe Gitleaks finding identity | COMPLETE |
| v0.4F1 | Gitleaks benchmark contract and manifest model | COMPLETE |
| v0.4F2 | Deterministic Gitleaks pre-scan corpus and manifest | COMPLETE |
| v0.4F3A | Controlled Gitleaks benchmark evaluator and production-path harness | COMPLETE |
| v0.4F3B | Initial controlled Gitleaks benchmark baseline | COMPLETE |
| v0.4F4A | Gitleaks adversarial characterization contract and corpus | COMPLETE |
| v0.4F4B1 | Controlled Gitleaks adversarial evaluator and runner | COMPLETE |
| v0.4F4B2 | Initial controlled Gitleaks adversarial characterization | COMPLETE |
| v0.4F4C | Gitleaks limitation, coverage, confidentiality and failure characterization | COMPLETE |
| v0.4F5A | Gitleaks bounded real-world evaluation contract | COMPLETE |
| v0.4F5B1 | Gitleaks real-world acquisition policy and manifest schema | COMPLETE |
| v0.4F5B2 | Gitleaks real-world repository selection | COMPLETE |
| v0.4F5B2R1 | Gitleaks real-world selection compatibility correction | COMPLETE |
| v0.4F5B2R2 | Gitleaks consolidated acquisition-compatible repository selection | COMPLETE |
| v0.4F5B3 | Gitleaks real-world bounded acquisition and snapshot freeze | COMPLETE |
| v0.4F5C | Gitleaks real-world first execution | COMPLETE |
| v0.4F5D | Gitleaks real-world repeatability characterization | COMPLETE |
| v0.4F6 | Gitleaks final evidence and maturity reconciliation | COMPLETE |

`GITLEAKS TARGET-1 INTEGRATION: COMPLETE`

`SECRET_DETECTION = SCANNABLE`

### Source Syft Package Inventory

| Version | Capability | Status |
|---|---|---|
| S1 | Pinned Syft current-snapshot package/component inventory | COMPLETE |

`PACKAGE_INVENTORY = SCANNABLE`

### Source OSV Dependency Intelligence

| Version | Capability | Status |
|---|---|---|
| S2 | OSV advisory matching and dependency vulnerability findings | COMPLETE |

`DEPENDENCY_ADVISORY_MATCHING = SCANNABLE`

Source v0.5 dependency intelligence is complete for its defined current-snapshot scope.
The S2 boundary consumes frozen Syft package evidence, queries exact versioned PURLs via
the bounded OSV v1 service client, validates full records against the frozen OSV 1.9.0
schema, groups alias-equivalent records per package, and emits deterministic findings.
Its controlled public-service snapshot replays offline. Online operation discloses
package coordinates to `api.osv.dev`, but never repository file contents; no OS-level
egress sandbox is claimed. See `docs/source-v0.5-dependency-intelligence.md`.

### Source Checkov Configuration Security

| Version | Capability | Status |
|---|---|---|
| S3 | Pinned Checkov source-native IaC/configuration security | COMPLETE |

`CONFIGURATION_SECURITY = SCANNABLE`

Source v0.6 S3 adds pinned Checkov 3.3.16 source-configuration analysis for
exactly Terraform, CloudFormation, Kubernetes, Dockerfile, and GitHub Actions.
The scanner receives only the frozen Source projection, an absolute
SecureScan-owned configuration, an empty child environment, and explicit
local/offline CLI controls. Repository `.checkov.yml`, `.checkov.yaml`, and
`.checkov.baseline` files are excluded from the scanner projection and cannot
alter the trusted command.

The frozen runtime identity is CPython 3.12.3 plus 97 exact hash-locked Python
distributions. Launcher hashes are local path-specific integrity guards, not the
portable scanner identity. Variable evaluation is disabled. Fifteen narrowly
identified direct secret-material policies are denied to preserve Gitleaks authority;
secret-management configuration controls remain enabled.

The defensive parser retains normalized active findings, inline suppression
evidence, framework completion aggregates, and explicit parsing gaps. It does
not retain raw JSON, code blocks, evaluated variables, connected-node data, or
absolute host paths. The controlled project-owned corpus confirms one selected
fail/pass policy relation for each framework, one suppression, and one
malformed-input gap; it is not a broad accuracy benchmark. Checkov secrets,
SCA, images, Terraform plans, Helm, Kustomize, external modules, custom policies,
and Prisma Cloud operation remain outside S3. SecureScan configures local
operation but does not claim an OS-level egress sandbox. See
`docs/source-v0.6-configuration-security.md`.

### Source Unified Evidence

| Version | Capability | Status |
|---|---|---|
| S4 | Unified Source evidence representation | COMPLETE |

Source v0.7 S4 adds a deterministic, typed projection over the already
validated Semgrep, Gitleaks, Syft, OSV, and Checkov native models. It keeps
findings, evidence, logical components, suppressions, gaps, and coverage
outcomes distinct. Scanner-native identities remain authoritative and S4 IDs
are authority-qualified and run-independent. Package inventory remains
component/evidence data rather than a finding category.

Gitleaks native duplicate multiplicity is preserved explicitly without changing
stable finding identity. OSV-to-Syft support is package/projection/snapshot/
binding validated, coverage identity includes component and selected scope, and
Semgrep sanitized-artifact provenance is retained as safe metadata only.

S4 does not replace legacy `ScanReport` or any scanner-native result. It does
not add cross-engine merging, correlation, lifecycle, risk scoring, confidence,
API migration, or persistence changes. See `docs/source-v0.7-unified-evidence.md`.

### Source Multi-Engine Orchestration

| Version | Capability | Status |
|---|---|---|
| S6A | Durable multi-engine orchestration foundation | COMPLETE |
| S6B | Scanner execution and safe native results | COMPLETE |
| S6C-A | Syft-to-OSV dependency evaluation foundation | COMPLETE |
| S6C-B | Orchestrated OSV execution and request authorization | COMPLETE |
| S6C-C | Durable dependency and lifecycle coordination | COMPLETE |
| S6D | Deterministic S4 assembly and exactly-once publication | COMPLETE |
| PC1 | Logical Source lineage and atomic S4 finding occurrence index | COMPLETE |
| PC2 | Comparable-scope finding lifecycle and deterministic priority | COMPLETE |
| PC3A | Durable Source submission intent and trusted intake | COMPLETE |
| PC3B | Product finalization runner and Source read model | COMPLETE |
| PC3C | Public Source HTTP API | COMPLETE |
| PC3D | Local Source CLI | IMPLEMENTED - PENDING PRODUCT CORE APPROVAL |
| R1A/R1B | Source runtime composition and bounded worker cycle | IMPLEMENTED - PENDING CONTROLLED EXECUTION |

S6A adds one durable Source orchestration per AnalysisRun, an exact server-owned
five-authority roster, a canonical CAS planning snapshot, deterministic runnable
nodes, the Syft-to-OSV dependency edge, parent/node state vocabularies, monotonic
cancellation versioning, deadline representation, and restart reconstruction.
It creates no scanner jobs or executions and publishes no report. See
`docs/source-v0.8-s6a-orchestration.md`.

S6B adds one durable Job per runnable local node, attempt-bound worker/lease and
containment evidence, worker-independent local process supervision, deterministic
Semgrep Docker cleanup/reconciliation proof, guarded safe-native-result acceptance,
and reconciliation that prevents generic lease recovery from retrying unproven
execution state. Controlled production-bridge tests cover the local and Docker
execution paths; injected envelopes alone are not presented as end-to-end evidence.
OSV dependency execution, global retry and cancellation policy, S4 assembly, and
report publication remain outside S6B. See
`docs/source-v0.8-s6b-scanner-execution.md`.

S6C-A validates the exact accepted Syft attempt, reconstructs advisory scope only
from the canonical S6A snapshot, classifies whole package observations without
rewriting identity, and reuses the frozen S2 candidate builder. Its canonical
dependency-evaluation artifact durably distinguishes runnable, not-applicable,
and partial outcomes. It creates no OSV Job, performs no OSV request, and does
not assemble or publish S4 evidence. See
`docs/source-v0.8-s6ca-dependency-evaluation.md`.

Engine Closure implements the dependency-gated OSV Job, attempt-bound helper,
one-operation durable request permits, orchestration-aware retry and cancellation/
deadline boundaries, short-lived restartable coordination, dedicated five-authority
production worker composition, a durable per-run active-Job ceiling defaulting to
two, and the final two-stage S4 assembly/publication path. It preserves
frozen scanner and advisory behavior, does not add semantic cross-engine merging,
and does not begin prioritization or finding lifecycle work. See
`docs/source-v0.9-engine-closure.md`.

PC1 adds an explicit server-owned logical Source lineage and a compact,
transactional occurrence index over published S4 findings. PC2 adds exact-ID
lifecycle only when authority-specific comparable-scope proof succeeds, plus
explicit deterministic triage bands. S4 remains authoritative; API and CLI are
not part of PC1 or PC2. See `docs/source-v0.10-product-core.md`.

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

The current Source-v1 Semgrep authority is bound to the verified immutable
`semgrep/semgrep@sha256:bdf7013b2c3634a487671158da77c554f531742326b543a9464d2adf6c433ac8`
image. This pre-v1 refreeze replaces the undeployable development placeholder;
there is no mutable fallback and placeholder-contract local runs are not
resumable by the corrected runtime. Historical Git checkpoints are unchanged.

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

## Gitleaks v0.4D Applicability and Planning Boundary

v0.4D keeps generic Source inventory, coverage, support, and planning contracts
unchanged. Gitleaks support is declared explicitly as SCANNABLE through the
existing SourceSupportPolicy. A scanner-specific applicability overlay then
expands SECRET_DETECTION from the generic text-oriented inventory surface to the
repository-wide current immutable snapshot, preserving path-only detector
coverage such as the frozen Gitleaks 8.30.1 pkcs12-file rule.

The overlay cannot independently promote DETECTED, override UNSUPPORTED, or
rewrite BENCHMARKED/PRODUCT_SUPPORTED maturity. SourceSupportPolicy remains the
authority for support state.

The frozen Source-v1 Gitleaks planning policy applies no SecureScan path
exclusions. Binary, generated, vendored, test, documentation, configuration,
and unknown-language files therefore remain in the declared scanner surface.
Gitleaks may apply its own frozen detector/file semantics internally; SecureScan
does not claim that every selected byte is inspected by every detector.

Runtime availability is represented through TrustedSourceAnalyzer using only
the frozen Gitleaks binding's executable/version/configuration verification.
No repository scan is performed during availability assessment.

SECRET_DETECTION is SCANNABLE for this Source-v1 integration. This is an
execution/support maturity statement, not benchmark evidence. BENCHMARKED and
PRODUCT_SUPPORTED remain unclaimed.

## Gitleaks v0.4E Finding Identity Boundary

v0.4E introduces a deterministic structural-location identity for normalized
Gitleaks findings. Identity is derived only from the frozen scanner identity,
rule identifier, normalized repository-relative path, detection kind, and,
for CONTENT findings, the normalized source location.

PATH findings intentionally contain no fabricated source coordinates.

The public finding instance identity excludes secret-bearing or secret-derived
material. Raw Secret, Match, Gitleaks Fingerprint, hashes of secret values,
file contents, file digests, repository digests, projection identifiers,
projection digests, and execution context digests do not participate in the
identity.

Run-specific Source projection and execution provenance therefore do not change
the identity of the same structural finding.

The identity represents a structural observation, not a credential identity.
A secret value changing at the same rule/path/location does not create a new
identity because v0.4E deliberately does not inspect, persist, or derive public
identity from the secret value.

A CONTENT finding moving to another normalized source location receives a
different identity. Cross-edit finding tracking is not claimed in v0.4E.

Equal identities do not perform or imply deduplication. Duplicate scanner
observations remain duplicate observations. Baseline comparison, finding
lifecycle, cross-scan tracking, suppression, credential grouping, and
cross-tool correlation remain outside this checkpoint.

v0.4E performs no filesystem access, network access, scanner execution, policy
suppression, maturity promotion, or finding deduplication.

## Gitleaks v0.4F1 Benchmark Contract Boundary

v0.4F1 freezes the benchmark law before any scored Gitleaks corpus or benchmark
result is created.

The contract is bound to Gitleaks 8.30.1, the frozen v0.4A trusted binding,
the v0.4E baseline commit and tag, and canonical content-addressed benchmark
metadata.

Each scored case defines exactly one expected detector relation. Expected
matches and expected non-matches later classify as TP/FN and FP/TN
respectively. OUT_OF_SCOPE cases are explicitly unscored. Findings from other
rules are not silently attributed to the case relation and must be accounted
for separately by later evaluation infrastructure.

The manifest and corpus fail closed for malformed schemas, duplicate case IDs,
duplicate paths, noncanonical case ordering, changed or missing files, unlisted
files, traversal-shaped paths, and symlink substitution of benchmark artifacts,
manifest files, corpus directories, or case files.

The contract permits whole-file SHA-256 only for benchmark corpus integrity.
Raw secret values, raw Match data, Gitleaks Fingerprint values, and
secret-derived public identities remain prohibited from benchmark reports.

v0.4F1 does not execute Gitleaks, produce detection metrics, create a maturity
decision, validate credentials, scan Git history, access the network, traverse
archives, or perform recursive decoding.

Representative future benchmark evidence will not certify every inherited
Gitleaks default detector, and perfect bounded-corpus metrics will not imply
ecosystem-wide zero false positives or zero false negatives.

## Gitleaks v0.4F2 Pre-Scan Corpus Boundary

v0.4F2 deterministically freezes 48 intended case/rule relations before any
Gitleaks execution against this corpus: 42 core relations across seven representative inherited
detectors and six scope/allowlist relations. Each core rule has exactly three
expected matches and three expected non-matches. The canonical plan is bound
to the full v0.4F1 commit and the frozen benchmark contract and binding
identities; the content-addressed manifest is built through the unchanged
v0.4F1 contract model.

The fixtures contain only deterministic project-owned synthetic and non-live
values. PEM-shaped private-key fixtures are non-cryptographic text, and PKCS12
path fixtures contain no usable certificate, key, or credential bundle. The
generator uses no randomness, clock, environment entropy, network, external
credential tool, Git repository, or scanner process.

This pre-scan corpus covers seven representative detectors only and does not
certify all detectors inherited from Gitleaks 8.30.1. SecureScan applicability
remains repository-wide even where inherited Gitleaks global allowlists may
internally suppress selected paths. Cross-rule observations are deliberately
not pre-suppressed. Gitleaks has not been executed against the corpus, and no
results or detection metrics exist at this checkpoint. Any future perfect
metrics remain bounded to this corpus. `SECRET_DETECTION` remains `SCANNABLE`.

## Gitleaks v0.4F3A Controlled Benchmark Machinery

v0.4F3A implements the pure F2 relation evaluator, canonical
`securescan-gitleaks-benchmark-report-v1` schema, and controlled production-path
harness. The harness prepares only `benchmarks/gitleaks/corpus` with the Source
workspace, durable context, artifact, and projection infrastructure, then uses
the existing Gitleaks Source bridge, parser, and stable structural finding
identity implementation unchanged.

Intended path/rule/detection-kind relations are scored independently of
unexpected cross-rule observations. Duplicate findings remain duplicate
observations without inflating a relation classification. Unknown paths and
any failed execution or integrity stage fail closed without metrics or
recording. A pre-parse confidentiality gate requires all deterministic frozen
fixture sentinels to be absent from raw stdout and stderr; the raw streams and
sentinels are never persisted in benchmark evidence. Pure evaluation makes no
confidentiality assertion. That assertion exists only on a controlled report
constructed after the gate validates the exact scanned projection bytes.

At the F3A freeze, Gitleaks had not been executed against the F2 corpus and no
baseline existed. F3B subsequently froze the initial controlled baseline at
`d183336c129977c4279cd1058bbe060742de0e54`: 22 TP, 23 TN, 0 FP, and 3 FN
across the 48 intended relations. Its report SHA-256 is
`62f9c00f79c659d56490a181de231f0aa3cdca6a418f2ca5a9215f7ed1bbbb34`.
`SECRET_DETECTION` remains `SCANNABLE`.

## Gitleaks v0.4F5B2R1 Selection Compatibility Correction

The first F5B3 acquisition attempt requested only the frozen Miniflux archive.
Its receipt was 985,853 bytes with SHA-256
`68fcd009c78c35ef4be5db07cde25cd44ea1edcce27e68bb5793c9409c702e3a`.
Complete pre-materialization validation found the member
`internal/reader/readability/testdata`, type `SYMLINK`, targeting
`../../reader/sanitizer/testdata/`. The archive was rejected before extraction
acceptance; zero SecureScan workspaces were created, the other five archives
were not requested, and Gitleaks did not execute.

F5B2R1 replaces only RW01 with the public MIT-licensed standalone CLI
`charmbracelet/gum` at commit
`4d089f95507708a71f64dacfe7ca513219dd5267`. Its complete authoritative Git
tree metadata contains 142 entries, no mode `120000` symlinks, no mode `160000`
submodules, a maximum path length of 37 bytes, and maximum depth three. The
replacement is solely an acquisition-policy compatibility correction; no
scanner result informed selection. RW02 through RW06 and every F5B1 security
requirement remain unchanged. The manifest remains `SELECTED`, all acquisition
fields remain null, no archive was downloaded for the corrected selection, and
`SECRET_DETECTION` remains `SCANNABLE`.

## Gitleaks v0.4F5B2R2 Consolidated Acquisition-Compatible Selection

The corrected F5B3 attempt acquired and ingested RW01 Gum, then rejected RW02
Requests during complete pre-materialization validation. The Requests archive
was 3,333,932 bytes with SHA-256
`55999922723576238c243ca02183f2c367c9b0c197a3c1afc671b35c2daf96c2` and
contained two forbidden symlinks:

- `tests/certs/mtls/client/ca` to `../../expired/ca/`
- `tests/certs/valid/ca` to `../expired/ca`

Requests was rejected before extraction acceptance. The Gum workspace was
rolled back, zero workspaces remain, RW03 through RW06 were not requested, no
snapshot identity was persisted, no result artifact was created, and Gitleaks
did not execute.

Before another acquisition, complete authoritative Git-tree metadata was
checked for RW02 through RW06. Only tree mode `040000` and blob modes `100644`
and `100755` were accepted:

| Slot | Repository and exact commit | Entries | Blobs | Blob bytes | Max blob | Max path bytes | Max depth | Symlinks | Gitlinks | Other modes | Result |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| RW02 | `pallets/click@36baa15ff831b939a22bc527cd76ce653ef6f66d` | 190 | 166 | 1,604,094 | 258,440 | 48 | 5 | 0 | 0 | 0 | accepted |
| RW03 | `pallets/flask@d318b683471101618febed18996405ad26462110` | 287 | 236 | 1,870,682 | 364,065 | 72 | 8 | 0 | 0 | 0 | unchanged |
| RW04 | `Quad4-Software/Reticulum-Go@5bf60debb7fdcd27b175d4db2585dd994a3d1b66` | 6,650 | 5,982 | 50,227,481 | 945,502 | 105 | 11 | 0 | 0 | 0 | unchanged |
| RW05 | `git/git@3cb9185f65410273787f74333cc027d2ea5daada` | 5,074 | 4,846 | 48,313,504 | 1,088,754 | 83 | 8 | 3 | 1 | 0 | rejected |
| RW05 | `golang/go@c5941983810b68ba93c30f0ef22c91ad63fb3e5c` | 17,697 | 15,899 | 152,648,293 | 4,170,206 | 105 | 14 | 0 | 0 | 0 | accepted |
| RW06 | `SSLMate/go-pkcs12@c0472edb16891765fbc86573ea468365b7fd2197` | 32 | 29 | 153,628 | 34,195 | 36 | 3 | 0 | 0 | 0 | unchanged |

Click is the public BSD-3-Clause reusable Python library selected for RW02.
Go is the public BSD-3-Clause multi-language toolchain selected for RW05.
Both replacements are solely F5B1 acquisition-policy compatibility
corrections. RW01 Gum and compatible RW03, RW04, and RW06 remain byte-identical
to F5B2R1. The manifest remains `SELECTED`; archive and snapshot output fields
remain null. No archive for the consolidated selection was acquired, no
repository was cloned or executed, no Gitleaks result informed selection, and
`SECRET_DETECTION` remains `SCANNABLE`.

## Gitleaks v0.4F5B3 Bounded Acquisition and Snapshot Freeze

F5B3 acquired the six exact F5B2R2 commit-addressed archives through bounded
HTTPS streaming. Each archive was treated as hostile input, completely
validated before materialization, extracted member by member outside the
repository, and passed as inert source data to `RepositoryWorkspaceManager`.
No repository code, package manager, build tool, test, hook, Git operation
against acquired content, or Gitleaks process executed.

| Slot | Repository | Archive SHA-256 | Archive bytes | Snapshot digest | Files | Snapshot bytes |
|---|---|---|---:|---|---:|---:|
| RW01 | `charmbracelet/gum` | `d8830519d8ae7c99c61df6d0568c1632f44f0c4d95d882a5c122ef328808249f` | 71,736 | `005226ad3e96e24a56abf837e4f61b845891408528c2e8938d941ff60bbfb8d8` | 115 | 228,095 |
| RW02 | `pallets/click` | `0fa792fe26295cb0b2568e811bec22b19fc0d4dc90f5f9d698c0e0202d3ac89e` | 495,302 | `082137a8ff57a6d04c77aa00fd86efb537d70607d98f7cebebf0bffb40a91a3f` | 166 | 1,604,094 |
| RW03 | `pallets/flask` | `d9e95f6100bb2479247da4b8055b80a52ef8c059cd74ade5b7df46ce01033d77` | 765,027 | `32ced363f940ccf3b79c960b0b7cc12b0934cff72afc47f2b32ecb385478f690` | 236 | 1,870,682 |
| RW04 | `Quad4-Software/Reticulum-Go` | `a3e8fccb17e438c489e2d785223a7324b6c237249e13e947ac48704018475488` | 9,758,061 | `74c4f655346c330b4090e189bc3c7e4ffd5998e3a76aeadfc8c5ae30d2aa07fe` | 5,982 | 50,227,481 |
| RW05 | `golang/go` | `362076280e37336993ebfdee92df2df3da2d72a00255cd6a5dfb2719684344a1` | 35,924,320 | `559abdc68125411009df49c80ba17ae79153857b1ea41620ddd0f82d7da595bd` | 15,899 | 152,648,293 |
| RW06 | `SSLMate/go-pkcs12` | `12bc72ac6ebfcd39b1aa006c81642c1f0ad719d1bf9fbc33f87cf0683d8655d2` | 52,146 | `dd392cfc612c5cede44c17a9d0c898fbf2eb553295577f2a12f399d98c46d45e` | 29 | 153,628 |

All six slots completed before the manifest atomically transitioned from
`SELECTED` to `ACQUIRED`. Archive and snapshot identities are present and
unique, and the canonical acquired-manifest SHA-256 is
`3a7f55e43210427974985c4e4009a1027fc4db12f3d94e119b490df8f0fc3b52`.
At the F5B3 checkpoint, no real-world result artifact existed and
`SECRET_DETECTION` remained `SCANNABLE`.

## Gitleaks v0.4F5C Fail-Closed Execution Attempt

F5C used only the six retained F5B3 SecureScan workspaces. Before execution,
the production projection inventory verifier reproduced each frozen snapshot
digest, file count, and byte count. The trusted Gitleaks 8.30.1 binding then
ran only through the durable Source context, immutable projection, production
Gitleaks execution bridge, and frozen parser path. No network, Git history,
repository code, package manager, build, hook, or provider validation ran.

RW01 Gum and RW02 Click completed with return code 0 and no parsed findings.
RW03 Flask completed with return code 1 and six sanitized structural findings.
RW04 Reticulum-Go reached the production parser, which rejected the completed
scanner output with fixed failure code `GITLEAKS_OUTPUT_INVALID_SCHEMA`.
Following the frozen failure semantics, RW04 was not represented as clean,
RW05 and RW06 were not evaluated as part of a completed run, no F5C result was
recorded, and F5D repeatability execution did not start.

This is an incomplete operational characterization, not an accuracy benchmark.
No TP, FP, FN, TN, precision, recall, F1, credential-validity, or live-secret
claim is made. At that fail-closed point both reserved result paths were absent
and `SECRET_DETECTION` remained `SCANNABLE`.

The second full restart passed RW04 after v0.4C1, then failed closed at RW05
when two legitimate multiline findings used end-line-relative columns smaller
than their start-line-relative columns. That attempt also recorded no result
and did not start F5D.

The first and second attempts remain historical fail-closed evidence. After
the v0.4C1 Match-layout and v0.4C2 multiline-location compatibility checkpoints
were frozen independently, F5C restarted from RW01 and all six repositories
completed. Per-slot parsed/content/path counts were `0/0/0`, `0/0/0`, `6/6/0`,
`8/8/0`, `123/123/0`, and `1/1/0`. All 138 observations have unique structural
identities; no duplicate observation was recorded. The canonical F5C SHA-256
is `33062f73834e348492349ce00b509f478ed5509b4b1b40183eba034be3a74313`.

Immediate F5D run #2 reproduced the same per-slot counts and canonical
structural sets. Every repository and the six-repository aggregate have zero
missing and zero new identities. The F5D artifact SHA-256 is
`8fde25f35da87d1e9abff97e087bf8bdb77116f622095b08e040278c21332303`.
This remains operational generalization and repeatability characterization,
not TP/FP/FN/TN, precision, recall, F1, or credential-validation evidence.
`SECRET_DETECTION` remains `SCANNABLE`.

## Gitleaks v0.4F4A Adversarial Pre-Scan Characterization

v0.4F4A freezes thirteen deterministic, project-owned cases that characterize
the three F3B misses and nearby controls. It records only
`EXPECTED_OBSERVED`/`EXPECTED_ABSENT` expectations for stopword, entropy,
empty-file source delivery, path-only matching, suffix boundaries, inherited
global path allowlists, and controls. This diagnostic contract does not replace
the F3B accuracy baseline and publishes no precision, recall, F1, or maturity
claim.

Static validators prove the intended bounded recipe properties without
reimplementing the complete Gitleaks detector. At the F4A freeze, no F4
scanner observation had occurred and
`benchmarks/gitleaks/adversarial-v1-result.json` did not exist. The F3B
baseline and all earlier evidence remain immutable.
`SECRET_DETECTION` remains `SCANNABLE`.

## Gitleaks v0.4F4B1 Controlled Adversarial Evaluator

v0.4F4B1 implements the deterministic PASS/FAIL characterization evaluator,
controlled production-path runner, confidentiality-bound canonical result,
narrow CLI, and atomic first-result recording policy. F4A remains immutable,
the F3B accuracy baseline remains unchanged, and F4 does not calculate or
replace accuracy metrics.

At the F4B1 freeze, no real adversarial scanner observation had occurred and
the reserved `benchmarks/gitleaks/adversarial-v1-result.json` artifact did not
exist; only fake execution envelopes were used by F4B1 tests. Findings for another rule
are represented as cross-rule observations; findings for the intended rule with
the wrong detection kind are represented separately as detection-kind
mismatches. Neither can satisfy or invalidate an intended relation.
`SECRET_DETECTION` remains `SCANNABLE`.

## Gitleaks v0.4F4C Conservative Characterization

F4B2 subsequently reproduced all thirteen frozen F4A hypotheses: thirteen
cases passed, none failed, five findings were parsed, and neither unexpected
observation category was populated. F3B remains the historical bounded
accuracy evidence; F4C does not recompute or reinterpret its metrics.

F4C records six machine-readable, evidence-bound characterizations covering
upstream generic-rule suppression and entropy behavior, empty-file directory
source behavior, path-only detection, inherited global path allowlists,
SecureScan fail-closed execution, and sanitized credential-independent
evidence. Scanner behavior, SecureScan behavior, and future product-policy
boundaries remain explicit and separate. F4C executes no scanner, creates no
new corpus, and makes no maturity promotion. `SECRET_DETECTION` remains
`SCANNABLE`.
## v0.4F4C Freeze Validation Note

The F4C focused and combined Gitleaks regression gates passed. The authoritative
full Python suite was not completed at this checkpoint because
`tests/test_api.py::test_health` intermittently stalled during Starlette
`TestClient.__enter__` while waiting for AnyIO portal startup. Faulthandler
localized the stall before application request execution. F4C modifies no API,
production Source, production Gitleaks, or dependency code; those surfaces
remain byte-identical to the preceding checkpoint whose authoritative full
regression completed successfully. This infrastructure/test-harness stall is
therefore recorded as a non-F4C regression waiver rather than represented as a
successful full-suite run.

## Gitleaks v0.4F5A Bounded Real-World Contract

F5A freezes six operational repository roles and the future acquisition,
current-snapshot execution, repeatability, review, confidentiality, and
fail-closed contracts before repository selection. At that checkpoint,
repository names, URLs, commits, archives, and snapshots remained unresolved;
no acquisition, network access, or real-world Gitleaks scan had occurred, and
no F5 result existed.

Future snapshots use the existing SecureScan `RepositoryManifest` identity
(`content_digest`, `file_count`, and `total_bytes`). F5B must freeze bounded,
containment-safe untrusted-archive extraction policy and record pre-scan role
eligibility evidence before selecting six distinct repositories.

F3B remains controlled accuracy evidence, while F4C remains limitation and
claim evidence. F5 is operational evaluation without complete ground truth and
does not authorize precision, recall, F1, TP, TN, FP, or FN. No maturity
promotion occurs; `SECRET_DETECTION` remains `SCANNABLE`.
## v0.4F5A Freeze Validation Note

The focused F5A and combined Gitleaks regression gates passed. The authoritative
full Python suite was not completed because the isolated API health test again
stalled during Starlette TestClient startup while waiting for the AnyIO portal,
before application request execution. F5A modifies no API, production Source,
production Gitleaks, or dependency code. This recurring test-harness condition
is recorded as a non-F5A regression waiver rather than represented as a
successful full-suite run.

At the F5A checkpoint, no repository acquisition, network operation, or
Gitleaks execution had occurred. No real-world result artifact existed and
SECRET_DETECTION remained SCANNABLE.

## Gitleaks v0.4F5B1 Acquisition Policy and Manifest Schema

F5B1 freezes the bounded untrusted-archive acquisition policy and unresolved
six-slot acquisition-manifest schema before repository selection. Archive
transport limits are distinct from, and archive expansion limits align with,
the unchanged production `RepositoryIntakeLimits`. Snapshot identity remains
the existing `RepositoryManifest` content digest, file count, and total bytes.

The manifest state machine is `PRE_SELECTION` to `SELECTED` to `ACQUIRED`.
Selection freezes distinct repository and immutable archive HTTPS identities,
exact commits, licenses, acquisition methods, and role evidence before archive
or snapshot outputs exist. Only regular files and directories may later be
materialized from an archive.

At the F5B1 checkpoint, no repository had been selected, no network access or
archive acquisition had occurred, no archive had been extracted, and neither
repository code nor Gitleaks had executed. The F5A contract remained frozen,
no populated acquisition manifest or F5 result existed, and
`SECRET_DETECTION` remained `SCANNABLE`.

## Gitleaks v0.4F5B2 Repository Selection

F5B2 advances the acquisition manifest to `SELECTED` and freezes exactly one
public repository for each of the six F5A roles. The selections are
`miniflux/v2`, `psf/requests`, `pallets/flask`,
`Quad4-Software/Reticulum-Go`, `git/git`, and `SSLMate/go-pkcs12`; each records
an exact 40-character commit, HTTPS upstream and commit-addressed archive URLs,
an SPDX-compatible license identifier, frozen-vocabulary pre-scan role
evidence, and a concise role rationale.

The selected repositories and archive resources are distinct under every F5B1
selection constraint. Archive SHA-256, archive byte count, snapshot digest,
file count, and byte count remain null until an explicit later acquisition
checkpoint. F5B2 downloaded or extracted no archive, cloned no repository,
executed neither repository code nor Gitleaks, and created no evaluation result.
`SECRET_DETECTION` remains `SCANNABLE`.

## Gitleaks v0.4F6 Final Evidence and Maturity Reconciliation

F6 reconciles the frozen trusted binding, F3B controlled benchmark, F4
adversarial characterization, F5B3 acquisition manifest, F5C real-world run,
and F5D repeatability result in
`benchmarks/gitleaks/final-capability-v1.json`. The canonical matrix records 12
`SUPPORTED`, 9 `LIMITED`, and 13 `NOT_SUPPORTED` claims without changing or
reinterpreting the frozen evidence.

SecureScan Source v1 provides deterministic, current-snapshot secret detection
through a pinned and verified Gitleaks 8.30.1 integration. Findings are parsed
through a fail-closed confidentiality-preserving boundary and receive stable
structural identities. Controlled benchmark, adversarial, acquisition, and
real-world repeatability evidence are frozen and reproducible.

The evidence comprises F3B's 22 TP, 23 TN, 0 FP, and 3 FN across seven
representative detectors; F4's 13/13 expected characterization outcomes; F5C's
138 sanitized content observations across six frozen repositories; and F5D's
equal structural sets with zero missing and zero new identities. Real-world
execution also established compatibility with multiline `Match` layout and
line-relative multiline columns while preserving fail-closed schema behavior.

This capability does not claim exhaustive secret detection, Git-history
coverage, credential validity, exploitability, universal detector accuracy, or
inspection of every selected byte. Upstream Gitleaks rules, allowlists,
enumeration behavior, and supported output schema remain material limitations.
Git history, provider validation, credential reachability, cross-tool
correlation, lifecycle deduplication, rotation tracking, and runtime validation
remain unsupported.

`SECRET_DETECTION` remains `SCANNABLE`, not `BENCHMARKED`: F3B covers seven
representative detectors and records three false negatives; F4 demonstrates
material upstream limitations; F5 has no complete frozen ground truth and
observed only three rule IDs; and repeatability proves determinism rather than
accuracy. A future `BENCHMARKED` state requires a broader frozen representative
detector-family corpus with explicit limitation-aware ground truth and
repeatable scoring. It would not mean exhaustive detection, live credential
validity, ecosystem-wide accuracy, or zero false negatives.

`GITLEAKS TARGET-1 INTEGRATION: COMPLETE`

## Syft S1 Package Inventory Boundary

S1 pins the official Syft 1.51.0 Linux amd64 executable and its project-owned
configuration. Production accepts only an absolute digest-verified executable,
constructs an explicit `directory` scan of the immutable Source projection,
uses `syft-json` schema 16.1.10, supplies an empty child environment, requests
no network-dependent enrichment, disables remote license searches, update
checks, and local package caches, and bounds time and output. Registry and image
sources are not permitted. S1 does not claim an OS-level egress sandbox.

The parser accepts only the frozen Syft descriptor, schema, directory source,
authorized projection-relative locations, bounded core artifact structure, and
standards-valid Package URLs. Package-specific `metadata`, raw stdout, raw
stderr, Syft artifact IDs, host paths, and temporary paths are never durable.
One `package_key` groups normalized package coordinates; a separate
`package_observation_id` binds the key to its cataloger and sorted evidence
locations, so equal coordinates at different manifests are not collapsed.

The controlled project-owned corpus produced ten observations: seven Python,
two npm, and one Go module. A separate zero-package fixture completed with zero
packages. Two real pinned-binary runs produced identical normalized structural
evidence. The corpus also proves that a target-owned `.syft.yaml`, near-miss
filenames, generated, test, and vendor paths do not alter SecureScan's explicit
configuration or repository-wide selection boundary.

S1 claims only what pinned Syft observed in the current immutable directory
snapshot. It does not claim direct/transitive/runtime/development dependency
semantics, installation, import, reachability, vulnerability, CVE applicability,
or exhaustive ecosystem discovery. `PACKAGE_INVENTORY` is `SCANNABLE`, not
`BENCHMARKED`; at the S1 freeze, OSV advisory matching remained future S2 scope.
