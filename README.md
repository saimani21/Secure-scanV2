# SecureScan Core

SecureScan Core v0.1.0 is a source-repository security-analysis orchestrator. It accepts
local repository directories, creates a deterministic read-only snapshot, runs Semgrep
Community Edition in an isolated Docker sandbox, normalizes findings, and commits a
canonical report as durable evidence.

The bundled baseline contains exactly three Python demonstration rules: dangerous
`eval`, `subprocess` with `shell=True`, and unsafe `yaml.load`. Partial analysis is
explicit: scanner diagnostics become analysis gaps rather than a false clean result.

Core v0.1 supports local directories only. It does not clone repositories, authenticate
users, provide multi-tenant isolation, cover multiple languages, or represent a complete
Semgrep ruleset. See [limitations](docs/core-v0.1-limitations.md).

SecureScan Source v1.2.0 is the current local product release built on this frozen
Core. The Python distribution and API retain their independent Core version `0.1.0`;
the annotated Git tag `source-v1.2.0` identifies the Source product release. See the
[Source v1.2 release notes](docs/source-v1.2-release.md) for supported workflows,
security boundaries, validation evidence, and limitations. The
[v1.1 release notes](docs/source-v1.1-release.md) remain the frozen prior record.

## Local setup

Python 3.12+, Docker Desktop or a compatible local Docker daemon, and PostgreSQL 16 are
required for the complete release gate.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev,postgres]'
cp .env.example .env
# Edit .env and set the required secrets, host database URL, runtime identity,
# and independently trusted Enry digest.
./.venv/bin/securescan system configure --from-env-file .env
./.venv/bin/securescan doctor
./.venv/bin/securescan system up
./.venv/bin/securescan open
```

Replace the example secrets and materialized host database URL before running
initialization. Use a separate database whose name ends in `_test` for destructive
PostgreSQL integration tests.

The private operator profile lets later shells use `securescan system status`
without sourcing a shell script. Operator commands ignore unrelated `.env`
files in the current directory; process `SECURESCAN_*` values can explicitly
override the profile. Stop the managed host worker and Compose services with
`securescan system down`; PostgreSQL volumes and deployment data are preserved.

## Tests

Ordinary tests do not require PostgreSQL or Docker:

```bash
pytest
```

Strict integration runs require already-present, digest-pinned local images:

```bash
SECURESCAN_REQUIRE_POSTGRES_TESTS=1 \
SECURESCAN_TEST_POSTGRES_URL='postgresql+psycopg://.../securescan_test' \
pytest -m postgres

SECURESCAN_REQUIRE_DOCKER_TESTS=1 \
SECURESCAN_TEST_DOCKER_IMAGE='local/image@sha256:...' \
pytest -m docker

SECURESCAN_REQUIRE_DOCKER_TESTS=1 \
SECURESCAN_REQUIRE_SEMGREP_TESTS=1 \
SECURESCAN_TEST_DOCKER_IMAGE='local/image@sha256:...' \
SECURESCAN_TEST_SEMGREP_IMAGE='semgrep/semgrep@sha256:...' \
pytest -m semgrep
```

## Release benchmark

The image must already exist locally; the evaluator never pulls or builds it.

```bash
python -m securescan.release.core_v01 \
  --corpus-root "$PWD/tests/fixtures/release_benchmark" \
  --output-directory "$PWD/release-evidence" \
  --semgrep-image 'semgrep/semgrep@sha256:...' \
  --workspace-base "$PWD/.release-workspaces"
```

The acceptance statement is deliberately narrow: 100% precision and recall on the
bundled three-rule curated micro-benchmark. Read the
[benchmark methodology](docs/core-v0.1-benchmark-methodology.md),
[operations guide](docs/core-v0.1-operations.md), and
[failure matrix](docs/core-v0.1-failure-matrix.md) before release.

## Source Python SAST evaluation

Source v0.3F2E5 is the authoritative corrected controlled real-world Python
SAST execution checkpoint. F2E3 exposed drift between provisional claim prose
and production behavior; F2E4 corrected the versioned claim contract and
applicability evidence without changing the production rules. F2E5 binds its
scoring only to those frozen v2 inputs and records new v2 evidence filenames.
Historical F2E3 metrics remain provisional and superseded. `PYTHON_SAST`
remains `SCANNABLE`; the maturity decision belongs to F2F. See the
[Source status](docs/source-v1-status.md) for the exact evidence and result
boundaries.

## Source Gitleaks real-world selection

Source v0.4F5B2R2 freezes a metadata-only, six-repository selection for the
future bounded Gitleaks real-world evaluation. Each public upstream is pinned
to an exact commit and a commit-addressed HTTPS archive resource:

| Role | Repository | Commit |
|---|---|---|
| Small application | `charmbracelet/gum` | `4d089f95507708a71f64dacfe7ca513219dd5267` |
| Library/package | `pallets/click` | `36baa15ff831b939a22bc527cd76ce653ef6f66d` |
| Documentation/examples-heavy | `pallets/flask` | `d318b683471101618febed18996405ad26462110` |
| Dependency/generated-path-heavy | `Quad4-Software/Reticulum-Go` | `5bf60debb7fdcd27b175d4db2585dd994a3d1b66` |
| Multi-language | `golang/go` | `c5941983810b68ba93c30f0ef22c91ad63fb3e5c` |
| Binary/config assets | `SSLMate/go-pkcs12` | `c0472edb16891765fbc86573ea468365b7fd2197` |

At the F5B2R2 selection checkpoint, selection used only public upstream
metadata and pre-scan role evidence from the frozen F5B1 vocabulary. No archive
had been downloaded or extracted, no repository code or Gitleaks process had
run, all archive/snapshot measurement fields remained unresolved, and no
real-world result existed. `SECRET_DETECTION` remained `SCANNABLE`.

F5B2R1 corrects only the small-application selection after the frozen Miniflux
archive failed the F5B1 acquisition policy because it contained a symlink.
Gum was selected from repository metadata, not scanner output; its exact Git
tree has 142 entries, no symlink or submodule modes, a maximum path length of
37 bytes, and a maximum depth of three.

F5B2R2 consolidates the remaining acquisition-policy compatibility corrections
before another acquisition attempt. Click replaces Requests after the frozen
Requests archive exposed two symlinks during complete pre-materialization
validation. Go replaces Git after complete provider tree metadata exposed three
symlinks and one gitlink. Click, Flask, Reticulum-Go, Go, and go-pkcs12 each
passed a complete metadata-only tree preflight with no symlink, gitlink, or
unexpected modes. These choices were made without scanner execution or result
data; the manifest remains `SELECTED` and all acquisition fields remain null.

F5B3 subsequently acquired those exact six commit-addressed archives through
the bounded hostile-archive path and froze their archive receipts and
`RepositoryWorkspaceManager` snapshot identities. The acquisition manifest is
now `ACQUIRED` with SHA-256
`3a7f55e43210427974985c4e4009a1027fc4db12f3d94e119b490df8f0fc3b52`.
At the F5B3 checkpoint, no repository code or Gitleaks process had run and no
real-world result existed. `SECRET_DETECTION` remained `SCANNABLE`.

The first F5C production-path execution attempt then failed closed at RW04:
the frozen parser rejected completed scanner output as
`GITLEAKS_OUTPUT_INVALID_SCHEMA`. RW01 and RW02 completed with no findings and
RW03 produced six sanitized structural findings, but no partial run is treated
as complete or clean. No F5C result was recorded, F5D did not start, and no
accuracy or credential-validity claim is made.

A second full restart passed RW04 after v0.4C1 but failed closed at RW05 when
the parser rejected two legitimate multiline, line-relative column tuples.
That attempt likewise produced no canonical result and did not start F5D.

After the v0.4C1 Match-layout and v0.4C2 multiline-location parser
compatibility corrections, F5C completed against all six frozen F5B3
snapshots. It recorded 138 sanitized structural findings, all content findings,
with 138 unique identities and zero duplicate observations. Immediate F5D
run #2 reproduced every per-repository canonical set with zero missing or new
identities. These operational observations are not accuracy metrics;
`SECRET_DETECTION` remains `SCANNABLE`.

## Source Gitleaks Target-1 closure

Source v0.4F6 reconciles the frozen Gitleaks evidence into the canonical
[`final-capability-v1.json`](benchmarks/gitleaks/final-capability-v1.json)
claim matrix. SecureScan provides pinned Gitleaks 8.30.1 current-snapshot
execution, repository-wide applicability planning, bounded lifecycle behavior,
fail-closed confidential parsing, sanitized content and validated path-only
findings, stable structural identity, and canonical evidence. The controlled
F3B corpus recorded 22 TP, 23 TN, 0 FP, and 3 FN across seven representative
detectors. F4 reproduced 13/13 adversarial characterization outcomes. F5C
recorded 138 sanitized content observations across six immutable repository
snapshots, and F5D reproduced every structural set with zero missing or new
identities.

Real repositories established compatibility with multiline `Match` values and
line-relative multiline coordinates; unsupported output still fails closed.
The evidence does not establish Git-history coverage, live credential validity,
exploitability, universal detector accuracy, inspection of every selected byte,
or zero false negatives. F3B is bounded, F4 documents material upstream
limitations, and F5 has no complete ground truth and observed only three rule
IDs. The final maturity is therefore `SECRET_DETECTION = SCANNABLE`, and the
Gitleaks Target-1 integration is complete without promotion to `BENCHMARKED`.

## Source Syft package inventory

Source S1 adds pinned Syft 1.51.0 directory-mode inventory for the immutable
Source projection. The trusted binding verifies the official Linux amd64
executable and frozen configuration, disables update checks, enrichment, remote
license searches, and host-cache lookups, and invokes only explicit `dir` source
behavior with bounded execution. It never installs dependencies, builds or
runs repository code, invokes Git, or uses an image/registry/container daemon.
No network-dependent operation is requested; S1 does not claim an OS-level
egress sandbox.

Defensive `syft-json` parsing retains only normalized package coordinates,
standards-valid PURLs, cataloger names, and authorized repository-relative
locations. Arbitrary package metadata and raw scanner streams remain transient.
`package_key` groups package coordinates for later advisory work, while
`package_observation_id` also includes the cataloger and location set so
structurally distinct evidence is preserved. Exact repeated Syft artifacts that
normalize to the same complete observation are represented once; contradictory
observations with the same identity fail closed. `package_count` is the number
of unique normalized observations, not the raw Syft artifact-array length.

The controlled S1 evidence covers Python, npm, and Go fixtures, including
multiple manifests and generated/test/vendor paths, plus a successful
zero-package fixture and repeatable normalized output. This supports
`PACKAGE_INVENTORY = SCANNABLE`. It does not establish dependency kind,
installation, runtime use, reachability, exhaustive discovery, vulnerability,
or CVE status. OSV matching is deliberately not part of the frozen S1 evidence.

## Source OSV dependency intelligence

Source S2 consumes the frozen Syft package observations and queries OSV only for exact,
versioned, package-name-consistent PyPI, npm, and Go PURLs. The trusted client is fixed to `api.osv.dev`, bounded
for batches, pagination, response sizes, timeouts, retries, and advisory counts, and
fails closed on transport, schema, pagination, or mutable-record inconsistencies. Full
records are validated against a frozen OSV 1.9.0 schema before alias-aware normalized
dependency vulnerability findings are produced.

The project-owned controlled snapshot covers affected and same-package fixed-boundary
queries for three ecosystems: six package versions, six advisory records, four alias
groups/findings, and three explicit zero-advisory boundary results. Ordinary
evaluation is deterministic and offline. Online matching sends package coordinates to
OSV but no repository contents and does not provide an OS-level egress sandbox.
`DEPENDENCY_ADVISORY_MATCHING = SCANNABLE`; it does not claim reachability,
exploitability, runtime relevance, universal advisory completeness, NVD, EPSS, or VEX.
See [the Source v0.5 claim matrix](docs/source-v0.5-dependency-intelligence.md).

## Source Checkov configuration security

Source v0.6 S3 adds a pinned, isolated Checkov 3.3.16 CLI integration for
exactly Terraform, CloudFormation, Kubernetes, Dockerfile, and GitHub Actions
files from the frozen Source projection. A SecureScan-owned configuration and
explicit CLI overrides prevent repository Checkov configuration, external
policies, external Terraform modules, secrets, SCA, images, and platform mode
from changing the S3 authority boundary.

The binding freezes CPython 3.12.3 and all 97 Checkov distributions through a
wheel-hash lock; the generated launcher hash is a local file-integrity guard, not a
portable scanner identity. Its venv-local shebang and normalized launcher template
are verified separately. A narrow denylist excludes direct secret-material
policies while retaining secret-management configuration controls. Variable
evaluation is disabled because projection-confined filesystem access could not be
proven.

Strict parsing emits normalized active configuration findings, separate inline
suppression observations, framework completion aggregates, and explicit parse
gaps. Raw Checkov JSON, source code blocks, evaluated variables, connected-node
data, and host paths are not persisted. Missing filename-deterministic framework
reports fail closed. Generic YAML/JSON remain conservative discovery candidates;
unrelated files are accepted as not applicable only for Checkov's exact all-zero
summary shape. The controlled 13-file corpus provides
one selected fail/pass relation per framework plus suppression and malformed
input coverage. It is controlled integration evidence, not a broad accuracy
benchmark. `CONFIGURATION_SECURITY = SCANNABLE`; deployed state, runtime
posture, exploitability, reachability, external-module contents, Terraform
plans, Helm, and Kustomize remain outside the claim. See the
[Source v0.6 claim matrix](docs/source-v0.6-configuration-security.md).

## Source unified evidence

Source v0.7 S4 adds a typed, deterministic unified representation generated
from validated Semgrep, Gitleaks, Syft, OSV, and Checkov native models. The
report keeps findings, evidence, logical repository/package components,
suppressions, gaps, and coverage outcomes separate. Finding and evidence IDs
are authority-qualified and run-independent; a concrete occurrence is addressed
by its Source run ID plus finding ID.

Gitleaks duplicate structural observations retain explicit native multiplicity
without changing stable finding identity. OSV supporting Syft evidence is
validated as an exact package/projection/snapshot/binding producer-consumer
chain, coverage identities are component/scope sensitive, and Semgrep retains
safe sanitized-artifact metadata without artifact bytes or storage paths.

The four finding categories are code security, secret exposure, dependency
vulnerability, and configuration security. Package inventory remains package
component/evidence data. Severity is optional and authority-qualified, OSV CVSS
remains typed advisory evidence, and no confidence or global risk score is
invented.

S4 does not replace `ScanReport`, native scanner results, historical assessment,
or API formats. It adds no scanner parsing or execution, cross-engine merging or
correlation, lifecycle, persistence migration, or maturity change. Its offline
controlled replay is bound to the frozen F1/F5D/S1/S2/S3 evidence digests and
does not run scanners or access the network. See the
[Source v0.7 unified-evidence contract](docs/source-v0.7-unified-evidence.md).

## Source orchestration foundation

Source v0.8 S6A adds the durable control-plane foundation for one Source
orchestration per AnalysisRun. It preserves the complete canonical planning truth
in content-addressed storage, pins the five trusted Source authorities, derives
deterministic runnable nodes, stores the Syft-to-OSV dependency edge, and uses a
monotonic parent version to linearize cancellation and reject stale coordinators.

S6A executes no scanner, calls no network service, creates no scanner Job or
ToolExecution, accepts no native result, and does not assemble or publish the S4
report. Process containment and cleanup belong to S6B. See the
[S6A durable orchestration contract](docs/source-v0.8-s6a-orchestration.md).

The S6B implementation connects runnable local S6A nodes to durable scanner `Job`
identities, retains attempt history, supervises local scanner process trees
independently of worker liveness, and accepts only canonical safe native results
after cleanup and projection revalidation. Frozen local bridges use an attempt-bound
process supervisor; Semgrep uses an attempt-bound Docker identity and Docker-specific
cleanup/reconciliation proof. S6B excludes OSV scheduling and never assembles or
writes the final Source report. See the
[S6B scanner-execution contract](docs/source-v0.8-s6b-scanner-execution.md).

S6C-A adds the dependency release decision between accepted Syft evidence and
future OSV execution. It derives scope only from the frozen S6A snapshot,
classifies complete package observations as in-scope, outside-scope, or mixed,
and passes only unchanged in-scope observations to the frozen S2 candidate
builder. It persists one canonical evaluation and may only release the OSV node
to `READY` or terminalize it as not applicable/partial. S6C-A creates no OSV Job,
does not access the network, and does not publish a report. See the
[S6C-A dependency-evaluation contract](docs/source-v0.8-s6ca-dependency-evaluation.md).

Engine Closure adds the remaining dependency execution and lifecycle path:
one dependency-gated OSV Job runs in an attempt-bound helper, every frozen S2
transport invocation requires a committed durable request permit, and parent
cancellation/deadline state prevents later permits, results, or retries. A
short-lived coordinator creates the four initial local Jobs, advances the
Syft-to-OSV edge, promotes only safely reconciled retries, resolves dependency
blocking, and enters `ASSEMBLY_READY` only after every node is durably terminal.
An immutable per-run lease ceiling defaults to two active Jobs and is enforced
under the parent database lock. The production Source dispatcher composes the
frozen Semgrep Docker adapter, local Gitleaks/Syft/Checkov bridges, and OSV helper;
test-injected handlers are not used as evidence of that production wiring.

S6D then consumes only accepted canonical CAS evidence and terminal node state,
projects the five authorities through the frozen S4 model, records one canonical
assembly artifact, and publishes `AnalysisRun.report_json` exactly once. Explicitly
cancelled runs never publish. Scanner failure, timeout, dependency blocking, and
limited dependency coverage remain explicit and cannot become a clean result.
See the [Engine Closure contract](docs/source-v0.9-engine-closure.md).

## API and CLI

Start the API with `uvicorn securescan.api.main:app`. The existing `securescan` CLI
retains database initialization and fake-scanner development commands; the release gate
is separate and never runs during API startup.

For the practical single-node Source v1 deployment, run PostgreSQL, Alembic, and
the API with Docker Compose while keeping `securescan worker` on the trusted
scanning host. See the [Source v1 deployment guide](docs/source-v1-deployment.md).
The supported sequence starts with `securescan init`, which creates or validates
the private shared runtime roots and projection ownership descriptor. It refuses
unsafe or conflicting existing directories; do not delete or recreate descriptor
files by hand. Both API and worker remain non-root.

The API also serves a dependency-free, same-origin Source analysis console at
`http://127.0.0.1:<SECURESCAN_API_PORT>/`. Submit repositories with the trusted-host
`securescan scan` CLI, then use Overview, Projects, and scan history to open the
result in the console. Normal browser navigation does not require pasting a run
ID. The browser does not accept repository paths or upload source trees.

The host CLI also provides `securescan project create` and `securescan project
list`, authoritative paginated scan/stage/dependency/coverage/gap views, and a
bounded `scan --wait` mode, so a supported local scan never requires direct SQL
or knowledge of the internal persistence model. A completed run can be exported
deterministically with `securescan sarif RUN_ID --output PATH`; findings never
become a policy exit failure in V1.1. See the
[V1.1D CLI, SARIF, and CI guide](docs/source-v1.1d-cli-sarif-ci.md).

The read-only navigation API exposes bounded `GET /v1/projects`,
`GET /v1/projects/{project_id}`, `GET /v1/projects/{project_id}/scans`, and
`GET /v1/scans` views. Clients can discover durable project and run IDs without
pasting a previously known UUID. Repository submission remains the trusted-host
CLI workflow; the browser/API cannot submit arbitrary host filesystem paths. See
the [V1.1B1 navigation contract](docs/source-v1.1b1-product-navigation.md).

The repository includes an inert, immutable-action-pinned
[GitHub Actions example](examples/github-actions/securescan.yml). It requires an
ephemeral pre-provisioned runner with the frozen scanner toolchain; it is not an
active workflow and does not claim universal GitHub-hosted-runner portability.
SecureScan findings remain authoritative and GitHub Code Scanning is a one-way
presentation surface.

V1.1D CLI, deterministic SARIF, and the inert CI example are complete and
frozen after isolated real scanning, empty-result, fail-closed output,
filesystem safety, restart persistence, PostgreSQL parity, static, and wheel
acceptance. Vulnerability findings—including `HIGH` and `CRITICAL`—remain
successful analysis results rather than a policy exit condition.

The [Source v1 release-acceptance runbook](docs/source-v1-release-acceptance.md)
defines the four-run, five-authority acceptance path and its sanitized evidence
summary. The committed RA1 fixtures and offline verifier do not themselves constitute
acceptance; the completed V1.1R product gate is recorded in the
[Source v1.1 release notes](docs/source-v1.1-release.md).
