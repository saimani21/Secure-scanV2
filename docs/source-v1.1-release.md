# SecureScan Source v1.1.0

SecureScan Source v1.1.0 is a single-node, trusted-host product for analyzing a
local source repository with a fixed five-authority pipeline. It preserves
scanner evidence, coverage, gaps, dependency truth, and cross-scan lifecycle as
separate facts. A successful scan may contain `HIGH` or `CRITICAL` findings;
V1.1 has no policy engine and does not turn findings into a process failure.

The Source product release and Python package use intentionally separate version
streams. `source-v1.1.0` is the annotated product tag. The `securescan-core`
Python distribution and FastAPI metadata remain `0.1.0`, matching the frozen
Core foundation. SARIF omits a tool version because historical scan evidence has
no authoritative Source release-version field.

## Supported product surface

V1.1 provides:

- a private operator profile, read-only prerequisite checks, one-command system
  startup/status/shutdown, and one identity-verified trusted-host worker;
- local trusted-host repository submission into immutable managed workspaces;
- Semgrep SAST, Gitleaks secret detection, Syft package inventory, OSV dependency
  evaluation, and Checkov configuration-security execution;
- durable project and scan history, safe stage progress, canonical findings,
  dependency/advisory projection, coverage, gaps, and verified reports;
- exact finding lifecycle states `NEW`, `EXISTING`, `RESOLVED`, and `REOPENED`;
- a same-origin, framework-free Web UI with Overview, Projects, Scans, Findings,
  Dependencies, Coverage, Gaps, and Report workspaces;
- bounded human and JSON CLI views, bounded `scan --wait`, deterministic SARIF
  2.1.0 export, and an inert immutable-action-pinned GitHub Actions example; and
- exact-pinned `requirements*.txt` dependency scope when a matching concrete
  Syft package observation exists.

Dependency results retain these meanings:

| State | Meaning |
|---|---|
| `COMPLETE` with `N` | exactly `N` known canonical vulnerability groups |
| `COMPLETE` with zero | zero known vulnerabilities in the evaluated scope |
| `PARTIAL` or `FAILED` | known vulnerability count is unknown |
| `NOT_APPLICABLE` | dependency evaluation is not applicable |

Aliases do not inflate advisory counts. Fixed versions are advisory data, not a
universal remediation claim. SecureScan priority remains authoritative and is
not interchangeable with scanner-native severity.

## Local operation

Python 3.12+, Docker with Compose, PostgreSQL 16, and the frozen scanner toolchain
are required. Configure a private profile from trusted local values, verify it,
and start the system:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev,postgres]'
securescan system configure --from-env-file .env
securescan doctor
securescan system up
securescan system status
securescan open
```

Create a durable project and submit a local repository from the trusted host:

```bash
securescan project create "Example" --json
securescan scan /absolute/path/to/repository \
  --project-id PROJECT_UUID \
  --wait
```

`scan` is asynchronous unless `--wait` is supplied. Waiting is bounded and does
not cancel a durable scan on client timeout or interruption. A completed scan,
including one with critical findings, exits zero. Operational failure,
cancellation, predecessor blocking, or wait timeout exits 5; interruption while
waiting exits 130. Invalid input exits 2, and an absent or not-ready resource
exits 3 where applicable.

Use the Web UI from Overview through project and scan history; normal navigation
does not require a run UUID, an API call, or raw JSON knowledge. The browser is
read-only with respect to repository submission and never accepts a host path or
source upload.

The corresponding CLI reads are:

```text
securescan project list
securescan scans [--project-id UUID]
securescan status RUN_ID
securescan stages RUN_ID
securescan findings RUN_ID
securescan dependencies RUN_ID
securescan coverage RUN_ID
securescan gaps RUN_ID
securescan report RUN_ID
```

Each supports the documented bounded behavior; data commands with `--json` emit
one JSON document on stdout and keep diagnostics on stderr. Human output encodes
terminal controls and bounds untrusted text.

Export a completed published run as deterministic SARIF:

```bash
securescan sarif RUN_ID --output ./securescan.sarif
```

The exporter verifies the complete Product Core finding set against the
published report and fails closed on missing, inconsistent, incomplete, or
unpublished evidence. It emits one result per canonical finding, uses
repository-relative locations, excludes raw secret material, and writes through
a private same-directory temporary file with an atomic install. Existing files
require explicit `--overwrite`; symlink targets, symlinked parents, directories,
special files, and missing parents are rejected.

The example at `examples/github-actions/securescan.yml` requires an ephemeral,
pre-provisioned runner with the frozen toolchain. The scan job has
`contents: read`; only the separate upload job has `security-events: write`.
It is documentation, not an installed workflow, and the release gate did not
perform or claim a real GitHub Code Scanning upload.

## Packaging boundary

The wheel contains the trusted-host CLI, worker/operator code, SARIF exporter,
scanner configuration, rules, and Web UI assets. In the supported deployment,
the Compose API image is built from the source distribution and owns
`alembic.ini` plus `migrations/`; those files are intentionally not wheel package
data. Release acceptance installed the built wheel for trusted-host operations
and used the source-built API image for migrations and the same-origin service.

## Security and truth boundaries

Repository paths enter only through the trusted-host CLI. The browser uses a
strict same-origin GET surface, a restrictive CSP, and text-node rendering for
untrusted values. Operator credentials remain in the private profile and are
not printed by normal status or doctor output. Scanner-native data is normalized
and sanitized before public evidence; Gitleaks output never exposes the matched
secret or an unsafe snippet. Unknown is never converted to zero, tool failure is
never converted to clean, and zero gaps is not described as complete security
coverage.

## Final acceptance

The V1.1R gate used a fresh isolated profile, Compose project, deployment root,
ports, volume namespace, database, and test database. An empty PostgreSQL
database migrated to head before project creation and real scanning. Older local
deployments remained running and untouched.

The primary run completed with ten canonical findings: seven Checkov, one
Gitleaks, one OSV, and one Semgrep. The five-authority stage roster published
complete coverage with zero gaps. The vulnerable dependency case retained one
canonical `PyYAML 5.3.1` advisory group; controlled clean and not-applicable runs
proved exact zero and N/A without mutable external intelligence. A four-scan
lineage exercised every V1.1 lifecycle state. The complete browser click path,
desktop/mobile visual sanity, CLI human/JSON surfaces, deterministic SARIF,
zero-result SARIF, fail-closed cases, and restart persistence all passed.

The final release-relevant matrix passed 3,216 unique tests, including 146
PostgreSQL tests. One skip was classified as nonapplicable because the gate had
one explicitly prepared Checkov environment rather than a second independent
hash-locked environment. Historical scanner characterization modules whose
contracts require the exact `source/v0.3-semgrep` branch were not rerun as V1.1R
branch tests; their frozen accepted evidence was unchanged, while the active
scanner regression partitions passed. Ruff, compileall, diff checks, wheel
inspection, source-cleanliness review, and final security/bounds review passed.

## Known limitations

V1.1 is deliberately limited:

- local trusted-host repositories only; no browser upload or remote Git backend;
- single-node operation, with no authentication or multi-tenant isolation;
- no policy engine, `fail-on-findings`, analyst disposition, accepted-risk, or
  suppression workflow;
- no KEV, EPSS, threat-intelligence enrichment, AI, reachability, VEX, DAST,
  malware analysis, or generalized container-scanning product surface;
- no universal remediation or exploitability claim;
- no exhaustive language, rule, package-manager, or secret-detection coverage;
- exact-pinned requirements support excludes ranges, compatible releases,
  unpinned names, extras, markers, include trees, VCS/local references, and
  dependency resolution; and
- the GitHub Actions example depends on a pre-provisioned ephemeral runner and
  is not claimed portable to ordinary GitHub-hosted runners.

These are explicit product boundaries, not clean-analysis conclusions.
