# SecureScan Source v1.3.0

SecureScan Source v1.3 deepens the existing evidence model rather than adding
an unrelated scanner catalog. The release combines the Prompt-1 trust,
component, and interoperability checkpoint at
`50500fbafecb5505164def267490a11fc2a09b9f` with bounded JavaScript and
TypeScript SAST and research-grade release validation.

## Trust and interoperability

All public Product Core security reads continue through the
`VerifiedPublishedRunGateway`: CAS identity, artifact digest, typed S4 schema,
and run ownership are verified before findings, dependencies, guidance,
exports, policy, or product views consume published truth. Stable invariants
are catalogued in `docs/security-invariants.md`; the trust boundary and its
explicit trusted-host limitation are in `docs/source-v1.3-trust-model.md`.

Package components now have one canonical native identity and normalized PURL.
Verified runs can export deterministic CycloneDX 1.7 JSON and a deterministic
toolchain manifest. The manifest records proven planner, roster, binding,
ruleset, scanner, adapter, projection, and accepted-execution identities. It
does not invent Enry execution identity or dependency edges that were not
persisted by the frozen evidence model.

## Validated Source SAST coverage

The current production analyzer is `semgrep-source-v1`, capability
`SOURCE_SAST`, binding schema `1.3`. Its immutable v3 ruleset preserves all 17
Python v2 rules and adds six project-owned JavaScript/TypeScript rules covering
bounded dynamic-eval, child-process, redirect, SQL-template, and path-use
shapes. Applicability is limited to Enry-classified Python, JavaScript,
TypeScript, JSX, and TSX text files admitted by the frozen selection policy.

The 18-case JS/TS corpus contains a positive, safe case, and near miss for each
rule family. The pinned Semgrep integration and fresh mixed-repository
acceptance both executed the real current ruleset. Findings retain the existing
Semgrep native identity and flow unchanged through S4, Product Core, lifecycle,
guidance, governance, suppression, baseline, Security Delta, policy, API, CLI,
JSON, SARIF, and Web UI. See
`docs/source-v1.3-js-ts-coverage-contract.md` for precise scope and non-claims.

Go and Java are deliberately deferred. Neither was supportable at the same
bounded-ruleset, applicability, corpus, identity, and regression standard
without materially expanding release risk.

## Validation evidence

The final collection contains 3,613 distinct pytest node IDs:

- 3,550 have passing release evidence;
- 62 are explicit historical branch-bound exclusions: 10 frozen Gitleaks
  maturity/acquisition checks and 52 frozen Python SAST maturity/real-world
  checks that intentionally require `source/v0.3-semgrep`;
- one optional second independently prepared Checkov environment remains an
  external-prerequisite skip; and
- no mandatory or unexplained failure remains.

This accounting is by distinct node identity, not by adding overlapping suite
totals: 3,313 original partition passes + 235 remediated/opt-in passes + two
newly collected passes = 3,550. The ordinary partition records, targeted
corrected-case reruns, 182
PostgreSQL integration passes, four strict Core release passes, seven immutable
Docker/Semgrep integration passes, seven real local Syft/Gitleaks replay
passes, and the new release tests were reconciled against the final collection.

The V1.3 invariant/property/fuzz campaign adds 77 deterministic generated
cases. It covers canonical component/PURL serialization, deterministic
CycloneDX output, required-unknown policy, governance after reopen, monotonic
baseline revision, malformed artifact envelopes and policy documents, strict
non-finite JSON rejection, and safe bounded failures. Existing hostile suites
continue to cover corrupted S4/CAS evidence, malformed PURLs and manifests,
dependency cycles, stale attempts, worker death and recovery, concurrent
lifecycle/governance/suppression/baseline/policy operations, object
substitution, hostile UI strings, export corruption, cancellation, PostgreSQL
state races, and artifact tampering. Unknown or incomplete truth never became
clean.

One fresh disposable mixed repository contained Python, JavaScript,
TypeScript, an exact dependency manifest, a secret fixture, and Terraform. It
ran the real pinned Semgrep, Gitleaks, Syft, and Checkov paths plus a
loopback-only, permit-controlled OSV response. The scenario proved intake,
profiling, applicability, S4 publication, Product Core, guidance, governance,
suppression, explicit baseline promotion, a changed second scan, Security
Delta, policy, CycloneDX 1.7, toolchain provenance, JSON/SARIF, API/CLI parity,
and the same-origin UI route. The second scan did not promote the baseline.
No package coordinate was disclosed to an external OSV service.

V1.2 compatibility is explicit. Frozen V1.2 `python-semgrep-v1` /
`PYTHON_SAST` planning snapshots remain exactly decodable and trusted for
historical reads, while new plans emit only the v1.3 Source-SAST contract.
Legacy runs do not acquire fabricated component, dependency-edge, or Enry
metadata. The complete PostgreSQL migration and upgrade-copy gate passed at
the unchanged Alembic head; V1.3 introduces no migration.

## Performance and resource envelope

The reproducible harness and environment are documented in
`docs/source-v1.3-performance.md`. SecureScan-owned intake/profile/planning
completed at 1,000, 10,000, and 50,000 files plus a bounded pathological shape.
The full run peaked at 196,368 KiB RSS. The 50,000-file case measured 5.900 s
intake, 11.078 s inventory, 15.601 s profiling, and 3.933 s planning on the
recorded WSL2 host. These are characterization results, not scanner-throughput
or production SLA claims.

Existing scanner time, memory, process, output, receipt, and temporary-storage
bounds remain in force. The evidence model proves package inventory rather
than dependency relationships, so no large or deep dependency graph was
fabricated for performance or CycloneDX tests.

## Known limits and non-claims

- JS/TS rules do not prove attacker control, exploitability, reachability,
  sanitization correctness, or interprocedural behavior.
- A clean rule result is not a claim of complete language vulnerability
  coverage.
- Historical/planning evidence did not persist Enry helper run identity.
- S4 proves package inventory, not direct/transitive dependency edges.
- SPDX, VEX, KEV, EPSS, OCI assurance, SLSA provenance, remote Git intake, and
  enterprise multi-tenancy remain out of scope.
- The optional second Checkov installation reproduction was not available; the
  frozen primary Checkov runtime, parser, PostgreSQL, and fresh E2E paths pass.
