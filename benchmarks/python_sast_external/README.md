# External Python SAST candidate acquisition

This directory is v0.3F2 candidate evidence, not scanner evaluation evidence. It records
external ground truth before any SecureScan or Semgrep result exists. `PYTHON_SAST` remains
`SCANNABLE`.

## Sources and roles

- OWASP BenchmarkPython is pinned to the immutable commit in `sources.lock.json`. It is a
  preliminary v0.1 Flask benchmark under GPL-3.0. Its answer key supplies externally labeled
  synthetic cases, but its labels are not assumed to be flawless and matching a selected CWE
  does not establish applicability to a SecureScan rule.
- BenchProctor is pinned to release `2026.07.22`, repository commit and the single Python
  `quicktest` ZIP. Its Flask, Django and FastAPI cases are Apache-2.0 synthetic, standalone
  finding cases. The published ZIP, sidecar, release checksum list, embedded manifest and three
  expected-results files are independently identified in the lock.

Bulk third-party code stays under the ignored `.cache/securescan-benchmarks/` directory. The
committed inventory contains source identities, external ground truth, provenance and hashes of
the review-sample source files. It contains no source code and no SecureScan result, rule mapping,
applicability decision or confusion-matrix classification.

Run the explicit networked acquisition once with:

```text
scripts/setup-python-sast-external-benchmarks.sh acquire
```

The command downloads only the pinned sources, verifies every locked identity and checksum, and
regenerates the canonical inventory and summary. It never discovers or updates a moving pin.
After acquisition, `verify` repeats source verification and inventory generation without network
access. Normal tests use tiny local fixtures and require no external cache or network.

## Candidate filter and sampling

Candidate extraction admits only CWE-78, CWE-79, CWE-89, CWE-94, CWE-95, CWE-295, CWE-347,
CWE-377, CWE-489, CWE-502 and CWE-611. This is a broad review filter only. A CWE family match does
not imply that the case exercises any particular frozen production rule.

All matching OWASP cases are retained. For BenchProctor, the committed review sample retains at
most 20 vulnerable and 20 safe cases per `(source, framework, CWE)`. Selection sorts each
source/framework/CWE/label group by SHA-256 of the immutable identity
`source:release:framework:external-case-id`, with that identity as the tie breaker. It does not use
a runtime seed, source contents, scanner findings or prior tool output. `candidate-summary.json`
preserves full and sampled counts for every reported dimension.

## Known benchmark contamination

Upstream OWASP pull request 6 reports additional reflected-XSS behavior in 33 deserialization
files. It does not establish that their original CWE-502 vulnerable/safe labels are incorrect.
Those labels and CWEs therefore remain accepted and unchanged. The separate
`known_issue = cross-category-xss-contamination` field records the additional behavior, while
`scoring_status = excluded-known-benchmark-contamination` keeps all 33 cases out of later scoring
until applicability review resolves their treatment. OWASP issue 1 disputes the CWE-22 label for
`BenchmarkTest00008`; CWE-22 is outside this candidate filter and the case is not inventoried.

## Claim-aligned applicability proposal

v0.3F2C records a proposed applicability disposition for all 1,460 candidates in
`applicability-proposal.json`. The proposal is generated before scanner execution from the
candidate metadata, verified source files, Python AST semantics, and the independent frozen claim
catalog in `rule-claims.json`. It does not read the production Semgrep YAML. CWE overlap alone is
not evidence that a candidate exercises a frozen claim.

The catalog distinguishes dangerous-API observations from explicit insecure patterns and the
direct-interpolation SQL sink. Safe-labeled examples that still use an intentionally audited API
are not treated as rule negatives. Meaningful literal safe counterparts may be proposed as
`APPLICABLE_NEGATIVE`; arbitrary same-CWE safe code may not. Ambiguous binding, shadowing,
multiple claim relations, and parser uncertainty remain `UNRESOLVED` and unscored. The 33 known
cross-category-contaminated cases remain `EXCLUDED` by fixed policy.

`applicability-audit-sample.json` provides a deterministic, hash-selected hostile-review sample
without source bodies or host paths. `applicability-summary.json` contains disposition and reason
counts only. All non-excluded decisions remain `pending-human-approval`; implementation does not
make them final benchmark truth.

Rebuild these three canonical proposal files from the already verified offline cache with:

```text
./.venv/bin/python -m securescan.benchmarks.python_sast_applicability_cli
```

The applicability proposal was generated before any external-corpus scan and reproduced
identically in a scanner-blocked environment. These F2C files contain no TP, FP, FN, TN,
precision, recall, or F1 measures.

## Controlled external evaluation

v0.3F2D scans all 1,460 frozen candidates from a fresh byte-verified temporary projection using
only `.venv-semgrep-1.171/bin/semgrep` version 1.171.0 and the unchanged production v2 ruleset.
The F2C expectations are immutable inputs. Exactly 579 expected relations are scored: 400
`APPLICABLE_POSITIVE` and 179 `APPLICABLE_NEGATIVE`. The 848 `OUT_OF_SCOPE` and 33 `EXCLUDED`
cases never enter TP, FP, FN, or TN; their findings are retained as non-scoring observations.
Unexpected cross-rule findings are also reported separately.

Use the isolated runner:

```text
scripts/run-python-sast-external-evaluation.sh check
scripts/run-python-sast-external-evaluation.sh test
scripts/run-python-sast-external-evaluation.sh report
scripts/run-python-sast-external-evaluation.sh record
```

The canonical `external-evaluation-report.json` records the primary and per-rule metrics,
coverage gaps, and all non-scoring observation relations. `external-evaluation-review.json`
contains failures, non-scoring observations, and deterministic TP/TN representatives without
source bodies, host paths, or timestamps.

This remains a controlled synthetic external corpus, not an ecosystem-wide or real-world CVE
benchmark. Rules lacking applicable external evidence remain explicitly unvalidated.
`PYTHON_SAST` remains `SCANNABLE`.

## Deferred PySASTBench boundary

The 6.2 GB PySASTBench archive is not downloaded or vendored here. A later phase may use
PySASTBench only as a real-world CVE discovery/index source. Candidate discovery may use CVE, CWE,
project, vulnerable position, and affected/fixed version fields. It must not use columns containing
prior Semgrep, Bandit, or other scanner detection results. Any selected real upstream repository
must then be pinned and authenticated directly.

The current proposal neither starts that work nor changes the F2B source selection.
