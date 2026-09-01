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

## PySASTBench boundary for v0.3F2C

The 6.2 GB PySASTBench archive is not downloaded or vendored here. A later v0.3F2C phase may use
PySASTBench only as a real-world CVE discovery/index source. Candidate discovery may use CVE, CWE,
project, vulnerable position, and affected/fixed version fields. It must not use columns containing
prior Semgrep, Bandit, or other scanner detection results. Any selected real upstream repository
must then be pinned and authenticated directly.

Claim-aligned applicability review occurs before any SecureScan scan. There are no external-corpus
precision, recall, F1 or product-readiness metrics in v0.3F2B.
