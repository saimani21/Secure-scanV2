# Python SAST local detection-quality benchmark

This controlled independent local benchmark evaluates the frozen 17-rule
`securescan-python-baseline-v2` ruleset against an independent handcrafted
local corpus. It does not reuse the v0.3E correctness fixtures and does not
modify scanner execution, assessment, planning, or maturity policy.

Valid evidence requires scanner `semgrep-ce`, engine version `1.171.0`, and the
exact ruleset ID, version, and digest in `manifest.json`. A different local
Semgrep version fails closed before evaluation evidence is returned.

## Ground truth and evaluation unit

`manifest.json` defines one explicit expected rule relation for each case file.
Each relation is classified once:

- expected and observed: TP
- expected and not observed: FN
- not expected and observed: FP
- not expected and not observed: TN

Repeated findings for the same case/rule relation do not create extra true
positives. A different production rule firing in a case is recorded under
`unexpected_matches`; it is not silently attributed to the case's expected
rule.

## Metrics

Overall and per-rule precision, recall, and F1 are calculated from case-level
TP/FP/FN counts. Decimal values are rounded to four places using round-half-up.
A zero-denominator metric is encoded as JSON `null`, rather than inventing a
percentage.

## Corpus identity and integrity

The corpus digest covers the schema and benchmark identifiers, frozen ruleset
identity and digest, ordered ground truth, case metadata, relative paths, and
SHA-256 identity of every case file. Loading fails closed for duplicate IDs or
paths, unknown rule IDs, missing or changed files, path traversal, invalid
boolean ground truth, unlisted Python files, and corpus-digest mismatch.

Scanner output is normalized through the existing Semgrep parser. Malformed
output, unknown paths or rules, and any analysis gap fail the run rather than
being skipped.

## Initial baseline

`initial-v0.3e-uncontrolled-observation.json` preserves the pre-reproducibility
run over the frozen v0.3E ruleset. That run used local Semgrep `1.145.0`; its
legacy report did not record scanner identity and is not valid controlled
benchmark evidence. It remains unchanged so later evidence cannot falsify the
history. A controlled initial baseline must be stored separately only after a
run with the exact trusted `1.171.0` engine.

`initial-v0.3e-baseline.json` is that controlled run. It records scanner
`semgrep-ce` version `1.171.0` and the exact frozen ruleset and corpus
identities. The controlled result is TP/FP/FN/TN `51/0/0/51`, with precision,
recall, and F1 each `1.0000` on this corpus only.

## Runner

Use `scripts/run-python-sast-benchmark.sh` without changing the interactive
shell `PATH`. The runner always invokes `.venv/bin/python` explicitly and makes
`.venv-semgrep-1.171/bin/semgrep` visible only inside the controlled benchmark
process tree. Its modes are `check`, `test`, `report`, and `record`. `report`
prints canonical JSON without writing evidence; `record` creates the controlled
initial baseline atomically and refuses to replace different existing evidence.

This local corpus is intentionally bounded. Perfect results here do not prove
ecosystem-wide accuracy, taint/dataflow coverage, or production readiness.
The observed `1.0000` precision, recall, and F1 apply only to this corpus.
