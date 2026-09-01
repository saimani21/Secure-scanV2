# Controlled Real-World Python CVE Acquisition

This directory is the v0.3F2E1 discovery and exact-upstream-pinning record. It
is an acquisition plan, not a scanner result or benchmark score.

PySASTBench is used only as a pinned discovery index. The parser creates a
dedicated model from exactly `CVE`, `CWE Type`, `Type`, `vul position`,
`project`, `Project Type`, and `Version`. Its historical tool-result columns
are forbidden from selection, are absent from the candidate and case evidence,
and are covered by a hostile invariance test. The large PySASTBench source
archive is neither downloaded nor vendored.

The canonical ledger records all 18 requested seed CVEs, including five
explicit deferrals. Thirteen cases meet the F2E1 acceptance requirements. Their
original upstream repositories, licenses, exact vulnerable and fixed
revisions, advisory provenance, bounded relevant Python paths, per-file
SHA-256 identities, relevant-tree digests, and concise fix-diff metadata are
frozen in `accepted-cases.json`. Repeated patch families are identified rather
than counted as independent diversity.

Original repositories live only under the ignored
`.cache/securescan-realworld-python/` directory. Acquisition invokes tightly
controlled Git commands with hooks, prompts, submodules, global/system config,
and LFS smudging disabled. It does not install dependencies, import project
modules, execute project scripts, run project tests, build containers, or
execute acquired code. `verify` and `summary` set Git's no-lazy-fetch boundary
and are offline-only.

Run:

```text
scripts/setup-python-sast-realworld-cases.sh acquire
scripts/setup-python-sast-realworld-cases.sh verify
scripts/setup-python-sast-realworld-cases.sh summary
```

Only `acquire` is permitted to use the network. It retrieves Git objects for
the pinned discovery CSV, exact revisions, bounded relevant source paths, and
license files. `verify` authenticates the stored remotes, commits, licenses,
per-file hashes, relevant-tree digests, case-set digest, and deterministic
summary without network access.

F2E2 adds a pending-human-approval claim-applicability proposal without changing
the frozen F2E1 corpus. It independently inspects only the bounded vulnerable
and fixed source and the human-readable frozen rule-claim catalog. Evidence is
location-aware and bound to the F2E1 path, revision-role, and source SHA-256;
same-CWE similarity alone is insufficient. Vulnerable and fixed revisions are
classified independently because a dangerous-API observation may legitimately
remain true after a vulnerability is fixed.

The three `applicability-*.json` documents account for all 13 accepted CVEs.
`OUTSIDE_FROZEN_RULE_CLAIMS` means that the legitimate CVE implementation is
outside the current claim boundary; it is not a future false negative and does
not enter F2E3 evaluation. Generation uses Python AST/source inspection and
offline Git blob reads only. It cannot execute Semgrep or SecureScan, does not
read production rule configuration or prior scanner results, and emits no
TP/FP/FN/TN, precision, recall, or F1.

Run the scanner-independent review tooling with the project interpreter:

```text
.venv/bin/python -m securescan.benchmarks.python_sast_realworld_applicability_cli check
.venv/bin/python -m securescan.benchmarks.python_sast_realworld_applicability_cli generate
.venv/bin/python -m securescan.benchmarks.python_sast_realworld_applicability_cli summary
```

F2E2 is implemented but pending hostile/human approval. F2E3 remains future
work, no real-world scan or metrics exist, and `PYTHON_SAST` remains
`SCANNABLE`.
