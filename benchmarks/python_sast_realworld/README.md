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

Applicability review remains unstarted. No production rule is associated with
a case, no real-world scan has occurred, and no real-world TP/FP/FN/TN,
precision, recall, or F1 exists. The F2D synthetic results did not influence
selection. `PYTHON_SAST` remains `SCANNABLE`.
