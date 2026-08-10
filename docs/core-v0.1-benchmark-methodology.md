# Core v0.1 benchmark methodology

The benchmark is a deterministic curated micro-benchmark for the exact Core v0.1
vertical slice. The vulnerable corpus has one intended finding for each of the three
bundled Python demonstration rules. The clean corpus has realistic safe alternatives.

Expected and observed findings match only on normalized rule ID, repository-relative
POSIX path, and starting line. Matching never depends on message text, scanner
fingerprints, result order, host paths, or workspace paths.

Metrics use multiset matching:

- `TP`: expected identities also observed
- `FP`: observed identities not expected
- `FN`: expected identities not observed
- precision: `TP / (TP + FP)`
- recall: `TP / (TP + FN)`
- F1: harmonic mean of precision and recall

When both sets are empty, precision, recall, and F1 are `1.0`. With observations but no
expectations they are `0.0`, `1.0`, and `0.0`. With expectations but no observations
they are `1.0`, `0.0`, and `0.0`.

Acceptance requires vulnerable `TP=3`, `FP=0`, `FN=0`, all three metrics at `1.0`, no
analysis gaps, and one raw JSON artifact. The clean corpus must have no observations,
no false positives, no gaps, and one raw artifact. A second vulnerable scan must have
the same repository digest, canonical findings and fingerprints, metrics, gap count,
and artifact count.

The corpus digest hashes the schema version, benchmark ID, sorted relative paths, file
SHA-256 values, and canonical expected findings. It excludes absolute paths, timestamps,
ownership, inode data, workspaces, images, and machine information.

The release-evidence digest hashes canonical release identity, corpus digests,
observations, metrics, gap and artifact counts, repeatability, acceptance, and
limitations. It excludes duration, generated time, runtime IDs, source bytes, raw JSON,
database configuration, image reference, and host data.

No cross-machine duration threshold exists. Any measured duration is local operational
information only. The result supports only this statement: 100% precision and recall on
the bundled three-rule curated micro-benchmark.
