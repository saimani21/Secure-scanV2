# Gitleaks bounded real-world evaluation

v0.4F5A is a pre-acquisition and pre-scan contract. It freezes six repository
roles before any repository names, URLs, commits, archives, or snapshots are
selected. Every slot has one primary role; all repository identity and size
fields remain unresolved while the contract state is `PRE_ACQUISITION`.
F5B must document role eligibility evidence and rationale before scanner
execution. Acquired selections must contain six distinct repository IDs, URLs,
URL/commit pairs, and snapshot digests.

Future acquisition is a separate explicit phase. It may use network access to
obtain pinned upstream archives, but later SecureScan execution must use only
verified local snapshots without `.git` history. Scanner execution remains on
the production Source bridge with Gitleaks 8.30.1, the frozen binding,
configuration, ignore file, sanitized parser output, and structural v0.4E
finding identities. Scanner network access and provider validation are
forbidden.

Acquisition must verify the complete archive SHA-256 and extract without
executing repository code, hooks, builds, or installs. Absolute and traversing
paths, containment escapes, symlink/hardlink escapes, special filesystem
entries, and duplicate normalized paths are rejected. F5B must freeze and
enforce bounded member-count, expanded-size, per-file-size, and path-length
limits. A provider top-level directory may be normalized or stripped only
after containment validation, and the resulting ordinary local source tree
must pass through the existing `RepositoryWorkspaceManager` path.

Snapshot identity is exactly the resulting `RepositoryManifest`: the stored
snapshot digest is `content_digest`, file count is `file_count`, and byte count
is `total_bytes`. No alternate repository hash is introduced.

F5 evaluates operational behavior and canonical finding-set repeatability. It
does not calculate precision, recall, F1, TP, TN, FP, or FN without a separately
frozen complete ground-truth dataset. Optional review labels describe only
local evidence and never imply provider validation, credential usability, or a
live secret. Raw credential material and raw scanner streams must never be
published.

No repository acquisition or real-world Gitleaks scan has occurred in F5A, and
`realworld-result-v1.json` does not exist. F3B remains controlled accuracy
evidence, F4C remains limitation and claim evidence, and `SECRET_DETECTION`
remains `SCANNABLE`.
