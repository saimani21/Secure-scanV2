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

## F5B1 acquisition policy and manifest schema

F5B1 freezes acquisition policy before repository selection. Only `tar.gz`
archives are permitted. Downloaded archives are limited to 268,435,456 bytes;
archive member count, expanded bytes, individual member size, path bytes, and
path depth align with the unchanged production `RepositoryIntakeLimits`:
50,000 members, 1,073,741,824 expanded bytes, 33,554,432 bytes per member,
4,096 normalized relative-path bytes, and depth 64.

Every archive must be SHA-256 verified before extraction acceptance. Extraction
is member-by-member after validation; blind standard-library `extractall` use,
absolute or traversing paths, containment escapes, normalized collisions,
links, and special entries are forbidden. Extraction occurs in a temporary
location outside the repository without code execution, package installation,
builds, hooks, Git checkout, submodules, or recursive acquisition. The ordinary
local tree then passes through `RepositoryWorkspaceManager`.

`acquisition-manifest-schema-v1.json` is an unresolved `PRE_SELECTION`
template. The state machine is exactly `PRE_SELECTION`, `SELECTED`, and
`ACQUIRED`: selection resolves repository, immutable archive URL, commit,
license, method, and role evidence before acquisition; archive and snapshot
outputs remain null until acquisition succeeds. Repository URL and archive URL
are separate provider-neutral HTTPS identities without userinfo, query, or
fragment, and the archive resource must be explicitly associated with the
selected exact commit.

The schema binds the F5A contract, acquisition policy, scanner, binding,
configuration, and ignore identities and freezes the ten permitted role
evidence types. Future extraction may materialize only regular files and
directories. The template contains no repository identity, acquisition,
scanner-result, finding, or secret data. No populated acquisition manifest or
F5 result exists.

## F5B2R1 repository-selection correction

F5B2 initially selected Miniflux for RW01. The first controlled F5B3 request
received its 985,853-byte archive with SHA-256
`68fcd009c78c35ef4be5db07cde25cd44ea1edcce27e68bb5793c9409c702e3a`.
Before extraction acceptance, validation rejected
`internal/reader/readability/testdata` because it is a `SYMLINK` to
`../../reader/sanitizer/testdata/`. Nothing was extracted, zero workspaces were
created, the other five archives were not requested, and Gitleaks did not run.

F5B2R1 therefore replaces only RW01 with `charmbracelet/gum`, a public
MIT-licensed standalone Go CLI application, at exact commit
`4d089f95507708a71f64dacfe7ca513219dd5267`. Authoritative recursive Git-tree
metadata for that commit was complete: 142 entries, zero `120000` symlink
entries, zero `160000` submodule entries, maximum path length 37 bytes, and
maximum depth three. Role evidence remains `application_entrypoint` and
`package_manifest` from the frozen vocabulary. This is an acquisition-policy
compatibility correction, not scanner-result-driven selection. RW02 through
RW06 remain byte-identical to F5B2 and all acquisition fields remain null.
