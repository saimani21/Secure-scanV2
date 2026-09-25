# SecureScan Source V1.1P exact-pinned requirements

Status: `COMPLETE - FROZEN`

V1.1P extends dependency-advisory applicability to the existing
`requirements*.txt` manifest family. These files remain `MANIFEST` inputs and
continue to participate in repository-wide Syft package inventory. They now also
establish `DEPENDENCY_ADVISORY_MATCHING` scope, allowing concrete package
observations from the frozen Syft binding to enter the existing dependency
evaluation path.

SecureScan does not parse or resolve Python requirements. Text in a requirements
file is not package truth. Candidate creation still requires this authority
chain:

```text
requirements*.txt advisory scope
        -> frozen Syft concrete PackageObservation
        -> supported ecosystem and canonical versioned PURL
        -> existing OSV candidate
```

The supported V1.1P syntax claim is limited to plain exact Python distribution
pins of the form `package==version`. Frozen Syft 1.51.0 was exercised twice over
exact, non-exact, and mixed fixtures. Exact pins produced deterministic PyPI
PURLs; ranges, compatible-release expressions, unpinned names, VCS references,
and local paths produced no package observations. In a mixed manifest containing
`PyYAML==5.3.1`, `requests>=2.31`, and `Flask`, only
`pkg:pypi/pyyaml@5.3.1` became an OSV candidate.

V1.1P does not claim support for `>=`, `<=`, `~=`, `!=`, wildcards, unpinned
names, VCS or Git references, editable installs, local paths, remote archives,
requirements include trees, extras, environment markers, dependency resolution,
transitive resolution, or platform/environment solving. Other manifest families,
including `package.json`, `pyproject.toml`, `Pipfile`, `go.mod`, and `go.sum`, do
not gain advisory eligibility from V1.1P. Existing lockfile behavior is unchanged.

Offline acceptance covers production inventory/profile/planning and the Syft to
OSV topology, deterministic frozen-Syft normalization, the real dependency
evaluation service, fake vulnerable and zero-advisory OSV results, Product Core
dependency projection, and PostgreSQL dependency-integrity parity. No live OSV
request, migration, scanner semantic change, OSV semantic change, or V1.1E
Product Core semantic change is part of this checkpoint.
