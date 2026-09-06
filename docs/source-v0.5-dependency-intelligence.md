# Source v0.5 dependency intelligence

Decision: `PACKAGE_INVENTORY = SCANNABLE` and
`DEPENDENCY_ADVISORY_MATCHING = SCANNABLE`.

Source v0.5 connects frozen Syft current-snapshot `PackageObservation` evidence to a
bounded OSV v1 client. It groups equal package coordinates by `package_key`, queries only
standards-valid, package-name-consistent versioned PURLs in the frozen PyPI/npm/Go
mapping, and retains every
originating observation ID and normalized evidence location. OSV remains the authority
for ecosystem-specific affected-version matching; SecureScan does not implement a second
version comparator.

Frozen S1 preserves and canonicalizes Syft's coordinate fields but does not independently
prove that `package_name` identifies the package encoded by `purl`. S2 therefore performs
that three-ecosystem consistency check before networking and records
`OSV_PURL_PACKAGE_MISMATCH` rather than querying contradictory coordinates.

Full advisory records are checked against the frozen OSV 1.9.0 JSON schema and against
the exact ID and `modified` value returned by `querybatch`. Withdrawn or changed records
fail closed. Alias components use only record IDs and `aliases`; `upstream` and `related`
never establish identity. Findings retain applicable fixed events, validated CVSS v2/v3/v4
vectors, CVE/GHSA aliases, and Syft projection provenance without claiming reachability
or exploitability. Affected entries without PURLs use only the frozen exact ecosystem
mapping and narrow ecosystem-specific package-name normalization. CVSS retains
`ADVISORY` or `MATCHED_PACKAGE` scope. Only `SEMVER` and `ECOSYSTEM` fix events become
fixed-version evidence; GIT commits never do.

## Claim matrix

Supported:

- Syft current-snapshot package inventory and exact queryable package coordinates
- OSV package/version advisory matching for the frozen PyPI, npm, and Go PURL mapping
- CVE/GHSA preservation and alias-aware per-package grouping
- applicable fixed-version evidence and validated CVSS evidence when present
- deterministic finding/provenance identities
- explicit successful zero-advisory completion, package gaps, and failures

Limited:

- ecosystem coverage and the availability of package PURLs/versions
- OSV database and alias completeness
- fixed-version and CVSS availability
- a mutable online advisory service
- privacy and network assurance: coordinates leave the machine; there is no OS-level
  egress sandbox

Not supported:

- exploitability, reachability, runtime relevance, or active exploitation
- NVD enrichment, EPSS, VEX, or a dependency remediation solver
- universal vulnerability completeness
- Git-history or runtime package inventory

The controlled S2 snapshot is repeatable offline and supports production-ready behavior
for this defined boundary. It is not a representative accuracy benchmark, so neither
capability is promoted to `BENCHMARKED`.
