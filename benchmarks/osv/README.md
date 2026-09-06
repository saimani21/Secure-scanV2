# Controlled OSV S2 evidence

This directory separates the frozen package query plan, trusted service contract,
sanitized public service snapshot, and deterministic offline evaluation. The single S2
acquisition used `POST /v1/querybatch` followed by `GET /v1/vulns/{id}` against
`https://api.osv.dev`. Ordinary checks and tests replay the committed snapshot and make
no network request.

The six package-version cases cover PyPI, npm, and Go with one historically affected
case and one same-package fixed/nonaffected boundary in each ecosystem. The acquired snapshot contains six
OSV records, four alias-equivalence groups, four normalized findings, and three complete
zero-advisory query results. It preserves public advisory identity, modified timestamps,
aliases, applicable affected-package data, fix events, and CVSS vectors needed by the
S2 contract. It excludes full details, credits, references, arbitrary database/ecosystem
metadata, raw headers, and transport internals.

Run the offline gate with:

```bash
scripts/run-osv-s2.sh check
scripts/run-osv-s2.sh test
scripts/run-osv-s2.sh report
```

`acquire` is a no-overwrite evidence-creation mode, not an ordinary test. The optional
`live-sentinel` checks service functionality but is not canonical evidence and makes no
stable advisory-count assertion.

Online OSV matching sends normalized package coordinates, including PURLs, names, and
versions, to `api.osv.dev`. It sends no repository file contents. SecureScan disables
redirect following and proxy inheritance, supplies no credentials or cookies, and fixes
the origin in code, but does not claim an OS-level egress sandbox. A local OSV database
mode is outside S2.

Zero advisories means only that OSV returned no known matching advisories for that exact
query in the captured service snapshot. It does not establish that a package is safe or
free of vulnerability risk.

Affected entries bind first by canonical versionless PURL. When OSV omits that optional
field, they bind only by an exact ecosystem mapping plus narrow package-name identity:
PEP 503 normalization for PyPI, exact scoped/unscoped npm identity, or exact Go module
path. `SEMVER` and `ECOSYSTEM` fixed events are version evidence; `GIT` fixed commits are
not. CVSS evidence retains whether it came from advisory-level or matched-package data.
