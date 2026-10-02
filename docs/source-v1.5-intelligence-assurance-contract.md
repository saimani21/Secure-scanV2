# SecureScan Source V1.5 intelligence and assurance contract

Status: Prompt 1 implementation contract

Baseline: `source-v1.3.0` at
`f01b1887cb232a928f3d0af8d2c3e8e28e5daa09`

## Existing authority path

The frozen dependency path is:

```text
accepted Syft evidence
-> canonical package component and PURL
-> OSV query candidate
-> exact OSV advisory revision
-> S4 OSV advisory-group evidence
-> verified Product Core finding
-> lifecycle / governance / baseline / delta / policy projections
```

OSV remains the only package affected-version authority. Its `aliases` array is
preserved by `OsvAdvisoryObservation`, S4 `OsvAdvisoryGroupEvidencePayload`, and
the verified Product Core finding evidence. `related`, `upstream`, descriptions,
CWE values, package names, and NVD CPE data are not identity evidence.

`VerifiedPublishedRunGateway` remains the single read boundary for published
source evidence. Finding Intelligence and Run Assurance consume its typed
`VerifiedPublishedRun`; they never reconstruct or repair S4 independently.

The existing Product Core contracts remain unchanged:

- finding identity is derived from frozen scanner evidence, never intelligence;
- lifecycle records source-evidence presence and absence;
- governance and suppression are explicit, episode-aware operator state;
- trusted baselines change only through explicit promotion;
- Security Delta compares a candidate with an explicitly promoted baseline;
- deterministic policy uses one evaluation timestamp and effective governance.

## Exact CVE identity

One canonical validator accepts uppercase `CVE-YYYY-NNNN...` only. The year is
four digits and the sequence contains 4 through 19 ASCII digits. Normalization
does not silently uppercase or trim malformed input. Exact, valid values from an
OSV advisory's `aliases` array are deduplicated and sorted. The OSV record ID is
an advisory identity and is not promoted to a CVE unless it was also supplied as
an alias. Multiple CVEs remain separate relationships.

## Source separation

- OSV: component-to-advisory and affected/fixed-version authority.
- NVD 2.0: descriptive data for an already proven exact CVE only.
- CISA KEV: catalog membership evidence for an exact CVE.
- FIRST EPSS: daily probability and percentile evidence for an exact CVE.

No source replaces another. SecureScan does not perform NVD CPE discovery,
package/description/CWE/fuzzy matching, a second GHSA matcher, or a composite
risk score.

Pinned Prompt-1 source contracts reviewed on 2026-10-02:

- NVD CVE API 2.0: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- CISA KEV JSON/schema repository:
  `https://github.com/cisagov/kev-data`
- FIRST bulk EPSS data contract:
  `https://www.first.org/epss/data`
- FIRST current daily file:
  `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`

The vendored KEV schema is packaged with the parser; the parser contract and
schema provenance are recorded on every snapshot. FIRST's metadata comment,
model version, and score date are preserved. NVD API keys are accepted only as
an in-memory client argument suitable for environment/configuration injection.

## Immutable persistence

An `IntelligenceSnapshot` is an immutable, content-addressed record for KEV or
EPSS. Identity is a domain-separated digest of source, parser contract, source
metadata, and raw-content SHA-256. The raw bytes are stored in the existing CAS;
the database stores the CAS digest/size plus normalized records and provenance.
Only a completely bounded, parsed, schema/semantically validated, normalized,
CAS-persisted snapshot is eligible. Duplicate content is idempotent. A failed
import writes no eligible snapshot and cannot deactivate or alter prior data.

NVD exact-CVE enrichment is immutable content-addressed evidence, not a feed
snapshot. Requests contain only `cveId`; an optional API key is sent only in the
`apiKey` header and is never stored or logged. Redirects are rejected. Responses
are bounded and must return exactly the requested CVE.

An `IntelligenceBundle` deterministically names one KEV snapshot, one EPSS
snapshot, and the selected immutable NVD records. Evaluation never reads live
network state.

`ThreatAssessment` is append-only and run/finding/advisory/CVE scoped. It records
the exact bundle and evaluated time. Re-evaluation with newer intelligence adds
new evidence and never rewrites history. Duplicate submission of the same
authoritative inputs is idempotent.

## Typed absence and freshness

KEV states are `LISTED`, `NOT_LISTED_IN_SNAPSHOT`, and `UNAVAILABLE`.
`NOT_LISTED_IN_SNAPSHOT` never means not exploited. EPSS states are `SCORED`,
`NOT_SCORED`, `UNAVAILABLE`, and `SNAPSHOT_INVALID`; absence never becomes zero.
NVD evidence may be unavailable without changing OSV affected-version truth.

Snapshot age is evidence. There is no product-wide stale threshold. A policy
that explicitly requires an intelligence source and maximum age produces
`ERROR` when evidence is missing, invalid, corrupt, or too old.

## Read projections

`FindingIntelligence` joins a verified finding to applicable immutable threat
evidence. Dependency findings expose component/PURL, OSV advisory, exact CVEs,
per-CVE NVD/KEV/EPSS evidence, and existing guidance. Other categories expose
only their already verified category evidence and guidance; no CVE is inferred.

`RunAssuranceView` is read-only and combines the verified run, Product Core,
Finding Intelligence, lifecycle, Effective Governance, coverage/gaps, trusted
baseline, Security Delta, and a caller-selected threat assessment set. It is the
backend authority for Prompt 2 consumers and cannot modify any source state.

## Threat-aware policy and proof

Threat-aware rules are an additive extension to deterministic policy. Rules may
fail introduced dependency vulnerabilities for explicit KEV membership or an
explicit EPSS threshold, optionally constrained by verified severity. Effective
governance exclusions retain their frozen meaning. Required missing/stale
intelligence produces `ERROR`, never `PASS`.

Each evaluation emits an immutable, machine-readable `PolicyDecisionProof`
containing the policy identity, candidate, one evaluation timestamp, baseline,
finding/component/advisory/CVE identities, delta, governance, coverage,
selected snapshots and records, rule IDs, deterministic reasons, and evidence
references. Stable proof content excludes the generated row ID. Identical
authoritative state, policy, bundle, and evaluation timestamp yields identical
canonical proof bytes.

## Refresh, evaluation, and concurrency

Refresh/import and evaluation are separate operations. Scanning never requires
KEV, EPSS, or NVD. Evaluation can replay offline from CAS-backed valid evidence,
and an old verified run can be evaluated against a newer explicit bundle.

PostgreSQL uniqueness constraints make duplicate content/evaluation idempotent.
Imports publish one complete row transaction. Evaluation uses one repeatable-read
transaction and concrete snapshot IDs, so a concurrent refresh cannot change its
inputs. No global lock is introduced.

## Explicit non-goals for Prompt 1

No scheduler, final dashboard, `securescan ci`, GitHub Actions, HTML assessment
report, AI assistant, NVD mirror, CPE matching, SPDX/VEX, or `source-v1.5.0` tag
is part of this checkpoint.
