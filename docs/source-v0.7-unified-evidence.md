# Source v0.7 S4 unified evidence

S4 is a narrow projection layer over SecureScan's frozen, validated
scanner-native models. It does not parse scanner output and does not alter any
scanner's identity, execution, binding, or completeness contract.

## Schema and report scope

The canonical schema is `securescan-unified-evidence-s4-v1`. A report contains:

- one `SecureScanReportScope` with `source_run_id`, `repository_digest`, and a
  paired optional `profile_digest`/`plan_digest`;
- logical repository or package components;
- typed evidence and findings;
- sibling suppressions, gaps, and normalized coverage outcomes.

Report scope addresses an occurrence as `(source_run_id, finding_id)`. It is
not part of finding identity. Adapter fragments carry an internal scope binding,
and report assembly rejects a fragment bound to another Source run or
repository.

## Identity contracts

S4 domain-separates deterministic identities:

```text
finding_id  = SHA-256(S4 finding domain, authority, native schema, native finding ID)
evidence_id = SHA-256(S4 evidence domain, authority, native schema, native evidence ID)
component_ref = SHA-256(S4 component domain, component kind, native component ID)
```

Neither finding nor evidence identity uses a list position or random UUID.
Finding identity excludes Source run, repository, binding, projection, display
message, and severity unless a value is already included by the authoritative
native engine identity. Consequently Semgrep remains line-sensitive, Checkov
remains line/name/severity-insensitive, Gitleaks retains its native
scanner-version-sensitive semantics, Syft separates package coordinates from
structural observations, and OSV retains package-and-alias-group identity.

Gitleaks is the one frozen native contract that permits indistinguishable
duplicate structural observations. S4 projects those duplicates to one stable
finding/evidence identity and records their exact `native_occurrence_count` on
the safe Gitleaks evidence payload. This preserves native multiplicity without
deduplication, manufactured identities, or private `Secret`, `Match`, or
Fingerprint material. Other authorities retain ordinary duplicate-ID
rejection.

## Closed taxonomy and types

The finding categories are exactly:

- `CODE_SECURITY`
- `SECRET_EXPOSURE`
- `DEPENDENCY_VULNERABILITY`
- `CONFIGURATION_SECURITY`

`PACKAGE_INVENTORY` is deliberately not a finding category. Syft observations
create `PackageComponent` and package evidence records.

Subjects are a closed union of source code, secret exposure, package,
configuration resource, and repository subjects. Locations are a closed union
of source spans, repository-relative paths, and repository scope. Source files
remain locations/provenance and are not expanded into top-level components.

Severity is optional and authority-qualified. Semgrep uses
`SEMGREP_NORMALIZED`; Checkov uses `CHECKOV`. OSV CVSS stays typed inside OSV
evidence and is not flattened into a generic severity. S4 has no confidence or
global risk score.

## Evidence relationships

Every finding has at least one primary evidence reference. Supporting evidence
is optional. All references resolve within the same report, and duplicate or
dangling relationships fail validation.

- Semgrep rule evidence is primary for code findings.
- Safe structural Gitleaks evidence is primary for secret findings.
- Syft package observations support package components and do not create
  findings.
- OSV advisory group/revision evidence is primary for dependency findings;
  corresponding Syft observations are supporting evidence.
- Checkov misconfiguration observations are primary for configuration findings.
  Checkov suppressions and parse gaps remain sibling records.

The OSV-to-Syft edge is a validated producer-consumer relationship, not
cross-engine correlation. The report requires the subject package component,
Syft package key, projection, snapshot digest, and Syft binding digest to agree,
binds the OSV group/revisions to the native dependency finding, and requires
the supporting evidence references to equal the exact S2
`package_observation_ids` set after deterministic Syft evidence-ID projection.

Coverage outcomes retain only security-relevant completion state, component
reference where present, selected scope, counts, and a bounded reason code.
Their deterministic identities include authority, capability, optional
framework, optional component, and canonical selected scope. Counts are checked
against records in that exact framework/component/scope, allowing multiple
same-capability component executions in one report without collision. Raw
process envelopes, streams, timings, and scanner JSON are not copied into S4.

`SecureScanCoverageOutcome.finding_count` is the authority-native result count
for that exact coverage outcome; it is not universally equal to the number of
unified finding records. In particular, two indistinguishable native Gitleaks
observations produce one S4 finding/evidence record with
`native_occurrence_count = 2`, while the coverage `finding_count` remains `2`.

Semgrep provenance additionally preserves the validated sanitized native-report
artifact ID, producing tool-execution ID, SHA-256, byte size, media type,
artifact kind, and `sanitized=true`. S4 verifies the supplied safe artifact
bytes against that size and digest during adaptation but never serializes the
bytes or the artifact storage/host path.

## Integrity and confidentiality

The report rejects duplicate IDs (after the explicit Gitleaks multiplicity
projection), unsorted canonical collections, dangling
evidence/component references, invalid category/authority/subject combinations,
native payload identity mismatches, cross-scope fragment assembly, and
coverage-count contradictions.

The typed model has no fields for raw Gitleaks `Secret`, `Match`, or
Fingerprint values; Checkov code blocks, variable evaluations, or connected
nodes; raw scanner JSON; source snippets; process stdout/stderr; or absolute
host paths. Canonical output is deterministic strict JSON with no nonfinite
numbers.

## Controlled integration evidence

`benchmarks/unified_evidence/controlled-s4-report.json` is a project-owned,
offline integration replay. It is bound to the existing frozen Semgrep F1,
Gitleaks F5D, Syft S1, OSV S2, and Checkov S3 evidence-file digests. It exercises
the native-model-to-S4 adapters without executing a scanner or using the
network. The report demonstrates one finding in each S4 category, one Syft
package component, an OSV finding supported by Syft evidence, one Checkov
suppression, one Checkov parse gap, and normalized coverage outcomes.

This is integration and determinism evidence, not a new scanner accuracy
benchmark and not cross-engine correlation.

## Deferred boundary

S4 is generated alongside the existing native and legacy representations.
`ScanReport`, historical Semgrep assessment reconstruction, and existing API
formats remain unchanged. Cross-engine deduplication/correlation, lifecycle and
rename tracking, severity harmonization, risk scoring, confidence, EPSS, VEX,
reachability, exploitability, AI, export formats, frontend work, persistence
redesign, and API replacement remain future work.
