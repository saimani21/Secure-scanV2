# SecureScan Source V1.3 trust model

Status: Prompt 1 foundation contract

## Trust boundary

`VerifiedPublishedRunGateway` is the read boundary for published Source evidence. A read is
trusted only when all of the following agree:

1. the run and orchestration are terminal, published, and status-consistent;
2. the reconstructed value is a fully typed S4 `SecureScanEvidenceReport`;
3. run, repository, profile, and plan identities agree with the orchestration;
4. the declared final-result media type, schema, digest, size, and CAS path are exact;
5. canonical typed S4 bytes equal both the CAS bytes and the canonical published DB JSON;
6. target/project ownership exists, and any caller-supplied project or lineage scope agrees.

The gateway returns a `VerifiedPublishedRun`, not untyped JSON. Product queries, guidance,
finding views, baseline reads, lifecycle processing, Security Delta, CycloneDX, and toolchain
exports therefore reuse the same verification implementation. The finding-index compatibility
methods delegate to the gateway; they do not define a second verification policy.

## Authoritative and derived data

The authoritative security evidence remains the frozen S4 report in content-addressed storage.
Database `report_json` is a publication copy that must byte-agree after canonicalization. Finding
indexes, lifecycle, governance, suppression, baseline, delta, policy, guidance, component
identity, CycloneDX, and toolchain documents are projections. A projection cannot repair,
augment, or override S4 evidence.

CycloneDX is a read-only interoperability projection. It includes components and coordinates
that S4 proves. It deliberately omits a dependency graph because current S4 package observations
prove inventory, not direct or transitive dependency edges. It never infers a dependency edge
from an OSV match, a manifest location, or co-occurrence in a run.

## Trusted tools and external authorities

Scanner facts are accepted only through the existing frozen binding, execution, parsing,
sanitization, and S4 assembly paths. A per-run toolchain manifest reports only persisted facts:

- scanner or service identity and version;
- adapter identity and version for recorded executions;
- binding, projection, ruleset, and advisory snapshot digests where S4 carries them;
- planning snapshot, profile, plan, and authority-roster digests;
- the verified final-report artifact digest.

The manifest is deterministic, run-linked, path-free, and read-only. Only executions linked to a
selected accepted scanner attempt are counted; unaccepted, failed, or unattached execution rows
cannot poison the manifest. Random execution IDs, timing, host paths, warnings, and errors are
excluded.

OSV is an external advisory authority. Its API version, schema version, snapshot digest, and Syft
binding link come from frozen S4 provenance. SecureScan does not reinterpret an OSV advisory as
a package identity or dependency relationship.

Enry is a trusted profiling helper during intake, but the frozen planning snapshot does not
persist its helper digest or library version. V1.3 Prompt 1 therefore reports
`ENRY_RUN_IDENTITY_NOT_PERSISTED_IN_FROZEN_PLANNING_EVIDENCE` instead of substituting the current
machine configuration. Adding historical Enry identity requires a separately reviewed future
evidence-contract change.

## Failure behavior

Missing rows, wrong ownership, non-terminal state, altered publication metadata, CAS corruption,
non-canonical or contradictory component coordinates, and DB/CAS/S4 disagreement all fail
closed. Export commands return no partial document when verification fails.

## Schema and migration decision

No database migration is required. The new outputs are derived from immutable S4, orchestration,
and execution facts already present. Persisting duplicate projection state would add a second
source of truth without improving integrity.

This phase does not change lifecycle matching, governance, suppression, baseline, delta, policy,
scanner execution, or V1.2 publication semantics. It adds no UI and does not implement the V1.3
JavaScript/TypeScript phase.
