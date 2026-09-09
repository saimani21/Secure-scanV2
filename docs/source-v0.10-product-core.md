# Source v0.10 Product Core

## PC1: logical lineage and finding occurrence index

PC1 adds a thin query index over the already-published S4 report. The canonical
S4 document in the final content-addressed artifact and `AnalysisRun.report_json`
remains authoritative. Product Core does not copy evidence, components,
scanner-native output, or complete finding documents.

A `source_target_lineage` is an explicit server-owned identity for Source runs
that belong to the same logical target across content revisions. It is linked
to a Project for ownership, but it is never inferred from a project name,
repository path, target name, content digest, Git metadata, or filesystem
location. Each published run is attached once, receives a sequence under a
lineage-row lock, and records the immediately preceding lineage run explicitly.

After S6D publication, one transaction verifies the terminal orchestration,
published report, frozen schema, artifact digest and size, canonical CAS bytes,
published JSON, run identity, and the report rebuilt through the frozen typed S4
assembly boundary. It then writes compact finding occurrences and marks the run
indexed atomically. Repeating an exact operation is idempotent; changed report,
membership, predecessor, or occurrence material fails closed.

Occurrences reuse S4 `finding_id` exactly and contain only authority, category,
native identity schema, optional severity, canonical subject/primary-location
summaries, report SHA, and ordinal. Expected S4 identity churn from moved spans,
changed package versions, changed resource identity, or changed native identity
is preserved. PC1 adds no fuzzy or cross-run fingerprint.

The index does not store source snippets, secrets, stdout/stderr, raw HTTP,
absolute workspace paths, native reports, Evidence objects, Component objects,
or package inventories. Rich data is loaded from authoritative S4 evidence when
needed.

PC1 does not implement finding lifecycle, first/last seen state, resolution,
priority, API, CLI, reporting UI, or final-report changes. Those remain later
Product Core slices.

## PC2: comparable-scope lifecycle and deterministic priority

PC2 adds a current lifecycle row keyed by the explicit PC1
`(lineage_id, finding_id)` identity and an immutable per-run event. The states
are `NEW`, `EXISTING`, `RESOLVED`, and `REOPENED`. First observation is `NEW`;
another observation of the exact same S4 identity is `EXISTING`; an exact
identity returning after `RESOLVED` is `REOPENED`. There is no fuzzy matching.
Consequently, a moved span, changed package version, changed resource identity,
or other native-identity change creates a new `finding_id` and therefore a new
`NEW` lifecycle. The old identity is considered for resolution independently.

Absence never proves resolution by itself. PC2 resolves an active identity only
when the current run is the explicitly linked, PC1-indexed successor and the
last-seen and current S4 reports have the same frozen schema and an exactly
matching authority coverage identity: capability, framework, component, and
canonical selected scope. Repository/profile/plan digests are deliberately not
used because content revisions are the point of lifecycle comparison.

For Semgrep, Gitleaks, and Checkov, the matching orchestration nodes must retain
the same analyzer ID, contract digest, and exact normalized selected-path set.
Both last-seen and current nodes must be terminal `COMPLETE`, have clean
containment, and reference an accepted clean attempt with a durable native
result. Current S4 coverage must be `COMPLETE`, `COMPLETE_WITH_FINDINGS`, or
`COMPLETE_WITH_SUPPRESSIONS` and must have no gap relevant to the finding
authority/capability/framework/path. For Checkov, a suppression matching the
same authority, subject, and location also withholds resolution; unrelated
suppressions do not. For OSV, all of those checks apply to the OSV node,
and the corresponding Syft prerequisite must independently retain the same
analyzer, contract, and selected paths with complete accepted clean execution.

OSV has one narrow successful-absence alternative. When comparable predecessor
OSV evidence exists, the current accepted clean Syft result and frozen dependency
evaluation may prove a complete zero-package inventory under the exact same
dependency scope. In that case, the current OSV node and S4 coverage must both
be `NOT_APPLICABLE` with exactly `NO_PACKAGES_OBSERVED`, the dependency
evaluation must be the complete `NOT_APPLICABLE_NO_PACKAGES` decision, and no
OSV Job may exist. The prior dependency finding then resolves with
`DEPENDENCY_REMOVED_ZERO_PACKAGE_PROOF`. `NO_PACKAGES_IN_ADVISORY_SCOPE`,
unsupported coordinates, mixed scope, partial or blocked prerequisites, changed
Syft contract/scope, unclean containment, missing accepted Syft evidence, or any
other not-applicable reason remains non-comparable and withholds resolution.

Cancellation, deadline expiry, failure, partial execution, dependency blocking,
reconciliation/unclean containment, missing accepted output, changed contract,
changed scope, incomplete coverage, a relevant gap, or a relevant suppression
records `RESOLUTION_WITHHELD` with stable reason codes. It does not alter the
last-known active state. Failure by an unrelated authority does not prevent a
transition whose own authority has complete comparable proof.

Lifecycle evaluation locks the lineage, current run, explicit predecessor, and
current lifecycle material; verifies PC1 and S4 again; writes priorities,
events, current state, and a deterministic completion digest in one transaction.
Re-evaluation validates that durable material against the full event history and
returns the existing result. Finding/event transition timestamps come from each
authoritative orchestration `published_at`: they describe when the scan
established the state. The lineage run's `lifecycle_evaluated_at` separately
records Product Core processing wall-clock time. Previously evaluated history is
never selected by timestamp or rewritten.

Priority is deterministic triage ordering, not exploitability or business risk.
The bands are `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, and `UNRANKED`:

- Semgrep and Checkov use their normalized severity with
  `SCANNER_NORMALIZED_SEVERITY`; missing or `UNKNOWN` severity is `UNRANKED`
  with `NO_NORMALIZED_SEVERITY`.
- OSV uses the maximum validated applicable CVSS base score: at least 9.0 is
  `CRITICAL`, at least 7.0 `HIGH`, at least 4.0 `MEDIUM`, greater than zero
  `LOW`, and an explicitly validated zero score is `INFO`; this zero-to-INFO
  mapping is a deterministic triage policy, not evidence of no business risk.
  Missing validated CVSS is `UNRANKED`. The reason is
  `VALIDATED_CVSS_BASE_SCORE` or `NO_VALIDATED_CVSS`.
- Gitleaks findings are `HIGH` under the transparent Source-v1 category policy
  `CATEGORY_POLICY_SECRET_EXPOSURE`. This does not claim that every secret is
  exploitable or has the same business impact.

PC2 persists only the priority band and reason codes on the compact occurrence
row. It adds no universal numeric risk score, EPSS, KEV, reachability, evidence
blob, API, CLI, final-report field, or presentation behavior.

The priority vocabulary includes `CRITICAL` for cross-authority consistency.
Frozen S4 Semgrep normalization currently emits only `HIGH`, `MEDIUM`, `LOW`,
or `INFORMATIONAL`, so the Semgrep-to-`CRITICAL` branch is reserved and is not
reachable from the current frozen Semgrep contract.
