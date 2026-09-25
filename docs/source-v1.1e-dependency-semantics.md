# SecureScan Source V1.1E dependency semantics

## E0 evidence-contract audit

Status: **E0 COMPLETE - AWAITING REVIEW**

Baseline: `source-v1.1B-read-model-api` at
`6c122dbe966f2a809a8f64a7b42ed0fe57bc2fb2`.

This checkpoint is a read-only architecture audit. It changes no production,
scanner, orchestration, evidence, API, UI, or database behavior.

### Authoritative chain

```text
Syft PackageObservation
  package coordinates -> package_key
  structural observation -> package_observation_id
        |
        v
S4 PACKAGE component
  (PACKAGE, package_key) -> component_ref
        |
        +--> SourceDependencyEvaluation
        |      observation scope classifications
        |      coordinate and mixed-scope gaps
        |      eligible observation IDs and candidate IDs
        |
        +--> accepted OSV input/result
               candidate_id -> package_key + observation IDs
               completed/zero-advisory candidate IDs
               package-bound advisory groups
        |
        v
S4 OSV finding + advisory-group evidence
        |
        v
Product Core priority + dependency projection
```

No dependency read path calls OSV or another external service. Current reads use
durable database state and content-addressed artifacts.

### Authority and correlation matrix

| Public fact | Authority and retained source | Correlation key | Nullable | Meaning | Integrity/failure behavior | Safe to expose |
|---|---|---|---|---|---|---|
| `component_ref` | S4 `SecureScanComponent` | digest of `PACKAGE` plus Syft `package_key` | no | Stable package-component reference for equal normalized coordinates | Typed S4 reconstruction rejects a mismatch | yes |
| `name` | Syft package component payload | `component_ref` / `package_key` | no | Observed normalized package name | Fail closed on malformed component payload | yes |
| `version` | Syft package component payload | `component_ref` / `package_key` | yes | Version observed by Syft; absence remains unknown | Fail closed on malformed payload | yes |
| `package_type` | Syft package component payload | `component_ref` / `package_key` | no | Syft package type | Fail closed on malformed payload | yes |
| `purl` | Syft package component payload | `component_ref` / `package_key` | yes | Canonicalized observed PURL when present | Invalid PURLs are rejected during normalization/S4 validation | yes |
| `locations` | Syft package-observation evidence | `component_ref` and exact observation IDs | no for a valid observation | Canonical repository-relative observation locations | Dangling/cross-component evidence fails S4 validation | yes |
| inventory observation | Presence of a Syft-derived `PACKAGE` component | `component_ref` | no | Every item currently returned by `/dependencies` is already observed inventory | Non-package components are not returned | yes, but a constant `OBSERVED` field would be redundant |
| evaluation state | Dependency evaluation artifact, accepted OSV result, OSV node/stage, and S4 coverage | run + OSV node + candidate/package correlation | state-dependent | Whether evaluation completed, was partial, failed, or was not applicable | Missing or contradictory required artifacts must fail closed; legitimate coarse states remain coarse | yes after E1 aggregation rules |
| evaluation reason | Frozen decision/gap/failure codes, with the stage projection's safe normalization where applicable | run/node or package gap | yes | Machine reason for a non-complete state | Never expose raw exception, response, path, or command text | yes with an explicit E1 allowlist/compatibility decision |
| `known_vulnerability_count` | Count of canonical package-bound OSV S4 findings | `component_ref` | yes | Exact count only when that package's evaluation is proven complete | `PARTIAL`, `FAILED`, and `NOT_APPLICABLE` must return `null`; contradictions fail closed | yes |
| advisory identity | OSV advisory group plus S4 finding identity | finding subject `component_ref`, group evidence, supporting Syft refs | no for a finding | One alias-connected advisory group for one package | S4 validates group digest, revisions, component, provenance, and exact Syft supports | yes; reuse an existing identity, do not invent one |
| OSV record IDs | `OsvAdvisoryGroupEvidencePayload.osv_record_ids` | advisory group | non-empty | OSV records in the canonical group | Strict, sorted, unique validated values | yes |
| generic aliases | OSV advisory-group `aliases` | advisory group | empty allowed | Aliases reported by accepted OSV records | Strict, sorted, unique validated values | yes |
| CVE aliases | OSV group `cve_aliases` | advisory group | empty allowed | CVE identities derived from record IDs plus aliases | Exact validated subset; aliases are not separate findings | yes |
| GHSA aliases | OSV group `ghsa_aliases` | advisory group | empty allowed | GHSA identities derived from record IDs plus aliases | Exact validated subset; aliases are not separate findings | yes |
| fixed versions | OSV group `fixed_versions` | advisory group and matched package | empty allowed | OSV `fixed` events from matching `SEMVER`/`ECOSYSTEM` affected ranges | Empty means no fixed event was retained, not that no fix exists | yes with conservative wording |
| priority band | Product Core lifecycle priority | S4 `finding_id` | no after finalization | SecureScan policy band derived from maximum validated OSV CVSS base score, or `UNRANKED` | Missing finalized priority is an integrity failure | yes; it is not OSV severity or a risk score |
| CVSS evidence | S4 OSV advisory-group evidence | advisory group | empty allowed | Validated OSV CVSS v2/v3/v4 vector/base score with advisory or matched-package scope | Retained in evidence, not currently exposed by the dependency API | potentially safe, but not proposed for V1.1E |

### Identity findings

- `package_key` is a domain-separated SHA-256 over normalized `name`, `version`,
  `type`, and canonical PURL. Locations and run IDs are excluded.
- `package_observation_id` adds cataloger, canonical locations, and `package_key`.
- `component_ref` is a second domain-separated SHA-256 over component kind
  `PACKAGE` and `package_key`.
- `candidate_id` is a domain-separated SHA-256 over `package_key` and PURL.
- OSV records are grouped by transitive intersection of record IDs and aliases.
  The group key includes the sorted OSV record IDs, aliases, and `package_key`.
- The native dependency finding ID is derived from that group key; S4 then wraps
  it with authority and identity-schema domains. One S4 OSV finding therefore
  represents one canonical advisory group for one package, not one alias.
- `canonical_advisory_id` already exists. The frozen rule chooses the first CVE,
  otherwise the first GHSA, otherwise the first OSV record ID. It is a display
  identity, while the digest finding/group identities are structural identities.
- These identities are stable across equivalent normalized evidence. Advisory
  group/finding identity can legitimately change if the accepted record/alias set
  changes; it is not an eternal identifier independent of OSV data.

### Per-package evaluation conclusion

The repository supports more than capability-level evaluation, but not for every
terminal path from one source alone.

For runs that reached durable dependency evaluation:

- every Syft observation is retained with `package_key` and `IN_SCOPE`,
  `OUTSIDE_SCOPE`, or `MIXED_SCOPE` classification;
- mixed-scope and coordinate gaps retain `package_key`, observation IDs,
  locations, and a closed reason code;
- the OSV execution input/result retains each candidate's `package_key` and exact
  observation IDs;
- an accepted OSV result requires its completed candidate IDs to equal the full
  candidate set and separately retains zero-advisory candidate IDs;
- OSV findings retain the same `package_key` and become S4 findings bound to the
  corresponding `component_ref`.

This proves candidate-to-component completion and clean/vulnerable results, and
it proves package-specific mixed/unsupported/outside-scope conditions. A single
package key may have several structural observations with different scope
classifications, so E1 must freeze a deterministic aggregation rule; it must not
select the most convenient observation.

For legitimate planning omission (the frozen zero-outcome Gate-4 case), there is
no OSV node/evaluation artifact. Only the validated roster/stage proves
capability-level `NOT_APPLICABLE`; that state must remain the conservative result
for all displayed packages. If dependency evaluation fails before its artifact,
or OSV execution fails without an accepted result, only the authoritative
node/capability failure is available for affected candidates. Missing artifacts
must not be interpreted as package success.

Therefore V1.1E can define a hybrid per-package projection without a migration or
scanner/orchestration change, provided E1 explicitly defines artifact-present and
legitimately-artifact-absent paths. A universal inference from S4 findings alone
is not defensible.

### Answers to the E0 audit questions

1. Canonical package identity is Syft `package_key`, derived from normalized
   name, version, type, and canonical PURL.
2. `component_ref` is derived from component kind `PACKAGE` and `package_key`.
3. It is stable for equivalent normalized coordinates across scans; coordinate or
   canonicalization changes correctly produce a new identity.
4. One native OSV vulnerability is an alias-connected, package-bound advisory
   group. Its structural identities are `advisory_group_key` and the derived
   finding ID; `canonical_advisory_id` is its existing display identity.
5. One OSV S4 finding equals one canonical advisory group for one package. The
   same advisory affecting different package identities produces separate
   package findings.
6. Yes. Transitive alias grouping joins several OSV/CVE/GHSA identities into one
   finding.
7. Generic aliases, CVE aliases, GHSA aliases, OSV record IDs, and fixed versions
   are stored in `OSV_ADVISORY_GROUP` evidence. Revision evidence separately
   retains each OSV record ID, modified timestamp, publication timestamp, and
   aliases.
8. The current endpoint counts OSV S4 findings grouped by `component_ref`, but
   returns that integer only when the single run-level OSV outcome maps to
   `COMPLETE`.
9. Valid producer output cannot create two same-package findings for records
   connected by aliases; grouping is transitive. The same advisory across two
   package components is intentionally two package findings. E1/E2 should also
   reject cross-finding duplicate group relationships in projected data.
10. Yes. Native OSV normalization performs deterministic transitive grouping and
    S4 rejects duplicate identities and invalid relationships.
11. Yes. Candidate -> `package_key` -> PACKAGE `component_ref` is exact, and the
    candidate retains exact Syft observation IDs.
12. Yes. Dependency evaluation persists per-observation scope classification and
    package-specific gaps. Accepted OSV input/result persists per-candidate data.
13. For an artifact-backed path SecureScan can prove evaluated candidates,
    outside-scope observations, mixed-scope observations, unsupported coordinates,
    and accepted zero-advisory completion. `skipped` is not a frozen package state
    and must not be invented.
14. Trustworthy evaluation is per candidate/package on artifact-backed paths and
    only capability-level on legitimate no-node or pre-artifact failure paths.
15. Closed producer codes include scope/coordinate gaps, dependency decisions,
    OSV execution failure codes, and coverage reasons. The stage API exposes only
    its existing normalized safe subset.
16. Dependency reasons are already observable as nullable public strings, but are
    not a strict response enum. E1 must preserve compatible values and define the
    safe package-level subset rather than expose arbitrary internal text.
17. OSV `PARTIAL` means accepted advisory work exists with a coverage limitation
    or a partial execution boundary; it does not mean zero findings.
18. Yes. Assembly retains validated findings from an accepted OSV result and adds
    gaps/`PARTIAL` coverage.
19. `FAILED` means the OSV/dependency capability did not produce an accepted
    complete result for its declared scope. Its count is unknown.
20. A genuine assembled failed terminal fragment contains no OSV findings. An
    accepted result terminalizes complete or partial; failed-plus-findings in S4
    would be contradictory.
21. Explicit `NOT_APPLICABLE` paths include no packages observed and packages only
    outside advisory scope. Planning may also legitimately omit an OSV node, which
    yields the roster stage `NOT_APPLICABLE` with no S4 outcome.
22. Yes. Zero OSV outcomes can be legitimate planning omission or missing/corrupt
    data. Absence alone has no semantic meaning.
23. The Gate-4 case is proved by the validated planning snapshot/trusted roster,
    the unique OSV stage with no node and `NOT_APPLICABLE`, published empty OSV
    coverage, and absence of OSV findings.
24. Fixed versions are authoritative accepted OSV data for matching affected
    package entries.
25. They mean only that OSV reported a `fixed` event in a matching `SEMVER` or
    `ECOSYSTEM` range. They are not a recommendation or compatibility/safety
    guarantee.
26. OSV priority bands are Product Core policy based on the maximum validated
    CVSS base score: critical at 9.0+, high at 7.0+, medium at 4.0+, low above
    zero, info at zero, and unranked without validated CVSS.
27. They are SecureScan priority, not OSV severity, CVSS itself, exploitability,
    or reachability.
28. Yes. Typed CVSS vector, base score, source, version, and advisory/matched-package
    scope are persisted in OSV advisory-group evidence.
29. The endpoint has no per-component database query, but it rescans all evidence
    to collect Syft locations for every component: CPU work is
    `O(components * evidence)`. The zero-outcome path also reconstructs the report
    again through `get_stages`.
30. Normal dependency reads load the verified report once and priorities in one
    query; database/CAS work does not grow per component. The current location
    scan is the clear scaling defect to remove with one in-memory index.

### Proposed architecture challenged by the audit

- `inventory_status="OBSERVED"` is not new information: the endpoint already
  returns only observed Syft PACKAGE components. E1 should omit it unless an
  explicit field materially improves compatibility for the future UI.
- Run-level OSV coverage cannot truthfully be copied onto every package. A run may
  contain completed candidates, unsupported coordinates, mixed observations, and
  outside-scope packages simultaneously.
- S4 alone does not retain successful zero-advisory candidate identities. The
  durable dependency-evaluation and accepted OSV artifacts are required for the
  finer projection.
- A flat union of aliases, fixed versions, and priority bands loses advisory
  relationships. Existing flat fields may remain compatibility summaries, but a
  nested advisory model must preserve each canonical group's evidence.
- `canonical_advisory_id`, OSV record IDs, aliases, and S4 finding ID are distinct
  facts. A new synthetic `advisory_ref` is unnecessary; E1 should select and name
  an existing identity explicitly.
- Current `known_vulnerability_count` is safe for globally complete homogeneous
  runs, but its run-level evaluation state is too coarse for mixed package scope.
- `PARTIAL` may expose an observed advisory subset, but its exact total must remain
  `null`. Genuine `FAILED` and `NOT_APPLICABLE` paths cannot expose advisories.

### E0 decision and E1 boundary

E0 finds no need for a migration, new scanner, external data source, or change to
frozen execution semantics. The required facts are already durably retained and
integrity checked.

E1 may proceed only to freeze a public semantic contract. It must decide:

1. the deterministic aggregation precedence for multiple observations/gaps under
   one package key;
2. artifact-backed per-package states and the conservative stage-level fallbacks;
3. whether to omit redundant `inventory_status`;
4. which existing identity names the nested advisory;
5. the exact safe reason-code compatibility set;
6. how flat compatibility summaries are derived from nested advisories; and
7. whether partial-prerequisite candidate completion can be called package-complete
   or must remain partial under the frozen coverage boundary.

No V1.1E production implementation is authorized by this document.
