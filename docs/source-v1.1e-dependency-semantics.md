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

## E1 public dependency semantics contract

Status: `E1 COMPLETE - AWAITING REVIEW`

E1 freezes the additive contract for
`GET /v1/scans/{run_id}/dependencies`. It does not authorize production, API,
UI, persistence, scanner, migration, or orchestration changes. E2 must implement
this contract without changing the frozen evidence producers.

### Public models

The proposed Product Core models use the existing naming style and add one
nested tuple to the existing dependency summary:

```python
@dataclass(frozen=True, slots=True)
class SourceDependencyAdvisorySummary:
    canonical_advisory_id: str
    finding_id: str
    osv_record_ids: tuple[str, ...]
    aliases: tuple[str, ...]
    cve_aliases: tuple[str, ...]
    ghsa_aliases: tuple[str, ...]
    fixed_versions: tuple[str, ...]
    priority_band: str


@dataclass(frozen=True, slots=True)
class SourceDependencySummary:
    component_ref: str
    name: str
    version: str | None
    package_type: str
    purl: str | None
    locations: tuple[Mapping[str, Any], ...]
    vulnerability_evaluation: str
    vulnerability_evaluation_reason: str | None
    known_vulnerability_count: int | None
    advisories: tuple[SourceDependencyAdvisorySummary, ...]
    advisory_aliases: tuple[str, ...]
    fixed_versions: tuple[str, ...]
    priority_bands: tuple[str, ...]
```

The HTTP schema adds the corresponding strict `DependencyAdvisoryResponse` and
the `advisories` field to `DependencySummaryResponse`. No `inventory_status` is
added: every returned dependency is already an observed Syft `PACKAGE`
component. The route and page envelope remain unchanged.

The dependency fields retain their V1.1B authority. The new advisory fields have
these exact authorities and meanings:

| Field | Authority | Contract |
|---|---|---|
| `canonical_advisory_id` | `OSV_ADVISORY_GROUP` evidence | Existing display identity: first sorted CVE, else first sorted GHSA, else first sorted OSV record ID |
| `finding_id` | S4 `SecureScanFinding.finding_id` | Existing public structural finding identity; it is not the native OSV finding digest in the evidence payload |
| `osv_record_ids` | `OSV_ADVISORY_GROUP` evidence | Exact OSV records in the canonical package-bound group |
| `aliases` | `OSV_ADVISORY_GROUP` evidence | Exact generic OSV aliases retained for the group |
| `cve_aliases` | `OSV_ADVISORY_GROUP` evidence | CVE identities derived by the accepted producer from record IDs and aliases |
| `ghsa_aliases` | `OSV_ADVISORY_GROUP` evidence | GHSA identities derived by the accepted producer from record IDs and aliases |
| `fixed_versions` | `OSV_ADVISORY_GROUP` evidence | OSV `fixed` events retained from matching accepted affected ranges only |
| `priority_band` | Product Core occurrence index | SecureScan Product Core priority for this exact public `finding_id` |

`priority_band` is one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, or
`UNRANKED` and is non-null for every returned advisory. It is SecureScan Product
Core priority, not OSV severity, a CVSS value, exploitability, reachability, or a
risk score. E1 does not expose CVSS.

`fixed_versions` is not an upgrade recommendation, minimum safe version,
compatibility guarantee, or application-remediation guarantee. An empty tuple
means only that no fixed event was retained in accepted evidence; it does not
mean that no fix exists.

The public `finding_id` is intended to support later finding-detail linking. It
and the underlying advisory-group structural identity may legitimately change
when the accepted OSV record/alias group changes. No synthetic `advisory_ref` is
created.

### Evaluation values and exact count contract

`vulnerability_evaluation` remains the closed set `COMPLETE`, `PARTIAL`,
`FAILED`, and `NOT_APPLICABLE`.

| Package evaluation | `known_vulnerability_count` | Advisories |
|---|---:|---|
| `COMPLETE`, accepted zero-advisory candidate | `0` | empty |
| `COMPLETE`, accepted candidate with N groups | `N` | exactly those N groups |
| `PARTIAL` | `null` | accepted, package-bound observed subset allowed |
| `FAILED` | `null` | forbidden |
| `NOT_APPLICABLE` | `null` | forbidden |

`N` is the number of distinct canonical package-bound S4 OSV findings, not the
number of aliases, CVEs, GHSAs, OSV records, or evidence objects. Only
`COMPLETE` may expose an exact count. In particular, `PARTIAL` plus two trusted
advisories means that two were observed, not that the complete count is two.

### Required correlation and integrity checks

Before choosing a package state, E2 must validate the complete evidence chain:

1. load and verify the published S4 report and its frozen run/scope identity;
2. correlate all Syft observation evidence for the `PACKAGE` component, require
   one shared `package_key`, and recompute that the `PACKAGE` component reference
   is the digest of that key; the hash-derived component reference is not
   reversible;
3. when an OSV node exists, load and verify its dependency-evaluation artifact;
4. verify the accepted OSV input binds the same dependency-evaluation digest,
   Syft result, run, node, scope, repository, profile, and plan;
5. verify the accepted OSV result binds that input and that its candidate IDs and
   completed candidate IDs equal the full sorted candidate set;
6. correlate candidate -> package key -> exact observation IDs -> component;
7. correlate every nested advisory through one S4 OSV finding, one
   `OSV_ADVISORY_GROUP` evidence object, the same component, and one Product Core
   priority row for the public finding ID; and
8. prove that the S4 package advisory set equals the accepted result's canonical
   package advisory-group set.

For one package, two advisory projections must not repeat a public finding ID,
native advisory-group key, canonical group relationship, or an identity-connected
OSV record/alias group. If two same-package groups share any member of
`osv_record_ids union aliases`, the producer should have merged them; projection
must reject the duplicate relationship rather than double count it.

Any broken binding, missing required object, unknown enum/code, duplicate
relationship, accepted-result/S4 disagreement, missing priority, or impossible
state is a whole-query integrity failure. The endpoint returns its existing
`QUERY_UNAVAILABLE` error path and no dependency page. It must not omit the bad
package, fabricate a default, or return a partially trusted page.

### Deterministic package-state algorithm

The algorithm first distinguishes whether package-specific artifacts can
legitimately exist, then applies conservative package aggregation. Rules appear
in precedence order; an integrity failure always precedes all semantic rows.

| Precedence and evidence | Evaluation | Reason source | Count | Advisories | Failure behavior |
|---|---|---|---:|---|---|
| Contradictory evidence, invalid binding, unknown code, missing object required by an existing binding, or duplicate advisory relationship | none | none | none | none | Fail the whole query |
| No package-specific artifacts because there is no OSV node/outcome/finding, and the unique authoritative OSV stage proves `authority=osv.dev`, `capability=dependency_advisory_matching`, `NOT_APPLICABLE`, and `coverage_states=()` | `NOT_APPLICABLE` | Safe nullable stage reason | `null` | forbidden | Any missing proof or OSV finding fails the whole query |
| No dependency-evaluation artifact exists, and the authoritative OSV capability/node is terminal failed or blocked by a failed dependency | `FAILED` | Safe nullable capability/stage reason | `null` | forbidden | Findings or an alleged completion fail the whole query |
| No dependency-evaluation artifact exists and neither preceding fallback is proved | none | none | none | none | Fail the whole query; absence has no meaning |
| Dependency evaluation exists but has no observation for the component's package key | none | none | none | none | Fail the whole query |
| All package observations are `OUTSIDE_SCOPE` | `NOT_APPLICABLE` | `OUTSIDE_SCOPE` | `null` | forbidden | Candidate or advisory for the package fails the whole query |
| No supported candidate exists because the package has mixed scope, heterogeneous scope without an eligible observation, an authoritative coordinate gap, or an incomplete prerequisite with no candidate | `PARTIAL` | Package limitation set | `null` | forbidden | A candidate or advisory that contradicts the evaluation artifact fails the whole query |
| A supported candidate exists, no accepted result exists, and an authoritative direct OSV or prerequisite failure is proved | `FAILED` | Safe nullable failure/stage reason | `null` | forbidden | Failure takes precedence over recorded package limitations because no advisory result was accepted |
| A supported candidate exists but input/result/completion is missing and no authoritative failure is proved | none | none | none | none | Fail the whole query |
| An accepted candidate completed and any package observation is `MIXED_SCOPE`, observation classes are heterogeneous, the prerequisite is incomplete, or another package-local limitation exists | `PARTIAL` | Package limitation set | `null` | Trusted accepted advisories allowed | Never select the favorable observation or promote candidate completion past its prerequisite |
| Accepted candidate completed with zero advisory groups, every package observation is `IN_SCOPE`, prerequisite is complete, and no package-local limitation exists | `COMPLETE` | `null` | `0` | empty | Any advisory contradicts the zero result |
| Accepted candidate completed with N canonical advisory groups under the same complete conditions | `COMPLETE` | `null` | `N` | exactly N | Any set/count mismatch fails the whole query |
| The published S4 OSV outcome for an accepted result is globally `PARTIAL` only because another package has a limitation, while this package proves every complete condition | `COMPLETE` | `null` | `0` or `N` | exact accepted set | Do not copy run-level partial state onto this package |
| `FAILED` or `NOT_APPLICABLE` package with any advisory | none | none | none | none | Fail the whole query |

The package limitation set is constructed from authoritative facts only:

- incomplete prerequisite contributes `SYFT_PREREQUISITE_PARTIAL`;
- a mixed observation contributes `MIXED_SCOPE_PACKAGE_OBSERVATION`;
- a coordinate gap contributes its exact `OsvGapReason` value; and
- heterogeneous observation classes contribute no invented code.

If exactly one code is in the set, it is the public reason. If more than one
exact limitation applies, the nullable reason is `null` rather than falsely
presenting one limitation as exhaustive. Heterogeneity likewise leaves the
reason null unless one other exact limitation is the sole reason. State remains
conservatively `PARTIAL` whenever no candidate failed. If a supported candidate
has no accepted result because of an authoritative failure, `FAILED` and its
failure reason take precedence; package limitations never turn that failure into
an apparently accepted partial result.

An accepted result's run-level `PARTIAL`/`PACKAGE_GAPS_PRESENT` state is a signal
to perform package aggregation, not a state to copy. Conversely, incomplete
Syft prerequisite evidence is global to the dependency-evaluation boundary and
keeps every otherwise eligible candidate package `PARTIAL`.

### Closed public reason mapping

E2 must implement a closed mapping, not pass through arbitrary strings.
Recognized values outside these tables fail the query.

Artifact-backed package reasons preserve these exact frozen producer values:

| Authoritative source | Public reason |
|---|---|
| `PackageScopeClassification.OUTSIDE_SCOPE` | `OUTSIDE_SCOPE` |
| mixed-scope gap `MIXED_SCOPE_PACKAGE_OBSERVATION` | `MIXED_SCOPE_PACKAGE_OBSERVATION` |
| `OsvGapReason.PACKAGE_VERSION_UNRESOLVED` | `OSV_PACKAGE_VERSION_UNRESOLVED` |
| `OsvGapReason.PACKAGE_PURL_UNRESOLVED` | `OSV_PACKAGE_PURL_UNRESOLVED` |
| `OsvGapReason.UNSUPPORTED_PURL_TYPE` | `OSV_UNSUPPORTED_PURL_TYPE` |
| `OsvGapReason.PURL_VERSION_MISMATCH` | `OSV_PURL_VERSION_MISMATCH` |
| `OsvGapReason.PURL_PACKAGE_MISMATCH` | `OSV_PURL_PACKAGE_MISMATCH` |
| incomplete Syft prerequisite | `SYFT_PREREQUISITE_PARTIAL` |

The legitimate no-artifact fallback accepts only the already-public normalized
stage values `NO_PACKAGES_OBSERVED`, `NO_PACKAGES_IN_ADVISORY_SCOPE`,
`NO_SUPPORTED_COORDINATES`, `DEPENDENCY_INCOMPLETE`, `DEPENDENCY_FAILED`,
`EXECUTION_FAILED`, and `CANCELLED`, or `null`. The value is copied only when its
stage state is compatible with it.

An OSV node blocked by a failed Syft prerequisite uses the existing normalized
stage reason `DEPENDENCY_FAILED`; it never exposes the constructed internal
`SYFT_*` terminal string. `DEPENDENCY_EVALUATION_FAILED` likewise maps through
the existing stage policy to `DEPENDENCY_FAILED`.

For a genuine direct OSV execution failure, the failed S4 terminal fragment's
closed safe producer set is the frozen `SourceOsvFailureCode` values:
`NETWORK_FAILURE`, `CONNECT_TIMEOUT`,
`READ_WRITE_TIMEOUT`, `HTTP_RATE_LIMIT`, `HTTP_RETRYABLE_SERVER_ERROR`,
`HTTP_PERMANENT_ERROR`, `INVALID_OSV_SCHEMA`, `PAGINATION_INTEGRITY_FAILURE`,
`OSV_DATA_CHANGED_DURING_QUERY`, `DEPENDENCY_INPUT_INTEGRITY_FAILURE`,
`RESULT_CANONICALIZATION_FAILURE`, `ARTIFACT_PERSISTENCE_FAILURE`,
`HELPER_EXECUTION_FAILURE`, `ATTEMPT_CONTAINMENT_FAILURE`, `CANCELLED`, and
`DEADLINE_EXCEEDED`. These map to the identical public string to preserve the
existing coverage-reason meaning. No other internal reason is public through
this endpoint.

### Advisory and compatibility projection

For every accepted package-bound S4 finding, create exactly one nested advisory.
All nested list fields are copied from its single correlated
`OSV_ADVISORY_GROUP` evidence object. Its `priority_band` comes from the bulk
Product Core priority index for the S4 public `finding_id`.

The nested model is authoritative. Existing fields remain additive compatibility
summaries derived from `advisories` in the same projection pass:

```text
advisory_aliases = sorted unique union of
    advisory.aliases
    + advisory.cve_aliases
    + advisory.ghsa_aliases

fixed_versions = sorted unique union of advisory.fixed_versions

priority_bands = sorted unique union of advisory.priority_band
```

This preserves V1.1B compatibility semantics: `advisory_aliases` does not add
all OSV record IDs merely because the nested model now exposes them. There is no
second independent flat-field algorithm.

### Deterministic ordering

- dependencies are unique and sorted ascending by `component_ref`; pagination is
  applied after that full ordering;
- advisories are unique and sorted ascending by public `finding_id`;
- `osv_record_ids`, `aliases`, `cve_aliases`, `ghsa_aliases`, and
  `fixed_versions` are each unique and sorted by Unicode code-point order, which
  matches their frozen ASCII identifier/version representation;
- compatibility `advisory_aliases`, `fixed_versions`, and `priority_bands` are
  unique and sorted by the same ordinary string order, preserving V1.1B output;
  priority bands are not reordered by severity rank;
- Syft dependency locations are unique `REPOSITORY_PATH` mappings sorted
  ascending by normalized repository-relative `path`; and
- input order, database row order, CAS load order, and advisory response order
  never affect output.

### Bounded artifact-loading and performance invariant

One dependency-page projection may perform only bounded run-level acquisition:

1. load and verify the published S4 report once;
2. load and verify the dependency-evaluation artifact at most once;
3. load and verify the accepted OSV input at most once;
4. load and verify the accepted OSV result at most once;
5. load the Product Core finding-priority mapping in one bulk query; and
6. when the legitimate no-artifact fallback is needed, load its authoritative
   planning/stage material once without reconstructing or reloading S4.

E2 must then build in-memory indexes once for component/package identity, Syft
observations and locations, scope classifications, package gaps, candidates,
candidate completion/zero results, package advisory findings/evidence, and
finding priorities. It must project every dependency only from those indexes.

There may be no per-component database query, per-component CAS load,
per-advisory CAS load, or external request. The current
`O(components * evidence)` Syft-location rescan must be replaced by one evidence
pass and a component-to-locations index. Projection work must be linear in the
loaded report/artifact relationships plus deterministic sort costs, not their
Cartesian product.

### Backward compatibility and E2 boundary

- `GET /v1/scans/{run_id}/dependencies` and its page envelope remain unchanged;
- no `/dependencies-v2` route is introduced;
- no existing dependency field is removed or made less nullable;
- `advisories` is the only new dependency field and is always an array;
- the three existing flat fields remain arrays and preserve their prior union
  semantics, but are now derived solely from `advisories`;
- zero OSV outcomes retain the frozen V1.1B proof rule; absence alone never
  becomes `NOT_APPLICABLE`; and
- security failures remain fail-closed `QUERY_UNAVAILABLE` responses without
  leaking artifact paths, commands, raw scanner payloads, credentials, or
  arbitrary internal reasons.

E1 requires no migration, new persistence field, scanner change, external data
source, or orchestration change. E2 is authorized only after E1 review and must
implement this contract with adversarial unit/integration coverage before any UI
change or release acceptance work.

## E2 Product Core advisory and dependency projection

Status: `E2 COMPLETE - AWAITING REVIEW`

E2 implements the frozen E1 contract as an internal Product Core read-model
projection. It does not change the HTTP schema, route, OpenAPI document, UI,
persistence schema, evidence producers, scanner execution, orchestration,
assembly, or lifecycle semantics.

### Implementation architecture

`src/securescan/product_core/dependencies.py` contains the isolated projection
boundary. `SourceDependencyProjectionService` acquires the durable run-level
material through the existing verified loaders, while
`resolve_dependency_summaries()` performs deterministic in-memory validation,
indexing, correlation, and package projection. `SourceScanQueryService` remains
responsible for loading the verified S4 report once, loading Product Core
priorities once, delegating one projection, and applying pagination after the
fully ordered dependency collection.

The internal `SourceDependencyAdvisorySummary` is the exact E1 frozen model:
`canonical_advisory_id`, public S4 `finding_id`, `osv_record_ids`, `aliases`,
`cve_aliases`, `ghsa_aliases`, `fixed_versions`, and finalized Product Core
`priority_band`. `SourceDependencySummary` adds `advisories` while retaining all
V1.1B fields. No synthetic advisory identity is introduced.

### Package resolver and observation aggregation

The resolver first validates the S4 package/component and Syft observation
bindings, then correlates the dependency evaluation, accepted OSV input, and
accepted result. Report scope and accepted input must agree on run, repository,
profile, and plan identities. Evaluation/input/result candidate identities and
the complete accepted-result/S4 advisory sets must also agree.

For every package key, all structural observations participate:

- all `OUTSIDE_SCOPE` observations produce `NOT_APPLICABLE`;
- any mixed observation, heterogeneous observation classes, coordinate gap, or
  incomplete prerequisite prevents `COMPLETE` and produces `PARTIAL` unless an
  unaccepted required candidate has an authoritative failure;
- an authoritative failure for a required candidate produces `FAILED` and
  exposes no advisories;
- an accepted completed candidate with a complete prerequisite and no local
  limitation produces `COMPLETE`, independently of a run-level `PARTIAL` caused
  by another package; and
- multiple independent limitation codes, or heterogeneous classes without one
  exhaustive code, retain `PARTIAL` with a null reason.

Only `COMPLETE` returns an exact `known_vulnerability_count`, computed as
`len(advisories)`. `PARTIAL`, `FAILED`, and `NOT_APPLICABLE` return null.
Accepted, package-bound advisories may remain visible for `PARTIAL`; they are
forbidden for `FAILED` and `NOT_APPLICABLE`.

### Advisory correlation and compatibility fields

The report is indexed once by component, evidence ID, package key, and public
finding ID. Every projected OSV advisory must bind one valid package component,
one correlated `OSV_ADVISORY_GROUP`, its supporting Syft observations, one
public S4 finding identity, one accepted-result advisory group, and one finalized
priority. Missing references, component mismatches, invalid evidence kinds,
missing priorities, duplicate public identities, repeated native relationships,
and identity-connected same-package groups fail the whole projection.

Advisories sort by public `finding_id`. Their tuple fields retain canonical
producer order, and dependencies sort by `component_ref`. The V1.1B flat fields
have no independent extraction path: `advisory_aliases`, `fixed_versions`, and
`priority_bands` are deterministic sorted unique unions derived exclusively from
the nested advisory tuple.

### Indexing and bounded loading

One pass over S4 evidence validates Syft observations and builds
`locations_by_component_ref`; package projection performs indexed lookups rather
than rescanning all evidence for every component. Focused instrumentation proves
one location extraction per Syft evidence object even when multiple package
components are projected.

For one dependency-page request, verified acquisition is bounded to one S4
report load, one bulk priority query, at most one dependency-evaluation artifact
load, at most one accepted OSV input load, and at most one accepted OSV result
load. Planning material is loaded once only for the legitimate no-node omission
path. The loader performs bounded run-level row queries and never performs a DB
query or CAS read per component or advisory. It makes no external request.

### Files, tests, and limitations

Production changes are limited to:

- `src/securescan/product_core/dependencies.py`;
- `src/securescan/product_core/query.py`; and
- `src/securescan/product_core/__init__.py`.

Focused coverage is in
`tests/test_source_dependency_projection_v11e2.py` with 27 passing cases across
the 25 required semantic/adversarial scenarios plus bounded-loader, query-call,
one-pass-location, read-only, confidentiality, alias-connected duplicate, and
cross-artifact scope-binding proofs. Existing synthetic PC3B tests were changed
only where E1 makes their old report-only/run-level assumptions invalid; the
updated tests now supply authoritative projection material or assert fail-closed
behavior.

The implemented structure follows the E1 proposal, with one concrete
organization choice: verified material loading and the pure resolver share the
focused `dependencies.py` module instead of extending the already large
`query.py`. Indexes are request-local and are not persisted. E2 deliberately
does not expose the nested advisory tuple over HTTP; strict public response
models, route serialization, OpenAPI, and legacy UI compatibility remain E3.
No CVSS, reachability, exploitability, upgrade recommendation, or external
vulnerability enrichment is added.

## E3 public API and backward compatibility

Status: `E3 COMPLETE - AWAITING REVIEW`

E3 exposes the accepted E2 projection through the existing
`GET /v1/scans/{run_id}/dependencies` route. The route, HTTP method, `limit` and
`offset` parameters, page envelope, error mapping, and every V1.1B dependency
field remain unchanged. No alternate versioned dependency route was added.

### Public schema and serialization

The strict public `DependencyAdvisoryResponse` has exactly these required fields:

```text
canonical_advisory_id: string
finding_id: string
osv_record_ids: array[string]
aliases: array[string]
cve_aliases: array[string]
ghsa_aliases: array[string]
fixed_versions: array[string]
priority_band: string
```

`DependencySummaryResponse` adds only the required
`advisories: array[DependencyAdvisoryResponse]` field. Existing `version`, `purl`,
`vulnerability_evaluation_reason`, and `known_vulnerability_count` nullability is
unchanged. `inventory_status` and synthetic advisory identifiers are not added.

Serialization remains a glass layer over Product Core:

```text
HTTP dependency request
  -> SourceScanQueryService.list_dependencies()
  -> E2 SourceDependencySummary
  -> strict DependencyPageResponse.model_validate(from_attributes=True)
  -> JSON
```

The route and schema do not inspect S4, load artifacts, regroup aliases, sort or
recount advisories, derive flat fields, infer fixed versions, or calculate
priority. They serialize the E2 values and ordering directly. Strict response
validation rejects missing required advisory fields, wrong scalar/collection
types, non-string aliases, and unexpected fields.

### Null, empty, ordering, and error behavior

`COMPLETE` serializes the E2 integer count, including zero. `PARTIAL`, `FAILED`,
and `NOT_APPLICABLE` serialize a null count. A `PARTIAL` dependency may retain
its accepted observed advisory array while its count remains null. Empty
advisories and all empty nested tuple fields serialize as JSON arrays, never as
null or presentation strings.

Dependency, advisory, identity, version, location, and priority ordering is
preserved exactly as E2 supplies it; the API introduces no set conversion or
secondary ordering. The E2 flat `advisory_aliases`, `fixed_versions`, and
`priority_bands` values are also serialized directly. A Product Core integrity
failure remains the existing safe HTTP 503 `QUERY_UNAVAILABLE` response and
never becomes a partial 200 response.

Generated OpenAPI retains the existing dependency operation and page schema,
adds one reusable `DependencyAdvisoryResponse` component, and shows
`items[].advisories[]` with the eight exact required fields. It continues to
describe `known_vulnerability_count`, `version`, `purl`, and
`vulnerability_evaluation_reason` as nullable.

### Legacy UI compatibility

The packaged HTML/JavaScript console remains the existing dependency table; no
frontend framework or toolchain was added. It now renders explicit evaluation
and count labels, nested advisory display identity, CVE/GHSA/generic aliases,
advisory-reported fixed versions, and `SecureScan priority`. The existing flat
priority-band badges remain as an explicitly labeled E2-provided compatibility
summary.

Presentation preserves semantic uncertainty:

- a complete clean package shows `Known vulnerabilities: 0` and
  `Advisories: none`;
- a partial package shows `Known vulnerabilities: Unknown` and labels retained
  entries as `Observed advisories`;
- a failed package shows `Unknown`, never zero; and
- a not-applicable package shows `N/A`, never zero.

Fixed-version text is `Fixed versions reported by advisory`; an empty value is
`No fixed version reported`. The UI does not call it a recommended upgrade,
safe version, or proof that no fix exists. Priority is never labeled OSV
severity, CVSS, risk, exploitability, or reachability.

### Security, tests, files, and limitations

Focused E3 validation passes 15 API/schema/OpenAPI cases, including exact nested
serialization, all four evaluation/count states, partial advisories, direct flat
compatibility values, pagination, stable ordering, strict malformed-model
rejection, safe errors, and confidentiality. The 14-test legacy frontend suite
and JavaScript syntax check pass. The unchanged 32-test PC3C API suite passes,
and all 27 E2 projection plus 44 PC3B read-model tests pass unchanged.

Serialized advisory output contains only the eight E1/E2-approved fields. It
does not expose native finding or advisory-group digests, CAS/artifact paths,
workspace or host paths, database/orchestration identifiers, commands,
stdout/stderr, raw errors or HTTP responses, credentials, operator settings, or
internal exception text.

E3 changes only:

- `src/securescan/api/source_scan_schemas.py`;
- `src/securescan/web/app.js`;
- `src/securescan/web/index.html`;
- `tests/test_source_dependency_api_v11e3.py`;
- `tests/test_source_frontend_d2.py`;
- this design checkpoint; and
- `docs/source-v1-status.md`.

No route implementation, Product Core projection, evidence producer, scanner,
orchestration, assembly, lifecycle, persistence schema, or migration changes.
No external integration or dependency-read network call was introduced. E3 does
not add finding-detail navigation or a large reason-message mapping. PostgreSQL
parity, bounded-query/load measurement at scale, and performance/confidentiality
acceptance remain E4; isolated real end-to-end and final freeze/tag remain E5.
