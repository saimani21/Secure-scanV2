# SecureScan Source V1.2H product-surface audit (H0)

Parent: `a05ac606e8d5b58f7c27742b2e2428bb434262ab`
Branch: `source/v1.2H-unified-product-experience`
Status: working audit; this is **not** V1.2H acceptance or a product freeze.
Migration: none proposed.

## Existing-surface inventory

This inventory records the code at the frozen G parent before H production changes. `—` means no corresponding operator surface was found, not that the underlying security fact is absent. Routes under `/v1/projects` below use `{p}` for project UUID, `{l}` for lineage UUID, `{r}` for run UUID, and `{f}` for the 64-character finding ID. Scan routes use `/v1/scans/{r}`. Existing HTTP error bodies use FastAPI `detail: {code, message}`; H must not silently break that shape. All current browser API calls are same-origin GETs.

| Capability | Authoritative service / data | Existing API | Existing CLI | Existing Web UI | Proven integration gap |
| --- | --- | --- | --- | --- | --- |
| Project creation/listing | `SourceProjectService` | `GET /v1/projects`, `GET /v1/projects/{p}`; no create route | `project create/list`, JSON | `/projects`, `/projects/{p}`; read-only | Browser cannot create; API lacks POST. |
| Repository/lineage identity | `SourceScanSubmissionService`, durable target/lineage and scan summaries | Scan summary contains project, target and lineage IDs; no lineage catalog/target-registration route | `scan PATH --project-id [--lineage-id]` performs trusted local preparation | Project/scan pages display IDs and a copyable CLI command | Browser cannot select a host path or register a trusted target. Existing scan POST requires an already trusted target ID. Do not turn displayed paths into file reads. |
| Scan start | Trusted-host CLI intake; `SourceTrustedTargetSubmissionService` for pre-registered targets | `POST /v1/scans` requires project, trusted target, idempotency key and deadline | `scan` submits local path, optional `--wait`, JSON | No mutation | API route is not equivalent to browser local-path intake; host/container trust boundary must be resolved before any browser start action. |
| Scan progress/status | `SourceScanQueryService` | `GET /v1/scans/{r}`, `GET /v1/scans/{r}/stages`, cancel POST | `status`, `stages`, `scan --wait` | `/scans/{r}` with bounded polling | Already integrated for reads; preserve stage/coverage distinction. |
| Scan history | `SourceScanQueryService.list_scans` | `GET /v1/scans`, `GET /v1/projects/{p}/scans` | `scans [--project-id]`, JSON | `/scans`, project detail | No lineage-specific catalog/filter. |
| Coverage | `SourceScanQueryService.get_coverage` | `GET /v1/scans/{r}/coverage` | `coverage`, JSON | `/scans/{r}/coverage`; scan summary also shows coverage | Reuse; always pair security counts with coverage context. |
| Analysis gaps | `SourceScanQueryService.list_gaps` | `GET /v1/scans/{r}/gaps` | `gaps`, JSON | `/scans/{r}/gaps`, report | Reuse; absence of gaps is not proof of complete coverage. |
| Findings list | `SourceScanQueryService.list_findings` | `GET /v1/scans/{r}/findings` with bounded authority/category/priority/lifecycle filters | `findings`, JSON | `/scans/{r}/findings` with bounded list/filter | Delta, governance and policy are not joined; lifecycle joins the **current** aggregate, so the old response must not be called exact-run lifecycle. |
| Finding detail / evidence | Verified published S4 through `SourceScanQueryService.get_report` and `SourceFindingIndexService` | Whole `GET /v1/scans/{r}/report`; no single finding-detail route | `report` JSON; no finding-detail command | Findings workspace correlates summary with report evidence client-side | Whole-report transfer for one detail; no shared bounded per-finding projection. Keep Gitleaks native raw secrets excluded. |
| Dependencies | `SourceDependencyProjectionService` through scan query | `GET /v1/scans/{r}/dependencies` and `/components` | `dependencies`, JSON | `/scans/{r}/dependencies` | Largely present; do not infer known-vulnerability zero from incomplete evaluation. |
| Lifecycle | Product Core lifecycle event per run; current lifecycle aggregate | Existing findings list returns the current aggregate state, even for a historical run; F policy loads exact candidate-run events | `findings` mirrors current aggregate | Findings workspace currently labels that value without temporal qualification | H needs an additive exact-run event projection or explicit current-state labeling; preserve the old route for clients. |
| Governance | `SourceFindingGovernanceService` | `GET/PUT /v1/projects/{p}/lineages/{l}/findings/{f}/governance`; `/events` GET | — | — | Add presentation/mutation orchestration with frozen expected revision; keep decisions visible rather than hiding findings. |
| Suppression | `SourceFindingSuppressionService` | `GET/PUT .../suppression`, `POST .../suppression/revoke`, `GET .../suppression/events` | — | — | Add reason/expiry/revoke UX without changing episode semantics. |
| EffectiveGovernance | `EffectiveGovernanceService` | `GET .../effective-governance` | — | — | Display clearly as **current/evaluation-time**, distinct from historical run lifecycle and policy snapshot. |
| Deterministic guidance | `FindingGuidanceService.get_for_run` over verified exact-run S4 | `GET /v1/projects/{p}/lineages/{l}/runs/{r}/findings/{f}/guidance` | — | — | Add exact-run basis/limitations to finding detail; do not invent fixes. |
| Trusted baseline | `SourceTrustedBaselineService.get_current/list_history` | `GET .../baseline`, `GET .../baseline/history` | — | — | Show baseline identity, revision, time and actor; absence is not clean. |
| Baseline promotion | `SourceTrustedBaselineService.promote` | `PUT .../baseline` with expected revision | — | — | Explicit confirmed action only; no auto promotion or PASS implication. |
| Security Delta | `SourceSecurityDeltaService.evaluate` | `GET .../runs/{r}/security-delta` | — | — | Present exact candidate and trusted baseline, including `NOT_COMPARABLE` reasons. |
| Trusted policy | `SourcePolicyService.get_policy/update_policy` | `GET/PUT .../policy` with expected version | — | — | Show identity/version/digest and typed rules; no UI policy editor is required merely for parity. |
| Policy evaluation | `SourcePolicyService.evaluate/get_evaluation` | `POST .../runs/{r}/policy-evaluations`; `GET .../policy-evaluations/{evaluation_id}` | — | — | Add explicit evaluation and result inspection; `PASS`, `FAIL`, `ERROR` remain distinct. No plain-scan exit change. |
| JSON output/export | Existing Pydantic API schemas; CLI `canonical_json` | JSON for all routes; full published report | Most read commands support `--json`; `report` emits JSON | `/scans/{r}/report` offers copy/download JSON | No single unified product JSON projection; do not break existing schemas. |
| SARIF | Frozen `build_sarif_bytes` | — | `sarif RUN --output PATH|-` | — | CLI already covers export; no API/UI parity mandate for SARIF. Keep frozen content and exit behavior. |
| System/health/runtime | Operator manager, readiness and metrics services | `/health`, `/health/live`, `/health/ready`, `/version`, `/v1/operations/metrics` | `doctor`, `system up/down/status`, `open`, JSON where supported | Shell consumes readiness and shows system indicator | Existing health does not imply every scanner authority is available. |

## Existing architecture and non-duplication decisions

- The Web UI is a packaged, dependency-free ES-module client with explicit allowlisted routes. It already has overview, projects, scans, scan detail, findings/detail-in-page, dependencies, coverage, gaps and report. H must extend these modules rather than replace the shell or create a second frontend stack.
- The existing finding detail obtains the whole published report and correlates exact IDs to S4 evidence. H should measure whether a bounded server-side detail projection is justified. No arbitrary filesystem source preview is authorized.
- `SourceScanQueryService` already owns bounded scan/finding/dependency/gap reads (maximum 200). New run/finding product views, if built, must compose it and the frozen B–G services. They must not persist copies of priority, lifecycle, delta, governance, policy or guidance.
- Policy evaluation is a durable **POST** that may create a new immutable evaluation. A product overview GET must not call it implicitly; it can show a specifically selected existing evaluation or an explicit unevaluated state.
- Security Delta is an exact-baseline comparison, not a property of a run in isolation. Its response must carry baseline identity/revision and comparison safety. If no baseline exists, absence/unknown is not zero introduced findings.
- Current EffectiveGovernance can change after a historical scan. Historical finding pages must label its temporal perspective and must not present it as the candidate-run governance snapshot. The policy evaluation stores its own evaluation-time decision.
- `SourceScanQueryService.list_findings` joins `SourceFindingLifecycleRow.current_state`. This is a concrete H temporal gap: the list is run-scoped for occurrences but its lifecycle value is current. The F engine correctly uses `load_candidate_facts_in_session` for exact-run lifecycle. Do not rewrite the frozen route silently; H's product projection must select the run event or label the legacy value as current.
- H must preserve `scan --wait` success independently of finding count and add policy enforcement only through an explicit mode/command. No CLI command should recalculate F's policy result.

## Implementation order and audit risks

1. Define small derived read models with explicit `run_id`, lineage/project scope, temporal labels and optional/unknown states. Reuse existing bounded queries. For mutable aggregates use a coherent snapshot where needed; never compose contradictory baseline, governance and policy states as though atomic.
2. Close the safe API gaps: project creation delegates to `SourceProjectService`; bounded product reads validate project → lineage → run → finding ownership; preserve existing response/error contracts. Do not add speculative route families.
3. Close CLI gaps by calling B–G services directly through a trusted local service context. Maintain frozen scan and SARIF behavior. Define explicit policy exit semantics and stable JSON.
4. Extend the existing UI with run/finding context, governance/guidance, baseline/delta/policy and accurate empty/error states. Use `textContent`/safe DOM construction and bounded requests. Avoid per-row governance/guidance requests.
5. **Approved V1.2 boundary:** trusted-host CLI intake remains the only repository preparation path. The browser must never upload source, submit a host filesystem path, or ask the backend to resolve one. The existing API may start a scan only for an already registered trusted target ID. If no safe target catalog is available to select such an ID, scan start remains CLI-only and the Web UI observes execution. `compose.yaml` mounts deployment data into the API container, not arbitrary host repositories; a browser path field would be both ineffective and unsafe. A bounded browser upload/intake contract would require a separate future security-engineering phase.

No production behavior was changed to produce this audit. The H acceptance matrix remains open.
