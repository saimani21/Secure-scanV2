# SecureScan Source V1.2H unified product experience

Status: **COMPLETE — FROZEN** (2026-10-01)
Parent: `a05ac606e8d5b58f7c27742b2e2428bb434262ab`
Branch: `source/v1.2H-unified-product-experience`
Migration: `NONE`.

## Approved intake boundary

**V1.2 does not accept repository paths or repository uploads from the browser. Local source intake remains a trusted-host operation. The Web UI operates on repositories/targets already admitted through the trusted local intake boundary.**

The host CLI prepares repositories and submits local scans. The existing API can submit a scan for an already registered trusted target ID, but no safe target catalog/selection surface currently exists in the browser. Until one is proven through the frozen server-side target-ID contract, scan initiation remains CLI-only; the Web UI observes progress and presents results. Browser upload, arbitrary host paths, repository preparation, and a new ingestion subsystem are explicitly outside H. The approved H operator scenario begins with trusted-host CLI intake, then continues in the browser for coverage, findings, evidence, guidance, governance, baseline, delta and policy.

## H0 audit and implementation

The [product-surface audit](source-v1.2h-product-surface-audit.md) inventories 23 capabilities across services, API, CLI and UI. It identifies existing routes and gaps so H does not duplicate security engines. H additions are:

- The browser can create a named project through the additive `POST /v1/projects` route, which delegates validation and persistence to the frozen `SourceProjectService`. The strict request rejects extra fields including repository paths; this is **not** source intake. The project form uses same-origin JSON, safe text rendering, and canonical-ID navigation.
- `securescan policy evaluate RUN_ID [--json]` delegates to the frozen F service. It derives project and lineage from the run query and uses the domain result without reinterpretation. Only this explicit command maps `PASS` to exit 0, proven `FAIL` to exit 1, and `ERROR`/operational inability to exit 5. Plain `scan` is unchanged.
- `securescan finding guidance RUN_ID FINDING_ID [--json]` delegates to frozen G exact-run verified evidence. It preserves basis, limitations and structured fields; it does not query a scanner or infer a fix.
- `securescan findings RUN_ID --exact-run [--json]` opts into the same immutable-event finding projection used by the H API and production Web UI. The legacy `findings` command remains unchanged by default. A focused CLI/API fixture asserts identical JSON facts for a reopened high-priority finding.
- The existing findings workspace can lazily read guidance for only the selected finding. The read first obtains the exact run's project/lineage scope, then calls the already frozen guidance GET. Responses are checked against selected run, finding ID and authority. Navigating or selecting a different finding aborts the old request; scanner-controlled text is rendered through `textContent` and bounded display helpers. No list-wide guidance N+1 requests are made.
- `SourceFindingProductViewService` adds a read-only, bounded occurrence-plus-immutable-lifecycle-event page in one database transaction. It reuses the frozen lifecycle digest/transition-chain verifier and rejects tampered history. `GET /v1/projects/{project_id}/lineages/{lineage_id}/runs/{run_id}/findings` validates ownership and exposes `lifecycle_state_at_run` without changing the legacy scan-finding route. The production findings workspace now uses this exact-run page; old C4 test doubles use the legacy path. No lifecycle or priority calculation was added.

The old `GET /v1/scans/{run_id}/findings` joins the *current* lifecycle aggregate to run-scoped occurrences. Thus its `lifecycle_state` is not necessarily the state at a historical run. Frozen F policy already loads exact candidate-run lifecycle events. The new H page selects the stored event for that run and explicitly labels the UI value "At scan". The old route is unchanged; when legacy test doubles use it, the UI labels its value "Current".

## Freeze acceptance

H was frozen after the complete gates below. No release tag was created.

### Verified gates (2026-10-01)

- The Findings workspace shows exact-run lifecycle separately from current/evaluation-time governance. Selected guidance, frozen governance dispositions, suppression creation/revocation, and reopened review-required UX use existing endpoints with optimistic revisions.
- The run Assurance page presents coverage/gaps, trusted baseline, explicit confirmation-based promotion, exact-baseline Security Delta, and explicit policy PASS/FAIL/ERROR. Missing evidence is unavailable or unknown, not clean. Browser requests use same-origin exact IDs. Repository intake and scan start remain trusted-host CLI-only.
- CLI reads include exact-run findings, guidance, current baseline, Security Delta, current EffectiveGovernance and current policy. Baseline promotion and policy evaluation require explicit commands; plain scan behavior is unchanged.
- A fresh disposable PostgreSQL container passed `alembic upgrade head`, `alembic check` (no metadata drift), and all 32 exact H plus affected B/C/D/E/F/G PostgreSQL tests without a skip or failure. The single Alembic head remains `f8c2d6e1a305`; H adds no migration.
- One consolidated disposable operator flow used trusted-host CLI intake and two real completed scans (plain-scan exit `0`, two findings each). For the same recorded scenario it checked exact-run JSON findings against HTTP, coverage/gaps, guidance against HTTP, audited FALSE_POSITIVE governance, current EffectiveGovernance against HTTP, pre-baseline policy `ERROR`/exit `5`, explicit baseline promotion from revision 0 to 1, a changed fixture and later scan, nonempty Security Delta against HTTP, policy against HTTP, JSON export, and SARIF 2.1.0 with two results. The run Assurance browser renderer displayed the same baseline, delta, coverage/gaps and policy facts. The second scan did **not** promote the baseline automatically; it stayed at revision 1 pointing to scan one. Delta remained `PARTIAL` and policy `ERROR`, not falsely clean.
- A separate three-scan disposable scenario established synthetic Gitleaks `INTRODUCED` with policy `FAIL` after explicit promotion, then `REMOVED` after a second explicit promotion. It also covered suppression creation/revocation and kept partial comparison visible. The consolidated run separately checked its actual policy result-to-exit mapping; focused CLI tests prove `PASS`/`FAIL`/`ERROR` map to `0`/`1`/`5`.
- Executable browser tests cover baseline confirmation, policy distinctions, reopened dormant governance, same-origin requests and Gitleaks/OSV/Checkov guidance. Independent current-governance reads may have different `evaluated_at` timestamps; their security facts matched. UI evidence is HTTP TestClient plus executable browser-module rendering, not a manual interactive browser session.
- Ruff, byte compilation and `git diff --check` passed. All disposable PostgreSQL containers and inspected private acceptance roots were removed; pre-existing Docker containers and preserved deployments were untouched.

### Exact regression reconciliation

The monolithic non-PostgreSQL run timed out and is **not** counted as a green run. Instead, its 3,288 collected exact pytest node IDs were partitioned into four disjoint bounded groups plus the three historical maturity files. Set-level reconciliation over JUnit outcomes found 3,225 unique passes, one classified environment-gated Checkov skip, 62 [documented historical branch-lock exclusions](source-v1.2h-historical-branch-exclusions.md), and **zero missing or unexplained current-branch IDs**. Thirteen initially skipped opt-in cases passed when their pinned local prerequisites were supplied. One Gitleaks malformed-archive parametrization has a gzip timestamp in its node ID; reconciliation normalized only that uniquely identified case across collection and run artifacts.

The fresh PostgreSQL release slice adds 32 disjoint passes: 3,320 unique collected cases in the combined inventory, 3,257 passes, one classified opt-in skip, 62 historical branch-lock exclusions, zero unexecuted unclassified IDs and zero unexplained failures. The second Checkov launcher was unavailable, so that independent-environment reproduction is **not** claimed. Every mandatory H and affected B–G test executed; no current-branch product regression remained unexplained. Scanner/parser/adapter cases were not excluded. The branch-lock cases validate historical provenance on their frozen branch and cannot run to their benchmark assertions on H without changing their contract.

This is partitioned coverage, not a claim that a single repository-wide pytest invocation completed. No frozen B–G security semantics, preserved deployment, schema migration, scanner, SARIF contract, or plain-scan exit policy was changed.
