# SecureScan Source V1.2G deterministic finding guidance

Parent: `ed917a7ef00f734fbe8cd9ce73406ae09df15ef4`
Branch: `source/v1.2G-deterministic-guidance`
Migration: `NONE`

## Authority and evidence contract

Guidance is a derived, run-scoped read model. `FindingGuidanceService` checks the project, lineage, indexed run membership, and exact finding occurrence before calling the existing `SourceFindingIndexService.load_verified_published_report`. That method rebuilds typed S4 through the frozen S6D path and verifies canonical bytes against the content-addressed artifact and published report JSON. Product Core occurrence rows provide scope, not guidance content: they omit primary evidence payloads. A stable `finding_id` can recur in another run, but only evidence from the requested run is rendered. No guidance prose is persisted.

| Authority | Accepted S4 facts used | Basis | Deliberate limits |
|---|---|---|---|
| Semgrep | Rule ID, source span, validated CWE IDs, normalized severity | `CLASSIFICATION` with CWE; otherwise `FAMILY` | Native rule/fix message is not accepted S4 guidance evidence. No exact patch, exploitability, reachability, or business-impact claim. |
| Gitleaks | Rule ID, `CONTENT`/`PATH`, source location, secret-safe observation | `FAMILY` | Raw `Secret` and `Match` are not carried into S4. No active-credential, rotation-complete, or revocation-complete claim. |
| Syft/OSV | Package component/name/version/PURL, accepted advisory-group ID, record IDs, aliases, reported fixed-event versions, revision evidence | `EXACT_EVIDENCE` for the accepted advisory match | Syft alone does not create a vulnerability finding. Full affected ranges and native advisory summary are not S4 guidance fields. Fixed events are not universal upgrade targets or compatibility guarantees. No reachability claim or live lookup. |
| Checkov | Framework, check ID/name, resource, source path/span, failed result | `EXACT_EVIDENCE` for the accepted check | Exact check identity is not an exact patch. Source IaC is not live cloud state or proof of deployed remediation. |

`EXACT_EVIDENCE` means a specific accepted check or advisory anchors the explanation, **not** that SecureScan knows an exact fix. `CLASSIFICATION`, `FAMILY`, and `EVIDENCE_ONLY` are progressively broader evidence bases, not exploitability/confidence scores. Semgrep is never promoted to exact remediation from rule ID alone. For unsupported or missing authority-specific payloads, the renderer returns `EVIDENCE_ONLY` guidance that references accepted evidence, recommends review and remediation, and requires a new comparable scan. It never fabricates technical steps.

## Derived schema and renderers

`FindingGuidance` contains `run_id`, `finding_id`, `authority`, basis, fixed title/summary, fixed-order remediation/verification/limitation lists, sorted evidence refs, and accepted source locations. Optional structured fields are rule ID, CWE IDs, Gitleaks detection kind, advisory ID/aliases, package name/observed version/reported fixed-event versions, and Checkov check ID/name/framework/resource. Scanner-controlled strings are returned only as JSON data fields; no markup is generated from them. The four authority-specific renderers do not interpret one another's payloads. `EvidenceOnlyGuidanceRenderer` is the safe fallback.

The trusted-host read-only API is `GET /v1/projects/{project_id}/lineages/{lineage_id}/runs/{run_id}/findings/{finding_id}/guidance`. It has no mutation or arbitrary interpretation parameters. A scope miss is 404; invalid identity is 422; integrity/read failure is 503. Output is deterministic for the same verified run evidence: no clock, randomness, scanner call, repository scan, OSV/package-registry request, credential test, cloud validation, AI, or patch generation.

Verification guidance requires a new valid/comparable scan. Semgrep calls for the same rule/coverage; Gitleaks rescans source but explicitly says source absence does not prove external revocation; OSV reruns dependency inventory and accepted-advisory matching without guaranteeing version compatibility; Checkov reruns IaC analysis and separates deployed-state validation.

## Safety and non-goals

The guidance read does not mutate scanner evidence, S4, identity, Product Core occurrence state, lifecycle, priority, governance, suppression, trusted baseline, Security Delta, or policy results. It does not change CLI exit behavior, SARIF, or current UI semantics. No migration, dependency, scanner behavior, live external lookup, AI, or automatic patching is added. A future exact Semgrep fix catalog or full OSV range display would require a separate accepted evidence contract; neither is inferred here.

## Validation

Focused tests cover the authority mappings, downgrade/fallback, deterministic output, secret non-disclosure, hostile metadata as JSON data, project/lineage/run isolation, verified-report tamper rejection, read-only database snapshot, and GET-only API contract. The acceptance matrix selected 1,006 unique cases: 1,002 passed and four opt-in real-Syft replay cases skipped, with zero failures. This includes 901 current-branch non-PostgreSQL cases, 65 existing Web UI cases, 36 real PostgreSQL cases in a disposable test container, and four extra exact-run/alias/hostile-input cases. The PostgreSQL test used the same verified S4 path and compared all database table contents before and after guidance reads. No preserved deployment was touched.
