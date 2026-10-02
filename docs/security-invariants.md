# SecureScan security invariant catalog

These identifiers are stable review handles. Changes require an explicit contract review and a
hostile regression named for the affected identifier.

| ID | Frozen invariant | Primary enforcement |
| --- | --- | --- |
| EVI-001 | Published security evidence is trusted only as a typed S4 report. | `VerifiedPublishedRunGateway` rebuilds through strict S4 assembly. |
| EVI-002 | Canonical typed S4, CAS bytes, and published DB JSON must agree exactly. | Verified-read byte comparison. |
| EVI-003 | Report scope must match run, repository, profile, and plan identities. | Verified-read scope checks. |
| EVI-004 | A derived projection cannot repair or supersede S4 evidence. | Read-only product and interoperability services. |
| EXE-001 | Tool output enters S4 only through a trusted binding and parser/adapter contract. | Frozen scanner execution and assembly paths. |
| EXE-002 | Tool, adapter, binding, ruleset, projection, and external snapshot identities are reported only when persisted. | Toolchain manifest projection. |
| EXE-003 | Host paths, raw scanner output, secrets, warnings, and errors do not enter interoperability exports. | Bounded export fields and hostile path checks. |
| EXE-004 | Only an execution linked to the selected accepted attempt may contribute actual tool/adapter identity. | Attempt, job mapping, planning snapshot, and execution cross-checks. |
| IDN-001 | S4 `package_key` and `component_ref` remain the authoritative package identities. | Frozen S4 component validation. |
| IDN-002 | PURLs are observed or deterministically derived; missing or unsupported coordinates are never guessed. | Component identity mapper. |
| LIF-001 | Lifecycle comparison uses frozen finding identity and lineage rules, not SBOM identity. | Existing lifecycle service unchanged. |
| LIF-002 | Only verified published runs participate in lifecycle evaluation. | Gateway-delegated lifecycle verification. |
| LIF-003 | V1.3 interoperability cannot change finding state or transition version. | Read-only services; no migration. |
| GOV-001 | Governance is project-, lineage-, finding-, and lifecycle-episode scoped. | Frozen effective-governance contract. |
| GOV-002 | Pre-reopen exclusionary governance is dormant until explicit reaffirmation. | Frozen V1.2D projection. |
| SUP-001 | Suppression is episode-scoped and pre-reopen suppression is dormant. | Frozen V1.2D projection. |
| BAS-001 | Baseline promotion is explicit and never caused by scan or export. | Frozen baseline service; read-only exports. |
| BAS-002 | A baseline refers to a verified eligible run in the same project and lineage. | Frozen baseline verification. |
| DEL-001 | Security Delta compares explicit trusted baseline and candidate runs. | Frozen Security Delta service. |
| DEL-002 | Partial or incomparable evidence remains visible and fails conservative decisions. | Frozen delta/policy status handling. |
| POL-001 | Plain scan and export do not persist a policy decision. | Explicit policy evaluation command only. |
| POL-002 | Policy consumes verified lifecycle/governance/baseline/delta facts and fails closed on missing evidence. | Frozen policy service. |
| GUIDE-001 | Guidance is derived from the exact verified run/finding and cannot mutate governance. | Guidance service verified read. |
| SEC-001 | Project and lineage ownership are checked at the verified-read boundary when supplied by a consumer. | Gateway ownership checks. |
| TIME-001 | Wall-clock time is not part of component, CycloneDX, or toolchain identity. | Canonical deterministic serializers. |
| THR-001 | KEV, EPSS, and NVD correlation requires an exact valid CVE from OSV `aliases`; related, upstream, descriptions, package similarity, CWE, CPE, fuzzy matching, and AI cannot establish identity. | Canonical CVE validator and verified S4 OSV group projection. |
| THR-002 | Absence from a valid KEV snapshot means `NOT_LISTED_IN_SNAPSHOT`, never not exploited. | Typed KEV assessment state. |
| THR-003 | Missing EPSS evidence never becomes zero. | Typed `NOT_SCORED`, `UNAVAILABLE`, and `SNAPSHOT_INVALID` states. |
| THR-004 | Intelligence cannot alter canonical finding identity. | Read-only correlation keyed by frozen S4 finding ID. |
| THR-005 | Intelligence cannot mutate lifecycle. | Append-only assessment tables have no lifecycle write path. |
| THR-006 | Intelligence cannot mutate a trusted baseline. | Explicit baseline service remains the sole promotion path. |
| THR-007 | A failed refresh cannot replace or corrupt the last valid snapshot. | Validate before insert; immutable content identity. |
| THR-008 | Only completely bounded, validated, normalized, CAS-persisted snapshots are eligible. | Atomic snapshot importer and verified reads. |
| THR-009 | Policy-required unavailable, invalid, corrupt, or stale intelligence produces `ERROR`. | Threat-policy required-source and freshness rules. |
| THR-010 | KEV, EPSS, CVSS, delta, governance, and policy remain separate; no composite risk score exists. | Typed source evidence and explicit rules. |
| THR-011 | Every exact CVE alias on one OSV advisory retains independent NVD, KEV, and EPSS evidence. | One assessment row per finding, advisory, CVE, and bundle. |
| THR-012 | AI cannot correlate or interpret Prompt-1 intelligence and cannot influence policy. | No AI dependency or call path. |
| THR-013 | Intelligence requests, artifacts, logs, and projections contain no source or raw secret material. | Exact-CVE NVD requests and generic feed imports only. |
| THR-014 | Every assessment records the exact immutable bundle and evidence references used. | Bundle foreign key and per-source evidence state. |
| THR-015 | Intelligence refresh and assessment do not require a source rescan. | Separate import and evaluation services. |
| THR-016 | Historical assessments are append-only and newer intelligence cannot rewrite them. | Content-derived identity and immutable unique inputs. |

## Prompt 1 acceptance mapping

`tests/test_v13_trust_components_interop.py` covers IDN-001/002, EVI-004, EXE-002/003/004,
SEC-001, and TIME-001. `tests/test_source_product_core_pc1.py` covers EVI-001/002/003 and hostile
published-state/CAS/DB disagreement. Existing V1.2 lifecycle, governance, baseline, delta, policy,
guidance, scanner, API, CLI, SARIF, and UI suites retain the remaining contract coverage.

V1.5 Prompt 1 tests cover THR-001 through THR-016 with hostile KEV/EPSS/NVD parsing,
CAS-corruption checks, exact-alias correlation, append-only replay, PostgreSQL races, and
deterministic decision-proof tests.
