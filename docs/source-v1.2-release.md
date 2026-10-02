# SecureScan Source v1.2.0

SecureScan Source v1.2.0 is a single-node, local-first security-analysis product
for repositories admitted through the trusted host. The annotated product tag
`source-v1.2.0` identifies this release. The Python distribution and FastAPI
metadata intentionally retain the independent SecureScan Core version `0.1.0`;
that is not the Source product release number.

## Supported workflow

```text
local scan → verified evidence → canonical finding → historical lifecycle
           → analyst governance → explicit trusted baseline → Security Delta
           → deterministic policy/CI decision → human fix → comparable rescan
           → proven RESOLVED only after eligible, authoritative absence
```

V1.2 retains the V1.1 five-authority scan pipeline, exact-run evidence,
coverage/gaps, JSON CLI, SARIF 2.1.0 export, and same-origin Web UI. It adds:

- Audited `FALSE_POSITIVE` and expiring `ACCEPTED_RISK` governance, separate
  expiring/revocable suppression, and a read-only EffectiveGovernance projection.
  A reopen makes pre-reopen exclusions dormant and requires explicit review.
- Explicit, revision-checked trusted baseline promotion. Security Delta compares
  an exact candidate run against that baseline and keeps `NOT_COMPARABLE`
  distinct from `INTRODUCED`, `PRESENT`, and `REMOVED`.
- Versioned, deterministic trusted policy definitions and immutable evaluations.
  `PASS`, `FAIL`, and `ERROR` are distinct; required unknown or incomplete truth
  is `ERROR`, not a clean pass. Explicit `securescan policy evaluate` maps them
  to exits `0`, `1`, and `5`; ordinary `scan` does not enforce policy.
- Run-scoped guidance derived only from verified published evidence. It offers
  bounded review/verification context, not an automatic patch or exploitability
  claim.
- Bounded API, CLI, and Web views for findings, guidance, governance,
  baseline, Delta, policy, and coverage. Repository intake and scan start remain
  trusted-host CLI operations; the browser can create a named project but cannot
  upload source or submit an arbitrary host path.

Disappearance alone does not prove `RESOLVED`: lifecycle depends on an eligible,
comparable run. No baseline is promoted automatically. Unknown/incomplete
evidence is never silently displayed as clean or zero findings. Public finding
reads reverify the published S4 content-addressed artifact before exposing
indexed results, and stranded scanner attempts may retry only after verified
clean containment.

## Installation and operation

Python 3.12+, Docker/Compose, PostgreSQL 16, and the frozen scanner toolchain
are required. The [single-node deployment guide](source-v1-deployment.md)
describes private operator-profile setup and `securescan system up`. Create a
project, submit a local repository through `securescan scan`, observe the run in
the Web UI or CLI, and use explicit governance, baseline, and policy actions
only after inspecting the accepted evidence. The existing immutable-pinned CI
example requires a pre-provisioned ephemeral runner; this release does not
claim a live GitHub upload.

## Schema and release evidence

The V1.2 migration path from the V1.1 head `f7c2d4e8a901` is linear:

```text
a2b7c4d9e105 governance
→ c4e8a1f6b203 suppression
→ d6f9b2c7a104 lifecycle event anchors
→ e7a1b3c5d902 trusted baseline
→ f8c2d6e1a305 deterministic policy (single head)
```

V1.2A and V1.2G–I add no migration. V1.2I froze with 942 distinct passing
selected tests, including all 164 PostgreSQL tests, no unresolved failure and
no selected-suite skip. Its real disposable gates proved worker SIGKILL
recovery, published-S4 tamper rejection, Ctrl+C wait durability, API restart,
PostgreSQL outage/restart, hostile browser rendering, and a two-scan
baseline/Delta/policy/JSON/SARIF workflow. V1.2R audited the 119-path V1.1→V1.2
diff and passed **366 distinct smoke tests**: 18 PostgreSQL migration/product/
recovery, 208 cross-layer, and 140 Gitleaks parser/hostile-guidance cases,
with zero failures or skips. A separate disposable database migrated from empty
with no model drift; a fresh local startup completed CLI, worker, API, Web UI,
two real scans, Product View and exports. The wheel contained the new product
modules and Web assets. Ruff lint, compilation and diff checks passed; no
production code, migration or preserved deployment changed in V1.2R. See
[status](source-v1-status.md) for the detailed release record.

## Security and product boundaries

- Local trusted-host repository intake only: no browser repository upload,
  arbitrary browser host path, or remote Git acquisition.
- Single-node/local-first operation; no authentication, RBAC, or multi-tenant
  isolation. Deploy only within the trusted operator boundary described in the
  deployment guide.
- No KEV, EPSS, VEX, reachability, DAST, malware analysis, autonomous AI, or
  automatic patching. A scanner finding is not proof of exploitability.
- No exhaustive language, rule, package-manager, advisory, or secret-detection
  coverage. Exact-pinned requirements support retains its documented narrow
  coordinate contract; ranges, VCS/local references, and resolution are not
  inferred as deterministic package versions.
- Guidance is evidence-derived and does not guarantee remediation. Source
  disappearance does not prove an exposed credential was revoked.

The 62 frozen historical benchmark tests requiring the exact v0.3 branch are
explicitly [excluded by provenance](source-v1.2h-historical-branch-exclusions.md),
not waived scanner/parser tests. A second independent hash-locked Checkov
launcher was not configured, so that optional reproduction is not claimed.
Repository-wide formatting still flags 326 unchanged legacy files, including
frozen benchmark fixtures; touched V1.2I files passed their format gate and
those legacy files were not mass-formatted for this release.
