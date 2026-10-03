# SecureScan Source V1.5 product release contract

Status: Prompt 2 implementation contract

Frozen backend checkpoint:
`c88bdfb46c9f6346c6b4de32fde6d0a10194ffda`

## Boundary

Prompt 2 is a consumer of the verified Product Core and Prompt-1 assurance
services. It does not establish finding, lifecycle, governance, baseline,
delta, CVE, KEV, EPSS, NVD, or policy truth. CI, API, Web UI, reports, and the
optional AI assistant receive the same typed assurance projection and policy
proof. No scanner, migration, remote Git intake, scheduler, risk score, or V2
artifact-assurance feature is added.

## CI command

The trusted-host command is:

```text
securescan ci REPOSITORY --project-id UUID --bundle-id ID --policy FILE
  [--lineage-id UUID] [--output DIRECTORY]
  [--deadline-seconds N] [--wait-timeout-seconds N] [--poll-seconds N]
```

It uses the existing secure local repository intake, durable submission, and
bounded wait. A running SecureScan worker remains an operator prerequisite.
After verified publication it creates the Prompt-1 threat assessment and
policy proof, then exports only that exact run's SARIF and CycloneDX document.
It never promotes a baseline. The explicit bundle and policy definition are
recorded in the proof. Historical reassessment remains available through
`securescan intel evaluate`, `assurance`, and `policy-proof` without a rescan.

The stable CI exits are `0` for policy `PASS`, `1` for policy `FAIL`, `2` for
invalid configuration or any operational/evidence/policy `ERROR`, and `130`
for an interrupted wait. `FAIL` means authoritative evidence violated policy;
`ERROR` means SecureScan could not decide safely. Missing baseline or required
intelligence is never converted to `PASS`.

## CI artifacts

The configurable output directory defaults to `.securescan`. Its parent must
already be a real directory. The target must not exist, and no symlink is
followed. Complete mode-0600 files are first written to a private sibling
staging directory and the directory is atomically installed:

- `ci-result.json`: compact orchestration record and artifact references;
- `decision-proof.json`: the exact Prompt-1 deterministic proof;
- `results.sarif`: existing verified SARIF 2.1.0 export;
- `sbom.cdx.json`: existing verified CycloneDX 1.7 export;
- `summary.md`: deterministic, Markdown-neutralized human summary;
- `assessment.html`: deterministic escaped print-friendly assessment.

The result references rather than duplicates complete findings. All artifacts
bind to one candidate run, baseline revision, bundle, evaluation timestamp,
and proof. Existing output is an error; CI does not merge or partially replace
prior evidence.

## Product read model

`ProductAssuranceService` composes existing verified reads into:

- an assurance dashboard with decision, delta, threat, governance, coverage,
  baseline, bundle, and freshness facts;
- category-aware knowledge cards with Prompt-1 per-CVE evidence, verified
  Product Core state, effective governance, deterministic guidance, and proof
  decisions;
- an escaped HTML assessment generated from that same projection.

The Web UI extends the existing same-origin module shell. It renders server
projections using `textContent`; it does not independently infer security
state. Typed absence such as `NOT_SCORED`, `NOT_LISTED_IN_SNAPSHOT`,
`UNAVAILABLE`, and `NOT_APPLICABLE` stays visible.

## Guidance v2

Existing deterministic guidance remains authoritative. A bounded verification
playbook is an additive presentation derived from an exact supported rule or
finding family. It describes manual checks, expected secure behavior, and
retest steps. It never generates exploit payloads, claims exploitation, or
labels a scanner observation as a manually validated vulnerability.

## HTML assessment

The report is a pure deterministic renderer. Every external/finding string is
HTML-escaped, URLs are not made active, fields are bounded, absolute local
paths are not introduced, and secret evidence is never reconstructed. It
labels observed evidence, external intelligence, deterministic conclusions,
guidance, and limitations separately. AI is not required and is not inserted
into the authoritative report by default.

## Optional AI boundary

AI is a server-side, read-only explanation feature. `DisabledProvider` is the
default. `OpenAIProvider` is loaded lazily from the optional `ai` dependency and
uses the Responses API with `store=False`, no tools, bounded input/output,
bounded timeouts, and one bounded retry. Configuration is only:

```text
SECURESCAN_AI_ENABLED
OPENAI_API_KEY
SECURESCAN_AI_MODEL
SECURESCAN_AI_ALLOW_SOURCE_SNIPPETS=false
```

The browser never receives the API key and never contacts OpenAI. The bounded
context contains only selected SecureScan read-model facts, deterministic
guidance, proof reasons, and supplied evidence-reference IDs. Repository text
is data, never instruction. Source snippets are omitted by default; secret
findings can never contain snippets. Provider failure affects only explanation.
Returned citations not present in the supplied context are dropped. AI output
is always labeled generated and cannot enter a mutation or policy path.

The official server-side Python integration reviewed for this contract is
`OpenAI(...).responses.create(...)`. No Assistants API, web search, computer
use, file search, or function tool is used.

## GitHub Actions

The documentation workflow uses GitHub's current official major versions:
`actions/checkout@v6` and `github/codeql-action/upload-sarif@v4`. It requires a
pre-provisioned ephemeral runner with the frozen scanner toolchain and an
honestly supplied SecureScan release wheel. `contents: read` is always present;
`security-events: write` is limited to SARIF publication. The CI exit is
captured, artifacts and step summary are published under `if: always()`, and
the original PASS/FAIL/ERROR result is restored afterward. No personal access
token or `pull_request_target` execution is required.

## Release acceptance

Release requires hostile CI/presentation/AI tests, API/CLI/UI parity, offline
replay, intelligence-only reassessment, PostgreSQL concurrency and upgrade
gates, complete relevant regressions counted by distinct node ID, wheel and
sdist inspection, clean installed-artifact smoke, real isolated startup/E2E,
secret/diff review, accurate documentation, a clean worktree, one release
commit, and an annotated local `source-v1.5.0` tag. Nothing is pushed and V2 is
not started.
