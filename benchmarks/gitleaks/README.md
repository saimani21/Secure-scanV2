# Gitleaks trusted binding v1

Source v0.4A pins Gitleaks `8.30.1` for Linux x64. The authoritative upstream
sources are the official [v8.30.1 release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1),
the versioned [README](https://github.com/gitleaks/gitleaks/blob/v8.30.1/README.md),
and the versioned [MIT license](https://github.com/gitleaks/gitleaks/blob/v8.30.1/LICENSE).

## Provisioning

An operator acquires `gitleaks_8.30.1_linux_x64.tar.gz` before SecureScan
execution, verifies archive SHA-256
`551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`,
extracts only the `gitleaks` executable into an operator-controlled absolute
path, and verifies executable SHA-256
`88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509`.
Production scans never download or install Gitleaks. The binding rejects a
missing, non-regular, symlinked, multiply linked, non-executable,
group/world-writable, digest-mismatched, or version-mismatched executable.

## Configuration

Configuration `securescan-gitleaks-built-in-default-v1`, version `1`, is the
small project-owned TOML wrapper that extends Gitleaks 8.30.1's built-in default
rules. The scanner version therefore freezes the inherited detector set. The
TOML SHA-256 is
`ca699281a4752ca677d7f1c1c22d97d2afca9c169eae28054486d4d95bae7fb4`.
An explicit project-owned empty ignore file, SHA-256
`c5f2fc626c9cae855bbf0261d37ea80600cb65a270483a2df536a6c1c60e8f85`,
prevents repository-local `.gitleaksignore` discovery from changing results.
No SecureScan-specific detector tuning or allowlist is present.

## Current-snapshot execution

The exact argv is:

```text
<absolute-gitleaks> dir
  --config <absolute-trusted-config>
  --gitleaks-ignore-path <absolute-trusted-empty-ignore>
  --report-format json
  --report-path -
  --redact=100
  --ignore-gitleaks-allow
  --no-banner
  --no-color
  --log-level error
  --max-archive-depth 0
  --max-decode-depth 0
  --timeout 295
  --exit-code 1
  <absolute-immutable-snapshot-root>
```

Gitleaks documents `dir` as directory/file scanning. Its separate `git` mode
uses `git log -p` to scan history. The contract has no command or flags input,
always constructs `dir`, supplies the snapshot root explicitly, and has no
Git-log, clone, URL, stdin, diagnostics, archive, or decode path. Its child
environment is empty. Repository-controlled `gitleaks:allow` directives are
explicitly disabled. Execution uses the shared cancellable process executor
with `shell=False`, a 300-second outer timeout, 64 MiB stdout limit, and 64 KiB
stderr limit. No repository code or dependency installation is involved.

## Confidentiality and scope

Gitleaks receives repository contents to scan, but the v0.4A command requests
100 percent redaction. Raw secret values must never enter API errors, logs,
generic finding logs, exception text, finding identity, metrics labels, or
provenance digests. A future identity must use non-secret structural evidence;
`hash(secret)` is not a public identifier.

Gitleaks scans the immutable current source snapshot only. Git history scanning
is outside Source v1. A detected secret is evidence of secret-like material in
source, not proof that the credential is currently valid, exploitable, or
active. Provider validation and network requests are outside this contract.

The existing `SECRET_DETECTION` capability is used. It remains `DETECTED` in
v0.4A because parsing, normalization, benchmark evidence, and production
planner registration are later checkpoints.

## Pinned binary functionality sentinel

The exact official Linux x64 executable passed a positive synthetic
`github-pat` detection and an empty-directory negative run using the command
above: `PINNED_BINARY_FUNCTIONALITY_SENTINEL_PASS`. The positive process exited
`1`, emitted one `github-pat` finding with `Secret` equal to `REDACTED`, and did
not emit the raw synthetic value on stdout or stderr. The empty directory
exited `0` with `[]` on stdout and empty stderr.

This sentinel establishes only that this pinned binary performs detection. It
is not benchmark evidence, is not scored, does not tune detectors, and does not
affect maturity. It can be repeated explicitly with:

```text
./.venv/bin/python scripts/verify-gitleaks-functionality-sentinel.py \
  --gitleaks /absolute/path/to/gitleaks
```

The helper creates and removes both synthetic directories under `/tmp`; the
ordinary Python test suite does not require Gitleaks to be installed.

## v0.4F2 pre-scan corpus freeze

The v0.4F2 corpus was designed and content-addressed before any Gitleaks
execution against this corpus or any v0.4F benchmark observation. `corpus-plan-v1.json` freezes 48 intended case/rule relations: 42
core relations covering seven representative inherited Gitleaks 8.30.1
detectors and six scope/allowlist relations. Each core detector has three
expected matches and three expected non-matches. The plan is bound to the full
v0.4F1 commit, frozen contract, trusted binding, scanner ID, and scanner
version. `manifest.json` is produced through the frozen v0.4F1 manifest model.

All token-shaped fixture values are deterministic, project-owned, synthetic,
and non-live. They must never be used as credentials or submitted to a
provider. The private-key cases are static non-cryptographic text; the PKCS12
path cases are empty files or meaningless fixed bytes and contain no usable
key, certificate, or credential bundle. Generation uses no entropy, network,
external program, Git repository, or scanner process.

The selected detector families are representative only. This corpus does not
certify every detector inherited from Gitleaks 8.30.1. SecureScan applicability
may select docs, generated, test, vendor, dependency, config, and
unknown-language paths even when an inherited Gitleaks global allowlist
suppresses a path internally; path selection does not guarantee that every
detector inspects every selected byte. Cross-rule observations are not
pre-suppressed and must be accounted for separately during a later evaluation.

Gitleaks has not been executed against this corpus at this checkpoint. No scan
observations, classifications, accuracy metrics, or maturity decision are part
of the plan or manifest. Even perfect future metrics would apply only to this
bounded project-owned corpus. `SECRET_DETECTION` remains `SCANNABLE`, and
v0.4F2 is frozen by `source-v0.4F2-gitleaks-prescan-corpus` at
`98034c4e124e935e2bb5a893c45013ed5090f6e3`.

## v0.4F3A controlled benchmark machinery

v0.4F3A implements the pure relation evaluator, deterministic report schema,
production-path harness, narrow CLI and runner, raw-output confidentiality
gate, and atomic first-baseline recording policy. The F2 ground truth remains
immutable. Scanner launch is delegated to the production Source bridge, and
the production parser and v0.4E structural finding identity implementation are
reused unchanged. The benchmark does not construct a separate Gitleaks command
or parse scanner JSON itself.

Each manifest case remains one intended path/rule/detection-kind relation.
Repeated matching observations remain individually represented but count once
for relation classification. Findings from a different rule remain separate
unexpected cross-rule observations, including parser-valid inherited rules
outside the seven representative families. A finding on a path outside the 48
frozen cases fails the evaluation.

Raw scanner stdout and stderr remain memory-only. Before parsing, deterministic
synthetic fixture values derived from the frozen corpus must be absent from
both streams. The pure evaluator makes no raw-output confidentiality claim;
only the controlled production-path report built after this validation may
carry the successful boolean assertion. No real Gitleaks execution against the
F2 corpus has occurred in F3A, no F3 detection metrics or baseline exist, and
no maturity decision is made. `SECRET_DETECTION` remains `SCANNABLE`.

## v0.4F3B immutable initial baseline

F3B froze the first controlled F2-corpus observation at commit
`d183336c129977c4279cd1058bbe060742de0e54` and tag
`source-v0.4F3B-gitleaks-initial-baseline`. The immutable report contains 22 TP,
23 TN, 0 FP, and 3 FN across 48 intended relations, with no unexpected
cross-rule observations. Its SHA-256 is
`62f9c00f79c659d56490a181de231f0aa3cdca6a418f2ca5a9215f7ed1bbbb34`.

The three frozen misses are `generic-api-key-positive-01`,
`pkcs12-file-positive-01`, and `pkcs12-file-positive-02`. F4 does not replace,
recalculate, or rewrite this accuracy baseline.

## v0.4F4A adversarial characterization pre-scan contract

F4A freezes thirteen deterministic diagnostic cases before the next scanner
observation. The cases bound the three F3B misses using high-entropy `alpha`
stopword probes, a low-entropy boundary, a generic high-entropy control,
zero-byte and one-byte PKCS12 path cases, case and suffix path boundaries, and
inherited `node_modules`/`vendor/github.com` allowlist controls.

This is characterization, not another representative accuracy benchmark.
Expectations use only `EXPECTED_OBSERVED` and `EXPECTED_ABSENT`; no precision,
recall, F1, benchmark maturity, or replacement F3B metrics are produced. The
static verifier checks structural regex compatibility, deterministic Shannon
entropy, stopword isolation, exact fixture sizes, PKCS12 path semantics,
allowlist path boundaries, canonical artifact identity, and complete corpus
membership without executing Gitleaks.

All detector-shaped values are deterministic, synthetic, project-owned, and
non-live. No credentials are validated, no network behavior occurs, and whole
fixture SHA-256 values exist only for corpus integrity. No F4 real scan has
occurred and the reserved `adversarial-v1-result.json` artifact does not exist.
`SECRET_DETECTION` remains `SCANNABLE`.
