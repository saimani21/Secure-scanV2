# Source v0.6 Configuration Security

## Decision

SecureScan Source S3 provides source-native configuration-security evidence
through an isolated, pinned Checkov 3.3.16 CLI. The capability maturity is:

```text
CONFIGURATION_SECURITY = SCANNABLE
```

This is a controlled vertical integration, not a claim that all configuration
defects or all Checkov frameworks are covered.

## Trusted boundary

The production path is:

```text
frozen Source projection
-> Checkov applicability
-> trusted Checkov 3.3.16 binding
-> bounded local CLI process
-> strict JSON parser
-> normalized findings, suppressions, and framework gaps
```

The framework allowlist is exactly:

- Terraform
- CloudFormation/SAM where handled by Checkov's CloudFormation runner
- Kubernetes manifests
- Dockerfiles
- GitHub Actions workflows

The binding verifies the absolute local launcher as a stable regular file, then
verifies the exact Checkov version and the complete frozen Python toolchain: CPython
3.12.3 plus 97 exact distributions from a wheel-hash lock. The universal binding
identity is the normalized toolchain digest, normalized launcher-template digest,
trusted configuration SHA-256, framework allowlist, and command contract. The
launcher must name its own venv Python and match that frozen normalized template. Its
raw SHA is intentionally only a local integrity guard: an independently constructed
second environment produced a different launcher hash because its shebang path
differed, while its launcher template, distribution inventory, and normalized
controlled report were byte-identical. The scanner runs
without a shell or stdin, with an empty child environment, a 300-second timeout, a
64 MiB stdout limit, and a 64 KiB stderr limit.

SecureScan passes an absolute project-owned configuration and explicit CLI
overrides. Repository `.checkov.yml`, `.checkov.yaml`, and `.checkov.baseline`
files do not enter the scanner projection. External checks, external Terraform
module downloads, policy/platform downloads, uploads, and platform credentials
are disabled. This configures Checkov for local/offline operation; it is not an
OS-level egress sandbox.

The trusted toolchain can be prepared only from an explicitly supplied offline
wheelhouse with `scripts/setup-checkov-s3-toolchain.sh`. Installation uses
`--no-index`, `--require-hashes`, and `--no-deps`; dependency resolution and network
access are not part of ordinary execution or tests.

Checkov's Terraform framework includes policies whose purpose is direct discovery of
literal credentials even when the `secrets` framework is disabled. S3 therefore
freezes a narrow 15-check authority denylist covering hard-coded provider credentials,
tokens, keys, and embedded-secret detectors. Configuration-security controls about
secret-store encryption, rotation, access, and use remain enabled. A controlled
Terraform fixture proves `CKV_AWS_41` is absent while the unrelated `CKV_AWS_18`
configuration control still fires on the same file.

The exact excluded check IDs are:

- provider credential material: `CKV_AWS_41`, `CKV_BCW_1`, `CKV_LIN_1`,
  `CKV_NCP_17`, `CKV_OCI_1`, `CKV_OPENSTACK_1`, and `CKV_PAN_1`
- embedded or custom-data secret discovery: `CKV_AWS_45`, `CKV_AWS_46`,
  `CKV_AWS_384`, `CKV_AZURE_45`, and `CKV_TC_13`
- literal secret/password field discovery: `CKV_AWS_295`, `CKV_AZURE_239`, and
  `CKV_OPENSTACK_4`

Variable evaluation is frozen off. A hostile fixture referenced a harmless marker
both relatively and through an absolute path outside the projection. The marker did
not appear in output, but filesystem-access confinement could not be independently
proven in this environment, so S3 does not authorize Checkov variable evaluation.

`quiet` is deliberately false. Checkov 3.3.16 omits passed and skipped records
from its compact JSON when quiet mode is enabled, which would prevent strict
suppression and framework-completion accounting. Raw scanner output remains
transient and bounded regardless.

## Normalized evidence

An active `ConfigurationSecurityFinding` is derived only from a failed,
non-suppressed policy observation. It retains the scanner and binding identity,
framework, check ID and name, resource, normalized repository-relative path,
optional line range, optional upstream severity, and frozen projection
provenance. SecureScan does not manufacture severity.

Finding identity is derived from framework, check ID, normalized path, and
resource identity. It excludes line numbers, check name, severity, URLs, code,
evaluated values, absolute paths, timestamps, and process metadata, so source
line movement alone does not change identity.

Suppressed checks are separate observations: they are neither active findings
nor passed checks. Parser errors are explicit coverage gaps and cannot become a
clean result. Passed checks are retained only as bounded transient records used
to validate framework aggregates; canonical evidence records aggregate counts,
not the pass-record inventory.

The parser rejects invalid UTF-8 or JSON, duplicate keys, non-finite values,
unexpected report structures, inconsistent summary counts, invalid check IDs,
unsafe paths, invalid line ranges, oversized strings, and excessive collection
sizes. It discards raw code blocks, evaluations, variable values, connected-node
structures, resource configuration, URLs, platform metadata, and raw JSON.

Terraform, Dockerfile, and GitHub Actions filenames provide deterministic framework
expectations. If Checkov omits any such expected report, parsing fails with
`CHECKOV_RESULT_INCONSISTENT`; absence cannot become `NOT_APPLICABLE`. Generic YAML
and JSON files remain conservative CloudFormation/Kubernetes discovery candidates,
not a claim that arbitrary YAML or JSON is configuration security. Checkov 3.3.16
returns a summary-only all-zero document for unrelated generic files; only that exact
shape, when no filename-deterministic framework is expected, becomes all-framework
`NOT_APPLICABLE`.

## Controlled evidence

The project-owned controlled corpus freezes 13 files across the five supported
frameworks. Each framework has a selected known-failing and corresponding
passing policy relation characterized against Checkov 3.3.16. The corpus also
contains a Terraform inline suppression and malformed Terraform input.

The controlled run records:

| Framework | Active findings | Passed checks | Suppressions | Parse gaps |
|---|---:|---:|---:|---:|
| Terraform | 26 | 17 | 1 | 1 |
| CloudFormation | 11 | 7 | 0 | 0 |
| Kubernetes | 32 | 146 | 0 | 0 |
| Dockerfile | 2 | 45 | 0 | 0 |
| GitHub Actions | 3 | 21 | 0 | 0 |
| Total | 74 | 236 | 1 | 1 |

The selected fail/pass relations are `CKV_AWS_18` for Terraform and
CloudFormation, `CKV_K8S_20` for Kubernetes, `CKV_DOCKER_3` for Dockerfile, and
`CKV_GHA_7` for GitHub Actions. These observations demonstrate deterministic
integration behavior on this corpus; they are not precision, recall, or broad
policy-coverage measurements.

## Claim matrix

### Supported

- Terraform source misconfiguration checks
- CloudFormation/SAM source checks handled by the CloudFormation runner
- Kubernetes manifest checks
- Dockerfile checks
- GitHub Actions workflow checks
- deterministic normalized Checkov policy findings
- inline suppression evidence
- explicit parser, gap, and process failure state

### Limited

- Checkov built-in policy coverage
- source-only evidence
- local variable resolution
- Checkov framework parser behavior
- external Terraform module contents, which are not downloaded or claimed
- policy severity without platform metadata
- local/no-network configuration without an OS-level egress sandbox

### Not supported

- deployed cloud state or runtime configuration
- exploitability, reachability, or active exposure
- secret detection through Checkov
- dependency or container-image scanning through Checkov
- Terraform plan analysis
- Helm or Kustomize rendering
- remote repository configuration
- custom external policies or Python policy execution
- Prisma Cloud platform policies or account state

`SCANNABLE` does not imply universal Checkov coverage, zero false positives or
false negatives, external-module coverage, or deployed-state validation.
