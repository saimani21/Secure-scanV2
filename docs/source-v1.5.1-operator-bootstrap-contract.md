# SecureScan Source V1.5.1 operator bootstrap contract

Status: implementation contract for the bounded V1.5.1 hotfix.

## Scope

V1.5.1 corrects operator bootstrap usability only. It does not change scanner
semantics, finding identity, lifecycle, governance, baseline, delta,
intelligence, policy, CI, AI, or persistence schemas.

The operator image build must copy every file declared as Python distribution
data before installing the project. This prevents a fresh build from depending
on a stale cached image layer.

Each managed Compose project uses its validated project name as the local API
image tag. A disposable or parallel project therefore cannot move the shared
legacy `securescan-core:d1` tag used by preserved deployments.

## Operator profile

The operator profile is versioned SecureScan-owned JSON, not a shell env file.
`SECURESCAN_OPERATOR_PROFILE` selects its path; operator commands load it
automatically with this precedence:

1. explicit `SECURESCAN_*` process environment;
2. the private operator profile;
3. safe defaults.

The V1 profile format and private file rules remain unchanged. The parent must
be an owner-owned mode `0700` directory and the profile must be an owner-owned
regular file with no group or other permissions. Existing V1.5 profiles remain
valid. Operators must export the profile *path* and must not source the profile.

`system configure --from-env-file` parses a restricted `KEY=VALUE` input file
without shell execution, validates recognized settings, writes the complete
resolved configuration atomically, and identifies the output as application
configuration in its success message.

## Trusted toolchain bootstrap

Gitleaks, Syft, Checkov, and Semgrep already obtain their frozen identities
from packaged binding metadata. Enry is the only affected scanner: V1.5
required its expected executable SHA-256 to be supplied independently in
configuration even though the release helper has a frozen identity.

V1.5.1 packages the V1.5 Enry helper SHA-256 as operator trust metadata:

```text
f72f6d34afb39a323be4060a0c04850b2bff58b8f9a1294a408b5776d3575864
```

When a controlled configure input omits
`SECURESCAN_SOURCE_ENRY_HELPER_SHA256`, `system configure` persists this
release identity. An explicit independently trusted digest still takes
precedence. SecureScan never derives trust by hashing the runtime helper and
accepting that result. Runtime verification remains exact and fail-closed.

## Diagnosis and inspection

`doctor` reports safe, actionable Enry failures for a missing expected digest,
missing executable, unreadable executable, untrusted file type or permissions,
digest mismatch, and other integrity failure. No credential or expected digest
is printed.

`system config [--json]` is a read-only inventory of the active profile path,
deployment identifiers, project-scoped image tag, ports, storage roots, scanner
paths, and trusted identity states. It never renders the database URL,
PostgreSQL password, HMAC key, tokens, or API keys.

## Supported bootstrap

```bash
export SECURESCAN_OPERATOR_PROFILE="$HOME/.config/securescan/v15-final.profile"
securescan system configure --from-env-file /tmp/securescan-v15-final.env
securescan system config
securescan doctor
securescan init
securescan system up
securescan system status
securescan open
```

The generated profile is consumed by SecureScan and is never sourced by the
shell.
