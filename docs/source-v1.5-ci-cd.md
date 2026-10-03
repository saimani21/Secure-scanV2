# SecureScan Source V1.5 CI/CD guide

`securescan ci` is one orchestration layer over existing authoritative services.
It does not rescan evidence for export and does not implement a second policy
engine.

```bash
securescan ci /absolute/path/to/repository \
  --project-id 00000000-0000-4000-8000-000000000000 \
  --bundle-id <64-lowercase-hex-intelligence-bundle-id> \
  --policy .securescan/threat-policy.json \
  --output .securescan
```

The repository path follows the frozen local trusted-host intake contract. The
project must already exist. The bundle must be an immutable eligible V1.5
bundle. The policy file is strict JSON matching `securescan-threat-policy-v1`.
The command never promotes or silently selects a trusted baseline.

Exit codes are stable:

| Code | Meaning |
| ---: | --- |
| 0 | Sufficient authoritative evidence produced policy `PASS`. |
| 1 | Sufficient authoritative evidence produced policy `FAIL`. |
| 2 | Configuration, operation, evidence, or required policy evaluation produced `ERROR`. |
| 130 | The operator interrupted waiting; the durable scan was not implicitly cancelled. |

On a completed decision the output directory is created atomically with mode
`0700`; files use `0600`. An existing output path is rejected. The exact set is:

```text
assessment.html
ci-result.json
decision-proof.json
results.sarif
sbom.cdx.json
summary.md
```

Every artifact derives from the same verified run. `ci-result.json` links the
candidate, baseline revision, immutable bundle, threat assessments, and proof.
Missing or corrupt required evidence is never represented as an empty result.

The inert reference workflow is
[`examples/github-actions/securescan-v15.yml`](../examples/github-actions/securescan-v15.yml).
It uses a trusted self-hosted runner because the Source scanner toolchain and
operator database are local security dependencies. SecureScan v1.5 is not
claimed to be on public PyPI. Supply an internally built V1.5 wheel and provision
the pinned scanner toolchain before applying the runner label. Normal use needs
only the repository `GITHUB_TOKEN`; no personal access token is required.
Set the repository variable `SECURESCAN_OPERATOR_PROFILE` to the absolute path
of that runner's private V1.5 operator profile; do not store profile contents in
workflow YAML.

The workflow records the gate code, publishes the summary, bundle, and SARIF on
PASS or FAIL, then exits with the original code. Its least-privilege permissions
are `contents: read` and `security-events: write`. Fork pull requests require
the repository's normal GitHub Code Scanning trust review.

Jenkins, GitLab CI, and other orchestrators invoke the same command, retain `$?`,
publish `.securescan`, and finally exit with that retained value. A scheduled
orchestrator can use the existing intelligence import/evaluation commands to
evaluate a historical verified run with a newer explicit bundle without a
source rescan.

`UNKNOWN != CLEAN`, `FAILURE != ZERO`, and `PASS != BASELINE PROMOTION`.
