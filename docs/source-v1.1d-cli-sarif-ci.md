# SecureScan Source V1.1D developer integration

## Boundary

V1.1D is a trusted-host developer surface over the frozen Product Core and
verified S4 report. It adds no HTTP client, scanner path, policy engine, remote
Git backend, suppression state, or GitHub-to-SecureScan state synchronization.
Project selection is always by durable UUID because names are not unique.

The command surface is:

```text
securescan project create NAME [--json]
securescan project list [--limit N] [--offset N] [--json]
securescan scan PATH --project-id UUID [--lineage-id UUID]
    [--deadline-seconds N] [--wait] [--wait-timeout-seconds N]
    [--poll-seconds N] [--json]
securescan scans [--project-id UUID] [--limit N] [--offset N] [--json]
securescan status RUN_ID [--json]
securescan stages RUN_ID [--json]
securescan findings RUN_ID [filters and pagination] [--json]
securescan dependencies RUN_ID [--limit N] [--offset N] [--json]
securescan coverage RUN_ID [--json]
securescan gaps RUN_ID [--authority AUTHORITY] [--limit N] [--offset N] [--json]
securescan report RUN_ID [--json]
securescan sarif RUN_ID --output PATH|- [--overwrite]
```

`scan` remains asynchronous unless `--wait` is supplied. Waiting polls durable
status with monotonic time and a bounded interval. Its default timeout is the
analysis deadline plus a fixed finalization allowance. A timeout or Ctrl-C stops
only the client wait; it does not cancel the durable scan.

## Exit and output contracts

The stable exit meanings are:

| Exit | Meaning |
|---:|---|
| 0 | Requested operation completed, including a completed scan with findings |
| 2 | Invalid input or unsafe output request |
| 3 | Resource absent, unpublished, or not ready |
| 4 | Durable submission conflict |
| 5 | Operator, persistence, workflow, analysis, timeout, or export failure |
| 130 | SIGINT while waiting |

Findings, including `CRITICAL` findings, never become policy failure in V1.1.
`FAILED`, `CANCELLED`, `BLOCKED_BY_PREDECESSOR`, and wait timeout are operational
failures. There is no V1.1 policy threshold or `fail-on-findings` option.

Machine mode emits one JSON document and a trailing newline on stdout. Errors
are a single diagnostic JSON document on stderr. Human output visibly encodes
terminal controls and bidirectional control characters and bounds untrusted
values. JSON preserves the underlying strings without terminal decoration.

## SARIF authority and limitations

SARIF 2.1.0 is generated only after all of these checks succeed:

1. the Product Core scan summary is `COMPLETED`;
2. finding summaries are fully traversed in authoritative pages of 200 with a
   frozen total, exact offsets, no short page, overrun, or duplicate ID;
3. one verified S4 `SourcePublishedReport` is loaded;
4. finding IDs correlate one-to-one, with exact authority, category, subject,
   and primary location;
5. authority-specific message and rule metadata pass a strict allowlist.

The exporter never merges Semgrep SARIF, Gitleaks JSON, Checkov JSON, or other
native scanner output. Rules are authority-qualified; results are sorted by
canonical finding ID and carry `securescanFindingId/v1` as the partial
fingerprint. SecureScan priority alone determines SARIF level. Native severity
is metadata, not a cross-authority level.

Gitleaks output uses a fixed rule-based message and never includes a match,
secret, snippet, context, raw scanner record, or code flow. CWE values are
emitted only from exact sanitized Semgrep evidence. OSV aliases and fixed
versions are labelled metadata and do not create duplicate results or fixes.
Repository paths are relative, POSIX, and URI encoded; absolute host paths and
managed workspace paths are rejected. Package-only findings receive no fake
location.

The exporter omits tool version because a frozen run has no authoritative
SecureScan release-version field. It also omits generated timestamps, help
links, taxa, fixes, code flows, stacks, attachments, snippets, replacements,
and baseline state. The same unchanged run produces byte-identical UTF-8 bytes.

For file output, the parent must already exist and no parent component or target
may be a symlink. Directories and special files are rejected. Existing regular
files require `--overwrite`. Complete bytes are written to a same-directory,
mode-0600 temporary file, flushed, synced, and atomically installed; an export
failure never leaves a partial SARIF result. `--output -` emits SARIF JSON only.

## GitHub Actions example

[`examples/github-actions/securescan.yml`](../examples/github-actions/securescan.yml)
is documentation, not an active workflow. V1.1 does not install Docker,
PostgreSQL, Enry, Gitleaks, Syft, Checkov, or the immutable Semgrep image. The
example therefore requires an ephemeral, pre-provisioned runner with the frozen
toolchain and repository variables containing trusted absolute tool paths and
the independently trusted Enry digest. `securescan doctor` is the final
preflight authority.

The scan job has only `contents: read`. It creates per-run database and HMAC
secrets without printing them, writes a private profile below `RUNNER_TEMP`,
uses a run-scoped Compose project and deployment root, stores SARIF below
`RUNNER_TEMP`, and always calls `securescan system down`. It does not cache
credentials, databases, scanner results, or runtime state.

The separate upload job does not check out or execute repository code. It alone
has `security-events: write`, downloads only the generated SARIF artifact, and
publishes it with GitHub's official upload action. Fork pull requests still run
the read-only scan job only when the chosen runner policy allows that untrusted
input; the privileged upload job is skipped because GitHub does not grant its
write permission to that trust boundary. Never convert this design to
`pull_request_target` execution of pull-request code. Persistent self-hosted
runners should not be exposed to untrusted public pull requests.

All actions were checked against their official GitHub repositories on
2026-09-26 and are pinned to immutable commit SHAs with the corresponding
release version in comments. No floating branch or major tag is used.

GitHub Code Scanning is a presentation and integration sink. SecureScan
canonical findings remain authoritative; GitHub dismissal state never flows
back into SecureScan lifecycle.
