# Source v0.8 S6B Scanner Execution and Safe Native Results

## Scope

S6B connects runnable Semgrep, Gitleaks, Syft, and Checkov nodes from the frozen
S6A planning snapshot to existing durable `Job` and `ToolExecution` records. OSV
remains dependency-gated for S6C. S6B does not schedule general retries, assemble
S4 evidence, or publish `AnalysisRun.report_json`.

## Freeze status

This checkpoint is implemented and pending hostile freeze review. The durable
Job/attempt/result services, attempt-bound execution adapters, containment helpers,
and safe native-result adapters are implemented. A controlled Syft execution proves
the local bridge path, and a controlled Semgrep execution proves the frozen adapter,
attempt-bound Docker lifecycle, sanitized native result, and atomic acceptance path.
The tests do not present injected envelopes alone as end-to-end scanner evidence.

## Node, Job, and context binding

Each local node has one deterministic Job identity and one durable mapping that
binds run, node, authority, capability, analyzer, trusted contract, canonical
`SourceExecutionContext`, and scanner-specific projection. Job creation reloads
the canonical S6A snapshot, reconstructs selected file metadata from that snapshot,
and proves the supplied prepared workspace against it. No request field selects an
executable, scanner version, rule/configuration, or endpoint.

The context bytes are stored and read back through the content-addressed artifact
store. Projection identity is deterministic per node. A result is never accepted
unless the projection can be reopened with the exact context and content digests
and its manifest still equals the frozen selected-file manifest.

## Attempts and containment

Every execution attempt binds the current Job attempt number to worker ID, lease
token, and a private random attempt token. Prior attempts and their
`ToolExecution` records remain durable. A successor attempt is forbidden unless
every earlier attempt is explicitly `CLEAN`; `ACTIVE` and
`RECONCILIATION_REQUIRED` fail closed.

The local supervisor is a small separate helper process. It owns the scanner in a
dedicated session/process group, monitors a worker-owned liveness pipe, acts as a
Linux child subreaper, uses parent-death signaling and pidfd observation where
available, and performs bounded TERM, KILL, descendant reap, and process-group
absence checks. It writes a canonical 0600 cleanup receipt into a private 0700
directory. The receipt binds Job, attempt number/token, supervisor PID/start
identity, scanner PID/process-group/start identity, and cleanup outcome.

A fresh service reads only the exact receipt filename using directory-relative,
no-follow file descriptors and stable pre/open/post stat identities. A valid clean
receipt may recover the supervisor handshake after a worker crash. Missing,
unstable, mismatched, or unparseable evidence becomes
`RECONCILIATION_REQUIRED`; unknown state never authorizes retry.

`AttemptBoundProcessExecutor` is the process-executor adapter supplied to the
frozen Gitleaks, Syft, and Checkov bridges. Frozen runtime/version probes remain
unchanged and are each placed under an isolated supervisor identity. Only the
exact scanner request declared before bridge execution may bind the durable S6B
attempt and write its cleanup receipt. A worker death during a probe leaves the
durable attempt `ACTIVE`; it cannot be mistaken for a clean completed scan.

Semgrep retains its frozen Docker executor and adapter behavior. S6B supplies a
deterministic attempt-bound container name, requires the trusted binding to match
the Docker request, and records a Docker-specific cleanup receipt only after the
frozen handle has confirmed container removal. Fresh reconciliation inspects the
exact deterministic name and server-owned labels, removes only a matching
container, proves name absence, and then records clean containment. A foreign or
ambiguous container identity fails closed and is not removed. Semgrep never uses a
fabricated local-process identity or process receipt.

## Safe native results

S6B defines one canonical wrapper schema,
`securescan-source-native-result-s6b-v1`, for the frozen native boundaries:

- Semgrep's sanitized native report;
- Gitleaks's normalized parser result, with raw stdout/stderr and secret-derived
  material excluded;
- Syft's canonical package observations; and
- Checkov's canonical observations, findings, suppressions, gaps, framework
  outcomes, and passed observations.

The wrapper binds authority, node, Job, attempt, scanner/analyzer/binding,
context/projection, repository/profile/plan, native schema, exact canonical bytes,
SHA-256, and size. Gitleaks, Syft, and Checkov execution envelopes pass through
their frozen parsers; only the resulting safe canonical representation is eligible
for persistence. Raw process envelopes are never durable evidence.

## Atomic acceptance and cancellation

Acceptance writes and reads back the canonical artifact before entering the
database transaction. The transaction locks the S6A parent, node, Job mapping,
Job, and current attempt; revalidates every identity, active lease, clean receipt,
and scanner contract; inserts exactly one `ToolExecution`; selects the accepted
attempt; and advances only that node and Job. An exact duplicate is idempotent; a
different artifact, stale attempt, cross-node/run material, expired lease, or
post-cancellation result is rejected.

The S6A parent row remains the cancellation ordering authority. If cancellation
locks and commits first, acceptance fails. If acceptance commits first, that native
result remains durable. No timestamp comparison decides the winner. Scanner Jobs
never write the final `report_json`.

## Lease recovery and exclusions

Generic lease recovery excludes S6B scanner Jobs. The S6B reconciler quarantines
expired active attempts without scheduling a replacement. S6C will own dependency
evaluation and global retry/cancellation policy. S6B adds no network behavior,
does not invoke OSV, changes no frozen scanner command/resource bound, and makes no
claim of kernel-enforced network isolation for trusted local scanners.
