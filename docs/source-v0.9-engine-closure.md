# Source v0.9 Engine Closure

Engine Closure completes S6C-B, S6C-C, and S6D without changing the frozen
Semgrep, Gitleaks, Syft, OSV, Checkov, or S4 contracts. The implementation is
uncommitted and remains pending hostile Engine Closure approval.

## Durable execution graph

The coordinator is a short-lived database state machine. Repeated or concurrent
advances create at most one deterministic Job for each initially runnable local
node. An accepted Syft result is evaluated through the frozen S6C-A contract;
only `OSV_RUN_REQUIRED` can create the single OSV Job. Zero packages and other
not-applicable dependency decisions make no network request. Permanent Syft
failure terminalizes OSV as `BLOCKED_BY_DEPENDENCY`; uncertain containment keeps
the dependency unresolved.

The dedicated Source worker leases only Jobs with a Source orchestration mapping,
under the parent ordering boundary, and dispatches the exact five-authority
roster. The production composition root binds Semgrep to the frozen attempt-bound
Docker adapter, Gitleaks/Syft/Checkov to `SourceLocalBridgeExecutionService`, and
OSV to `SourceOsvHelperExecutionService`. Handlers receive the Job and attempt
already owned by the worker; they do not create Jobs, fabricate native results or
cleanup receipts, use `JobResultCommitService`, or publish a report.

Each orchestration durably records a server-owned `max_active_jobs` limit. Source
v1 defaults to **2** through the server-owned `SourceOrchestrationService`
configuration, configurable only within the frozen range 1 through 4 when the
orchestration is created. Leasing holds the parent row lock and counts leased,
running, and reconciliation-required attempts, so concurrent workers, retries,
and uncertain containment cannot exceed or evade the same per-run ceiling.
Cancellation and the parent deadline are checked inside that leasing transaction.

One bounded characterization run used the four existing controlled bridge
workloads (fake-Docker Semgrep and frozen local Gitleaks, Syft, and Checkov paths).
The `/proc` measurements are approximate observations, not benchmark evidence:

| Concurrency | Wall time | Peak descendants | Approx. peak aggregate RSS | Approx. CPU (one-core basis) | Failures |
|---:|---:|---:|---:|---:|---:|
| 1 | 20.652 s | 10 | 493,360 KiB | 28.2% | 0 |
| 2 | 17.444 s | 10 | 532,684 KiB | 68.1% | 0 |
| 3 | 14.744 s | 13 | 706,656 KiB | 140.3% | 0 |
| 4 | 10.388 s | 15 | 1,091,804 KiB | 142.8% | 0 |

The sample did not exercise cancellation, and it cannot establish stable host-wide
CPU/RSS guarantees. Separate controlled cancellation gates retain the 3.0-second
stop SLA. The pronounced memory increase at four concurrent workloads supports
the conservative default of two for the minimum supported Linux/WSL profile.
Local scanners retain the S6B bridge/supervisor or Docker path. OSV runs in a
separate attempt-bound helper process through the same S6B process-group,
cleanup-receipt, and reconciliation machinery.

## OSV request authorization

A committed request permit is the authorization and database linearization point
for one network operation. It is not proof that an HTTP socket operation physically
began. The helper requests a fresh permit before every query batch, pagination
query, frozen S2 transport retry, and advisory fetch. Permit rows contain only
attempt identity, sequence, operation kind, a logical-request digest, transport
attempt number, helper identity, and authorization time; no request/response body,
header, credential, or repository content is persisted.

The application-layer destination remains exactly `https://api.osv.dev:443` and
the frozen `/v1/querybatch` and `/v1/vulns/{id}` endpoint families. The client
does not trust proxy environment configuration, credentials, cookies, or redirects.
This is not a claim of kernel-level egress enforcement.

Parent cancellation or deadline obtains the parent lock before denying a later
permit. If a permit commits first, that one operation is authorized, but the
worker can immediately terminate the active helper and no subsequent operation
can receive a permit. The controlled termination SLA is 3.0 seconds, using TERM,
bounded grace, KILL if required, reap, process-tree absence verification, and a
durable cleanup receipt. Unknown cleanup becomes `RECONCILIATION_REQUIRED` and
cannot authorize a replacement attempt.

Job-level retries are capped at three attempts. A replacement is eligible only
after every earlier attempt is terminal, rejected, and durably `CLEAN`; its delay
is derived from the last durable completion (5 seconds after attempt one and 30
seconds after attempt two). Cancellation, deadline, integrity failures, permanent
HTTP failures, invalid schema, pagination failure, and unknown containment are not
retryable. Frozen S2 retries remain inside one Job attempt and each transport
invocation receives its own permit.

## Accepted evidence and assembly

The OSV native result is a canonical sanitized artifact bound to the run, node,
Job, attempt, frozen service contract, planning digests, S6C-A evaluation, exact
selected Syft result, node scope, candidate IDs, and frozen
`OsvDependencyAnalysis`. Raw HTTP bodies are never durable evidence. A completed
non-empty candidate set with zero advisories is successful complete coverage with
zero dependency findings; it is not `NOT_APPLICABLE`. Mixed-scope, unsupported-
coordinate, and partial-Syft gaps remain coverage limitations after OSV succeeds.

Assembly begins only from `ASSEMBLY_READY`, after every node is explicitly
terminal and every attempt is clean. It reads the canonical planning snapshot,
exact durable node identities, accepted selected CAS results, dependency evaluation,
and terminal failure state. Authority mapping remains frozen:

- Semgrep to `CODE_SECURITY`
- Gitleaks to `SECRET_EXPOSURE`
- Syft to package components and inventory evidence only
- OSV to `DEPENDENCY_VULNERABILITY`
- Checkov to `CONFIGURATION_SECURITY`

Only the frozen Syft-to-OSV supporting relationship is permitted. Scanner failure,
timeout, cancellation, output limit, and dependency blocking produce explicit
failed/partial coverage and gaps rather than clean absence.

Publication is two-stage and restartable: canonical S4 bytes are written and read
back from CAS, assembly metadata moves the parent to `COMMITTING`, and a parent-row
locked transaction writes `AnalysisRun.report_json` once before terminalizing the
orchestration. Exact duplicate publication is idempotent and conflicting evidence
fails closed. An explicitly cancelled orchestration never assembles or publishes;
accepted child evidence remains internal and auditable.

Engine Closure does not add reachability, exploitability, semantic cross-engine
deduplication, prioritization, finding history, API presentation changes, or a
maturity promotion.
