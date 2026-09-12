# Source v1 release acceptance

## Boundary

RA1 is a reproducible manual acceptance procedure for the already-built Source v1
product. It does not add scanner, orchestration, evidence, Product Core, API, worker,
deployment, or frontend behavior. The committed fixture contract and helper prepare four
local repository states and validate canonical public CLI observations plus four
sanitized, read-only Product Core lifecycle-event observations. The helper does not
execute SecureScan, scanners, network requests, or database operations.

RA1 preparation and unit tests are not release-acceptance evidence. A PASS summary may
be recorded only after the commands below complete against a clean release-candidate
checkout and the configured D1 deployment. Real run observations remain external until
the strict validator records their sanitized summary; they are never fabricated by this
repository tooling.

## Prerequisites

Use the frozen D1 single-node deployment, host worker toolchain, and configuration in
[`source-v1-deployment.md`](source-v1-deployment.md). PostgreSQL, Alembic, API readiness,
the shared CAS roots, and every pinned scanner must already pass their existing checks.
Use a fresh dedicated project UUID and the fresh lineage returned by Run A. Every rerun
must use another fresh project and lineage; never try to recover sequence numbers 1-4 in
an existing acceptance lineage. Do not print the database URL, password, HMAC key, or
scanner output.

Before release acceptance, require a clean checkout and verify the fixture contract:

```bash
cd ~/projects/securescan-core-step1
test -z "$(git status --short)"
./.venv/bin/python scripts/source_v1_acceptance.py verify
curl --fail --silent --show-error \
  "http://127.0.0.1:${SECURESCAN_API_PORT:-8000}/health/ready"
echo
```

The fixture contract reuses the existing controlled Gitleaks case
`github-pat-positive-01`. Frozen Gitleaks 8.30.1 observes the project-owned synthetic,
non-live value at line 3 as rule `github-pat` with detection kind `CONTENT`. Its source
bytes, corpus case, corpus manifest, corpus plan, observed F3B `TP`, and unchanged
production configuration are SHA-256 bound by `manifest-v1.json`. State C uses the
existing low-entropy negative counterpart. No new token shape or scanner claim was
guessed for RA1.

The earlier external all-features fixture produced no Gitleaks finding and had no
committed rule-bound fixture contract. Its exact bytes are not available here, so RA1
does not invent a retrospective regex, entropy, or allowlist explanation. The actionable
defect was an unverified fixture expectation; RA1 replaces it with an already frozen,
observed positive relation.

## Prepare the four repository states

Create a fresh temporary root. The helper refuses an existing destination and copies only
SHA-verified repository fixtures:

```bash
export PROJECT_ID='<existing-project-uuid>'
export ACCEPTANCE_ROOT
ACCEPTANCE_ROOT="$(mktemp -d /tmp/securescan-source-v1-ra1.XXXXXX)"
export FIXTURES="$ACCEPTANCE_ROOT/fixtures"
export OBSERVATIONS="$ACCEPTANCE_ROOT/observations"
mkdir -m 0700 "$OBSERVATIONS"
./.venv/bin/python scripts/source_v1_acceptance.py prepare "$FIXTURES"

require_sequence() {
  ./.venv/bin/python -c \
    'import json,sys; actual=json.load(open(sys.argv[1], encoding="utf-8"))["submission_sequence"]; expected=int(sys.argv[2]); raise SystemExit(0 if actual == expected else 1)' \
    "$1" "$2"
}
```

`require_sequence` runs immediately after each submission response. A mismatch means the
submission has already reserved an unexpected sequence: stop the attempt, submit no later
state, preserve the durable run, and restart RA1 with a fresh project and lineage. A
post-submission check cannot prevent that reservation; it only prevents compounding it.
Do not use a cached or shell-global `LAST_RUN_ID`. Submission-response files enforce this
operational stop rule but are not inputs to the final summary; durable lifecycle events
authoritatively bind the selected run IDs and sequences for replay.

Every state contains the same Semgrep, Syft/OSV, and Checkov inputs. A, B, and D contain
the exact same selected Gitleaks bytes at `config/release-sentinel.txt`; C alone replaces
that file with its frozen negative counterpart:

| State | Directory | Selected relation | Expected lifecycle |
|---|---|---|---|
| A | `state-a-vulnerable-initial` | present | `NEW` |
| B | `state-b-vulnerable-unchanged` | present, byte-identical to A | `EXISTING` |
| C | `state-c-remediated` | absent; other authority inputs unchanged | `RESOLVED` |
| D | `state-d-vulnerable-reintroduced` | restored byte-for-byte | `REOPENED` |

## Run the worker

In a second trusted-host terminal, export the same D1 host-worker environment and run:

```bash
cd ~/projects/securescan-core-step1
./.venv/bin/securescan worker
```

Keep that worker running while submitting A through D. Stop it once with `Ctrl+C` after
all observations are collected. Do not run scanner executables directly.

## Submit and observe A through D

Run the following in the first terminal. Each `scan` call uses the same project and,
after A, the same lineage. A 7,200-second parent deadline remains finite while allowing
the pinned tools to complete.

```bash
cd ~/projects/securescan-core-step1

./.venv/bin/securescan scan \
  "$FIXTURES/state-a-vulnerable-initial" \
  --project-id "$PROJECT_ID" --deadline-seconds 7200 --json \
  > "$OBSERVATIONS/a-submission.json"
require_sequence "$OBSERVATIONS/a-submission.json" 1

export RUN_A LINEAGE_ID
RUN_A="$(./.venv/bin/python -c \
  'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["run_id"])' \
  "$OBSERVATIONS/a-submission.json")"
LINEAGE_ID="$(./.venv/bin/python -c \
  'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["lineage_id"])' \
  "$OBSERVATIONS/a-submission.json")"
```

Poll `./.venv/bin/securescan status "$RUN_A" --json` until it reports `COMPLETED`.
Then record A:

```bash
./.venv/bin/securescan status "$RUN_A" --json > "$OBSERVATIONS/a-status.json"
./.venv/bin/securescan report "$RUN_A" --json > "$OBSERVATIONS/a-report.json"
```

Submit B, extract its run ID, wait for `COMPLETED`, and record it:

```bash
./.venv/bin/securescan scan \
  "$FIXTURES/state-b-vulnerable-unchanged" \
  --project-id "$PROJECT_ID" --lineage-id "$LINEAGE_ID" \
  --deadline-seconds 7200 --json > "$OBSERVATIONS/b-submission.json"
require_sequence "$OBSERVATIONS/b-submission.json" 2
export RUN_B
RUN_B="$(./.venv/bin/python -c \
  'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["run_id"])' \
  "$OBSERVATIONS/b-submission.json")"
./.venv/bin/securescan status "$RUN_B" --json
# Repeat the status command until COMPLETED, then:
./.venv/bin/securescan status "$RUN_B" --json > "$OBSERVATIONS/b-status.json"
./.venv/bin/securescan report "$RUN_B" --json > "$OBSERVATIONS/b-report.json"
```

Submit C and wait for `COMPLETED`. The selected relation must be absent from C's current
S4 report. Its `RESOLVED` transition is captured separately from the durable lifecycle
event; it is never inferred from a current-run findings page:

```bash
./.venv/bin/securescan scan \
  "$FIXTURES/state-c-remediated" \
  --project-id "$PROJECT_ID" --lineage-id "$LINEAGE_ID" \
  --deadline-seconds 7200 --json > "$OBSERVATIONS/c-submission.json"
require_sequence "$OBSERVATIONS/c-submission.json" 3
export RUN_C
RUN_C="$(./.venv/bin/python -c \
  'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["run_id"])' \
  "$OBSERVATIONS/c-submission.json")"
./.venv/bin/securescan status "$RUN_C" --json
# Repeat the status command until COMPLETED, then:
./.venv/bin/securescan status "$RUN_C" --json > "$OBSERVATIONS/c-status.json"
./.venv/bin/securescan report "$RUN_C" --json > "$OBSERVATIONS/c-report.json"
```

Finally submit D, wait for `COMPLETED`, and record it:

```bash
./.venv/bin/securescan scan \
  "$FIXTURES/state-d-vulnerable-reintroduced" \
  --project-id "$PROJECT_ID" --lineage-id "$LINEAGE_ID" \
  --deadline-seconds 7200 --json > "$OBSERVATIONS/d-submission.json"
require_sequence "$OBSERVATIONS/d-submission.json" 4
export RUN_D
RUN_D="$(./.venv/bin/python -c \
  'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["run_id"])' \
  "$OBSERVATIONS/d-submission.json")"
./.venv/bin/securescan status "$RUN_D" --json
# Repeat the status command until COMPLETED, then:
./.venv/bin/securescan status "$RUN_D" --json > "$OBSERVATIONS/d-status.json"
./.venv/bin/securescan report "$RUN_D" --json > "$OBSERVATIONS/d-report.json"
```

## Export authoritative lifecycle events read-only

Derive the selected safe canonical finding ID from Run A's published report, then export
exactly one durable Product Core transition event for each selected run. This query reads
only lifecycle, submission, and lineage identity columns. It emits no timestamps,
repository paths, finding payloads, credentials, or scanner evidence.

```bash
export SELECTED_FINDING_ID
SELECTED_FINDING_ID="$(./.venv/bin/python -c '
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))["report"]
matches = [item for item in report["findings"] if item["authority"] == "gitleaks" and item["subject"].get("rule_id") == "github-pat" and any(location.get("path") == "config/release-sentinel.txt" and location.get("start_line") == 3 for location in item["locations"])]
if len(matches) != 1:
    raise SystemExit("expected exactly one selected Gitleaks finding")
print(matches[0]["finding_id"])
' "$OBSERVATIONS/a-report.json")"

capture_lifecycle_event() {
  label="$1"
  run_id="$2"
  case "$label" in a|b|c|d) ;; *) return 1 ;; esac
  ./.venv/bin/python -c '
import re, sys, uuid
valid = str(uuid.UUID(sys.argv[1])) == sys.argv[1]
valid = valid and str(uuid.UUID(sys.argv[2])) == sys.argv[2]
valid = valid and re.fullmatch(r"[0-9a-f]{64}", sys.argv[3]) is not None
raise SystemExit(0 if valid else 1)
' "$LINEAGE_ID" "$run_id" "$SELECTED_FINDING_ID"
  docker compose exec -T --user postgres postgres psql \
    --username "${SECURESCAN_POSTGRES_USER:-securescan}" \
    --dbname "${SECURESCAN_POSTGRES_DB:-securescan}" \
    --no-align --tuples-only --quiet --set ON_ERROR_STOP=1 \
    --command="COPY (
      SELECT jsonb_build_object(
        'schema_version', 'securescan-source-v1-ra1-lifecycle-event-v1',
        'project_id', l.project_id,
        'lineage_id', e.lineage_id,
        'run_id', e.run_id,
        'submission_sequence', s.submission_sequence_number,
        'finding_id', e.finding_id,
        'event_kind', e.event_kind,
        'previous_state', e.previous_state,
        'resulting_state', e.resulting_state,
        'reason_codes', e.reason_codes_json,
        'transition_version', e.transition_version
      )::text
      FROM source_finding_lifecycle_events AS e
      JOIN source_scan_submissions AS s
        ON s.run_id = e.run_id AND s.lineage_id = e.lineage_id
      JOIN source_target_lineages AS l ON l.lineage_id = e.lineage_id
      WHERE e.lineage_id = '$LINEAGE_ID'
        AND e.run_id = '$run_id'
        AND e.finding_id = '$SELECTED_FINDING_ID'
    ) TO STDOUT" > "$OBSERVATIONS/$label-lifecycle-event.json"
  test "$(wc -l < "$OBSERVATIONS/$label-lifecycle-event.json")" -eq 1
}

capture_lifecycle_event a "$RUN_A"
capture_lifecycle_event b "$RUN_B"
capture_lifecycle_event c "$RUN_C"
capture_lifecycle_event d "$RUN_D"
```

The validator requires transition versions 1-4 and the exact reason sequence
`FIRST_OBSERVATION`, `OBSERVED_AGAIN`, `COMPARABLE_SCOPE_ABSENCE`, and
`RETURNED_AFTER_RESOLUTION`. Extra later runs in the lineage are neither queried nor
included in the selected A-D artifact.

## Validate and record the sanitized summary

The summary validator requires four unique ordered run IDs in one lineage, `COMPLETED`
status, publication and finalization, complete coverage, matching status/report coverage
counts, identical planned authority scopes, the five expected authority evidence roles,
one stable selected finding ID, and the exact durable lifecycle-event sequence and reason
codes. Run C must omit the target from its report while its sole Gitleaks coverage outcome
is `COMPLETE` with zero findings and gaps. It permits
`NOT_APPLICABLE` sub-scopes only when that authority also has successful applicable
coverage. It rejects failed or partial authority coverage.

```bash
export SECURESCAN_COMMIT
SECURESCAN_COMMIT="$(git rev-parse HEAD)"
./.venv/bin/python scripts/source_v1_acceptance.py summarize \
  "$OBSERVATIONS" "$ACCEPTANCE_ROOT/source-v1-acceptance-summary.json" \
  --securescan-commit "$SECURESCAN_COMMIT" --project-id "$PROJECT_ID"
```

The create-once canonical JSON summary contains only commit, fixture identity, project,
lineage and run IDs, status and safe aggregate counts, authority coverage states, the
selected canonical finding ID and lifecycle state, and explicit PASS assertions. It
contains no database or HMAC material, scanner streams, raw secrets, raw evidence, host
repository paths, or timestamps.

Confirm the same published Run A is readable through the public API. These endpoints
must return HTTP 200 and bounded, sanitized Product Core/S4 projections:

```bash
export API_ROOT="http://127.0.0.1:${SECURESCAN_API_PORT:-8000}"
curl --fail --silent --show-error "$API_ROOT/v1/scans/$RUN_A"
curl --fail --silent --show-error \
  "$API_ROOT/v1/scans/$RUN_A/findings?authority=gitleaks&limit=200&offset=0"
curl --fail --silent --show-error \
  "$API_ROOT/v1/scans/$RUN_A/components?limit=200&offset=0"
curl --fail --silent --show-error \
  "$API_ROOT/v1/scans/$RUN_A/dependencies?limit=200&offset=0"
curl --fail --silent --show-error "$API_ROOT/v1/scans/$RUN_A/coverage"
curl --fail --silent --show-error \
  "$API_ROOT/v1/scans/$RUN_A/gaps?limit=200&offset=0"
curl --fail --silent --show-error "$API_ROOT/v1/scans/$RUN_A/report"
echo
```

## Assertions and frontend smoke

Acceptance requires:

- A, B, C, and D are published and finalized as `COMPLETED`, with complete comparable
  coverage and no failed or partial expected authority.
- A contains the expected Semgrep, Gitleaks, Checkov, Syft package-component, and OSV
  dependency evidence. The same non-secret authority relations remain in B, C, and D.
- Syft remains package component/evidence and is never counted as a vulnerability finding.
- The selected Gitleaks canonical identity is `NEW`, `EXISTING`, `RESOLVED`, then
  `REOPENED`; C's current S4 report does not contain the removed finding.

After A completes, open `http://127.0.0.1:<SECURESCAN_API_PORT>/`, load `RUN_A`, and
confirm overview, findings, dependency information, coverage/gaps, and finding detail
render. Confirm the Gitleaks finding is visible and any zero or partial coverage is
represented honestly rather than as clean.

## Focused failure, restart, and cancellation gate

These existing tests are the release gate for durable restart, reconciliation, cancellation,
failed coverage, assembly visibility, and predecessor ordering. They do not execute the
RA1 fixture scans:

```bash
timeout 1200s ./.venv/bin/python -m pytest -q \
  tests/test_source_runtime_r1.py::test_fresh_runtime_instances_resume_bounded_durable_worker_queue \
  tests/test_source_runtime_r1.py::test_reconciliation_required_work_is_counted_and_not_dispatched_when_idle \
  tests/test_worker_cycle.py::test_expired_lease_during_commit_returns_lease_lost \
  tests/test_source_projection_lifecycle.py::test_restart_reconciliation_cleans_crash_after_terminal_commit \
  tests/test_source_assembly_s6d.py::test_cancelled_parent_cannot_assemble_or_publish \
  tests/test_source_assembly_s6d.py::test_failed_authority_projects_explicit_gap_not_clean \
  tests/test_source_runtime_r1.py::test_assembly_failure_is_isolated_and_visible_only_as_a_count \
  tests/test_source_runtime_r1c.py::test_continuous_cycle_failure_summary_is_visible_and_loop_continues \
  tests/test_source_product_core_pc3b.py::test_runner_keeps_successor_not_ready_when_predecessor_is_unpublished \
  tests/test_source_product_core_pc2.py::test_existing_resolved_reopened_and_existing_history
```

## PASS and cleanup

RA1 passes only when the fixture verifier, four real runs, summary validator, focused
failure gate, and manual frontend smoke all pass. An interrupted, failed, cancelled,
timed-out, partial, unpublished, unfinalized, non-comparable, or upstream-OSV-drifted run
is not acceptance evidence.

Stop the host worker with one `Ctrl+C`. Preserve PostgreSQL, the named volume, CAS,
managed workspaces, and all durable Source/Product Core records for review. Copy the
sanitized summary to the designated release-evidence location. Only then may the
temporary `$ACCEPTANCE_ROOT` fixture/observation directory be removed explicitly. Normal
RA1 cleanup never runs `docker compose down -v`, removes a Docker volume, resets the
database, or deletes durable SecureScan data.
