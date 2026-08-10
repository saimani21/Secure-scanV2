# Step 1 Status: Execution and Evidence Kernel

## Completed

- Core Pydantic domain models
- Explicit run and tool-execution outcome enums
- Tool adapter interface
- Fake scanner and controlled failure modes
- Bounded local-process executor with `shell=False`
- Timeout termination
- Output-size termination
- Native-output sanitization before persistence
- Content-addressed artifact store with SHA-256 verification
- Minimal FastAPI and Typer interfaces
- SQLite developer mode and PostgreSQL-ready SQLAlchemy tables
- SecureScan report and tool-manifest JSON Schemas
- Architecture Decision Records

## Verified behavior

| Scenario | Expected result | Verified |
|---|---|---|
| Tool returns one observation | `SUCCEEDED_WITH_OBSERVATIONS` | Yes |
| Tool returns no observations | `SUCCEEDED_NO_OBSERVATIONS` | Yes |
| Tool returns warning | `SUCCEEDED_WITH_WARNINGS` | Yes |
| Tool exits non-zero with valid report | Valid observations retained | Yes |
| Tool exceeds timeout | `TIMEOUT`, overall partial | Yes |
| Tool emits malformed JSON | `INVALID_OUTPUT`, overall partial | Yes |
| Tool emits wrong schema | `INVALID_OUTPUT`, overall partial | Yes |
| Tool floods output | `OUTPUT_LIMIT_EXCEEDED` | Yes |
| Tool emits test secrets | Redacted before persistence | Yes |
| Artifact modified after storage | Digest mismatch detected | Yes |

## Test result

`13 passed`

## Deliberately deferred to Step 2

- Durable job queue
- PostgreSQL worker leasing
- Retry policy
- Cancellation
- Worker heartbeat and lease expiry
- Crash recovery
- Durable persistence of full reports and observations
- Docker executor

No real security scanner should be integrated before Step 2 passes its own recovery and isolation gates.
