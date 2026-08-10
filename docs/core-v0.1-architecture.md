# Core v0.1 architecture

SecureScan is a modular monolith with explicit trust and persistence boundaries.

1. The API accepts durable job submissions and exposes job, run, execution, and report
   read models. The CLI provides local administrative and development entry points.
2. PostgreSQL stores projects, targets, analysis runs, jobs, tool-execution attempts,
   and canonical report JSON. Alembic owns schema evolution.
3. The worker leases one job using ownership and fencing tokens. Heartbeats, recovery,
   retries, cancellation, and terminal commitment use atomic service operations.
4. The immutable trusted-adapter registry maps the persisted `adapter_id` to
   application-owned configuration. Job metadata cannot select an image, command,
   ruleset, or sandbox policy.
5. The sandbox policy fixes disabled networking, a non-root identity, dropped
   capabilities, a read-only root filesystem and source mount, a writable output mount,
   and bounded resources.
6. The Docker executor uses argv arrays, requires a digest-pinned local image, passes
   `--pull never`, and removes managed containers on success and failure.
7. `RepositoryWorkspaceManager` validates a local directory, rejects links and special
   entries, applies intake bounds, and creates a deterministic read-only snapshot and
   manifest.
8. The trusted Semgrep adapter materializes the application-owned three-rule baseline
   outside the source tree, executes offline, bounds JSON input, and delegates
   normalization to the canonical parser.
9. The parser validates paths against the manifest, converts diagnostics to analysis
   gaps, deduplicates findings, and computes stable SecureScan fingerprints.
10. Result commitment atomically stores the terminal job state, one execution attempt,
    the analysis-run aggregate, and canonical report JSON. `RunQueryService` retrieves a
    defensive copy of that report.

The release evaluator reuses the workspace manager, Docker executor, ruleset, trusted
definition, Semgrep adapter, parser output, and canonical finding models. It does not
create a second scanner or production persistence path.
