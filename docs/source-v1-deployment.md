# SecureScan Source v1 single-node deployment

## Boundary

The D1 deployment runs PostgreSQL, a one-shot Alembic migration, and the
FastAPI application under Docker Compose. The continuous Source worker and the
local submission CLI run directly on the trusted scanning host.

The worker is intentionally not a Compose service. Production Semgrep retains
its frozen Docker sandbox, so a containerized worker would require Docker socket
authority (or nested Docker) and would make projection bind paths cross host and
container namespaces. D1 adds neither `/var/run/docker.sock` nor Docker-in-Docker
and does not alter any frozen scanner contract.

The resulting single-node boundary is:

```text
localhost API -> FastAPI container -> PostgreSQL container
host CLI ---------------------------> PostgreSQL container
host worker -> frozen scanners -----> PostgreSQL container
       |                 |
       +---- shared CAS and managed Source directories ----+
```

The `/v1/scans` submission API continues to accept only server-owned trusted
target identities. It does not accept a host path. Local filesystem submission
is the trusted-host `securescan scan` operation.

## Configure the deployment

Create a local environment file, replace both empty secret values, and replace
the `replace-me` password in the materialized host database URL:

```bash
cd ~/projects/securescan-core-step1
cp .env.example .env
# Edit .env, then import its data without executing it as shell code.
./.venv/bin/securescan system configure --from-env-file .env
./.venv/bin/securescan doctor
```

Set `SECURESCAN_POSTGRES_PASSWORD` to a strong URL-unreserved value and set
`SECURESCAN_HMAC_KEY` to an independent random value. For example, locally
generate two different 32-byte hex values with `openssl rand -hex 32`; do not
print them in logs or commit `.env`. The same HMAC key must be supplied to the
API and host worker.

The import writes `~/.config/securescan/operator.json` (or
`$XDG_CONFIG_HOME/securescan/operator.json`) as a mode `0600` JSON file inside
a mode `0700` directory. It never sources the input. Operator commands ignore
arbitrary current-directory `.env` files. Their runtime precedence is process
environment, the private operator profile, then safe defaults. The explicit
`system configure --from-env-file` import is the only operator path that reads
an env file. Legacy v1 application commands retain their existing cwd `.env`
compatibility.

Set `SECURESCAN_RUNTIME_UID` and `SECURESCAN_RUNTIME_GID` to the nonzero numeric
identity that will run the host worker (normally the output of `id -u` and
`id -g`). The image build rejects a root UID or GID. Use an absolute
`SECURESCAN_DEPLOY_DATA_ROOT` for an installation intended to survive checkout
moves. Keep the four host runtime roots at the standard child paths shown in
`.env.example`; this lets the host worker and containerized API share the same
artifacts and managed Source state.

`system up` initializes storage as the configured non-root runtime identity:

```bash
./.venv/bin/securescan system up
```

The command creates the deployment root and its artifact, workspace, projection,
and runtime-receipt children with private permissions. It creates the projection
ownership descriptor through the same production projection service that
validates it, and re-running it is idempotent. Explicit initialization may mark
an existing projection root only when it is empty, private, not a symlink, and
owned by the configured runtime identity. A populated unmarked directory,
malformed or contradictory descriptor, unsafe path, wrong owner, or wrong
permissions is rejected without repair.

For lower-level diagnosis or administrator recovery, storage initialization can
still be run independently with:

```bash
./.venv/bin/securescan init
```

Normal operation should use `securescan system up`, which invokes this same
trusted storage boundary before starting any service.

The bind mount uses `create_host_path: false`, so Compose fails rather than
silently creating a root-owned deployment directory. The image's default user is
also non-root; its UID and GID are build arguments supplied by Compose. This
preserves write access without a root API process, a privileged container, broad
permissions, or automatic `chown` of an arbitrary host path.

The projection root is descriptor-protected. Do not delete or reconstruct
`.securescan-source-projection-root`, and do not delete only the contents of a
managed runtime root. If `securescan init` refuses an existing location, preserve
it for diagnosis and select a new empty deployment root or deliberately correct
the reported host ownership or permission problem.

### Existing PostgreSQL volume

`POSTGRES_PASSWORD` initializes a new PostgreSQL data directory; changing the
variable does not rotate a role password already stored in `securescan_pg`. An
existing volume created by the earlier development Compose configuration must be
handled explicitly. Preserve its data by rotating the existing role through the
container's local PostgreSQL administration boundary:

```bash
docker compose exec --user postgres postgres \
  psql --dbname postgres --username "${SECURESCAN_POSTGRES_USER:-securescan}" \
  --command "\\password ${SECURESCAN_POSTGRES_USER:-securescan}"
```

Enter the same new password configured as `SECURESCAN_POSTGRES_PASSWORD`; `psql`
prompts without echoing it. This command assumes the database and role names were
not also changed. If they changed, perform an explicit database migration rather
than treating environment variables as a rename mechanism. Deleting
`securescan_pg` is destructive and is not part of the normal D1 upgrade or
shutdown procedure.

Database URLs are not assembled by SecureScan from other `.env` entries. The
Compose services receive an explicit internal URL whose hostname is `postgres`.
The host CLI and worker require a separately materialized URL using the published
localhost port. The password is embedded in the Compose URL, so the deployment
password must contain only URL-unreserved characters (`A-Z`, `a-z`, `0-9`, `.`,
`_`, `~`, `-`).

## Start and inspect the complete service

After the private profile is configured and `doctor` has no blocking failures:

```bash
./.venv/bin/securescan system up
./.venv/bin/securescan system status
./.venv/bin/securescan open
```

The manager enforces `storage -> postgres healthy -> migration success ->
API /health/ready -> one verified host worker`. Repeated `system up` is
idempotent and does not start another worker. The API sets
`SECURESCAN_ALLOW_SQLITE_SCHEMA_BOOTSTRAP=false`; Alembic is
the only deployment migration authority. The readiness response reports database
reachability and whether the schema is at the migration head, without returning
credentials or the database URL.

## Open the Source analysis console

The FastAPI service serves the D2 same-origin console and its local assets; no
separate frontend service or Node build is required. Open:

```text
http://127.0.0.1:<SECURESCAN_API_PORT>/
```

Create or select a durable project, then submit a repository from the trusted
SecureScan host, not from the browser:

```bash
./.venv/bin/securescan project create "My project"
./.venv/bin/securescan project list
./.venv/bin/securescan scan /absolute/repository/path --project-id <project-uuid>
```

Paste the returned run ID into the console to inspect Product Core status,
findings, published evidence, dependency intelligence, and explicit coverage
gaps. The console is read-only and does not accept filesystem paths, source
uploads, or remote Git locations.

Compose publishes PostgreSQL and the API on `127.0.0.1` only. PostgreSQL data is
stored in the `securescan_pg` named volume. CAS objects, managed workspaces,
projections, and runtime receipts are stored below the host deployment root and
mounted at `/var/lib/securescan` for the API. Durable database records retain
opaque workspace and relative content-addressed references rather than a
container-only root path.

## Managed trusted-host worker

`system up` launches the existing worker on the trusted scanning host; it does
not move scanners into Compose and does not require a second terminal. The
database URL in the imported profile remains fully materialized because
SQLAlchemy does not expand `${...}` references.

Managed state is under `<SECURESCAN_DEPLOY_DATA_ROOT>/operator/`: the lifecycle
lock, private worker identity, and `worker.log`. The identity binds PID, Linux
process start time, executable, exact command, and a non-secret deployment
marker read from the live process's bounded `/proc/<pid>/environ` data.
`system down` re-verifies all of them before SIGTERM and again before any
SIGKILL. A missing, malformed, or mismatched marker produces
`STALE_WORKER_STATE` and no new signal. Diagnose the live PID and log without
deleting state; only after independently confirming that no managed worker is
alive should the exact stale identity file be archived for recovery.

The worker reports storage-bootstrap and database-connection failures with a
safe reason code, phase, and remediation. For automation,
`securescan worker --json` emits the same error fields as canonical JSON. Run
`securescan init` with the identical loaded configuration for a storage failure;
do not repair descriptor files by hand.

The frozen host tool identities remain:

- Enry helper 0.2.3 with go-enry v2.9.6; its locally built executable is accepted
  only with the independently trusted digest configured above.
- Gitleaks 8.30.1, executable SHA-256
  `88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509`.
- Syft 1.51.0, executable SHA-256
  `5a8b71e94f4607973145f02e27e01d50b9f7c7bc41e38d40b39606ad138b43b5`.
- Checkov 3.3.16 using the existing hash-locked CPython 3.12.3 toolchain;
  toolchain digest
  `a8e451a6ed27fcf1ab0e639b5effbe4bb6e38ef8378058f95f51d7b5f99eefea`.
- Docker available to the host worker for the immutable Semgrep image
  `semgrep/semgrep@sha256:bdf7013b2c3634a487671158da77c554f531742326b543a9464d2adf6c433ac8`.

Use the existing frozen setup and verification mechanisms for these tools. The
API image deliberately contains none of them and does not require Enry to start
or accept an existing trusted target.

After migrations and the host toolchain are ready, the supported local workflow
does not require direct database access:

```bash
./.venv/bin/securescan project create "My project"
./.venv/bin/securescan project list
./.venv/bin/securescan scan /absolute/repository/path --project-id <project-uuid>
./.venv/bin/securescan status <run-id>
./.venv/bin/securescan findings <run-id>
./.venv/bin/securescan report <run-id>
```

The same-origin console provides the bounded component, dependency, coverage,
and gap views backed by the public `/v1/scans/{run_id}` read endpoints. A
dependency row reports OSV evaluation status explicitly; its known-vulnerability
count is unknown rather than zero when advisory evaluation was partial, failed,
or not applicable.

## Status, diagnosis, and shutdown

`system status` reports `READY`, `DEGRADED`, `STOPPED`, or `ERROR` from the
separate database, API readiness/schema, and worker states. `doctor` is
read-only: `PASS` and `WARN` do not block its exit, while any `FAIL` returns a
nonzero exit. Docker/Compose details remain available in their own logs, and
host-worker output is in the private operator log.

Stop the managed worker and this installation's deterministic Compose project
without destroying PostgreSQL state:

```bash
./.venv/bin/securescan system down
```

The command never adds `-v`. Removing the named volume is a separate,
destructive database operation. The deployment bind directory is also durable
state and must be backed up and protected consistently with PostgreSQL.

For a disposable local acceptance deployment only, first stop its worker, then
use its explicit Compose project name to stop the containers. Inspect the exact
named volume before removing it, and move the exact dedicated deployment root to
a backup location so filesystem state remains recoverable:

```bash
docker compose --project-name securescan-acceptance down
docker volume inspect securescan-acceptance_securescan_pg
docker volume rm securescan-acceptance_securescan_pg
mv -- /absolute/dedicated/securescan-acceptance-root \
  /absolute/backup/securescan-acceptance-root.saved
```

Substitute only names and absolute paths verified for that disposable project.
Never delete individual marker files or children from a runtime root, never use
a broad or unresolved path, and never reset a shared deployment.
