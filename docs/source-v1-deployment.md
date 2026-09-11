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

Create a local environment file and replace both empty secret values:

```bash
cd ~/projects/securescan-core-step1
cp .env.example .env
# Edit .env, then make its configured values available to the commands below.
set -a
. ./.env
set +a
```

Set `SECURESCAN_POSTGRES_PASSWORD` to a strong URL-unreserved value and set
`SECURESCAN_HMAC_KEY` to an independent random value. For example, locally
generate two different 32-byte hex values with `openssl rand -hex 32`; do not
print them in logs or commit `.env`. The same HMAC key must be supplied to the
API and host worker.

Set `SECURESCAN_RUNTIME_UID` and `SECURESCAN_RUNTIME_GID` to the nonzero numeric
identity that will run the host worker (normally the output of `id -u` and
`id -g`). The image build rejects a root UID or GID. Use
an absolute `SECURESCAN_DEPLOY_DATA_ROOT` for an installation intended to survive
checkout moves. Before Compose starts, create it as that host identity:

```bash
install -d -m 0700 /absolute/path/to/securescan-data
```

The bind mount uses `create_host_path: false`, so Compose fails rather than
silently creating a root-owned deployment directory. The image's default user is
also non-root; its UID and GID are build arguments supplied by Compose. Do not
pre-create the managed child roots. SecureScan creates them with their required
permissions and, where applicable, ownership markers. In particular, an existing
unmarked `source-projections` directory is deliberately rejected by the frozen
projection trust boundary.

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

## Start PostgreSQL, migrate, and start the API

After `.env` and the deployment directory are ready:

```bash
docker compose config --quiet
docker compose build api migrate
docker compose up -d postgres
docker compose run --rm migrate
docker compose up -d api
docker compose ps
curl --fail --silent --show-error \
  "http://127.0.0.1:${SECURESCAN_API_PORT:-8000}/health/ready"
```

The startup dependency is `postgres healthy -> migrate completed successfully
-> api`. The API sets `SECURESCAN_ALLOW_SQLITE_SCHEMA_BOOTSTRAP=false`; Alembic is
the only deployment migration authority. The readiness response reports database
reachability and whether the schema is at the migration head, without returning
credentials or the database URL.

Compose publishes PostgreSQL and the API on `127.0.0.1` only. PostgreSQL data is
stored in the `securescan_pg` named volume. CAS objects, managed workspaces,
projections, and runtime receipts are stored below the host deployment root and
mounted at `/var/lib/securescan` for the API. Durable database records retain
opaque workspace and relative content-addressed references rather than a
container-only root path.

## Configure and run the host worker

Run the worker from the project environment on the same host. Supply the same
database, HMAC, and filesystem identities as the API, using fully materialized
values rather than `${...}` references inside a SQLAlchemy URL:

```bash
export SECURESCAN_DATABASE_URL='postgresql+psycopg://securescan:REPLACE_ME@127.0.0.1:55432/securescan'
export SECURESCAN_HMAC_KEY='REPLACE_WITH_THE_SAME_API_HMAC_KEY'
export SECURESCAN_ALLOW_SQLITE_SCHEMA_BOOTSTRAP=false
export SECURESCAN_ARTIFACT_ROOT='/absolute/path/to/securescan-data/artifacts'
export SECURESCAN_SOURCE_WORKSPACE_ROOT='/absolute/path/to/securescan-data/source-workspaces'
export SECURESCAN_SOURCE_PROJECTION_ROOT='/absolute/path/to/securescan-data/source-projections'
export SECURESCAN_SOURCE_RUNTIME_RECEIPT_ROOT='/absolute/path/to/securescan-data/source-runtime-receipts'
export SECURESCAN_SOURCE_ENRY_HELPER_PATH="$PWD/tools/enry-helper/bin/securescan-enry-helper"
export SECURESCAN_SOURCE_ENRY_HELPER_SHA256='<independently-trusted-lowercase-sha256>'
export SECURESCAN_SOURCE_GITLEAKS_EXECUTABLE_PATH="$HOME/.local/securescan-tools/gitleaks/8.30.1/gitleaks"
export SECURESCAN_SOURCE_SYFT_EXECUTABLE_PATH="$PWD/.venv-syft-1.51/bin/syft"
export SECURESCAN_SOURCE_CHECKOV_EXECUTABLE_PATH="$PWD/.venv-checkov-3.3.16/bin/checkov"
./.venv/bin/securescan worker
```

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

After migrations and the host toolchain are ready, local trusted submission is:

```bash
./.venv/bin/securescan scan /absolute/repository/path --project-id <project-uuid>
```

## Shutdown and state

Stop the containers without destroying PostgreSQL state:

```bash
docker compose down
```

Do not add `-v` to routine shutdown. Removing the named volume is a separate,
destructive database operation. The deployment bind directory is also durable
state and must be backed up and protected consistently with PostgreSQL.
