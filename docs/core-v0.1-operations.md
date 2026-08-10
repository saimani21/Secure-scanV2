# Core v0.1 operations

## Assumptions and startup

Linux or WSL with Docker Desktop integration is expected. Docker must be reachable from
the current user. Start the local PostgreSQL 16 service with:

```bash
docker compose up -d postgres
```

Copy `.env.example` to `.env` only for local development. Set
`SECURESCAN_DATABASE_URL` to PostgreSQL when exercising durable production-oriented
paths, and replace all example secrets outside local development.

Apply migrations before starting application or worker processes:

```bash
alembic upgrade head
```

The expected migration head is `f4a8c2d17b65`. Application readiness checks schema
state and does not create tables.

## Strict validation variables

Use a disposable database ending in `_test`:

```bash
export SECURESCAN_TEST_POSTGRES_URL='postgresql+psycopg://.../securescan_test'
export SECURESCAN_REQUIRE_POSTGRES_TESTS=1
export SECURESCAN_TEST_DOCKER_IMAGE='local/test-image@sha256:...'
export SECURESCAN_REQUIRE_DOCKER_TESTS=1
export SECURESCAN_TEST_SEMGREP_IMAGE='semgrep/semgrep@sha256:...'
export SECURESCAN_REQUIRE_SEMGREP_TESTS=1
export SECURESCAN_REQUIRE_RELEASE_TESTS=1
```

Find the immutable digest of an image that is already local:

```bash
docker image inspect --format '{{index .RepoDigests 0}}' semgrep/semgrep
```

The guards reject mutable references and missing local images. They never pull or build.

## Cleanup and recovery

After tests, verify the PostgreSQL test schema is empty and no managed containers remain:

```bash
docker ps -a --filter label=securescan.managed=true
```

Release workspaces must be empty after success or failure. Investigate any residue before
rerunning. Take a tested PostgreSQL backup before migration or release activity; the
repository does not create an operational backup automatically.

Starlette/httpx may emit a known compatibility or deprecation warning in some supported
test environments. It is not claimed as fixed here; record and assess the exact warning
during release validation.
