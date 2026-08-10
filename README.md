# SecureScan Core

SecureScan Core v0.1.0 is a source-repository security-analysis orchestrator. It accepts
local repository directories, creates a deterministic read-only snapshot, runs Semgrep
Community Edition in an isolated Docker sandbox, normalizes findings, and commits a
canonical report as durable evidence.

The bundled baseline contains exactly three Python demonstration rules: dangerous
`eval`, `subprocess` with `shell=True`, and unsafe `yaml.load`. Partial analysis is
explicit: scanner diagnostics become analysis gaps rather than a false clean result.

Core v0.1 supports local directories only. It does not clone repositories, authenticate
users, provide multi-tenant isolation, cover multiple languages, or represent a complete
Semgrep ruleset. See [limitations](docs/core-v0.1-limitations.md).

## Local setup

Python 3.12+, Docker Desktop or a compatible local Docker daemon, and PostgreSQL 16 are
required for the complete release gate.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev,postgres]'
cp .env.example .env
docker compose up -d postgres
alembic upgrade head
```

The example environment keeps SQLite as the application default. Use a separate database
whose name ends in `_test` for destructive PostgreSQL integration tests.

## Tests

Ordinary tests do not require PostgreSQL or Docker:

```bash
pytest
```

Strict integration runs require already-present, digest-pinned local images:

```bash
SECURESCAN_REQUIRE_POSTGRES_TESTS=1 \
SECURESCAN_TEST_POSTGRES_URL='postgresql+psycopg://.../securescan_test' \
pytest -m postgres

SECURESCAN_REQUIRE_DOCKER_TESTS=1 \
SECURESCAN_TEST_DOCKER_IMAGE='local/image@sha256:...' \
pytest -m docker

SECURESCAN_REQUIRE_DOCKER_TESTS=1 \
SECURESCAN_REQUIRE_SEMGREP_TESTS=1 \
SECURESCAN_TEST_DOCKER_IMAGE='local/image@sha256:...' \
SECURESCAN_TEST_SEMGREP_IMAGE='semgrep/semgrep@sha256:...' \
pytest -m semgrep
```

## Release benchmark

The image must already exist locally; the evaluator never pulls or builds it.

```bash
python -m securescan.release.core_v01 \
  --corpus-root "$PWD/tests/fixtures/release_benchmark" \
  --output-directory "$PWD/release-evidence" \
  --semgrep-image 'semgrep/semgrep@sha256:...' \
  --workspace-base "$PWD/.release-workspaces"
```

The acceptance statement is deliberately narrow: 100% precision and recall on the
bundled three-rule curated micro-benchmark. Read the
[benchmark methodology](docs/core-v0.1-benchmark-methodology.md),
[operations guide](docs/core-v0.1-operations.md), and
[failure matrix](docs/core-v0.1-failure-matrix.md) before release.

## API and CLI

Start the API with `uvicorn securescan.api.main:app`. The existing `securescan` CLI
retains database initialization and fake-scanner development commands; the release gate
is separate and never runs during API startup.
