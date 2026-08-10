# SecureScan Core v0.1 release checklist

Runtime-dependent items are deliberately unchecked. Record command output in the release
work item rather than permanently marking environmental checks as passed here.

- [ ] Ruff: `ruff check .`
- [ ] Bytecode compilation: `python -m compileall -q src tests`
- [ ] Ordinary tests: `pytest`
- [ ] Strict PostgreSQL tests:
  `SECURESCAN_REQUIRE_POSTGRES_TESTS=1 pytest -m postgres`
- [ ] Strict Docker tests: `SECURESCAN_REQUIRE_DOCKER_TESTS=1 pytest -m docker`
- [ ] Strict Semgrep tests:
  `SECURESCAN_REQUIRE_SEMGREP_TESTS=1 pytest -m semgrep`
- [ ] Release benchmark:
  `SECURESCAN_REQUIRE_RELEASE_TESTS=1 pytest -m release`
- [ ] PostgreSQL schema cleanup: inspect the disposable `_test` database after tests
- [ ] Managed-container cleanup:
  `docker ps -a --filter label=securescan.managed=true`
- [ ] Workspace cleanup: verify the configured release workspace base is empty
- [ ] Migration head: `alembic current` must report `f4a8c2d17b65`
- [ ] No new dependency: compare `pyproject.toml` with the approved release baseline
- [ ] No migration: verify `migrations/versions/` contains no Step 12 revision
- [ ] No Git requirement: benchmark and tests run without invoking Git
- [ ] Backup created: create and test an operator-managed PostgreSQL backup
- [ ] Limitations reviewed: read `docs/core-v0.1-limitations.md` and the benchmark report
