from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def _text(relative_path: str) -> str:
    return (_ROOT / relative_path).read_text(encoding="utf-8")


def _compose_service_names(compose: str) -> set[str]:
    lines = compose.splitlines()
    start = lines.index("services:") + 1
    names: set[str] = set()
    for line in lines[start:]:
        if line and not line.startswith(" "):
            break
        if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
            names.add(line.strip()[:-1])
    return names


def test_compose_has_only_the_d1_runtime_services() -> None:
    compose = _text("compose.yaml")

    assert _compose_service_names(compose) == {"postgres", "migrate", "api"}
    assert "\n  worker:\n" not in compose
    assert "/var/run/docker.sock" not in compose


def test_compose_fails_closed_on_secrets_and_binds_only_to_localhost() -> None:
    compose = _text("compose.yaml")

    assert (
        "${SECURESCAN_POSTGRES_PASSWORD:?SECURESCAN_POSTGRES_PASSWORD is required}"
        in compose
    )
    assert "${SECURESCAN_HMAC_KEY:?SECURESCAN_HMAC_KEY is required}" in compose
    assert "securescan-dev-only" not in compose
    assert '"127.0.0.1:${SECURESCAN_POSTGRES_PORT:-55432}:5432"' in compose
    assert '"127.0.0.1:${SECURESCAN_API_PORT:-8000}:8000"' in compose
    assert "0.0.0.0:${SECURESCAN_POSTGRES_PORT" not in compose
    assert "0.0.0.0:${SECURESCAN_API_PORT" not in compose


def test_compose_orders_migration_and_api_readiness() -> None:
    compose = _text("compose.yaml")

    assert 'command: ["alembic", "upgrade", "head"]' in compose
    assert "condition: service_healthy" in compose
    assert "condition: service_completed_successfully" in compose
    assert "@postgres:5432/" in compose
    assert "@database" not in compose
    assert "SECURESCAN_ALLOW_SQLITE_SCHEMA_BOOTSTRAP: \"false\"" in compose
    assert "http://127.0.0.1:8000/health/ready" in compose


def test_compose_shares_the_host_runtime_root_with_the_api() -> None:
    compose = _text("compose.yaml")

    assert (
        "source: ${SECURESCAN_DEPLOY_DATA_ROOT:-./.securescan-deploy}" in compose
    )
    assert "target: /var/lib/securescan" in compose
    assert "create_host_path: false" in compose
    assert "SECURESCAN_ARTIFACT_ROOT: /var/lib/securescan/artifacts" in compose
    assert (
        "SECURESCAN_SOURCE_WORKSPACE_ROOT: /var/lib/securescan/source-workspaces"
        in compose
    )
    assert (
        "SECURESCAN_SOURCE_PROJECTION_ROOT: /var/lib/securescan/source-projections"
        in compose
    )
    assert (
        "SECURESCAN_SOURCE_RUNTIME_RECEIPT_ROOT: "
        "/var/lib/securescan/source-runtime-receipts" in compose
    )


def test_application_image_is_non_root_and_contains_only_application_runtime() -> None:
    dockerfile = _text("Dockerfile")
    lowered = dockerfile.lower()

    assert "FROM python:3.12-slim-bookworm" in dockerfile
    assert '/opt/securescan/bin/pip install ".[postgres]"' in dockerfile
    assert "COPY --chown=securescan:securescan migrations /app/migrations" in dockerfile
    assert "COPY --chown=securescan:securescan alembic.ini /app/alembic.ini" in dockerfile
    assert "PYTHONPATH=/app/src" in dockerfile
    assert 'test "${SECURESCAN_RUNTIME_UID}" -gt 0' in dockerfile
    assert 'test "${SECURESCAN_RUNTIME_GID}" -gt 0' in dockerfile
    assert "USER securescan:securescan" in dockerfile
    assert "USER root" not in dockerfile
    assert all(name not in lowered for name in ("semgrep", "gitleaks", "syft", "checkov"))


def test_environment_example_and_ignores_describe_deployment_boundary() -> None:
    environment = _text(".env.example")
    gitignore = _text(".gitignore")
    dockerignore = _text(".dockerignore")

    assert "SECURESCAN_HMAC_KEY=\n" in environment
    assert "SECURESCAN_POSTGRES_PASSWORD=\n" in environment
    assert "SECURESCAN_API_PORT=8000" in environment
    assert "SECURESCAN_DEPLOY_DATA_ROOT=./.securescan-deploy" in environment
    assert "@127.0.0.1:55432" in environment
    assert "@postgres:5432" in environment
    assert "@database" not in environment
    assert ".securescan-deploy/" in gitignore
    assert ".securescan-deploy/" in dockerignore
    assert "migrations/" not in dockerignore


def test_deployment_guide_preserves_existing_postgres_state() -> None:
    guide = _text("docs/source-v1-deployment.md")

    assert "changing the\nvariable does not rotate a role password" in guide
    assert (
        '--command "\\\\password ${SECURESCAN_POSTGRES_USER:-securescan}"' in guide
    )
    assert "docker compose down -v" not in guide


def test_deployment_guide_does_not_precreate_managed_projection_root() -> None:
    guide = _text("docs/source-v1-deployment.md")

    assert "Do not\npre-create the managed child roots" in guide
    assert "an existing\nunmarked `source-projections` directory" in guide
    assert "install -d -m 0700 \\\n  /absolute/path/to/securescan-data" not in guide
