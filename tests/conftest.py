from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path

import pytest
from docker_test_guard import (
    docker_test_image_is_configured,
    require_docker_tests,
    validated_docker_test_image,
)
from postgres_test_guard import (
    postgres_test_url_is_configured,
    require_postgres_tests,
    validated_postgres_test_url,
)

from securescan.adapters.fake_scanner import FakeScannerAdapter
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.config import get_operator_settings, get_settings
from securescan.domain.enums import TargetType
from securescan.domain.models import TargetProfile
from securescan.execution.local_executor import LocalProcessExecutor
from securescan.runtime_storage import initialize_source_runtime_storage
from securescan.services.scan_service import ScanService


@pytest.fixture(scope="session", autouse=True)
def isolate_operator_profile_from_host(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[None]:
    """Prevent a developer's persistent operator profile from affecting tests."""

    isolated_profile = (
        tmp_path_factory.mktemp("securescan-test-profile")
        / "missing-operator.json"
    )

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("SECURESCAN_OPERATOR_PROFILE", str(isolated_profile))
        get_settings.cache_clear()
        get_operator_settings.cache_clear()
        try:
            yield
        finally:
            get_settings.cache_clear()
            get_operator_settings.cache_clear()


@pytest.fixture(scope="session", autouse=True)
def enforce_required_postgres_test_environment() -> None:
    if require_postgres_tests() or postgres_test_url_is_configured():
        validated_postgres_test_url()


@pytest.fixture(scope="session", autouse=True)
def enforce_required_docker_test_environment() -> None:
    if require_docker_tests() or docker_test_image_is_configured():
        validated_docker_test_image()


@pytest.fixture
def initialized_api_runtime_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    root = tmp_path / "api-runtime"
    monkeypatch.setenv("SECURESCAN_ARTIFACT_ROOT", str(root / "artifacts"))
    monkeypatch.setenv(
        "SECURESCAN_SOURCE_WORKSPACE_ROOT", str(root / "source-workspaces")
    )
    monkeypatch.setenv(
        "SECURESCAN_SOURCE_PROJECTION_ROOT", str(root / "source-projections")
    )
    monkeypatch.setenv(
        "SECURESCAN_SOURCE_RUNTIME_RECEIPT_ROOT",
        str(root / "source-runtime-receipts"),
    )
    get_settings.cache_clear()
    initialize_source_runtime_storage(get_settings())
    try:
        yield
    finally:
        get_settings.cache_clear()


@pytest.fixture
def target(tmp_path: Path) -> TargetProfile:
    (tmp_path / "sample.py").write_text("print('hello')\n", encoding="utf-8")
    return TargetProfile(
        target_type=TargetType.SOURCE_REPOSITORY,
        path=tmp_path,
        content_digest=hashlib.sha256(b"fixture").hexdigest(),
    )


@pytest.fixture
def adapter() -> FakeScannerAdapter:
    return FakeScannerAdapter("unit-test-hmac-key")


@pytest.fixture
def service(tmp_path: Path) -> ScanService:
    return ScanService(
        executor=LocalProcessExecutor(),
        artifact_store=ContentAddressedArtifactStore(tmp_path / "artifacts"),
    )
