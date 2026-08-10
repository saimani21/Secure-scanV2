from __future__ import annotations

import hashlib
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
from securescan.domain.enums import TargetType
from securescan.domain.models import TargetProfile
from securescan.execution.local_executor import LocalProcessExecutor
from securescan.services.scan_service import ScanService


@pytest.fixture(scope="session", autouse=True)
def enforce_required_postgres_test_environment() -> None:
    if require_postgres_tests() or postgres_test_url_is_configured():
        validated_postgres_test_url()


@pytest.fixture(scope="session", autouse=True)
def enforce_required_docker_test_environment() -> None:
    if require_docker_tests() or docker_test_image_is_configured():
        validated_docker_test_image()


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
