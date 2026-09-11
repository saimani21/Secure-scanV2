import os
import re
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_securescan_data_root() -> Path:
    configured_root = Path(os.environ.get("XDG_DATA_HOME", "")).expanduser()
    data_root = (
        configured_root
        if configured_root.is_absolute()
        else Path.home() / ".local" / "share"
    )
    return (data_root / "securescan").resolve(strict=False)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SECURESCAN_",
        env_file=".env",
        extra="ignore",
        validate_default=True,
    )

    database_url: str = Field(
        default_factory=lambda: (
            f"sqlite:///{(_default_securescan_data_root() / 'securescan.db').as_posix()}"
        )
    )
    artifact_root: Path = Field(
        default_factory=lambda: _default_securescan_data_root() / "artifacts"
    )
    source_projection_root: Path = Field(
        default_factory=lambda: _default_securescan_data_root() / "source-projections"
    )
    source_workspace_root: Path = Field(
        default_factory=lambda: _default_securescan_data_root() / "source-workspaces"
    )
    source_runtime_receipt_root: Path = Field(
        default_factory=lambda: _default_securescan_data_root()
        / "source-runtime-receipts"
    )
    source_enry_helper_path: Path = Path(
        "./tools/enry-helper/bin/securescan-enry-helper"
    )
    source_enry_helper_sha256: str | None = None
    source_scan_deadline_seconds: int = Field(default=1_800, ge=300, le=86_400)
    source_worker_poll_seconds: float = Field(default=1.0, ge=0.1, le=60)
    source_gitleaks_executable_path: Path = Path(
        "~/.local/securescan-tools/gitleaks/8.30.1/gitleaks"
    )
    source_syft_executable_path: Path = Path("./.venv-syft-1.51/bin/syft")
    source_checkov_executable_path: Path = Path("./.venv-checkov-3.3.16/bin/checkov")
    hmac_key: str = Field(default="development-only-key", min_length=8)
    max_output_bytes: int = Field(default=1_048_576, ge=1_024)
    default_timeout_seconds: int = Field(default=15, ge=1, le=3_600)
    allow_sqlite_schema_bootstrap: bool = True

    @field_validator(
        "artifact_root",
        "source_projection_root",
        "source_workspace_root",
        "source_runtime_receipt_root",
        "source_enry_helper_path",
        "source_gitleaks_executable_path",
        "source_syft_executable_path",
        "source_checkov_executable_path",
        mode="after",
    )
    @classmethod
    def normalize_source_runtime_root(cls, value: Path) -> Path:
        return value.expanduser().resolve(strict=False)

    @field_validator("source_enry_helper_sha256")
    @classmethod
    def validate_source_enry_helper_sha256(cls, value: str | None) -> str | None:
        if value is not None and re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("Source Enry helper digest must be lowercase SHA-256")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
