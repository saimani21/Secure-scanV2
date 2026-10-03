import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from securescan.operator.profile import read_operator_profile
from securescan.runtime_assets import runtime_asset_path


def _default_securescan_data_root() -> Path:
    configured_root = Path(os.environ.get("XDG_DATA_HOME", "")).expanduser()
    data_root = (
        configured_root if configured_root.is_absolute() else Path.home() / ".local" / "share"
    )
    return (data_root / "securescan").resolve(strict=False)


def _absolute_path_without_resolving_symlinks(value: Path) -> Path:
    """Normalize lexical path components while preserving symlink detection."""

    return Path(os.path.abspath(value.expanduser()))


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
    deploy_data_root: Path | None = None
    runtime_uid: int = Field(default=1000, ge=1)
    runtime_gid: int = Field(default=1000, ge=1)
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
        default_factory=lambda: _default_securescan_data_root() / "source-runtime-receipts"
    )
    source_enry_helper_path: Path = Path("./tools/enry-helper/bin/securescan-enry-helper")
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
    postgres_db: str = "securescan"
    postgres_user: str = "securescan"
    postgres_password: str = ""
    postgres_port: int = Field(default=55_432, ge=1, le=65_535)
    api_port: int = Field(default=8_000, ge=1, le=65_535)
    operator_compose_file: Path = Field(default_factory=lambda: runtime_asset_path("compose.yaml"))
    operator_compose_project: str = "securescan-source-v11"
    operator_startup_timeout_seconds: float = Field(default=120.0, ge=5, le=600)
    operator_shutdown_timeout_seconds: float = Field(default=15.0, ge=1, le=120)
    ai_enabled: bool = False
    ai_model: str | None = Field(default=None, max_length=200)
    ai_allow_source_snippets: bool = False

    @field_validator(
        "deploy_data_root",
        "artifact_root",
        "source_projection_root",
        "source_workspace_root",
        "source_runtime_receipt_root",
        "source_enry_helper_path",
        "source_gitleaks_executable_path",
        "source_syft_executable_path",
        "source_checkov_executable_path",
        "operator_compose_file",
        mode="after",
    )
    @classmethod
    def normalize_source_runtime_root(cls, value: Path | None) -> Path | None:
        if value is None:
            return None
        return _absolute_path_without_resolving_symlinks(value)

    @field_validator("source_enry_helper_sha256")
    @classmethod
    def validate_source_enry_helper_sha256(cls, value: str | None) -> str | None:
        if value is not None and re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("Source Enry helper digest must be lowercase SHA-256")
        return value

    @field_validator("operator_compose_project")
    @classmethod
    def validate_operator_compose_project(cls, value: str) -> str:
        if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", value) is None:
            raise ValueError("Operator Compose project name is invalid")
        return value

    @field_validator("postgres_db", "postgres_user", "postgres_password")
    @classmethod
    def validate_postgres_value(cls, value: str) -> str:
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("PostgreSQL configuration contains control characters")
        return value

    @field_validator("ai_model")
    @classmethod
    def validate_ai_model(cls, value: str | None) -> str | None:
        if value is not None and (
            not value.strip()
            or value != value.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("AI model identifier is invalid")
        return value

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource | Any, ...]:
        # Highest priority first. Legacy Settings() retains cwd .env compatibility;
        # operator commands use Settings(_env_file=None), which disables that source.
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            read_operator_profile,
            file_secret_settings,
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_operator_settings() -> Settings:
    """Load operator configuration without consulting an arbitrary cwd .env."""

    return Settings(_env_file=None)
