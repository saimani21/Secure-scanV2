from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SECURESCAN_",
        env_file=".env",
        extra="ignore",
    )

    database_url: str = "sqlite:///./securescan.db"
    artifact_root: Path = Path("./data/artifacts")
    hmac_key: str = Field(default="development-only-key", min_length=8)
    max_output_bytes: int = Field(default=1_048_576, ge=1_024)
    default_timeout_seconds: int = Field(default=15, ge=1, le=3_600)
    allow_sqlite_schema_bootstrap: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
