"""Runtime configuration, read from environment variables / `.env`.

Every component (intel CLI, orggen CLI, API, tests) imports `get_settings()`
so there is exactly one place that knows host names, ports and passwords.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Repo root = four levels up from this file:
# packages/core/src/reachable_core/settings.py
REPO_ROOT = Path(__file__).resolve().parents[4]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=REPO_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- FalkorDB (speaks the Redis protocol) ---
    falkordb_host: str = "localhost"
    falkordb_port: int = 6380
    falkordb_password: str | None = None
    falkordb_browser_port: int = 3001

    # --- Postgres (baseline mirror only; FalkorDB is the primary store) ---
    postgres_host: str = "localhost"
    postgres_port: int = 5434
    postgres_user: str = "reachable"
    postgres_password: str = "reachable"
    postgres_db: str = "reachable"

    # --- Threat intel ---
    # Read the NVD key from the environment when fetching. None => slow path
    # (5 requests / 30s). A free key raises that to 50 / 30s.
    nvd_api_key: str | None = None

    # --- Org names (one FalkorDB graph per org) ---
    orgs: list[str] = Field(default_factory=lambda: ["org_a", "org_b", "org_c"])

    data_dir: Path = REPO_ROOT / "data"
    seed: int = 42

    @property
    def threatintel_dir(self) -> Path:
        return self.data_dir / "threatintel"

    @property
    def orgs_dir(self) -> Path:
        return self.data_dir / "orgs"

    @property
    def postgres_dsn(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
