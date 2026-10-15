"""Runtime configuration, read from environment variables / `.env`.

Every component (intel CLI, orggen CLI, API, tests) imports `get_settings()`
so there is exactly one place that knows host names, ports and passwords.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
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

    # --- LLM router (S4 agents). Keys are SecretStr: they never print in a repr
    # or a log line; only llm.py unwraps them, to hand them to LiteLLM. ---
    gemini_api_key: SecretStr | None = None  # primary (free tier)
    groq_api_key: SecretStr | None = None  # fallback 1 (free tier)
    # Free tier is 20 requests/DAY per model (one run is ~12 calls), so the
    # model is an env knob: switch when one model's daily quota is spent.
    llm_primary_model: str = "gemini/gemini-3.5-flash-lite"
    # (Groq retired llama-3.3-70b-versatile; `python -m reachable_agents check`
    # probes every configured model with a real tool call.)
    llm_fallback_model: str = "groq/qwen/qwen3.8-27b"
    # Fallback 2: a small paid model, OFF unless both are set (judging week).
    llm_reserve_model: str | None = None
    llm_reserve_api_key: SecretStr | None = None
    llm_timeout_s: float = 60.0  # per call
    # Client-side pacing: at most this many calls per minute (Gemini's free tier
    # answered 5 then 429'd). A call waits up to llm_max_wait_s for a slot rather
    # than burn the fallback; 0 disables pacing.
    llm_rpm: int = 5
    llm_max_wait_s: float = 30.0
    llm_patience_retries: int = 3  # per run: wait 35 s and retry on a short-lived 429
    llm_retries: int = 1  # Router retries per deployment before falling back
    llm_max_tokens: int = 4096  # per completion (thinking tokens count too)

    # --- Agent run budgets (free-tier protection) ---
    agent_max_llm_calls: int = 30
    agent_max_tool_calls: int = 45

    @property
    def graphs(self) -> list[str]:
        """Every org graph a tool may read: scan v1 is `<org>`, scan v2 `<org>_v2`."""
        return [*self.orgs, *(f"{o}_v2" for o in self.orgs)]

    @property
    def threatintel_dir(self) -> Path:
        return self.data_dir / "threatintel"

    @property
    def orgs_dir(self) -> Path:
        return self.data_dir / "orgs"

    def scan_graph(self, org: str, scan: str = "v1") -> str:
        if org not in self.orgs or scan not in ("v1", "v2"):
            raise ValueError(f"unknown org/scan {org!r}/{scan!r}")
        return org if scan == "v1" else f"{org}_v2"

    @property
    def postgres_dsn(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
