"""
ONYX CTI — Platform Configuration
Centralized configuration using Pydantic Settings.
All settings are loaded from environment variables with validation.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

# Resolve the project root .env file (works regardless of CWD)
_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"
if not _ENV_FILE.exists():
    # Fallback: try CWD
    _ENV_FILE = Path(".env")
_ENV_PATH = str(_ENV_FILE)


class ElasticsearchConfig(BaseSettings):
    """Elasticsearch connection and index configuration."""

    model_config = SettingsConfigDict(env_prefix="ELASTICSEARCH_")

    host: str = Field(default="elasticsearch", description="ES hostname")
    port: int = Field(default=9200)
    scheme: str = Field(default="http")
    user: str = Field(default="elastic")
    password: str = Field(default="onyx_elastic_secret_2026")
    ioc_index: str = Field(default="onyx-iocs")
    threats_index: str = Field(default="onyx-threats")
    audit_index: str = Field(default="onyx-audit")
    metrics_index: str = Field(default="onyx-metrics")
    max_result_window: int = Field(default=50000)

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


class MongoDBConfig(BaseSettings):
    """MongoDB connection configuration."""

    model_config = SettingsConfigDict(env_prefix="MONGODB_")

    host: str = Field(default="mongodb")
    port: int = Field(default=27017)
    database: str = Field(default="onyx_cti")
    user: str = Field(default="onyx_admin")
    password: str = Field(default="onyx_mongo_secret_2026")
    auth_source: str = Field(default="admin")

    @property
    def uri(self) -> str:
        return (
            f"mongodb://{self.user}:{self.password}@{self.host}:{self.port}"
            f"/{self.database}?authSource={self.auth_source}"
        )


class RedisConfig(BaseSettings):
    """Redis connection configuration."""

    model_config = SettingsConfigDict(env_prefix="REDIS_")

    host: str = Field(default="redis")
    port: int = Field(default=6379)
    password: str = Field(default="onyx_redis_secret_2026")
    db_cache: int = Field(default=0)
    db_queue: int = Field(default=1)
    db_sessions: int = Field(default=2)
    db_events: int = Field(default=3)

    def url(self, db: int | None = None) -> str:
        db_num = db if db is not None else self.db_cache
        return f"redis://:{self.password}@{self.host}:{self.port}/{db_num}"


class TorConfig(BaseSettings):
    """Tor proxy configuration."""

    model_config = SettingsConfigDict(env_prefix="TOR_")

    socks_port: int = Field(default=9050)
    control_port: int = Field(default=9051)
    control_password: str = Field(default="onyx_tor_control_2026")
    privoxy_port: int = Field(default=8118)
    circuit_rotation_seconds: int = Field(default=300)
    max_circuits: int = Field(default=5)
    kill_switch: bool = Field(default=False, description="Emergency kill switch for all Tor traffic")

    @property
    def socks_proxy(self) -> str:
        return f"socks5h://tor-proxy:{self.socks_port}"

    @property
    def http_proxy(self) -> str:
        return f"http://tor-proxy:{self.privoxy_port}"


class CrawlerConfig(BaseSettings):
    """Crawler module configuration."""

    model_config = SettingsConfigDict(env_prefix="CRAWLER_")

    darkweb_enabled: bool = Field(default=True)
    clearweb_enabled: bool = Field(default=True)
    request_delay: float = Field(default=5.0, description="Delay between requests in seconds")
    request_timeout: int = Field(default=30)
    max_concurrent: int = Field(default=3)
    user_agent_rotation: bool = Field(default=True)
    screenshot_enabled: bool = Field(default=True)


class NLPConfig(BaseSettings):
    """NLP engine configuration."""

    model_config = SettingsConfigDict(env_prefix="NLP_")

    scibert_model: str = Field(default="allenai/scibert_scivocab_uncased")
    spacy_model: str = Field(default="en_core_web_trf")
    batch_size: int = Field(default=32)
    confidence_threshold: float = Field(default=0.65)
    ioc_defang_enabled: bool = Field(default=True)


class GeminiConfig(BaseSettings):
    """Google Gemini LLM configuration."""

    model_config = SettingsConfigDict(env_prefix="GEMINI_", env_file=_ENV_PATH, extra="ignore")

    api_key: str = Field(default="", description="Gemini API key — loaded from env only")
    model: str = Field(default="gemini-2.5-flash")
    temperature: float = Field(default=0.3)
    max_output_tokens: int = Field(default=8192)
    embedding_model: str = Field(default="gemini-embedding-2-preview")


class QdrantConfig(BaseSettings):
    """Qdrant vector store configuration.
    When QDRANT_URL is empty → in-memory mode (zero infra).
    When QDRANT_URL is set  → persistent remote mode.
    """

    model_config = SettingsConfigDict(env_prefix="QDRANT_", env_file=_ENV_PATH, extra="ignore")

    url: str = Field(default="", description="Remote Qdrant URL — empty = in-memory")
    api_key: str = Field(default="", description="API key for managed Qdrant Cloud")
    collection_name: str = Field(default="onyx_cti_iocs")

    @property
    def is_remote(self) -> bool:
        """True if a remote Qdrant instance is configured."""
        return bool(self.url)


class GuardrailsConfig(BaseSettings):
    """LLM security guardrails configuration."""

    model_config = SettingsConfigDict(env_prefix="GUARDRAILS_", env_file=_ENV_PATH, extra="ignore")

    enabled: bool = Field(default=True)
    max_input_length: int = Field(default=4000)
    max_output_length: int = Field(default=16000)


class OnyxConfig(BaseSettings):
    """Root configuration aggregating all sub-configs."""

    model_config = SettingsConfigDict(
        env_prefix="ONYX_",
        env_file=_ENV_PATH,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: str = Field(default="development")
    debug: bool = Field(default=True)
    secret_key: str = Field(default="change-me-to-a-64-char-random-hex-string")
    log_level: str = Field(default="INFO")
    timezone: str = Field(default="UTC")

    # API server
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    api_workers: int = Field(default=4)
    api_cors_origins: list[str] = Field(default=["http://localhost:3000"])
    api_rate_limit: str = Field(default="100/minute")

    # JWT
    jwt_secret: str = Field(default="change-me-to-another-64-char-random-hex-string")
    jwt_algorithm: str = Field(default="HS256")
    jwt_expiration_minutes: int = Field(default=1440)

    # Sub-configurations (loaded independently via their own env prefixes)
    @property
    def elasticsearch(self) -> ElasticsearchConfig:
        return ElasticsearchConfig()

    @property
    def mongodb(self) -> MongoDBConfig:
        return MongoDBConfig()

    @property
    def redis(self) -> RedisConfig:
        return RedisConfig()

    @property
    def tor(self) -> TorConfig:
        return TorConfig()

    @property
    def crawler(self) -> CrawlerConfig:
        return CrawlerConfig()

    @property
    def nlp(self) -> NLPConfig:
        return NLPConfig()

    @property
    def gemini(self) -> GeminiConfig:
        return GeminiConfig()

    @property
    def qdrant(self) -> QdrantConfig:
        return QdrantConfig()

    @property
    def guardrails(self) -> GuardrailsConfig:
        return GuardrailsConfig()


# Singleton instance
_config: OnyxConfig | None = None


def get_config() -> OnyxConfig:
    """Get or create the global configuration singleton."""
    global _config
    if _config is None:
        _config = OnyxConfig()
    return _config
