from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    FEED_OTX_API_KEY: Optional[str] = Field(default=None, alias="OTX_API_KEY")
    OSINT_VIRUSTOTAL_API_KEY: Optional[str] = None
    OSINT_ABUSEIPDB_API_KEY: Optional[str] = None
    OSINT_SHODAN_API_KEY: Optional[str] = None
    URLHAUS_API_KEY: Optional[str] = None

    QDRANT_URL: Optional[str] = None
    QDRANT_API_KEY: Optional[str] = None
    QDRANT_COLLECTION_NAME: str = "onyx_cti_knowledge"


settings = Settings()
