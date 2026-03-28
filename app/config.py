from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # App
    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000

    # Redis
    redis_url: str

    # Postgres
    database_url: str

    # Security
    secret_key: str

    # Rate limiting
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60

    # Bloom filter
    bloom_filter_capacity: int = 1_000_000
    bloom_filter_error_rate: float = 0.001

    # Abuse detection
    auth_failure_ip_threshold: int = 10
    auth_failure_user_threshold: int = 20
    auth_failure_window_seconds: int = 300
    scraping_entropy_threshold: float = 0.5
    scraping_sample_size: int = 20

    # Shadow mode
    shadow_mode_enabled: bool = True
    shadow_mode_redis_key: str = "config:shadow_mode_enabled"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
