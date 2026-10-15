from functools import lru_cache

from urllib.parse import quote_plus

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="CONNECTOR_", extra="ignore")

    # AWS S3 Storage for uploaded files
    aws_bucket_name: str = Field(default="", validation_alias=AliasChoices("AWS_BUCKET_NAME", "CONNECTOR_AWS_BUCKET_NAME"))
    aws_access_key_id: str = Field(default="", validation_alias=AliasChoices("AWS_ACCESS_KEY_ID", "CONNECTOR_AWS_ACCESS_KEY_ID"))
    aws_secret_access_key: str = Field(default="", validation_alias=AliasChoices("AWS_SECRET_ACCESS_KEY", "CONNECTOR_AWS_SECRET_ACCESS_KEY"))
    aws_region: str = Field(default="ap-south-1", validation_alias=AliasChoices("AWS_REGION", "CONNECTOR_AWS_REGION"))

    # Database configuration (PostgreSQL via DB_* or full CONNECTOR_DATABASE_URL)
    db_host: str = Field(default="", validation_alias=AliasChoices("DB_HOST", "CONNECTOR_DB_HOST"))
    db_port: int = Field(default=5432, validation_alias=AliasChoices("DB_PORT", "CONNECTOR_DB_PORT"))
    db_database: str = Field(default="", validation_alias=AliasChoices("DB_DATABASE", "CONNECTOR_DB_DATABASE"))
    db_user: str = Field(default="", validation_alias=AliasChoices("DB_USER", "CONNECTOR_DB_USER"))
    db_password: str = Field(default="", validation_alias=AliasChoices("DB_PASSWORD", "CONNECTOR_DB_PASSWORD"))

    database_url: str = Field(
        default="sqlite+aiosqlite:///./connector.db",
        validation_alias=AliasChoices("CONNECTOR_DATABASE_URL", "DATABASE_URL")
    )
    public_base_url: str = "http://localhost:8000"
    # 32-byte key, base64. Encrypts data-source credentials (AES-256-GCM).
    master_key: str = ""
    # HS256 secret for OAuth access tokens.
    jwt_secret: str = ""
    access_token_ttl_s: int = 1800
    refresh_token_ttl_s: int = 60 * 60 * 24 * 30
    allowed_redirect_prefixes: list[str] = [
        "https://claude.ai/api/mcp/auth_callback",
        # ChatGPT connectors. OpenAI's docs/guides show both a fixed callback and a per-app
        # callback (/connector/oauth/<id>), so both are allowed; matching is structural.
        "https://chatgpt.com/connector_platform_oauth_redirect",
        "https://chatgpt.com/connector/oauth/",
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",
    ]
    # Fixed client_id for Gemini's custom MCP connector form (it asks for one instead of
    # registering itself). A public client: PKCE is mandatory and there is no secret. Its redirect
    # is accepted only for Google's redirector with this server's own name in the path.
    gemini_client_id: str = "medkart-gemini"
    default_max_rows: int = 500
    hard_max_rows: int = 10_000
    query_timeout_s: int = 60
    # SSRF controls for user-supplied DB hosts. Link-local/metadata ranges are always blocked.
    allow_loopback: bool = False
    # Dev/test only: lets users register a local SQLite file (arbitrary file access!).
    enable_sqlite: bool = False
    max_schema_tables: int = 5000
    data_dir: str = "./data"  # uploaded files + per-source DuckDB databases
    max_upload_mb: int = 100
    max_upload_files: int = 20
    # Exports (full results as CSV)
    export_max_rows: int = 2_000_000
    export_timeout_s: int = 600
    export_max_mb: int = 500
    export_retention_h: int = 24
    export_link_ttl_s: int = 1800
    audit_retention_days: int = 180
    # Rate limits (per user unless noted) and resilience
    rate_tools_per_min: int = 240
    rate_queries_per_min: int = 60
    rate_exports_per_hour: int = 20
    rate_login_per_min_ip: int = 20
    rate_token_per_min_ip: int = 60
    trusted_proxy_count: int = 0       # number of reverse proxies in front (for client IPs)
    breaker_failures: int = 5
    breaker_open_s: int = 60
    # Observability / hosts
    allowed_hosts: list[str] = []      # extra Host header values besides public_base_url's
    metrics_token: str = ""            # /metrics requires this bearer token (404 if unset)
    log_json: bool = True
    # Optional first admin, created at startup ONLY if there are no users (see app/bootstrap.py)
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""
    bootstrap_admin_name: str = "Administrator"

    @model_validator(mode="after")
    def compute_database_url(self) -> "Settings":
        if self.db_host and self.db_database:
            user = quote_plus(self.db_user) if self.db_user else ""
            pwd = f":{quote_plus(self.db_password)}" if self.db_password else ""
            auth = f"{user}{pwd}@" if user or pwd else ""
            self.database_url = f"postgresql+asyncpg://{auth}{self.db_host}:{self.db_port}/{self.db_database}"
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
