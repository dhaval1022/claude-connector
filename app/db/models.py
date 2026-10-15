import re
import uuid
from datetime import datetime, timezone

from sqlalchemy import (JSON, BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer,
                        LargeBinary, String, Text, TypeDecorator, text)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, synonym, validates

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def _id() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "mcp_users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(Text, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(50))
    password_hash: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(20), default="analyst")  # admin | analyst
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Which AI apps may use this user's data sources (app/providers.py). New users: Claude only.
    allowed_providers: Mapped[list] = mapped_column(
        JSON, default=lambda: ["claude"], server_default=text('\'["claude"]\''))
    # Which data sources this user is granted access to (None = owned only; list = assigned sources)
    allowed_sources: Mapped[list | None] = mapped_column(JSON, nullable=True, default=None)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    updated_by: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    deleted_by: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)

    @validates("email")
    def validate_email(self, key, value):
        if not value or not EMAIL_REGEX.match(str(value).strip()):
            raise ValueError(f"Invalid email address: {value}")
        return str(value).strip().lower()

    @validates("name")
    def validate_name(self, key, value):
        val = str(value or "").strip()
        if not val:
            raise ValueError("Name cannot be empty")
        if len(val) > 50:
            raise ValueError("Name cannot exceed 50 characters")
        return val

    @property
    def must_change_password(self) -> bool:
        return False

    @must_change_password.setter
    def must_change_password(self, val):
        pass

    @property
    def failed_logins(self) -> int:
        return 0

    @failed_logins.setter
    def failed_logins(self, val):
        pass


class DataSource(Base):
    __tablename__ = "mcp_data_sources"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    database_name: Mapped[str] = mapped_column(String(120))
    engine: Mapped[str] = mapped_column(String(30))
    config_encrypted: Mapped[bytes] = mapped_column(LargeBinary)
    status: Mapped[str] = mapped_column(String(20), default="ok")
    schema_cache: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    masked_columns: Mapped[list | None] = mapped_column(JSON, nullable=True)  # PII deny list
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("mcp_users.id"), index=True, nullable=True)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("mcp_users.id"), nullable=True)
    deleted_by: Mapped[int | None] = mapped_column(ForeignKey("mcp_users.id"), nullable=True)

    # Synonyms for backward compatibility
    name = synonym("database_name")
    owner_id = synonym("created_by")

    @property
    def schema_cached_at(self) -> datetime | None:
        return self.updated_at


class OAuthClient(Base):
    __tablename__ = "mcp_oauth_clients"
    client_id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_id)
    client_name: Mapped[str] = mapped_column(String(255), default="")
    redirect_uris: Mapped[list] = mapped_column(JSON)
    # 'claude'/'openai' when every redirect is that provider's web host, else '' (user chooses)
    provider_hint: Mapped[str] = mapped_column(String(20), default="", server_default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class OAuthCode(Base):
    __tablename__ = "mcp_oauth_codes"
    code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[int] = mapped_column(ForeignKey("mcp_users.id"))
    redirect_uri: Mapped[str] = mapped_column(Text)
    code_challenge: Mapped[str] = mapped_column(String(128))
    provider: Mapped[str] = mapped_column(String(20), default="claude", server_default="claude")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class RefreshToken(Base):
    __tablename__ = "mcp_refresh_tokens"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[int] = mapped_column(ForeignKey("mcp_users.id"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    provider: Mapped[str] = mapped_column(String(20), default="claude", server_default="claude")


class StrOrInt(str):
    def __eq__(self, other):
        if isinstance(other, int):
            try:
                return int(self) == other
            except ValueError:
                return False
        return super().__eq__(other)

    def __hash__(self):
        return super().__hash__()


class FlexibleString(TypeDecorator):
    impl = String
    cache_ok = True

    def __init__(self, length=None, **kwargs):
        super().__init__(length=length, **kwargs)

    def process_result_value(self, value, dialect):
        return StrOrInt(value) if value is not None else None


class AuditLog(Base):
    __tablename__ = "mcp_audit_logs"
    __table_args__ = (
        Index("ix_mcp_audit_logs_ts", "ts"),
        Index("ix_mcp_audit_logs_user_ts", "user_id", "ts"),
        Index("ix_mcp_audit_logs_source_ts", "source_id", "ts"),
        Index("ix_mcp_audit_logs_status_ts", "status", "ts"),
        Index("ix_mcp_audit_logs_sql_hash", "sql_hash"),
    )
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    request_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_id: Mapped[str | None] = mapped_column(FlexibleString(32), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(20), nullable=True)
    client: Mapped[str | None] = mapped_column(String(40), nullable=True)
    tool: Mapped[str] = mapped_column(String(60), nullable=False)
    sql_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    sql_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    row_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_returned: Mapped[int | None] = mapped_column(Integer, nullable=True)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    elapsed_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(40), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class SemanticItem(Base):
    """Business context for a data source: metric definitions, glossary terms, table/column
    notes and standing rules. Entered by the user (or by Claude on the user's behalf)."""
    __tablename__ = "mcp_semantic_items"
    __table_args__ = (
        CheckConstraint("(deleted_at IS NULL) = (deleted_by IS NULL)", name="ck_mcp_semantic_items_deleted"),
        Index("ix_mcp_semantic_items_source_id", "source_id", postgresql_where=text("deleted_at IS NULL"), sqlite_where=text("deleted_at IS NULL")),
        Index("ix_mcp_semantic_items_created_by", "created_by"),
        Index("ux_mcp_semantic_items_source_kind_name", "source_id", "kind", "name", unique=True, postgresql_where=text("deleted_at IS NULL"), sqlite_where=text("deleted_at IS NULL")),
    )
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    source_id: Mapped[int] = mapped_column(ForeignKey("mcp_data_sources.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    sql_expression: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    created_by: Mapped[int] = mapped_column(ForeignKey("mcp_users.id"), nullable=False)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("mcp_users.id"), nullable=True, default=None)
    deleted_by: Mapped[int | None] = mapped_column(ForeignKey("mcp_users.id"), nullable=True, default=None)

    # Synonym for backward compatibility
    owner_id = synonym("created_by")


class Export(Base):
    """A full-result CSV export kept briefly on disk for download / local analysis scripts."""
    __tablename__ = "mcp_exports"
    __table_args__ = (
        CheckConstraint("row_count >= 0", name="ck_mcp_exports_row_count"),
        CheckConstraint("size_bytes >= 0", name="ck_mcp_exports_size_bytes"),
        CheckConstraint("(deleted_at IS NULL) = (deleted_by IS NULL)", name="ck_mcp_exports_deleted"),
        Index("ix_mcp_exports_expires_at", "expires_at"),
        Index("ix_mcp_exports_owner_created", "created_by", text("created_at DESC")),
        Index("ix_mcp_exports_source_id", "source_id"),
    )
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    source_id: Mapped[str] = mapped_column(String(32), nullable=False)
    filename: Mapped[str] = mapped_column(String(120), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    row_count: Mapped[int] = mapped_column(Integer, nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    columns_json: Mapped[list] = mapped_column(JSON, nullable=False)
    sql_text: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    created_by: Mapped[int] = mapped_column(ForeignKey("mcp_users.id"), nullable=False)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("mcp_users.id"), nullable=True, default=None)
    deleted_by: Mapped[int | None] = mapped_column(ForeignKey("mcp_users.id"), nullable=True, default=None)

    # Synonyms for backward compatibility
    owner_id = synonym("created_by")
    rows = synonym("row_count")
    columns = synonym("columns_json")


class ApiToken(Base):
    """Personal access token for MCP clients that send a static bearer token (OpenAI's
    `authorization` field, Gemini CLI headers). Only the SHA-256 is stored; the secret is shown
    once. Expiry is mandatory; disabling the owner disables the token."""
    __tablename__ = "mcp_api_tokens"
    __table_args__ = (
        CheckConstraint("(deleted_at IS NULL) = (deleted_by IS NULL)", name="ck_mcp_api_tokens_deleted"),
        Index("ix_mcp_api_tokens_created_by", "created_by"),
        Index("ix_mcp_api_tokens_token_hash", "token_hash", unique=True),
    )
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    name: Mapped[str] = mapped_column(String(80))
    token_hash: Mapped[str] = mapped_column(String(64))
    prefix: Mapped[str] = mapped_column(String(16))      # first chars, to recognise it in the UI
    provider: Mapped[str] = mapped_column(String(20), default="other")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    created_by: Mapped[int] = mapped_column(ForeignKey("mcp_users.id"), nullable=False)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("mcp_users.id"), nullable=True, default=None)
    deleted_by: Mapped[int | None] = mapped_column(ForeignKey("mcp_users.id"), nullable=True, default=None)

    # Synonym for backward compatibility
    owner_id = synonym("created_by")
