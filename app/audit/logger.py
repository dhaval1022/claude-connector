import hashlib

from app.context import current_provider
from app.db.models import AuditLog
from app.db.session import SessionLocal
from app.observability import log_event, record_tool, request_id_var


async def audit(*, user_id: str | int | None, tool: str, status: str, source_id: str | int | None = None,
                sql: str | None = None, row_count: int | None = None,
                elapsed_ms: int | None = None, error: str | None = None,
                provider: str | None = None, client: str | None = None,
                request_id: str | None = None, sql_hash: str | None = None,
                bytes_returned: int | None = None, truncated: bool = False,
                error_code: str | None = None) -> None:
    """Record a tool call. Result data is never stored, only the SQL and counts."""
    provider = provider or current_provider.get()
    record_tool(tool, status, elapsed_ms, provider)
    log_event("tool_call", tool=tool, status=status, provider=provider, user_id=user_id,
              source_id=source_id,
              rows=row_count, ms=elapsed_ms)
    rid = request_id or (request_id_var.get() if request_id_var.get() != "-" else None)
    if sql and not sql_hash:
        sql_hash = hashlib.sha256(sql.encode()).hexdigest()
    async with SessionLocal() as db:
        db.add(AuditLog(
            request_id=rid[:32] if rid else None,
            user_id=str(user_id) if user_id is not None else None,
            source_id=str(source_id) if source_id is not None else None,
            provider=provider,
            client=client,
            tool=tool[:60],
            sql_text=sql[:20000] if sql else None,
            sql_hash=sql_hash,
            row_count=row_count,
            bytes_returned=bytes_returned,
            truncated=truncated,
            elapsed_ms=elapsed_ms,
            status=status[:20],
            error_code=error_code[:40] if error_code else None,
            error=error[:2000] if error else None
        ))
        await db.commit()

