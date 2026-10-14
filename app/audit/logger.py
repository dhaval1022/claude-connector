from app.db.models import AuditLog
from app.db.session import SessionLocal
from app.observability import log_event, record_tool


async def audit(*, user_id: str | None, tool: str, status: str, source_id: str | None = None,
                sql: str | None = None, row_count: int | None = None,
                elapsed_ms: int | None = None, error: str | None = None) -> None:
    """Record a tool call. Result data is never stored, only the SQL and counts."""
    record_tool(tool, status, elapsed_ms)
    log_event("tool_call", tool=tool, status=status, user_id=user_id, source_id=source_id,
              rows=row_count, ms=elapsed_ms)
    async with SessionLocal() as db:
        db.add(AuditLog(user_id=user_id, tool=tool, status=status, source_id=source_id,
                        sql_text=sql[:20000] if sql else None, row_count=row_count,
                        elapsed_ms=elapsed_ms, error=error[:2000] if error else None))
        await db.commit()
