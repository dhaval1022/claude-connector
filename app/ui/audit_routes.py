"""Admin view of the audit log (who ran what, when). Read-only; SQL text is HTML-escaped by the
template engine and truncated for display."""
from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog, User
from app.db.session import get_session
from app.ui.routes import Ctx, _admin, _page

router = APIRouter()
STATUSES = ("ok", "rejected", "error")


@router.get("/admin/audit")
async def audit_view(request: Request, status: str = "", tool: str = "", user: str = "",
                     ctx: Ctx = Depends(_admin), db: AsyncSession = Depends(get_session)):
    q = select(AuditLog).order_by(AuditLog.ts.desc()).limit(200)
    if status in STATUSES:
        q = q.where(AuditLog.status == status)
    if tool.strip():
        q = q.where(AuditLog.tool == tool.strip()[:60])
    if user.strip():
        found = (await db.execute(select(User.id).where(
            User.email == user.strip().lower()))).scalar_one_or_none()
        q = q.where(AuditLog.user_id == (found or "-"))
    rows = (await db.execute(q)).scalars().all()
    emails = {u.id: u.email for u in (await db.execute(select(User))).scalars()}
    return _page(request, "audit.html", ctx, rows=rows, emails=emails, statuses=STATUSES,
                 f_status=status, f_tool=tool, f_user=user)
