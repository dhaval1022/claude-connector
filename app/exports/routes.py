from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select

from app.db.models import Export, User
from app.db.session import SessionLocal
from app.exports.service import aware, verify_link
from datetime import datetime, timezone

router = APIRouter()


@router.get("/files/{token}")
async def download(token: str):
    """Signed, short-lived download. The token binds export id + owner; no cookie needed so a
    local analysis script can fetch it. Disabled users and expired exports are refused."""
    claims = verify_link(token)
    if not claims:
        raise HTTPException(403, "Link invalid or expired. Ask Claude for a new link.")
    async with SessionLocal() as db:
        e = (await db.execute(select(Export).where(
            Export.id == claims["sub"], Export.owner_id == claims["uid"]))).scalar_one_or_none()
        user = await db.get(User, claims["uid"])
    if (not e or not user or not user.is_active
            or aware(e.expires_at) < datetime.now(timezone.utc) or not Path(e.path).exists()):
        raise HTTPException(404, "Export not found or expired.")
    return FileResponse(e.path, media_type="text/csv", filename=e.filename,
                        headers={"X-Export-SHA256": e.sha256, "X-Export-Rows": str(e.rows),
                                 "Cache-Control": "no-store"})
