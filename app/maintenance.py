"""Periodic housekeeping: expired exports, spent OAuth artefacts, old audit rows."""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, or_

from app.config import get_settings
from app.db.models import AuditLog, OAuthCode, RefreshToken
from app.db.session import SessionLocal
from app.exports.service import purge_expired
from app.observability import log_event

log = logging.getLogger("connector")


async def run_once() -> dict:
    s, now = get_settings(), datetime.now(timezone.utc)
    done = {"exports": await purge_expired()}
    async with SessionLocal() as db:
        r1 = await db.execute(delete(OAuthCode).where(
            or_(OAuthCode.used.is_(True), OAuthCode.expires_at < now - timedelta(days=1))))
        # Revoked-but-unexpired tokens are KEPT: they are how refresh-token replay is detected.
        r2 = await db.execute(delete(RefreshToken).where(RefreshToken.expires_at < now))
        r3 = await db.execute(delete(AuditLog).where(
            AuditLog.ts < now - timedelta(days=s.audit_retention_days)))
        await db.commit()
    done.update(oauth_codes=r1.rowcount, refresh_tokens=r2.rowcount, audit_rows=r3.rowcount)
    log_event("maintenance", **done)
    return done


async def loop(interval_s: int = 3600) -> None:
    while True:
        try:
            await run_once()
        except Exception:   # never let housekeeping kill the server
            log.exception("maintenance failed")
        await asyncio.sleep(interval_s)
