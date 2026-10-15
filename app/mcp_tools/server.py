from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from sqlalchemy import select

from app.config import get_settings
from app.context import current_provider, current_user_id  # noqa: F401  (re-exported for tools)
from app.db.models import DataSource, User
from app.db.session import SessionLocal
from app.providers import LABELS, is_allowed
from app.semantic import service as semantic

mcp = FastMCP(
    "Medkart Data Connector",
    stateless_http=True,
    json_response=True,
    streamable_http_path="/",
    # Host validation is handled by the reverse proxy / public_base_url.
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


async def app_enabled_for_user() -> bool:
    """Has the signed-in user enabled the calling app (their Connect page setting)?"""
    async with SessionLocal() as db:
        user = await db.get(User, current_user_id.get())
    return bool(user) and is_allowed(user.allowed_providers, current_provider.get())


@mcp.tool()
async def list_data_sources() -> dict:
    """List the databases/files the signed-in user has connected.

    Start here: returns each source's id, name, engine and status. Use the id in all other
    tools. Only the caller's own sources are ever returned. If the user has not enabled this app
    for their account, no sources are listed and `not_enabled_for_this_app` says how many exist."""
    provider = current_provider.get()
    enabled = await app_enabled_for_user()
    async with SessionLocal() as db:
        rows = (await db.execute(
            select(DataSource).where(DataSource.owner_id == current_user_id.get())
            .order_by(DataSource.name))).scalars().all()
    visible = rows if enabled else []
    db_notes = await semantic.all_database_notes(current_user_id.get()) if enabled else {}
    out: dict = {"data_sources": [
        {"id": r.id, "name": r.name, "engine": r.engine, "status": r.status,
         **({"context": db_notes[r.id]} if r.id in db_notes else {}),
         "schema_cached_at": r.schema_cached_at.isoformat() if r.schema_cached_at else None}
        for r in visible]}
    hidden = len(rows) - len(visible)
    if hidden:
        out["not_enabled_for_this_app"] = hidden
        out["note"] = (f"{LABELS[provider]} is not enabled for your account, so {hidden} of your "
                       "data sources are hidden. Enable it on the Connect page: "
                       f"{get_settings().public_base_url.rstrip('/')}/account/connect")
    return out
