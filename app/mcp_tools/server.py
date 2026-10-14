from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from sqlalchemy import select

from app.config import get_settings
from app.context import current_provider, current_user_id  # noqa: F401  (re-exported for tools)
from app.db.models import DataSource
from app.db.session import SessionLocal
from app.providers import LABELS, is_allowed

mcp = FastMCP(
    "Medkart Data Connector",
    stateless_http=True,
    json_response=True,
    streamable_http_path="/",
    # Host validation is handled by the reverse proxy / public_base_url.
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


@mcp.tool()
async def list_data_sources() -> dict:
    """List the databases/files the signed-in user has connected AND enabled for this app.

    Start here: returns each source's id, name, engine and status. Use the id in all other
    tools. Only the caller's own sources are ever returned. Sources the owner has not enabled
    for this app are not listed; `not_enabled_for_this_app` says how many exist."""
    provider = current_provider.get()
    async with SessionLocal() as db:
        rows = (await db.execute(
            select(DataSource).where(DataSource.owner_id == current_user_id.get())
            .order_by(DataSource.name))).scalars().all()
    visible = [r for r in rows if is_allowed(r.allowed_providers, provider)]
    out: dict = {"data_sources": [
        {"id": r.id, "name": r.name, "engine": r.engine, "status": r.status,
         "schema_cached_at": r.schema_cached_at.isoformat() if r.schema_cached_at else None}
        for r in visible]}
    hidden = len(rows) - len(visible)
    if hidden:
        out["not_enabled_for_this_app"] = hidden
        out["note"] = (f"{hidden} of your data sources are not enabled for {LABELS[provider]}. "
                       "Their owner can enable them on the Data sources page: "
                       f"{get_settings().public_base_url.rstrip('/')}/sources")
    return out
