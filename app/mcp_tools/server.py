from contextvars import ContextVar

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from sqlalchemy import select

from app.db.models import DataSource
from app.db.session import SessionLocal

current_user_id: ContextVar[str] = ContextVar("current_user_id")

mcp = FastMCP(
    "Medkart Data Connector",
    stateless_http=True,
    json_response=True,
    streamable_http_path="/",
    # Host validation is handled by the reverse proxy / public_base_url.
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


@mcp.tool()
async def list_data_sources() -> list[dict]:
    """List the databases/files the signed-in user has connected.

    Start here: returns each source's id, name, engine and status. Use the id in
    all other tools. Only the caller's own sources are ever returned."""
    async with SessionLocal() as db:
        rows = (await db.execute(
            select(DataSource).where(DataSource.owner_id == current_user_id.get())
            .order_by(DataSource.name))).scalars()
        return [{"id": r.id, "name": r.name, "engine": r.engine, "status": r.status,
                 "schema_cached_at": r.schema_cached_at.isoformat()
                 if r.schema_cached_at else None} for r in rows]
