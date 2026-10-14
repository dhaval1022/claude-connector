import asyncio
import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import text
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import maintenance
from app.bootstrap import ensure_bootstrap_admin
from app.auth.mcp_auth import McpAuthMiddleware
from app.auth.oauth_server import router as oauth_router
from app.config import get_settings
from app.db.session import engine
from app.exports.routes import router as exports_router
from app.mcp_tools import analysis, data, exports, scripts, semantic  # noqa: F401
from app.mcp_tools.server import mcp
from app.observability import (RequestContextMiddleware, allowed_hosts, configure_logging,
                               metrics_body)
from app.ui.audit_routes import router as audit_router
from app.ui.routes import router as ui_router
from app.ui.sources_routes import router as sources_router

mcp_app = mcp.streamable_http_app()  # creates the session manager used below


@asynccontextmanager
async def lifespan(_: FastAPI):
    configure_logging()
    s = get_settings()
    if not s.jwt_secret or len(s.jwt_secret) < 32:
        raise RuntimeError("CONNECTOR_JWT_SECRET must be set to a random string of 32+ chars")
    if not s.master_key:
        raise RuntimeError("CONNECTOR_MASTER_KEY is not set (python -m app.cli gen-key)")
    await ensure_bootstrap_admin()
    task = asyncio.create_task(maintenance.loop())
    try:
        async with mcp.session_manager.run():
            yield
    finally:
        task.cancel()


app = FastAPI(title="Medkart Data Connector", lifespan=lifespan, docs_url=None, redoc_url=None,
              openapi_url=None)
app.include_router(oauth_router)
app.include_router(ui_router)
app.include_router(sources_router)
app.include_router(audit_router)
app.include_router(exports_router)
app.mount("/mcp", McpAuthMiddleware(mcp_app))
# Order matters: the last middleware added is the outermost.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts())
app.add_middleware(RequestContextMiddleware)


@app.get("/healthz")
async def healthz() -> dict:
    """Liveness: the process is up."""
    return {"status": "ok"}


@app.get("/readyz")
async def readyz():
    """Readiness: the metadata database answers."""
    try:
        async with engine.connect() as c:
            await c.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse({"status": "unavailable"}, status_code=503)
    return {"status": "ready"}


@app.get("/metrics")
async def metrics(request: Request):
    """Prometheus metrics. Disabled (404) unless CONNECTOR_METRICS_TOKEN is set."""
    token = get_settings().metrics_token
    if not token:
        raise HTTPException(404)
    given = request.headers.get("authorization", "")
    if not secrets.compare_digest(given, f"Bearer {token}"):
        raise HTTPException(401, headers={"WWW-Authenticate": "Bearer"})
    body, ctype = metrics_body()
    return Response(body, media_type=ctype)
