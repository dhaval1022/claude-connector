"""Personal API tokens page: create (shown once), list, revoke."""
import json

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.logger import audit
from app.auth import api_tokens
from app.config import get_settings
from app.db.session import get_session
from app.providers import LABELS, PROVIDERS
from app.ui.routes import Ctx, _check_csrf, _page, _require

router = APIRouter()


def snippet(provider: str, token: str) -> str:
    """Copy-paste connection config for the chosen app (the token is shown once, here)."""
    url = get_settings().public_base_url.rstrip("/") + "/mcp"
    if provider == "openai":
        return ("# OpenAI Responses API: remote MCP tool\n" + json.dumps({
            "type": "mcp", "server_label": "medkart", "server_url": url,
            "authorization": token, "require_approval": "always"}, indent=2))
    if provider == "gemini":
        return ("// Gemini CLI: ~/.gemini/settings.json\n" + json.dumps({
            "mcpServers": {"medkart": {"httpUrl": url,
                                       "headers": {"Authorization": f"Bearer {token}"}}}},
            indent=2))
    return f"URL:    {url}\nHeader: Authorization: Bearer {token}"


async def _page_tokens(request, ctx, db, error="", created=None):
    rows = await api_tokens.list_tokens(db, ctx.user.id)
    return _page(request, "tokens.html", ctx, tokens=rows, labels=LABELS, providers=PROVIDERS,
                 lifetimes=api_tokens.LIFETIMES_DAYS, error=error, created=created,
                 max_active=api_tokens.MAX_ACTIVE)


@router.get("/account/connect")
async def connect_info(request: Request, ctx: Ctx = Depends(_require)):
    """Values to paste into an AI app's custom-connector form (no secrets here)."""
    s = get_settings()
    base = s.public_base_url.rstrip("/")
    return _page(request, "connect.html", ctx, mcp_url=base + "/mcp", base=base,
                 gemini_client_id=s.gemini_client_id)


@router.get("/account/tokens")
async def tokens_list(request: Request, ctx: Ctx = Depends(_require),
                      db: AsyncSession = Depends(get_session)):
    return await _page_tokens(request, ctx, db)


@router.post("/account/tokens")
async def token_create(request: Request, name: str = Form(""), provider: str = Form(""),
                       days: int = Form(90), csrf: str = Form(), ctx: Ctx = Depends(_require),
                       db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    try:
        plain, row = await api_tokens.create_token(db, ctx.user, name, provider, days)
    except api_tokens.TokenError as e:
        return await _page_tokens(request, ctx, db, error=str(e))
    await audit(user_id=ctx.user.id, tool="ui:create_api_token", status="ok", provider=provider,
                sql=f"token {row.prefix}... name={row.name!r} expires={row.expires_at:%Y-%m-%d}")
    return await _page_tokens(request, ctx, db, created={
        "name": row.name, "token": plain, "snippet": snippet(provider, plain),
        "expires": row.expires_at.strftime("%Y-%m-%d")})


@router.post("/account/tokens/{token_id}/revoke")
async def token_revoke(request: Request, token_id: str, csrf: str = Form(),
                       ctx: Ctx = Depends(_require), db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    if not await api_tokens.revoke_token(db, ctx.user.id, token_id):
        raise HTTPException(404)
    await audit(user_id=ctx.user.id, tool="ui:revoke_api_token", status="ok",
                sql=f"token id {token_id}")
    return await _page_tokens(request, ctx, db)
