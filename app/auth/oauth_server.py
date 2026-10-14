"""Minimal OAuth 2.1 authorization server (auth-code + PKCE S256, DCR, refresh rotation)
for Claude custom connectors."""
import base64
import hashlib
import html
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.login import authenticate
from app.auth.tokens import aware, issue_access_token, random_token, sha256
from app.config import get_settings
from app.ratelimit import ip_limit
from app.db.models import OAuthClient, OAuthCode, RefreshToken, User
from app.db.session import get_session

router = APIRouter()


def _base() -> str:
    return get_settings().public_base_url.rstrip("/")


LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _redirect_allowed(uri: str) -> bool:
    """Structural match, never a string prefix: 'http://localhost.evil.com' and
    'http://localhost@evil.com' must NOT pass for an allowed 'http://localhost'.
    - loopback entries allow any port/path on exactly that loopback host (native/CLI clients)
    - other entries must match scheme + host + port exactly, and the path exactly or below it"""
    try:
        u = urlsplit(uri)
        host, port = u.hostname, u.port
    except ValueError:
        return False
    if (u.scheme not in ("https", "http") or not host or u.username is not None
            or u.password is not None or u.fragment or ".." in u.path or "\\" in uri
            or any(ord(ch) < 33 for ch in uri)):
        return False
    for entry in get_settings().allowed_redirect_prefixes:
        a = urlsplit(entry)
        if a.hostname in LOOPBACK_HOSTS:
            if u.scheme == "http" and host == a.hostname and (a.port is None or port == a.port):
                return True
            continue
        if (u.scheme, host, port) == (a.scheme, a.hostname, a.port):
            base = a.path.rstrip("/")
            if u.path == a.path or u.path == base or u.path.startswith(base + "/"):
                return True
    return False


@router.get("/.well-known/oauth-protected-resource")
async def protected_resource():
    return {"resource": _base() + "/mcp", "authorization_servers": [_base()],
            "bearer_methods_supported": ["header"]}


@router.get("/.well-known/oauth-authorization-server")
async def as_metadata():
    b = _base()
    return {
        "issuer": b,
        "authorization_endpoint": f"{b}/oauth/authorize",
        "token_endpoint": f"{b}/oauth/token",
        "registration_endpoint": f"{b}/oauth/register",
        "revocation_endpoint": f"{b}/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }


@router.post("/oauth/register", dependencies=[Depends(ip_limit("register", "rate_token_per_min_ip"))])
async def register(request: Request, db: AsyncSession = Depends(get_session)):
    body = await request.json()
    uris = body.get("redirect_uris") or []
    if not uris or not all(isinstance(u, str) and _redirect_allowed(u) for u in uris):
        return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)
    client = OAuthClient(client_name=str(body.get("client_name", ""))[:255], redirect_uris=uris)
    db.add(client)
    await db.commit()
    return JSONResponse({
        "client_id": client.client_id, "client_name": client.client_name,
        "redirect_uris": uris, "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"], "token_endpoint_auth_method": "none",
    }, status_code=201)


_LOGIN = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width">
<title>Sign in</title>
<style>body{{font:16px system-ui;max-width:360px;margin:12vh auto;padding:0 16px}}
input,button{{width:100%;padding:10px;margin:6px 0;box-sizing:border-box}}.e{{color:#b00}}</style>
<h2>Medkart Data Connector</h2><p>Sign in to authorize <b>{client}</b>.</p>
<p class=e>{error}</p>
<form method=post action="/oauth/authorize">{hidden}
<input name=email type=email placeholder=Email required autofocus>
<input name=password type=password placeholder=Password required>
<button>Sign in &amp; authorize</button></form>"""


def _render(params: dict, client_name: str, error: str = "") -> HTMLResponse:
    hidden = "".join(
        f'<input type=hidden name="{html.escape(k)}" value="{html.escape(v)}">'
        for k, v in params.items())
    return HTMLResponse(_LOGIN.format(client=html.escape(client_name or "an application"),
                                      error=html.escape(error), hidden=hidden),
                        headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"})


async def _validate_authz(db, client_id, redirect_uri, challenge, method, response_type):
    client = await db.get(OAuthClient, client_id)
    if not client or redirect_uri not in client.redirect_uris:
        raise HTTPException(400, "invalid client or redirect_uri")
    if response_type != "code" or method != "S256" or not challenge:
        raise HTTPException(400, "PKCE S256 and response_type=code required")
    return client


@router.get("/oauth/authorize")
async def authorize_get(client_id: str, redirect_uri: str, code_challenge: str,
                        response_type: str = "code", code_challenge_method: str = "S256",
                        state: str = "", db: AsyncSession = Depends(get_session)):
    client = await _validate_authz(db, client_id, redirect_uri, code_challenge,
                                   code_challenge_method, response_type)
    return _render({"client_id": client_id, "redirect_uri": redirect_uri,
                    "code_challenge": code_challenge, "state": state}, client.client_name)


@router.post("/oauth/authorize", dependencies=[Depends(ip_limit("login", "rate_login_per_min_ip"))])
async def authorize_post(client_id: str = Form(), redirect_uri: str = Form(),
                         code_challenge: str = Form(), state: str = Form(""),
                         email: str = Form(), password: str = Form(),
                         db: AsyncSession = Depends(get_session)):
    client = await _validate_authz(db, client_id, redirect_uri, code_challenge, "S256", "code")
    params = {"client_id": client_id, "redirect_uri": redirect_uri,
              "code_challenge": code_challenge, "state": state}
    now = datetime.now(timezone.utc)
    user, error = await authenticate(db, email, password)
    if not user:
        return _render(params, client.client_name, error)
    code = random_token()
    db.add(OAuthCode(code_hash=sha256(code), client_id=client_id, user_id=user.id,
                     redirect_uri=redirect_uri, code_challenge=code_challenge,
                     expires_at=now + timedelta(minutes=5)))
    await db.commit()
    q = {"code": code, **({"state": state} if state else {})}
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(q)}", status_code=303)


def _err(error: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": error}, status_code=status,
                        headers={"Cache-Control": "no-store"})


async def _mint(db, user_id: str, client_id: str) -> JSONResponse:
    s = get_settings()
    refresh = random_token()
    db.add(RefreshToken(token_hash=sha256(refresh), client_id=client_id, user_id=user_id,
                        expires_at=datetime.now(timezone.utc)
                        + timedelta(seconds=s.refresh_token_ttl_s)))
    await db.commit()
    return JSONResponse({"access_token": issue_access_token(user_id, client_id),
                         "token_type": "Bearer", "expires_in": s.access_token_ttl_s,
                         "refresh_token": refresh},
                        headers={"Cache-Control": "no-store"})


@router.post("/oauth/token", dependencies=[Depends(ip_limit("token", "rate_token_per_min_ip"))])
async def token(grant_type: str = Form(), client_id: str = Form(),
                code: str = Form(""), redirect_uri: str = Form(""),
                code_verifier: str = Form(""), refresh_token: str = Form(""),
                db: AsyncSession = Depends(get_session)):
    now = datetime.now(timezone.utc)
    if grant_type == "authorization_code":
        rec = await db.get(OAuthCode, sha256(code))
        if (not rec or rec.used or rec.client_id != client_id
                or rec.redirect_uri != redirect_uri or aware(rec.expires_at) < now):
            return _err("invalid_grant")
        rec.used = True
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
        if not secrets.compare_digest(digest, rec.code_challenge):
            await db.commit()
            return _err("invalid_grant")
        user = await db.get(User, rec.user_id)
        if not user or not user.is_active:
            return _err("invalid_grant")
        return await _mint(db, user.id, client_id)
    if grant_type == "refresh_token":
        rec = await db.get(RefreshToken, sha256(refresh_token))
        if not rec or rec.client_id != client_id or aware(rec.expires_at) < now:
            return _err("invalid_grant")
        if rec.revoked:  # replay of a rotated token: revoke the user's whole client session
            for t in (await db.execute(select(RefreshToken).where(
                    RefreshToken.user_id == rec.user_id,
                    RefreshToken.client_id == client_id))).scalars():
                t.revoked = True
            await db.commit()
            return _err("invalid_grant")
        user = await db.get(User, rec.user_id)
        if not user or not user.is_active:
            return _err("invalid_grant")
        rec.revoked = True  # rotation
        return await _mint(db, user.id, client_id)
    return _err("unsupported_grant_type")


@router.post("/oauth/revoke")
async def revoke(token: str = Form(), db: AsyncSession = Depends(get_session)):
    rec = await db.get(RefreshToken, sha256(token))
    if rec:
        rec.revoked = True
        await db.commit()
    return JSONResponse({})
