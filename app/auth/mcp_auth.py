"""ASGI middleware: require a valid Bearer token on /mcp and bind user + provider to the request.

Two kinds of bearer token are accepted:
  * an OAuth access token (JWT) issued by our authorization server, or
  * a personal API token (`mk_...`, app/auth/api_tokens.py) for clients that send a static token.
"""
import json

from app.auth import api_tokens
from app.auth.tokens import verify_access_token
from app.config import get_settings
from app.context import current_provider, current_user_id
from app.db.models import User
from app.db.session import SessionLocal
from app.providers import normalize
from app.ratelimit import LIMITER


class McpAuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def _deny(self, send, status=401):
        meta = get_settings().public_base_url.rstrip("/") + "/.well-known/oauth-protected-resource"
        body = json.dumps({"error": "unauthorized" if status == 401 else "rate_limited"}).encode()
        headers = [(b"content-type", b"application/json")]
        if status == 401:
            headers.append((b"www-authenticate", f'Bearer resource_metadata="{meta}"'.encode()))
        else:
            headers.append((b"retry-after", b"60"))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    @staticmethod
    async def _identify(token: str) -> tuple[str, str] | None:
        """(user_id, provider) for a valid token, else None."""
        if api_tokens.looks_like_token(token):
            async with SessionLocal() as db:
                found = await api_tokens.authenticate_token(db, token)
            return (found[0].id, normalize(found[1].provider)) if found else None
        claims = verify_access_token(token)
        if not claims:
            return None
        async with SessionLocal() as db:  # access is cut off as soon as the user is disabled
            user = await db.get(User, claims["sub"])
        if not user or not user.is_active:
            return None
        # Tokens issued before providers existed carry no `prv`: they were Claude's.
        return user.id, normalize(claims.get("prv"))

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        auth = dict(scope["headers"]).get(b"authorization", b"").decode()
        ident = (await self._identify(auth[7:].strip())
                 if auth[:7].lower() == "bearer " else None)
        if not ident:
            ip = (scope.get("client") or ("-",))[0]
            # throttle repeated bad credentials per address (a missing header is not an attack)
            if auth and LIMITER.hit(f"mcp-badauth:{ip}", 60, 60) is not None:
                return await self._deny(send, 429)
            return await self._deny(send)
        user_id, provider = ident
        r1, r2 = current_user_id.set(user_id), current_provider.set(provider)
        try:
            await self.app(scope, receive, send)
        finally:
            current_provider.reset(r2)
            current_user_id.reset(r1)
