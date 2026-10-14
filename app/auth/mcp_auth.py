"""ASGI middleware: require a valid Bearer token on /mcp and bind the user to the request."""
import json

from app.auth.tokens import verify_access_token
from app.config import get_settings
from app.db.models import User
from app.db.session import SessionLocal
from app.mcp_tools.server import current_user_id


class McpAuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def _deny(self, send, status=401):
        meta = get_settings().public_base_url.rstrip("/") + "/.well-known/oauth-protected-resource"
        body = json.dumps({"error": "unauthorized"}).encode()
        await send({"type": "http.response.start", "status": status, "headers": [
            (b"content-type", b"application/json"),
            (b"www-authenticate", f'Bearer resource_metadata="{meta}"'.encode())]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        auth = dict(scope["headers"]).get(b"authorization", b"").decode()
        claims = verify_access_token(auth[7:]) if auth[:7].lower() == "bearer " else None
        if not claims:
            return await self._deny(send)
        async with SessionLocal() as db:  # token revocation on user disable
            user = await db.get(User, claims["sub"])
        if not user or not user.is_active:
            return await self._deny(send)
        reset = current_user_id.set(user.id)
        try:
            await self.app(scope, receive, send)
        finally:
            current_user_id.reset(reset)
