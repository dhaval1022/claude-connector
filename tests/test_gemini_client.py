"""Built-in Gemini client: fixed client_id, per-user Google redirect accepted only for this server."""
import httpx
import pytest
import pytest_asyncio

from app.auth.oauth_server import gemini_redirect_allowed
from app.config import get_settings
from app.db.models import Base
from app.db.session import engine
from app.main import app

HOST = "claude-connector-c4ce.onrender.com"
GOOD = ("https://oauth-redirect.googleusercontent.com/r/"
        "user_bound_custom-mcp-106010816662739304230-claude-connector-c4ce_onrender_com")


@pytest.fixture(autouse=True)
def public_url(monkeypatch):
    monkeypatch.setattr(get_settings(), "public_base_url", f"https://{HOST}")


@pytest.mark.parametrize("uri,ok", [
    (GOOD, True),
    (GOOD.replace("106010816662739304230", "999"), True),                  # another user
    (GOOD.replace("c4ce_onrender_com", "other_onrender_com"), False),      # another server
    (GOOD.replace("https", "http"), False),
    (GOOD.replace("oauth-redirect", "oauth-redirect.evil"), False),
    (GOOD + "?x=1", False), (GOOD + "/extra", False), (GOOD + "#f", False),
    ("https://oauth-redirect.googleusercontent.com:444/r/user_bound_custom-mcp-1-"
     "claude-connector-c4ce_onrender_com", False),
    ("https://u@oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-1-"
     "claude-connector-c4ce_onrender_com", False),
    ("https://example.com/r/user_bound_custom-mcp-1-claude-connector-c4ce_onrender_com", False),
])
def test_gemini_redirect_allowed(uri, ok):
    assert gemini_redirect_allowed(uri) is ok


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://test") as c:
        yield c


def _q(client_id, redirect):
    return {"client_id": client_id, "redirect_uri": redirect, "code_challenge": "x" * 43,
            "code_challenge_method": "S256", "response_type": "code", "state": "s"}


@pytest.mark.asyncio
async def test_authorize_with_builtin_gemini_client(client):
    cid = get_settings().gemini_client_id
    r = await client.get("/oauth/authorize", params=_q(cid, GOOD))
    assert r.status_code == 200 and "Gemini" in r.text


@pytest.mark.asyncio
async def test_authorize_rejects_unknown_client_or_foreign_redirect(client):
    cid = get_settings().gemini_client_id
    assert (await client.get("/oauth/authorize", params=_q("ds@medkart.in", GOOD))).status_code == 400
    assert (await client.get("/oauth/authorize",
                             params=_q(cid, "https://evil.example/cb"))).status_code == 400
