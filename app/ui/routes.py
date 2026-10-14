"""Server-rendered web UI: login, account password change, admin user management."""
import secrets
import time
from pathlib import Path

import jwt
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.login import MIN_PASSWORD_LEN, authenticate
from app.auth.passwords import hash_password, verify_password
from app.config import get_settings
from app.ratelimit import ip_limit
from app.db.models import RefreshToken, User
from app.db.session import get_session

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
COOKIE = "session"
SESSION_TTL = 8 * 3600
ROLES = ("admin", "analyst")


def _make_session(user: User) -> str:
    now = int(time.time())
    return jwt.encode({"sub": user.id, "csrf": secrets.token_urlsafe(24), "iat": now,
                       "exp": now + SESSION_TTL}, get_settings().jwt_secret, algorithm="HS256")


def _set_cookie(resp, token: str):
    resp.set_cookie(COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax",
                    secure=get_settings().public_base_url.startswith("https"))


class Ctx:
    """Resolved session for a request: the user plus the CSRF token for its forms."""
    def __init__(self, user: User, csrf: str):
        self.user, self.csrf = user, csrf


async def _ctx(request: Request, db: AsyncSession) -> Ctx | None:
    raw = request.cookies.get(COOKIE)
    if not raw:
        return None
    try:
        claims = jwt.decode(raw, get_settings().jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    user = await db.get(User, claims["sub"])
    return Ctx(user, claims["csrf"]) if user and user.is_active else None


async def _require(request: Request, db: AsyncSession = Depends(get_session)) -> Ctx:
    ctx = await _ctx(request, db)
    if not ctx:
        raise HTTPException(303, headers={"Location": "/login"})
    if ctx.user.must_change_password and request.url.path != "/account/password":
        raise HTTPException(303, headers={"Location": "/account/password"})
    return ctx


async def _admin(ctx: Ctx = Depends(_require)) -> Ctx:
    if ctx.user.role != "admin":
        raise HTTPException(403, "Admin only")
    return ctx


def _check_csrf(ctx: Ctx, token: str):
    if not secrets.compare_digest(ctx.csrf, token):
        raise HTTPException(403, "Bad CSRF token")


def _page(request, name, ctx=None, **kw):
    resp = templates.TemplateResponse(request, name, {"ctx": ctx, **kw})
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'"
    return resp


@router.get("/")
async def home():
    return RedirectResponse("/sources", status_code=303)


@router.get("/login")
async def login_form(request: Request):
    return _page(request, "login.html", error="")


@router.post("/login", dependencies=[Depends(ip_limit("login", "rate_login_per_min_ip"))])
async def login(request: Request, email: str = Form(), password: str = Form(),
                db: AsyncSession = Depends(get_session)):
    user, error = await authenticate(db, email, password)
    if not user:
        return _page(request, "login.html", error=error)
    resp = RedirectResponse("/sources", status_code=303)
    _set_cookie(resp, _make_session(user))
    return resp


@router.post("/logout")
async def logout(ctx: Ctx = Depends(_require), csrf: str = Form()):
    _check_csrf(ctx, csrf)
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(COOKIE)
    return resp


@router.get("/account/password")
async def password_form(request: Request, ctx: Ctx = Depends(_require)):
    return _page(request, "password.html", ctx, error="")


@router.post("/account/password")
async def password_change(request: Request, current: str = Form(), new: str = Form(),
                          csrf: str = Form(), ctx: Ctx = Depends(_require),
                          db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    err = ""
    if not verify_password(current, ctx.user.password_hash):
        err = "Current password is incorrect."
    elif len(new) < MIN_PASSWORD_LEN:
        err = f"New password must be at least {MIN_PASSWORD_LEN} characters."
    elif new == current:
        err = "New password must differ from the current one."
    if err:
        return _page(request, "password.html", ctx, error=err)
    user = await db.get(User, ctx.user.id)
    user.password_hash, user.must_change_password = hash_password(new), False
    await db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id)
                     .values(revoked=True))  # sign out Claude sessions after a password change
    await db.commit()
    return RedirectResponse("/admin/users", status_code=303)


async def _users_page(request, ctx, db, notice="", error=""):
    users = (await db.execute(select(User).order_by(User.email))).scalars().all()
    return _page(request, "users.html", ctx, users=users, notice=notice, error=error,
                 roles=ROLES)


@router.get("/admin/users")
async def users_list(request: Request, ctx: Ctx = Depends(_require),
                     db: AsyncSession = Depends(get_session)):
    if ctx.user.role != "admin":
        return _page(request, "home.html", ctx)
    return await _users_page(request, ctx, db)


@router.post("/admin/users")
async def user_create(request: Request, email: str = Form(), name: str = Form(),
                      role: str = Form("analyst"), csrf: str = Form(),
                      ctx: Ctx = Depends(_admin), db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    email = email.strip().lower()
    if role not in ROLES or "@" not in email or not name.strip():
        return await _users_page(request, ctx, db, error="Enter a valid email, name and role.")
    temp = secrets.token_urlsafe(12)
    db.add(User(email=email, name=name.strip(), role=role, password_hash=hash_password(temp),
                must_change_password=True))
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return await _users_page(request, ctx, db, error=f"{email} already exists.")
    return await _users_page(
        request, ctx, db, notice=f"Created {email}. Temporary password (shown once): {temp}")


@router.post("/admin/users/{user_id}/toggle")
async def user_toggle(request: Request, user_id: str, csrf: str = Form(),
                      ctx: Ctx = Depends(_admin), db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(404)
    if user.id == ctx.user.id:
        return await _users_page(request, ctx, db, error="You cannot disable your own account.")
    user.is_active = not user.is_active
    if not user.is_active:  # cut off any connected Claude sessions immediately
        await db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id)
                         .values(revoked=True))
    await db.commit()
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/admin/users/{user_id}/reset")
async def user_reset(request: Request, user_id: str, csrf: str = Form(),
                     ctx: Ctx = Depends(_admin), db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(404)
    temp = secrets.token_urlsafe(12)
    user.password_hash, user.must_change_password = hash_password(temp), True
    user.failed_logins, user.locked_until = 0, None
    await db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id)
                     .values(revoked=True))
    await db.commit()
    return await _users_page(
        request, ctx, db, notice=f"Password reset for {user.email}. Temporary password "
                                 f"(shown once): {temp}")
