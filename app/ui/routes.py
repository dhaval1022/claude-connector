"""Server-rendered web UI: login, account password change, admin user management."""
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

import jwt
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.logger import audit
from app.auth.login import MIN_PASSWORD_LEN, authenticate
from app.auth.passwords import hash_password, verify_password
from app.config import get_settings
from app.db.models import RefreshToken, User
from app.db.session import get_session
from app.providers import LABELS, clean_allowed
from app.ratelimit import ip_limit

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
COOKIE = "session"
SESSION_TTL = 8 * 3600
ROLES = ("admin", "analyst")


def _make_session(user: User) -> str:
    now = int(time.time())
    return jwt.encode({"sub": str(user.id), "csrf": secrets.token_urlsafe(24), "iat": now,
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
    sub = claims.get("sub")
    if sub is None:
        return None
    try:
        uid = int(sub)
    except (ValueError, TypeError):
        uid = sub
    user = await db.get(User, uid)
    return Ctx(user, claims["csrf"]) if user and user.is_active and not user.deleted_at else None


async def _require(request: Request, db: AsyncSession = Depends(get_session)) -> Ctx:
    ctx = await _ctx(request, db)
    if not ctx:
        raise HTTPException(303, headers={"Location": "/login"})
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
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:"
    )
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
    user.password_hash = hash_password(new)
    user.updated_at = datetime.now(timezone.utc)
    user.updated_by = ctx.user.id
    await db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id)
                     .values(revoked=True))  # sign out Claude sessions after a password change
    await db.commit()
    return RedirectResponse("/admin/users", status_code=303)


async def _users_page(request, ctx, db, notice="", error=""):
    users = (await db.execute(select(User).where(User.deleted_at.is_(None)).order_by(User.email))).scalars().all()
    return _page(request, "users.html", ctx, users=users, notice=notice, error=error,
                 roles=ROLES, providers=LABELS)


@router.get("/admin/users")
async def users_list(request: Request, notice: str = "", error: str = "",
                     ctx: Ctx = Depends(_require),
                     db: AsyncSession = Depends(get_session)):
    if ctx.user.role != "admin":
        return _page(request, "home.html", ctx)
    return await _users_page(request, ctx, db, notice=notice, error=error)


@router.post("/admin/users")
async def user_create(request: Request, email: str = Form(), name: str = Form(),
                      role: str = Form("analyst"), providers: list[str] = Form(default=["claude"]),
                      csrf: str = Form(),
                      ctx: Ctx = Depends(_admin), db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    email = email.strip().lower()
    if role not in ROLES or "@" not in email or not name.strip():
        return await _users_page(request, ctx, db, error="Enter a valid email, name and role.")
    temp = secrets.token_urlsafe(12)
    allowed = clean_allowed(providers) or ["claude"]
    db.add(User(email=email, name=name.strip()[:50], role=role, password_hash=hash_password(temp),
                allowed_providers=allowed, created_by=ctx.user.id))
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return await _users_page(request, ctx, db, error=f"{email} already exists.")
    return await _users_page(
        request, ctx, db, notice=f"Created {email}. Password: {temp}")


@router.post("/admin/users/{user_id}/providers")
async def user_set_providers(request: Request, user_id: str, csrf: str = Form(),
                             providers: list[str] = Form(default=[]),
                             ctx: Ctx = Depends(_admin), db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    user = await db.get(User, int(user_id) if str(user_id).isdigit() else user_id)
    if not user or user.deleted_at:
        raise HTTPException(404)
    old, new = list(user.allowed_providers or []), clean_allowed(providers)
    user.allowed_providers = new
    user.updated_at = datetime.now(timezone.utc)
    user.updated_by = ctx.user.id
    await db.commit()
    await audit(user_id=ctx.user.id, tool="admin:set_user_providers", status="ok",
                sql=f"user {user.email} allowed_providers: {old} -> {new}")
    return RedirectResponse(f"/admin/users?notice=Updated+AI+app+permissions+for+{user.email}", status_code=303)


@router.post("/admin/users/{user_id}/toggle")
async def user_toggle(request: Request, user_id: str, csrf: str = Form(),
                      ctx: Ctx = Depends(_admin), db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    user = await db.get(User, int(user_id) if str(user_id).isdigit() else user_id)
    if not user or user.deleted_at:
        raise HTTPException(404)
    if user.id == ctx.user.id:
        return await _users_page(request, ctx, db, error="You cannot disable your own account.")
    user.is_active = not user.is_active
    user.updated_at = datetime.now(timezone.utc)
    user.updated_by = ctx.user.id
    if not user.is_active:  # cut off any connected Claude sessions immediately
        await db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id)
                         .values(revoked=True))
    await db.commit()
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/admin/users/{user_id}/reset")
async def user_reset(request: Request, user_id: str, csrf: str = Form(),
                     ctx: Ctx = Depends(_admin), db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    user = await db.get(User, int(user_id) if str(user_id).isdigit() else user_id)
    if not user or user.deleted_at:
        raise HTTPException(404)
    temp = secrets.token_urlsafe(12)
    user.password_hash = hash_password(temp)
    user.locked_until = None
    user.updated_at = datetime.now(timezone.utc)
    user.updated_by = ctx.user.id
    await db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id)
                     .values(revoked=True))
    await db.commit()
    return await _users_page(
        request, ctx, db, notice=f"Password reset for {user.email}. New password: {temp}")


@router.post("/admin/users/{user_id}/delete")
async def user_delete(request: Request, user_id: str, csrf: str = Form(),
                      ctx: Ctx = Depends(_admin), db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    user = await db.get(User, int(user_id) if str(user_id).isdigit() else user_id)
    if not user or user.deleted_at:
        raise HTTPException(404)
    if user.id == ctx.user.id:
        return await _users_page(request, ctx, db, error="You cannot delete your own account.")
    now = datetime.now(timezone.utc)
    user.deleted_at = now
    user.deleted_by = ctx.user.id
    user.is_active = False
    await db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id)
                     .values(revoked=True))
    await db.commit()
    await audit(user_id=ctx.user.id, tool="admin:delete_user", status="ok",
                sql=f"soft-deleted user {user.email}")
    return RedirectResponse(f"/admin/users?notice=User+{user.email}+deleted.", status_code=303)

