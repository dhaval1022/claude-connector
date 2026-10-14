"""Web UI for users to connect and manage their own data sources."""
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.logger import audit
from app.db.models import DataSource
from app.providers import LABELS, clean_allowed
from app.db.session import get_session
from app.sources import service
from app.ui.routes import Ctx, _check_csrf, _page, _require

router = APIRouter()


async def _list(request, ctx, db, notice="", error="", form=None):
    sources = (await db.execute(select(DataSource).where(DataSource.owner_id == ctx.user.id)
                                .order_by(DataSource.name))).scalars().all()
    return _page(request, "sources.html", ctx, sources=sources, notice=notice, error=error,
                 engines=service.available_engines(), form=form or {}, providers=LABELS)


@router.get("/sources")
async def sources_list(request: Request, ctx: Ctx = Depends(_require),
                       db: AsyncSession = Depends(get_session)):
    return await _list(request, ctx, db)


@router.post("/sources")
async def source_add(request: Request, name: str = Form(), engine: str = Form(),
                     host: str = Form(""), port: str = Form(""), database: str = Form(),
                     username: str = Form(""), password: str = Form(""),
                     trust_server_cert: str = Form(""), region: str = Form(""),
                     s3_output: str = Form(""), workgroup: str = Form(""),
                     access_key_id: str = Form(""), secret_access_key: str = Form(""),
                     csrf: str = Form(),
                     ctx: Ctx = Depends(_require), db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    form = dict(name=name, engine=engine, host=host, port=port, database=database,
                username=username, trust_server_cert=trust_server_cert, region=region,
                s3_output=s3_output, workgroup=workgroup,
                access_key_id=access_key_id)  # never echo secrets
    try:
        cfg = service.parse_config(engine, {**form, "password": password,
                                            "secret_access_key": secret_access_key})
        await service.create_source(db, ctx.user.id, name, engine, cfg)
    except service.SourceError as e:
        return await _list(request, ctx, db, error=str(e), form=form)
    return await _list(request, ctx, db, notice=f"Connected '{name}'. Schema loaded.")


@router.post("/sources/upload")
async def source_upload(request: Request, name: str = Form(), csrf: str = Form(),
                        files: list[UploadFile] = File(default=[]),
                        ctx: Ctx = Depends(_require), db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    real = [(f.filename or "", f) for f in files if f.filename]
    try:
        src = await service.create_file_source(db, ctx.user.id, name, real)
    except service.SourceError as e:
        return await _list(request, ctx, db, error=str(e), form={"name": name})
    tables = sum(len(t) for t in src.schema_cache["schemas"].values())
    return await _list(request, ctx, db, notice=f"Loaded '{name}': {tables} table(s) from "
                                                f"{len(real)} file(s).")


async def _owned_or_404(db, ctx, source_id) -> DataSource:
    src = await service.get_owned(db, ctx.user.id, source_id)
    if not src:
        raise HTTPException(404)
    return src


@router.post("/sources/{source_id}/refresh")
async def source_refresh(request: Request, source_id: str, csrf: str = Form(),
                         ctx: Ctx = Depends(_require), db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    src = await _owned_or_404(db, ctx, source_id)
    try:
        await service.refresh_schema(db, src)
    except service.SourceError as e:
        return await _list(request, ctx, db, error=str(e))
    return await _list(request, ctx, db, notice=f"Schema refreshed for '{src.name}'.")


@router.post("/sources/{source_id}/providers")
async def source_providers(request: Request, source_id: str, csrf: str = Form(),
                           providers: list[str] = Form(default=[]),
                           ctx: Ctx = Depends(_require), db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    src = await _owned_or_404(db, ctx, source_id)
    old, new = list(src.allowed_providers or []), clean_allowed(providers)
    src.allowed_providers = new
    await db.commit()
    await audit(user_id=ctx.user.id, tool="ui:set_providers", source_id=src.id, status="ok",
                sql=f"allowed_providers: {old} -> {new}")
    extra = [LABELS[p] for p in new if p != "claude"]
    msg = (f"'{src.name}' is now usable from: {', '.join(LABELS[p] for p in new) or 'no app'}.")
    if extra:
        msg += (" Query results from this source will be sent to " + ", ".join(extra) + ".")
    return await _list(request, ctx, db, notice=msg)


@router.post("/sources/{source_id}/masked")
async def source_masked(request: Request, source_id: str, columns: str = Form(""),
                        csrf: str = Form(), ctx: Ctx = Depends(_require),
                        db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    src = await _owned_or_404(db, ctx, source_id)
    src.masked_columns = sorted({c.strip().lower() for c in columns.replace("\n", ",").split(",")
                                 if c.strip()})
    await db.commit()
    return await _list(request, ctx, db, notice=f"Masked columns updated for '{src.name}'.")


@router.post("/sources/{source_id}/delete")
async def source_delete(source_id: str, csrf: str = Form(), ctx: Ctx = Depends(_require),
                        db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    if not await service.delete_source(db, ctx.user.id, source_id):
        raise HTTPException(404)
    return RedirectResponse("/sources", status_code=303)
