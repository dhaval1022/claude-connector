"""Web UI for users to connect and manage their own data sources."""
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import DataSource
from app.db.session import get_session
from app.semantic import service as semantic
from app.sources import service
from app.sources.service import flat_tables
from app.ui.routes import Ctx, _check_csrf, _page, _require

router = APIRouter()


async def _list(request, ctx, db, notice="", error="", form=None):
    sources = (await db.execute(select(DataSource).where(DataSource.owner_id == ctx.user.id)
                                .order_by(DataSource.name))).scalars().all()
    return _page(request, "sources.html", ctx, sources=sources, notice=notice, error=error,
                 engines=service.available_engines(), form=form or {})


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
                     context: str = Form(""),
                     csrf: str = Form(),
                     ctx: Ctx = Depends(_require), db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    form = dict(name=name, engine=engine, host=host, port=port, database=database,
                username=username, trust_server_cert=trust_server_cert, region=region,
                s3_output=s3_output, workgroup=workgroup,
                access_key_id=access_key_id, context=context)  # never echo secrets
    try:
        cfg = service.parse_config(engine, {**form, "password": password,
                                            "secret_access_key": secret_access_key})
        src = await service.create_source(db, ctx.user.id, name, engine, cfg)
        if context.strip():
            await semantic.set_database_note(ctx.user.id, src.id, context.strip())
    except service.SourceError as e:
        return await _list(request, ctx, db, error=str(e), form=form)
    return await _list(request, ctx, db, notice=f"Connected '{name}'. Schema loaded.")


@router.post("/sources/upload")
async def source_upload(request: Request, name: str = Form(), context: str = Form(""), csrf: str = Form(),
                        files: list[UploadFile] = File(default=[]),
                        ctx: Ctx = Depends(_require), db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    real = [(f.filename or "", f) for f in files if f.filename]
    try:
        src = await service.create_file_source(db, ctx.user.id, name, real)
        if context.strip():
            await semantic.set_database_note(ctx.user.id, src.id, context.strip())
    except service.SourceError as e:
        return await _list(request, ctx, db, error=str(e), form={"name": name, "context": context})
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


@router.get("/sources/{source_id}/context")
async def source_context(request: Request, source_id: str, notice: str = "", error: str = "",
                         ctx: Ctx = Depends(_require), db: AsyncSession = Depends(get_session)):
    src = await _owned_or_404(db, ctx, source_id)
    db_context = await semantic.database_note(ctx.user.id, src.id)
    t_notes = await semantic.table_notes_for_source(ctx.user.id, src.id)
    tables = []
    if src.schema_cache:
        for s, t, info in flat_tables(src.schema_cache):
            full = f"{s}.{t}" if s else t
            note = t_notes.get(t.lower()) or (t_notes.get(full.lower()) if s else "")
            tables.append({
                "schema": s, "table": t, "full_name": full,
                "kind": info.get("kind", "table"),
                "columns_count": len(info.get("columns", [])),
                "context": note or ""
            })
    return _page(request, "context.html", ctx, source=src, database_context=db_context or "",
                 tables=tables, notice=notice, error=error)


@router.post("/sources/{source_id}/context/database")
async def source_context_database_save(request: Request, source_id: str,
                                       description: str = Form(""),
                                       csrf: str = Form(), ctx: Ctx = Depends(_require),
                                       db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    src = await _owned_or_404(db, ctx, source_id)
    await semantic.set_database_note(ctx.user.id, src.id, description)
    return RedirectResponse(f"/sources/{src.id}/context?notice=Database+context+updated.",
                            status_code=303)


@router.post("/sources/{source_id}/context/table")
async def source_context_table_save(request: Request, source_id: str, table: str = Form(),
                                    description: str = Form(""), csrf: str = Form(),
                                    ctx: Ctx = Depends(_require),
                                    db: AsyncSession = Depends(get_session)):
    _check_csrf(ctx, csrf)
    src = await _owned_or_404(db, ctx, source_id)
    t = table.strip()
    if not t:
        raise HTTPException(400, "Table name is required")
    await semantic.set_table_note(ctx.user.id, src.id, t, description)
    return RedirectResponse(f"/sources/{src.id}/context?notice=Table+context+for+'{t}'+updated.",
                            status_code=303)

