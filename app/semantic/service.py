from datetime import datetime, timezone

from sqlalchemy import and_, delete, func, select

from app.db.models import SemanticItem
from app.db.session import SessionLocal

KINDS = ("metric", "glossary", "table_note", "column_note", "rule", "database_note")
MAX_NAME, MAX_DESC, MAX_SQL = 160, 2000, 4000


def item_dict(i: SemanticItem) -> dict:
    return {"kind": i.kind, "name": i.name, "description": i.description,
            **({"sql_expression": i.sql_expression} if i.sql_expression else {}),
            "updated_at": i.updated_at.isoformat() if i.updated_at else None}


async def upsert(owner_id: int | str, source_id: int | str, kind: str, name: str, description: str,
                 sql_expression: str | None) -> SemanticItem:
    async with SessionLocal() as db:
        oid, sid = int(owner_id), int(source_id)
        item = (await db.execute(select(SemanticItem).where(
            SemanticItem.created_by == oid, SemanticItem.source_id == sid,
            SemanticItem.kind == kind, func.lower(SemanticItem.name) == name.lower(),
            SemanticItem.deleted_at.is_(None))
        )).scalar_one_or_none()
        now = datetime.now(timezone.utc)
        if item is None:
            item = SemanticItem(created_by=oid, source_id=sid, kind=kind, name=name,
                                description=description, sql_expression=sql_expression)
            db.add(item)
        else:
            item.description, item.sql_expression = description, sql_expression
            item.updated_at = now
            item.updated_by = oid
        await db.commit()
        return item


async def list_items(owner_id: int | str, source_id: int | str, kind: str | None = None) -> list[SemanticItem]:
    async with SessionLocal() as db:
        try:
            oid, sid = int(owner_id), int(source_id)
        except (ValueError, TypeError):
            return []
        q = select(SemanticItem).where(
            SemanticItem.created_by == oid,
            SemanticItem.source_id == sid,
            SemanticItem.deleted_at.is_(None)
        )
        if kind:
            q = q.where(SemanticItem.kind == kind)
        return list((await db.execute(q.order_by(SemanticItem.kind, SemanticItem.name))).scalars())


async def remove(owner_id: int | str, source_id: int | str, kind: str, name: str) -> bool:
    async with SessionLocal() as db:
        try:
            oid, sid = int(owner_id), int(source_id)
        except (ValueError, TypeError):
            return False
        item = (await db.execute(select(SemanticItem).where(
            SemanticItem.created_by == oid, SemanticItem.source_id == sid,
            SemanticItem.kind == kind, func.lower(SemanticItem.name) == name.lower(),
            SemanticItem.deleted_at.is_(None)))).scalar_one_or_none()
        if not item:
            return False
        now = datetime.now(timezone.utc)
        item.deleted_at = now
        item.deleted_by = oid
        await db.commit()
        return True


async def notes_for_table(owner_id: int | str, source_id: int | str, table: str) -> dict:
    """Table note + column notes ('table.column') for one table."""
    items = await list_items(owner_id, source_id)
    t = table.lower()
    out: dict = {}
    for i in items:
        if i.kind == "table_note" and i.name.lower() == t:
            out["table"] = i.description
        elif i.kind == "column_note" and i.name.lower().startswith(t + "."):
            out.setdefault("columns", {})[i.name.split(".", 1)[1]] = i.description
    return out


async def matching_terms(owner_id: int | str, source_id: int | str, words: list[str]) -> list[dict]:
    items = await list_items(owner_id, source_id)
    return [item_dict(i) for i in items if i.kind in ("glossary", "metric") and any(
        w in i.name.lower() or w in i.description.lower() for w in words)]


async def database_note(owner_id: int | str, source_id: int | str) -> str | None:
    items = await list_items(owner_id, source_id, kind="database_note")
    return items[0].description if items else None


async def all_database_notes(owner_id: int | str) -> dict[str, str]:
    """Map of source_id -> database context description for all user's sources."""
    async with SessionLocal() as db:
        try:
            oid = int(owner_id)
        except (ValueError, TypeError):
            return {}
        items = (await db.execute(select(SemanticItem).where(
            SemanticItem.created_by == oid,
            SemanticItem.kind == "database_note",
            SemanticItem.deleted_at.is_(None)
        ))).scalars().all()
        return {str(i.source_id): i.description for i in items if i.description}


async def table_notes_for_source(owner_id: str, source_id: str) -> dict[str, str]:
    """Map of table_name.lower() -> table description for all table notes in this source."""
    items = await list_items(owner_id, source_id, kind="table_note")
    return {i.name.lower(): i.description for i in items if i.description}


async def set_database_note(owner_id: str, source_id: str, description: str) -> None:
    desc = description.strip()
    if desc:
        await upsert(owner_id, source_id, "database_note", "database", desc, None)
    else:
        await remove(owner_id, source_id, "database_note", "database")


async def set_table_note(owner_id: str, source_id: str, table: str, description: str) -> None:
    desc = description.strip()
    t = table.strip()
    if desc:
        await upsert(owner_id, source_id, "table_note", t, desc, None)
    else:
        await remove(owner_id, source_id, "table_note", t)

