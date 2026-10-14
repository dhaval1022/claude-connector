from datetime import datetime, timezone

from sqlalchemy import and_, delete, func, select

from app.db.models import SemanticItem
from app.db.session import SessionLocal

KINDS = ("metric", "glossary", "table_note", "column_note", "rule")
MAX_NAME, MAX_DESC, MAX_SQL = 160, 2000, 4000


def item_dict(i: SemanticItem) -> dict:
    return {"kind": i.kind, "name": i.name, "description": i.description,
            **({"sql_expression": i.sql_expression} if i.sql_expression else {}),
            "updated_at": i.updated_at.isoformat() if i.updated_at else None}


async def upsert(owner_id: str, source_id: str, kind: str, name: str, description: str,
                 sql_expression: str | None) -> SemanticItem:
    async with SessionLocal() as db:
        item = (await db.execute(select(SemanticItem).where(
            SemanticItem.owner_id == owner_id, SemanticItem.source_id == source_id,
            SemanticItem.kind == kind, func.lower(SemanticItem.name) == name.lower())
        )).scalar_one_or_none()
        if item is None:
            item = SemanticItem(owner_id=owner_id, source_id=source_id, kind=kind, name=name)
            db.add(item)
        item.description, item.sql_expression = description, sql_expression
        item.updated_at = datetime.now(timezone.utc)
        await db.commit()
        return item


async def list_items(owner_id: str, source_id: str, kind: str | None = None) -> list[SemanticItem]:
    async with SessionLocal() as db:
        q = select(SemanticItem).where(SemanticItem.owner_id == owner_id,
                                       SemanticItem.source_id == source_id)
        if kind:
            q = q.where(SemanticItem.kind == kind)
        return list((await db.execute(q.order_by(SemanticItem.kind, SemanticItem.name))).scalars())


async def remove(owner_id: str, source_id: str, kind: str, name: str) -> bool:
    async with SessionLocal() as db:
        res = await db.execute(delete(SemanticItem).where(and_(
            SemanticItem.owner_id == owner_id, SemanticItem.source_id == source_id,
            SemanticItem.kind == kind, func.lower(SemanticItem.name) == name.lower())))
        await db.commit()
        return res.rowcount > 0


async def notes_for_table(owner_id: str, source_id: str, table: str) -> dict:
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


async def matching_terms(owner_id: str, source_id: str, words: list[str]) -> list[dict]:
    items = await list_items(owner_id, source_id)
    return [item_dict(i) for i in items if i.kind in ("glossary", "metric") and any(
        w in i.name.lower() or w in i.description.lower() for w in words)]
