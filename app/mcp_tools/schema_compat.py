"""Publish tool definitions in a form every MCP client/model accepts.

The MCP SDK generates pydantic-style JSON Schema (`anyOf:[X,null]`, `default`, `title`,
`additionalProperties`). OpenAI and Claude cope, but Gemini's function declarations accept only an
OpenAPI-3.0 *subset* (type/description/enum/items/properties/required, with fragile `nullable`),
so the PUBLISHED schema is reduced to that lowest common denominator:

  * `title` and `additionalProperties` are dropped;
  * `anyOf:[X, null]` becomes just `X` (an optional argument is simply not in `required`);
  * `default` is removed and moved into the description as "(default N)".

Only the schema advertised to clients changes. Calls are still validated by the SDK's own pydantic
model, so `null`/omitted optional arguments keep working exactly as before.

Also sets MCP tool annotations (readOnlyHint etc.), which ChatGPT uses to decide which tools need
a confirmation prompt."""
import copy
import json

from mcp.types import ToolAnnotations

_DROP_KEYS = {"title", "additionalProperties", "default", "$defs", "definitions"}

# Tools that change something. Everything else only reads.
WRITE_TOOLS = {
    "save_business_context": ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                             idempotentHint=True, openWorldHint=False),
    "delete_business_context": ToolAnnotations(readOnlyHint=False, destructiveHint=True,
                                               idempotentHint=True, openWorldHint=False),
    "export_result": ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                     idempotentHint=False, openWorldHint=False),
    "refresh_schema_cache": ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                            idempotentHint=True, openWorldHint=False),
}
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True,
                            openWorldHint=False)


def _clean(node):
    if not isinstance(node, dict):
        return node
    # Optional[X] -> X
    any_of = node.get("anyOf")
    if any_of:
        non_null = [b for b in any_of if b.get("type") != "null"]
        if len(non_null) < len(any_of):               # a null branch was present: drop it
            rest = {k: v for k, v in node.items() if k != "anyOf"}
            if len(non_null) == 1:                    # Optional[X] -> X
                node = {**_clean_branch(non_null[0]), **rest}
            elif non_null:                            # Optional[A | B] -> A | B
                node = {**rest, "anyOf": non_null}
    out = {}
    for key, value in node.items():
        if key in _DROP_KEYS:
            continue
        if key == "properties":                      # a MAP of names -> schemas (names are data)
            out[key] = {name: _clean(sub) for name, sub in value.items()}
        elif key == "items":
            out[key] = _clean(value)
        elif key in ("anyOf", "oneOf", "allOf"):
            out[key] = [_clean(b) for b in value]
        else:
            out[key] = value
    default = node.get("default")
    if default is not None:
        note = f"(default {json.dumps(default)})"
        out["description"] = f"{out.get('description', '')} {note}".strip()
    return out


def _clean_branch(branch: dict) -> dict:
    return branch


def lean_schema(schema: dict) -> dict:
    return _clean(copy.deepcopy(schema))


def apply_lean_schemas(mcp) -> int:
    """Rewrite the published schema + annotations of every registered tool. Returns the count."""
    tools = mcp._tool_manager.list_tools()
    for tool in tools:
        tool.parameters = lean_schema(tool.parameters)
        tool.annotations = WRITE_TOOLS.get(tool.name, READ_ONLY)
    return len(tools)
