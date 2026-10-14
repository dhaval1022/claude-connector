"""Published tool definitions must be acceptable to Claude, OpenAI AND Gemini (whose function
declarations take only an OpenAPI-3.0 subset), without changing how calls are validated."""
import asyncio
import json
import re

import pytest

import app.main  # noqa: F401  (registers all tools and applies the lean schemas)
from app.mcp_tools import script_templates
from app.mcp_tools.schema_compat import READ_ONLY, WRITE_TOOLS, apply_lean_schemas, lean_schema
from app.mcp_tools.server import mcp

TOOLS = {t.name: t for t in mcp._tool_manager.list_tools()}
FORBIDDEN_KEYS = {"anyOf", "oneOf", "allOf", "$ref", "$defs", "definitions", "default", "title",
                  "additionalProperties", "nullable"}
SCALARS = {"string", "integer", "number", "boolean"}


def walk(node, path=""):
    """Yield (path, key, value) for every key in a schema tree."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield path, k, v
            if k == "properties":                       # property NAMES are data, not keywords
                for name, sub in v.items():
                    yield from walk(sub, f"{path}.{name}")
            else:
                yield from walk(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk(v, f"{path}[{i}]")


def test_there_are_exactly_the_expected_tools():
    assert len(TOOLS) == 20


@pytest.mark.parametrize("name", sorted(TOOLS))
def test_published_schema_uses_only_the_lowest_common_denominator(name):
    schema = TOOLS[name].parameters
    assert schema["type"] == "object"
    keys = {k for _, k, _ in walk(schema)}
    assert not (keys & FORBIDDEN_KEYS), f"{name}: {keys & FORBIDDEN_KEYS}"
    types = [v for _, k, v in walk(schema) if k == "type"]            # (not the text "null": a
    assert "null" not in types and not any(isinstance(t, list) for t in types)   # parameter may be
    props = schema.get("properties", {})                                          # named null_columns)
    assert set(schema.get("required", [])) <= set(props)
    for pname, p in props.items():
        assert p.get("type") in SCALARS | {"array"}, f"{name}.{pname}: {p}"   # no bare objects
        if p["type"] == "array":
            assert p["items"].get("type") in SCALARS, f"{name}.{pname}"


def test_defaults_are_preserved_as_text_for_the_model():
    assert "(default 500)" in TOOLS["run_query"].parameters["properties"]["max_rows"]["description"]
    assert "(default 3)" in TOOLS["describe_table"].parameters["properties"]["sample_rows"]["description"]


def required_value(p):
    return {"string": "x", "integer": 1, "number": 1.0, "boolean": True, "array": []}[p["type"]]


@pytest.mark.parametrize("name", sorted(TOOLS))
def test_calls_are_still_validated_by_the_original_model(name):
    """The published schema is simplified; validation must be unchanged: required arguments are
    still required, optional ones may be omitted OR sent as null, defaults still apply."""
    tool = TOOLS[name]
    model = tool.fn_metadata.arg_model
    original = model.model_json_schema()
    pub = tool.parameters["properties"]
    required = {k: required_value(pub[k]) for k in tool.parameters.get("required", [])}
    model.model_validate(required)                                     # only required args
    nullable = {k: None for k, p in original["properties"].items()
                if any(b.get("type") == "null" for b in p.get("anyOf", []))}
    model.model_validate({**required, **nullable})                    # optional args sent as null
    for missing in required:                                          # each required arg enforced
        with pytest.raises(Exception):
            model.model_validate({k: v for k, v in required.items() if k != missing})


def test_lean_schema_unit_behaviour_and_it_does_not_mutate_its_input():
    original = {
        "title": "xArguments", "type": "object", "required": ["a"],
        "properties": {
            "a": {"title": "A", "type": "string"},
            "title": {"title": "Title", "type": "string"},               # a property NAMED title
            "n": {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": None, "title": "N"},
            "d": {"type": "integer", "default": 5, "title": "D"},
            "free": {"anyOf": [{"additionalProperties": True, "type": "object"}, {"type": "null"}],
                     "default": None},
            "multi": {"anyOf": [{"type": "string"}, {"type": "integer"}, {"type": "null"}]},
            "lst": {"type": "array", "items": {"type": "string", "title": "I"}, "title": "L"},
        }}
    snapshot = json.loads(json.dumps(original))
    out = lean_schema(original)
    assert original == snapshot                                          # input untouched
    assert "title" not in out and out["required"] == ["a"]
    p = out["properties"]
    assert p["title"] == {"type": "string"}                              # the property survived
    assert p["a"] == {"type": "string"}
    assert p["n"] == {"type": "integer"}                                 # Optional[int] -> int
    assert p["d"] == {"type": "integer", "description": "(default 5)"}
    assert p["free"] == {"type": "object"}
    assert p["multi"] == {"anyOf": [{"type": "string"}, {"type": "integer"}]}   # real unions kept
    assert p["lst"] == {"type": "array", "items": {"type": "string"}}
    assert lean_schema(out) == out                                       # idempotent


def test_apply_is_idempotent_and_what_clients_receive_is_the_lean_form():
    before = {n: json.dumps(t.parameters, sort_keys=True) for n, t in TOOLS.items()}
    assert apply_lean_schemas(mcp) == 20
    assert {n: json.dumps(t.parameters, sort_keys=True) for n, t in TOOLS.items()} == before
    listed = {t.name: t for t in asyncio.run(mcp.list_tools())}       # the actual MCP response
    assert {n: t.inputSchema for n, t in listed.items()} == {n: t.parameters for n, t in TOOLS.items()}


def test_annotations_mark_exactly_the_state_changing_tools():
    assert set(WRITE_TOOLS) == {"save_business_context", "delete_business_context",
                                "export_result", "refresh_schema_cache"}
    for name, tool in TOOLS.items():
        a = tool.annotations
        assert a is not None, name
        assert a.openWorldHint is False
        if name in WRITE_TOOLS:
            assert a.readOnlyHint is False, name
        else:
            assert a == READ_ONLY and a.readOnlyHint is True and a.destructiveHint is False, name
    assert TOOLS["delete_business_context"].annotations.destructiveHint is True
    listed = {t.name: t for t in asyncio.run(mcp.list_tools())}
    assert listed["run_query"].annotations.readOnlyHint is True          # sent to clients


@pytest.mark.parametrize("name", sorted(TOOLS))
def test_names_and_descriptions_are_valid_for_openai_and_gemini(name):
    assert re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", name)                    # OpenAI function names
    assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,127}", name)        # Gemini function names
    desc = TOOLS[name].description
    assert desc and 40 < len(desc) < 1600, f"{name}: description length {len(desc or '')}"
    for pname in TOOLS[name].parameters.get("properties", {}):
        assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", pname), f"{name}.{pname}"


def test_total_published_size_stays_modest_for_models_with_tool_limits():
    total = sum(len(json.dumps({"n": t.name, "d": t.description, "s": t.parameters}))
                for t in TOOLS.values())
    assert total < 30_000, f"tool definitions are {total} chars; models pay for this on every turn"


def test_nothing_published_is_specific_to_one_provider():
    for name, tool in TOOLS.items():
        blob = (name + tool.description + json.dumps(tool.parameters)).lower()
        assert "claude" not in blob and "artifact" not in blob and "anthropic" not in blob, name
    text = script_templates.HEADER + script_templates.FOOTER + json.dumps(
        {k: [t["title"], t["description"]] for k, t in script_templates.TEMPLATES.items()})
    assert "claude" not in text.lower() and "artifact" not in text.lower()
    assert "ask your AI assistant" in script_templates.HEADER


def test_descriptions_tell_the_model_how_to_use_the_flat_script_arguments():
    d = TOOLS["generate_analysis_script"].description
    assert "item_column" in d and "params_json" in d and "list_script_templates" in d
    props = TOOLS["generate_analysis_script"].parameters["properties"]
    assert {"item_column", "date_column", "quantity_column", "value_column", "customer_column",
            "revenue_column", "order_id_column", "params_json"} <= set(props)
    assert TOOLS["generate_analysis_script"].parameters["required"] == ["export_id", "template"]
