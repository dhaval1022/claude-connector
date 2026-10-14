"""Analysis-script tools. Claude presents the returned script to the user (as an artifact); the
USER runs it locally, so database credentials never leave the server. The script embeds a
manifest and refuses to run on an incomplete or modified file."""
from datetime import date

from app.exports import service as exports
from app.mcp_tools.script_templates import (FOOTER, HEADER, REQUIRED_PARAMS, TEMPLATES)
from app.mcp_tools.server import current_user_id, mcp


def kind_of(type_str: str) -> str:
    t = (type_str or "").lower()
    if "bool" in t:
        return "bool"
    if "timestamp" in t or t.startswith("date"):
        return "date"
    if "dec" in t or "numeric" in t or "number" in t:
        return "decimal"
    if any(k in t for k in ("float", "double", "real")):
        return "float"
    if "int" in t:
        return "int"
    return "text"


ROLE_KINDS = {"date": {"date", "text"}, "numeric": {"int", "float", "decimal"},
              "any": {"int", "float", "decimal", "date", "bool", "text"}}


def _resolve_columns(template: dict, mapping: dict, columns: list[dict]) -> dict:
    roles = template["roles"]
    by_lower = {c["name"].lower(): c for c in columns}
    unknown = sorted(set(mapping) - set(roles))
    if unknown:
        raise ValueError(f"Unknown column roles {unknown}. This template uses: {sorted(roles)}.")
    missing = [r for r, (req, _, _) in roles.items() if req and r not in mapping]
    if missing:
        raise ValueError("Map these roles to export columns: " + "; ".join(
            f"{r} ({roles[r][2]})" for r in missing) + ". Available columns: "
            + ", ".join(c["name"] for c in columns))
    out = {}
    for role, name in mapping.items():
        c = by_lower.get(str(name).lower())
        if not c:
            raise ValueError(f"Role '{role}': column '{name}' is not in the export. "
                             f"Available: {', '.join(x['name'] for x in columns)}.")
        need = roles[role][1]
        if kind_of(c["type"]) not in ROLE_KINDS[need]:
            raise ValueError(f"Role '{role}' needs a {need} column but '{c['name']}' is "
                             f"{c['type']}.")
        out[role] = c["name"]
    return out


def _resolve_params(name: str, template: dict, given: dict) -> dict:
    spec = template["params"]
    unknown = sorted(set(given) - set(spec))
    if unknown:
        raise ValueError(f"Unknown parameters {unknown}. Valid: {sorted(spec)}.")
    out = {}
    for key, (default, typ, _, lo, hi) in spec.items():
        v = given.get(key, default)
        if v is None:
            if key in REQUIRED_PARAMS.get(name, []):
                raise ValueError(f"Parameter '{key}' is required.")
            out[key] = None
            continue
        try:
            if typ is bool:
                if not isinstance(v, bool):
                    raise ValueError
            elif typ is str and key.endswith(("date", "start", "end")):
                date.fromisoformat(str(v))
                v = str(v)
            elif typ is str:
                v = str(v)
            else:
                v = typ(v)
        except (TypeError, ValueError):
            raise ValueError(f"Parameter '{key}' must be a valid {typ.__name__}"
                             f"{' (ISO date YYYY-MM-DD)' if key.endswith(('date', 'start', 'end')) else ''}.")
        if typ in (int, float) and not (lo <= v <= hi):
            raise ValueError(f"Parameter '{key}' must be between {lo} and {hi}.")
        out[key] = v
    if name == "demand_forecast" and out["freq"] not in ("W", "M"):
        raise ValueError("freq must be 'W' or 'M'.")
    if name == "abc_xyz" and not (out["abc_a_pct"] < out["abc_b_pct"]):
        raise ValueError("abc_a_pct must be smaller than abc_b_pct.")
    if name == "abc_xyz" and not (out["xyz_x_cv"] <= out["xyz_y_cv"]):
        raise ValueError("xyz_x_cv must not exceed xyz_y_cv.")
    if name == "price_volume_mix":
        if not (out["baseline_start"] < out["baseline_end"]
                and out["current_start"] < out["current_end"]):
            raise ValueError("Each period's end must be after its start (end is exclusive).")
    return out


@mcp.tool()
async def list_script_templates() -> dict:
    """List the vetted analysis-script templates, the column roles each needs and their
    parameters. Pick one that fits, or use 'generic' as a verified starting point for a custom
    analysis. Needs an export (see export_result) to generate."""
    return {"templates": {k: {
        "title": t["title"], "description": t["description"],
        "roles": {r: {"required": req, "type": kind, "meaning": d}
                  for r, (req, kind, d) in t["roles"].items()},
        "params": {p: {"default": d, "meaning": desc}
                   for p, (d, _, desc, _, _) in t["params"].items()}}
        for k, t in TEMPLATES.items()}}


@mcp.tool()
async def generate_analysis_script(export_id: str, template: str,
                                   columns: dict[str, str] | None = None,
                                   params: dict | None = None) -> dict:
    """Generate a ready-to-run Python script for an exported dataset, to present to the user as
    an artifact (code file). The user runs it on their own machine (pandas + numpy); it
    downloads the export, VERIFIES its checksum and row count, analyses it, writes CSVs to
    ./output and fails loudly if its own self-checks do not reconcile.

    template: see list_script_templates (abc_xyz, rfm, cohort_retention, demand_forecast,
    price_volume_mix, generic). columns maps each role to a column of the export, e.g.
    {"item": "sku", "date": "sold_on", "quantity": "qty"}. For work no template covers, use
    template='generic' and extend its analyze() function: the verified loading code is the
    valuable part, so keep it. Explain the method and its limits when presenting the script."""
    t = TEMPLATES.get(template)
    if not t:
        raise ValueError(f"Unknown template '{template}'. Choose from {sorted(TEMPLATES)}.")
    e = await exports.get_owned_export(current_user_id.get(), export_id)
    if not e:
        raise ValueError("Export not found or expired. Run export_result first.")
    cols = _resolve_columns(t, columns or {}, e.columns)
    prm = _resolve_params(template, t, params or {})
    m = exports.manifest(e)
    expected = {"filename": e.filename, "rows": e.rows, "sha256": e.sha256,
                "columns": [{"name": c["name"], "type": c["type"]} for c in e.columns],
                "kinds": {c["name"]: kind_of(c["type"]) for c in e.columns}}
    script_name = f"{template}_{e.id[:8]}.py"
    head = HEADER.format(title=t["title"], template=template, script_name=script_name,
                         filename=e.filename, expected=expected, sql=e.sql_text,
                         url=m["download_url"], cols=cols, params=prm)
    return {"filename": script_name, "language": "python", "template": template,
            "script": head + t["body"] + FOOTER,
            "requires": ["pandas", "numpy"], "columns": cols, "params": prm,
            "how_to_run": ["pip install pandas numpy", f"python {script_name}",
                           "Results are written to ./output/*.csv and summarised on screen."],
            "download_link_expires_at": m["download_link_expires_at"],
            "note": ("Present this to the user as a code artifact. The script embeds a "
                     "30-minute download link; if it expires they can download the file via a "
                     "fresh link from get_export_link and pass --file. Describe the method "
                     "and its limitations (see comments in the script).")}
