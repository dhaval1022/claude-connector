# Medkart Data Connector

A remote [MCP](https://modelcontextprotocol.io) server that lets people use an AI assistant on
their own databases: **Claude, ChatGPT / OpenAI and Gemini** (any MCP client works). Admins create
users; each user connects their own data sources and chooses which AI apps may use each one; the
assistant then explores the schema, runs guarded read-only SQL, checks data quality, compares
periods, finds anomalies, and hands back verified Python analysis scripts.

```
AI app ──HTTPS, OAuth 2.1 + PKCE or API token──► reverse proxy ──► this app (FastAPI, 1 process)
                                                        ├─ /mcp        MCP tools (Streamable HTTP)
                                                        ├─ /oauth/*    authorization server
                                                        ├─ /sources …  web UI: users, data sources, tokens, audit
                                                        ├─ /files/<t>  signed export downloads
                                                        └─ metadata DB (SQLite or PostgreSQL)
```

## Supported data sources

| Engine | Notes |
|---|---|
| PostgreSQL, MySQL/MariaDB, SQL Server | via SQLAlchemy; SQL Server needs ODBC Driver 18 |
| Amazon Athena | via boto3 + Glue catalog; reports bytes scanned and warns about unfiltered partitioned tables |
| CSV / Excel (.xlsx) uploads | loaded into a per-source read-only DuckDB database |

BigQuery, Snowflake and ClickHouse are **not** implemented.

## What the assistant can do (20 tools)

| Area | Tools |
|---|---|
| Discover | `list_data_sources`, `get_schema_overview`, `search_schema`, `describe_table`, `refresh_schema_cache`, `get_relationships` |
| Query | `run_query` (read-only, row-capped, `truncated` flag), `validate_result` (exact counts, fan-out, sums) |
| Data quality | `profile_table`, `profile_column` |
| Analyse | `compare_periods`, `detect_anomalies` |
| Business context | `get_business_context`, `save_business_context`, `delete_business_context` |
| Big data / scripts | `export_result`, `get_export_link`, `list_exports`, `list_script_templates`, `generate_analysis_script` |

`list_data_sources` shows only the sources enabled for the calling app (and how many are not).
Script templates: `abc_xyz`, `rfm`, `cohort_retention`, `demand_forecast`,
`price_volume_mix`, `generic`. Generated scripts verify the export's SHA-256 and row count
before analysing, and fail loudly if their own self-checks do not reconcile. The **user** runs
them locally, so database credentials never leave the server.

## How accuracy is protected

- **Read-only, three layers**: SQL is parsed (sqlglot) and only one `SELECT` is allowed (no
  DML/DDL, `SELECT INTO`, locking reads, dangerous functions, system credential tables, file
  reads); sessions are read-only with a timeout and always rolled back; and you should supply a
  read-only database account.
- **No silent truncation**: results fetch `max_rows + 1`, so `truncated` is exact and comes with
  a warning. Exports **fail** rather than truncate.
- **Exact numbers**: decimals travel as strings; sums in analysis tools use `Decimal`.
- **No guessing**: unknown tables get "did you mean"; column and type notes surface in
  `describe_table`; uploads never reinterpret codes (`00123` stays text; non-ISO dates stay text).
- **Reconciliation**: `compare_periods` checks group deltas against an independent total;
  `validate_result` finds JOIN fan-out; scripts self-check.
- **PII**: per-source masked columns can't be selected, filtered on, or reached with `SELECT *`.

## Quick start (development)

```powershell
python -m venv .venv ; .\.venv\Scripts\pip install -e ".[dev,engines]"
copy .env.example .env      # fill CONNECTOR_MASTER_KEY / CONNECTOR_JWT_SECRET (see below)
.\.venv\Scripts\python -m app.cli gen-key
.\.venv\Scripts\python -m app.cli gen-secret
.\.venv\Scripts\python -m app.cli create-admin you@medkart.in "Your Name" "a-long-password"
.\.venv\Scripts\uvicorn app.main:app --port 8000
```

Open http://localhost:8000, sign in (you must change the temporary password), create users,
and add a data source. Tests: `pytest` (see *Testing*).

## Production

Run **one** worker behind an HTTPS reverse proxy.

- Windows: [deploy/windows-service.md](deploy/windows-service.md) (NSSM + Caddy)
- Linux: [deploy/claude-connector.service](deploy/claude-connector.service) (systemd) with
  [deploy/Caddyfile](deploy/Caddyfile) or [deploy/nginx.conf](deploy/nginx.conf)
- All settings: [.env.example](.env.example)

**Why one worker**: rate limits and circuit breakers are in-process. For more than one process
or host, move that state to Redis first.

### First admin without a shell

On a host where you cannot run `create-admin`, set `CONNECTOR_BOOTSTRAP_ADMIN_EMAIL` and
`CONNECTOR_BOOTSTRAP_ADMIN_PASSWORD` (10+ chars). At startup, **only if the database has no users**,
that admin is created and must change the password at first sign-in. It never runs again once any
user exists and never resets an existing password, so remove the variables after your first login.
Run the pre-deploy `python -m app.cli migrate` first.

## Connecting AI apps

Everything speaks the same MCP endpoint, `https://<your-host>/mcp` (with or without a trailing
slash). There are two ways to authenticate:

* **Sign in through the browser (OAuth)**, used by Claude, ChatGPT connectors and Gemini CLI. The app
  opens this server's sign-in page; the user signs in with the account an admin created. Where the app
  can't be identified from its callback (Claude Code, Gemini CLI) the page asks **"Which app is
  this?"**, and that choice decides which data sources the session may use.
* **A personal API token** (`mk_...`), created at *API tokens* in the web UI, for clients that send a
  fixed bearer token (OpenAI's API, some Gemini CLI builds, scripts). Pick the app it is for, an expiry
  (30/90/365 days) and keep one token per app. It acts as **you**, so never paste it into anything
  other people use (for example a shared Custom GPT).

> **Reachability.** claude.ai, ChatGPT and other hosted apps call your server **from their own
> infrastructure**, so it must be reachable from the internet over HTTPS. Command-line clients
> (Claude Code, Gemini CLI) run on the user's machine, so an internal URL works for them. Check each
> vendor's current documentation for plan requirements and any published IP ranges.

| App | How to connect |
|---|---|
| **Claude** (claude.ai / Desktop) | Settings → Connectors → *Add custom connector* → the MCP URL. Sign in when prompted. |
| **Claude Code** | `claude mcp add --transport http medkart https://<host>/mcp`, then `/mcp` to authenticate and pick *Claude* on the sign-in page. |
| **ChatGPT** | Developer mode → add a custom MCP connector with the MCP URL and OAuth. ChatGPT's callback URLs are pre-allowed (see below). |
| **OpenAI API** | Responses API remote-MCP tool with an API token (below). |
| **Gemini CLI** | `httpUrl` in `settings.json`, then `/mcp auth medkart`, or a bearer-token header (below). |
| **Gemini API / SDK** | Pass an MCP session as a tool, using an API token (below). |

**OpenAI Responses API** (create the token with *app = ChatGPT / OpenAI*; use a current model name):

```python
from openai import OpenAI
resp = OpenAI().responses.create(
    model="<a current model>",
    input="Which data sources do I have, and what is in the biggest table?",
    tools=[{"type": "mcp", "server_label": "medkart", "server_url": "https://<host>/mcp",
            "authorization": "mk_...", "require_approval": "always",
            "allowed_tools": ["list_data_sources", "get_schema_overview", "describe_table", "run_query"]}])
```

**Gemini CLI**, `~/.gemini/settings.json` (OAuth: omit `headers` and run `/mcp auth medkart`, choosing
*Gemini* on the sign-in page; token: create it with *app = Gemini (Google)*):

```json
{"mcpServers": {"medkart": {"httpUrl": "https://<host>/mcp",
                            "headers": {"Authorization": "Bearer mk_..."}}}}
```

**Gemini API / SDK** (Google describes MCP support in its SDKs as experimental; check its docs):

```python
from google import genai
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async with streamablehttp_client("https://<host>/mcp",
                                 headers={"Authorization": "Bearer mk_..."}) as (r, w, _):
    async with ClientSession(r, w) as session:
        await session.initialize()
        reply = await genai.Client().aio.models.generate_content(
            model="<a current model>", contents="List my data sources.",
            config=genai.types.GenerateContentConfig(tools=[session]))
```

### Which AI apps may see which data

Query results are sent to whichever provider you connect, so **every data source has an allow-list of
apps**, edited on the *Data sources* page. **A new source is Claude-only**; nothing becomes visible to
OpenAI or Google until its owner ticks that app. It is enforced in every tool call (a test fails if any
tool that touches a source or an export skips the check), refusals are audited (status `denied`, with the
app), and `list_data_sources` reports how many sources are hidden from the calling app.

The app is identified by the callback host for known web clients (`claude.ai`, `chatgpt.com`; a form field
can't override it), by your choice at sign-in for command-line clients, and by the token's setting for API
tokens. This is a **data-governance control against accidental exposure, not a security boundary**: someone
who deliberately mislabels their own client can still do so. Combine it with masked columns for sensitive
fields, and check your organisation's policy before enabling a third-party provider.

If ChatGPT or another client is rejected at sign-in, the server logs `oauth_redirect_rejected` with the
callback host and path it sent; if it is legitimate, add it to `CONNECTOR_ALLOWED_REDIRECT_PREFIXES`.

## Operations

| Task | Command / place |
|---|---|
| Create/upgrade the database | `python -m app.cli migrate` (also run on every deploy) |
| New admin | `python -m app.cli create-admin EMAIL NAME PASSWORD` |
| Rotate the master key | `python -m app.cli rotate-key OLD NEW --dry-run`, then without `--dry-run`, then set `CONNECTOR_MASTER_KEY=NEW` and restart. All-or-nothing. |
| Disable a user | Admin → Users → Disable (immediately cuts off their OAuth sessions **and** API tokens) |
| Who ran what | Admin → Audit (app, SQL + counts; result data is never stored). Filter `denied` to see allow-list refusals. |
| Health | `/healthz` (liveness), `/readyz` (database) |
| Metrics | `/metrics` with `Authorization: Bearer $CONNECTOR_METRICS_TOKEN` (404 if unset) |
| Logs | JSON on stderr, with `request_id`. Tokens/query strings/SQL are never logged. |
| Housekeeping | automatic hourly: expired exports/tokens, audit rows older than 180 days |

**Keep the database and `data/` folder out of OneDrive/Dropbox-style synced folders**: a sync
client can lock or rewrite a live SQLite file and corrupt it (tests hit this symptom). Use a local
path (e.g. `C:\claude-connector-data`) or PostgreSQL.

**Back up** the metadata database, the `data/` folder, and the master key — separately. Losing
the master key makes every stored credential unrecoverable (users re-enter them).

When you change `app/db/models.py`, add an Alembic migration
(`alembic revision --autogenerate -m "..."`); a test fails if models and migrations drift.

## Security model and limits

- Users are admin-created; passwords are argon2id; 5 failed sign-ins lock an account for 15
  minutes; sign-in, token and registration endpoints are rate-limited per client IP.
- OAuth 2.1 authorization-code + PKCE (S256 only), exact structural redirect-URI matching,
  single-use codes, rotating refresh tokens with replay detection, short-lived access tokens.
- API tokens: 256-bit random, only the SHA-256 is stored, shown once, mandatory expiry, max 10
  active per user, revocable, dead when the owner is disabled; repeated bad tokens are throttled per IP.
- Credentials are encrypted at rest (AES-256-GCM, bound to the source id) and never returned
  to the assistant or logged. Error messages are scrubbed of them.
- Each user can only reach their own sources, exports, and notes (enforced in the service layer
  and tested). Link-local/cloud-metadata addresses are blocked for database hosts.
- **Saved business notes are shown to the assistant as data**, but any stored text can carry a prompt
  injection. Only save entries the user stated or confirmed.
- Stored data stays in your infrastructure, but query results you ask an assistant to look at are
  sent to that assistant's provider (Anthropic, OpenAI or Google) like any other conversation
  content. Use the per-source app allow-list and masked columns for sensitive data.

## Testing

```powershell
pytest                       # hundreds of tests; real-database tests skip unless configured
pytest -m integration        # needs CC_TEST_PG_URL / CC_TEST_MYSQL_URL / CC_TEST_MSSQL_URL
```

`CC_TEST_*_URL` = `host:port/database/user/password` of a **disposable** database (tests
create and drop `cc_*` tables).

### What is and is not verified

| Verified by tests here | Not verified here |
|---|---|
| Guard, masking, truncation, exports, scripts (executed), OAuth, rate limits, breaker, migrations, key rotation — on SQLite and DuckDB | Athena against real AWS (fake-client contract tests only) |
| **The official MCP Python client** against a real server process using an API token: tool list, per-provider visibility, refusals, exports, bad/expired/revoked tokens, `/mcp` with and without a trailing slash | **ChatGPT, the OpenAI API and Gemini themselves.** Their exact behaviour (callback URLs, which plans allow custom connectors, how Gemini treats tool schemas) is taken from vendor documentation that disagrees in places. The first real connection may need a small adjustment. |
| Published tool schemas contain only type/description/enum/items/properties/required (no `anyOf`/`default`/`title`/free-form objects), tool names valid for OpenAI and Gemini, tool annotations | Gemini's exact schema validation (the subset is documented; not tested against the live API) |
| PostgreSQL and MySQL against real servers (earlier run: read-only enforcement, timeouts, exactness) | SQL Server: ODBC Driver 18 was unavailable in the dev environment |
| | The SQL generated by the analysis tools on PostgreSQL/MySQL/SQL Server/Athena (built with sqlglot per dialect, exercised only on SQLite/DuckDB) |
| | Caddy/nginx/systemd/NSSM files were written but not run |
| | A full connector session from any vendor over the public internet |
