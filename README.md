# Medkart Data Connector

A remote [MCP](https://modelcontextprotocol.io) server that lets people use **Claude** on their
own databases. Admins create users; each user connects their own data sources; Claude then
explores the schema, runs guarded read-only SQL, checks data quality, compares periods,
finds anomalies, and hands back verified Python analysis scripts.

```
Claude ──HTTPS, OAuth 2.1 + PKCE──► reverse proxy ──► this app (FastAPI, one process)
                                                        ├─ /mcp        MCP tools (Streamable HTTP)
                                                        ├─ /oauth/*    authorization server
                                                        ├─ /sources …  web UI: users, data sources, audit
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

## What Claude can do (20 tools)

| Area | Tools |
|---|---|
| Discover | `list_data_sources`, `get_schema_overview`, `search_schema`, `describe_table`, `refresh_schema_cache`, `get_relationships` |
| Query | `run_query` (read-only, row-capped, `truncated` flag), `validate_result` (exact counts, fan-out, sums) |
| Data quality | `profile_table`, `profile_column` |
| Analyse | `compare_periods`, `detect_anomalies` |
| Business context | `get_business_context`, `save_business_context`, `delete_business_context` |
| Big data / scripts | `export_result`, `get_export_link`, `list_exports`, `list_script_templates`, `generate_analysis_script` |

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

### Adding it to Claude

Settings → Connectors → *Add custom connector* → URL `https://<your-host>/mcp`. Claude opens a
sign-in page served by this app; each user signs in with the account an admin created for them.

> Connectors used from claude.ai and the Claude apps are normally reached **from Anthropic's
> infrastructure**, so the URL must be reachable from the internet over HTTPS (check Anthropic's
> current connector documentation, including any egress IP ranges you can allow-list). Claude
> Code connects from the user's own machine, so an internal URL works there.

## Operations

| Task | Command / place |
|---|---|
| Create/upgrade the database | `python -m app.cli migrate` (also run on every deploy) |
| New admin | `python -m app.cli create-admin EMAIL NAME PASSWORD` |
| Rotate the master key | `python -m app.cli rotate-key OLD NEW --dry-run`, then without `--dry-run`, then set `CONNECTOR_MASTER_KEY=NEW` and restart. All-or-nothing. |
| Disable a user | Admin → Users → Disable (revokes their Claude sessions) |
| Who ran what | Admin → Audit (SQL + counts; result data is never stored) |
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
- Credentials are encrypted at rest (AES-256-GCM, bound to the source id) and never returned
  to Claude or logged. Error messages are scrubbed of them.
- Each user can only reach their own sources, exports, and notes (enforced in the service layer
  and tested). Link-local/cloud-metadata addresses are blocked for database hosts.
- **Saved business notes are shown to Claude as data**, but any stored text can carry a prompt
  injection. Only save entries the user stated or confirmed.
- Stored data stays in your infrastructure, but query results you ask Claude to look at are
  sent to Anthropic like any other conversation content. Use masked columns for sensitive
  fields.

## Testing

```powershell
pytest                       # ~190 tests; real-server tests are skipped unless configured
pytest -m integration        # needs CC_TEST_PG_URL / CC_TEST_MYSQL_URL / CC_TEST_MSSQL_URL
```

`CC_TEST_*_URL` = `host:port/database/user/password` of a **disposable** database (tests
create and drop `cc_*` tables).

### What is and is not verified

| Verified by tests here | Not verified here |
|---|---|
| Guard, masking, truncation, exports, scripts (executed), OAuth, rate limits, breaker, migrations, key rotation — on SQLite and DuckDB | Athena against real AWS (fake-client contract tests only) |
| PostgreSQL and MySQL against real servers (earlier run: read-only enforcement, timeouts, exactness) | SQL Server: ODBC Driver 18 was unavailable in the dev environment |
| | The SQL generated by the analysis tools on PostgreSQL/MySQL/SQL Server/Athena (built with sqlglot per dialect, exercised only on SQLite/DuckDB) |
| | Caddy/nginx/systemd/NSSM files were written but not run |
| | A full Claude custom-connector session over the public internet |
