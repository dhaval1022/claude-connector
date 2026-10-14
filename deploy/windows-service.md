# Running as a Windows service (no Docker)

Uses [NSSM](https://nssm.cc) (the Non-Sucking Service Manager) so the server starts at boot and
restarts on failure. Run PowerShell **as Administrator**.

```powershell
# 1. Install into a fixed folder with its own virtual environment
cd C:\claude-connector
py -3.12 -m venv .venv
.\.venv\Scripts\pip install -e ".[engines]"
# SQL Server also needs "ODBC Driver 18 for SQL Server" (Microsoft installer), not just pyodbc.

# 2. Configure: copy .env.example to .env and fill it in
copy .env.example .env
.\.venv\Scripts\python -m app.cli gen-key       # -> CONNECTOR_MASTER_KEY
.\.venv\Scripts\python -m app.cli gen-secret    # -> CONNECTOR_JWT_SECRET
notepad .env

# 3. Create the database and the first admin
.\.venv\Scripts\python -m app.cli migrate
.\.venv\Scripts\python -m app.cli create-admin you@medkart.in "Your Name" "a-long-password"

# 4. Register the service (ONE worker: rate limits are in-process)
nssm install ClaudeConnector C:\claude-connector\.venv\Scripts\python.exe
nssm set ClaudeConnector AppParameters "-m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1 --proxy-headers --forwarded-allow-ips=127.0.0.1 --no-server-header"
nssm set ClaudeConnector AppDirectory C:\claude-connector
nssm set ClaudeConnector Start SERVICE_AUTO_START
mkdir C:\claude-connector\logs
nssm set ClaudeConnector AppStdout C:\claude-connector\logs\out.log
nssm set ClaudeConnector AppStderr C:\claude-connector\logs\err.log
nssm set ClaudeConnector AppRotateFiles 1
nssm set ClaudeConnector AppRotateBytes 10485760
nssm start ClaudeConnector
```

The app reads `.env` from its working directory. Restrict who can read it:

```powershell
icacls C:\claude-connector\.env /inheritance:r /grant:r "SYSTEM:F" "Administrators:F"
```

## HTTPS

Put Caddy (a single `caddy.exe`) in front, using `deploy\Caddyfile`, and run it as a service too:

```powershell
nssm install Caddy C:\caddy\caddy.exe
nssm set Caddy AppParameters "run --config C:\claude-connector\deploy\Caddyfile"
nssm start Caddy
```

IIS with URL Rewrite + ARR also works; disable response buffering and set the forwarded
`X-Forwarded-For` header to the client address (one proxy => `CONNECTOR_TRUSTED_PROXY_COUNT=1`).

## Upgrading

```powershell
nssm stop ClaudeConnector
git pull                                   # or copy the new release over
.\.venv\Scripts\pip install -e ".[engines]"
.\.venv\Scripts\python -m app.cli migrate
nssm start ClaudeConnector
```

Back up `connector.db` (or your PostgreSQL database), the `data\` folder, and the master key
**in separate places**.
