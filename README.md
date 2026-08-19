# apk-docforge

`apk-docforge` is a local-first Python toolkit for documenting and auditing Android
APK artifacts. It combines deterministic static analysis, optional controlled
runtime observation on an authorized ADB device, provenance-aware downloads, a
FastAPI web interface, and an MCP stdio server.

Use it only with applications you own, are authorized to assess, or may inspect
under their license. The project does not bypass authentication, payments, DRM,
certificate pinning, licensing, or anti-tamper controls.

## Highlights

- APK, APKS, and XAPK intake with quarantine and SHA-256 provenance.
- Static mapping of package structure, manifest data, permissions, resources,
  screens, network signals, SDKs, features, and security findings.
- Evidence references plus explicit `observed`, `inferred`, and `unknown` status.
- Search adapters for F-Droid and GitHub Releases, plus exact-host allowlisted
  official URLs.
- Controlled dynamic analysis on an explicitly selected ADB device, with
  non-destructive navigation and blocked sensitive flows.
- Local web UI, JSON API, and MCP-compatible stdio tools.
- Deterministic Markdown output with an optional bounded DeepSeek addendum.

## Quick start

Requirements: Python 3.11 or newer and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --locked --extra dev
uv run --locked apk-docforge serve
open http://127.0.0.1:8765/
```

Run a static analysis directly:

```bash
uv run --locked apk-docforge analyze ./app.apk --out ./outputs/app --mode static
```

The generated directory includes `analysis_summary.json`, `report.md`,
`codex_ingestion_prompt.md`, `qa_report.json`, and versioned JSON evidence.

## Security defaults

The HTTP service is intentionally local-only:

- `serve` defaults to `127.0.0.1` and rejects every other bind address.
- The ASGI layer also rejects HTTP clients whose socket address is not loopback.
- Trusted hosts are exactly `127.0.0.1` and `localhost`.
- Browser cross-origin access is limited to configured loopback origins.
- Upload bodies are bounded before and during multipart parsing.
- Downloads validate `Content-Length`, enforce a streaming byte limit, and
  revalidate every redirect and final URL against the source policy.
- Nested artifacts, archive expansion, and manifest reads have independent limits.
- Settings are written atomically to a regular `.env` file with mode `0600`.

Default limits are conservative and configurable through environment variables:

| Setting | Default |
| --- | ---: |
| `APK_DOCFORGE_MAX_UPLOAD_BYTES` | 256 MiB |
| `APK_DOCFORGE_MAX_DOWNLOAD_BYTES` | 512 MiB |
| `APK_DOCFORGE_MAX_NESTED_ARTIFACT_BYTES` | 256 MiB |
| `APK_DOCFORGE_MAX_ARCHIVE_MEMBERS` | 10,000 |
| `APK_DOCFORGE_MAX_ARCHIVE_UNCOMPRESSED_BYTES` | 1 GiB |
| `APK_DOCFORGE_MAX_DOWNLOAD_REDIRECTS` | 5 |

Copy `.env.example` for local configuration and keep the resulting file private:

```bash
cp .env.example .env
chmod 600 .env
```

See [SECURITY.md](SECURITY.md) for the threat model and vulnerability reporting
process.

## Commands

```bash
apk-docforge analyze ./app.apk --out ./outputs/app --mode static
apk-docforge search "TeamNewPipe/NewPipe" --sources github --limit 1
apk-docforge download --candidate-id 3 --out ./downloads
apk-docforge import-device --package com.example.app --out ./downloads
apk-docforge sources
apk-docforge serve
apk-docforge mcp-server
```

Dynamic analysis is opt-in and requires an authorized device serial:

```bash
apk-docforge analyze ./app.apk \
  --out ./outputs/app-dynamic \
  --mode dynamic \
  --device emulator-5554
```

`search` persists candidates in the local SQLite index and prints the numeric ID
accepted by `download`.

## Download policy

- F-Droid downloads stay on the approved F-Droid host.
- GitHub release assets stay on approved GitHub asset hosts.
- Official URLs require HTTPS and an exact DNS host in
  `APK_DOCFORGE_OFFICIAL_URL_ALLOWLIST`; IP literals are rejected.
- Redirect destinations and the final response URL are evaluated with the same
  policy before their response bodies are accepted.
- Third-party APK mirrors and Google Play scraping remain disabled.

The Google Play Developer adapter is a reserved integration point only; it does
not currently search or download artifacts, even when a credentials path is
configured.

## Optional DeepSeek documentation

Set a key only if you want the optional documentation addendum:

```bash
export APK_DOCFORGE_DOCUMENTATION_PROVIDER=deepseek
export DEEPSEEK_API_KEY=...
```

APK binaries and full decompiled source are not sent. The provider receives
bounded JSON summaries and evidence references. Without a key, the deterministic
local report remains available.

## API and MCP

The local API includes health, upload, search, download, analysis, report,
findings, features, screens, sources, and settings endpoints under `/api`.
Interactive OpenAPI documentation is available at `http://127.0.0.1:8765/docs`.

MCP smoke test:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}\n' \
  | uv run --locked apk-docforge mcp-server
```

## Optional containers

Docker services bind to loopback only and are disabled unless their profile is
selected. MobSF is pinned to a published versioned image:

```bash
docker compose --profile mobsf up mobsf
```

PostgreSQL and Redis are future integration services; the application uses
SQLite by default. Set a non-empty password before starting the future profile:

```bash
export APK_DOCFORGE_POSTGRES_PASSWORD='replace-with-a-strong-secret'
docker compose --profile future up postgres redis
```

## Development

```bash
uv sync --locked --extra dev
uv run --locked --extra dev ruff check .
uv run --locked --extra dev pytest
```

CI runs the same lint, formatting, and test gates on Python 3.11 and 3.12.

## Current limitations

- Static depth depends on optional Android tools such as `apkanalyzer`, `jadx`,
  and `apktool`.
- Dynamic mode installs one selected primary APK; split-package installation is
  not implemented.
- Runtime navigation never enters credentials or triggers login, payment,
  publishing, sharing, deletion, subscription, or logout flows.
- Traffic interception and Frida-based instrumentation are intentionally absent.
- The API has no remote authentication because remote binding is unsupported.
