# apk-docforge Agents

Agents are deterministic Python modules with versioned JSON inputs and outputs.
They write artifacts under the selected analysis output directory and attach
evidence references to generated findings, features, screens, endpoints, and UI
elements.

## Implemented analysis agents

- IntakeAgent
- PackageStructureAgent
- StaticReverseEngineeringAgent
- PermissionPrivacyAgent
- NetworkConnectionAgent
- UIStaticMapperAgent
- FeatureInferenceAgent
- SecurityAuditAgent
- ControlBoundaryAuditAgent
- AppUnderstandingAgent
- DocumentationAgent
- CodexPromptBuilderAgent
- QAValidationAgent
- SourceDiscoveryAgent
- DownloadProvenanceAgent
- DynamicRunnerAgent
- UIExplorerAgent

## Implemented interfaces and sources

- F-Droid, GitHub Releases, exact-host official URL, local file, and authorized
  ADB import adapters.
- SQLite source, candidate, artifact, and analysis index.
- FastAPI routes for the web UI, settings, upload, search, download, analysis,
  reports, findings, features, screens, and source management.
- MCP stdio JSON-RPC server with `initialize`, `tools/list`, and `tools/call`.
- Controlled dynamic evidence capture through ADB and UIAutomator.

The Google Play Developer adapter is a non-functional reserved integration point.
Do not describe it as implemented search or download support.

## Security invariants

- Do not implement bypasses for certificate pinning, login, payments,
  subscriptions, DRM, licenses, or anti-tamper controls.
- Do not execute downloaded APKs automatically.
- Keep downloaded and uploaded files in quarantine before analysis.
- Keep the HTTP server on the exact `127.0.0.1` bind; do not add remote bind
  options without an authentication and authorization design.
- Preserve exact-host and HTTPS validation on every download redirect and final
  URL.
- Enforce configured upload, download, nested artifact, archive member, and
  expanded-size limits while streaming data.
- Never expose stored secrets through public settings responses. Reject control
  characters and invalid environment names, and preserve mode `0600` for `.env`.
- Use `observed`, `inferred`, or `unknown` status in outputs.

## Change validation

Run the smallest relevant test first, then the complete gates before reporting a
change as complete:

```bash
uv run --locked --extra dev ruff check .
uv run --locked --extra dev pytest
```

Project version `0.1.0` has a single source in
`src/apk_docforge/__init__.py`; packaging, HTTP, user-agent, and MCP metadata must
use that value rather than a separate hard-coded version.
