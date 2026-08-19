# Android Audit Report

Use this skill to turn apk-docforge outputs into human documentation, QA plans, or development prompts.

Required inputs:

- `report.md`
- `codex_ingestion_prompt.md`
- `features.json`
- `security_findings.json`
- `permissions.json`
- `network_endpoints.json`
- `static_screens.json`
- `screens_dynamic.json` if dynamic mode ran
- `ui_elements_dynamic.json` if dynamic mode ran
- `navigation_graph.json` if dynamic mode ran
- `blocked_flows.json` if dynamic mode ran
- `qa_report.json`

Equivalent MCP tools:

- `get_report`
- `get_codex_prompt`
- `list_findings`
- `list_features`
- `list_screens`

Rules:

- Cite evidence refs from the JSON.
- Keep `observed`, `inferred`, and `unknown` separate.
- Mark confidence scores.
- Do not turn static strings into runtime claims unless the evidence supports it.
- Treat dynamic UIAutomator/screenshot evidence as observed runtime UI only for the tested device/session.
- Do not include bypass instructions.
