# APK Analysis

Use this skill when the user asks to document or audit an authorized Android APK with apk-docforge.

Workflow:

1. Verify the artifact is local, open-source, owned, or explicitly authorized by the user.
2. Run static analysis first:

   ```bash
   apk-docforge analyze ./app.apk --out ./outputs/app --mode static
   ```

   Dynamic analysis is optional and controlled:

   ```bash
   apk-docforge analyze ./app.apk --out ./outputs/app-dynamic --mode dynamic --device emulator-5554
   ```

3. Read `analysis_summary.json`, `qa_report.json`, `report.md`, and `codex_ingestion_prompt.md`.
4. Treat JSON outputs as source of truth. Do not invent runtime behavior.
5. Do not propose bypasses for certificate pinning, login, payments, DRM, licenses, subscriptions, or anti-tamper controls.

API/MCP:

- Start API: `apk-docforge serve --host 127.0.0.1 --port 8765`.
- Start MCP stdio: `apk-docforge mcp-server`.
- MCP tools expose search, download, analyze, report, Codex prompt, findings, features, and screens.
- Use numeric candidate IDs returned by `search_apps`/`apk-docforge search` for `download_app`.
- For dynamic mode, pass `device` to `analyze_artifact` and use only authorized emulator/test devices.
- Dynamic navigation is intentionally non-destructive and does not enter credentials or trigger payments, sends, posts, deletes, subscriptions, or logout.

DeepSeek:

- `DocumentationAgent` uses DeepSeek when `DEEPSEEK_API_KEY` is set.
- It sends bounded JSON summaries, not APK binaries or full decompiled source.
