from __future__ import annotations

import json
from ipaddress import ip_address
from pathlib import Path
from typing import Annotated

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from apk_docforge.adapters.adb_importer import ADBImporter
from apk_docforge.db.session import init_db
from apk_docforge.logging import configure_logging
from apk_docforge.pipeline import run_analysis
from apk_docforge.services.discovery import search_apps
from apk_docforge.services.downloader import download_candidate
from apk_docforge.services.source_registry import list_sources, upsert_source


app = typer.Typer(help="Local Android APK documentation and audit pipeline.")
console = Console()


@app.callback()
def main(verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging.")) -> None:
    configure_logging("DEBUG" if verbose else "INFO")


@app.command()
def analyze(
    artifact: Annotated[Path, typer.Argument(help="APK/APKS/XAPK or directory to analyze.")],
    out: Annotated[Path | None, typer.Option("--out", help="Output directory.")] = None,
    mode: Annotated[str, typer.Option("--mode", help="Analysis mode: static or dynamic.")] = "static",
    device: Annotated[str | None, typer.Option("--device", help="Authorized ADB device id for dynamic mode.")] = None,
) -> None:
    """Analyze a local Android artifact."""
    try:
        summary = run_analysis(artifact, out=out, mode=mode, device=device)
    except (NotImplementedError, ValueError, RuntimeError) as exc:
        console.print(f"[red]Blocked:[/red] {exc}")
        raise typer.Exit(2) from exc
    console.print("[green]Analysis completed[/green]")
    console.print_json(json.dumps(summary, ensure_ascii=False))


@app.command()
def search(
    query: Annotated[str, typer.Argument(help="App name, package name, developer, or URL.")],
    sources: Annotated[
        str,
        typer.Option("--sources", help="Comma-separated sources: fdroid,github."),
    ] = "fdroid,github",
    limit: Annotated[int, typer.Option("--limit", help="Max candidates per source.")] = 10,
) -> None:
    """Search allowed public sources without downloading."""
    result = search_apps(
        query,
        [item.strip().lower() for item in sources.split(",") if item.strip()],
        limit=limit,
        persist=True,
    )
    table = Table(title="Source candidates")
    table.add_column("Candidate ID")
    table.add_column("Source")
    table.add_column("Name")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Download")
    table.add_column("Policy")
    if result["errors"]:
        console.print(f"[yellow]Search warnings:[/yellow] {result['errors']}")
    for decision in result["policy_decisions"]:
        if not decision.get("allowed"):
            console.print(f"[yellow]Policy:[/yellow] {decision.get('source')}: {decision.get('reason')}")
    for item in result["candidates"]:
        table.add_row(
            str(item.get("id")),
            str(item.get("source")),
            str(item.get("app_name") or "unknown"),
            str(item.get("package_name") or "unknown"),
            str(item.get("version_name") or "unknown"),
            "yes" if item.get("download_url") else "no",
            str(item.get("policy_status") or "unknown"),
        )
    console.print(table)
    console.print_json(json.dumps(result, ensure_ascii=False))


@app.command()
def download(
    candidate_id: Annotated[
        str,
        typer.Option(
            "--candidate-id",
            help="Numeric candidate id from `apk-docforge search`.",
        ),
    ],
    out: Annotated[Path, typer.Option("--out", help="Download output directory.")] = Path("downloads"),
) -> None:
    """Download an allowed public candidate into quarantine/downloads with provenance."""
    result = download_candidate(candidate_id, out=out)
    console.print_json(json.dumps(result, ensure_ascii=False))
    if result.get("status") != "completed":
        raise typer.Exit(2)


@app.command("import-device")
def import_device(
    package: Annotated[str, typer.Option("--package", help="Installed package name.")],
    out: Annotated[Path, typer.Option("--out", help="Output directory.")] = Path("downloads"),
    device: Annotated[str | None, typer.Option("--device", help="ADB device id.")] = None,
) -> None:
    """Import APKs from an authorized test device via adb."""
    result = ADBImporter().import_package(package, out, device=device)
    console.print_json(json.dumps(result, ensure_ascii=False))
    if result.get("status") != "completed":
        raise typer.Exit(1)


@app.command()
def serve(
    host: Annotated[str, typer.Option("--host", help="Loopback bind address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Bind port.")] = 8765,
) -> None:
    """Serve the loopback-only FastAPI API."""
    try:
        host = _validated_loopback_host(host)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--host") from exc
    init_db()
    uvicorn.run("apk_docforge.api.app:app", host=host, port=port, reload=False)


@app.command()
def sources(
    add_json: Annotated[
        str | None,
        typer.Option("--add-json", help="JSON object for adding/updating a source."),
    ] = None,
) -> None:
    """List or update local source records."""
    if add_json:
        payload = json.loads(add_json)
        console.print_json(json.dumps(upsert_source(payload), ensure_ascii=False))
        return
    table = Table(title="Configured sources")
    table.add_column("ID")
    table.add_column("Type")
    table.add_column("Enabled")
    table.add_column("Policy")
    table.add_column("Trust")
    for row in list_sources():
        table.add_row(
            str(row["id"]),
            str(row["type"]),
            str(row["enabled"]),
            str(row["policy_status"]),
            str(row["trust_level"]),
        )
    console.print(table)
    console.print_json(json.dumps({"sources": list_sources()}, ensure_ascii=False))


@app.command("mcp-server")
def mcp_server() -> None:
    """Start the local MCP stdio server."""
    from apk_docforge.mcp.server import run_stdio_server

    run_stdio_server()


def _validated_loopback_host(host: str) -> str:
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        address = ip_address(candidate)
    except ValueError as exc:
        raise ValueError("apk-docforge only accepts literal loopback IP addresses") from exc
    if not address.is_loopback:
        raise ValueError("apk-docforge refuses non-loopback bind addresses")
    if str(address) != "127.0.0.1":
        raise ValueError("apk-docforge currently supports only the exact 127.0.0.1 bind address")
    return str(address)
