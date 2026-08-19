from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from apk_docforge.api.app import app
from apk_docforge.api.middleware import MULTIPART_OVERHEAD_BYTES
from apk_docforge.cli import _validated_loopback_host, app as cli_app
from apk_docforge.config import Settings, get_settings


def test_api_rejects_untrusted_host_and_cross_origin(isolated_app_env: Path) -> None:
    client = TestClient(
        app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 50000)
    )

    remote_client = TestClient(
        app, base_url="http://127.0.0.1:8765", client=("203.0.113.10", 50000)
    )
    assert remote_client.get("/api/health").status_code == 403

    untrusted_host = client.get("/api/health", headers={"Host": "attacker.example"})
    assert untrusted_host.status_code == 400

    allowed_preflight = client.options(
        "/api/health",
        headers={
            "Origin": "http://127.0.0.1:8765",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert allowed_preflight.status_code == 200
    assert allowed_preflight.headers["access-control-allow-origin"] == "http://127.0.0.1:8765"

    blocked_preflight = client.options(
        "/api/health",
        headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert blocked_preflight.status_code == 400
    assert "access-control-allow-origin" not in blocked_preflight.headers


def test_upload_rejects_declared_and_actual_oversize(
    isolated_app_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APK_DOCFORGE_MAX_UPLOAD_BYTES", "8")
    get_settings.cache_clear()
    client = TestClient(
        app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 50000)
    )

    declared = client.post(
        "/api/upload",
        content=b"",
        headers={
            "Content-Type": "multipart/form-data; boundary=limit",
            "Content-Length": str(8 + MULTIPART_OVERHEAD_BYTES + 1),
        },
    )
    assert declared.status_code == 413

    streamed = client.post(
        "/api/upload",
        content=iter([b"x" * (8 + MULTIPART_OVERHEAD_BYTES + 1)]),
        headers={"Content-Type": "multipart/form-data; boundary=limit"},
    )
    assert streamed.status_code == 413

    actual = client.post(
        "/api/upload",
        files={"file": ("oversize.apk", b"123456789", "application/octet-stream")},
    )
    assert actual.status_code == 413
    upload_dir = isolated_app_env / "quarantine" / "uploads"
    assert not upload_dir.exists() or not list(upload_dir.iterdir())


def test_server_and_origin_configuration_are_loopback_only() -> None:
    assert _validated_loopback_host("127.0.0.1") == "127.0.0.1"
    with pytest.raises(ValueError, match="exact 127.0.0.1"):
        _validated_loopback_host("::1")
    with pytest.raises(ValueError, match="non-loopback"):
        _validated_loopback_host("0.0.0.0")
    with pytest.raises(ValueError, match="literal loopback"):
        _validated_loopback_host("example.com")
    with pytest.raises(ValueError, match="loopback"):
        Settings(api_allowed_origins="https://example.com")
    with pytest.raises(ValueError, match="exact host names"):
        Settings(official_url_allowlist="https://example.com")
    with pytest.raises(ValueError, match="not IP literals"):
        Settings(official_url_allowlist="127.0.0.1")

    result = CliRunner().invoke(cli_app, ["serve", "--host", "0.0.0.0"])
    assert result.exit_code == 2
    assert "refuses non-loopback" in result.output
