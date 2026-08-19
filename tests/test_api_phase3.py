from __future__ import annotations

from fastapi.testclient import TestClient

from apk_docforge.api.app import app


def test_api_analysis_read_endpoints(sample_apk, tmp_path, isolated_app_env) -> None:
    client = TestClient(
        app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 50000)
    )

    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    out = tmp_path / "api-analysis"
    analyze = client.post(
        "/api/analyze",
        json={"path": str(sample_apk), "out": str(out), "mode": "static"},
    )
    assert analyze.status_code == 200
    summary = analyze.json()
    analysis_id = summary["analysis_id"]

    fetched = client.get(f"/api/analyses/{analysis_id}")
    assert fetched.status_code == 200
    assert fetched.json()["analysis_id"] == analysis_id

    listed = client.get("/api/analyses")
    assert listed.status_code == 200
    assert any(item["analysis_id"] == analysis_id for item in listed.json()["analyses"])

    report = client.get(f"/api/analyses/{analysis_id}/report")
    assert report.status_code == 200
    assert "# apk-docforge static analysis report" in report.json()["report"]

    prompt = client.get(f"/api/analyses/{analysis_id}/codex-prompt")
    assert prompt.status_code == 200
    assert (
        "# Master prompt for documenting Android reverse engineering"
        in prompt.json()["codex_prompt"]
    )

    features = client.get(f"/api/analyses/{analysis_id}/features")
    assert features.status_code == 200
    assert any(item["name"] == "login/auth" for item in features.json()["features"])

    findings = client.get(f"/api/analyses/{analysis_id}/findings")
    assert findings.status_code == 200
    assert "findings" in findings.json()

    screens = client.get(f"/api/analyses/{analysis_id}/screens")
    assert screens.status_code == 200
    assert "screens" in screens.json()


def test_api_sources_and_search(isolated_app_env) -> None:
    client = TestClient(
        app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 50000)
    )

    sources = client.get("/api/sources")
    assert sources.status_code == 200
    assert any(item["type"] == "official_url" for item in sources.json()["sources"])

    updated = client.post(
        "/api/sources",
        json={"type": "official_url", "enabled": True, "notes": "test update"},
    )
    assert updated.status_code == 200
    assert updated.json()["source"]["type"] == "official_url"

    search = client.post(
        "/api/search",
        json={"query": "https://example.com/app.apk", "sources": ["official"], "limit": 1},
    )
    assert search.status_code == 200
    body = search.json()
    assert body["candidates"][0]["source"] == "official_url"
    assert body["candidates"][0]["download_url"] == "https://example.com/app.apk"


def test_api_upload_and_settings(sample_apk, isolated_app_env) -> None:
    client = TestClient(
        app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 50000)
    )

    home = client.get("/")
    assert home.status_code == 200
    assert "Choose how to provide the app" in home.text

    with sample_apk.open("rb") as handle:
        upload = client.post(
            "/api/upload",
            files={"file": ("sample.apk", handle, "application/vnd.android.package-archive")},
        )
    assert upload.status_code == 200
    uploaded = upload.json()
    assert uploaded["status"] == "uploaded"
    assert uploaded["quarantine"] is True
    assert uploaded["sha256"]

    settings = client.post(
        "/api/settings",
        json={
            "deepseek_api_key": "test-secret",
            "official_url_allowlist": "example.com, apps.example.org",
            "google_play_credentials_json": "/tmp/google-play.json",
            "allow_dynamic": True,
        },
    )
    assert settings.status_code == 200
    body = settings.json()
    assert body["deepseek_api_key_configured"] is True
    assert "deepseek_api_key" not in body
    assert "google_play_credentials_json" not in body
    assert body["allow_dynamic"] is True
    assert "apps.example.org" in body["official_url_hosts"]
