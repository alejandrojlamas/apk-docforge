from __future__ import annotations

import json
import zipfile

import pytest

from apk_docforge.agents import package_structure as package_structure_module
from apk_docforge.config import get_settings
from apk_docforge.pipeline import run_analysis


def test_static_pipeline_generates_outputs(sample_apk, tmp_path, isolated_app_env) -> None:
    out = tmp_path / "outputs" / "sample"
    summary = run_analysis(sample_apk, out=out, mode="static")
    assert summary["status"] == "completed"
    assert (out / "report.md").exists()
    assert (out / "codex_ingestion_prompt.md").exists()
    assert (out / "qa_report.json").exists()
    assert (out / "app_understanding.json").exists()
    assert (out / "reconstruction_brief.json").exists()

    features = json.loads((out / "features.json").read_text())
    assert any(item["name"] == "login/auth" for item in features["features"])
    assert any(item["name"] == "payments/subscriptions" for item in features["features"])

    qa = json.loads((out / "qa_report.json").read_text())
    assert qa["status"] == "passed"

    endpoints = json.loads((out / "network_endpoints.json").read_text())
    assert all(item.get("domain") != "schemas.android.com" for item in endpoints["endpoints"])

    boundaries = json.loads((out / "control_boundary_assessment.json").read_text())
    assert boundaries["policy"]["bypass_implemented"] is False
    assert boundaries["policy"]["bypass_attempted"] is False
    observed_controls = {item["name"] for item in boundaries["controls"] if item["status"] != "unknown"}
    assert "authentication_gate" in observed_controls
    assert "certificate_pinning" in observed_controls
    assert all(item["bypass_allowed"] is False for item in boundaries["controls"])
    expected_docs = {
        "00_executive_summary.md",
        "01_app_identity.md",
        "02_feature_map.md",
        "02b_codex_reconstruction_brief.md",
        "03_screens_and_buttons.md",
        "04_connections_and_sdks.md",
        "05_permissions_and_privacy.md",
        "06_security_findings.md",
        "06b_controls_and_boundaries.md",
        "07_test_matrix.md",
        "08_recommended_backlog.md",
        "09_limitations.md",
    }
    assert {path.name for path in (out / "docs").glob("*.md")} == expected_docs

    prompt = (out / "codex_ingestion_prompt.md").read_text(encoding="utf-8")
    report = (out / "report.md").read_text(encoding="utf-8")
    understanding = json.loads((out / "app_understanding.json").read_text())
    reconstruction = json.loads((out / "reconstruction_brief.json").read_text())
    assert understanding["what_it_is"]
    assert reconstruction["codex_goal"]
    assert "## What It Is And How It Works" in report
    assert "# Master prompt for documenting Android reverse engineering" in prompt
    assert "Write the reverse-engineering record in natural language" in prompt
    assert "### Protection controls and boundaries" in prompt
    assert "Bypass implemented: false" in prompt


def test_static_pipeline_preserves_original_container_type(sample_apk, tmp_path, isolated_app_env) -> None:
    xapk = tmp_path / "sample.xapk"
    with zipfile.ZipFile(xapk, "w") as archive:
        archive.writestr("manifest.json", "{}")
        archive.writestr("base.apk", sample_apk.read_bytes())

    out = tmp_path / "outputs" / "xapk"
    run_analysis(xapk, out=out, mode="static")
    run_analysis(xapk, out=out, mode="static")

    package_structure = json.loads((out / "package_structure.json").read_text())
    data = package_structure["data"]
    assert data["artifact_type"] == "xapk"
    assert data["primary_artifact_type"] == "apk"


def test_static_pipeline_rejects_oversized_nested_apk(
    sample_apk,
    tmp_path,
    isolated_app_env,
    monkeypatch,
) -> None:
    monkeypatch.setenv("APK_DOCFORGE_MAX_NESTED_ARTIFACT_BYTES", "8")
    get_settings.cache_clear()
    xapk = tmp_path / "oversize.xapk"
    with zipfile.ZipFile(xapk, "w") as archive:
        archive.writestr("manifest.json", "{}")
        archive.writestr("base.apk", sample_apk.read_bytes())

    with pytest.raises(ValueError, match="Nested artifact exceeds"):
        run_analysis(xapk, out=tmp_path / "outputs" / "oversize", mode="static")


def test_static_pipeline_rejects_oversized_manifest(
    tmp_path,
    isolated_app_env,
    monkeypatch,
) -> None:
    monkeypatch.setattr(package_structure_module, "MAX_MANIFEST_BYTES", 8)
    apk = tmp_path / "oversize-manifest.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"123456789")
        archive.writestr("classes.dex", b"dex\n")

    with pytest.raises(ValueError, match="AndroidManifest.xml exceeds"):
        run_analysis(apk, out=tmp_path / "outputs" / "oversize-manifest", mode="static")
